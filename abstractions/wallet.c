//
// Created by d4rp4t on 21/02/2026.
//
#include "wallet.h"
#include "storage.h"
#include "../cashu/http.h"
#include "../cashu/protocol.h"
#include "../cashu/encoding.h"
#include "../cashu/utils.h"
#include <secp256k1.h>
#include <stdlib.h>
#include <string.h>

static char *s_mint_url = NULL;
static char *s_unit     = NULL;

cashu_err_t wallet_init(const char *mint_url, const char *storage_path,
                        const char *unit) {
    s_mint_url = strdup(mint_url);
    if (!s_mint_url) return CASHU_ERR_OOM;

    s_unit = strdup(unit ? unit : "sat");
    if (!s_unit) { free(s_mint_url); s_mint_url = NULL; return CASHU_ERR_OOM; }

    cashu_err_t err = storage_init(storage_path);
    if (err != CASHU_OK) {
        free(s_unit);     s_unit     = NULL;
        free(s_mint_url); s_mint_url = NULL;
    }
    return err;
}

void wallet_term(void) {
    storage_term();
    free(s_mint_url); s_mint_url = NULL;
    free(s_unit);     s_unit     = NULL;
}

static void proof_array_free(proof_t *p, size_t n) {
    if (!p) return;
    for (size_t i = 0; i < n; i++) { free(p[i].id); free(p[i].secret); }
    free(p);
}

static uint64_t proof_array_sum(const proof_t *p, size_t n) {
    uint64_t s = 0;
    for (size_t i = 0; i < n; i++) s += p[i].amount;
    return s;
}

// Power-of-2 decomposition, largest denomination first.
// out must have at least 32 elements.
static size_t decompose(uint64_t amount, uint64_t *out) {
    size_t n = 0;
    for (int bit = 31; bit >= 0 && amount > 0; bit--) {
        uint64_t d = (uint64_t)1 << bit;
        while (amount >= d) { out[n++] = d; amount -= d; }
    }
    return n;
}

static const keyset_key_t *find_key(const keyset_t *ks, uint64_t amount) {
    for (size_t i = 0; i < ks->key_count; i++)
        if (ks->keys[i].amount == amount) return &ks->keys[i];
    return NULL;
}

static keyset_t *find_ks_by_unit(keyset_t *ks, size_t n, const char *unit) {
    for (size_t i = 0; i < n; i++)
        if (ks[i].unit && strcmp(ks[i].unit, unit) == 0 && ks[i].active)
            return &ks[i];
    return NULL;
}

static uint32_t find_fee_ppk(const char *keyset_id,
                              const keyset_t *ks, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (strcmp(ks[i].id, keyset_id) == 0) return ks[i].input_fee_ppk;
    return 0;
}

static uint64_t compute_fee(const proof_t *inputs, size_t n,
                             const keyset_t *ks, size_t ks_n) {
    uint64_t sum = 0;
    for (size_t i = 0; i < n; i++)
        sum += find_fee_ppk(inputs[i].id, ks, ks_n);
    return (sum + 999) / 1000;
}

// greedy (largest-first) selection of proofs from pool summing to >= target.
// returns deep-copied proof array; caller frees with proof_array_free().
static cashu_err_t select_proofs(const proof_t *pool, size_t pool_n,
                                  uint64_t target,
                                  proof_t **out, size_t *out_n) {
    if (proof_array_sum(pool, pool_n) < target)
        return CASHU_ERR_INSUFFICIENT_FUNDS;

    // sort indices descending by amount (insertion sort - small n in practice)
    size_t *idx = malloc(pool_n * sizeof(size_t));
    if (!idx) return CASHU_ERR_OOM;
    for (size_t i = 0; i < pool_n; i++) idx[i] = i;
    for (size_t i = 1; i < pool_n; i++) {
        size_t k = idx[i], j = i;
        while (j > 0 && pool[idx[j-1]].amount < pool[k].amount)
            { idx[j] = idx[j-1]; j--; }
        idx[j] = k;
    }

    proof_t *sel = malloc(pool_n * sizeof(proof_t));
    if (!sel) { free(idx); return CASHU_ERR_OOM; }

    size_t   n       = 0;
    uint64_t running = 0;
    for (size_t i = 0; i < pool_n && running < target; i++) {
        const proof_t *src = &pool[idx[i]];
        sel[n].amount = src->amount;
        sel[n].id     = strdup(src->id);
        sel[n].secret = strdup(src->secret);
        memcpy(sel[n].C, src->C, 33);
        if (!sel[n].id || !sel[n].secret) {
            for (size_t k = 0; k <= n; k++) { free(sel[k].id); free(sel[k].secret); }
            free(sel); free(idx);
            return CASHU_ERR_OOM;
        }
        running += src->amount;
        n++;
    }

    free(idx);
    *out   = sel;
    *out_n = n;
    return CASHU_OK;
}

// ephemeral per-output blinding state needed for unblinding after swap/mint.
typedef struct {
    uint8_t secret[32];
    uint8_t r[32];
    char    secret_hex[65];
    char    B_hex[67];
} out_mat_t;

static void random_scalar(uint8_t out[32]) {
    do { arc4random_buf(out, 32); }
    while (!secp256k1_ec_seckey_verify(crypto_ctx(), out));
}

// fills mat[0..n-1] with random secrets/r values and msgs[0..n-1] with the
// corresponding blinded messages. msgs[i].id and msgs[i].B_ point into mat[i]
// (no separate allocation).
static cashu_err_t build_outputs(const uint64_t *amounts, size_t n,
                                  const keyset_t *ks,
                                  out_mat_t *mat, blinded_message_t *msgs) {
    for (size_t i = 0; i < n; i++) {
        arc4random_buf(mat[i].secret, 32);
        random_scalar(mat[i].r);
        hex_encode(mat[i].secret, 32, mat[i].secret_hex);
        mat[i].secret_hex[64] = '\0';

        secp256k1_pubkey Y, B_;
        cashu_err_t err = hash_to_curve((const uint8_t *)mat[i].secret_hex, 64, &Y);
        if (err != CASHU_OK) return err;
        err = blind(&Y, mat[i].r, &B_);
        if (err != CASHU_OK) return err;

        uint8_t B_bytes[33];
        size_t  B_len = 33;
        secp256k1_ec_pubkey_serialize(crypto_ctx(), B_bytes, &B_len, &B_,
                                      SECP256K1_EC_COMPRESSED);
        hex_encode(B_bytes, 33, mat[i].B_hex);
        mat[i].B_hex[66] = '\0';

        msgs[i].amount = amounts[i];
        msgs[i].id     = ks->id;    // borrowed from keyset; valid until keyset freed
        msgs[i].B_     = mat[i].B_hex;
    }
    return CASHU_OK;
}


// unblind sigs[0..n-1] into proofs[0..n-1].
// *built = number successfully constructed; proofs[0..*built] have strdup'd id/secret.
static cashu_err_t do_unblind_all(const uint64_t *amounts, size_t n,
                                   const blind_signature_t *sigs,
                                   const out_mat_t *mat,
                                   const keyset_t *ks,
                                   proof_t *proofs, size_t *built) {
    *built = 0;
    for (size_t i = 0; i < n; i++) {
        const keyset_key_t *mint_key = find_key(ks, amounts[i]);
        if (!mint_key) return CASHU_ERR_PROTOCOL;

        uint8_t A_bytes[33];
        hex_decode(mint_key->pubkey, A_bytes, 33);
        secp256k1_pubkey A;
        if (!secp256k1_ec_pubkey_parse(crypto_ctx(), &A, A_bytes, 33))
            return CASHU_ERR_INVALID_POINT;

        uint8_t C__bytes[33];
        hex_decode(sigs[i].C_, C__bytes, 33);
        secp256k1_pubkey C_;
        if (!secp256k1_ec_pubkey_parse(crypto_ctx(), &C_, C__bytes, 33))
            return CASHU_ERR_INVALID_POINT;

        secp256k1_pubkey C;
        cashu_err_t err = unblind(&C_, mat[i].r, &A, &C);
        if (err != CASHU_OK) return err;

        size_t C_len = 33;
        secp256k1_ec_pubkey_serialize(crypto_ctx(), proofs[i].C, &C_len, &C,
                                      SECP256K1_EC_COMPRESSED);
        proofs[i].amount = amounts[i];
        proofs[i].id     = strdup(ks->id);
        proofs[i].secret = strdup(mat[i].secret_hex);
        if (!proofs[i].id || !proofs[i].secret) return CASHU_ERR_OOM;
        (*built)++;
    }
    return CASHU_OK;
}


uint64_t wallet_balance(void) {
    proof_t *p; size_t n;
    if (storage_get_by_mint(s_mint_url, &p, &n) != CASHU_OK) return 0;
    uint64_t bal = proof_array_sum(p, n);
    proof_array_free(p, n);
    return bal;
}


cashu_err_t wallet_mint_quote(uint64_t amount, mint_quote_t *out) {
    return cashu_mint_quote(s_mint_url, amount, s_unit, out);
}

cashu_err_t wallet_mint_quote_state(const char *quote_id, mint_quote_t *out) {
    return cashu_mint_quote_state(s_mint_url, quote_id, out);
}

cashu_err_t wallet_mint(const char *quote_id, uint64_t amount) {
    keyset_t *keysets = NULL; size_t ks_count = 0;
    cashu_err_t err = cashu_get_keys(s_mint_url, &keysets, &ks_count);
    if (err != CASHU_OK) return err;

    keyset_t *ks = find_ks_by_unit(keysets, ks_count, s_unit);
    if (!ks) { err = CASHU_ERR_PROTOCOL; goto done_keys; }

    {
        uint64_t out_amounts[32];
        size_t   out_n = decompose(amount, out_amounts);

        out_mat_t         *mat  = malloc(out_n * sizeof(out_mat_t));
        blinded_message_t *msgs = malloc(out_n * sizeof(blinded_message_t));
        if (!mat || !msgs) { err = CASHU_ERR_OOM; goto done_out; }

        err = build_outputs(out_amounts, out_n, ks, mat, msgs);
        if (err != CASHU_OK) goto done_out;

        blind_signature_t *sigs = NULL; size_t sig_count = 0;
        err = cashu_mint(s_mint_url, quote_id, msgs, out_n, &sigs, &sig_count);
        if (err != CASHU_OK) goto done_out;
        if (sig_count != out_n) { err = CASHU_ERR_PROTOCOL; goto done_sigs; }

        proof_t *new_proofs = malloc(out_n * sizeof(proof_t));
        if (!new_proofs) { err = CASHU_ERR_OOM; goto done_sigs; }

        size_t built = 0;
        err = do_unblind_all(out_amounts, out_n, sigs, mat, ks, new_proofs, &built);
        for (size_t i = 0; i < built && err == CASHU_OK; i++)
            err = storage_save_proof(&new_proofs[i], s_mint_url);

        for (size_t i = 0; i < built; i++) { free(new_proofs[i].id); free(new_proofs[i].secret); }
        free(new_proofs);
done_sigs:
        for (size_t i = 0; i < sig_count; i++) { free(sigs[i].id); free(sigs[i].C_); }
        free(sigs);
done_out:
        free(mat); free(msgs);
    }
done_keys:
    for (size_t i = 0; i < ks_count; i++) keyset_free(&keysets[i]);
    free(keysets);
    return err;
}


cashu_err_t wallet_melt_quote(const char *bolt11, melt_quote_t *out) {
    return cashu_melt_quote(s_mint_url, bolt11, s_unit, out);
}

cashu_err_t wallet_melt(const melt_quote_t *melt_q) {
    uint64_t target = melt_q->amount + melt_q->fee_reserve;

    proof_t *pool = NULL; size_t pool_n = 0;
    cashu_err_t err = storage_get_by_mint(s_mint_url, &pool, &pool_n);
    if (err != CASHU_OK) return err;

    if (proof_array_sum(pool, pool_n) < target) {
        proof_array_free(pool, pool_n);
        return CASHU_ERR_INSUFFICIENT_FUNDS;
    }

    proof_t *inputs = NULL; size_t inp_n = 0;
    err = select_proofs(pool, pool_n, target, &inputs, &inp_n);
    proof_array_free(pool, pool_n);
    if (err != CASHU_OK) return err;

    melt_quote_t result;
    err = cashu_melt(s_mint_url, melt_q->quote, inputs, inp_n, &result);
    if (err == CASHU_OK) {
        if (strcmp(result.state, "PAID") == 0)
            storage_remove_proofs(inputs, inp_n);
        melt_quote_free(&result);
    }

    proof_array_free(inputs, inp_n);
    return err;
}

cashu_err_t wallet_send(uint64_t amount, char **token_out) {
    // 1. load proofs + balance check
    proof_t *pool = NULL; size_t pool_n = 0;
    cashu_err_t err = storage_get_by_mint(s_mint_url, &pool, &pool_n);
    if (err != CASHU_OK) return err;

    if (proof_array_sum(pool, pool_n) < amount) {
        proof_array_free(pool, pool_n);
        return CASHU_ERR_INSUFFICIENT_FUNDS;
    }

    // 2. fee info
    keyset_t *fee_ks = NULL; size_t fee_count = 0;
    err = cashu_get_keysets(s_mint_url, &fee_ks, &fee_count);
    if (err != CASHU_OK) { proof_array_free(pool, pool_n); return err; }

    // 3. select inputs - first attempt covers `amount`, then recheck against fee
    proof_t *inputs = NULL; size_t inp_n = 0;
    err = select_proofs(pool, pool_n, amount, &inputs, &inp_n);
    if (err != CASHU_OK) goto done_fee_ks;

    {
        uint64_t fee     = compute_fee(inputs, inp_n, fee_ks, fee_count);
        uint64_t inp_sum = proof_array_sum(inputs, inp_n);

        if (inp_sum < amount + fee) {
            // need more — retry with a larger target
            proof_array_free(inputs, inp_n); inputs = NULL; inp_n = 0;
            err = select_proofs(pool, pool_n, amount + fee, &inputs, &inp_n);
            if (err != CASHU_OK) goto done_fee_ks;
            fee     = compute_fee(inputs, inp_n, fee_ks, fee_count);
            inp_sum = proof_array_sum(inputs, inp_n);
            if (inp_sum < amount + fee) {
                err = CASHU_ERR_INSUFFICIENT_FUNDS; goto done_inputs;
            }
        }

        // 4. decompose outputs as [send denominations | change denominations]
        uint64_t change = inp_sum - amount - fee;
        uint64_t out_amounts[64];
        size_t   out_n        = decompose(amount, out_amounts);
        size_t   change_start = out_n;
        if (change > 0) out_n += decompose(change, out_amounts + change_start);

        // 5. keys
        keyset_t *keysets = NULL; size_t ks_count = 0;
        err = cashu_get_keys(s_mint_url, &keysets, &ks_count);
        if (err != CASHU_OK) goto done_inputs;

        keyset_t *ks = find_ks_by_unit(keysets, ks_count, s_unit);
        if (!ks) { err = CASHU_ERR_PROTOCOL; goto done_keys; }

        // 6. build + swap + unblind
        out_mat_t         *mat  = malloc(out_n * sizeof(out_mat_t));
        blinded_message_t *msgs = malloc(out_n * sizeof(blinded_message_t));
        if (!mat || !msgs) { err = CASHU_ERR_OOM; goto done_out; }

        err = build_outputs(out_amounts, out_n, ks, mat, msgs);
        if (err != CASHU_OK) goto done_out;

        blind_signature_t *sigs = NULL; size_t sig_count = 0;
        err = cashu_swap(s_mint_url, inputs, inp_n, msgs, out_n, &sigs, &sig_count);
        if (err != CASHU_OK) goto done_out;
        if (sig_count != out_n) { err = CASHU_ERR_PROTOCOL; goto done_sigs; }

        proof_t *new_proofs = malloc(out_n * sizeof(proof_t));
        if (!new_proofs) { err = CASHU_ERR_OOM; goto done_sigs; }

        size_t built = 0;
        err = do_unblind_all(out_amounts, out_n, sigs, mat, ks, new_proofs, &built);
        if (err != CASHU_OK) goto done_proofs;

        // 7. atomic storage: spent inputs out, change proofs in
        err = storage_swap(inputs, inp_n,
                           new_proofs + change_start, out_n - change_start,
                           s_mint_url);
        if (err != CASHU_OK) goto done_proofs;

        // 8. encode token from send proofs (indices 0..change_start-1)
        token_t tok = {
            .mint_url    = s_mint_url,
            .unit        = s_unit,
            .proofs      = new_proofs,
            .proof_count = change_start,
            .memo        = NULL,
        };
        err = token_encode(&tok, token_out);

done_proofs:
        for (size_t i = 0; i < built; i++) { free(new_proofs[i].id); free(new_proofs[i].secret); }
        free(new_proofs);
done_sigs:
        for (size_t i = 0; i < sig_count; i++) { free(sigs[i].id); free(sigs[i].C_); }
        free(sigs);
done_out:
        free(mat); free(msgs);
done_keys:
        for (size_t i = 0; i < ks_count; i++) keyset_free(&keysets[i]);
        free(keysets);
    }
done_inputs:
    proof_array_free(inputs, inp_n);
done_fee_ks:
    for (size_t i = 0; i < fee_count; i++) keyset_free(&fee_ks[i]);
    free(fee_ks);
    proof_array_free(pool, pool_n);
    return err;
}


cashu_err_t wallet_receive(const char *token) {
    // 1. decode
    token_t tok;
    cashu_err_t err = token_decode(token, &tok);
    if (err != CASHU_OK) return err;

    uint64_t total = 0;
    for (size_t i = 0; i < tok.proof_count; i++) total += tok.proofs[i].amount;

    // 2. fee for incoming proofs
    keyset_t *fee_ks = NULL; size_t fee_count = 0;
    err = cashu_get_keysets(s_mint_url, &fee_ks, &fee_count);
    if (err != CASHU_OK) { token_free(&tok); return err; }

    uint64_t fee = compute_fee(tok.proofs, tok.proof_count, fee_ks, fee_count);
    for (size_t i = 0; i < fee_count; i++) keyset_free(&fee_ks[i]);
    free(fee_ks);

    if (fee >= total) { token_free(&tok); return CASHU_ERR_PROTOCOL; }
    uint64_t net = total - fee;

    // 3. decompose net into denominations
    uint64_t out_amounts[32];
    size_t   out_n = decompose(net, out_amounts);

    // 4. keys
    keyset_t *keysets = NULL; size_t ks_count = 0;
    err = cashu_get_keys(s_mint_url, &keysets, &ks_count);
    if (err != CASHU_OK) { token_free(&tok); return err; }

    keyset_t *ks = find_ks_by_unit(keysets, ks_count, s_unit);
    if (!ks) { err = CASHU_ERR_PROTOCOL; goto done_keys; }

    {
        out_mat_t         *mat  = malloc(out_n * sizeof(out_mat_t));
        blinded_message_t *msgs = malloc(out_n * sizeof(blinded_message_t));
        if (!mat || !msgs) { err = CASHU_ERR_OOM; goto done_out; }

        err = build_outputs(out_amounts, out_n, ks, mat, msgs);
        if (err != CASHU_OK) goto done_out;

        blind_signature_t *sigs = NULL; size_t sig_count = 0;
        err = cashu_swap(s_mint_url, tok.proofs, tok.proof_count, msgs, out_n, &sigs, &sig_count);
        if (err != CASHU_OK) goto done_out;
        if (sig_count != out_n) { err = CASHU_ERR_PROTOCOL; goto done_sigs; }

        proof_t *new_proofs = malloc(out_n * sizeof(proof_t));
        if (!new_proofs) { err = CASHU_ERR_OOM; goto done_sigs; }

        size_t built = 0;
        err = do_unblind_all(out_amounts, out_n, sigs, mat, ks, new_proofs, &built);
        for (size_t i = 0; i < built && err == CASHU_OK; i++)
            err = storage_save_proof(&new_proofs[i], s_mint_url);

        for (size_t i = 0; i < built; i++) { free(new_proofs[i].id); free(new_proofs[i].secret); }
        free(new_proofs);
done_sigs:
        for (size_t i = 0; i < sig_count; i++) { free(sigs[i].id); free(sigs[i].C_); }
        free(sigs);
done_out:
        free(mat); free(msgs);
    }
done_keys:
    for (size_t i = 0; i < ks_count; i++) keyset_free(&keysets[i]);
    free(keysets);
    token_free(&tok);
    return err;
}

// ==============================================================================
//                                 low-level swap
// ==============================================================================

cashu_err_t wallet_swap(const proof_t  *inputs,  size_t inp_n,
                        const uint64_t *amounts, size_t amount_n) {
    keyset_t *fee_ks = NULL; size_t fee_count = 0;
    cashu_err_t err = cashu_get_keysets(s_mint_url, &fee_ks, &fee_count);
    if (err != CASHU_OK) return err;

    uint64_t fee     = compute_fee(inputs, inp_n, fee_ks, fee_count);
    uint64_t inp_sum = proof_array_sum(inputs, inp_n);
    uint64_t out_sum = 0;
    for (size_t i = 0; i < amount_n; i++) out_sum += amounts[i];

    if (out_sum + fee != inp_sum) { err = CASHU_ERR_PROTOCOL; goto done_fee_ks; }

    {
        keyset_t *keysets = NULL; size_t ks_count = 0;
        err = cashu_get_keys(s_mint_url, &keysets, &ks_count);
        if (err != CASHU_OK) goto done_fee_ks;

        keyset_t *ks = find_ks_by_unit(keysets, ks_count, s_unit);
        if (!ks) { err = CASHU_ERR_PROTOCOL; goto done_keys; }

        out_mat_t         *mat  = malloc(amount_n * sizeof(out_mat_t));
        blinded_message_t *msgs = malloc(amount_n * sizeof(blinded_message_t));
        if (!mat || !msgs) { err = CASHU_ERR_OOM; goto done_out; }

        err = build_outputs(amounts, amount_n, ks, mat, msgs);
        if (err != CASHU_OK) goto done_out;

        blind_signature_t *sigs = NULL; size_t sig_count = 0;
        err = cashu_swap(s_mint_url, inputs, inp_n, msgs, amount_n, &sigs, &sig_count);
        if (err != CASHU_OK) goto done_out;
        if (sig_count != amount_n) { err = CASHU_ERR_PROTOCOL; goto done_sigs; }

        proof_t *new_proofs = malloc(amount_n * sizeof(proof_t));
        if (!new_proofs) { err = CASHU_ERR_OOM; goto done_sigs; }

        size_t built = 0;
        err = do_unblind_all(amounts, amount_n, sigs, mat, ks, new_proofs, &built);
        if (err == CASHU_OK)
            err = storage_swap(inputs, inp_n, new_proofs, amount_n, s_mint_url);

        for (size_t i = 0; i < built; i++) { free(new_proofs[i].id); free(new_proofs[i].secret); }
        free(new_proofs);
done_sigs:
        for (size_t i = 0; i < sig_count; i++) { free(sigs[i].id); free(sigs[i].C_); }
        free(sigs);
done_out:
        free(mat); free(msgs);
done_keys:
        for (size_t i = 0; i < ks_count; i++) keyset_free(&keysets[i]);
        free(keysets);
    }
done_fee_ks:
    for (size_t i = 0; i < fee_count; i++) keyset_free(&fee_ks[i]);
    free(fee_ks);
    return err;
}
