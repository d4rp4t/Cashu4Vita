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
#include <stdio.h>
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


// number of blank outputs to send for change on a melt request.
// = ceil(log2(fee_reserve)), minimum 1 if fee_reserve > 0.
static size_t blank_output_count(uint64_t fee_reserve) {
    if (fee_reserve == 0) return 0;
    size_t n = 0;
    uint64_t v = 1;
    while (v < fee_reserve) { v <<= 1; n++; }
    return n > 0 ? n : 1;
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


// unblind change sigs into proofs.
// sigs[i].amount drives key lookup (not a pre-known amount array).
// mat[i] holds the blinding state for the i-th blank output we sent.
// slots where sigs[i].amount == 0 are skipped.
static cashu_err_t do_unblind_change(const blind_signature_t *sigs, size_t sig_n,
                                      const out_mat_t *mat, size_t mat_n,
                                      const keyset_t *ks,
                                      proof_t *proofs, size_t *built) {
    *built = 0;
    size_t lim = sig_n < mat_n ? sig_n : mat_n;
    for (size_t i = 0; i < lim; i++) {
        if (sigs[i].amount == 0) continue;

        const keyset_key_t *mint_key = find_key(ks, sigs[i].amount);
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
        secp256k1_ec_pubkey_serialize(crypto_ctx(), proofs[*built].C, &C_len, &C,
                                      SECP256K1_EC_COMPRESSED);
        proofs[*built].amount = sigs[i].amount;
        proofs[*built].id     = strdup(ks->id);
        proofs[*built].secret = strdup(mat[i].secret_hex);
        if (!proofs[*built].id || !proofs[*built].secret) return CASHU_ERR_OOM;
        (*built)++;
    }
    return CASHU_OK;
}

uint64_t wallet_balance(void) {
    return storage_total_balance();
}

uint64_t wallet_balance_for(const char *mint_url) {
    proof_t *p; size_t n;
    if (storage_get_by_mint(mint_url, &p, &n) != CASHU_OK) return 0;
    uint64_t bal = proof_array_sum(p, n);
    proof_array_free(p, n);
    return bal;
}

const char *wallet_active_mint(void) { return s_mint_url; }

void wallet_set_active_mint(const char *url) {
    char *dup = strdup(url);
    if (!dup) return;
    free(s_mint_url);
    s_mint_url = dup;
}

cashu_err_t wallet_list_mints(mint_info_t **out, size_t *count) {
    char **urls = NULL; size_t n = 0;
    cashu_err_t err = storage_list_mints(&urls, &n);
    if (err != CASHU_OK) return err;

    // check if active mint is already in storage
    int found = 0;
    for (size_t i = 0; i < n && !found; i++)
        if (strcmp(urls[i], s_mint_url) == 0) found = 1;

    size_t total = n + (found ? 0 : 1);
    mint_info_t *result = malloc(total * sizeof(mint_info_t));
    if (!result) {
        for (size_t i = 0; i < n; i++) free(urls[i]);
        free(urls);
        return CASHU_ERR_OOM;
    }

    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        result[j].url     = urls[i]; /* transfer ownership */
        result[j].balance = wallet_balance_for(urls[i]);
        j++;
    }
    free(urls);

    if (!found) {
        result[j].url     = strdup(s_mint_url);
        result[j].balance = wallet_balance_for(s_mint_url);
        if (!result[j].url) {
            for (size_t i = 0; i < j; i++) free(result[i].url);
            free(result);
            return CASHU_ERR_OOM;
        }
        j++;
    }

    *out   = result;
    *count = j;
    return CASHU_OK;
}

void wallet_mints_free(mint_info_t *mints, size_t count) {
    if (!mints) return;
    for (size_t i = 0; i < count; i++) free(mints[i].url);
    free(mints);
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
    uint64_t base_target = melt_q->amount + melt_q->fee_reserve;

    proof_t *pool = NULL; size_t pool_n = 0;
    cashu_err_t err = storage_get_by_mint(s_mint_url, &pool, &pool_n);
    if (err != CASHU_OK) return err;

    if (proof_array_sum(pool, pool_n) < base_target) {
        proof_array_free(pool, pool_n);
        return CASHU_ERR_INSUFFICIENT_FUNDS;
    }

    // mint charges keyset fee on melt proofs
    // in addition to the lightning fee_reserve. two-pass selection to find
    // eff_target = base_target + cashu_fee, same pattern as wallet_send.
    keyset_t *fee_ks = NULL; size_t fee_count = 0;
    err = cashu_get_keysets(s_mint_url, &fee_ks, &fee_count);
    if (err != CASHU_OK) { proof_array_free(pool, pool_n); return err; }

    proof_t *inputs = NULL; size_t inp_n = 0;
    err = select_proofs(pool, pool_n, base_target, &inputs, &inp_n);
    if (err != CASHU_OK) goto done_pool;

    {
        uint64_t cashu_fee  = compute_fee(inputs, inp_n, fee_ks, fee_count);
        uint64_t eff_target = base_target + cashu_fee;

        if (proof_array_sum(inputs, inp_n) < eff_target) {
            proof_array_free(inputs, inp_n); inputs = NULL; inp_n = 0;
            err = select_proofs(pool, pool_n, eff_target, &inputs, &inp_n);
            if (err != CASHU_OK) goto done_pool;
            cashu_fee  = compute_fee(inputs, inp_n, fee_ks, fee_count);
            eff_target = base_target + cashu_fee;
            if (proof_array_sum(inputs, inp_n) < eff_target) {
                err = CASHU_ERR_INSUFFICIENT_FUNDS;
                goto done_inputs;
            }
        }
        proof_array_free(pool, pool_n); pool = NULL;

        uint64_t inp_sum = proof_array_sum(inputs, inp_n);

        // keys needed for swap (overshoot) and/or blank outputs
        keyset_t *keysets = NULL; size_t ks_count = 0;
        out_mat_t         *mat  = NULL;
        blinded_message_t *msgs = NULL;
        size_t             out_n = 0;

        if (inp_sum > eff_target || melt_q->fee_reserve > 0) {
            err = cashu_get_keys(s_mint_url, &keysets, &ks_count);
            if (err != CASHU_OK) goto done_melt;
        }
        keyset_t *ks = keysets ? find_ks_by_unit(keysets, ks_count, s_unit) : NULL;
        if ((inp_sum > eff_target || melt_q->fee_reserve > 0) && !ks) {
            err = CASHU_ERR_PROTOCOL; goto done_melt;
        }

        // ===================================================================
        // pre-melt swap when inputs overshoot eff_target.
        //
        // mint only returns (fee_reserve - actual_routing_fee) as change
        // any (inp_sum - eff_target) excess is lost otherwise
        //
        // swap splits inputs into:
        //   [0 .. sw_eff_n-1] --> exact melt proofs (sum = sw_t)
        //   [sw_eff_n .. sw_n-1] --> change kept in wallet
        //
        // all swap proofs are stored before the melt so melt proofs are
        // recoverable from storage if the app crashes before melt completes.
        // ===================================================================
        if (inp_sum > eff_target && ks) {
            // compute post_swap_eff_target (sw_t): smallest T such that
            // decompose(T) proofs cover base_target + their own cashu fee
            // fixed-point: T = base_target + fee(decompose(T)), 2-3 iterations.
            uint64_t sw_t = eff_target;
            uint32_t ppk  = find_fee_ppk(ks->id, fee_ks, fee_count);
            for (int iter = 0; iter < 8; iter++) {
                uint64_t dummy[32];
                size_t   n    = decompose(sw_t, dummy);
                uint64_t fee  = ((uint64_t)n * ppk + 999) / 1000;
                uint64_t need = base_target + fee;
                if (need <= sw_t) break;
                sw_t = need;
            }

            uint64_t swap_fee = compute_fee(inputs, inp_n, fee_ks, fee_count);

            if (inp_sum > sw_t + swap_fee) {
                uint64_t keep = inp_sum - sw_t - swap_fee;

                uint64_t sw_amounts[64];
                size_t sw_n    = decompose(sw_t, sw_amounts);
                size_t sw_eff_n = sw_n;  // [0..sw_eff_n-1] = melt proofs
                if (keep > 0) sw_n += decompose(keep, sw_amounts + sw_eff_n);

                out_mat_t         *sw_mat  = malloc(sw_n * sizeof(out_mat_t));
                blinded_message_t *sw_msgs = malloc(sw_n * sizeof(blinded_message_t));
                proof_t           *sw_pfs  = malloc(sw_n * sizeof(proof_t));
                if (!sw_mat || !sw_msgs || !sw_pfs) {
                    free(sw_mat); free(sw_msgs); free(sw_pfs);
                    err = CASHU_ERR_OOM; goto done_melt;
                }

                err = build_outputs(sw_amounts, sw_n, ks, sw_mat, sw_msgs);
                if (err == CASHU_OK) {
                    blind_signature_t *sw_sigs = NULL; size_t sw_sig_n = 0;
                    err = cashu_swap(s_mint_url, inputs, inp_n, sw_msgs, sw_n,
                                     &sw_sigs, &sw_sig_n);
                    if (err == CASHU_OK) {
                        if (sw_sig_n != sw_n) { err = CASHU_ERR_PROTOCOL; }
                        else {
                            size_t built = 0;
                            err = do_unblind_all(sw_amounts, sw_n, sw_sigs, sw_mat,
                                                 ks, sw_pfs, &built);
                            if (err == CASHU_OK)
                                err = storage_swap(inputs, inp_n, sw_pfs, sw_n,
                                                   s_mint_url);
                            if (err == CASHU_OK) {
                                proof_array_free(inputs, inp_n);
                                for (size_t i = sw_eff_n; i < built; i++) {
                                    free(sw_pfs[i].id);     sw_pfs[i].id     = NULL;
                                    free(sw_pfs[i].secret); sw_pfs[i].secret = NULL;
                                }
                                inputs  = sw_pfs;  sw_pfs = NULL;
                                inp_n   = sw_eff_n;
                                inp_sum = sw_t;
                            } else {
                                for (size_t i = 0; i < built; i++) {
                                    free(sw_pfs[i].id); free(sw_pfs[i].secret);
                                }
                            }
                        }
                        for (size_t i = 0; i < sw_sig_n; i++) {
                            free(sw_sigs[i].id); free(sw_sigs[i].C_);
                        }
                        free(sw_sigs);
                    }
                }
                free(sw_pfs); free(sw_mat); free(sw_msgs);
                if (err != CASHU_OK) goto done_melt;
            }
            // else: not worth swapping (keep = inp_sum - sw_t - swap_fee ≤ 0)
        }

        // blank outputs so the mint can return unused fee_reserve as change
        out_n = blank_output_count(melt_q->fee_reserve);
        if (out_n > 0 && ks) {
            uint64_t *zeros = calloc(out_n, sizeof(uint64_t));
            mat  = malloc(out_n * sizeof(out_mat_t));
            msgs = malloc(out_n * sizeof(blinded_message_t));
            if (!zeros || !mat || !msgs) { free(zeros); err = CASHU_ERR_OOM; goto done_melt; }
            err = build_outputs(zeros, out_n, ks, mat, msgs);
            free(zeros);
            if (err != CASHU_OK) goto done_melt;
        }

        {
            melt_quote_t result = {0};
            err = cashu_melt(s_mint_url, melt_q->quote, inputs, inp_n,
                             msgs, out_n, &result);
            if (err == CASHU_OK) {
                if (strcmp(result.state, "PAID") == 0) {
                    storage_remove_proofs(inputs, inp_n);
                    if (result.change_count > 0 && mat && ks) {
                        proof_t *cp = malloc(result.change_count * sizeof(proof_t));
                        if (cp) {
                            size_t built = 0;
                            if (do_unblind_change(result.change, result.change_count,
                                                  mat, out_n, ks, cp, &built) == CASHU_OK) {
                                for (size_t i = 0; i < built; i++)
                                    storage_save_proof(&cp[i], s_mint_url);
                            }
                            for (size_t i = 0; i < built; i++) {
                                free(cp[i].id); free(cp[i].secret);
                            }
                            free(cp);
                        }
                    }
                }
                melt_quote_free(&result);
            }
        }

done_melt:
        for (size_t i = 0; i < ks_count; i++) keyset_free(&keysets[i]);
        free(keysets);
        free(mat); free(msgs);
    }

done_inputs:
    proof_array_free(inputs, inp_n);
done_pool:
    proof_array_free(pool, pool_n);
    for (size_t i = 0; i < fee_count; i++) keyset_free(&fee_ks[i]);
    free(fee_ks);
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
    token_t tok;
    cashu_err_t err = token_decode(token, &tok);
    if (err != CASHU_OK) return err;

    uint64_t total = 0;
    for (size_t i = 0; i < tok.proof_count; i++) total += tok.proofs[i].amount;

    keyset_t *fee_ks = NULL; size_t fee_count = 0;
    err = cashu_get_keysets(tok.mint_url, &fee_ks, &fee_count);
    if (err != CASHU_OK) { token_free(&tok); return err; }

    uint64_t fee = compute_fee(tok.proofs, tok.proof_count, fee_ks, fee_count);
    for (size_t i = 0; i < fee_count; i++) keyset_free(&fee_ks[i]);
    free(fee_ks);

    if (fee >= total) { token_free(&tok); return CASHU_ERR_PROTOCOL; }
    uint64_t net = total - fee;

    uint64_t out_amounts[32];
    size_t   out_n = decompose(net, out_amounts);

    keyset_t *keysets = NULL; size_t ks_count = 0;
    err = cashu_get_keys(tok.mint_url, &keysets, &ks_count);
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
        err = cashu_swap(tok.mint_url, tok.proofs, tok.proof_count,
                         msgs, out_n, &sigs, &sig_count);
        if (err != CASHU_OK) goto done_out;
        if (sig_count != out_n) { err = CASHU_ERR_PROTOCOL; goto done_sigs; }

        proof_t *new_proofs = malloc(out_n * sizeof(proof_t));
        if (!new_proofs) { err = CASHU_ERR_OOM; goto done_sigs; }

        size_t built = 0;
        err = do_unblind_all(out_amounts, out_n, sigs, mat, ks, new_proofs, &built);
        for (size_t i = 0; i < built && err == CASHU_OK; i++)
            err = storage_save_proof(&new_proofs[i], tok.mint_url);

        // auto-switch active mint so the received funds are immediately visible
        if (err == CASHU_OK && strcmp(tok.mint_url, s_mint_url) != 0) {
            char *new_url = strdup(tok.mint_url);
            if (new_url) { free(s_mint_url); s_mint_url = new_url; }
        }

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
