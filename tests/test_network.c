//
// Created by d4rp4t on 21/02/2026.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "testing_utils.h"
#include "../cashu/http.h"
#include "../cashu/protocol.h"
#include "../cashu/models.h"
#include "../cashu/errors.h"
#include "../cashu/utils.h"
#include <secp256k1.h>

static int pass_count  = 0;
static int total_count = 0;

#define MINT_URL "https://testnut.cashu.space"

// ================================================================================
//                                     shared helpers
// ================================================================================

static void random_scalar(uint8_t out[32]) {
    do { arc4random_buf(out, 32); }
    while (!secp256k1_ec_seckey_verify(crypto_ctx(), out));
}

// build a blinded output for `amount` using the given keyset.
// writes B_hex (67 bytes), secret (32 bytes), r (32 bytes) into caller buffers
static cashu_err_t make_output(uint64_t amount, keyset_t *ks,
                                char B_hex[67], uint8_t secret[32], uint8_t r[32],
                                char secret_hex[65]) {
    arc4random_buf(secret, 32);
    random_scalar(r);

    hex_encode(secret, 32, secret_hex);
    secret_hex[64] = '\0';

    secp256k1_pubkey Y, B_;
    // use the hex string as secret - mint verifies with hash_to_curve(proof.secret)
    cashu_err_t err = hash_to_curve((const uint8_t *)secret_hex, 64, &Y);
    if (err != CASHU_OK) return err;
    err = blind(&Y, r, &B_);
    if (err != CASHU_OK) return err;

    uint8_t B_bytes[33];
    size_t  B_len = 33;
    secp256k1_ec_pubkey_serialize(crypto_ctx(), B_bytes, &B_len, &B_,
                                  SECP256K1_EC_COMPRESSED);
    hex_encode(B_bytes, 33, B_hex);
    B_hex[66] = '\0';
    return CASHU_OK;
}

// unblind a signature into proof.C - returns CASHU_OK on success.
static cashu_err_t do_unblind(const char *C__hex, const uint8_t r[32],
                               const char *A_hex, uint8_t C_out[33]) {
    uint8_t A_bytes[33];
    hex_decode(A_hex, A_bytes, 33);
    secp256k1_pubkey A;
    if (!secp256k1_ec_pubkey_parse(crypto_ctx(), &A, A_bytes, 33))
        return CASHU_ERR_INVALID_POINT;

    uint8_t C__bytes[33];
    hex_decode(C__hex, C__bytes, 33);
    secp256k1_pubkey C_;
    if (!secp256k1_ec_pubkey_parse(crypto_ctx(), &C_, C__bytes, 33))
        return CASHU_ERR_INVALID_POINT;

    secp256k1_pubkey C;
    cashu_err_t err = unblind(&C_, r, &A, &C);
    if (err != CASHU_OK) return err;

    size_t C_len = 33;
    secp256k1_ec_pubkey_serialize(crypto_ctx(), C_out, &C_len, &C,
                                  SECP256K1_EC_COMPRESSED);
    return CASHU_OK;
}

// find active keyset for given unit, return pointer into keysets array or NULL
static keyset_t *find_active_keyset(keyset_t *keysets, size_t count, const char *unit) {
    for (size_t i = 0; i < count; i++)
        if (keysets[i].unit && strcmp(keysets[i].unit, unit) == 0 && keysets[i].active)
            return &keysets[i];
    return NULL;
}

// find pubkey hex for a given amount in a keyset, or NULL
static const char *find_pubkey(const keyset_t *ks, uint64_t amount) {
    for (size_t i = 0; i < ks->key_count; i++)
        if (ks->keys[i].amount == amount) return ks->keys[i].pubkey;
    return NULL;
}

// mint a single proof with sat unit on MINT_URL.
// waits for testnut to auto-pay (~6s) caller must free proof.id and proof.secret.
static cashu_err_t mint_proof(uint64_t amount, proof_t *out) {
    mint_quote_t quote;
    cashu_err_t err = cashu_mint_quote(MINT_URL, amount, "sat", &quote);
    if (err != CASHU_OK) return err;

    printf("  (waiting 6s for testnut to auto-pay %llu sat...)\n",
           (unsigned long long)amount);
    sleep(6);

    mint_quote_t q2;
    err = cashu_mint_quote_state(MINT_URL, quote.quote, &q2);
    if (err != CASHU_OK || strcmp(q2.state, "PAID") != 0) {
        mint_quote_free(&quote); mint_quote_free(&q2);
        return CASHU_ERR_PROTOCOL;
    }
    mint_quote_free(&q2);

    keyset_t *keysets = NULL; size_t ks_count = 0;
    err = cashu_get_keys(MINT_URL, &keysets, &ks_count);
    if (err != CASHU_OK) { mint_quote_free(&quote); return err; }

    keyset_t *ks = find_active_keyset(keysets, ks_count, "sat");
    const char *A_hex = ks ? find_pubkey(ks, amount) : NULL;

    if (!ks || !A_hex) {
        err = CASHU_ERR_PROTOCOL; goto cleanup_keys;
    }

    char B_hex[67]; uint8_t secret[32], r[32]; char secret_hex[65];
    err = make_output(amount, ks, B_hex, secret, r, secret_hex);
    if (err != CASHU_OK) goto cleanup_keys;

    blinded_message_t output = { .amount = amount, .id = ks->id, .B_ = B_hex };
    blind_signature_t *sigs = NULL; size_t sig_count = 0;
    err = cashu_mint(MINT_URL, quote.quote, &output, 1, &sigs, &sig_count);
    if (err != CASHU_OK || sig_count != 1) {
        err = (err != CASHU_OK) ? err : CASHU_ERR_PROTOCOL; goto cleanup_keys;
    }

    err = do_unblind(sigs[0].C_, r, A_hex, out->C);
    if (err == CASHU_OK) {
        out->amount = amount;
        out->id     = strdup(ks->id);
        out->secret = strdup(secret_hex);
        if (!out->id || !out->secret) err = CASHU_ERR_OOM;
    }

    free(sigs[0].id); free(sigs[0].C_); free(sigs);
cleanup_keys:
    for (size_t i = 0; i < ks_count; i++) keyset_free(&keysets[i]);
    free(keysets);
    mint_quote_free(&quote);
    return err;
}


static void test_get_keysets(void) {
    keyset_t *ks = NULL; size_t count = 0;
    cashu_err_t err = cashu_get_keysets(MINT_URL, &ks, &count);
    ASSERT(err == CASHU_OK, "get_keysets: returns OK");
    ASSERT(count > 0,       "get_keysets: at least one keyset");
    if (err == CASHU_OK && count > 0) {
        ASSERT(ks[0].id != NULL,   "get_keysets: id not NULL");
        ASSERT(ks[0].unit != NULL, "get_keysets: unit not NULL");
    }
    for (size_t i = 0; i < count; i++) keyset_free(&ks[i]);
    free(ks);
}

static void test_get_keys(void) {
    keyset_t *ks = NULL; size_t count = 0;
    cashu_err_t err = cashu_get_keys(MINT_URL, &ks, &count);
    ASSERT(err == CASHU_OK,         "get_keys: returns OK");
    ASSERT(count > 0,               "get_keys: at least one keyset");
    if (err == CASHU_OK && count > 0)
        ASSERT(ks[0].key_count > 0, "get_keys: has keys");
    for (size_t i = 0; i < count; i++) keyset_free(&ks[i]);
    free(ks);
}

static void test_mint(void) {
    proof_t p;
    cashu_err_t err = mint_proof(1, &p);
    ASSERT(err == CASHU_OK,      "mint: proof minted OK");
    ASSERT(p.amount == 1,        "mint: amount correct");
    ASSERT(p.id     != NULL,     "mint: id not NULL");
    ASSERT(p.secret != NULL,     "mint: secret not NULL");
    if (err == CASHU_OK) { free(p.id); free(p.secret); }
}

#define SWAP_MINT_AMOUNT 16
#define MAX_SWAP_OUTPUTS 16

static void test_swap(void) {
    proof_t input;
    cashu_err_t err = mint_proof(SWAP_MINT_AMOUNT, &input);
    ASSERT(err == CASHU_OK, "swap: mint 16-sat input OK");
    if (err != CASHU_OK) return;

    // fee for input's keyset (per proof)
    keyset_t *fee_ks = NULL; size_t fee_count = 0;
    cashu_get_keysets(MINT_URL, &fee_ks, &fee_count);
    uint64_t fee_ppk = 0;
    for (size_t i = 0; i < fee_count; i++)
        if (strcmp(fee_ks[i].id, input.id) == 0) fee_ppk += fee_ks[i].input_fee_ppk;
    uint64_t fee = (fee_ppk + 999) / 1000;

    uint64_t out_total = input.amount - fee;
    printf("  (input=%llu fee=%llu out_total=%llu)\n",
           (unsigned long long)input.amount, (unsigned long long)fee,
           (unsigned long long)out_total);
    if (out_total == 0) {
        printf("  (fee >= amount, skipping swap body)\n");
        goto cleanup_fee;
    }

    // decompose out_total into power-of-2 denominations (largest first)
    uint64_t amounts[MAX_SWAP_OUTPUTS];
    size_t   out_n = 0;
    uint64_t rem = out_total;
    for (int bit = 13; bit >= 0 && rem > 0; bit--) {
        uint64_t denom = (uint64_t)1 << bit;
        while (rem >= denom && out_n < MAX_SWAP_OUTPUTS) {
            amounts[out_n++] = denom;
            rem -= denom;
        }
    }
    ASSERT(rem == 0, "swap: out_total decomposed exactly");

    // fetch keys
    keyset_t *keysets = NULL; size_t ks_count = 0;
    cashu_get_keys(MINT_URL, &keysets, &ks_count);
    keyset_t *ks = find_active_keyset(keysets, ks_count, "sat");
    ASSERT(ks != NULL, "swap: active sat keyset found");
    if (!ks) goto cleanup_keys;

    // build blinded outputs
    char              B_hexes[MAX_SWAP_OUTPUTS][67];
    uint8_t           secrets[MAX_SWAP_OUTPUTS][32];
    uint8_t           rs[MAX_SWAP_OUTPUTS][32];
    char              secret_hexes[MAX_SWAP_OUTPUTS][65];
    blinded_message_t outputs[MAX_SWAP_OUTPUTS];
    for (size_t i = 0; i < out_n; i++) {
        err = make_output(amounts[i], ks, B_hexes[i], secrets[i], rs[i], secret_hexes[i]);
        ASSERT(err == CASHU_OK, "swap: make_output OK");
        if (err != CASHU_OK) goto cleanup_keys;
        outputs[i].amount = amounts[i];
        outputs[i].id     = ks->id;
        outputs[i].B_     = B_hexes[i];
    }

    blind_signature_t *sigs = NULL; size_t sig_count = 0;
    err = cashu_swap(MINT_URL, &input, 1, outputs, out_n, &sigs, &sig_count);
    ASSERT(err == CASHU_OK,        "swap: cashu_swap OK");
    ASSERT(sig_count == out_n,     "swap: signature count matches outputs");

    if (err == CASHU_OK) {
        for (size_t i = 0; i < out_n && i < sig_count; i++) {
            const char *A_hex = find_pubkey(ks, amounts[i]);
            ASSERT(A_hex != NULL, "swap: pubkey for denomination found");
            if (!A_hex) break;
            uint8_t C[33];
            err = do_unblind(sigs[i].C_, rs[i], A_hex, C);
            ASSERT(err == CASHU_OK, "swap: unblind OK");
        }
        for (size_t i = 0; i < sig_count; i++) { free(sigs[i].id); free(sigs[i].C_); }
        free(sigs);
    }

cleanup_keys:
    for (size_t i = 0; i < ks_count; i++) keyset_free(&keysets[i]);
    free(keysets);
cleanup_fee:
    for (size_t i = 0; i < fee_count; i++) keyset_free(&fee_ks[i]);
    free(fee_ks);
    free(input.id); free(input.secret);
}

static void test_melt(void) {
    // mint 2 sat so we can cover melt amount + fee_reserve
    proof_t input;
    cashu_err_t err = mint_proof(2, &input);
    ASSERT(err == CASHU_OK, "melt: mint input OK");
    if (err != CASHU_OK) return;

    // create a 1 sat mint quote — its bolt11 is what we'll pay via melt
    mint_quote_t pay_quote;
    err = cashu_mint_quote(MINT_URL, 1, "sat", &pay_quote);
    ASSERT(err == CASHU_OK, "melt: create target bolt11 OK");
    if (err != CASHU_OK) goto cleanup_input;

    // create melt quote for that bolt11
    melt_quote_t melt_q;
    err = cashu_melt_quote(MINT_URL, pay_quote.request, "sat", &melt_q);
    ASSERT(err == CASHU_OK, "melt: melt_quote OK");
    if (err != CASHU_OK) { mint_quote_free(&pay_quote); goto cleanup_input; }

    uint64_t needed = melt_q.amount + melt_q.fee_reserve;
    ASSERT(input.amount >= needed, "melt: enough tokens for amount+fee_reserve");

    if (input.amount >= needed) {
        melt_quote_t result;
        err = cashu_melt(MINT_URL, melt_q.quote, &input, 1, &result);
        ASSERT(err == CASHU_OK,                    "melt: cashu_melt OK");
        if (err == CASHU_OK) {
            ASSERT(strcmp(result.state, "PAID") == 0, "melt: state PAID");
            melt_quote_free(&result);
        }
    }

    melt_quote_free(&melt_q);
    mint_quote_free(&pay_quote);
cleanup_input:
    free(input.id); free(input.secret);
}


int main(void) {
    cashu_http_init();
    crypto_init();

    printf("================= network tests (%s) =================\n", MINT_URL);
    test_get_keysets();
    test_get_keys();
    test_mint();
    test_swap();
    test_melt();

    printf("\n%d/%d passed\n", pass_count, total_count);

    crypto_free();
    cashu_http_term();
    return pass_count == total_count ? 0 : 1;
}
