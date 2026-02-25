//
// Created by d4rp4t on 18/02/2026.
//
#include "protocol.h"
#include "utils.h"
#include <stdint.h>
#include <mbedtls/sha256.h>
#include <secp256k1.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "models.h"
#include "../deps/secp256k1/src/group.h"

static const char *DOMAIN_SEPARATOR = "Secp256k1_HashToCurve_Cashu_";
static secp256k1_context *ctx = NULL;

void crypto_init(void) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

void crypto_free(void) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
}

secp256k1_context *crypto_ctx(void) { return ctx; }

static int get_msg_hash(const uint8_t *msg, size_t msg_len, uint8_t *hash) {
    int ret;
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    if ((ret = mbedtls_sha256_starts(&sha, 0)) != 0) goto cleanup;
    if ((ret = mbedtls_sha256_update(&sha, (const uint8_t *)DOMAIN_SEPARATOR,
                                     strlen(DOMAIN_SEPARATOR))) != 0) goto cleanup;
    if ((ret = mbedtls_sha256_update(&sha, msg, msg_len)) != 0) goto cleanup;
    if ((ret = mbedtls_sha256_finish(&sha, hash)) != 0) goto cleanup;
    ret = 0;
cleanup:
    mbedtls_sha256_free(&sha);
    return ret;
}

cashu_err_t hash_to_curve(const uint8_t *x, size_t x_len, secp256k1_pubkey *out) {
    uint8_t msg_hash[32];
    if (get_msg_hash(x, x_len, msg_hash) != 0)
        return CASHU_ERR_HASH_TO_CURVE;

    for (uint32_t i = 0; i < UINT32_MAX; i++) {
        uint8_t point_bytes[33];
        point_bytes[0] = 0x02;

        uint8_t counter_le[4] = {
            i & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF, (i >> 24) & 0xFF,
        };

        mbedtls_sha256_context sha;
        mbedtls_sha256_init(&sha);
        mbedtls_sha256_starts(&sha, 0);
        mbedtls_sha256_update(&sha, msg_hash, 32);
        mbedtls_sha256_update(&sha, counter_le, 4);
        mbedtls_sha256_finish(&sha, point_bytes + 1);
        mbedtls_sha256_free(&sha);

        if (secp256k1_ec_pubkey_parse(ctx, out, point_bytes, 33) == 1)
            return CASHU_OK;
    }
    return CASHU_ERR_HASH_TO_CURVE;
}

cashu_err_t message_to_curve(const char *message, secp256k1_pubkey *out) {
    return hash_to_curve((const uint8_t *)message, strlen(message), out);
}

cashu_err_t hex_to_curve(const char *hex, size_t hex_len, secp256k1_pubkey *out) {
    if (hex_len % 2 != 0) return CASHU_ERR_INVALID_POINT;
    size_t bytes_len = hex_len / 2;
    uint8_t *bytes = malloc(bytes_len);
    if (!bytes) return CASHU_ERR_OOM;
    hex_decode(hex, bytes, bytes_len);
    cashu_err_t ret = hash_to_curve(bytes, bytes_len, out);
    free(bytes);
    return ret;
}

// B_ = Y + rG
cashu_err_t blind(const secp256k1_pubkey *Y, const uint8_t *r, secp256k1_pubkey *out) {
    secp256k1_pubkey rG;
    if (!secp256k1_ec_pubkey_create(ctx, &rG, r))
        return CASHU_ERR_INVALID_SCALAR;

    const secp256k1_pubkey *points[2] = { Y, &rG };
    if (!secp256k1_ec_pubkey_combine(ctx, out, points, 2))
        return CASHU_ERR_INVALID_POINT;

    return CASHU_OK;
}

// C = C_ - rA
cashu_err_t unblind(const secp256k1_pubkey *C_, const uint8_t *r,
                    const secp256k1_pubkey *A, secp256k1_pubkey *out) {
    uint8_t neg_r[32];
    memcpy(neg_r, r, 32);
    if (!secp256k1_ec_seckey_negate(ctx, neg_r))
        return CASHU_ERR_INVALID_SCALAR;

    secp256k1_pubkey rA;
    memcpy(&rA, A, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &rA, neg_r))
        return CASHU_ERR_INVALID_POINT;

    const secp256k1_pubkey *points[2] = { C_, &rA };
    if (!secp256k1_ec_pubkey_combine(ctx, out, points, 2))
        return CASHU_ERR_INVALID_POINT;

    return CASHU_OK;
}


/*
 * SHA256 of the UTF-8 string formed by concatenating the
 * lowercase hex representations of the four points serialized uncompressed
 * (65 bytes -> 130 hex chars each, total 520 chars)
 */
static cashu_err_t hash_e(secp256k1_pubkey *R1, secp256k1_pubkey *R2,
                           const secp256k1_pubkey *A, const secp256k1_pubkey *C_,
                           uint8_t out32[32]) {
    uint8_t bin[65];
    char hexbuf[131];
    size_t out_len;
    cashu_err_t ret = CASHU_ERR_INVALID_POINT;

    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);

    // cast away const for the secp256k1 serialize API (does not mutate)
    secp256k1_pubkey *keys[4] = {
        R1, R2,
        (secp256k1_pubkey *)(uintptr_t)A,
        (secp256k1_pubkey *)(uintptr_t)C_
    };

    for (int i = 0; i < 4; i++) {
        out_len = sizeof(bin);
        if (!secp256k1_ec_pubkey_serialize(ctx, bin, &out_len, keys[i],
                                           SECP256K1_EC_UNCOMPRESSED))
            goto cleanup;
        hex_encode(bin, out_len, hexbuf);
        mbedtls_sha256_update(&sha, (const uint8_t *)hexbuf, 130);
    }

    mbedtls_sha256_finish(&sha, out32);
    ret = CASHU_OK;

cleanup:
    mbedtls_sha256_free(&sha);
    return ret;
}

/*
 * verify_dleq_blind_sig - DLEQ verification for a blind signature.
 * B_, C_ - the blinded message and mint's blind signature
 * e32, s32 - 32-byte DLEQ components from the mint
 * A - mint's public key for this denomination
 */
bool verify_dleq_blind_sig(const secp256k1_pubkey *B_,
                            const secp256k1_pubkey *C_,
                            const uint8_t e32[32],
                            const uint8_t s32[32],
                            const secp256k1_pubkey *A) {
    secp256k1_pubkey sG, neg_eA, r1;
    secp256k1_pubkey sB_, neg_eC_, r2;
    uint8_t neg_e[32];
    uint8_t computed_e[32];

    memcpy(neg_e, e32, 32);
    if (!secp256k1_ec_seckey_negate(ctx, neg_e)) return false; // shouldn't happen

    // R1 = s*G - e*A
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s32)) return false;
    neg_eA = *A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_eA, neg_e)) return false;
    const secp256k1_pubkey *p1[2] = { &sG, &neg_eA };
    if (!secp256k1_ec_pubkey_combine(ctx, &r1, p1, 2)) return false;

    // R2 = s*B_ - e*C_
    sB_ = *B_;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &sB_, s32)) return false;
    neg_eC_ = *C_;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_eC_, neg_e)) return false;
    const secp256k1_pubkey *p2[2] = { &sB_, &neg_eC_ };
    if (!secp256k1_ec_pubkey_combine(ctx, &r2, p2, 2)) return false;

    if (hash_e(&r1, &r2, A, C_, computed_e) != CASHU_OK) return false;
    return memcmp(e32, computed_e, 32) == 0;
}

/*
 * verify_dleq_unblinded - verify the DLEQ proof carried by an unblinded proof
 */
bool verify_dleq_unblinded(const uint8_t C_bytes[33],
                            const uint8_t r32[32],
                            const uint8_t e32[32],
                            const uint8_t s32[32],
                            const char *secret,
                            size_t secret_len,
                            const secp256k1_pubkey *A) {
    // reconstruct C_ = C + r*A  (reverse of unblind: C = C_ - r*A)
    secp256k1_pubkey C, rA, C_;
    if (!secp256k1_ec_pubkey_parse(ctx, &C, C_bytes, 33)) return false;
    rA = *A;
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &rA, r32))    return false;
    const secp256k1_pubkey *pts[2] = { &C, &rA };
    if (!secp256k1_ec_pubkey_combine(ctx, &C_, pts, 2))   return false;

    // reconstruct B_ = Y + r*G  (Y = hash_to_curve(secret))
    secp256k1_pubkey Y, B_;
    if (hash_to_curve((const uint8_t *)secret, secret_len, &Y) != CASHU_OK) return false;
    if (blind(&Y, r32, &B_) != CASHU_OK)                  return false;

    return verify_dleq_blind_sig(&B_, &C_, e32, s32, A);
}