//
// Created by d4rp4t on 18/02/2026.
//
#include "protocol.h"
#include "utils.h"
#include <stdint.h>
#include <mbedtls/sha256.h>
#include <secp256k1.h>
#include <stdlib.h>
#include <string.h>

static const char *DOMAIN_SEPARATOR = "Secp256k1_HashToCurve_Cashu_";
static secp256k1_context *ctx = NULL;

void crypto_init(void) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

void crypto_free(void) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
}

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
