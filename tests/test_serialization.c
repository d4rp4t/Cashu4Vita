//
// Created by d4rp4t on 20/02/2026.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "testing_utils.h"
#include "../cashu/encoding.h"
#include "../cashu/models.h"
#include "../cashu/errors.h"
#include "../cashu/utils.h"

#define KNOWN_TOKEN \
    "cashuBo2F0gqJhaUgA_9SLj17PgGFwgaNhYQFhc3hAYWNjMTI0MzVlN2I4NDg0YzNjZj" \
    "E4NTAxNDkyMThhZjkwZjcxNmE1MmJmNGE1ZWQzNDdlNDhlY2MxM2Y3NzM4OGFjWCECRF" \
    "ODGd5IXVW-07KaZCvuWHk3WrnnpiDhHki6SCQh88-iYWlIAK0mjE0fWCZhcIKjYWECYX" \
    "N4QDEzMjNkM2Q0NzA3YTU4YWQyZTIzYWRhNGU5ZjFmNDlmNWE1YjRhYzdiNzA4ZWIwZD" \
    "YxZjczOGY0ODMwN2U4ZWVhY1ghAjRWqhENhLSsdHrr2Cw7AFrKUL9Ffr1XN6RBT6w659" \
    "lNo2FhAWFzeEA1NmJjYmNiYjdjYzY0MDZiM2ZhNWQ1N2QyMTc0ZjRlZmY4YjQ0MDJiMT" \
    "c2OTI2ZDNhNTdkM2MzZGNiYjU5ZDU3YWNYIQJzEpxXGeWZN5qXSmJjY8MzxWyvwObQGr" \
    "5G1YCCgHicY2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3NhdA"


static int pass_count = 0;
static int total_count = 0;


// ============== helpers =========================

static token_t make_token(void) {
    token_t t;
    t.mint_url    = "https://mint.example.com";
    t.unit        = "sat";
    t.memo        = NULL;
    t.proof_count = 3;
    t.proofs      = calloc(3, sizeof(proof_t));

    // two proofs sharing keyset 00ffd48b8f5ecf80
    t.proofs[0].amount = 1;
    t.proofs[0].id     = "00ffd48b8f5ecf80";
    t.proofs[0].secret = "secret_a";
    memset(t.proofs[0].C, 0x02, 33);

    t.proofs[1].amount = 2;
    t.proofs[1].id     = "00ffd48b8f5ecf80";
    t.proofs[1].secret = "secret_b";
    memset(t.proofs[1].C, 0x03, 33);

    // one proof in a different keyset
    t.proofs[2].amount = 8;
    t.proofs[2].id     = "00ad268c4d1f5826";
    t.proofs[2].secret = "secret_c";
    memset(t.proofs[2].C, 0x04, 33);

    return t;
}

static void test_bad_prefix(void) {
    token_t t;
    cashu_err_t err = token_decode("cashuAthisisnotvalid", &t);
    ASSERT(err == CASHU_ERR_INVALID_TOKEN, "bad prefix → CASHU_ERR_INVALID_TOKEN");

    err = token_decode("notcashu", &t);
    ASSERT(err == CASHU_ERR_INVALID_TOKEN, "garbage → CASHU_ERR_INVALID_TOKEN");
}

static void test_roundtrip(void) {
    token_t original = make_token();

    char *encoded = NULL;
    cashu_err_t err = token_encode(&original, &encoded);
    ASSERT(err == CASHU_OK,                    "roundtrip: encode returns OK");
    ASSERT(encoded != NULL,                    "roundtrip: encoded != NULL");
    ASSERT(strncmp(encoded, "cashuB", 6) == 0, "roundtrip: starts with cashuB");

    if (err != CASHU_OK) { free(original.proofs); return; }

    token_t decoded;
    err = token_decode(encoded, &decoded);
    ASSERT(err == CASHU_OK, "roundtrip: decode returns OK");

    if (err == CASHU_OK) {
        ASSERT(strcmp(original.mint_url, decoded.mint_url) == 0, "roundtrip: mint_url");
        ASSERT(strcmp(original.unit,     decoded.unit)     == 0, "roundtrip: unit");
        ASSERT(decoded.memo == NULL,                             "roundtrip: memo NULL");
        ASSERT(original.proof_count == decoded.proof_count,     "roundtrip: proof_count");

        for (size_t i = 0; i < original.proof_count && i < decoded.proof_count; i++) {
            char label[64];
            sprintf(label, "roundtrip: proof[%zu] amount", i);
            ASSERT(original.proofs[i].amount == decoded.proofs[i].amount, label);

            sprintf(label, "roundtrip: proof[%zu] id", i);
            ASSERT(strcmp(original.proofs[i].id, decoded.proofs[i].id) == 0, label);

            sprintf(label, "roundtrip: proof[%zu] secret", i);
            ASSERT(strcmp(original.proofs[i].secret, decoded.proofs[i].secret) == 0, label);

            sprintf(label, "roundtrip: proof[%zu] C", i);
            ASSERT(memcmp(original.proofs[i].C, decoded.proofs[i].C, 33) == 0, label);
        }

        token_free(&decoded);
    }

    free(encoded);
    free(original.proofs);
}

static void test_memo_roundtrip(void) {
    token_t original = make_token();
    original.memo = "test memo";

    char *encoded = NULL;
    cashu_err_t err = token_encode(&original, &encoded);
    ASSERT(err == CASHU_OK, "memo: encode OK");

    if (err == CASHU_OK) {
        token_t decoded;
        err = token_decode(encoded, &decoded);
        ASSERT(err == CASHU_OK, "memo: decode OK");

        if (err == CASHU_OK) {
            ASSERT(decoded.memo != NULL, "memo: not NULL after decode");
            ASSERT(decoded.memo != NULL &&
                   strcmp(original.memo, decoded.memo) == 0, "memo: value matches");
            token_free(&decoded);
        }
        free(encoded);
    }

    free(original.proofs);
}

static void test_decode_known(void) {
    token_t t;
    cashu_err_t err = token_decode(KNOWN_TOKEN, &t);
    ASSERT(err == CASHU_OK, "known: decode OK");
    if (err != CASHU_OK) return;

    ASSERT(strcmp(t.mint_url, "http://localhost:3338") == 0, "known: mint_url");
    ASSERT(strcmp(t.unit, "sat") == 0,                       "known: unit");
    ASSERT(t.memo == NULL,                                   "known: memo NULL");
    ASSERT(t.proof_count == 3,                               "known: proof_count == 3");
    if (t.proof_count != 3) { token_free(&t); return; }

    uint8_t expected_C[3][33];
    hex_decode("0244538319de485d55bed3b29a642bee5879375ab9e7a620e11e48ba482421f3cf",
               expected_C[0], 33);
    hex_decode("023456aa110d84b4ac747aebd82c3b005aca50bf457ebd5737a4414fac3ae7d94d",
               expected_C[1], 33);
    hex_decode("0273129c5719e599379a974a626363c333c56cafc0e6d01abe46d5808280789c63",
               expected_C[2], 33);

    // proof[0]
    ASSERT(t.proofs[0].amount == 1,                                      "known: proof[0] amount");
    ASSERT(strcmp(t.proofs[0].id, "00ffd48b8f5ecf80") == 0,             "known: proof[0] id");
    ASSERT(strcmp(t.proofs[0].secret,
        "acc12435e7b8484c3cf1850149218af90f716a52bf4a5ed347e48ecc13f77388") == 0,
        "known: proof[0] secret");
    ASSERT(memcmp(t.proofs[0].C, expected_C[0], 33) == 0,               "known: proof[0] C");

    // proof[1]
    ASSERT(t.proofs[1].amount == 2,                                      "known: proof[1] amount");
    ASSERT(strcmp(t.proofs[1].id, "00ad268c4d1f5826") == 0,             "known: proof[1] id");
    ASSERT(strcmp(t.proofs[1].secret,
        "1323d3d4707a58ad2e23ada4e9f1f49f5a5b4ac7b708eb0d61f738f48307e8ee") == 0,
        "known: proof[1] secret");
    ASSERT(memcmp(t.proofs[1].C, expected_C[1], 33) == 0,               "known: proof[1] C");

    // proof[2]
    ASSERT(t.proofs[2].amount == 1,                                      "known: proof[2] amount");
    ASSERT(strcmp(t.proofs[2].id, "00ad268c4d1f5826") == 0,             "known: proof[2] id");
    ASSERT(strcmp(t.proofs[2].secret,
        "56bcbcbb7cc6406b3fa5d57d2174f4eff8b4402b176926d3a57d3c3dcbb59d57") == 0,
        "known: proof[2] secret");
    ASSERT(memcmp(t.proofs[2].C, expected_C[2], 33) == 0,               "known: proof[2] C");

    token_free(&t);
}

static void test_reencode(void) {
    token_t t;
    cashu_err_t err = token_decode(KNOWN_TOKEN, &t);
    if (err != CASHU_OK) { ASSERT(0, "reencode: decode failed"); return; }

    char *encoded = NULL;
    err = token_encode(&t, &encoded);
    ASSERT(err == CASHU_OK, "reencode: encode OK");

    if (err == CASHU_OK) {
        ASSERT(strcmp(encoded, KNOWN_TOKEN) == 0, "reencode: output == input");
        free(encoded);
    }

    token_free(&t);
}

int main(void) {
    printf("====================== bad prefix =======================\n");
    test_bad_prefix();

    printf("====================== roundtrip =======================\n");
    test_roundtrip();

    printf("====================== roundtrip ======================= \n");
    test_memo_roundtrip();

    printf("================== known token decode ===================\n");
    test_decode_known();

    printf("================= known token re-encode =================\n");
    test_reencode();

    printf("\n%d/%d passed\n", pass_count, total_count);
    return pass_count == total_count ? 0 : 1;
}
