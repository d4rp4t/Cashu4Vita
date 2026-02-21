//
// Created by d4rp4t on 20/02/2026.
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../cashu/protocol.h"
#include "../cashu/utils.h"
#include <secp256k1.h>

#include "testing_utils.h"

static secp256k1_context *test_ctx;

static int run_test(const char *name, const char *x_hex, const char *r_hex, const char *expected_hex) {
    uint8_t x[32], r[32], expected[33];
    hex_decode(x_hex,        x,        32);
    hex_decode(r_hex,        r,        32);
    hex_decode(expected_hex, expected, 33);

    secp256k1_pubkey Y;
    if (hash_to_curve(x, 32, &Y) != 0) {
        printf(RED "FAIL" RESET " %s: hash_to_curve error\n", name);
        return 0;
    }

    secp256k1_pubkey B_;
    if (blind(&Y, r, &B_) != 0) {
        printf(RED "FAIL" RESET " %s: blind error\n", name);
        return 0;
    }

    uint8_t serialized[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(test_ctx, serialized, &len, &B_, SECP256K1_EC_COMPRESSED);

    if (memcmp(serialized, expected, 33) != 0) {
        char got_hex[67];
        pubkey_to_hex(test_ctx, &B_, got_hex);
        printf(RED "FAIL" RESET " %s\n", name);
        printf("  expected: %s\n", expected_hex);
        printf("  got:      %s\n", got_hex);
        return 0;
    }

    printf(GREEN "PASS" RESET " %s\n", name);
    return 1;
}

int main(void) {
    crypto_init();
    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    int pass = 0, total = 0;

    pass += run_test("test 1",
        "d341ee4871f1f889041e63cf0d3823c713eea6aff01e80f1719f08f9e5be98f6",
        "99fce58439fc37412ab3468b73db0569322588f62fb3a49182d67e23d877824a",
        "033b1a9737a40cc3fd9b6af4b723632b76a67a36782596304612a6c2bfb5197e6d");
    total++;

    pass += run_test("test 2",
        "f1aaf16c2239746f369572c0784d9dd3d032d952c2d992175873fb58fae31a60",
        "f78476ea7cc9ade20f9e05e58a804cf19533f03ea805ece5fee88c8e2874ba50",
        "029bdf2d716ee366eddf599ba252786c1033f47e230248a4612a5670ab931f1763");
    total++;

    secp256k1_context_destroy(test_ctx);
    crypto_free();

    printf("\n%d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}
