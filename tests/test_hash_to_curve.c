//
// Created by d4rp4t on 20/02/2026.
//

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../cashu/protocol.h"
#include "../cashu/utils.h"
#include <secp256k1.h>

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define RESET "\033[0m"

static int run_test(const char *name, const char *msg_hex, const char *expected_hex) {
    uint8_t msg[32];
    uint8_t expected[33];
    hex_decode(msg_hex,      msg,      32);
    hex_decode(expected_hex, expected, 33);

    secp256k1_pubkey point;
    if (hash_to_curve(msg, 32, &point) != 0) {
        printf(RED "FAIL" RESET " %s: hash_to_curve returned error\n", name);
        return 0;
    }

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    uint8_t serialized[33];
    size_t ser_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, serialized, &ser_len, &point, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    if (memcmp(serialized, expected, 33) != 0) {
        printf(RED "FAIL" RESET " %s\n", name);
        printf("  expected: %s\n", expected_hex);
        printf("  got:      ");
        for (int i = 0; i < 33; i++) printf("%02x", serialized[i]);
        printf("\n");
        return 0;
    }

    printf(GREEN "PASS" RESET " %s\n", name);
    return 1;
}

int main(void) {
    crypto_init();

    int pass = 0, total = 0;

    pass += run_test("test 1",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725");
    total++;

    pass += run_test("test 2",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf");
    total++;

    pass += run_test("test 3 (multiple iterations)",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f");
    total++;

    crypto_free();

    printf("\n%d/%d passed\n", pass, total);
    return pass == total ? 0 : 1;
}
