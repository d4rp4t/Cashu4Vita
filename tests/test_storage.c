//
// Created by d4rp4t on 21/02/2026.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "testing_utils.h"
#include "../abstractions/storage.h"
#include "../cashu/models.h"
#include "../cashu/errors.h"

static int pass_count  = 0;
static int total_count = 0;

#define TEST_PATH "/tmp/test_proofs.json"

static proof_t make_proof(uint64_t amount, const char *id, const char *secret) {
    proof_t p;
    p.amount = amount;
    p.id     = (char *)id;
    p.secret = (char *)secret;
    memset(p.C, 0x02, 33);
    return p;
}

static void setup(void) {
    remove(TEST_PATH);
    remove(TEST_PATH ".tmp");
    storage_term();
    storage_init(TEST_PATH);
}

static void test_save_and_get(void) {
    setup();

    proof_t p = make_proof(8, "009a1f293253e41e", "secret_abc");
    cashu_err_t err = storage_save_proof(&p, "https://mint.example");
    ASSERT(err == CASHU_OK, "save_proof: returns OK");

    proof_t *out = NULL;
    size_t count = 0;
    err = storage_get_proofs("009a1f293253e41e", &out, &count);
    ASSERT(err == CASHU_OK,  "get_proofs: returns OK");
    ASSERT(count == 1,       "get_proofs: count == 1");

    if (count == 1) {
        ASSERT(out[0].amount == 8,                           "get_proofs: amount");
        ASSERT(strcmp(out[0].secret, "secret_abc") == 0,    "get_proofs: secret");
        ASSERT(strcmp(out[0].id, "009a1f293253e41e") == 0,  "get_proofs: id");
        proof_free(&out[0]);
    }
    free(out);
}

static void test_get_by_keyset_id(void) {
    setup();

    proof_t a = make_proof(1, "keyset_aaa", "sec_a1");
    proof_t b = make_proof(2, "keyset_aaa", "sec_a2");
    proof_t c = make_proof(4, "keyset_bbb", "sec_b1");

    storage_save_proof(&a, "https://mint.example");
    storage_save_proof(&b, "https://mint.example");
    storage_save_proof(&c, "https://mint.example");

    proof_t *out = NULL;
    size_t count = 0;
    storage_get_proofs("keyset_aaa", &out, &count);
    ASSERT(count == 2, "get_by_keyset_id: 2 proofs for keyset_aaa");

    storage_get_proofs("keyset_bbb", &out, &count);
    ASSERT(count == 1, "get_by_keyset_id: 1 proof for keyset_bbb");

    storage_get_proofs("keyset_nope", &out, &count);
    ASSERT(count == 0 && out == NULL, "get_by_keyset_id: 0 proofs for unknown keyset");

    for (size_t i = 0; i < count; i++) proof_free(&out[i]);
    free(out);
}

static void test_remove(void) {
    setup();

    proof_t a = make_proof(1, "009a1f293253e41e", "sec_x");
    proof_t b = make_proof(2, "009a1f293253e41e", "sec_y");
    storage_save_proof(&a, "https://mint.example");
    storage_save_proof(&b, "https://mint.example");

    cashu_err_t err = storage_remove_proofs(&a, 1);
    ASSERT(err == CASHU_OK, "remove_proofs: returns OK");

    proof_t *out = NULL;
    size_t count = 0;
    storage_get_proofs("009a1f293253e41e", &out, &count);
    ASSERT(count == 1, "remove_proofs: 1 proof left");
    if (count == 1)
        ASSERT(strcmp(out[0].secret, "sec_y") == 0, "remove_proofs: correct proof remains");

    for (size_t i = 0; i < count; i++) proof_free(&out[i]);
    free(out);
}

static void test_swap(void) {
    setup();

    proof_t old1 = make_proof(4, "009a1f293253e41e", "old_sec_1");
    proof_t old2 = make_proof(4, "009a1f293253e41e", "old_sec_2");
    storage_save_proof(&old1, "https://mint.example");
    storage_save_proof(&old2, "https://mint.example");

    proof_t spent[2] = { old1, old2 };
    proof_t fresh[1];
    fresh[0] = make_proof(8, "009a1f293253e41e", "new_sec_1");
    memset(fresh[0].C, 0x03, 33);

    cashu_err_t err = storage_swap(spent, 2, fresh, 1, "https://mint.example");
    ASSERT(err == CASHU_OK, "swap: returns OK");

    proof_t *out = NULL;
    size_t count = 0;
    storage_get_proofs("009a1f293253e41e", &out, &count);
    ASSERT(count == 1, "swap: 1 fresh proof");
    if (count == 1) {
        ASSERT(out[0].amount == 8,                           "swap: fresh amount");
        ASSERT(strcmp(out[0].secret, "new_sec_1") == 0,     "swap: fresh secret");
    }

    for (size_t i = 0; i < count; i++) proof_free(&out[i]);
    free(out);
}

static void test_persistence(void) {
    remove(TEST_PATH);
    remove(TEST_PATH ".tmp");
    storage_term();
    storage_init(TEST_PATH);

    proof_t p = make_proof(16, "009a1f293253e41e", "persistent_secret");
    storage_save_proof(&p, "https://mint.example");

        storage_term();
    cashu_err_t err = storage_init(TEST_PATH);
    ASSERT(err == CASHU_OK, "persistence: reinit returns OK");

    proof_t *out = NULL;
    size_t count = 0;
    storage_get_proofs("009a1f293253e41e", &out, &count);
    ASSERT(count == 1, "persistence: proof survives reinit");
    if (count == 1)
        ASSERT(strcmp(out[0].secret, "persistent_secret") == 0,
               "persistence: secret intact");

    for (size_t i = 0; i < count; i++) proof_free(&out[i]);
    free(out);
}

int main(void) {
    printf("================= storage tests =================\n");
    test_save_and_get();
    test_get_by_keyset_id();
    test_remove();
    test_swap();
    test_persistence();

    printf("\n%d/%d passed\n", pass_count, total_count);

    storage_term();
    remove(TEST_PATH);
    return pass_count == total_count ? 0 : 1;
}
