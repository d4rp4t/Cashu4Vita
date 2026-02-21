//
// Created by d4rp4t on 21/02/2026.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cJSON.h>

#include "testing_utils.h"
#include "../cashu/json.h"
#include "../cashu/models.h"
#include "../cashu/errors.h"

static int pass_count  = 0;
static int total_count = 0;


static void test_mint_quote_request(void) {
    char *json = json_mint_quote_request(10, "sat");
    ASSERT(json != NULL, "mint_quote_request: not NULL");
    if (!json) return;

    cJSON *root = cJSON_Parse(json);
    ASSERT(root != NULL, "mint_quote_request: valid JSON");
    if (root) {
        cJSON *amount = cJSON_GetObjectItemCaseSensitive(root, "amount");
        cJSON *unit   = cJSON_GetObjectItemCaseSensitive(root, "unit");
        ASSERT(cJSON_IsNumber(amount) && amount->valuedouble == 10.0,
               "mint_quote_request: amount == 10");
        ASSERT(cJSON_IsString(unit) && strcmp(unit->valuestring, "sat") == 0,
               "mint_quote_request: unit == sat");
        cJSON_Delete(root);
    }
    free(json);
}

static void test_mint_request(void) {
    blinded_message_t  outputs[2] = {
        {.amount = 1, .id = "009a1f293253e41e", .B_ = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"},
        {.amount = 2, .id = "009a1f293253e41e", .B_ = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba3"},
    };
    char *json = json_mint_request("quote-abc", outputs, 2);
    ASSERT(json != NULL, "mint_request: not NULL");
    if (!json) return;

    cJSON *root = cJSON_Parse(json);
    ASSERT(root != NULL, "mint_request: valid JSON");
    if (root) {
        cJSON *quote = cJSON_GetObjectItemCaseSensitive(root, "quote");
        cJSON *arr   = cJSON_GetObjectItemCaseSensitive(root, "outputs");
        ASSERT(cJSON_IsString(quote) && strcmp(quote->valuestring, "quote-abc") == 0,
               "mint_request: quote field");
        ASSERT(cJSON_IsArray(arr) && cJSON_GetArraySize(arr) == 2,
               "mint_request: 2 outputs");
        if (cJSON_IsArray(arr)) {
            cJSON *first = cJSON_GetArrayItem(arr, 0);
            cJSON *amt   = cJSON_GetObjectItemCaseSensitive(first, "amount");
            cJSON *id    = cJSON_GetObjectItemCaseSensitive(first, "id");
            cJSON *B_    = cJSON_GetObjectItemCaseSensitive(first, "B_");
            ASSERT(cJSON_IsNumber(amt) && amt->valuedouble == 1.0,
                   "mint_request: outputs[0].amount");
            ASSERT(cJSON_IsString(id) && strcmp(id->valuestring, "009a1f293253e41e") == 0,
                   "mint_request: outputs[0].id");
            ASSERT(cJSON_IsString(B_), "mint_request: outputs[0].B_ present");
        }
        cJSON_Delete(root);
    }
    free(json);
}

static void test_melt_quote_request(void) {
    char *json = json_melt_quote_request("lnbc10n1pjtest", "sat");
    ASSERT(json != NULL, "melt_quote_request: not NULL");
    if (!json) return;

    cJSON *root = cJSON_Parse(json);
    ASSERT(root != NULL, "melt_quote_request: valid JSON");
    if (root) {
        cJSON *req  = cJSON_GetObjectItemCaseSensitive(root, "request");
        cJSON *unit = cJSON_GetObjectItemCaseSensitive(root, "unit");
        ASSERT(cJSON_IsString(req) && strcmp(req->valuestring, "lnbc10n1pjtest") == 0,
               "melt_quote_request: request field");
        ASSERT(cJSON_IsString(unit) && strcmp(unit->valuestring, "sat") == 0,
               "melt_quote_request: unit field");
        cJSON_Delete(root);
    }
    free(json);
}

static void test_melt_request(void) {
    proof_t input;
    input.amount = 8;
    input.id     = "00ffd48b8f5ecf80";
    input.secret = "my_secret";
    memset(input.C, 0x02, 33);

    char *json = json_melt_request("melt-quote-id", &input, 1);
    ASSERT(json != NULL, "melt_request: not NULL");
    if (!json) return;

    cJSON *root = cJSON_Parse(json);
    ASSERT(root != NULL, "melt_request: valid JSON");
    if (root) {
        cJSON *quote  = cJSON_GetObjectItemCaseSensitive(root, "quote");
        cJSON *inputs = cJSON_GetObjectItemCaseSensitive(root, "inputs");
        ASSERT(cJSON_IsString(quote) && strcmp(quote->valuestring, "melt-quote-id") == 0,
               "melt_request: quote field");
        ASSERT(cJSON_IsArray(inputs) && cJSON_GetArraySize(inputs) == 1,
               "melt_request: 1 input");
        if (cJSON_IsArray(inputs)) {
            cJSON *p   = cJSON_GetArrayItem(inputs, 0);
            cJSON *amt = cJSON_GetObjectItemCaseSensitive(p, "amount");
            cJSON *id  = cJSON_GetObjectItemCaseSensitive(p, "id");
            cJSON *sec = cJSON_GetObjectItemCaseSensitive(p, "secret");
            cJSON *C   = cJSON_GetObjectItemCaseSensitive(p, "C");
            ASSERT(cJSON_IsNumber(amt) && amt->valuedouble == 8.0,
                   "melt_request: input.amount");
            ASSERT(cJSON_IsString(id) && strcmp(id->valuestring, "00ffd48b8f5ecf80") == 0,
                   "melt_request: input.id");
            ASSERT(cJSON_IsString(sec) && strcmp(sec->valuestring, "my_secret") == 0,
                   "melt_request: input.secret");
            ASSERT(cJSON_IsString(C), "melt_request: input.C present");
        }
        cJSON_Delete(root);
    }
    free(json);
}

static void test_swap_request(void) {
    proof_t inputs[2];
    inputs[0].amount = 4;
    inputs[0].id     = "00ffd48b8f5ecf80";
    inputs[0].secret = "sec_a";
    memset(inputs[0].C, 0x02, 33);
    inputs[1].amount = 4;
    inputs[1].id     = "00ffd48b8f5ecf80";
    inputs[1].secret = "sec_b";
    memset(inputs[1].C, 0x03, 33);

    blinded_message_t outputs[1] = {
        {.amount = 8, .id = "009a1f293253e41e", .B_ = "02aabbcc"},
    };

    char *json = json_swap_request(inputs, 2, outputs, 1);
    ASSERT(json != NULL, "swap_request: not NULL");
    if (!json) return;

    cJSON *root = cJSON_Parse(json);
    ASSERT(root != NULL, "swap_request: valid JSON");
    if (root) {
        cJSON *in_arr  = cJSON_GetObjectItemCaseSensitive(root, "inputs");
        cJSON *out_arr = cJSON_GetObjectItemCaseSensitive(root, "outputs");
        ASSERT(cJSON_IsArray(in_arr)  && cJSON_GetArraySize(in_arr)  == 2,
               "swap_request: 2 inputs");
        ASSERT(cJSON_IsArray(out_arr) && cJSON_GetArraySize(out_arr) == 1,
               "swap_request: 1 output");
        cJSON_Delete(root);
    }
    free(json);
}

// ===================== response parsers ====================================

static void test_parse_mint_quote(void) {
    const char *resp =
        "{\"quote\":\"9d745270-abc\",\"request\":\"lnbc10n1pjtest\","
        "\"state\":\"UNPAID\",\"expiry\":1701704757}";

    mint_quote_t q;
    cashu_err_t err = json_parse_mint_quote(resp, &q);
    ASSERT(err == CASHU_OK, "parse_mint_quote: returns OK");
    if (err != CASHU_OK) return;

    ASSERT(strcmp(q.quote,   "9d745270-abc") == 0,  "parse_mint_quote: quote");
    ASSERT(strcmp(q.request, "lnbc10n1pjtest") == 0, "parse_mint_quote: request");
    ASSERT(strcmp(q.state,   "UNPAID") == 0,         "parse_mint_quote: state");
    ASSERT(q.expiry == 1701704757u,                  "parse_mint_quote: expiry");
    mint_quote_free(&q);
}

static void test_parse_mint_quote_errors(void) {
    mint_quote_t q;

    cashu_err_t err = json_parse_mint_quote("{\"quote\":\"abc\",\"request\":\"x\"}", &q);
    ASSERT(err == CASHU_ERR_JSON_MISSING,
           "parse_mint_quote: missing state → ERR_JSON_MISSING");

    err = json_parse_mint_quote("not json at all", &q);
    ASSERT(err == CASHU_ERR_JSON_PARSE,
           "parse_mint_quote: invalid JSON → ERR_JSON_PARSE");
}

static void test_parse_melt_quote(void) {
    const char *resp =
        "{\"quote\":\"melt-xyz\",\"amount\":10,\"fee_reserve\":2,"
        "\"state\":\"UNPAID\"}";

    melt_quote_t q;
    cashu_err_t err = json_parse_melt_quote(resp, &q);
    ASSERT(err == CASHU_OK, "parse_melt_quote: returns OK");
    if (err != CASHU_OK) return;

    ASSERT(strcmp(q.quote, "melt-xyz") == 0, "parse_melt_quote: quote");
    ASSERT(q.amount       == 10,             "parse_melt_quote: amount");
    ASSERT(q.fee_reserve  == 2,              "parse_melt_quote: fee_reserve");
    ASSERT(strcmp(q.state, "UNPAID") == 0,   "parse_melt_quote: state");
    ASSERT(q.payment_preimage == NULL,       "parse_melt_quote: preimage NULL");
    melt_quote_free(&q);
}

static void test_parse_melt_quote_with_preimage(void) {
    const char *resp =
        "{\"quote\":\"melt-xyz\",\"amount\":10,\"fee_reserve\":2,"
        "\"state\":\"PAID\",\"payment_preimage\":\"deadbeef\"}";

    melt_quote_t q;
    cashu_err_t err = json_parse_melt_quote(resp, &q);
    ASSERT(err == CASHU_OK, "parse_melt_quote+preimage: returns OK");
    if (err != CASHU_OK) return;

    ASSERT(q.payment_preimage != NULL &&
           strcmp(q.payment_preimage, "deadbeef") == 0,
           "parse_melt_quote+preimage: preimage value");
    melt_quote_free(&q);
}

static void test_parse_signatures(void) {
    const char *resp =
        "{\"signatures\":["
        "{\"amount\":1,\"id\":\"00ffd48b8f5ecf80\",\"C_\":\"02abcd\"},"
        "{\"amount\":2,\"id\":\"00ffd48b8f5ecf80\",\"C_\":\"03ef01\"}"
        "]}";

    blind_signature_t *sigs = NULL;
    size_t count = 0;
    cashu_err_t err = json_parse_signatures(resp, &sigs, &count);
    ASSERT(err == CASHU_OK, "parse_signatures: returns OK");
    ASSERT(count == 2,      "parse_signatures: count == 2");

    if (err == CASHU_OK && count == 2) {
        ASSERT(sigs[0].amount == 1, "parse_signatures: sigs[0].amount");
        ASSERT(sigs[0].id != NULL && strcmp(sigs[0].id, "00ffd48b8f5ecf80") == 0,
               "parse_signatures: sigs[0].id");
        ASSERT(sigs[0].C_ != NULL && strcmp(sigs[0].C_, "02abcd") == 0,
               "parse_signatures: sigs[0].C_");
        ASSERT(sigs[1].amount == 2, "parse_signatures: sigs[1].amount");

        for (size_t i = 0; i < count; i++) {
            free(sigs[i].id);
            free(sigs[i].C_);
        }
        free(sigs);
    }
}

static void test_parse_signatures_errors(void) {
    blind_signature_t *sigs = NULL;
    size_t count = 0;

    cashu_err_t err = json_parse_signatures("{\"other\":[]}", &sigs, &count);
    ASSERT(err == CASHU_ERR_JSON_MISSING,
           "parse_signatures: missing 'signatures' → ERR_JSON_MISSING");

    err = json_parse_signatures("bad json", &sigs, &count);
    ASSERT(err == CASHU_ERR_JSON_PARSE,
           "parse_signatures: invalid JSON → ERR_JSON_PARSE");
}

static void test_parse_keys(void) {
    const char *resp =
        "{\"keysets\":[{"
        "\"id\":\"009a1f293253e41e\","
        "\"unit\":\"sat\","
        "\"active\":true,"
        "\"keys\":{"
        "\"1\":\"02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2\","
        "\"2\":\"020000000000000000000000000000000000000000000000000000000000000001\","
        "\"4\":\"02f9b40f35e2c8e92d73f876dfe8b06ef85f0df12a37d78c2f37c8a52f5f671a9b\","
        "\"8\":\"038b0bae30c8e37ba2cfd3d4a0a8b9e7b23d63f3a1e6e3c67a1b9b48f82a5c9e31\""
        "}}]}";

    keyset_t *ks = NULL;
    size_t count = 0;
    cashu_err_t err = json_parse_keys(resp, &ks, &count);
    ASSERT(err == CASHU_OK, "parse_keys: returns OK");
    ASSERT(count == 1,      "parse_keys: 1 keyset");

    if (err == CASHU_OK && count == 1) {
        ASSERT(strcmp(ks[0].id,   "009a1f293253e41e") == 0, "parse_keys: id");
        ASSERT(strcmp(ks[0].unit, "sat") == 0,              "parse_keys: unit");
        ASSERT(ks[0].active    == 1,                        "parse_keys: active true");
        ASSERT(ks[0].key_count == 4,                        "parse_keys: 4 keys");

        int found_1 = 0, found_8 = 0;
        for (size_t i = 0; i < ks[0].key_count; i++) {
            if (ks[0].keys[i].amount == 1) {
                ASSERT(strcmp(ks[0].keys[i].pubkey,
                    "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2") == 0,
                    "parse_keys: key[1].pubkey");
                found_1 = 1;
            }
            if (ks[0].keys[i].amount == 8) {
                found_8 = 1;
            }
        }
        ASSERT(found_1, "parse_keys: found key for amount 1");
        ASSERT(found_8, "parse_keys: found key for amount 8");

        keyset_free(&ks[0]);
        free(ks);
    }
}

static void test_parse_keysets(void) {
    const char *resp =
        "{\"keysets\":["
        "{\"id\":\"009a1f293253e41e\",\"unit\":\"sat\",\"active\":true},"
        "{\"id\":\"00ffd48b8f5ecf80\",\"unit\":\"sat\",\"active\":false}"
        "]}";

    keyset_t *ks = NULL;
    size_t count = 0;
    cashu_err_t err = json_parse_keysets(resp, &ks, &count);
    ASSERT(err == CASHU_OK, "parse_keysets: returns OK");
    ASSERT(count == 2,      "parse_keysets: 2 keysets");

    if (err == CASHU_OK && count == 2) {
        ASSERT(strcmp(ks[0].id, "009a1f293253e41e") == 0, "parse_keysets: ks[0].id");
        ASSERT(ks[0].active == 1,                         "parse_keysets: ks[0].active true");
        ASSERT(strcmp(ks[1].id, "00ffd48b8f5ecf80") == 0, "parse_keysets: ks[1].id");
        ASSERT(ks[1].active == 0,                         "parse_keysets: ks[1].active false");
        ASSERT(ks[0].keys == NULL && ks[0].key_count == 0,"parse_keysets: ks[0] no keys");
        ASSERT(ks[1].keys == NULL && ks[1].key_count == 0,"parse_keysets: ks[1] no keys");

        for (size_t i = 0; i < count; i++) keyset_free(&ks[i]);
        free(ks);
    }
}


int main(void) {
    printf("================= request builders =================\n");
    test_mint_quote_request();
    test_mint_request();
    test_melt_quote_request();
    test_melt_request();
    test_swap_request();

    printf("================= response parsers =================\n");
    test_parse_mint_quote();
    test_parse_mint_quote_errors();
    test_parse_melt_quote();
    test_parse_melt_quote_with_preimage();
    test_parse_signatures();
    test_parse_signatures_errors();

    printf("================= keyset parsers ==================\n");
    test_parse_keys();
    test_parse_keysets();

    printf("\n%d/%d passed\n", pass_count, total_count);
    return pass_count == total_count ? 0 : 1;
}
