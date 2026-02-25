//
// Created by d4rp4t on 20/02/2026.
//
#include "json.h"
#include "utils.h"
#include <cJSON.h>
#include <stdlib.h>
#include <string.h>

// ===================================================================
//                         helpers
// ===================================================================

static cJSON *blinded_message_to_cjson(const blinded_message_t *bm) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "amount", (double)bm->amount);
    cJSON_AddStringToObject(obj, "id", bm->id);
    cJSON_AddStringToObject(obj, "B_", bm->B_);
    return obj;
}

static cJSON *proof_to_cjson(const proof_t *p) {
    char c_hex[67];
    hex_encode(p->C, 33, c_hex);
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "amount", (double)p->amount);
    cJSON_AddStringToObject(obj, "id", p->id);
    cJSON_AddStringToObject(obj, "secret", p->secret);
    cJSON_AddStringToObject(obj, "C", c_hex);
    if (p->has_dleq && p->dleq_e[0] && p->dleq_s[0] && p->dleq_r[0]) {
        cJSON *dleq = cJSON_CreateObject();
        cJSON_AddStringToObject(dleq, "e", p->dleq_e);
        cJSON_AddStringToObject(dleq, "s", p->dleq_s);
        cJSON_AddStringToObject(dleq, "r", p->dleq_r);
        cJSON_AddItemToObject(obj, "dleq", dleq);
    }
    return obj;
}

static char *render(cJSON *root) {
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

// ===================================================================
//                      request builders
// ===================================================================

char *json_mint_quote_request(uint64_t amount, const char *unit) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "amount", (double)amount);
    cJSON_AddStringToObject(root, "unit", unit);
    return render(root);
}

char *json_mint_request(const char *quote, const blinded_message_t *outputs, size_t count) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "quote", quote);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
        cJSON_AddItemToArray(arr, blinded_message_to_cjson(&outputs[i]));
    cJSON_AddItemToObject(root, "outputs", arr);
    return render(root);
}

char *json_melt_quote_request(const char *bolt11, const char *unit) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "request", bolt11);
    cJSON_AddStringToObject(root, "unit", unit);
    return render(root);
}

char *json_melt_request(const char *quote, const proof_t *inputs, size_t count,
                        const blinded_message_t *outputs, size_t out_n) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "quote", quote);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < count; i++)
        cJSON_AddItemToArray(arr, proof_to_cjson(&inputs[i]));
    cJSON_AddItemToObject(root, "inputs", arr);
    if (outputs && out_n > 0) {
        cJSON *out_arr = cJSON_CreateArray();
        for (size_t i = 0; i < out_n; i++)
            cJSON_AddItemToArray(out_arr, blinded_message_to_cjson(&outputs[i]));
        cJSON_AddItemToObject(root, "outputs", out_arr);
    }
    return render(root);
}

char *json_swap_request(const proof_t *inputs, size_t inp_n,
                        const blinded_message_t *outputs, size_t out_n) {
    cJSON *root = cJSON_CreateObject();
    cJSON *in_arr = cJSON_CreateArray();
    for (size_t i = 0; i < inp_n; i++)
        cJSON_AddItemToArray(in_arr, proof_to_cjson(&inputs[i]));
    cJSON_AddItemToObject(root, "inputs", in_arr);
    cJSON *out_arr = cJSON_CreateArray();
    for (size_t i = 0; i < out_n; i++)
        cJSON_AddItemToArray(out_arr, blinded_message_to_cjson(&outputs[i]));
    cJSON_AddItemToObject(root, "outputs", out_arr);
    return render(root);
}
char *json_pr_payload(const char *id, const char *memo,
                      const char *mint, const char *unit,
                      const proof_t *proofs, size_t proof_count) {
    cJSON *root = cJSON_CreateObject();
    if (id)   cJSON_AddStringToObject(root, "id",   id);
    if (memo) cJSON_AddStringToObject(root, "memo", memo);
    cJSON_AddStringToObject(root, "mint", mint);
    cJSON_AddStringToObject(root, "unit", unit);
    cJSON *arr = cJSON_CreateArray();
    for (size_t i = 0; i < proof_count; i++)
        cJSON_AddItemToArray(arr, proof_to_cjson(&proofs[i]));
    cJSON_AddItemToObject(root, "proofs", arr);
    return render(root);
}

// ===================================================================
//                      response parsers
// ===================================================================

cashu_err_t json_parse_mint_quote(const char *json, mint_quote_t *out) {
    cJSON *root = cJSON_Parse(json);
    if (!root) return CASHU_ERR_JSON_PARSE;

    cJSON *quote   = cJSON_GetObjectItemCaseSensitive(root, "quote");
    cJSON *request = cJSON_GetObjectItemCaseSensitive(root, "request");
    cJSON *state   = cJSON_GetObjectItemCaseSensitive(root, "state");
    cJSON *expiry  = cJSON_GetObjectItemCaseSensitive(root, "expiry");

    if (!cJSON_IsString(quote) || !cJSON_IsString(request) || !cJSON_IsString(state)) {
        cJSON_Delete(root);
        return CASHU_ERR_JSON_MISSING;
    }

    out->quote   = strdup(quote->valuestring);
    out->request = strdup(request->valuestring);
    out->state   = strdup(state->valuestring);
    out->expiry  = cJSON_IsNumber(expiry) ? (uint32_t)expiry->valuedouble : 0;

    cJSON_Delete(root);
    return CASHU_OK;
}

cashu_err_t json_parse_melt_quote(const char *json, melt_quote_t *out) {
    cJSON *root = cJSON_Parse(json);
    if (!root) return CASHU_ERR_JSON_PARSE;

    cJSON *quote       = cJSON_GetObjectItemCaseSensitive(root, "quote");
    cJSON *amount      = cJSON_GetObjectItemCaseSensitive(root, "amount");
    cJSON *fee_reserve = cJSON_GetObjectItemCaseSensitive(root, "fee_reserve");
    cJSON *state       = cJSON_GetObjectItemCaseSensitive(root, "state");
    cJSON *preimage    = cJSON_GetObjectItemCaseSensitive(root, "payment_preimage");

    if (!cJSON_IsString(quote) || !cJSON_IsNumber(amount) ||
        !cJSON_IsNumber(fee_reserve) || !cJSON_IsString(state)) {
        cJSON_Delete(root);
        return CASHU_ERR_JSON_MISSING;
    }

    out->quote            = strdup(quote->valuestring);
    out->amount           = (uint64_t)amount->valuedouble;
    out->fee_reserve      = (uint64_t)fee_reserve->valuedouble;
    out->state            = strdup(state->valuestring);
    out->payment_preimage = (cJSON_IsString(preimage) && preimage->valuestring[0])
                            ? strdup(preimage->valuestring) : NULL;
    out->change       = NULL;
    out->change_count = 0;

    cJSON *change_arr = cJSON_GetObjectItemCaseSensitive(root, "change");
    if (cJSON_IsArray(change_arr)) {
        int cn = cJSON_GetArraySize(change_arr);
        if (cn > 0) {
            out->change = malloc((size_t)cn * sizeof(blind_signature_t));
            if (!out->change) {
                free(out->quote); free(out->state); free(out->payment_preimage);
                cJSON_Delete(root);
                return CASHU_ERR_OOM;
            }
            int ci = 0;
            cJSON *item;
            cJSON_ArrayForEach(item, change_arr) {
                cJSON *amt = cJSON_GetObjectItemCaseSensitive(item, "amount");
                cJSON *id  = cJSON_GetObjectItemCaseSensitive(item, "id");
                cJSON *C_  = cJSON_GetObjectItemCaseSensitive(item, "C_");
                out->change[ci].amount = cJSON_IsNumber(amt) ? (uint64_t)amt->valuedouble : 0;
                out->change[ci].id     = cJSON_IsString(id) ? strdup(id->valuestring) : NULL;
                out->change[ci].C_     = cJSON_IsString(C_) ? strdup(C_->valuestring) : NULL;
                ci++;
            }
            out->change_count = (size_t)cn;
        }
    }

    cJSON_Delete(root);
    return CASHU_OK;
}

cashu_err_t json_parse_signatures(const char *json, blind_signature_t **out, size_t *count) {
    cJSON *root = cJSON_Parse(json);
    if (!root) return CASHU_ERR_JSON_PARSE;

    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "signatures");
    if (!cJSON_IsArray(arr)) { cJSON_Delete(root); return CASHU_ERR_JSON_MISSING; }

    int n = cJSON_GetArraySize(arr);
    *count = (size_t)n;
    *out = malloc((size_t)n * sizeof(blind_signature_t));
    if (!*out) { cJSON_Delete(root); return CASHU_ERR_OOM; }

    int i = 0;
    cJSON *item;
    cJSON_ArrayForEach(item, arr) {
        cJSON *amount = cJSON_GetObjectItemCaseSensitive(item, "amount");
        cJSON *id     = cJSON_GetObjectItemCaseSensitive(item, "id");
        cJSON *C_     = cJSON_GetObjectItemCaseSensitive(item, "C_");

        (*out)[i].amount    = cJSON_IsNumber(amount) ? (uint64_t)amount->valuedouble : 0;
        (*out)[i].id        = cJSON_IsString(id) ? strdup(id->valuestring) : NULL;
        (*out)[i].C_        = cJSON_IsString(C_) ? strdup(C_->valuestring) : NULL;
        (*out)[i].has_dleq  = false;

        // optional dleq object with e and s hex strings
        cJSON *dleq = cJSON_GetObjectItemCaseSensitive(item, "dleq");
        if (cJSON_IsObject(dleq)) {
            cJSON *e = cJSON_GetObjectItemCaseSensitive(dleq, "e");
            cJSON *s = cJSON_GetObjectItemCaseSensitive(dleq, "s");
            if (cJSON_IsString(e) && cJSON_IsString(s)) {
                strncpy((*out)[i].dleq_e, e->valuestring, 64);
                (*out)[i].dleq_e[64] = '\0';
                strncpy((*out)[i].dleq_s, s->valuestring, 64);
                (*out)[i].dleq_s[64] = '\0';
                (*out)[i].has_dleq = true;
            }
        }
        i++;
    }

    cJSON_Delete(root);
    return CASHU_OK;
}

// ===================================================================
//                      keyset parsers
// ===================================================================

cashu_err_t json_parse_keys(const char *json, keyset_t **out, size_t *count) {
    cJSON *root = cJSON_Parse(json);
    if (!root) return CASHU_ERR_JSON_PARSE;

    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "keysets");
    if (!cJSON_IsArray(arr)) { cJSON_Delete(root); return CASHU_ERR_JSON_MISSING; }

    int n = cJSON_GetArraySize(arr);
    *count = (size_t)n;
    *out = calloc((size_t)n, sizeof(keyset_t));
    if (!*out) { cJSON_Delete(root); return CASHU_ERR_OOM; }

    int i = 0;
    cJSON *ks;
    cJSON_ArrayForEach(ks, arr) {
        cJSON *id     = cJSON_GetObjectItemCaseSensitive(ks, "id");
        cJSON *unit   = cJSON_GetObjectItemCaseSensitive(ks, "unit");
        cJSON *active = cJSON_GetObjectItemCaseSensitive(ks, "active");
        cJSON *keys   = cJSON_GetObjectItemCaseSensitive(ks, "keys");

        (*out)[i].id     = cJSON_IsString(id)  ? strdup(id->valuestring)   : NULL;
        (*out)[i].unit   = cJSON_IsString(unit) ? strdup(unit->valuestring) : NULL;
        (*out)[i].active = cJSON_IsBool(active) ? cJSON_IsTrue(active)      : 1;

        if (cJSON_IsObject(keys)) {
            int kn = cJSON_GetArraySize(keys);
            (*out)[i].keys = malloc((size_t)kn * sizeof(keyset_key_t));
            (*out)[i].key_count = 0;

            cJSON *kv;
            cJSON_ArrayForEach(kv, keys) {
                if (!cJSON_IsString(kv)) continue;
                keyset_key_t *k = &(*out)[i].keys[(*out)[i].key_count++];
                k->amount = (uint64_t)strtoull(kv->string, NULL, 10);
                strncpy(k->pubkey, kv->valuestring, 66);
                k->pubkey[66] = '\0';
            }
        }
        i++;
    }

    cJSON_Delete(root);
    return CASHU_OK;
}

cashu_err_t json_parse_keysets(const char *json, keyset_t **out, size_t *count) {
    cJSON *root = cJSON_Parse(json);
    if (!root) return CASHU_ERR_JSON_PARSE;

    cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, "keysets");
    if (!cJSON_IsArray(arr)) { cJSON_Delete(root); return CASHU_ERR_JSON_MISSING; }

    int n = cJSON_GetArraySize(arr);
    *count = (size_t)n;
    *out = calloc((size_t)n, sizeof(keyset_t));
    if (!*out) { cJSON_Delete(root); return CASHU_ERR_OOM; }

    int i = 0;
    cJSON *ks;
    cJSON_ArrayForEach(ks, arr) {
        cJSON *id     = cJSON_GetObjectItemCaseSensitive(ks, "id");
        cJSON *unit   = cJSON_GetObjectItemCaseSensitive(ks, "unit");
        cJSON *active = cJSON_GetObjectItemCaseSensitive(ks, "active");

        (*out)[i].id        = cJSON_IsString(id)  ? strdup(id->valuestring)   : NULL;
        cJSON *fee  = cJSON_GetObjectItemCaseSensitive(ks, "input_fee_ppk");
        (*out)[i].unit          = cJSON_IsString(unit) ? strdup(unit->valuestring) : NULL;
        (*out)[i].active        = cJSON_IsBool(active) ? cJSON_IsTrue(active)      : 1;
        (*out)[i].input_fee_ppk = cJSON_IsNumber(fee)  ? (uint32_t)fee->valuedouble : 0;
        (*out)[i].keys          = NULL;
        (*out)[i].key_count     = 0;
        i++;
    }

    cJSON_Delete(root);
    return CASHU_OK;
}

