//
// Created by d4rp4t on 21/02/2026.
//
#include "../cashu/utils.h"
#include "storage.h"
#include <cJSON.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


// ================================================================
// vitasdk newlib swaps fopen/fwrite/rename → sceIo* under the hood.
// nice, we can have the same api for testing on host and for vita.
// ================================================================

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    char *buf = malloc((size_t)size + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[size] = '\0';
    return buf;
}

static cashu_err_t write_file(const char *path, const char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return CASHU_ERR_IO;
    fwrite(data, 1, len, f);
    fclose(f);
    return CASHU_OK;
}

static cashu_err_t rename_file(const char *src, const char *dst) {
    return rename(src, dst) == 0 ? CASHU_OK : CASHU_ERR_IO;
}

// ==============================================================================
//                                 in-memory store
// ==============================================================================

typedef struct {
    proof_t  proof;
    char    *mint_url;
} stored_proof_t;

static stored_proof_t *s_proofs   = NULL;
static size_t          s_count    = 0;
static size_t          s_cap      = 0;
static char           *s_path     = NULL;
static char           *s_tmp_path = NULL;


// ==============================================================================
//                                 internals
// ==============================================================================
static cashu_err_t ensure_cap(void) {
    if (s_count < s_cap) return CASHU_OK;
    size_t new_cap = s_cap ? s_cap * 2 : 8;
    stored_proof_t *tmp = realloc(s_proofs, new_cap * sizeof(*tmp));
    if (!tmp) return CASHU_ERR_OOM;
    s_proofs = tmp;
    s_cap    = new_cap;
    return CASHU_OK;
}

static void stored_proof_free(stored_proof_t *sp) {
    free(sp->proof.id);
    free(sp->proof.secret);
    free(sp->mint_url);
}

static cashu_err_t parse_json(const char *json) {
    cJSON *root = cJSON_Parse(json);
    if (!root || !cJSON_IsArray(root)) { cJSON_Delete(root); return CASHU_ERR_JSON_PARSE; }

    int n = cJSON_GetArraySize(root);
    for (int i = 0; i < n; i++) {
        cJSON *item   = cJSON_GetArrayItem(root, i);
        cJSON *amount = cJSON_GetObjectItemCaseSensitive(item, "amount");
        cJSON *id     = cJSON_GetObjectItemCaseSensitive(item, "id");
        cJSON *secret = cJSON_GetObjectItemCaseSensitive(item, "secret");
        cJSON *C_hex  = cJSON_GetObjectItemCaseSensitive(item, "C");
        cJSON *mint   = cJSON_GetObjectItemCaseSensitive(item, "mint_url");

        if (!cJSON_IsNumber(amount) || !cJSON_IsString(id)   ||
            !cJSON_IsString(secret) || !cJSON_IsString(C_hex) ||
            !cJSON_IsString(mint)) continue;

        cashu_err_t err = ensure_cap();
        if (err != CASHU_OK) { cJSON_Delete(root); return err; }

        stored_proof_t *sp = &s_proofs[s_count];
        sp->proof.amount = (uint64_t)amount->valuedouble;
        sp->proof.id     = strdup(id->valuestring);
        sp->proof.secret = strdup(secret->valuestring);
        sp->mint_url     = strdup(mint->valuestring);
        hex_decode(C_hex->valuestring, sp->proof.C, 33);

        if (!sp->proof.id || !sp->proof.secret || !sp->mint_url) {
            cJSON_Delete(root);
            return CASHU_ERR_OOM;
        }
        s_count++;
    }

    cJSON_Delete(root);
    return CASHU_OK;
}

static cashu_err_t flush(void) {
    cJSON *root = cJSON_CreateArray();
    if (!root) return CASHU_ERR_OOM;

    for (size_t i = 0; i < s_count; i++) {
        proof_t *p = &s_proofs[i].proof;
        char c_hex[67];
        hex_encode(p->C, 33, c_hex);
        c_hex[66] = '\0';

        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "amount",   (double)p->amount);
        cJSON_AddStringToObject(item, "id",       p->id);
        cJSON_AddStringToObject(item, "secret",   p->secret);
        cJSON_AddStringToObject(item, "C",        c_hex);
        cJSON_AddStringToObject(item, "mint_url", s_proofs[i].mint_url);
        cJSON_AddItemToArray(root, item);
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return CASHU_ERR_OOM;

    cashu_err_t err = write_file(s_tmp_path, json, strlen(json));
    free(json);
    if (err != CASHU_OK) return err;

    return rename_file(s_tmp_path, s_path);
}

// ==============================================================================
//                                 lifecycle
// ==============================================================================

cashu_err_t storage_init(const char *path) {
    s_path = strdup(path);
    if (!s_path) return CASHU_ERR_OOM;

    size_t plen = strlen(path);
    s_tmp_path = malloc(plen + 5);
    if (!s_tmp_path) { free(s_path); s_path = NULL; return CASHU_ERR_OOM; }
    snprintf(s_tmp_path, plen + 5, "%s.tmp", path);

    char *existing = read_file(path);
    if (existing) {
        parse_json(existing); // start fresh on corrupted file, not fatal
        free(existing);
    }

    return CASHU_OK;
}

void storage_term(void) {
    for (size_t i = 0; i < s_count; i++) stored_proof_free(&s_proofs[i]);
    free(s_proofs);
    free(s_path);
    free(s_tmp_path);
    s_proofs   = NULL;
    s_count    = 0;
    s_cap      = 0;
    s_path     = NULL;
    s_tmp_path = NULL;
}

// ==============================================================================
//                                 API
// ==============================================================================

cashu_err_t storage_save_proof(const proof_t *p, const char *mint_url) {
    cashu_err_t err = ensure_cap();
    if (err != CASHU_OK) return err;

    stored_proof_t *sp = &s_proofs[s_count];
    sp->proof.amount = p->amount;
    sp->proof.id     = strdup(p->id);
    sp->proof.secret = strdup(p->secret);
    sp->mint_url     = strdup(mint_url);
    memcpy(sp->proof.C, p->C, 33);

    if (!sp->proof.id || !sp->proof.secret || !sp->mint_url) return CASHU_ERR_OOM;
    s_count++;
    return flush();
}

cashu_err_t storage_get_by_mint(const char *mint_url, proof_t **out, size_t *count) {
    size_t n = 0;
    for (size_t i = 0; i < s_count; i++)
        if (strcmp(s_proofs[i].mint_url, mint_url) == 0) n++;

    if (n == 0) { *out = NULL; *count = 0; return CASHU_OK; }

    proof_t *result = malloc(n * sizeof(proof_t));
    if (!result) return CASHU_ERR_OOM;

    size_t j = 0;
    for (size_t i = 0; i < s_count; i++) {
        if (strcmp(s_proofs[i].mint_url, mint_url) != 0) continue;
        proof_t *src     = &s_proofs[i].proof;
        result[j].amount = src->amount;
        result[j].id     = strdup(src->id);
        result[j].secret = strdup(src->secret);
        memcpy(result[j].C, src->C, 33);
        j++;
    }

    *out   = result;
    *count = n;
    return CASHU_OK;
}

cashu_err_t storage_get_proofs(const char *keyset_id, proof_t **out, size_t *count) {
    size_t n = 0;
    for (size_t i = 0; i < s_count; i++)
        if (strcmp(s_proofs[i].proof.id, keyset_id) == 0) n++;

    if (n == 0) { *out = NULL; *count = 0; return CASHU_OK; }

    proof_t *result = malloc(n * sizeof(proof_t));
    if (!result) return CASHU_ERR_OOM;

    size_t j = 0;
    for (size_t i = 0; i < s_count; i++) {
        if (strcmp(s_proofs[i].proof.id, keyset_id) != 0) continue;
        proof_t *src   = &s_proofs[i].proof;
        result[j].amount = src->amount;
        result[j].id     = strdup(src->id);
        result[j].secret = strdup(src->secret);
        memcpy(result[j].C, src->C, 33);
        j++;
    }

    *out   = result;
    *count = n;
    return CASHU_OK;
}

cashu_err_t storage_remove_proofs(const proof_t *proofs, size_t count) {
    for (size_t d = 0; d < count; d++) {
        for (size_t i = 0; i < s_count; i++) {
            if (strcmp(s_proofs[i].proof.secret, proofs[d].secret) != 0) continue;
            stored_proof_free(&s_proofs[i]);
            s_proofs[i] = s_proofs[--s_count];
            break;
        }
    }
    return flush();
}

uint64_t storage_total_balance(void) {
    uint64_t total = 0;
    for (size_t i = 0; i < s_count; i++)
        total += s_proofs[i].proof.amount;
    return total;
}

cashu_err_t storage_list_mints(char ***urls_out, size_t *count_out) {
    // two-pass: count uniques, then collect
    size_t unique = 0;
    for (size_t i = 0; i < s_count; i++) {
        int dup = 0;
        for (size_t j = 0; j < i && !dup; j++)
            if (strcmp(s_proofs[j].mint_url, s_proofs[i].mint_url) == 0) dup = 1;
        if (!dup) unique++;
    }
    if (unique == 0) { *urls_out = NULL; *count_out = 0; return CASHU_OK; }

    char **urls = malloc(unique * sizeof(char *));
    if (!urls) return CASHU_ERR_OOM;

    size_t n = 0;
    for (size_t i = 0; i < s_count; i++) {
        int dup = 0;
        for (size_t j = 0; j < n && !dup; j++)
            if (strcmp(urls[j], s_proofs[i].mint_url) == 0) dup = 1;
        if (dup) continue;
        urls[n] = strdup(s_proofs[i].mint_url);
        if (!urls[n]) {
            for (size_t k = 0; k < n; k++) free(urls[k]);
            free(urls);
            return CASHU_ERR_OOM;
        }
        n++;
    }
    *urls_out  = urls;
    *count_out = n;
    return CASHU_OK;
}

cashu_err_t storage_swap(const proof_t *spent, size_t spent_n,
                         const proof_t *fresh,  size_t fresh_n,
                         const char    *mint_url) {
    for (size_t d = 0; d < spent_n; d++) {
        for (size_t i = 0; i < s_count; i++) {
            if (strcmp(s_proofs[i].proof.secret, spent[d].secret) != 0) continue;
            stored_proof_free(&s_proofs[i]);
            s_proofs[i] = s_proofs[--s_count];
            break;
        }
    }

    for (size_t a = 0; a < fresh_n; a++) {
        cashu_err_t err = ensure_cap();
        if (err != CASHU_OK) return err;

        stored_proof_t *sp = &s_proofs[s_count];
        sp->proof.amount = fresh[a].amount;
        sp->proof.id     = strdup(fresh[a].id);
        sp->proof.secret = strdup(fresh[a].secret);
        sp->mint_url     = strdup(mint_url);
        memcpy(sp->proof.C, fresh[a].C, 33);

        if (!sp->proof.id || !sp->proof.secret || !sp->mint_url) return CASHU_ERR_OOM;
        s_count++;
    }

    return flush();
}
