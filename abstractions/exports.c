//
// Created by d4rp4t on 22/02/2026.
//
#include "exports.h"
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// =============================================================================
//  helpers
// =============================================================================
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);
    return buf;
}

static int write_file(const char *path, const char *data) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    fwrite(data, 1, strlen(data), f);
    fclose(f);
    return rename(tmp, path);
}

static cJSON *load_arr(const char *path) {
    char *buf = read_file(path);
    if (!buf) return cJSON_CreateArray();
    cJSON *arr = cJSON_Parse(buf);
    free(buf);
    if (!arr || !cJSON_IsArray(arr)) {
        cJSON_Delete(arr);
        return cJSON_CreateArray();
    }
    return arr;
}

/* ---- public API ---------------------------------------------------------- */

int exports_save(const char *path, const char *token, uint64_t amount) {
    cJSON *arr = load_arr(path);
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "token",  token);
    cJSON_AddNumberToObject(obj, "amount", (double)amount);
    cJSON_AddItemToArray(arr, obj);
    char *s = cJSON_PrintUnformatted(arr);
    int r = s ? write_file(path, s) : -1;
    free(s);
    cJSON_Delete(arr);
    return r;
}

int exports_load(const char *path, exported_token_t **out, size_t *count) {
    *out = NULL; *count = 0;
    cJSON *arr = load_arr(path);
    int n = cJSON_GetArraySize(arr);
    if (n <= 0) { cJSON_Delete(arr); return 0; }
    exported_token_t *list = calloc((size_t)n, sizeof(*list));
    if (!list) { cJSON_Delete(arr); return -1; }
    size_t k = 0;
    cJSON *it;
    cJSON_ArrayForEach(it, arr) {
        cJSON *t = cJSON_GetObjectItemCaseSensitive(it, "token");
        cJSON *a = cJSON_GetObjectItemCaseSensitive(it, "amount");
        if (cJSON_IsString(t) && cJSON_IsNumber(a)) {
            list[k].token  = strdup(t->valuestring);
            list[k].amount = (uint64_t)a->valuedouble;
            k++;
        }
    }
    cJSON_Delete(arr);
    *out = list; *count = k;
    return 0;
}

int exports_delete(const char *path, size_t idx) {
    cJSON *arr = load_arr(path);
    int n = cJSON_GetArraySize(arr);
    if ((int)idx >= n) { cJSON_Delete(arr); return -1; }
    cJSON_DeleteItemFromArray(arr, (int)idx);
    char *s = cJSON_PrintUnformatted(arr);
    int r = s ? write_file(path, s) : -1;
    free(s);
    cJSON_Delete(arr);
    return r;
}

void exports_free(exported_token_t *list, size_t count) {
    if (!list) return;
    for (size_t i = 0; i < count; i++) free(list[i].token);
    free(list);
}
