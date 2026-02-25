//
// Created by d4rp4t on 21/02/2026.
//

#include "http.h"
#include "json.h"
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

//===============================================================================
// Host-side HTTP implementation using libcurl.
// Implements the same cashu_http_* API as http.c - used for host builds only.
//===============================================================================

static char s_last_err_body[512] = {0};

const char *cashu_http_last_error_body(void) { return s_last_err_body; }



//===============================================================================
//                                  helpers
//===============================================================================

static char *make_url(const char *base, const char *path) {
    size_t blen = strlen(base);
    int has_slash = blen > 0 && base[blen - 1] == '/';
    size_t total = blen + strlen(path) + 6;
    char *url = malloc(total);
    if (!url) return NULL;
    snprintf(url, total, has_slash ? "%sv1/%s" : "%s/v1/%s", base, path);
    return url;
}

typedef struct { char *data; size_t len; size_t cap; } buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *ud) {
    size_t n = size * nmemb;
    buf_t *b = ud;
    if (b->len + n + 1 > b->cap) {
        size_t new_cap = b->cap ? b->cap * 2 : 4096;
        while (new_cap < b->len + n + 1) new_cap *= 2;
        char *tmp = realloc(b->data, new_cap);
        if (!tmp) return 0;
        b->data = tmp;
        b->cap  = new_cap;
    }
    memcpy(b->data + b->len, ptr, n);
    b->len += n;
    b->data[b->len] = '\0';
    return n;
}

typedef enum { M_GET, M_POST } method_t;

static cashu_err_t do_request(method_t method, const char *url,
                               const char *body, char **body_out) {
    CURL *curl = curl_easy_init();
    if (!curl) return CASHU_ERR_HTTP;

    buf_t buf = { NULL, 0, 0 };
    struct curl_slist *headers = NULL;
    cashu_err_t ret = CASHU_ERR_HTTP;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    if (method == M_POST) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body ? body : "");
        if (!body) curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    }

    if (curl_easy_perform(curl) != CURLE_OK) goto cleanup;

    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status < 200 || status >= 300) {
        if (buf.data) {
            strncpy(s_last_err_body, buf.data, sizeof(s_last_err_body) - 1);
            s_last_err_body[sizeof(s_last_err_body) - 1] = '\0';
        } else {
            s_last_err_body[0] = '\0';
        }
        fprintf(stderr, "[http] %ld %s\n  body: %s\n",
                status, url, s_last_err_body[0] ? s_last_err_body : "(empty)");
        ret = CASHU_ERR_HTTP_STATUS;
        goto cleanup;
    }

    *body_out = buf.data;
    buf.data  = NULL;
    ret = CASHU_OK;

cleanup:
    free(buf.data);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ret;
}

//===============================================================================
//                                  lifecycle
//===============================================================================

cashu_err_t cashu_http_init(void) {
    return curl_global_init(CURL_GLOBAL_DEFAULT) == 0 ? CASHU_OK : CASHU_ERR_HTTP;
}

void cashu_http_term(void) { curl_global_cleanup(); }

//===============================================================================
//                                mint api
//===============================================================================

cashu_err_t cashu_get_keys(const char *mint_url, keyset_t **out, size_t *count) {
    char *url = make_url(mint_url, "keys");
    if (!url) return CASHU_ERR_OOM;
    char *resp = NULL;
    cashu_err_t err = do_request(M_GET, url, NULL, &resp);
    free(url);
    if (err != CASHU_OK) return err;
    err = json_parse_keys(resp, out, count);
    free(resp);
    return err;
}

cashu_err_t cashu_get_keysets(const char *mint_url, keyset_t **out, size_t *count) {
    char *url = make_url(mint_url, "keysets");
    if (!url) return CASHU_ERR_OOM;
    char *resp = NULL;
    cashu_err_t err = do_request(M_GET, url, NULL, &resp);
    free(url);
    if (err != CASHU_OK) return err;
    err = json_parse_keysets(resp, out, count);
    free(resp);
    return err;
}

cashu_err_t cashu_mint_quote(const char *mint_url, uint64_t amount,
                             const char *unit, mint_quote_t *out) {
    char *url = make_url(mint_url, "mint/quote/bolt11");
    if (!url) return CASHU_ERR_OOM;
    char *req_body = json_mint_quote_request(amount, unit);
    if (!req_body) { free(url); return CASHU_ERR_OOM; }
    char *resp = NULL;
    cashu_err_t err = do_request(M_POST, url, req_body, &resp);
    free(url); free(req_body);
    if (err != CASHU_OK) return err;
    err = json_parse_mint_quote(resp, out);
    free(resp);
    return err;
}

cashu_err_t cashu_mint_quote_state(const char *mint_url, const char *quote_id,
                                   mint_quote_t *out) {
    char path[256];
    snprintf(path, sizeof(path), "mint/quote/bolt11/%s", quote_id);
    char *url = make_url(mint_url, path);
    if (!url) return CASHU_ERR_OOM;
    char *resp = NULL;
    cashu_err_t err = do_request(M_GET, url, NULL, &resp);
    free(url);
    if (err != CASHU_OK) return err;
    err = json_parse_mint_quote(resp, out);
    free(resp);
    return err;
}

cashu_err_t cashu_mint(const char *mint_url, const char *quote,
                       const blinded_message_t *outputs, size_t count,
                       blind_signature_t **sigs_out, size_t *sig_count) {
    char *url = make_url(mint_url, "mint/bolt11");
    if (!url) return CASHU_ERR_OOM;
    char *req_body = json_mint_request(quote, outputs, count);
    if (!req_body) { free(url); return CASHU_ERR_OOM; }
    char *resp = NULL;
    cashu_err_t err = do_request(M_POST, url, req_body, &resp);
    free(url); free(req_body);
    if (err != CASHU_OK) return err;
    err = json_parse_signatures(resp, sigs_out, sig_count);
    free(resp);
    return err;
}

cashu_err_t cashu_melt_quote(const char *mint_url, const char *bolt11,
                             const char *unit, melt_quote_t *out) {
    char *url = make_url(mint_url, "melt/quote/bolt11");
    if (!url) return CASHU_ERR_OOM;
    char *req_body = json_melt_quote_request(bolt11, unit);
    if (!req_body) { free(url); return CASHU_ERR_OOM; }
    char *resp = NULL;
    cashu_err_t err = do_request(M_POST, url, req_body, &resp);
    free(url); free(req_body);
    if (err != CASHU_OK) return err;
    err = json_parse_melt_quote(resp, out);
    free(resp);
    return err;
}

cashu_err_t cashu_melt_quote_state(const char *mint_url, const char *quote_id,
                                   melt_quote_t *out) {
    char path[256];
    snprintf(path, sizeof(path), "melt/quote/bolt11/%s", quote_id);
    char *url = make_url(mint_url, path);
    if (!url) return CASHU_ERR_OOM;
    char *resp = NULL;
    cashu_err_t err = do_request(M_GET, url, NULL, &resp);
    free(url);
    if (err != CASHU_OK) return err;
    err = json_parse_melt_quote(resp, out);
    free(resp);
    return err;
}

cashu_err_t cashu_melt(const char *mint_url, const char *quote,
                       const proof_t *inputs, size_t count,
                       const blinded_message_t *outputs, size_t out_n,
                       melt_quote_t *out) {
    char *url = make_url(mint_url, "melt/bolt11");
    if (!url) return CASHU_ERR_OOM;
    char *req_body = json_melt_request(quote, inputs, count, outputs, out_n);
    if (!req_body) { free(url); return CASHU_ERR_OOM; }
    char *resp = NULL;
    cashu_err_t err = do_request(M_POST, url, req_body, &resp);
    free(url); free(req_body);
    if (err != CASHU_OK) return err;
    err = json_parse_melt_quote(resp, out);
    free(resp);
    return err;
}

cashu_err_t cashu_http_post_raw(const char *url, const char *body) {
    char *resp = NULL;
    cashu_err_t err = do_request(M_POST, url, body, &resp);
    free(resp);
    return err;
}

cashu_err_t cashu_swap(const char *mint_url,
                       const proof_t *inputs,            size_t inp_n,
                       const blinded_message_t *outputs, size_t out_n,
                       blind_signature_t **sigs_out, size_t *sig_count) {
    char *url = make_url(mint_url, "swap");
    if (!url) return CASHU_ERR_OOM;
    char *req_body = json_swap_request(inputs, inp_n, outputs, out_n);
    if (!req_body) { free(url); return CASHU_ERR_OOM; }
    char *resp = NULL;
    cashu_err_t err = do_request(M_POST, url, req_body, &resp);
    free(url); free(req_body);
    if (err != CASHU_OK) return err;
    err = json_parse_signatures(resp, sigs_out, sig_count);
    free(resp);
    return err;
}
