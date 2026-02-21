//
// Created by d4rp4t on 21/02/2026.
//
#include "http.h"
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <psp2/net/http.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/libssl.h>
#include <psp2/sysmodule.h>

/*
 * =================================================================
 *  No tests for that, you cannot test this shit outside of vita :/
 *  Probably buggy AS FUCK
 * =================================================================
 */

#define NET_POOL_SIZE  (1 * 1024 * 1024)
#define SSL_POOL_SIZE  (1 * 1024 * 1024)
#define HTTP_POOL_SIZE (4 * 1024 * 1024)
#define READ_CHUNK     4096

static void *s_net_mem = NULL;
static int   s_tmpl    = -1;

cashu_err_t cashu_http_init(void) {
    sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
    sceSysmoduleLoadModule(SCE_SYSMODULE_HTTP);
    sceSysmoduleLoadModule(SCE_SYSMODULE_SSL);

    s_net_mem = malloc(NET_POOL_SIZE);
    if (!s_net_mem) return CASHU_ERR_OOM;

    SceNetInitParam net_param;
    net_param.memory = s_net_mem;
    net_param.size   = NET_POOL_SIZE;
    net_param.flags  = 0;
    if (sceNetInit(&net_param) < 0) { free(s_net_mem); return CASHU_ERR_HTTP; }

    sceNetCtlInit();

    if (sceSslInit(SSL_POOL_SIZE) < 0) {
        sceNetCtlTerm();
        sceNetTerm();
        free(s_net_mem);
        return CASHU_ERR_HTTP;
    }

    if (sceHttpInit(HTTP_POOL_SIZE) < 0) {
        sceSslTerm();
        sceNetCtlTerm();
        sceNetTerm();
        free(s_net_mem);
        return CASHU_ERR_HTTP;
    }

    sceHttpsDisableOption(SCE_HTTPS_FLAG_SERVER_VERIFY |
                          SCE_HTTPS_FLAG_CN_CHECK      |
                          SCE_HTTPS_FLAG_KNOWN_CA_CHECK);

    s_tmpl = sceHttpCreateTemplate("VitaCashu/1.0", SCE_HTTP_VERSION_1_1, SCE_TRUE);
    if (s_tmpl < 0) {
        sceHttpTerm();
        sceSslTerm();
        sceNetCtlTerm();
        sceNetTerm();
        free(s_net_mem);
        return CASHU_ERR_HTTP;
    }

    return CASHU_OK;
}

void cashu_http_term(void) {
    if (s_tmpl >= 0) { sceHttpDeleteTemplate(s_tmpl); s_tmpl = -1; }
    sceHttpTerm();
    sceSslTerm();
    sceNetCtlTerm();
    sceNetTerm();
    free(s_net_mem);
    s_net_mem = NULL;
}

static char *make_url(const char *base, const char *path) {
    size_t blen = strlen(base);
    int has_slash = blen > 0 && base[blen - 1] == '/';
    size_t total = blen + strlen(path) + 5; // "/v1/" + '\0'
    char *url = malloc(total);
    if (!url) return NULL;
    snprintf(url, total, has_slash ? "%sv1/%s" : "%s/v1/%s", base, path);
    return url;
}

static cashu_err_t do_request(int method, const char *url,
                               const char *body, char **body_out) {
    int conn = sceHttpCreateConnectionWithURL(s_tmpl, url, SCE_FALSE);
    if (conn < 0) return CASHU_ERR_HTTP;

    unsigned long long body_len = body ? (unsigned long long)strlen(body) : 0;
    int req = sceHttpCreateRequestWithURL(conn, method, url, body_len);
    if (req < 0) { sceHttpDeleteConnection(conn); return CASHU_ERR_HTTP; }

    if (body)
        sceHttpAddRequestHeader(req, "Content-Type", "application/json",
                                SCE_HTTP_HEADER_OVERWRITE);

    cashu_err_t ret = CASHU_ERR_HTTP;
    if (sceHttpSendRequest(req, (void *)body, (unsigned int)body_len) < 0)
        goto cleanup;

    int status = 0;
    sceHttpGetStatusCode(req, &status);
    if (status < 200 || status >= 300) { ret = CASHU_ERR_HTTP_STATUS; goto cleanup; }

    char *buf = malloc(READ_CHUNK);
    if (!buf) { ret = CASHU_ERR_OOM; goto cleanup; }
    size_t cap = READ_CHUNK, total = 0;

    int n;
    while ((n = sceHttpReadData(req, buf + total,
                                (unsigned int)(cap - total - 1))) > 0) {
        total += (size_t)n;
        if (total + READ_CHUNK > cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); ret = CASHU_ERR_OOM; goto cleanup; }
            buf = tmp;
        }
    }
    buf[total] = '\0';
    *body_out = buf;
    ret = CASHU_OK;

cleanup:
    sceHttpDeleteRequest(req);
    sceHttpDeleteConnection(conn);
    return ret;
}

cashu_err_t cashu_get_keys(const char *mint_url, keyset_t **out, size_t *count) {
    char *url = make_url(mint_url, "keys");
    if (!url) return CASHU_ERR_OOM;
    char *resp = NULL;
    cashu_err_t err = do_request(SCE_HTTP_METHOD_GET, url, NULL, &resp);
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
    cashu_err_t err = do_request(SCE_HTTP_METHOD_GET, url, NULL, &resp);
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
    cashu_err_t err = do_request(SCE_HTTP_METHOD_POST, url, req_body, &resp);
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
    cashu_err_t err = do_request(SCE_HTTP_METHOD_GET, url, NULL, &resp);
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
    cashu_err_t err = do_request(SCE_HTTP_METHOD_POST, url, req_body, &resp);
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
    cashu_err_t err = do_request(SCE_HTTP_METHOD_POST, url, req_body, &resp);
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
    cashu_err_t err = do_request(SCE_HTTP_METHOD_GET, url, NULL, &resp);
    free(url);
    if (err != CASHU_OK) return err;
    err = json_parse_melt_quote(resp, out);
    free(resp);
    return err;
}

cashu_err_t cashu_melt(const char *mint_url, const char *quote,
                       const proof_t *inputs, size_t count,
                       melt_quote_t *out) {
    char *url = make_url(mint_url, "melt/bolt11");
    if (!url) return CASHU_ERR_OOM;
    char *req_body = json_melt_request(quote, inputs, count);
    if (!req_body) { free(url); return CASHU_ERR_OOM; }
    char *resp = NULL;
    cashu_err_t err = do_request(SCE_HTTP_METHOD_POST, url, req_body, &resp);
    free(url); free(req_body);
    if (err != CASHU_OK) return err;
    err = json_parse_melt_quote(resp, out);
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
    cashu_err_t err = do_request(SCE_HTTP_METHOD_POST, url, req_body, &resp);
    free(url); free(req_body);
    if (err != CASHU_OK) return err;
    err = json_parse_signatures(resp, sigs_out, sig_count);
    free(resp);
    return err;
}
