//
// Created by d4rp4t on 20/02/2026.
//
#include "encoding.h"
#include "utils.h"
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <stdlib.h>
#include <string.h>

#define CBOR_BUF_SIZE 16384

// ===================================================================
//                              base64url
// ===================================================================

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url_encoded_len(size_t n) { return (n * 4 + 2) / 3; }

static void b64url_encode(const uint8_t *in, size_t in_len, char *out) {
    size_t out_len = b64url_encoded_len(in_len);
    size_t i = 0, j = 0;
    while (i < in_len) {
        uint32_t a = in[i++];
        uint32_t b = i < in_len ? in[i++] : 0;
        uint32_t c = i < in_len ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        if (j < out_len) out[j++] = B64URL[(triple >> 18) & 0x3F];
        if (j < out_len) out[j++] = B64URL[(triple >> 12) & 0x3F];
        if (j < out_len) out[j++] = B64URL[(triple >>  6) & 0x3F];
        if (j < out_len) out[j++] = B64URL[ triple        & 0x3F];
    }
    out[out_len] = '\0';
}

static int b64url_char_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static uint8_t *b64url_decode(const char *in, size_t *out_len) {
    size_t in_len = strlen(in);
    size_t padded = in_len;
    if (padded % 4 == 2) padded += 2;
    else if (padded % 4 == 3) padded += 1;
    *out_len = padded / 4 * 3 - (padded - in_len);
    uint8_t *out = malloc(*out_len);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < in_len) {
        int a = b64url_char_val(in[i++]);
        int b = i < in_len ? b64url_char_val(in[i++]) : 0;
        int c = i < in_len ? b64url_char_val(in[i++]) : 0;
        int d = i < in_len ? b64url_char_val(in[i++]) : 0;
        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                          ((uint32_t)c <<  6) |  (uint32_t)d;
        if (j < *out_len) out[j++] = (triple >> 16) & 0xFF;
        if (j < *out_len) out[j++] = (triple >>  8) & 0xFF;
        if (j < *out_len) out[j++] =  triple        & 0xFF;
    }
    return out;
}

// ===================================================================
//                              helpers
// ===================================================================

static char *dupn(const void *s, size_t len) {
    char *out = malloc(len + 1);
    if (out) { memcpy(out, s, len); out[len] = '\0'; }
    return out;
}

// ===================================================================
//                      token_encode
// ===================================================================

cashu_err_t token_encode(const token_t *token, char **out) {
    uint8_t *cbor_buf = malloc(CBOR_BUF_SIZE);
    if (!cbor_buf) return CASHU_ERR_OOM;

    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, (UsefulBuf){ cbor_buf, CBOR_BUF_SIZE });

    QCBOREncode_OpenMap(&ctx);

    if (token->memo)
        QCBOREncode_AddSZStringToMap(&ctx, "d", token->memo);

    QCBOREncode_OpenArrayInMap(&ctx, "t");

    for (size_t g = 0; g < token->proof_count; g++) {
        int dup = 0;
        for (size_t k = 0; k < g; k++)
            if (strcmp(token->proofs[k].id, token->proofs[g].id) == 0) { dup = 1; break; }
        if (dup) continue;

        uint8_t kid[8];
        hex_decode(token->proofs[g].id, kid, 8);

        QCBOREncode_OpenMap(&ctx);
        QCBOREncode_AddBytesToMap(&ctx, "i", (UsefulBufC){ kid, 8 });
        QCBOREncode_OpenArrayInMap(&ctx, "p");

        for (size_t i = 0; i < token->proof_count; i++) {
            if (strcmp(token->proofs[i].id, token->proofs[g].id) != 0) continue;
            QCBOREncode_OpenMap(&ctx);
            QCBOREncode_AddUInt64ToMap(&ctx, "a", token->proofs[i].amount);
            QCBOREncode_AddTextToMap(&ctx, "s",
                (UsefulBufC){ token->proofs[i].secret, strlen(token->proofs[i].secret) });
            QCBOREncode_AddBytesToMap(&ctx, "c",
                (UsefulBufC){ token->proofs[i].C, 33 });
            QCBOREncode_CloseMap(&ctx);
        }

        QCBOREncode_CloseArray(&ctx);
        QCBOREncode_CloseMap(&ctx);
    }

    QCBOREncode_CloseArray(&ctx);
    QCBOREncode_AddSZStringToMap(&ctx, "m", token->mint_url);
    QCBOREncode_AddSZStringToMap(&ctx, "u", token->unit);
    QCBOREncode_CloseMap(&ctx);

    UsefulBufC result;
    if (QCBOREncode_Finish(&ctx, &result) != QCBOR_SUCCESS) {
        free(cbor_buf);
        return CASHU_ERR_CBOR_ENCODE;
    }

    size_t total = 6 + b64url_encoded_len(result.len) + 1;
    *out = malloc(total);
    if (!*out) {
        free(cbor_buf);
        return CASHU_ERR_OOM;
    }

    memcpy(*out, "cashuB", 6);
    b64url_encode(result.ptr, result.len, *out + 6);

    free(cbor_buf);
    return CASHU_OK;
}

// ===================================================================
//                      token_decode
// ===================================================================

cashu_err_t token_decode(const char *encoded, token_t *out) {
    if (strncmp(encoded, "cashuB", 6) != 0) return CASHU_ERR_INVALID_TOKEN;

    size_t cbor_len;
    uint8_t *cbor_buf = b64url_decode(encoded + 6, &cbor_len);
    if (!cbor_buf) return CASHU_ERR_OOM;

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, (UsefulBufC){ cbor_buf, cbor_len }, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterMap(&ctx, NULL);

    UsefulBufC mint_c, unit_c;
    QCBORDecode_GetTextStringInMapSZ(&ctx, "m", &mint_c);
    QCBORDecode_GetTextStringInMapSZ(&ctx, "u", &unit_c);

    out->mint_url    = dupn(mint_c.ptr, mint_c.len);
    out->unit        = dupn(unit_c.ptr, unit_c.len);
    out->proofs      = NULL;
    out->proof_count = 0;
    out->memo        = NULL;

    {
        UsefulBufC memo_c;
        QCBORDecode_GetTextStringInMapSZ(&ctx, "d", &memo_c);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_SUCCESS)
            out->memo = dupn(memo_c.ptr, memo_c.len);
    }

    QCBORDecode_EnterArrayFromMapSZ(&ctx, "t");

    while (1) {
        QCBORDecode_EnterMap(&ctx, NULL);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_ERR_NO_MORE_ITEMS) break;

        UsefulBufC id_c;
        QCBORDecode_GetByteStringInMapSZ(&ctx, "i", &id_c);

        char id_hex[17];
        hex_encode(id_c.ptr, id_c.len, id_hex);

        QCBORDecode_EnterArrayFromMapSZ(&ctx, "p");

        while (1) {
            QCBORDecode_EnterMap(&ctx, NULL);
            if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_ERR_NO_MORE_ITEMS) break;

            uint64_t amount;
            UsefulBufC secret_c, C_c;
            QCBORDecode_GetUInt64InMapSZ(&ctx, "a", &amount);
            QCBORDecode_GetTextStringInMapSZ(&ctx, "s", &secret_c);
            QCBORDecode_GetByteStringInMapSZ(&ctx, "c", &C_c);
            proof_t *tmp = realloc(out->proofs, (out->proof_count + 1) * sizeof(proof_t));
            if (tmp == NULL) {
                return CASHU_ERR_OOM;
            }
            out->proofs = tmp;
            proof_t *p  = &out->proofs[out->proof_count++];
            p->amount   = amount;
            p->id       = strdup(id_hex);
            p->secret   = dupn(secret_c.ptr, secret_c.len);
            memcpy(p->C, C_c.ptr, 33);

            QCBORDecode_ExitMap(&ctx);
        }

        QCBORDecode_ExitArray(&ctx);
        QCBORDecode_ExitMap(&ctx);
    }

    QCBORDecode_ExitArray(&ctx);
    QCBORDecode_ExitMap(&ctx);

    const cashu_err_t ret = QCBORDecode_Finish(&ctx) == QCBOR_SUCCESS
                      ? CASHU_OK : CASHU_ERR_CBOR_DECODE;
    free(cbor_buf);
    return ret;
}
