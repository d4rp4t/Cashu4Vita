//
// Created by d4rp4t on 20/02/2026.
//
#include "encoding.h"
#include "utils.h"
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <qcbor/qcbor_common.h>
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
    if (in_len == 0) { *out_len = 0; return NULL; }
    size_t padded = in_len;
    if (padded % 4 == 2) padded += 2;
    else if (padded % 4 == 3) padded += 1;
    *out_len = padded / 4 * 3 - (padded - in_len);
    if (*out_len == 0) return NULL;
    uint8_t *out = malloc(*out_len);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < in_len) {
        int a = b64url_char_val(in[i++]);
        int b = i < in_len ? b64url_char_val(in[i++]) : 0;
        int c = i < in_len ? b64url_char_val(in[i++]) : 0;
        int d = i < in_len ? b64url_char_val(in[i++]) : 0;
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            free(out);
            return NULL;
        }
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

static char *dupn_safe(const void *s, size_t len) {
    if (!s || len == SIZE_MAX) return NULL;
    char *out = malloc(len + 1);
    if (!out) return NULL;
    memcpy(out, s, len);
    out[len] = '\0';
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
            if (token->proofs[i].has_dleq &&
                token->proofs[i].dleq_e[0] &&
                token->proofs[i].dleq_s[0] &&
                token->proofs[i].dleq_r[0]) {
                uint8_t de[32], ds[32], dr[32];
                hex_decode(token->proofs[i].dleq_e, de, 32);
                hex_decode(token->proofs[i].dleq_s, ds, 32);
                hex_decode(token->proofs[i].dleq_r, dr, 32);
                QCBOREncode_OpenMapInMap(&ctx, "d");
                QCBOREncode_AddBytesToMap(&ctx, "e", (UsefulBufC){ de, 32 });
                QCBOREncode_AddBytesToMap(&ctx, "s", (UsefulBufC){ ds, 32 });
                QCBOREncode_AddBytesToMap(&ctx, "r", (UsefulBufC){ dr, 32 });
                QCBOREncode_CloseMap(&ctx);
            }
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
    if (QCBORDecode_GetAndResetError(&ctx) != QCBOR_SUCCESS) {
        free(cbor_buf);
        return CASHU_ERR_CBOR_DECODE;
    }
    QCBORDecode_GetTextStringInMapSZ(&ctx, "u", &unit_c);
    if (QCBORDecode_GetAndResetError(&ctx) != QCBOR_SUCCESS) {
        free(cbor_buf);
        return CASHU_ERR_CBOR_DECODE;
    }

    out->mint_url = dupn_safe(mint_c.ptr, mint_c.len);
    out->unit     = dupn_safe(unit_c.ptr, unit_c.len);
    out->proofs    = NULL;
    out->proof_count = 0;
    out->memo      = NULL;
    if (!out->mint_url || !out->unit) {
        free(out->mint_url);
        free(out->unit);
        free(cbor_buf);
        return CASHU_ERR_OOM;
    }

    {
        UsefulBufC memo_c;
        QCBORDecode_GetTextStringInMapSZ(&ctx, "d", &memo_c);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_SUCCESS && memo_c.ptr)
            out->memo = dupn_safe(memo_c.ptr, memo_c.len);
    }

    QCBORDecode_EnterArrayFromMapSZ(&ctx, "t");

    while (1) {
        QCBORDecode_EnterMap(&ctx, NULL);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_ERR_NO_MORE_ITEMS) break;

        UsefulBufC id_c;
        QCBORDecode_GetByteStringInMapSZ(&ctx, "i", &id_c);
        if (QCBORDecode_GetAndResetError(&ctx) != QCBOR_SUCCESS ||
            !id_c.ptr || id_c.len != 8) {
            // cleanup: token_free would free proofs, but there may be partial state
            for (size_t i = 0; i < out->proof_count; i++) {
                free(out->proofs[i].id);
                free(out->proofs[i].secret);
            }
            free(out->proofs);
            free(out->mint_url);
            free(out->unit);
            free(out->memo);
            free(cbor_buf);
            return CASHU_ERR_CBOR_DECODE;
        }

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
            if (QCBORDecode_GetAndResetError(&ctx) != QCBOR_SUCCESS ||
                !secret_c.ptr || !C_c.ptr || C_c.len != 33) {
                for (size_t i = 0; i < out->proof_count; i++) {
                    free(out->proofs[i].id);
                    free(out->proofs[i].secret);
                }
                free(out->proofs);
                free(out->mint_url);
                free(out->unit);
                free(out->memo);
                free(cbor_buf);
                return CASHU_ERR_CBOR_DECODE;
            }
            proof_t *tmp = realloc(out->proofs, (out->proof_count + 1) * sizeof(proof_t));
            if (tmp == NULL) {
                for (size_t i = 0; i < out->proof_count; i++) {
                    free(out->proofs[i].id);
                    free(out->proofs[i].secret);
                }
                free(out->proofs);
                free(out->mint_url);
                free(out->unit);
                free(out->memo);
                free(cbor_buf);
                return CASHU_ERR_OOM;
            }
            out->proofs = tmp;
            proof_t *p  = &out->proofs[out->proof_count++];
            p->amount   = amount;
            p->id       = strdup(id_hex);
            p->secret   = dupn_safe(secret_c.ptr, secret_c.len);
            if (!p->id || !p->secret) {
                free(p->id);
                free(p->secret);
                for (size_t i = 0; i < out->proof_count - 1; i++) {
                    free(out->proofs[i].id);
                    free(out->proofs[i].secret);
                }
                free(out->proofs);
                free(out->mint_url);
                free(out->unit);
                free(out->memo);
                free(cbor_buf);
                return CASHU_ERR_OOM;
            }
            memcpy(p->C, C_c.ptr, 33);

            p->has_dleq = false;
            {
                QCBORDecode_EnterMapFromMapSZ(&ctx, "d");
                QCBORError derr = QCBORDecode_GetAndResetError(&ctx);
                if (derr == QCBOR_SUCCESS) {
                    UsefulBufC de = {NULL,0}, ds = {NULL,0}, dr = {NULL,0};
                    QCBORDecode_GetByteStringInMapSZ(&ctx, "e", &de);
                    QCBORDecode_GetAndResetError(&ctx);
                    QCBORDecode_GetByteStringInMapSZ(&ctx, "s", &ds);
                    QCBORDecode_GetAndResetError(&ctx);
                    QCBORDecode_GetByteStringInMapSZ(&ctx, "r", &dr);
                    QCBORDecode_GetAndResetError(&ctx);
                    QCBORDecode_ExitMap(&ctx);
                    QCBORDecode_GetAndResetError(&ctx);
                    if (de.ptr && de.len == 32 && ds.ptr && ds.len == 32 &&
                        dr.ptr && dr.len == 32) {
                        hex_encode(de.ptr, 32, p->dleq_e); p->dleq_e[64] = '\0';
                        hex_encode(ds.ptr, 32, p->dleq_s); p->dleq_s[64] = '\0';
                        hex_encode(dr.ptr, 32, p->dleq_r); p->dleq_r[64] = '\0';
                        p->has_dleq = true;
                    }
                }
            }

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

// ===================================================================
//                      decode payment request
// ===================================================================

cashu_err_t creq_decode(const char *encoded, payment_request_t *out) {
    if (strncmp(encoded, "creqA", 5) != 0) return CASHU_ERR_INVALID_PAYMENT_REQUEST;

    size_t cbor_len;
    uint8_t *cbor_buf = b64url_decode(encoded + 5, &cbor_len);
    if (!cbor_buf) return CASHU_ERR_OOM;

    out->id          = NULL;
    out->amount      = 0;
    out->unit        = NULL;
    out->has_amount  = false;
    out->single_use  = false;
    out->mints       = NULL;
    out->mint_count  = 0;
    out->description     = NULL;
    out->transports      = NULL;
    out->transport_count = 0;

    cashu_err_t ret = CASHU_OK;

    QCBORDecodeContext ctx;
    QCBORDecode_Init(&ctx, (UsefulBufC){ cbor_buf, cbor_len }, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&ctx, NULL);

    {
        UsefulBufC id;
        QCBORDecode_GetTextStringInMapSZ(&ctx, "i", &id);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_SUCCESS && id.ptr)
            out->id = dupn_safe(id.ptr, id.len);
    }

    {
        uint64_t amount;
        QCBORDecode_GetUInt64InMapSZ(&ctx, "a", &amount);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_SUCCESS) {
            out->amount     = amount;
            out->has_amount = true;
        }
    }

    {
        UsefulBufC unit;
        QCBORDecode_GetTextStringInMapSZ(&ctx, "u", &unit);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_SUCCESS && unit.ptr) {
            out->unit = dupn_safe(unit.ptr, unit.len);
            if (!out->unit) { ret = CASHU_ERR_OOM; goto cleanup; }
        } else if (out->has_amount) {
            ret = CASHU_ERR_INVALID_PAYMENT_REQUEST;
            goto cleanup;
        }
    }

    {
        bool su;
        QCBORDecode_GetBoolInMapSZ(&ctx, "s", &su);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_SUCCESS)
            out->single_use = su;
    }

    {
        UsefulBufC desc;
        QCBORDecode_GetTextStringInMapSZ(&ctx, "d", &desc);
        if (QCBORDecode_GetAndResetError(&ctx) == QCBOR_SUCCESS && desc.ptr)
            out->description = dupn_safe(desc.ptr, desc.len);
    }

    {
        QCBORDecode_EnterArrayFromMapSZ(&ctx, "m");
        QCBORError merr = QCBORDecode_GetAndResetError(&ctx);
        if (merr == QCBOR_SUCCESS) {
            while (1) {
                UsefulBufC mint_url;
                QCBORDecode_GetTextString(&ctx, &mint_url);
                QCBORError ierr = QCBORDecode_GetAndResetError(&ctx);
                if (ierr == QCBOR_ERR_NO_MORE_ITEMS) break;
                if (ierr != QCBOR_SUCCESS) {
                    ret = CASHU_ERR_INVALID_PAYMENT_REQUEST;
                    goto cleanup;
                }
                char **tmp = realloc(out->mints, (out->mint_count + 1) * sizeof(char *));
                if (!tmp) { ret = CASHU_ERR_OOM; goto cleanup; }
                out->mints = tmp;
                out->mints[out->mint_count] = dupn_safe(mint_url.ptr, mint_url.len);
                if (!out->mints[out->mint_count]) { ret = CASHU_ERR_OOM; goto cleanup; }
                out->mint_count++;
            }
            QCBORDecode_ExitArray(&ctx);
            QCBORDecode_GetAndResetError(&ctx);
        } else if (merr != QCBOR_ERR_LABEL_NOT_FOUND) {
            ret = CASHU_ERR_INVALID_PAYMENT_REQUEST;
            goto cleanup;
        }
    }

    {
        QCBORDecode_EnterArrayFromMapSZ(&ctx, "t");
        QCBORError terr = QCBORDecode_GetAndResetError(&ctx);
        if (terr == QCBOR_SUCCESS) {
            while (1) {
                QCBORDecode_EnterMap(&ctx, NULL);
                QCBORError ierr = QCBORDecode_GetAndResetError(&ctx);
                if (ierr == QCBOR_ERR_NO_MORE_ITEMS) break;
                if (ierr != QCBOR_SUCCESS) {
                    ret = CASHU_ERR_INVALID_PAYMENT_REQUEST;
                    goto cleanup;
                }

                UsefulBufC type_c = { NULL, 0 };
                UsefulBufC addr_c = { NULL, 0 };
                QCBORDecode_GetTextStringInMapSZ(&ctx, "t", &type_c);
                QCBORDecode_GetAndResetError(&ctx); /* type is optional */
                QCBORDecode_GetTextStringInMapSZ(&ctx, "a", &addr_c);
                QCBORDecode_GetAndResetError(&ctx); /* addr is optional */
                QCBORDecode_ExitMap(&ctx);
                QCBORDecode_GetAndResetError(&ctx);

                payment_request_transport_t *tmp =
                    realloc(out->transports,
                            (out->transport_count + 1) * sizeof(payment_request_transport_t));
                if (!tmp) { ret = CASHU_ERR_OOM; goto cleanup; }
                out->transports = tmp;
                payment_request_transport_t *tr = &out->transports[out->transport_count++];
                if (type_c.ptr) {
                    size_t tlen = type_c.len < 15 ? type_c.len : 15;
                    memcpy(tr->type, type_c.ptr, tlen);
                    tr->type[tlen] = '\0';
                } else {
                    tr->type[0] = '\0';
                }
                tr->target = addr_c.ptr ? dupn_safe(addr_c.ptr, addr_c.len) : NULL;
            }
            QCBORDecode_ExitArray(&ctx);
            QCBORDecode_GetAndResetError(&ctx);
        } else if (terr != QCBOR_ERR_LABEL_NOT_FOUND) {
            ret = CASHU_ERR_INVALID_PAYMENT_REQUEST;
            goto cleanup;
        }
    }

cleanup:
    if (ret != CASHU_OK) {
        free(out->id);              out->id          = NULL;
        free(out->unit);            out->unit        = NULL;
        free(out->description);     out->description = NULL;
        for (size_t i = 0; i < out->mint_count; i++) free(out->mints[i]);
        free(out->mints);           out->mints       = NULL;
        out->mint_count = 0;
        for (size_t i = 0; i < out->transport_count; i++) free(out->transports[i].target);
        free(out->transports);      out->transports      = NULL;
        out->transport_count = 0;
    }
    free(cbor_buf);
    return ret;
}

