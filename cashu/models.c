//
// Created by d4rp4t on 18/02/2026.
//
#include <stdint.h>
#include "models.h"
#include <qcbor/qcbor_encode.h>
#include <qcbor/qcbor_decode.h>

int token_to_cbor(const token_t *token, uint8_t *buf, size_t buf_len, size_t *out_len) {
    UsefulBuf output = { buf, buf_len };
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, output);

    QCBOREncode_OpenMap(&ctx);
    QCBOREncode_AddSZStringToMap(&ctx, "m", token->mint_url); // zastąp
    QCBOREncode_AddSZStringToMap(&ctx, "u", token->unit);

    QCBOREncode_OpenArrayInMap(&ctx, "t");
    QCBOREncode_OpenMap(&ctx);

    // i = kid hex to bytex
    uint8_t *kid;
    // token->proofs[0].id_bytes
    UsefulBufC id_bytes = { kid, 8 };
    QCBOREncode_AddBytesToMap(&ctx, "i", id_bytes);

    QCBOREncode_OpenArrayInMap(&ctx, "p");
    for (size_t i = 0; i < token->proof_count; i++) {
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
    QCBOREncode_CloseArray(&ctx);
    QCBOREncode_CloseMap(&ctx);

    UsefulBufC result;
    if (QCBOREncode_Finish(&ctx, &result) != QCBOR_SUCCESS) return 1;
    *out_len = result.len;
    return 0;
}
int token_decode (const char *json, token_t *out) {

}