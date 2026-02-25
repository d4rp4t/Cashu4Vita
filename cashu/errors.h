//
// Created by d4rp4t on 20/02/2026.
//

#ifndef ERRORS_H
#define ERRORS_H

typedef enum {
    CASHU_OK = 0,

    CASHU_ERR_OOM,               // malloc / realloc returned NULL

    CASHU_ERR_HASH_TO_CURVE,     // hash_to_curve: no valid point found
    CASHU_ERR_INVALID_POINT,     // pubkey parse / combine failed
    CASHU_ERR_INVALID_SCALAR,    // scalar / seckey invalid

    CASHU_ERR_CBOR_ENCODE,       // qcbor encode failed
    CASHU_ERR_CBOR_DECODE,       // qcbor decode failed
    CASHU_ERR_INVALID_TOKEN,     // bad cashuB prefix or base64url

    CASHU_ERR_JSON_PARSE,        // cJSON_Parse returned NULL
    CASHU_ERR_JSON_MISSING,      // required field absent or wrong type

    CASHU_ERR_HTTP,              // SceHttp call failed
    CASHU_ERR_HTTP_STATUS,       // server returned non-2xx

    CASHU_ERR_IO,                // file read/write failed

    CASHU_ERR_PROTOCOL,          // mint returned protocol exception

    CASHU_ERR_INSUFFICIENT_FUNDS, // wallet balance < requested amount

    CASHU_ERR_INVALID_PAYMENT_REQUEST, // bad creqA prefix or missing required field
} cashu_err_t;

#endif //ERRORS_H
