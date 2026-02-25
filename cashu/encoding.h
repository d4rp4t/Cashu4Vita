//
// Created by d4rp4t on 20/02/2026.
//

#ifndef ENCODING_H
#define ENCODING_H

#include "errors.h"
#include "models.h"

cashu_err_t token_encode(const token_t *token, char **out);
cashu_err_t token_decode(const char *encoded, token_t *out);
cashu_err_t creq_decode(const char *encoded, payment_request_t *out);

#endif //ENCODING_H
