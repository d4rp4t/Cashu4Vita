//
// Created by d4rp4t on 20/02/2026.
//

#ifndef ENCODING_H
#define ENCODING_H

#include "models.h"

int token_encode(const token_t *token, char *out);
int token_decode(const char *encoded, token_t *out);

#endif //ENCODING_H
