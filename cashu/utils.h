//
// Created by d4rp4t on 19/02/2026.
//

#ifndef UTILS_H
#define UTILS_H
#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

int hex_decode(const char *hex, uint8_t *out, size_t out_len);
void hex_encode(const uint8_t *bytes, size_t len, char *out);
void pubkey_to_hex(const secp256k1_context *ctx, const secp256k1_pubkey *key, char *out);
#endif //UTILS_H
