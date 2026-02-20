//
// Created by d4rp4t on 19/02/2026.
//
#include <stdint.h>
#include <stdio.h>
#include "utils.h"


static const int8_t hex_lut[256] = {
    ['0'] = 0,  ['1'] = 1,  ['2'] = 2,  ['3'] = 3,
    ['4'] = 4,  ['5'] = 5,  ['6'] = 6,  ['7'] = 7,
    ['8'] = 8,  ['9'] = 9,
    ['a'] = 10, ['b'] = 11, ['c'] = 12, ['d'] = 13, ['e'] = 14, ['f'] = 15,
    ['A'] = 10, ['B'] = 11, ['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
};

void hex_encode(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", bytes[i]);
    out[len * 2] = '\0';
}

void pubkey_to_hex(const secp256k1_context *ctx, const secp256k1_pubkey *key, char *out) {
    uint8_t buf[33];
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, buf, &len, key, SECP256K1_EC_COMPRESSED);
    hex_encode(buf, 33, out);
}

int hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_lut[(uint8_t)hex[2*i]];
        int lo = hex_lut[(uint8_t)hex[2*i + 1]];
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}