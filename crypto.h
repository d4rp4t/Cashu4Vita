//
// Created by d4rp4t on 18/02/2026.
//
#ifndef CRYPTO_H
#define CRYPTO_H
#include <secp256k1.h>
#include <stdint.h>

void crypto_init(void);
void crypto_free(void);

int hash_to_curve(const uint8_t *x, size_t x_len, secp256k1_pubkey *out);

int hex_to_curve(const char *hex, size_t hex_len, secp256k1_pubkey *out);
int message_to_curve(const char *message, secp256k1_pubkey *out);
int blind(
    const secp256k1_pubkey *Y,
    const uint8_t *r,
    secp256k1_pubkey *out
);
int unblind(
    const secp256k1_pubkey *C_,
    const uint8_t *r,
    const secp256k1_pubkey *A,
    secp256k1_pubkey *out
);
#endif //CRYPTO_H
