//
// Created by d4rp4t on 18/02/2026.
//
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "errors.h"
#include <secp256k1.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void crypto_init(void);
void crypto_free(void);
secp256k1_context *crypto_ctx(void);

cashu_err_t hash_to_curve(const uint8_t *x, size_t x_len, secp256k1_pubkey *out);
cashu_err_t hex_to_curve(const char *hex, size_t hex_len, secp256k1_pubkey *out);
cashu_err_t message_to_curve(const char *message, secp256k1_pubkey *out);

cashu_err_t blind(const secp256k1_pubkey *Y, const uint8_t *r, secp256k1_pubkey *out);
cashu_err_t unblind(const secp256k1_pubkey *C_, const uint8_t *r,
                    const secp256k1_pubkey *A, secp256k1_pubkey *out);

// dleq verification
bool verify_dleq_blind_sig(const secp256k1_pubkey *B_,
                            const secp256k1_pubkey *C_,
                            const uint8_t e32[32],
                            const uint8_t s32[32],
                            const secp256k1_pubkey *A);

bool verify_dleq_unblinded(const uint8_t C_bytes[33],
                            const uint8_t r32[32],
                            const uint8_t e32[32],
                            const uint8_t s32[32],
                            const char *secret,
                            size_t secret_len,
                            const secp256k1_pubkey *A);

#endif //PROTOCOL_H
