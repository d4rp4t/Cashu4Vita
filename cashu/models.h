//
// Created by d4rp4t on 18/02/2026.
//

#ifndef CASHU_PROOF_H
#define CASHU_PROOF_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t amount;
    char *id;
    char *B_;
} blinded_message_t;

typedef struct {
    uint64_t amount;
    char *id;
    char *C_;
} blind_signature_t;

typedef struct {
    uint64_t amount;
    char *id; // keysetid
    char *secret;
    uint8_t C[33];
} proof_t;

typedef struct {
    char *mint_url;
    char *unit;
    proof_t *proofs;
    size_t proof_count;
} token_t;

// serialization
int token_encode (const token_t *token, char *out);
int token_decode (const char *json, token_t *out);

#endif