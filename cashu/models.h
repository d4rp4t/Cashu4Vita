//
// Created by d4rp4t on 18/02/2026.
//

#ifndef CASHU_MODELS_H
#define CASHU_MODELS_H

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
    char *memo;
} token_t;


typedef struct {
    uint64_t amount;
    char pubkey[67]; // 66 hex + '\0'
} keyset_key_t;

typedef struct {
    char *id;
    char *unit;
    int active;
    uint32_t input_fee_ppk;
    keyset_key_t *keys;
    size_t key_count;
} keyset_t;


typedef struct {
    char *quote;
    char *request; // bolt11 invoice
    char *state;   // UNPAID / PAID / ISSUED
    uint32_t expiry;
} mint_quote_t;

typedef struct {
    char *quote;
    uint64_t amount;
    uint64_t fee_reserve;
    char *state;
    char *payment_preimage; // NULL if not set
} melt_quote_t;

void proof_free(proof_t *p);
void token_free(token_t *t);
void keyset_free(keyset_t *k);
void mint_quote_free(mint_quote_t *q);
void melt_quote_free(melt_quote_t *q);

#endif
