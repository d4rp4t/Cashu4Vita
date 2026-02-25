//
// Created by d4rp4t on 18/02/2026.
//

#ifndef CASHU_MODELS_H
#define CASHU_MODELS_H

#include <stdbool.h>
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
    // DLEQ proof from mint (optional)
    bool has_dleq;
    char dleq_e[65]; // e component - 32-byte scalar as hex + NUL
    char dleq_s[65]; // s component — 32-byte scalar as hex + NUL
} blind_signature_t;

typedef struct {
    uint64_t amount;
    char *id; // keysetid
    char *secret;
    uint8_t C[33];
    // NUT-12 DLEQ proof to forward to recipients (optional)
    bool has_dleq;
    char dleq_r[65]; // blinding factor hex
    char dleq_e[65]; // e component hex
    char dleq_s[65]; // s component hex
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
    char *payment_preimage;   // NULL if not set
    blind_signature_t *change; // change sigs; NULL if none
    size_t change_count;
} melt_quote_t;

typedef struct {
    char *id;
    char *memo;
    char *mint;
    char *unit;
    proof_t *proofs;
    size_t proof_count;
} payment_request_payload_t;

typedef struct {
    char  type[16];
    char *target;
} payment_request_transport_t;

typedef struct {
    char *id; //i

    bool has_amount;
    uint64_t amount; //a

    char *unit; //u MUST BE SET IF "amount" SET

    bool single_use; //s

    char **mints; //m
    size_t mint_count;

    char *description; //d

    payment_request_transport_t *transports; //t
    size_t transport_count;
    // we don't support p2pk here
} payment_request_t;


void proof_free(proof_t *p);
void token_free(token_t *t);
void keyset_free(keyset_t *k);
void mint_quote_free(mint_quote_t *q);
void melt_quote_free(melt_quote_t *q);
void payment_request_free(payment_request_t *r);

#endif
