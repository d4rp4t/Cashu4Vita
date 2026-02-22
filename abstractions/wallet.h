
//
// Created by d4rp4t on 21/02/2026.
//
#ifndef WALLET_H
#define WALLET_H

#include "../cashu/errors.h"
#include "../cashu/models.h"

// ==============================================================================
//                                 lifecycle
// =============================================================================

cashu_err_t wallet_init(const char *mint_url, const char *storage_path,
                        const char *unit);   // e.g. "sat"
void wallet_term(void);


// ==============================================================================
//                                 balance
// =============================================================================

uint64_t wallet_balance(void);          // total across all mints
uint64_t wallet_balance_for(const char *mint_url); // per-mint balance

// ==============================================================================
//                                 mint management
// =============================================================================

const char *wallet_active_mint(void);
void        wallet_set_active_mint(const char *url); // switches active mint

typedef struct { char *url; uint64_t balance; } mint_info_t;
cashu_err_t wallet_list_mints(mint_info_t **out, size_t *count);
void        wallet_mints_free(mint_info_t *mints, size_t count);

// ==============================================================================
//                                 minting
// =============================================================================

// flow:
//   1. wallet_mint_quote(amount, &q) --> show q.request (bolt11) as QR
//   2. poll wallet_mint_quote_state(q.quote, &q) until q.state == "PAID"
//   3. wallet_mint(q.quote, amount) --> proofs saved to storage
//   4. mint_quote_free(&q)

cashu_err_t wallet_mint_quote(uint64_t amount, mint_quote_t *out);
cashu_err_t wallet_mint_quote_state(const char *quote_id, mint_quote_t *out);
cashu_err_t wallet_mint(const char *quote_id, uint64_t amount);

// ==============================================================================
//                                 melting
// =============================================================================

// flow:
//   1. wallet_melt_quote(bolt11, &q) --> show q.amount + q.fee_reserve to user
//   2. wallet_melt(&q) --> proofs removed from storage on PAID
//   3. melt_quote_free(&q)

cashu_err_t wallet_melt_quote(const char *bolt11, melt_quote_t *out);
cashu_err_t wallet_melt(const melt_quote_t *melt_q);

// ==============================================================================
//                                 send / receive
// =============================================================================

// wallet_send:  selects proofs covering `amount` (swapping for exact change),
//               returns heap-allocated cashuB token string; caller free()s it.
// wallet_receive: decodes cashuB token, swaps proofs into own keyset, stores.

cashu_err_t wallet_send(uint64_t amount, char **token_out);
cashu_err_t wallet_receive(const char *token);

// ==============================================================================
//                                 swap (lowlevel)
// =============================================================================

// Re-blinds `inputs` into new proofs of `amounts`.
// sum(amounts) + fee must equal sum(inputs).

cashu_err_t wallet_swap(const proof_t  *inputs,  size_t input_n,
                        const uint64_t *amounts, size_t amount_n);

#endif //WALLET_H
