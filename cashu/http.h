//
// Created by d4rp4t on 21/02/2026.
//

#ifndef HTTP_H
#define HTTP_H

#include "errors.h"
#include "models.h"


cashu_err_t cashu_http_init(void);
void cashu_http_term(void);

// last raw return code set on every CASHU_ERR_HTTP
int cashu_http_last_sce_err(void);

// GET /v1/keys
cashu_err_t cashu_get_keys(const char *mint_url, keyset_t **out, size_t *count);

// GET /v1/keysets
cashu_err_t cashu_get_keysets(const char *mint_url, keyset_t **out, size_t *count);

// POST /v1/mint/quote/bolt11
cashu_err_t cashu_mint_quote(const char *mint_url, uint64_t amount,
                             const char *unit, mint_quote_t *out);

// GET /v1/mint/quote/bolt11/{quote_id}
cashu_err_t cashu_mint_quote_state(const char *mint_url, const char *quote_id,
                                   mint_quote_t *out);

// POST /v1/mint/bolt11
cashu_err_t cashu_mint(const char *mint_url, const char *quote,
                       const blinded_message_t *outputs, size_t count,
                       blind_signature_t **sigs_out, size_t *sig_count);

// POST /v1/melt/quote/bolt11
cashu_err_t cashu_melt_quote(const char *mint_url, const char *bolt11,
                             const char *unit, melt_quote_t *out);

// GET /v1/melt/quote/bolt11/{quote_id}
cashu_err_t cashu_melt_quote_state(const char *mint_url, const char *quote_id,
                                   melt_quote_t *out);

// POST /v1/melt/bolt11
cashu_err_t cashu_melt(const char *mint_url, const char *quote,
                       const proof_t *inputs, size_t count,
                       const blinded_message_t *outputs, size_t out_n,
                       melt_quote_t *out);

// POST /v1/swap
cashu_err_t cashu_swap(const char *mint_url,
                       const proof_t *inputs,   size_t inp_n,
                       const blinded_message_t *outputs, size_t out_n,
                       blind_signature_t **sigs_out, size_t *sig_count);

#endif //HTTP_H
