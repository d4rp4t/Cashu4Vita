//
// Created by d4rp4t on 20/02/2026.
//

#ifndef JSON_H
#define JSON_H

#include "errors.h"
#include "models.h"


char *json_mint_quote_request(uint64_t amount, const char *unit);
char *json_mint_request(const char *quote, const blinded_message_t *outputs, size_t count);

char *json_melt_quote_request(const char *bolt11, const char *unit);
char *json_melt_request(const char *quote, const proof_t *inputs, size_t count,
                        const blinded_message_t *outputs, size_t out_n);

char *json_swap_request(const proof_t *inputs, size_t inp_n,
                        const blinded_message_t *outputs, size_t out_n);

// nut-18 POST transport payload
// id and memo are optional
char *json_pr_payload(const char *id, const char *memo,
                      const char *mint, const char *unit,
                      const proof_t *proofs, size_t proof_count);


cashu_err_t json_parse_mint_quote(const char *json, mint_quote_t *out);
cashu_err_t json_parse_melt_quote(const char *json, melt_quote_t *out);

cashu_err_t json_parse_signatures(const char *json, blind_signature_t **out, size_t *count);

cashu_err_t json_parse_keys(const char *json, keyset_t **out, size_t *count);

cashu_err_t json_parse_keysets(const char *json, keyset_t **out, size_t *count);

#endif //JSON_H
