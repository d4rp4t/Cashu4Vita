//
// Created by d4rp4t on 21/02/2026.
//
#ifndef STORAGE_H
#define STORAGE_H
#include "../cashu/models.h"
#include "../cashu/errors.h"

cashu_err_t storage_init(const char *path);
void        storage_term(void);

cashu_err_t storage_save_proof(const proof_t *p, const char *mint_url);
cashu_err_t storage_get_proofs(const char *keyset_id, proof_t **out, size_t *count);
cashu_err_t storage_get_by_mint(const char *mint_url, proof_t **out, size_t *count);
cashu_err_t storage_remove_proofs(const proof_t *proofs, size_t count);
cashu_err_t storage_swap(const proof_t *spent, size_t spent_n,
                         const proof_t *fresh,  size_t fresh_n,
                         const char    *mint_url);

// sum of all stored proof amounts across every mint
uint64_t storage_total_balance(void);

// returns heap-allocated array of unique mint URLs found in storage
// caller must free urls[i] and urls
cashu_err_t storage_list_mints(char ***urls_out, size_t *count_out);

#endif //STORAGE_H
