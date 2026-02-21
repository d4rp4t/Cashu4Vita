//
// Created by d4rp4t on 18/02/2026.
//
#include "models.h"
#include <stdlib.h>

void proof_free(proof_t *p) {
    if (!p) return;
    free(p->id);
    free(p->secret);
}

void token_free(token_t *t) {
    if (!t) return;
    free(t->mint_url);
    free(t->unit);
    free(t->memo);
    for (size_t i = 0; i < t->proof_count; i++)
        proof_free(&t->proofs[i]);
    free(t->proofs);
}

void keyset_free(keyset_t *k) {
    if (!k) return;
    free(k->id);
    free(k->unit);
    free(k->keys);
}

void mint_quote_free(mint_quote_t *q) {
    if (!q) return;
    free(q->quote);
    free(q->request);
    free(q->state);
}

void melt_quote_free(melt_quote_t *q) {
    if (!q) return;
    free(q->quote);
    free(q->state);
    free(q->payment_preimage);
}
