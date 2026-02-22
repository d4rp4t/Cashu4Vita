//
// Created by d4rp4t on 22/02/2026.
//
#ifndef EXPORTS_H
#define EXPORTS_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char    *token;   /* cashuB string */
    uint64_t amount;
} exported_token_t;

/* append a new exported token to the JSON file. */
int exports_save(const char *path, const char *token, uint64_t amount);

/* load all exported tokens. Caller must call exports_free(). */
int exports_load(const char *path, exported_token_t **out, size_t *count);

/* delete entry at index idx (rewrites file). */
int exports_delete(const char *path, size_t idx);

void exports_free(exported_token_t *list, size_t count);

#endif /* EXPORTS_H */
