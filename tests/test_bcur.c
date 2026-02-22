//
// Created by d4rp4t on 22/02/2026.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../cashu/bcur.h"
#include "testing_utils.h"

static int pass_count  = 0;
static int total_count = 0;

// encode `data`, collect all original parts, then decode them back.
// returns heap-allocated recovered bytes on success, NULL on any failure.
// *out_len set to recovered length.
static uint8_t *roundtrip(const uint8_t *data, size_t len,
                           size_t max_frag, size_t *out_len) {
    bcur_encoder_t *enc = bcur_encoder_new(data, len, max_frag);
    if (!enc) return NULL;

    size_t   seq_len = bcur_encoder_seq_len(enc);
    char   **parts   = (char **)malloc(seq_len * sizeof(char *));
    if (!parts) { bcur_encoder_free(enc); return NULL; }

    for (size_t i = 0; i < seq_len; i++) {
        parts[i] = bcur_encoder_next_part(enc);
    }
    bcur_encoder_free(enc);

    bcur_decoder_t *dec = bcur_decoder_new();
    if (!dec) { for (size_t i = 0; i < seq_len; i++) free(parts[i]); free(parts); return NULL; }

    for (size_t i = 0; i < seq_len; i++) {
        bcur_decoder_receive_part(dec, parts[i]);
        free(parts[i]);
    }
    free(parts);

    uint8_t *result = NULL;
    if (bcur_decoder_is_success(dec))
        result = bcur_decoder_result(dec, out_len);

    bcur_decoder_free(dec);
    return result;
}

static void test_single_part(void) {
    // short payload → should fit in one part
    const char *msg = "hello cashu";
    size_t      len = strlen(msg);

    bcur_encoder_t *enc = bcur_encoder_new((const uint8_t *)msg, len, 200);
    ASSERT(enc != NULL, "single_part: encoder created");
    if (!enc) return;

    ASSERT(bcur_encoder_seq_len(enc) == 1, "single_part: seq_len == 1");
    ASSERT(bcur_encoder_is_complete(enc) == 0, "single_part: not complete before first part");

    char *part = bcur_encoder_next_part(enc);
    ASSERT(part != NULL, "single_part: got part string");
    ASSERT(strncmp(part, "ur:bytes/", 9) == 0, "single_part: starts with ur:bytes/");
    ASSERT(bcur_encoder_is_complete(enc) == 1, "single_part: complete after first part");

    // decode it back
    bcur_decoder_t *dec = bcur_decoder_new();
    ASSERT(dec != NULL, "single_part: decoder created");
    int useful = bcur_decoder_receive_part(dec, part);
    ASSERT(useful == 1, "single_part: part was useful");
    ASSERT(bcur_decoder_is_complete(dec) == 1, "single_part: decoder complete");
    ASSERT(bcur_decoder_is_success(dec) == 1, "single_part: decoder success");

    size_t   out_len;
    uint8_t *out = bcur_decoder_result(dec, &out_len);
    ASSERT(out != NULL,      "single_part: result not NULL");
    ASSERT(out_len == len,   "single_part: recovered length matches");
    ASSERT(memcmp(out, msg, len) == 0, "single_part: recovered bytes match");

    free(out);
    free(part);
    bcur_decoder_free(dec);
    bcur_encoder_free(enc);
}

static void test_multipart_roundtrip(void) {
    // 256 bytes of pseudo-random data split into small fragments → multi-part UR
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = (uint8_t)(i ^ 0xA5);

    size_t   out_len;
    uint8_t *recovered = roundtrip(data, sizeof(data), 50, &out_len);

    ASSERT(recovered != NULL,              "multipart: roundtrip succeeded");
    ASSERT(out_len == sizeof(data),        "multipart: recovered length matches");
    ASSERT(memcmp(recovered, data, sizeof(data)) == 0,
                                           "multipart: recovered bytes match");
    free(recovered);
}

static void test_parts_have_sequence(void) {
    uint8_t data[300];
    for (int i = 0; i < 300; i++) data[i] = (uint8_t)i;

    bcur_encoder_t *enc = bcur_encoder_new(data, sizeof(data), 60);
    ASSERT(enc != NULL, "sequence: encoder created");
    if (!enc) return;

    size_t seq_len = bcur_encoder_seq_len(enc);
    ASSERT(seq_len > 1, "sequence: multi-part (seq_len > 1)");

    // verify seq_num advances
    uint32_t prev = 0;
    int ok = 1;
    for (size_t i = 0; i < seq_len; i++) {
        char *p = bcur_encoder_next_part(enc);
        uint32_t cur = bcur_encoder_seq_num(enc);
        if (i > 0 && cur <= prev) ok = 0;
        prev = cur;
        free(p);
    }
    ASSERT(ok, "sequence: seq_num advances each call");
    ASSERT(bcur_encoder_is_complete(enc) == 1, "sequence: complete after all parts");

    bcur_encoder_free(enc);
}

int main(void) {
    printf("================= bcur tests =================\n");
    test_single_part();
    test_multipart_roundtrip();
    test_parts_have_sequence();
    printf("\n%d/%d passed\n", pass_count, total_count);
    return pass_count == total_count ? 0 : 1;
}
