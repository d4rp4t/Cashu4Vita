//
// Created by d4rp4t on 22/02/2026.
//
#ifndef BCUR_H
#define BCUR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
//                             encoder
// ============================================================================

typedef struct bcur_encoder bcur_encoder_t;

// create encoder for raw `data` of `len` bytes
// `max_fragment_len` controls how many characters per QR part (e.g. 200)
// returns NULL on allocation failure
bcur_encoder_t *bcur_encoder_new(const uint8_t *data, size_t len,
                                  size_t max_fragment_len);
void bcur_encoder_free(bcur_encoder_t *enc);

// returns heap-allocated part string, caller free()s it
// cycles through fountain parts indefinitely — call in render loop
char *bcur_encoder_next_part(bcur_encoder_t *enc);

// true once seq_num >= seq_len (all original parts emitted at least once)
int bcur_encoder_is_complete(const bcur_encoder_t *enc);

// total number of original parts (= number of QR frames before fountain kicks in)
size_t bcur_encoder_seq_len(const bcur_encoder_t *enc);

// current sequence number (increments each next_part())
uint32_t bcur_encoder_seq_num(const bcur_encoder_t *enc);

// ============================================================================
//                             Decoder
// ============================================================================

typedef struct bcur_decoder bcur_decoder_t;

bcur_decoder_t *bcur_decoder_new(void);
void bcur_decoder_free(bcur_decoder_t *dec);

// feed one QR string
// returns 1 if the part was useful, 0 otherwise
int bcur_decoder_receive_part(bcur_decoder_t *dec, const char *part);

// 1 once decoding is done (success or failure)
int bcur_decoder_is_complete(const bcur_decoder_t *dec);

// 1 if complete AND successful
int bcur_decoder_is_success(const bcur_decoder_t *dec);

// 0.0–1.0 estimated progress
double bcur_decoder_progress(const bcur_decoder_t *dec);

// returns heap allocated decoded bytes on success, caller free()s it
// sets *len
// returns NULL if not yet complete or failed
uint8_t *bcur_decoder_result(const bcur_decoder_t *dec, size_t *len);

#ifdef __cplusplus
}
#endif

#endif // BCUR_H
