//
// Created by d4rp4t on 22/02/2026.
//
#ifndef QR_READER_H
#define QR_READER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    QR_READER_SCANNING,   // waiting for QR
    QR_READER_COMPLETE,   // cashu token ready (cashuB or bc-ur decoded)
    QR_READER_BOLT11,     // lightning invoice ready
    QR_READER_ERROR,      // decode error
} qr_reader_state_t;

/*
 * open camera and initialize quirc + bc-ur decoder.
 * returns 0 on success, negative on error.
 */
int  qr_reader_init(void);
void qr_reader_term(void);

/*
 * process single camera frame. call once per game loop tick.
 * reads camera frame, runs quirc, feeds recognized QR strings into
 * the bc-ur decoder (or detects a plain cashuA/cashuB token directly)
 */
//todo add creq
qr_reader_state_t qr_reader_tick(void);

// decode progress: 0.0 (nothing) → 1.0 (complete).
double qr_reader_progress(void);

/*
 * when state == QR_READER_COMPLETE:
 * returns malloced, null-terminated cashuB token string
 * caller must free(). subsequent calls return NULL.
 */
char *qr_reader_result(void);

// reset bc-ur decoder (e.g. after QR_READER_ERROR to retry).
void qr_reader_reset(void);

/*
 * returns a pointer to the latest Y-plane (grayscale) camera frame buffer
 * (CAM_WIDTH * CAM_HEIGHT bytes)
 * NULL before camera is opened
 * if w/h are non-NULL they are set to the frame dimensions
 */
const uint8_t *qr_reader_frame(int *w, int *h);

#endif /* QR_READER_H */
