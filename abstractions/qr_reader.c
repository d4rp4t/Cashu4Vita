//
// Created by d4rp4t on 22/02/2026.

#include "qr_reader.h"
#include "../cashu/bcur.h"

#include <quirc.h>
#include <psp2/camera.h>

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
// =============================================================================
//                                  camera config
// =============================================================================
#define CAM_DEVICE  SCE_CAMERA_DEVICE_BACK
#define CAM_WIDTH   320
#define CAM_HEIGHT  240
#define CAM_Y_SIZE  (CAM_WIDTH * CAM_HEIGHT)
#define CAM_UV_SIZE (CAM_Y_SIZE / 2)  /* YUV420: U+V each WH/4 */

// =============================================================================
//                                  internal state
// =============================================================================
static struct quirc      *s_qr        = NULL;
static bcur_decoder_t    *s_dec       = NULL;
static qr_reader_state_t  s_state     = QR_READER_SCANNING;
static char              *s_result    = NULL;

/*
 * camera DMA buffers MUST BE allocated as static arrays rather than heap
 * camera DMA controller writes directly to these buffers, keeping them
 * outside the malloc heap prevents any DMA overrun from corrupting heap
 * metadata and causing a downstream crash in malloc/free traversal
 * i've spent 2 hours on it
 */
static uint8_t s_y_buf_storage[CAM_Y_SIZE];
static uint8_t s_uv_buf_storage[CAM_UV_SIZE];
static uint8_t *s_y_buf      = NULL;  // points into s_y_buf_storage when active
static uint8_t *s_uv_buf     = NULL;  //points into s_uv_buf_storage when active
static int      s_cam_active = 0;

// large structs kept as module-level statics to avoid ~13 KB of stack use per tick
static struct quirc_code s_qr_code;
static struct quirc_data s_qr_data;

// =============================================================================
//                                  camera
// =============================================================================

static int cam_open(void) {
    s_y_buf  = s_y_buf_storage;
    s_uv_buf = s_uv_buf_storage;
    memset(s_y_buf_storage,  0, CAM_Y_SIZE);
    memset(s_uv_buf_storage, 0, CAM_UV_SIZE);

    SceCameraInfo ci;
    memset(&ci, 0, sizeof(ci));
    ci.size      = sizeof(SceCameraInfo);
    ci.format    = SCE_CAMERA_FORMAT_YUV420_PLANE;
    ci.resolution = SCE_CAMERA_RESOLUTION_320_240;
    ci.framerate  = SCE_CAMERA_FRAMERATE_15_FPS;
    // Y plane = luminance = grayscale
    ci.pIBase    = s_y_buf;
    ci.sizeIBase = CAM_Y_SIZE;
    ci.pUBase    = s_uv_buf;
    ci.sizeUBase = CAM_UV_SIZE / 2;
    ci.pVBase    = s_uv_buf + CAM_UV_SIZE / 2;
    ci.sizeVBase = CAM_UV_SIZE / 2;

    if (sceCameraOpen(CAM_DEVICE, &ci) < 0)  return -1;
    if (sceCameraStart(CAM_DEVICE)     < 0) {
        sceCameraClose(CAM_DEVICE);
        return -1;
    }
    s_cam_active = 1;
    return 0;
}

static void cam_close(void) {
    if (s_cam_active) {
        sceCameraStop(CAM_DEVICE);
        sceCameraClose(CAM_DEVICE);
        s_cam_active = 0;
    }
    s_y_buf  = NULL;
    s_uv_buf = NULL;
}

// non-blocking read - returns 0 if a new frame is available in s_y_buf.
static int cam_read(void) {
    SceCameraRead cr;
    memset(&cr, 0, sizeof(cr));
    cr.size = sizeof(SceCameraRead);
    cr.mode = 1; // non-blocking: return latest frame or error if none ready
    return sceCameraRead(CAM_DEVICE, &cr);
}


// =============================================================================
//                           qr payload handling
// =============================================================================

static int has_prefix(const char *s, const char *prefix) {
    while (*prefix)
        if (tolower((unsigned char)*s++) != (unsigned char)*prefix++) return 0;
    return 1;
}

static void process_payload(const uint8_t *data, size_t len) {
    if (s_state == QR_READER_COMPLETE  ||
        s_state == QR_READER_BOLT11    ||
        s_state == QR_READER_PAYMENT_REQUEST) return;

    char *str = malloc(len + 1);
    if (!str) return;
    memcpy(str, data, len);
    str[len] = '\0';

    /* strip known URI scheme prefixes before classifying */
    const char *p = str;
    if (strncmp(p, "cashu:", 6) == 0)        p += 6;  /* cashu:cashuB... */
    else if (has_prefix(p, "lightning:")) p += 10; /* lightning:lnbc... */

    if (strncmp(p, "creqA", 5) == 0) {
        // cashu payment request
        char *req = strdup(p);
        free(str);
        if (!req) return;
        free(s_result);
        s_result = req;
        s_state  = QR_READER_PAYMENT_REQUEST;

    } else if (strncmp(p, "cashu", 5) == 0) {
        /* cashu token — strdup from p to drop any leading URI scheme */
        char *tok = strdup(p);
        free(str);
        if (!tok) return;
        free(s_result);
        s_result = tok;
        s_state  = QR_READER_COMPLETE;

    } else if (strncmp(p, "ur:", 3) == 0) {
        /* bc-ur fountain part */
        bcur_decoder_receive_part(s_dec, p);
        free(str);

        if (bcur_decoder_is_complete(s_dec)) {
            if (bcur_decoder_is_success(s_dec)) {
                size_t rlen = 0;
                uint8_t *raw = bcur_decoder_result(s_dec, &rlen);
                if (raw && rlen > 0) {
                    char *tok = realloc(raw, rlen + 1);
                    if (tok) {
                        tok[rlen] = '\0';
                        free(s_result);
                        s_result = tok;
                        s_state  = QR_READER_COMPLETE;
                    } else {
                        free(raw);
                        s_state = QR_READER_ERROR;
                    }
                } else {
                    free(raw);
                    s_state = QR_READER_ERROR;
                }
            } else {
                s_state = QR_READER_ERROR;
            }
        }

    } else if (has_prefix(p, "ln")) {
        /* bolt11 — lowercase in-place then strdup */
        for (size_t i = 0; p[i]; i++)
            ((char *)p)[i] = (char)tolower((unsigned char)p[i]);
        char *inv = strdup(p);
        free(str);
        if (!inv) return;
        free(s_result);
        s_result = inv;
        s_state  = QR_READER_BOLT11;

    } else {
        free(str); /* unrecognized */
    }
}

// =============================================================================
//                                     api
// =============================================================================

int qr_reader_init(void) {
    if (cam_open() < 0) return -1;

    s_qr = quirc_new();
    if (!s_qr) { cam_close(); return -1; }

    if (quirc_resize(s_qr, CAM_WIDTH, CAM_HEIGHT) < 0) {
        quirc_destroy(s_qr); s_qr = NULL;
        cam_close();
        return -1;
    }

    s_dec = bcur_decoder_new();
    if (!s_dec) {
        quirc_destroy(s_qr); s_qr = NULL;
        cam_close();
        return -1;
    }

    s_state  = QR_READER_SCANNING;
    s_result = NULL;
    return 0;
}

void qr_reader_term(void) {
    bcur_decoder_free(s_dec); s_dec = NULL;
    quirc_destroy(s_qr);      s_qr  = NULL;
    cam_close();
    free(s_result); s_result = NULL;
    s_state = QR_READER_SCANNING;
}

qr_reader_state_t qr_reader_tick(void) {
    if (s_state != QR_READER_SCANNING) return s_state;
    if (!s_cam_active || !s_qr || !s_dec) return s_state;

    if (cam_read() < 0) return s_state; // no new frame this tick

    // copy Y plane into quirc image buffer
    int w, h;
    uint8_t *buf = quirc_begin(s_qr, &w, &h);
    memcpy(buf, s_y_buf, (size_t)(w * h));
    quirc_end(s_qr);

    int n = quirc_count(s_qr);
    for (int i = 0; i < n; i++) {
        quirc_extract(s_qr, i, &s_qr_code);
        if (quirc_decode(&s_qr_code, &s_qr_data) == QUIRC_SUCCESS)
            process_payload(s_qr_data.payload, s_qr_data.payload_len);
    }
    return s_state;
}

double qr_reader_progress(void) {
    if (s_state == QR_READER_COMPLETE) return 1.0;
    if (!s_dec) return 0.0;
    return bcur_decoder_progress(s_dec);
}

char *qr_reader_result(void) {
    if (s_state != QR_READER_COMPLETE &&
        s_state != QR_READER_BOLT11   &&
        s_state != QR_READER_PAYMENT_REQUEST) return NULL;
    char *r  = s_result;
    s_result = NULL;
    return r;
}

const uint8_t *qr_reader_frame(int *w, int *h) {
    if (w) *w = CAM_WIDTH;
    if (h) *h = CAM_HEIGHT;
    return s_y_buf;
}

void qr_reader_reset(void) {
    bcur_decoder_free(s_dec);
    s_dec    = bcur_decoder_new();
    free(s_result);
    s_result = NULL;
    s_state  = QR_READER_SCANNING;
}
