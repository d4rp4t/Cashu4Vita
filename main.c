//
// Created by d4rp4t on 18/02/2026.
//
#include <vita2d.h>
#include <psp2/ctrl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/ime_dialog.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "abstractions/wallet.h"
#include "abstractions/exports.h"
#include "abstractions/qr_reader.h"
#include "cashu/http.h"
#include "cashu/protocol.h"
#include "cashu/models.h"
#include "cashu/encoding.h"
#include "cashu/bcur.h"
#include "qrcodegen.h"

#define MINT_URL     "https://testnut.cashu.space"
#define STORAGE_DIR  "ux0:data/VitaCashu"
#define STORAGE_PATH "ux0:data/VitaCashu/proofs.json"
#define EXPORTS_PATH "ux0:data/VitaCashu/exports.json"

// =============================================================================
//                                      colors
// =============================================================================
#define C_BG     RGBA8(0x10, 0x10, 0x10, 0xFF)
#define C_WHITE  RGBA8(0xFF, 0xFF, 0xFF, 0xFF)
#define C_GRAY   RGBA8(0xAA, 0xAA, 0xAA, 0xFF)
#define C_DIM    RGBA8(0x50, 0x50, 0x50, 0xFF)
#define C_LINE   RGBA8(0x28, 0x28, 0x28, 0xFF)
#define C_HILIGHT RGBA8(0x22, 0x22, 0x38, 0xFF)
#define C_YELLOW RGBA8(0xFF, 0xD7, 0x00, 0xFF)
#define C_GREEN  RGBA8(0x00, 0xFF, 0x88, 0xFF)
#define C_RED    RGBA8(0xFF, 0x44, 0x44, 0xFF)
#define C_CYAN   RGBA8(0x00, 0xE5, 0xFF, 0xFF)
#define C_BLUE   RGBA8(0x44, 0x88, 0xFF, 0xFF)

// =============================================================================
//                                  screen states
// =============================================================================
typedef enum {
    SCR_HOME,

    // melt (no manual input: bolt11 comes from QR scan)
    SCR_MELT_QUOTE,
    SCR_MELT_PAYING,
    SCR_MELT_RESULT,

    // mint
    SCR_MINT_AMOUNT,
    SCR_MINT_INVOICE,
    SCR_MINT_RESULT,

    // export token
    SCR_SEND_AMOUNT,
    SCR_SEND_QR,

    // show exported tokens
    SCR_EXPORTS,
    SCR_EXPORT_VIEW,

    // receive / payment request
    SCR_RECEIVE,
    SCR_RECEIVE_RESULT,
    SCR_CREQ_CONFIRM,   // NUT-18 payment request confirmation
} screen_t;

// =============================================================================
//                                      IME
// =============================================================================
static SceWChar16 s_ime_buf[512];

static void ime_open(const char *ascii_title, int numeric) {
    static SceWChar16 title_buf[64];
    size_t i = 0;
    while (i < 63 && ascii_title[i]) { title_buf[i] = (SceWChar16)ascii_title[i]; i++; }
    title_buf[i] = 0;

    SceImeDialogParam p;
    sceImeDialogParamInit(&p);
    p.supportedLanguages = 0;
    p.languagesForced    = SCE_FALSE;
    p.type               = numeric ? SCE_IME_TYPE_NUMBER : SCE_IME_TYPE_BASIC_LATIN;
    p.option             = 0;
    p.title              = title_buf;
    p.maxTextLength      = (unsigned int)(sizeof(s_ime_buf) / sizeof(s_ime_buf[0])) - 1;
    p.inputTextBuffer    = s_ime_buf;
    memset(s_ime_buf, 0, sizeof(s_ime_buf));
    sceImeDialogInit(&p);
}

static void ime_to_ascii(char *dst, size_t max) {
    size_t i = 0;
    while (i < max - 1 && s_ime_buf[i]) { dst[i] = (char)(s_ime_buf[i] & 0x7F); i++; }
    dst[i] = '\0';
}

static uint64_t ime_to_u64(void) {
    char buf[32]; ime_to_ascii(buf, sizeof(buf));
    return (uint64_t)atoll(buf);
}

// =============================================================================
//                                QR rendering
// =============================================================================
static uint8_t s_qr_data[qrcodegen_BUFFER_LEN_MAX];
static uint8_t s_qr_tmp[qrcodegen_BUFFER_LEN_MAX];

/*
 * renders a QR code for `text` centered at (cx, cy)
 * max_px is the maximum side length in pixels
 * module size is computed so the QR always fits regardless of version
 */
static void draw_qr(const char *text, float cx, float cy, float max_px) {
    bool ok = qrcodegen_encodeText(text, s_qr_tmp, s_qr_data,
                                   qrcodegen_Ecc_LOW,
                                   qrcodegen_VERSION_MIN, qrcodegen_VERSION_MAX,
                                   qrcodegen_Mask_AUTO, true);
    if (!ok) return;
    int sz = qrcodegen_getSize(s_qr_data);
    float mod = max_px / (float)sz;
    if (mod < 1.0f) mod = 1.0f;
    float origin_x = cx - (sz * mod) / 2.0f;
    float origin_y = cy - (sz * mod) / 2.0f;
    float pad = mod * 2.0f;
    vita2d_draw_rectangle(origin_x - pad, origin_y - pad,
                          sz * mod + pad * 2.0f, sz * mod + pad * 2.0f, C_WHITE);
    for (int r = 0; r < sz; r++)
        for (int c = 0; c < sz; c++)
            if (qrcodegen_getModule(s_qr_data, c, r))
                vita2d_draw_rectangle(origin_x + c * mod, origin_y + r * mod,
                                      mod, mod, C_BG);
}

// =============================================================================
//                                draw helpers
// =============================================================================

static void hline(float y) {
    vita2d_draw_rectangle(0, y, 960, 1, C_LINE);
}

static void extract_host(const char *url, char *out, size_t max) {
    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) p += 8;
    else if (strncmp(p, "http://", 7) == 0) p += 7;
    size_t i = 0;
    while (p[i] && p[i] != '/' && i < max - 1) { out[i] = p[i]; i++; }
    out[i] = '\0';
}

static void draw_header(vita2d_pgf *f, const char *label) {
    vita2d_pgf_draw_text(f, 20, 34, C_WHITE, 1.0f, "VitaCashu");
    char host[48]; extract_host(wallet_active_mint(), host, sizeof(host));
    vita2d_pgf_draw_text(f, 960 - 20 - (int)(strlen(host) * 8), 34, C_DIM, 0.65f, host);
    hline(44);
    if (label)
        vita2d_pgf_draw_text(f, 20, 75, C_GRAY, 0.75f, label);
}

static void draw_hint(vita2d_pgf *f, const char *hint) {
    hline(460);
    vita2d_pgf_draw_text(f, 20, 530, C_DIM, 0.75f, hint);
}

static const char *err_str(cashu_err_t e) {
    switch (e) {
    case CASHU_OK:                    return "OK";
    case CASHU_ERR_OOM:               return "Out of memory";
    case CASHU_ERR_HTTP:              return "Network error";
    case CASHU_ERR_HTTP_STATUS:       return "Mint returned an error";
    case CASHU_ERR_JSON_PARSE:
    case CASHU_ERR_JSON_MISSING:      return "Bad response from mint";
    case CASHU_ERR_INVALID_TOKEN:              return "Invalid token";
    case CASHU_ERR_INVALID_PAYMENT_REQUEST:    return "Invalid payment request";
    case CASHU_ERR_INSUFFICIENT_FUNDS:         return "Insufficient funds";
    case CASHU_ERR_PROTOCOL:          return "Mint rejected request";
    case CASHU_ERR_IO:                return "Storage error";
    case CASHU_ERR_CBOR_ENCODE:
    case CASHU_ERR_CBOR_DECODE:       return "Encoding error";
    case CASHU_ERR_HASH_TO_CURVE:
    case CASHU_ERR_INVALID_POINT:
    case CASHU_ERR_INVALID_SCALAR:    return "Crypto error";
    default:                          return "Unknown error";
    }
}

static void trunc_str(const char *src, char *dst, size_t maxlen) {
    size_t len = strlen(src);
    if (len <= maxlen) { strcpy(dst, src); return; }
    strncpy(dst, src, maxlen - 3);
    strcpy(dst + maxlen - 3, "...");
}

// =============================================================================
//                                state
// =============================================================================

static uint64_t     s_balance;        // active mint balance
static uint64_t     s_total_balance;  // all mints combined
static screen_t     s_screen;
static char         s_errmsg[128];

// melt
static char         s_bolt11[512];
static melt_quote_t s_melt_q;
static cashu_err_t  s_melt_err;
static int          s_exec_melt;
static int          s_exec_melt_quote; /* fetch melt quote after bolt11 QR scan */

// mint
static uint64_t     s_mint_amount;
static mint_quote_t s_mint_q;
static cashu_err_t  s_mint_err;
static int          s_exec_mint_poll;
static int          s_exec_mint;

// send (also reused for export view)
static uint64_t         s_send_amount;
static bcur_encoder_t  *s_send_enc;
static char            *s_send_part;
static int              s_send_frame;
#define SEND_QR_INTERVAL 15   // advance QR part every N frames (~4 fps at 60 fps)

// exports
static exported_token_t *s_exports           = NULL;
static size_t            s_export_count      = 0;
static int               s_export_sel        = 0;
static uint64_t          s_export_view_amount = 0;

// receive
static char           *s_recv_token   = NULL;  // token string from qr_reader_result()
static cashu_err_t     s_recv_err     = CASHU_OK;
static int             s_exec_receive = 0;
static int             s_recv_qr_ok   = 1;    // 0 = QR/bcur decode failed
static vita2d_texture *s_cam_tex      = NULL;  // grayscale camera preview texture

// payment request (NUT-18 POST transport)
static payment_request_t s_creq;
static int               s_exec_pay_request = 0;

// =============================================================================
//                                helpers
// =============================================================================

static void cycle_mint(int dir) { /* dir: +1 next, -1 prev */
    mint_info_t *mints = NULL; size_t mc = 0;
    if (wallet_list_mints(&mints, &mc) == CASHU_OK && mc > 1) {
        const char *cur = wallet_active_mint();
        int cur_i = 0;
        for (int i = 0; i < (int)mc; i++)
            if (strcmp(mints[i].url, cur) == 0) { cur_i = i; break; }
        int next = ((cur_i + dir) % (int)mc + (int)mc) % (int)mc;
        wallet_set_active_mint(mints[next].url);
        s_balance = wallet_balance_for(wallet_active_mint());
    }
    wallet_mints_free(mints, mc);
}

static void go_home(void) {
    s_balance       = wallet_balance_for(wallet_active_mint());
    s_total_balance = wallet_balance();
    s_screen        = SCR_HOME;
    s_errmsg[0]     = '\0';
}

static void melt_reset(void) {
    melt_quote_free(&s_melt_q);
    memset(&s_melt_q, 0, sizeof(s_melt_q));
}

static void mint_reset(void) {
    mint_quote_free(&s_mint_q);
    memset(&s_mint_q, 0, sizeof(s_mint_q));
}

static void send_reset(void) {
    free(s_send_part);  s_send_part = NULL;
    bcur_encoder_free(s_send_enc); s_send_enc = NULL;
    s_send_frame = 0;
}

static void load_exports(void) {
    exports_free(s_exports, s_export_count);
    s_exports = NULL; s_export_count = 0;
    exports_load(EXPORTS_PATH, &s_exports, &s_export_count);
    if (s_export_count > 0 && s_export_sel >= (int)s_export_count)
        s_export_sel = (int)s_export_count - 1;
    if (s_export_count == 0) s_export_sel = 0;
}

static void exports_cleanup(void) {
    exports_free(s_exports, s_export_count);
    s_exports = NULL; s_export_count = 0;
    s_export_sel = 0;
}

static void recv_cleanup(void) {
    qr_reader_term();
    vita2d_free_texture(s_cam_tex); s_cam_tex = NULL;
    free(s_recv_token); s_recv_token = NULL;
    s_exec_receive = 0;
    s_recv_qr_ok   = 1;
}

static void creq_reset(void) {
    payment_request_free(&s_creq);
    memset(&s_creq, 0, sizeof(s_creq));
    s_exec_pay_request = 0;
}

// ---- animated QR helper (shared by SEND_QR and EXPORT_VIEW) --------------

static void draw_animated_qr_screen(vita2d_pgf *f,
                                     const char *header,
                                     uint64_t amount,
                                     const char *hint) {
    draw_header(f, header);

    // right side: QR, max 370px, vertically centered in content area
    if (s_send_part)
        draw_qr(s_send_part, 710, 265, 370);

    // left side: info
    char am[48];
    snprintf(am, sizeof(am), "%llu sat", (unsigned long long)amount);
    vita2d_pgf_draw_text(f, 20, 105, C_GRAY,   0.7f,  "AMOUNT");
    vita2d_pgf_draw_text(f, 20, 150, C_YELLOW, 1.7f,  am);

    vita2d_pgf_draw_text(f, 20, 215, C_GRAY,  0.78f, "Scan with recipient wallet.");
    vita2d_pgf_draw_text(f, 20, 248, C_DIM,   0.7f,  "(animated bc-ur)");

    // if (s_send_enc) {
    //     char prog[32];
    //     snprintf(prog, sizeof(prog), "Part %u / %zu",
    //              bcur_encoder_seq_num(s_send_enc),
    //              bcur_encoder_seq_len(s_send_enc));
    //     vita2d_pgf_draw_text(f, 20, 310, C_CYAN, 0.85f, prog);
    // }

    draw_hint(f, hint);
}

int main(void) {
    vita2d_init();
    vita2d_set_clear_color(C_BG);
    vita2d_pgf *font = vita2d_load_default_pgf();

    cashu_err_t http_init_err = cashu_http_init();
    crypto_init();

    sceIoMkdir(STORAGE_DIR, 0777);
    wallet_init(MINT_URL, STORAGE_PATH, "sat");

    go_home();

    sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG);
    SceCtrlData pad_old = {0};

    while (1) {
        SceCtrlData pad;
        sceCtrlReadBufferPositive(0, &pad, 1);
        unsigned int pressed = pad.buttons & ~pad_old.buttons;
        pad_old = pad;

        if (pressed & SCE_CTRL_START) break;

        // ================================================================
        //                 input / state transitions
        // ================================================================
        switch (s_screen) {

        // ---- HOME ----
        case SCR_HOME:
            if (pressed & SCE_CTRL_SQUARE) {
                ime_open("Amount (sat)", 1);
                s_screen = SCR_MINT_AMOUNT;
            } else if (pressed & SCE_CTRL_CROSS) {
                // scan QR: auto-detects bolt11 (pay) or cashu token (receive)
                s_recv_qr_ok = 1;
                if (qr_reader_init() == 0) {
                    s_cam_tex = vita2d_create_empty_texture(320, 240);
                    s_screen  = SCR_RECEIVE;
                } else {
                    snprintf(s_errmsg, sizeof(s_errmsg), "Camera init failed");
                }
            } else if (pressed & SCE_CTRL_TRIANGLE) {
                ime_open("Amount (sat)", 1);
                s_screen = SCR_SEND_AMOUNT;
            } else if (pressed & SCE_CTRL_CIRCLE) {
                s_export_sel = 0;
                load_exports();
                s_screen = SCR_EXPORTS;
            } else if (pressed & SCE_CTRL_LTRIGGER) {
                cycle_mint(-1);
            } else if (pressed & SCE_CTRL_RTRIGGER) {
                cycle_mint(+1);
            }
            break;

        // ---- MELT ----
        case SCR_MELT_QUOTE:
            if (pressed & SCE_CTRL_CROSS)  { s_exec_melt = 1; s_screen = SCR_MELT_PAYING; }
            if (pressed & SCE_CTRL_CIRCLE) { melt_reset(); s_screen = SCR_HOME; }
            break;

        case SCR_MELT_RESULT:
            if (pressed) { melt_reset(); go_home(); }
            break;

        // ---- MINT ----
        case SCR_MINT_AMOUNT:
            if (sceImeDialogGetStatus() == SCE_COMMON_DIALOG_STATUS_FINISHED) {
                SceImeDialogResult res; memset(&res, 0, sizeof(res));
                sceImeDialogGetResult(&res); sceImeDialogTerm();
                if (res.button == SCE_IME_DIALOG_BUTTON_ENTER) {
                    s_mint_amount = ime_to_u64();
                    if (s_mint_amount == 0) { s_screen = SCR_HOME; break; }
                    cashu_err_t e = wallet_mint_quote(s_mint_amount, &s_mint_q);
                    if (e == CASHU_OK) {
                        s_screen = SCR_MINT_INVOICE;
                    } else {
                        snprintf(s_errmsg, sizeof(s_errmsg),
                                 "Deposit failed: %s", err_str(e));
                        s_screen = SCR_HOME;
                    }
                } else { s_screen = SCR_HOME; }
            }
            break;

        case SCR_MINT_INVOICE:
            if (pressed & SCE_CTRL_CROSS)  { s_exec_mint_poll = 1; }
            if (pressed & SCE_CTRL_CIRCLE) { mint_reset(); s_screen = SCR_HOME; }
            break;

        case SCR_MINT_RESULT:
            if (pressed) { mint_reset(); go_home(); }
            break;

        // ---- SEND ----
        case SCR_SEND_AMOUNT:
            if (sceImeDialogGetStatus() == SCE_COMMON_DIALOG_STATUS_FINISHED) {
                SceImeDialogResult res; memset(&res, 0, sizeof(res));
                sceImeDialogGetResult(&res); sceImeDialogTerm();
                if (res.button == SCE_IME_DIALOG_BUTTON_ENTER) {
                    s_send_amount = ime_to_u64();
                    if (s_send_amount == 0) { s_screen = SCR_HOME; break; }
                    char *token = NULL;
                    cashu_err_t e = wallet_send(s_send_amount, &token);
                    if (e == CASHU_OK && token) {
                        // save to exports before displaying
                        exports_save(EXPORTS_PATH, token, s_send_amount);
                        s_send_enc = bcur_encoder_new(
                            (const uint8_t *)token, strlen(token), 200);
                        free(token);
                        if (s_send_enc) {
                            s_send_part  = bcur_encoder_next_part(s_send_enc);
                            s_send_frame = 0;
                            s_screen     = SCR_SEND_QR;
                        } else {
                            snprintf(s_errmsg, sizeof(s_errmsg), "bcur init failed");
                            go_home();
                        }
                    } else {
                        free(token);
                        snprintf(s_errmsg, sizeof(s_errmsg),
                                 "Send failed: %s", err_str(e));
                        s_screen = SCR_HOME;
                    }
                } else { s_screen = SCR_HOME; }
            }
            break;

        case SCR_SEND_QR:
            if (++s_send_frame >= SEND_QR_INTERVAL) {
                s_send_frame = 0;
                free(s_send_part);
                s_send_part = bcur_encoder_next_part(s_send_enc);
            }
            if (pressed & SCE_CTRL_CIRCLE) { send_reset(); go_home(); }
            break;

        // ---- EXPORTS ----
        case SCR_EXPORTS:
            if ((pressed & SCE_CTRL_UP) && s_export_count > 0)
                s_export_sel = s_export_sel > 0
                               ? s_export_sel - 1
                               : (int)s_export_count - 1;
            if ((pressed & SCE_CTRL_DOWN) && s_export_count > 0)
                s_export_sel = (s_export_sel + 1) % (int)s_export_count;

            if ((pressed & SCE_CTRL_CROSS) && s_export_count > 0) {
                s_export_view_amount = s_exports[s_export_sel].amount;
                const char *tok = s_exports[s_export_sel].token;
                s_send_enc = bcur_encoder_new(
                    (const uint8_t *)tok, strlen(tok), 200);
                if (s_send_enc) {
                    s_send_part  = bcur_encoder_next_part(s_send_enc);
                    s_send_frame = 0;
                    s_screen     = SCR_EXPORT_VIEW;
                }
            }
            if ((pressed & SCE_CTRL_SQUARE) && s_export_count > 0) {
                exports_delete(EXPORTS_PATH, (size_t)s_export_sel);
                load_exports();
            }
            if (pressed & SCE_CTRL_CIRCLE) {
                exports_cleanup();
                go_home();
            }
            break;

        case SCR_EXPORT_VIEW:
            if (++s_send_frame >= SEND_QR_INTERVAL) {
                s_send_frame = 0;
                free(s_send_part);
                s_send_part = bcur_encoder_next_part(s_send_enc);
            }
            if (pressed & SCE_CTRL_CIRCLE) {
                send_reset();
                s_screen = SCR_EXPORTS;
            }
            break;

        // ---- RECEIVE ----
        case SCR_RECEIVE: {
            qr_reader_state_t rs = qr_reader_tick();

            // update camera preview texture here, before vita2d_start_drawing()
            if (s_cam_tex) {
                const uint8_t *frame = qr_reader_frame(NULL, NULL);
                if (frame) {
                    uint32_t stride_b = vita2d_texture_get_stride(s_cam_tex);
                    uint32_t stride_px = (stride_b >= 4) ? (stride_b / 4) : 320;
                    if (stride_px < 320) stride_px = 320;
                    uint32_t *texdata = vita2d_texture_get_datap(s_cam_tex);
                    if (texdata && stride_px > 0) {
                        for (int row = 0; row < 240; row++)
                            for (int col = 0; col < 320; col++)
                                texdata[row * stride_px + col] = RGBA8(
                                    frame[row * 320 + col],
                                    frame[row * 320 + col],
                                    frame[row * 320 + col], 0xFF);
                    }
                }
            }

            if (rs == QR_READER_COMPLETE) {
                s_recv_token = qr_reader_result();
                s_exec_receive = 1;
            } else if (rs == QR_READER_BOLT11) {
                char *inv = qr_reader_result();
                qr_reader_term();
                vita2d_free_texture(s_cam_tex); s_cam_tex = NULL;
                if (inv && strlen(inv) < sizeof(s_bolt11)) {
                    strcpy(s_bolt11, inv);
                    free(inv);
                    melt_reset();
                    s_screen          = SCR_MELT_PAYING; /* show while fetching quote */
                    s_exec_melt_quote = 1;
                } else {
                    free(inv);
                    s_recv_qr_ok = 0;
                    s_screen     = SCR_RECEIVE_RESULT;
                }
            } else if (rs == QR_READER_PAYMENT_REQUEST) {
                char *raw = qr_reader_result();
                qr_reader_term();
                vita2d_free_texture(s_cam_tex); s_cam_tex = NULL;
                creq_reset();
                cashu_err_t de = raw ? creq_decode(raw, &s_creq) : CASHU_ERR_INVALID_PAYMENT_REQUEST;
                free(raw);
                if (de == CASHU_OK) {
                    s_screen = SCR_CREQ_CONFIRM;
                } else {
                    snprintf(s_errmsg, sizeof(s_errmsg),
                             "Payment request error: %s", err_str(de));
                    go_home();
                }
            } else if (rs == QR_READER_ERROR) {
                s_recv_qr_ok = 0;
                qr_reader_term();
                s_screen = SCR_RECEIVE_RESULT;
            } else if (pressed & SCE_CTRL_CIRCLE) {
                recv_cleanup();
                go_home();
            }
            break;
        }

        case SCR_RECEIVE_RESULT:
            if (pressed) { go_home(); }
            break;

        // ---- PAYMENT REQUEST CONFIRM ----
        case SCR_CREQ_CONFIRM:
            if (pressed & SCE_CTRL_CROSS)  { s_exec_pay_request = 1; } /* screen set in exec block */
            if (pressed & SCE_CTRL_CIRCLE) { creq_reset(); go_home(); }
            break;

        default: break;
        }

        /* ================================================================
         * render
         * ============================================================== */
        vita2d_start_drawing();
        vita2d_clear_screen();

        switch (s_screen) {

        // ---- HOME ----
        case SCR_HOME: {
            draw_header(font, NULL);

            char murl[52]; trunc_str(wallet_active_mint(), murl, 48);
            vita2d_pgf_draw_text(font, 20, 115, C_GRAY,   0.75f, "BALANCE");
            vita2d_pgf_draw_text(font, 20, 148, C_DIM,    0.65f, murl);
            char bal[32];
            snprintf(bal, sizeof(bal), "%llu sat", (unsigned long long)s_balance);
            vita2d_pgf_draw_text(font, 20, 205, C_YELLOW, 2.4f, bal);
            if (s_total_balance != s_balance) {
                char tot[48];
                snprintf(tot, sizeof(tot), "Total all mints: %llu sat",
                         (unsigned long long)s_total_balance);
                vita2d_pgf_draw_text(font, 20, 258, C_GRAY, 0.7f, tot);
            }

            if (http_init_err != CASHU_OK) {
                vita2d_pgf_draw_text(font, 20, 340, C_RED, 0.75f,
                                     "HTTP init failed — no network access");
            }
            if (s_errmsg[0]) {
                vita2d_pgf_draw_text(font, 20, 385, C_RED, 0.8f, s_errmsg);
            }

            draw_hint(font, "L1/R1: switch mint   \u25a1: mint   X: scan   \u25b3: export token   \u25cb: export history");
            break;
        }

        // ---- MELT QUOTE ----
        case SCR_MELT_QUOTE: {
            draw_header(font, "CONFIRM PAYMENT");

            char l1[64], l2[64], l3[64];
            snprintf(l1, sizeof(l1), "Amount:       %llu sat",
                     (unsigned long long)s_melt_q.amount);
            snprintf(l2, sizeof(l2), "Fee reserve:  %llu sat",
                     (unsigned long long)s_melt_q.fee_reserve);
            snprintf(l3, sizeof(l3), "Max total:    %llu sat",
                     (unsigned long long)(s_melt_q.amount + s_melt_q.fee_reserve));
            vita2d_pgf_draw_text(font, 20, 200, C_WHITE,  1.0f, l1);
            vita2d_pgf_draw_text(font, 20, 240, C_GRAY,   1.0f, l2);
            hline(258);
            vita2d_pgf_draw_text(font, 20, 295, C_YELLOW, 1.1f, l3);

            if (s_balance >= s_melt_q.amount + s_melt_q.fee_reserve) {
                char l4[64];
                snprintf(l4, sizeof(l4), "Balance after (est):  %llu sat",
                         (unsigned long long)(s_balance - s_melt_q.amount
                                              - s_melt_q.fee_reserve));
                vita2d_pgf_draw_text(font, 20, 350, C_DIM, 0.85f, l4);
            } else {
                vita2d_pgf_draw_text(font, 20, 350, C_RED, 0.85f,
                                     "Warning: may not have enough funds");
            }
            draw_hint(font, "X: pay   \u25cb: cancel");
            break;
        }

        // ---- MELT PAYING ----
        case SCR_MELT_PAYING:
            draw_header(font, "PAYING");
            vita2d_pgf_draw_text(font, 20, 235, C_CYAN, 1.8f, "Paying...");
            vita2d_pgf_draw_text(font, 20, 285, C_DIM,  0.8f, "Do not power off.");
            break;

        // ---- MELT RESULT ----
        case SCR_MELT_RESULT:
            draw_header(font, "RESULT");
            if (s_melt_err == CASHU_OK) {
                vita2d_pgf_draw_text(font, 20, 230, C_GREEN, 2.5f, "PAID");
                vita2d_pgf_draw_text(font, 20, 285, C_GRAY,  0.9f, "Invoice settled.");
            } else {
                vita2d_pgf_draw_text(font, 20, 230, C_RED,  2.5f, "FAILED");
                vita2d_pgf_draw_text(font, 20, 285, C_GRAY, 0.9f, err_str(s_melt_err));
            }
            draw_hint(font, "Any button to continue");
            break;

        // ---- MINT AMOUNT ----
        case SCR_MINT_AMOUNT:
            draw_header(font, "MINT");
            vita2d_pgf_draw_text(font, 20, 175, C_DIM, 0.85f,
                                 "Enter amount to deposit (sat)...");
            break;

        // ---- MINT INVOICE ----
        case SCR_MINT_INVOICE: {
            draw_header(font, "SCAN TO PAY");
            if (s_mint_q.request)
                draw_qr(s_mint_q.request, 710, 265, 370);

            char t[36]; trunc_str(s_mint_q.request ? s_mint_q.request : "", t, 32);
            vita2d_pgf_draw_text(font, 20, 105, C_GRAY, 0.7f, "AMOUNT");
            char am[48];
            snprintf(am, sizeof(am), "%llu sat", (unsigned long long)s_mint_amount);
            vita2d_pgf_draw_text(font, 20, 148, C_YELLOW, 1.7f, am);
            vita2d_pgf_draw_text(font, 20, 210, C_DIM, 0.65f, t);
            vita2d_pgf_draw_text(font, 20, 260, C_GRAY, 0.78f,
                                 "Pay the invoice from your");
            vita2d_pgf_draw_text(font, 20, 290, C_GRAY, 0.78f,
                                 "lightning wallet, then press X.");
            draw_hint(font, "X: check payment   \u25cb: cancel");
            break;
        }

        // ---- MINT RESULT ----
        case SCR_MINT_RESULT:
            draw_header(font, "MINT RESULT");
            if (s_mint_err == CASHU_OK) {
                vita2d_pgf_draw_text(font, 20, 230, C_GREEN, 2.0f, "MINTED");
                char am[48];
                snprintf(am, sizeof(am), "+%llu sat", (unsigned long long)s_mint_amount);
                vita2d_pgf_draw_text(font, 20, 285, C_YELLOW, 1.2f, am);
            } else {
                vita2d_pgf_draw_text(font, 20, 230, C_RED, 2.0f, "FAILED");
                vita2d_pgf_draw_text(font, 20, 285, C_GRAY, 0.9f, err_str(s_mint_err));
            }
            draw_hint(font, "Any button to continue");
            break;

        // ---- SEND AMOUNT ----
        case SCR_SEND_AMOUNT:
            draw_header(font, "SEND TOKEN");
            vita2d_pgf_draw_text(font, 20, 175, C_DIM, 0.85f,
                                 "Enter amount to send (sat)...");
            break;

        // ---- SEND QR ----
        case SCR_SEND_QR:
            draw_animated_qr_screen(font, "SCAN TOKEN", s_send_amount,
                                    "\u25cb: done (saved in exports)");
            break;

        // ---- EXPORTS LIST ----
        case SCR_EXPORTS: {
            draw_header(font, "EXPORTED TOKENS");

            if (s_export_count == 0) {
                vita2d_pgf_draw_text(font, 20, 210, C_DIM, 0.9f,
                                     "No exported tokens.");
                vita2d_pgf_draw_text(font, 20, 250, C_DIM, 0.75f,
                                     "Send a token and it will appear here.");
            } else {
                // scroll window: keep selected near center
                int vis = 7;
                int top = s_export_sel - vis / 2;
                if (top < 0) top = 0;
                if (top + vis > (int)s_export_count)
                    top = (int)s_export_count - vis;
                if (top < 0) top = 0;

                for (int i = top; i < (int)s_export_count && i < top + vis; i++) {
                    float row_y = 85.0f + (i - top) * 52.0f;
                    if (i == s_export_sel)
                        vita2d_draw_rectangle(8, row_y - 26.0f, 944, 38, C_HILIGHT);

                    unsigned int col = (i == s_export_sel) ? C_YELLOW : C_WHITE;
                    char tok_short[20];
                    strncpy(tok_short, s_exports[i].token, 16);
                    tok_short[16] = '\0';
                    char line[80];
                    snprintf(line, sizeof(line), "%3llu sat   %s...",
                             (unsigned long long)s_exports[i].amount, tok_short);
                    vita2d_pgf_draw_text(font, 20, (int)row_y, col, 0.85f, line);
                }

                // scroll indicator
                char idx[20];
                snprintf(idx, sizeof(idx), "%d / %zu",
                         s_export_sel + 1, s_export_count);
                vita2d_pgf_draw_text(font, 840, 34, C_DIM, 0.65f, idx);
            }
            draw_hint(font, "X: show QR   \u25a1: delete   \u25cb: back");
            break;
        }

        // ---- EXPORT VIEW (re-display QR for a saved token) ----
        case SCR_EXPORT_VIEW:
            draw_animated_qr_screen(font, "RESEND TOKEN", s_export_view_amount,
                                    "\u25cb: back");
            break;

        // ---- RECEIVE ----
        case SCR_RECEIVE: {
            draw_header(font, "SCAN QR");

            // camera preview: texture already updated in input section
            if (s_cam_tex)
                vita2d_draw_texture_scale(s_cam_tex, 20.0f, 82.0f, 1.5f, 1.5f);

            // right side: progress info
            double prog = qr_reader_progress();
            char pct[24];
            snprintf(pct, sizeof(pct), "%.0f%%", prog * 100.0);
            vita2d_pgf_draw_text(font, 520, 130, C_GRAY,  0.75f, "SCAN PROGRESS");
            vita2d_pgf_draw_text(font, 520, 185, C_CYAN,  2.0f,  pct);

            float bar_x = 520.0f, bar_y = 230.0f, bar_w = 420.0f, bar_h = 22.0f;
            vita2d_draw_rectangle(bar_x, bar_y, bar_w, bar_h, C_DIM);
            if (prog > 0.0)
                vita2d_draw_rectangle(bar_x, bar_y, (float)(prog * bar_w), bar_h, C_CYAN);

            vita2d_pgf_draw_text(font, 520, 295, C_DIM, 0.7f,
                                 "Hold QR in front of");
            vita2d_pgf_draw_text(font, 520, 322, C_DIM, 0.7f,
                                 "the back camera.");

            draw_hint(font, "\u25cb: cancel");
            break;
        }

        // ---- PAYMENT REQUEST CONFIRM ----
        case SCR_CREQ_CONFIRM: {
            draw_header(font, "PAY REQUEST");

            if (s_creq.description)
                vita2d_pgf_draw_text(font, 20, 105, C_GRAY, 0.75f, s_creq.description);

            char am[48];
            if (s_creq.has_amount)
                snprintf(am, sizeof(am), "%llu sat", (unsigned long long)s_creq.amount);
            else
                snprintf(am, sizeof(am), "any amount");
            vita2d_pgf_draw_text(font, 20, s_creq.description ? 150 : 120,
                                 C_YELLOW, 2.0f, am);

            /* find first post transport to show target URL */
            const char *post_target = NULL;
            for (size_t i = 0; i < s_creq.transport_count && !post_target; i++)
                if (strcmp(s_creq.transports[i].type, "post") == 0)
                    post_target = s_creq.transports[i].target;
            if (post_target) {
                char tgt[52]; trunc_str(post_target, tgt, 48);
                vita2d_pgf_draw_text(font, 20, 270, C_GRAY,  0.7f, "SEND TO");
                vita2d_pgf_draw_text(font, 20, 305, C_WHITE, 0.8f, tgt);
            }

            if (s_creq.mint_count > 0) {
                char ml[52]; trunc_str(s_creq.mints[0], ml, 48);
                vita2d_pgf_draw_text(font, 20, 360, C_GRAY, 0.7f, "MINT");
                vita2d_pgf_draw_text(font, 20, 393, C_DIM,  0.75f, ml);
            }

            if (s_creq.has_amount && s_balance < s_creq.amount)
                vita2d_pgf_draw_text(font, 20, 430, C_RED, 0.8f, "Insufficient funds");

            draw_hint(font, "X: pay   \u25cb: cancel");
            break;
        }

        // ---- RECEIVE / PAY RESULT ----
        case SCR_RECEIVE_RESULT:
            draw_header(font, "RESULT");
            if (!s_recv_qr_ok) {
                vita2d_pgf_draw_text(font, 20, 230, C_RED,  2.0f, "QR ERROR");
                vita2d_pgf_draw_text(font, 20, 290, C_GRAY, 0.85f,
                                     "Decoding failed. Try again.");
            } else if (s_recv_err == CASHU_OK) {
                vita2d_pgf_draw_text(font, 20, 230, C_GREEN, 2.0f, "DONE");
                vita2d_pgf_draw_text(font, 20, 290, C_GRAY,  0.85f,
                                     "Balance updated.");
            } else {
                vita2d_pgf_draw_text(font, 20, 230, C_RED,  2.0f, "FAILED");
                vita2d_pgf_draw_text(font, 20, 290, C_GRAY, 0.85f, err_str(s_recv_err));
                const char *body = cashu_http_last_error_body();
                if (body && body[0]) {
                    char trunc[80]; trunc_str(body, trunc, sizeof(trunc));
                    vita2d_pgf_draw_text(font, 20, 340, C_DIM, 0.65f, trunc);
                }
            }
            draw_hint(font, "Any button to continue");
            break;

        default: break;
        }

        vita2d_end_drawing();
        vita2d_common_dialog_update();
        vita2d_swap_buffers();

        // ================================================================
        // these below are blocking - make sure that ui is already drawn
        // ================================================================

        if (s_exec_melt_quote) {
            s_exec_melt_quote = 0;
            cashu_err_t qe = wallet_melt_quote(s_bolt11, &s_melt_q);
            if (qe == CASHU_OK) {
                s_screen = SCR_MELT_QUOTE;
            } else {
                snprintf(s_errmsg, sizeof(s_errmsg), "Payment quote failed: %s", err_str(qe));
                go_home();
            }
        }

        if (s_exec_melt) {
            s_exec_melt = 0;
            s_melt_err  = wallet_melt(&s_melt_q);
            s_screen    = SCR_MELT_RESULT;
        }

        if (s_exec_mint_poll) {
            s_exec_mint_poll = 0;
            mint_quote_t q2;
            cashu_err_t e = wallet_mint_quote_state(s_mint_q.quote, &q2);
            if (e == CASHU_OK && q2.state && strcmp(q2.state, "PAID") == 0) {
                mint_quote_free(&q2);
                s_exec_mint = 1;
            } else {
                mint_quote_free(&q2);
                if (e != CASHU_OK) {
                    snprintf(s_errmsg, sizeof(s_errmsg),
                             "Payment check failed: %s", err_str(e));
                }
            }
        }

        if (s_exec_mint) {
            s_exec_mint = 0;
            s_mint_err  = wallet_mint(s_mint_q.quote, s_mint_amount);
            s_screen    = SCR_MINT_RESULT;
        }

        if (s_exec_receive) {
            s_exec_receive = 0;
            qr_reader_term();
            vita2d_free_texture(s_cam_tex); s_cam_tex = NULL;
            if (s_recv_token) {
                s_recv_err = wallet_receive(s_recv_token);
                free(s_recv_token);
            } else {
                s_recv_err = CASHU_ERR_INVALID_TOKEN;
            }
            s_recv_token = NULL;
            s_screen     = SCR_RECEIVE_RESULT;
            if (s_recv_err == CASHU_OK) {
                s_balance       = wallet_balance_for(wallet_active_mint());
                s_total_balance = wallet_balance();
            }
        }

        if (s_exec_pay_request) {
            s_exec_pay_request = 0;
            s_recv_err = wallet_pay_request(&s_creq);
            creq_reset();
            s_recv_qr_ok = 1;   /* reuse receive result screen */
            if (s_recv_err == CASHU_OK) {
                s_balance       = wallet_balance_for(wallet_active_mint());
                s_total_balance = wallet_balance();
            }
            s_screen = SCR_RECEIVE_RESULT;
        }
    }

    send_reset();
    exports_cleanup();
    recv_cleanup();
    creq_reset();
    mint_reset();
    melt_reset();
    vita2d_free_pgf(font);
    wallet_term();
    crypto_free();
    cashu_http_term();
    vita2d_fini();

    sceKernelExitProcess(0);
    return 0;
}
