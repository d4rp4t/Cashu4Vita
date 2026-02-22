//
// Created by d4rp4t on 22/02/2026.
//
#include "bcur.h"
#include "../deps/bc-ur/src/bc-ur.hpp"

#include <cstring>
#include <cstdlib>
#include <vector>

using namespace ur;

// ============================================================================
//                                   helpers
// ============================================================================

static ByteVector cbor_encode_bytes(const uint8_t *data, size_t len) {
    ByteVector result;
    if (len <= 23) {
        result.push_back(0x40u | (uint8_t)len);
    } else if (len <= 0xFFu) {
        result.push_back(0x58u);
        result.push_back((uint8_t)len);
    } else if (len <= 0xFFFFu) {
        result.push_back(0x59u);
        result.push_back((uint8_t)(len >> 8));
        result.push_back((uint8_t)(len & 0xFF));
    } else {
        result.push_back(0x5Au);
        result.push_back((uint8_t)(len >> 24));
        result.push_back((uint8_t)((len >> 16) & 0xFF));
        result.push_back((uint8_t)((len >>  8) & 0xFF));
        result.push_back((uint8_t)(len & 0xFF));
    }
    result.insert(result.end(), data, data + len);
    return result;
}

static std::vector<uint8_t> cbor_decode_bytes(const ByteVector &cbor) {
    if (cbor.empty()) return {};
    size_t  offset = 0;
    uint8_t first  = cbor[offset++];
    uint8_t major  = first >> 5;
    uint8_t info   = first & 0x1Fu;
    if (major != 2) return {};   // not a byte string
    size_t len = 0;
    if (info <= 23) {
        len = info;
    } else if (info == 24) {
        if (offset >= cbor.size()) return {};
        len = cbor[offset++];
    } else if (info == 25) {
        if (offset + 1 >= cbor.size()) return {};
        len = ((size_t)cbor[offset] << 8) | cbor[offset + 1];
        offset += 2;
    } else if (info == 26) {
        if (offset + 3 >= cbor.size()) return {};
        len = ((size_t)cbor[offset    ] << 24)
            | ((size_t)cbor[offset + 1] << 16)
            | ((size_t)cbor[offset + 2] <<  8)
            |  (size_t)cbor[offset + 3];
        offset += 4;
    } else {
        return {};
    }
    if (offset + len > cbor.size()) return {};
    return std::vector<uint8_t>(cbor.begin() + (ptrdiff_t)offset,
                                cbor.begin() + (ptrdiff_t)(offset + len));
}

// ============================================================================
//                                 encoder
// ============================================================================

struct bcur_encoder {
    UREncoder enc;
    bcur_encoder(const UR &ur, size_t max_frag)
        : enc(ur, max_frag) {}
};

bcur_encoder_t *bcur_encoder_new(const uint8_t *data, size_t len,
                                  size_t max_fragment_len) {
    try {
        ByteVector cbor = cbor_encode_bytes(data, len);
        UR ur("bytes", cbor);
        return new bcur_encoder(ur, max_fragment_len);
    } catch (...) {
        return nullptr;
    }
}

void bcur_encoder_free(bcur_encoder_t *enc) {
    delete enc;
}

char *bcur_encoder_next_part(bcur_encoder_t *enc) {
    if (!enc) return nullptr;
    try {
        std::string part = enc->enc.next_part();
        char *result = (char *)malloc(part.size() + 1);
        if (!result) return nullptr;
        memcpy(result, part.c_str(), part.size() + 1);
        return result;
    } catch (...) {
        return nullptr;
    }
}

int bcur_encoder_is_complete(const bcur_encoder_t *enc) {
    return (enc && enc->enc.is_complete()) ? 1 : 0;
}

size_t bcur_encoder_seq_len(const bcur_encoder_t *enc) {
    return enc ? enc->enc.seq_len() : 0;
}

uint32_t bcur_encoder_seq_num(const bcur_encoder_t *enc) {
    return enc ? enc->enc.seq_num() : 0;
}

// ============================================================================
//                                  decoder
// ============================================================================

struct bcur_decoder {
    URDecoder dec;
};

bcur_decoder_t *bcur_decoder_new(void) {
    try {
        return new bcur_decoder();
    } catch (...) {
        return nullptr;
    }
}

void bcur_decoder_free(bcur_decoder_t *dec) {
    delete dec;
}

int bcur_decoder_receive_part(bcur_decoder_t *dec, const char *part) {
    if (!dec || !part) return 0;
    try {
        return dec->dec.receive_part(std::string(part)) ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int bcur_decoder_is_complete(const bcur_decoder_t *dec) {
    return (dec && dec->dec.is_complete()) ? 1 : 0;
}

int bcur_decoder_is_success(const bcur_decoder_t *dec) {
    return (dec && dec->dec.is_success()) ? 1 : 0;
}

double bcur_decoder_progress(const bcur_decoder_t *dec) {
    return dec ? dec->dec.estimated_percent_complete() : 0.0;
}

uint8_t *bcur_decoder_result(const bcur_decoder_t *dec, size_t *len) {
    if (!dec || !len || !dec->dec.is_success()) return nullptr;
    try {
        const UR &ur = dec->dec.result_ur();
        std::vector<uint8_t> bytes = cbor_decode_bytes(ur.cbor());
        if (bytes.empty()) { *len = 0; return nullptr; }
        uint8_t *result = (uint8_t *)malloc(bytes.size());
        if (!result) return nullptr;
        memcpy(result, bytes.data(), bytes.size());
        *len = bytes.size();
        return result;
    } catch (...) {
        return nullptr;
    }
}
