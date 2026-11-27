#include "apex/compress.h"
#include <brotli/encode.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>
#include <zstd.h>

static const char *const DEFAULT_COMPRESSIBLE_TYPES[] = {
    "text/html",
    "text/plain",
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "application/json",
    "application/xml",
    "text/xml",
    "image/svg+xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    NULL
};

const char *apex_compress_algo_name(apex_compress_algo_t algo) {
    switch (algo) {
    case APEX_COMPRESS_ZSTD:
        return "zstd";
    case APEX_COMPRESS_BROTLI:
        return "br";
    case APEX_COMPRESS_GZIP:
        return "gzip";
    case APEX_COMPRESS_NONE:
    default:
        return "none";
    }
}

bool apex_compress_is_type_eligible(char *const *types, size_t type_count, const char *content_type) {
    if (content_type == NULL || content_type[0] == '\0') {
        return false;
    }

    /* Extract the MIME type without parameters (e.g. "application/json; charset=utf-8" -> "application/json") */
    const char *semi = strchr(content_type, ';');
    size_t ct_len = semi != NULL ? (size_t)(semi - content_type) : strlen(content_type);
    while (ct_len > 0 && isspace((unsigned char)content_type[ct_len - 1])) {
        ct_len--;
    }
    const char *ct_start = content_type;
    while (*ct_start && isspace((unsigned char)*ct_start)) {
        ct_start++;
        ct_len--;
    }

    if (type_count > 0 && types != NULL) {
        for (size_t i = 0; i < type_count; i++) {
            if (types[i] == NULL) continue;
            if (strcasecmp(types[i], "*") == 0) return true;
            if (strncasecmp(types[i], ct_start, ct_len) == 0 && types[i][ct_len] == '\0') {
                return true;
            }
        }
        return false;
    }

    /* Default types list */
    for (size_t i = 0; DEFAULT_COMPRESSIBLE_TYPES[i] != NULL; i++) {
        const char *dt = DEFAULT_COMPRESSIBLE_TYPES[i];
        if (strncasecmp(dt, ct_start, ct_len) == 0 && dt[ct_len] == '\0') {
            return true;
        }
    }
    return false;
}

static bool is_qvalue_zero(const char *param, const char *end) {
    const char *p = param;
    while (p < end && *p != ',') {
        if (*p == ';') {
            p++;
            while (p < end && isspace((unsigned char)*p)) p++;
            if (p < end && (*p == 'q' || *p == 'Q')) {
                p++;
                while (p < end && isspace((unsigned char)*p)) p++;
                if (p < end && *p == '=') {
                    p++;
                    while (p < end && isspace((unsigned char)*p)) p++;
                    if (p < end && *p == '0') {
                        p++;
                        if (p < end && *p == '.') {
                            p++;
                            bool has_nonzero = false;
                            while (p < end && isdigit((unsigned char)*p)) {
                                if (*p != '0') {
                                    has_nonzero = true;
                                    break;
                                }
                                p++;
                            }
                            if (!has_nonzero) {
                                return true;
                            }
                        } else if (p >= end || *p == ';' || *p == ',' || isspace((unsigned char)*p)) {
                            return true;
                        }
                    }
                }
            }
        } else {
            p++;
        }
    }
    return false;
}

static bool header_contains_token(const char *header, size_t header_len, const char *token) {
    if (header == NULL || header_len == 0 || token == NULL) {
        return false;
    }
    size_t token_len = strlen(token);
    const char *ptr = header;
    const char *end = header + header_len;

    while (ptr < end) {
        while (ptr < end && (isspace((unsigned char)*ptr) || *ptr == ',')) {
            ptr++;
        }
        if (ptr >= end) break;

        const char *tok_start = ptr;
        while (ptr < end && *ptr != ',' && *ptr != ';' && !isspace((unsigned char)*ptr)) {
            ptr++;
        }
        size_t cur_len = (size_t)(ptr - tok_start);
        if (cur_len == token_len && strncasecmp(tok_start, token, token_len) == 0) {
            if (!is_qvalue_zero(ptr, end)) {
                return true;
            }
        }

        /* Skip quality values / parameters like ;q=0.8 */
        while (ptr < end && *ptr != ',') {
            ptr++;
        }
    }
    return false;
}

apex_compress_algo_t apex_compress_negotiate(const apex_compress_config_t *config,
                                             const char *accept_encoding, size_t accept_encoding_len,
                                             const char *content_type, size_t body_len) {
    if (config == NULL || accept_encoding == NULL || accept_encoding_len == 0) {
        return APEX_COMPRESS_NONE;
    }

    /* Check min_length threshold */
    uint32_t min_len = config->gzip_min_length > 0 ? config->gzip_min_length : 20;
    if (body_len < min_len) {
        return APEX_COMPRESS_NONE;
    }

    /* 1. Zstandard: highest speed and modern compression */
    if (config->zstd_enabled) {
        if (header_contains_token(accept_encoding, accept_encoding_len, "zstd") ||
            header_contains_token(accept_encoding, accept_encoding_len, "zstandard")) {
            if (apex_compress_is_type_eligible(config->zstd_types, config->zstd_type_count, content_type)) {
                return APEX_COMPRESS_ZSTD;
            }
        }
    }

    /* 2. Brotli: best compression ratio for text */
    if (config->brotli_enabled) {
        if (header_contains_token(accept_encoding, accept_encoding_len, "br")) {
            if (apex_compress_is_type_eligible(config->brotli_types, config->brotli_type_count, content_type)) {
                return APEX_COMPRESS_BROTLI;
            }
        }
    }

    /* 3. Gzip: ubiquitous standard fallback */
    if (config->gzip_enabled) {
        if (header_contains_token(accept_encoding, accept_encoding_len, "gzip") ||
            header_contains_token(accept_encoding, accept_encoding_len, "deflate")) {
            if (apex_compress_is_type_eligible(config->gzip_types, config->gzip_type_count, content_type)) {
                return APEX_COMPRESS_GZIP;
            }
        }
    }

    return APEX_COMPRESS_NONE;
}

static bool compress_zstd(int comp_level, const void *in_buf, size_t in_len,
                          void **out_buf, size_t *out_len) {
    if (comp_level < 1 || comp_level > 19) {
        comp_level = 3;
    }
    size_t bound = ZSTD_compressBound(in_len);
    void *dst = malloc(bound > 0 ? bound : 64);
    if (dst == NULL) {
        return false;
    }
    size_t result = ZSTD_compress(dst, bound, in_buf, in_len, comp_level);
    if (ZSTD_isError(result)) {
        free(dst);
        return false;
    }
    *out_buf = dst;
    *out_len = result;
    return true;
}

static bool compress_brotli(int comp_level, const void *in_buf, size_t in_len,
                            void **out_buf, size_t *out_len) {
    if (comp_level < 1 || comp_level > 11) {
        comp_level = 4;
    }
    size_t bound = BrotliEncoderMaxCompressedSize(in_len);
    if (bound == 0) {
        bound = in_len + 512;
    }
    uint8_t *dst = malloc(bound);
    if (dst == NULL) {
        return false;
    }
    size_t encoded_len = bound;
    BROTLI_BOOL ok = BrotliEncoderCompress(comp_level,
                                           BROTLI_DEFAULT_WINDOW,
                                           BROTLI_DEFAULT_MODE,
                                           in_len,
                                           (const uint8_t *)in_buf,
                                           &encoded_len,
                                           dst);
    if (!ok) {
        free(dst);
        return false;
    }
    *out_buf = dst;
    *out_len = encoded_len;
    return true;
}

static bool compress_gzip(int comp_level, const void *in_buf, size_t in_len,
                          void **out_buf, size_t *out_len) {
    if (in_len > (size_t)UINT_MAX) {
        return false;
    }
    if (comp_level < 1 || comp_level > 9) {
        comp_level = 6;
    }
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    /* 16 + MAX_WBITS instructs zlib to produce a standard gzip header and crc32 */
    if (deflateInit2(&strm, comp_level, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return false;
    }

    uLong bound = deflateBound(&strm, (uLong)in_len);
    unsigned char *dst = malloc(bound);
    if (dst == NULL) {
        deflateEnd(&strm);
        return false;
    }

    strm.next_in = (Bytef *)(uintptr_t)in_buf;
    strm.avail_in = (uInt)in_len;
    strm.next_out = dst;
    strm.avail_out = (uInt)bound;

    int ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&strm);
        free(dst);
        return false;
    }

    *out_len = strm.total_out;
    *out_buf = dst;
    deflateEnd(&strm);
    return true;
}

bool apex_compress_buffer(apex_compress_algo_t algo, int comp_level,
                          const void *in_buf, size_t in_len,
                          void **out_buf, size_t *out_len) {
    if (in_buf == NULL || out_buf == NULL || out_len == NULL) {
        return false;
    }
    switch (algo) {
    case APEX_COMPRESS_ZSTD:
        return compress_zstd(comp_level, in_buf, in_len, out_buf, out_len);
    case APEX_COMPRESS_BROTLI:
        return compress_brotli(comp_level, in_buf, in_len, out_buf, out_len);
    case APEX_COMPRESS_GZIP:
        return compress_gzip(comp_level, in_buf, in_len, out_buf, out_len);
    case APEX_COMPRESS_NONE:
    default:
        return false;
    }
}
