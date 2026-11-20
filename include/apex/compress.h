#ifndef APEX_COMPRESS_H
#define APEX_COMPRESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    APEX_COMPRESS_NONE = 0,
    APEX_COMPRESS_ZSTD = 1,
    APEX_COMPRESS_BROTLI = 2,
    APEX_COMPRESS_GZIP = 3,
} apex_compress_algo_t;

typedef struct {
    bool gzip_enabled;
    bool has_gzip;
    uint32_t gzip_min_length;
    int gzip_comp_level; /* 1-9 */
    char **gzip_types;
    size_t gzip_type_count;

    bool brotli_enabled;
    bool has_brotli;
    int brotli_comp_level; /* 1-11 */
    char **brotli_types;
    size_t brotli_type_count;

    bool zstd_enabled;
    bool has_zstd;
    int zstd_comp_level; /* 1-19 */
    char **zstd_types;
    size_t zstd_type_count;
} apex_compress_config_t;

/* Determine the preferred compression algorithm given client Accept-Encoding
 * and configured compression rules for the given content type and body length. */
apex_compress_algo_t apex_compress_negotiate(const apex_compress_config_t *config,
                                             const char *accept_encoding, size_t accept_encoding_len,
                                             const char *content_type, size_t body_len);

/* Check if a MIME type is eligible for compression according to types list */
bool apex_compress_is_type_eligible(char *const *types, size_t type_count, const char *content_type);

/* Returns standard string name for the algorithm (e.g. "zstd", "br", "gzip") */
const char *apex_compress_algo_name(apex_compress_algo_t algo);

/* Compress input buffer using chosen algorithm.
 * Allocates *out_buf via malloc; caller must free(*out_buf) on success.
 * Returns true on success and populates *out_buf and *out_len. */
bool apex_compress_buffer(apex_compress_algo_t algo, int comp_level,
                          const void *in_buf, size_t in_len,
                          void **out_buf, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* APEX_COMPRESS_H */
