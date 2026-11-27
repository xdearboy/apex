#include "apex/http_util.h"
#include "core/internal.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    const char *text = (const char *)data;

    /* 1. Fuzz HTTP/1.1 header block and request-line scanner */
    size_t header_len = 0;
    size_t content_len = 0;
    bool has_cl = false;
    bool has_te = false;
    apex_http1_scan_request(text, size, &header_len, &content_len, &has_cl, &has_te);

    /* 2. Fuzz chunked transfer decoding */
    size_t decoded_len = 0;
    size_t wire_len = 0;
    int chunk_res = apex_http1_parse_chunked(text, size, &decoded_len, &wire_len);
    if (chunk_res == 1 && wire_len <= size) {
        char *chunk_copy = malloc(wire_len + 1);
        if (chunk_copy != NULL) {
            memcpy(chunk_copy, text, wire_len);
            chunk_copy[wire_len] = '\0';
            size_t out_len = 0;
            apex_http1_decode_chunked_inplace(chunk_copy, wire_len, &out_len);
            free(chunk_copy);
        }
    }

    /* 3. Fuzz header lookups */
    const char *header_val = NULL;
    size_t header_val_len = 0;
    apex_http_find_header(text, size, "Host", &header_val, &header_val_len);
    apex_http_find_header(text, size, "Content-Length", &header_val, &header_val_len);
    apex_http_find_header(text, size, "Transfer-Encoding", &header_val, &header_val_len);
    apex_http_find_header(text, size, "Connection", &header_val, &header_val_len);

    /* 4. Fuzz connection token parser */
    apex_http_is_connection_token(text, size, "close", 5);
    apex_http_is_connection_token(text, size, "keep-alive", 10);
    apex_http_is_connection_token(text, size, "upgrade", 7);

    /* 5. Fuzz HTTP date parser */
    time_t parsed_time = 0;
    apex_http_parse_date(text, size, &parsed_time);

    return 0;
}
