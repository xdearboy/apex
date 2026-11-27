#include "apex/http_util.h"
#include "apex/static.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    const char *src = (const char *)data;

    /* 1. URI decode into fixed and dynamic buffers */
    char decoded_buf[4096];
    bool decoded = apex_uri_decode(src, size, decoded_buf, sizeof(decoded_buf));
    if (decoded) {
        size_t dec_len = strlen(decoded_buf);
        apex_uri_is_traversal(decoded_buf, dec_len);
        apex_mime_type(decoded_buf);
    }

    /* Direct traversal test on raw input */
    apex_uri_is_traversal(src, size);

    /* 2. Base64 encode and decode */
    char b64_out[8192];
    size_t out_len = 0;
    if (apex_base64_decode(src, size, b64_out, sizeof(b64_out), &out_len)) {
        char reencoded[16384];
        apex_base64_encode((const unsigned char *)b64_out, out_len, reencoded, sizeof(reencoded));
    }

    /* 3. Hex encode */
    if (size < 2048) {
        char hex_out[4096];
        apex_hex_encode(data, size, hex_out);
    }

    return 0;
}
