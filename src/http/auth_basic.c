#include "apex/auth_basic.h"
#include "apex/http_util.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <openssl/crypto.h>

bool apex_auth_basic_check(const char *req_buf, size_t req_buf_len, const apex_auth_basic_config_t *ab) {
    if (ab == NULL || !ab->enabled) {
        return true;
    }
    if (ab->user_file[0] == '\0') {
        return true;
    }

    const char *auth_hdr = NULL;
    size_t auth_hdr_len = 0;
    if (!apex_http_find_header(req_buf, req_buf_len, "Authorization", &auth_hdr, &auth_hdr_len)) {
        return false;
    }
    while (auth_hdr_len > 0 && (*auth_hdr == ' ' || *auth_hdr == '\t')) {
        auth_hdr++;
        auth_hdr_len--;
    }
    if (auth_hdr_len < 6 || strncasecmp(auth_hdr, "Basic ", 6) != 0) {
        return false;
    }
    const char *b64_str = auth_hdr + 6;
    size_t b64_len = auth_hdr_len - 6;
    while (b64_len > 0 && (*b64_str == ' ' || *b64_str == '\t')) {
        b64_str++;
        b64_len--;
    }
    while (b64_len > 0 && (b64_str[b64_len - 1] == ' ' || b64_str[b64_len - 1] == '\t' ||
                          b64_str[b64_len - 1] == '\r' || b64_str[b64_len - 1] == '\n')) {
        b64_len--;
    }

    char decoded[256];
    size_t decoded_len = 0;
    if (!apex_base64_decode(b64_str, b64_len, decoded, sizeof(decoded), &decoded_len)) {
        return false;
    }

    char *colon = strchr(decoded, ':');
    if (colon == NULL) {
        return false;
    }
    *colon = '\0';
    const char *req_user = decoded;
    const char *req_pass = colon + 1;

    FILE *f = fopen(ab->user_file, "r");
    if (f == NULL) {
        return false;
    }

    char line[512];
    bool matched = false;
    while (fgets(line, sizeof(line), f) != NULL) {
        char *nl = strchr(line, '\n');
        if (nl != NULL) *nl = '\0';
        char *cr = strchr(line, '\r');
        if (cr != NULL) *cr = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

        char *fcolon = strchr(line, ':');
        if (fcolon == NULL) continue;
        *fcolon = '\0';
        const char *fuser = line;
        const char *fpass = fcolon + 1;

        if (strcmp(req_user, fuser) == 0) {
            size_t req_pass_len = strlen(req_pass);
            size_t fpass_len = strlen(fpass);
            if (req_pass_len == fpass_len && CRYPTO_memcmp(req_pass, fpass, req_pass_len) == 0) {
                matched = true;
                break;
            }
        }
    }
    fclose(f);
    return matched;
}
