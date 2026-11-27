#include "apex/http_util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef APEX_VERSION
#define APEX_VERSION "1.3.2"
#endif

const char *apex_http_find_crlf(const char *data, size_t length) {
    if (data == NULL || length < 2u) {
        return NULL;
    }
    for (size_t i = 0; i + 1u < length; i++) {
        if (data[i] == '\r' && data[i + 1u] == '\n') {
            return data + i;
        }
    }
    return NULL;
}

bool apex_http_header_name_equal(const char *name, size_t name_length, const char *expected) {
    if (name == NULL || expected == NULL) {
        return false;
    }
    size_t expected_length = strlen(expected);
    if (name_length != expected_length) {
        return false;
    }
    return strncasecmp(name, expected, expected_length) == 0;
}

bool apex_http_find_header(const char *buffer, size_t length, const char *name,
                           const char **value_out, size_t *value_length_out) {
    if (buffer == NULL || length == 0 || name == NULL || value_out == NULL || value_length_out == NULL) {
        return false;
    }

    const char *first_end = apex_http_find_crlf(buffer, length);
    if (first_end == NULL) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t position = (size_t)(first_end - buffer) + 2u;

    while (position < length) {
        const char *line = buffer + position;
        const char *line_end = apex_http_find_crlf(line, length - position);
        if (line_end == NULL) {
            return false;
        }

        size_t line_length = (size_t)(line_end - line);
        if (line_length == 0) {
            return false;
        }

        const char *colon = memchr(line, ':', line_length);
        if (colon != NULL) {
            size_t field_length = (size_t)(colon - line);
            while (field_length > 0 && (line[field_length - 1u] == ' ' || line[field_length - 1u] == '\t')) {
                field_length--;
            }
            if (field_length == name_len && strncasecmp(line, name, name_len) == 0) {
                const char *val_start = colon + 1;
                const char *val_end = line + line_length;
                while (val_start < val_end && (*val_start == ' ' || *val_start == '\t')) {
                    val_start++;
                }
                while (val_end > val_start && (val_end[-1] == ' ' || val_end[-1] == '\t')) {
                    val_end--;
                }
                *value_out = val_start;
                *value_length_out = (size_t)(val_end - val_start);
                return true;
            }
        }

        position += line_length + 2u;
    }

    return false;
}

bool apex_http_is_connection_token(const char *conn_val, size_t conn_val_len,
                                   const char *token, size_t token_len) {
    if (conn_val == NULL || conn_val_len == 0 || token == NULL || token_len == 0) {
        return false;
    }

    const char *ptr = conn_val;
    const char *end = conn_val + conn_val_len;

    while (ptr < end) {
        while (ptr < end && (*ptr == ' ' || *ptr == '\t' || *ptr == ',')) {
            ptr++;
        }
        if (ptr >= end) {
            break;
        }
        const char *token_start = ptr;
        while (ptr < end && *ptr != ' ' && *ptr != '\t' && *ptr != ',') {
            ptr++;
        }
        size_t cur_len = (size_t)(ptr - token_start);
        if (cur_len == token_len && strncasecmp(token_start, token, cur_len) == 0) {
            return true;
        }
    }
    return false;
}

size_t apex_http_format_server_header(const apex_server_tokens_config_t *tokens,
                                      char *buf, size_t buf_cap) {
    if (buf == NULL || buf_cap == 0) {
        return 0;
    }
    if (tokens == NULL || !tokens->set || tokens->mode == APEX_SERVER_TOKENS_ON) {
        return (size_t)snprintf(buf, buf_cap, "Server: apex\r\n");
    }
    if (tokens->mode == APEX_SERVER_TOKENS_CUSTOM) {
        return (size_t)snprintf(buf, buf_cap, "Server: %s\r\n", tokens->custom_value);
    }
    /* APEX_SERVER_TOKENS_OFF */
    buf[0] = '\0';
    return 0;
}

const apex_server_tokens_config_t *apex_http_get_server_tokens(const apex_server_config_t *server,
                                                               const apex_http_config_t *http) {
    if (server != NULL && server->server_tokens.set) {
        return &server->server_tokens;
    }
    if (http != NULL && http->server_tokens.set) {
        return &http->server_tokens;
    }
    static const apex_server_tokens_config_t def_tokens = {
        .mode = APEX_SERVER_TOKENS_ON,
        .set = true,
        .custom_value = ""
    };
    return &def_tokens;
}

static const char *MONTHS[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

bool apex_http_parse_date(const char *str, size_t len, time_t *out_time) {
    if (str == NULL || len < 29 || out_time == NULL) {
        return false;
    }

    /* IMF-fixdate format: "Sun, 06 Nov 1994 08:49:37 GMT" */
    char copy[32];
    if (len >= sizeof(copy)) {
        return false;
    }
    memcpy(copy, str, len);
    copy[len] = '\0';

    char mon_str[4];
    int day = 0, year = 0, hour = 0, min = 0, sec = 0;
    if (sscanf(copy, "%*3s, %d %3s %d %d:%d:%d GMT", &day, mon_str, &year, &hour, &min, &sec) != 6) {
        return false;
    }

    int mon = -1;
    for (int i = 0; i < 12; i++) {
        if (strcmp(mon_str, MONTHS[i]) == 0) {
            mon = i;
            break;
        }
    }
    if (mon < 0 || day < 1 || day > 31 || year < 1970 || hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 60) {
        return false;
    }

    struct tm tm_val;
    memset(&tm_val, 0, sizeof(tm_val));
    tm_val.tm_mday = day;
    tm_val.tm_mon = mon;
    tm_val.tm_year = year - 1900;
    tm_val.tm_hour = hour;
    tm_val.tm_min = min;
    tm_val.tm_sec = sec;

    time_t result = timegm(&tm_val);
    if (result == (time_t)-1) {
        return false;
    }
    *out_time = result;
    return true;
}

bool apex_http_format_date(time_t t, char *buf, size_t buf_cap) {
    if (buf == NULL || buf_cap < 30) {
        return false;
    }
    struct tm tm_val;
    if (gmtime_r(&t, &tm_val) == NULL) {
        return false;
    }
    static const char *DAYS[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    int written = snprintf(buf, buf_cap, "%s, %02d %s %04d %02d:%02d:%02d GMT",
                           DAYS[tm_val.tm_wday], tm_val.tm_mday, MONTHS[tm_val.tm_mon],
                           tm_val.tm_year + 1900, tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec);
    return written > 0 && (size_t)written < buf_cap;
}

int apex_hex_char_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void apex_hex_encode(const unsigned char *src, size_t len, char *dst) {
    if (src == NULL || dst == NULL) {
        return;
    }
    static const char HEX_DIGITS[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        dst[i * 2] = HEX_DIGITS[(src[i] >> 4) & 0x0F];
        dst[i * 2 + 1] = HEX_DIGITS[src[i] & 0x0F];
    }
    dst[len * 2] = '\0';
}

static const signed char B64_TABLE[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
    ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
    ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39,
    ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
    ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
    ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
};

bool apex_base64_decode(const char *in, size_t in_len, char *out, size_t out_cap, size_t *out_len) {
    if (in == NULL || out == NULL || out_len == NULL) {
        return false;
    }
    while (in_len > 0 && (in[in_len - 1] == ' ' || in[in_len - 1] == '\r' || in[in_len - 1] == '\n')) {
        in_len--;
    }
    if (in_len % 4 != 0) {
        return false;
    }

    size_t out_idx = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        char c0 = in[i];
        char c1 = in[i + 1];
        char c2 = in[i + 2];
        char c3 = in[i + 3];

        signed char b0 = B64_TABLE[(unsigned char)c0];
        signed char b1 = B64_TABLE[(unsigned char)c1];
        signed char b2 = (c2 == '=') ? 0 : B64_TABLE[(unsigned char)c2];
        signed char b3 = (c3 == '=') ? 0 : B64_TABLE[(unsigned char)c3];

        if (b0 < 0 || b1 < 0 || (c2 != '=' && b2 < 0) || (c3 != '=' && b3 < 0)) {
            return false;
        }

        uint32_t triple = ((uint32_t)b0 << 18) | ((uint32_t)b1 << 12) | ((uint32_t)b2 << 6) | (uint32_t)b3;

        if (out_idx >= out_cap) return false;
        out[out_idx++] = (char)((triple >> 16) & 0xFF);

        if (c2 != '=') {
            if (out_idx >= out_cap) return false;
            out[out_idx++] = (char)((triple >> 8) & 0xFF);
        }
        if (c3 != '=') {
            if (out_idx >= out_cap) return false;
            out[out_idx++] = (char)(triple & 0xFF);
        }
    }

    if (out_idx < out_cap) {
        out[out_idx] = '\0';
    }
    *out_len = out_idx;
    return true;
}

bool apex_base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_cap) {
    if (in == NULL || out == NULL) {
        return false;
    }
    static const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t needed = ((in_len + 2) / 3) * 4 + 1;
    if (out_cap < needed) {
        return false;
    }

    size_t out_idx = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t octet_a = in[i];
        uint32_t octet_b = (i + 1 < in_len) ? in[i + 1] : 0;
        uint32_t octet_c = (i + 2 < in_len) ? in[i + 2] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[out_idx++] = B64_CHARS[(triple >> 18) & 0x3F];
        out[out_idx++] = B64_CHARS[(triple >> 12) & 0x3F];
        out[out_idx++] = (i + 1 < in_len) ? B64_CHARS[(triple >> 6) & 0x3F] : '=';
        out[out_idx++] = (i + 2 < in_len) ? B64_CHARS[triple & 0x3F] : '=';
    }
    out[out_idx] = '\0';
    return true;
}

bool apex_uri_decode(const char *src, size_t src_len, char *dst, size_t dst_cap) {
    if (src == NULL || dst == NULL || dst_cap == 0) {
        return false;
    }
    size_t src_idx = 0;
    size_t dst_idx = 0;

    while (src_idx < src_len) {
        if (dst_idx + 1 >= dst_cap) {
            return false;
        }
        if (src[src_idx] == '%') {
            if (src_idx + 2 < src_len) {
                int high = apex_hex_char_value(src[src_idx + 1]);
                int low = apex_hex_char_value(src[src_idx + 2]);
                if (high >= 0 && low >= 0) {
                    char ch = (char)((high << 4) | low);
                    if (ch == '\0') {
                        return false; /* Disallow null byte in path */
                    }
                    dst[dst_idx++] = ch;
                    src_idx += 3;
                    continue;
                }
            }
            return false; /* Malformed % encoding */
        }
        if (src[src_idx] == '\0') {
            return false;
        }
        dst[dst_idx++] = src[src_idx++];
    }
    dst[dst_idx] = '\0';
    return true;
}

bool apex_uri_is_traversal(const char *path, size_t len) {
    if (path == NULL) {
        return false;
    }
    for (size_t index = 0; index + 1 < len; index++) {
        if (path[index] == '.' && path[index + 1] == '.') {
            if (index + 2 == len || path[index + 2] == '/' || index == 0 || path[index - 1] == '/') {
                return true;
            }
        }
    }
    return false;
}

int apex_http1_scan_request(const char *buffer, size_t buffer_len,
                            size_t *out_header_len, size_t *out_content_len,
                            bool *out_has_cl, bool *out_has_te) {
    if (buffer == NULL || buffer_len < 4) {
        return 0;
    }
    const char *crlf_delimiter = memmem(buffer, buffer_len, "\r\n\r\n", 4);
    if (crlf_delimiter == NULL) {
        return 0;
    }
    size_t header_length = (size_t)((crlf_delimiter + 4) - buffer);
    size_t content_length = 0;
    bool has_cl = false;
    bool has_te = false;
    bool malformed_cl = false;
    bool malformed_te = false;

    const char *first_crlf = memmem(buffer, header_length, "\r\n", 2);
    if (first_crlf == NULL) {
        return -1;
    }
    const char *hdr_start = first_crlf + 2;
    const char *cur = hdr_start;
    const char *hdr_end = crlf_delimiter;

    while (cur < hdr_end) {
        const char *next_crlf = memmem(cur, (size_t)(hdr_end - cur), "\r\n", 2);
        size_t line_len = next_crlf ? (size_t)(next_crlf - cur) : (size_t)(hdr_end - cur);

        /* RFC 9112 §5.2: reject obs-fold (leading space or tab on header lines) */
        if (line_len > 0 && (cur[0] == ' ' || cur[0] == '\t')) {
            return -1;
        }

        /* RFC 9112 §5.1: No whitespace is allowed between header field name and colon */
        const char *colon = memchr(cur, ':', line_len);
        if (colon != NULL && colon > cur && (colon[-1] == ' ' || colon[-1] == '\t')) {
            return -1;
        }

        if (line_len >= 15 && strncasecmp(cur, "content-length:", 15) == 0) {
            const char *val = cur + 15;
            while (val < cur + line_len && (*val == ' ' || *val == '\t')) {
                val++;
            }
            if (*val == '+' || *val == '-' || !isdigit((unsigned char)*val)) {
                malformed_cl = true;
            } else {
                char *endptr = NULL;
                errno = 0;
                unsigned long parsed_cl = strtoul(val, &endptr, 10);
                if (endptr == val || errno != 0) {
                    malformed_cl = true;
                } else {
                    while (endptr < cur + line_len && (*endptr == ' ' || *endptr == '\t')) {
                        endptr++;
                    }
                    if (endptr != cur + line_len) {
                        malformed_cl = true;
                    }
                }
                if (has_cl && parsed_cl != content_length) {
                    malformed_cl = true;
                }
                has_cl = true;
                content_length = (size_t)parsed_cl;
            }
        } else if (line_len >= 18 && strncasecmp(cur, "transfer-encoding:", 18) == 0) {
            const char *val = cur + 18;
            /* RFC 9112 §6.3: verify chunked is the final transfer-coding */
            const char *te_ptr = val;
            const char *te_end = cur + line_len;
            const char *last_token = NULL;
            size_t last_token_len = 0;
            while (te_ptr < te_end) {
                while (te_ptr < te_end && (*te_ptr == ' ' || *te_ptr == '\t' || *te_ptr == ',')) {
                    te_ptr++;
                }
                if (te_ptr >= te_end) {
                    break;
                }
                const char *tok_start = te_ptr;
                while (te_ptr < te_end && *te_ptr != ' ' && *te_ptr != '\t' && *te_ptr != ',') {
                    te_ptr++;
                }
                last_token = tok_start;
                last_token_len = (size_t)(te_ptr - tok_start);
            }
            if (last_token != NULL && last_token_len == 7 && strncasecmp(last_token, "chunked", 7) == 0) {
                has_te = true;
            } else if (last_token != NULL) {
                malformed_te = true;
            }
        }

        if (next_crlf == NULL) {
            break;
        }
        cur = next_crlf + 2;
    }

    if (malformed_cl || (has_cl && has_te) || malformed_te) {
        return -1;
    }

    if (out_header_len != NULL) *out_header_len = header_length;
    if (out_content_len != NULL) *out_content_len = content_length;
    if (out_has_cl != NULL) *out_has_cl = has_cl;
    if (out_has_te != NULL) *out_has_te = has_te;
    return 1;
}
