#ifndef APEX_HTTP_UTIL_H
#define APEX_HTTP_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "apex/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Locate the first occurrence of CRLF ("\r\n") within a memory buffer.
 * Returns pointer to '\r' or NULL if not found.
 */
const char *apex_http_find_crlf(const char *data, size_t length);

/**
 * Compare an HTTP header field name against an expected string case-insensitively.
 */
bool apex_http_header_name_equal(const char *name, size_t name_length, const char *expected);

/**
 * Search an HTTP request or response header block for a specific header by name.
 * On success, sets *value_out to the trimmed start of the value and *value_length_out
 * to its length, returning true.
 */
bool apex_http_find_header(const char *buffer, size_t length, const char *name,
                           const char **value_out, size_t *value_length_out);

/**
 * Check if a comma-separated list of tokens (such as Connection: Upgrade, keep-alive)
 * contains a specific token case-insensitively.
 */
bool apex_http_is_connection_token(const char *conn_val, size_t conn_val_len,
                                   const char *token, size_t token_len);

/**
 * Format the standard HTTP "Server:" header line according to apex_server_tokens_config_t.
 * Always writes trailing "\r\n" and returns the number of characters formatted.
 */
size_t apex_http_format_server_header(const apex_server_tokens_config_t *tokens,
                                      char *buf, size_t buf_cap);

/**
 * Resolve effective server_tokens config from server or http block, falling back to default (ON).
 */
const apex_server_tokens_config_t *apex_http_get_server_tokens(const apex_server_config_t *server,
                                                               const apex_http_config_t *http);

/**
 * Parse an HTTP date in IMF-fixdate format (e.g. "Sun, 06 Nov 1994 08:49:37 GMT").
 * Sets *out_time and returns true on success.
 */
bool apex_http_parse_date(const char *str, size_t len, time_t *out_time);

/**
 * Format a time_t value as an IMF-fixdate string into buf.
 * Returns true on success.
 */
bool apex_http_format_date(time_t t, char *buf, size_t buf_cap);

/**
 * Return numerical value (0-15) for a hex character, or -1 if invalid.
 */
int apex_hex_char_value(char c);

/**
 * Encode raw bytes as a lowercase hexadecimal null-terminated string.
 * dst must have capacity at least (len * 2 + 1).
 */
void apex_hex_encode(const unsigned char *src, size_t len, char *dst);

/**
 * Decode a Base64 string into raw bytes.
 * Returns true on success with *out_len set.
 */
bool apex_base64_decode(const char *in, size_t in_len, char *out, size_t out_cap, size_t *out_len);

/**
 * Encode raw bytes into a Base64 null-terminated string.
 * Returns true on success.
 */
bool apex_base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_cap);

/**
 * Decode a percent-encoded URI path into dst.
 * Returns true on success, false if malformed hex, illegal characters, or null byte injection.
 */
bool apex_uri_decode(const char *src, size_t src_len, char *dst, size_t dst_cap);

/**
 * Check if a decoded URI path attempts directory traversal ("..").
 * Returns true if traversal detected.
 */
bool apex_uri_is_traversal(const char *path, size_t len);

/**
 * Scan an HTTP/1.1 request buffer for valid headers, RFC 9112 compliance,
 * Content-Length and Transfer-Encoding validity.
 * Returns: 1 if complete and valid, 0 if incomplete (no CRLFCRLF), -1 if malformed.
 */
int apex_http1_scan_request(const char *buffer, size_t buffer_len,
                            size_t *out_header_len, size_t *out_content_len,
                            bool *out_has_cl, bool *out_has_te);

#ifdef __cplusplus
}
#endif

#endif /* APEX_HTTP_UTIL_H */
