#ifndef APEX_AUTH_BASIC_H
#define APEX_AUTH_BASIC_H

#include "apex/config.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Validate an HTTP request against the configured HTTP Basic Authentication rules.
 * Returns true if authentication succeeds or is not required; false if rejected.
 */
bool apex_auth_basic_check(const char *req_buf, size_t req_buf_len, const apex_auth_basic_config_t *ab);

#ifdef __cplusplus
}
#endif

#endif /* APEX_AUTH_BASIC_H */
