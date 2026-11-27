#ifndef APEX_ACME_H
#define APEX_ACME_H

#include "apex/config.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Thread-safe in-memory challenge token table for HTTP-01 challenges */
bool apex_acme_challenge_register(const char *token, const char *key_authorization);
bool apex_acme_challenge_lookup(const char *token, char *out_key_auth, size_t out_cap);
void apex_acme_challenge_unregister(const char *token);
void apex_acme_challenge_clear_all(void);

/* Hot reload active TLS context without restarting workers or dropping connections */
bool apex_acme_hot_reload_tls(apex_runtime_t *runtime, const char *cert_path, const char *key_path,
                              char *err_buf, size_t err_cap);

/* ACME Manager lifecycle */
typedef struct apex_acme_manager apex_acme_manager_t;

apex_acme_manager_t *apex_acme_manager_create(const apex_acme_config_t *config, apex_runtime_t *runtime);
void apex_acme_manager_destroy(apex_acme_manager_t *mgr);

/* Obtains/renews certificate for configured domains via RFC 8555 */
bool apex_acme_obtain_certificate(apex_acme_manager_t *mgr, char *err_buf, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* APEX_ACME_H */
