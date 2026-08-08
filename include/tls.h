#ifndef TLS_H
#define TLS_H

#include "tachyon.h"

extern SSL_CTX *g_ssl_ctx;

int tls_init_server_ctx(const char *cert_path, const char *key_path);
void tls_destroy_server_ctx(void);

#endif /* TLS_H */
