/* TLS transport: SSL_CTX lifecycle and ALPN selection for listener endpoints.
 *
 * A generation owns its SSL_CTX (created from the validated configuration);
 * individual SSL objects reference it with OpenSSL's internal refcount, so
 * connections survive generation swaps and the context dies with its
 * generation. HTTP/2 negotiation lands in milestone 2b; for now ALPN only
 * selects "http/1.1" so the served protocol never exceeds what the core
 * implements. */
#include "internal.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static unsigned char g_session_ticket_key[48];
static pthread_once_t g_ticket_key_once = PTHREAD_ONCE_INIT;
static bool g_ticket_key_valid = false;

static void init_ticket_key(void) {
    if (RAND_bytes(g_session_ticket_key, sizeof(g_session_ticket_key)) == 1) {
        g_ticket_key_valid = true;
    }
}

static void tls_error(apex_config_error_t *error, const apex_config_t *config, const apex_server_config_t *server,
                      apex_config_status_t code, const char *format, ...) {
    memset(error, 0, sizeof(*error));
    error->code = code;
    error->line = server->line;
    snprintf(error->file, sizeof(error->file), "%s", config->source);

    char detail[APEX_CONFIG_MESSAGE_MAX];
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(detail, sizeof(detail), format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= sizeof(detail)) {
        snprintf(error->message, sizeof(error->message), "tls configuration failed");
        return;
    }

    const unsigned long ssl_error = ERR_peek_last_error();
    if (ssl_error != 0) {
        char reason[128];
        ERR_error_string_n(ssl_error, reason, sizeof(reason));
        snprintf(error->message, sizeof(error->message), "%s: %s", detail, reason);
    } else {
        snprintf(error->message, sizeof(error->message), "%s", detail);
    }
}

/* Advertised in client-preference order: HTTP/2 first, HTTP/1.1 fallback. */
static const unsigned char tls_alpn_protocols[] = {
    2u, 'h', '2', 8u, 'h', 't', 't', 'p', '/', '1', '.', '1',
};

static int tls_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *out_length,
                           const unsigned char *client, unsigned int client_length, void *argument) {
    (void)ssl;
    (void)argument;
    const unsigned char *selected = NULL;
    if (SSL_select_next_proto((unsigned char **)&selected, out_length, tls_alpn_protocols,
                              (unsigned int)sizeof(tls_alpn_protocols), client, client_length) ==
        OPENSSL_NPN_NEGOTIATED) {
        *out = selected;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

SSL_CTX *apex_tls_context_create(const apex_config_t *config, const apex_server_config_t *server,
                                 apex_config_error_t *error) {
    SSL_CTX *context = SSL_CTX_new(TLS_server_method());
    if (context == NULL) {
        tls_error(error, config, server, APEX_CONFIG_ERR_RUNTIME, "cannot allocate tls context");
        return NULL;
    }
    SSL_CTX_set_options(context, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_SERVER);
    static const unsigned char APEX_SID_CTX[] = "apex_v1";
    SSL_CTX_set_session_id_context(context, APEX_SID_CTX, sizeof(APEX_SID_CTX) - 1);
    SSL_CTX_set_timeout(context, 300);

    pthread_once(&g_ticket_key_once, init_ticket_key);
    if (g_ticket_key_valid) {
        SSL_CTX_set_tlsext_ticket_keys(context, g_session_ticket_key, sizeof(g_session_ticket_key));
    }

    /* The HTTP/2 send callback may complete an SSL_write across calls with
     * different buffers (nghttp2 retries pending data from its own internal
     * buffer), so partial writes and moving write buffers must be allowed.
     * The h1 path already copes with partial writes via write_offset. */
    SSL_CTX_set_mode(context, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_alpn_select_cb(context, tls_alpn_select, NULL);
    if (SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION) != 1) {
        tls_error(error, config, server, APEX_CONFIG_ERR_RUNTIME, "cannot set minimum tls version");
        SSL_CTX_free(context);
        return NULL;
    }

    for (size_t index = 0; index < server->tls.protocol_count; index++) {
        const char *protocol = server->tls.protocols[index];
        if (strcmp(protocol, "TLSv1.2") == 0) {
            if (SSL_CTX_set_max_proto_version(context, TLS1_2_VERSION) != 1) {
                tls_error(error, config, server, APEX_CONFIG_ERR_RUNTIME, "cannot restrict tls to %s", protocol);
                SSL_CTX_free(context);
                return NULL;
            }
        } else if (strcmp(protocol, "TLSv1.3") == 0) {
            if (SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION) != 1) {
                tls_error(error, config, server, APEX_CONFIG_ERR_RUNTIME, "cannot restrict tls to %s", protocol);
                SSL_CTX_free(context);
                return NULL;
            }
        } else {
            tls_error(error, config, server, APEX_CONFIG_ERR_SEMANTIC,
                      "tls protocols accepts TLSv1.2 or TLSv1.3, not '%s'", protocol);
            SSL_CTX_free(context);
            return NULL;
        }
    }

    if (server->tls.ciphers != NULL) {
        if (SSL_CTX_set_cipher_list(context, server->tls.ciphers) != 1) {
            tls_error(error, config, server, APEX_CONFIG_ERR_SEMANTIC, "tls ciphers rejected by openssl");
            SSL_CTX_free(context);
            return NULL;
        }
    }

    if (server->tls.client_auth == APEX_TLS_CLIENT_AUTH_REQUIRED) {
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        (void)SSL_CTX_set_default_verify_paths(context);
    } else if (server->tls.client_auth == APEX_TLS_CLIENT_AUTH_OPTIONAL) {
        SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);
        (void)SSL_CTX_set_default_verify_paths(context);
    } else {
        SSL_CTX_set_verify(context, SSL_VERIFY_NONE, NULL);
    }

    ERR_clear_error();
    if (SSL_CTX_use_certificate_chain_file(context, server->tls.certificate) != 1) {
        tls_error(error, config, server, APEX_CONFIG_ERR_IO, "cannot load certificate '%s'",
                  server->tls.certificate);
        SSL_CTX_free(context);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(context, server->tls.private_key, SSL_FILETYPE_PEM) != 1) {
        tls_error(error, config, server, APEX_CONFIG_ERR_IO, "cannot load private key '%s'", server->tls.private_key);
        SSL_CTX_free(context);
        return NULL;
    }
    if (SSL_CTX_check_private_key(context) != 1) {
        tls_error(error, config, server, APEX_CONFIG_ERR_SEMANTIC, "private key does not match the certificate");
        SSL_CTX_free(context);
        return NULL;
    }
    return context;
}

void apex_tls_context_destroy(SSL_CTX *context) {
    SSL_CTX_free(context);
}

bool apex_tls_config_has_listener(const apex_config_t *config) {
    for (size_t index = 0; index < config->server_count; index++) {
        if (config->servers[index].listen_tls) {
            return true;
        }
    }
    return false;
}

/* Validation-only pass used by `-t`: build and discard every configured
 * TLS context so certificate/key problems surface without serving. */
bool apex_tls_validate_config(const apex_config_t *config, apex_config_error_t *error) {
    for (size_t index = 0; index < config->server_count; index++) {
        const apex_server_config_t *server = &config->servers[index];
        if (!server->listen_tls) {
            continue;
        }
        SSL_CTX *context = apex_tls_context_create(config, server, error);
        if (context == NULL) {
            return false;
        }
        apex_tls_context_destroy(context);
    }
    return true;
}
