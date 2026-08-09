#include "tls.h"

SSL_CTX *g_ssl_ctx = NULL;

static int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char proto[] = "\x08http/1.1";
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              proto, sizeof(proto) - 1,
                              in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    *out = (const unsigned char *)"http/1.1";
    *outlen = 8;
    return SSL_TLSEXT_ERR_OK;
}

int tls_init_server_ctx(const char *cert_path, const char *key_path) {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_callback, NULL);

#ifdef SSL_OP_ENABLE_KTLS
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
#endif
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                          SSL_MODE_RELEASE_BUFFERS);

    const char *c = cert_path;
    const char *k = key_path;

    if ((!c || !c[0]) && access("cert.pem", R_OK) == 0) c = "cert.pem";
    if ((!k || !k[0]) && access("key.pem", R_OK) == 0) k = "key.pem";

    if (!c || !k || access(c, R_OK) != 0 || access(k, R_OK) != 0) {
        fprintf(stderr, "tachyon: TLS certificate or key file not found.\n");
        fprintf(stderr, "Please specify -c <cert.pem> -k <key.pem> or generate test certs via 'make certs'.\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, c) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, k, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return -1;
    }

    g_ssl_ctx = ctx;
    return 0;
}

void tls_destroy_server_ctx(void) {
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}
