#include "tls.h"

SSL_CTX *g_ssl_ctx = NULL;

static int alpn_select_callback(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char server_protos[] = "\x08http/1.1";
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              server_protos, sizeof(server_protos) - 1,
                              in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    *out = (const unsigned char *)"http/1.1";
    *outlen = 8;
    return SSL_TLSEXT_ERR_OK;
}

static int init_in_memory_self_signed_cert(SSL_CTX *ctx) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return -1;

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    X509 *x509 = X509_new();
    if (!x509) { EVP_PKEY_free(pkey); return -1; }

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 315360000L);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"tachyon-https", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (X509_sign(x509, pkey, EVP_sha256()) <= 0 ||
        SSL_CTX_use_certificate(ctx, x509) <= 0 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 0;
}

int tls_init_server_ctx(const char *cert_path, const char *key_path) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
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
    SSL_CTX_set1_groups_list(ctx, "X25519:prime256v1");

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                          SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_set_timeout(ctx, 3600);

    if (cert_path && key_path && access(cert_path, R_OK) == 0 && access(key_path, R_OK) == 0) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return -1;
        }
    } else {
        if (init_in_memory_self_signed_cert(ctx) < 0) {
            fprintf(stderr, "Failed to initialize SSL certificate\n");
            SSL_CTX_free(ctx);
            return -1;
        }
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
