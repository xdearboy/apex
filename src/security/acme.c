#include "apex/acme.h"
#include "apex/http_util.h"
#include "internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define APEX_ACME_MAX_CHALLENGES 64
#define APEX_ACME_HTTP_TIMEOUT_SEC 10
#define APEX_ACME_POLL_MAX_ATTEMPTS 30

typedef struct {
    char token[128];
    char key_authorization[256];
    bool in_use;
} acme_challenge_entry_t;

static struct {
    acme_challenge_entry_t entries[APEX_ACME_MAX_CHALLENGES];
    pthread_rwlock_t lock;
    bool initialized;
} g_acme_challenges = {
    .lock = PTHREAD_RWLOCK_INITIALIZER,
    .initialized = true
};

bool apex_acme_challenge_register(const char *token, const char *key_authorization) {
    if (token == NULL || token[0] == '\0' || key_authorization == NULL || key_authorization[0] == '\0') {
        return false;
    }

    pthread_rwlock_wrlock(&g_acme_challenges.lock);
    int free_slot = -1;

    for (int i = 0; i < APEX_ACME_MAX_CHALLENGES; i++) {
        if (g_acme_challenges.entries[i].in_use) {
            if (strcmp(g_acme_challenges.entries[i].token, token) == 0) {
                snprintf(g_acme_challenges.entries[i].key_authorization,
                         sizeof(g_acme_challenges.entries[i].key_authorization), "%s", key_authorization);
                pthread_rwlock_unlock(&g_acme_challenges.lock);
                return true;
            }
        } else if (free_slot < 0) {
            free_slot = i;
        }
    }

    if (free_slot < 0) {
        pthread_rwlock_unlock(&g_acme_challenges.lock);
        return false;
    }

    acme_challenge_entry_t *entry = &g_acme_challenges.entries[free_slot];
    snprintf(entry->token, sizeof(entry->token), "%s", token);
    snprintf(entry->key_authorization, sizeof(entry->key_authorization), "%s", key_authorization);
    entry->in_use = true;

    pthread_rwlock_unlock(&g_acme_challenges.lock);
    return true;
}

bool apex_acme_challenge_lookup(const char *token, char *out_key_auth, size_t out_cap) {
    if (token == NULL || token[0] == '\0' || out_key_auth == NULL || out_cap == 0) {
        return false;
    }

    pthread_rwlock_rdlock(&g_acme_challenges.lock);

    for (int i = 0; i < APEX_ACME_MAX_CHALLENGES; i++) {
        if (g_acme_challenges.entries[i].in_use && strcmp(g_acme_challenges.entries[i].token, token) == 0) {
            snprintf(out_key_auth, out_cap, "%s", g_acme_challenges.entries[i].key_authorization);
            pthread_rwlock_unlock(&g_acme_challenges.lock);
            return true;
        }
    }

    pthread_rwlock_unlock(&g_acme_challenges.lock);
    return false;
}

void apex_acme_challenge_unregister(const char *token) {
    if (token == NULL || token[0] == '\0') {
        return;
    }

    pthread_rwlock_wrlock(&g_acme_challenges.lock);

    for (int i = 0; i < APEX_ACME_MAX_CHALLENGES; i++) {
        if (g_acme_challenges.entries[i].in_use && strcmp(g_acme_challenges.entries[i].token, token) == 0) {
            memset(&g_acme_challenges.entries[i], 0, sizeof(g_acme_challenges.entries[i]));
            break;
        }
    }

    pthread_rwlock_unlock(&g_acme_challenges.lock);
}

void apex_acme_challenge_clear_all(void) {
    pthread_rwlock_wrlock(&g_acme_challenges.lock);
    memset(g_acme_challenges.entries, 0, sizeof(g_acme_challenges.entries));
    pthread_rwlock_unlock(&g_acme_challenges.lock);
}

bool apex_acme_hot_reload_tls(apex_runtime_t *runtime, const char *cert_path, const char *key_path,
                              char *err_buf, size_t err_cap) {
    if (runtime == NULL || cert_path == NULL || key_path == NULL) {
        if (err_buf && err_cap > 0) {
            snprintf(err_buf, err_cap, "invalid runtime or certificate paths");
        }
        return false;
    }

    SSL_CTX *new_context = apex_tls_context_create_from_files(cert_path, key_path, err_buf, err_cap);
    if (new_context == NULL) {
        return false;
    }

    /* Atomically update runtime->tls_context and active generation's context */
    void *old_context = NULL;
    __atomic_exchange(&runtime->tls_context, &new_context, &old_context, __ATOMIC_SEQ_CST);
    if (runtime->active_generation != NULL) {
        apex_generation_t *gen = (apex_generation_t *)runtime->active_generation;
        void *old_gen_ctx = NULL;
        __atomic_exchange(&gen->tls_context, &new_context, &old_gen_ctx, __ATOMIC_SEQ_CST);
    }
    (void)old_context;
    return true;
}

/* ========================================================================= */
/* Base64URL and Cryptographic Helpers (RFC 7515 / RFC 8555)                 */
/* ========================================================================= */

static const char B64URL_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int base64url_encode(const unsigned char *in, size_t in_len, char *out, size_t out_max) {
    size_t out_len = ((in_len + 2) / 3) * 4;
    if (out_len >= out_max) {
        return -1;
    }

    size_t i = 0;
    size_t j = 0;
    while (i < in_len) {
        uint32_t octet_a = in[i++];
        uint32_t octet_b = (i < in_len) ? in[i++] : 0;
        uint32_t octet_c = (i < in_len) ? in[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = B64URL_TABLE[(triple >> 18) & 0x3F];
        out[j++] = B64URL_TABLE[(triple >> 12) & 0x3F];

        size_t remaining = in_len - (i - (octet_c ? 0 : (octet_b ? 1 : 2)));
        if (remaining >= 2) {
            out[j++] = B64URL_TABLE[(triple >> 6) & 0x3F];
        }
        if (remaining >= 3) {
            out[j++] = B64URL_TABLE[triple & 0x3F];
        }
    }
    out[j] = '\0';
    return (int)j;
}

static EVP_PKEY *acme_generate_ec_key(void) {
    return EVP_EC_gen("P-256");
}

static bool acme_save_key_pem(EVP_PKEY *key, const char *path) {
    if (key == NULL || path == NULL || path[0] == '\0') {
        return false;
    }
    BIO *bio = BIO_new_file(path, "w");
    if (bio == NULL) {
        return false;
    }
    int rc = PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
    BIO_free(bio);
    return (rc == 1);
}

static EVP_PKEY *acme_load_key_pem(const char *path) {
    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    BIO *bio = BIO_new_file(path, "r");
    if (bio == NULL) {
        return NULL;
    }
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return key;
}

static bool acme_compute_jwk_thumbprint(EVP_PKEY *key, char *out_thumbprint, size_t out_cap,
                                        char *out_x_b64, size_t out_x_cap,
                                        char *out_y_b64, size_t out_y_cap) {
    if (key == NULL || out_thumbprint == NULL || out_cap == 0) {
        return false;
    }

    unsigned char pub[128];
    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub), &pub_len) != 1 ||
        pub_len != 65 || pub[0] != 0x04) {
        return false;
    }

    /* pub[1..32] is X coordinate, pub[33..64] is Y coordinate */
    char x_b64[64];
    char y_b64[64];
    if (base64url_encode(pub + 1, 32, x_b64, sizeof(x_b64)) < 0 ||
        base64url_encode(pub + 33, 32, y_b64, sizeof(y_b64)) < 0) {
        return false;
    }

    if (out_x_b64 && out_x_cap > 0) {
        snprintf(out_x_b64, out_x_cap, "%s", x_b64);
    }
    if (out_y_b64 && out_y_cap > 0) {
        snprintf(out_y_b64, out_y_cap, "%s", y_b64);
    }

    /* RFC 7638 canonical JWK for EC P-256 */
    char canonical_jwk[256];
    int len = snprintf(canonical_jwk, sizeof(canonical_jwk),
                       "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
                       x_b64, y_b64);
    if (len < 0 || (size_t)len >= sizeof(canonical_jwk)) {
        return false;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)canonical_jwk, (size_t)len, hash);

    if (base64url_encode(hash, sizeof(hash), out_thumbprint, out_cap) < 0) {
        return false;
    }

    return true;
}

/* ========================================================================= */
/* JSON Helper Functions for ACME Parsing                                    */
/* ========================================================================= */

static bool acme_json_find_string(const char *json, size_t json_len, const char *key,
                                 char *out, size_t out_cap) {
    if (json == NULL || key == NULL || out == NULL || out_cap == 0) {
        return false;
    }
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *found = memmem(json, json_len, needle, strlen(needle));
    if (found == NULL) {
        return false;
    }
    const char *colon = memchr(found + strlen(needle), ':', json_len - (size_t)(found + strlen(needle) - json));
    if (colon == NULL) {
        return false;
    }
    const char *p = colon + 1;
    while (p < json + json_len && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    if (p >= json + json_len || *p != '"') {
        return false;
    }
    p++;
    const char *start = p;
    while (p < json + json_len && *p != '"') {
        if (*p == '\\' && p + 1 < json + json_len) {
            p++;
        }
        p++;
    }
    if (p >= json + json_len) {
        return false;
    }
    size_t val_len = (size_t)(p - start);
    if (val_len >= out_cap) {
        val_len = out_cap - 1;
    }
    memcpy(out, start, val_len);
    out[val_len] = '\0';
    return true;
}

static bool acme_json_find_first_array_string(const char *json, size_t json_len, const char *array_key,
                                              char *out, size_t out_cap) {
    if (json == NULL || array_key == NULL || out == NULL || out_cap == 0) {
        return false;
    }
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", array_key);
    const char *found = memmem(json, json_len, needle, strlen(needle));
    if (found == NULL) {
        return false;
    }
    const char *bracket = memchr(found + strlen(needle), '[', json_len - (size_t)(found + strlen(needle) - json));
    if (bracket == NULL) {
        return false;
    }
    const char *quote = memchr(bracket + 1, '"', json_len - (size_t)(bracket + 1 - json));
    if (quote == NULL) {
        return false;
    }
    const char *start = quote + 1;
    const char *end = memchr(start, '"', json_len - (size_t)(start - json));
    if (end == NULL) {
        return false;
    }
    size_t val_len = (size_t)(end - start);
    if (val_len >= out_cap) {
        val_len = out_cap - 1;
    }
    memcpy(out, start, val_len);
    out[val_len] = '\0';
    return true;
}

/* ========================================================================= */
/* HTTP / HTTPS Client Helper (Socket + OpenSSL)                             */
/* ========================================================================= */

typedef struct {
    int status_code;
    char replay_nonce[128];
    char location[512];
    char *body;
    size_t body_len;
    size_t body_cap;
} acme_http_response_t;

static void acme_http_response_init(acme_http_response_t *resp) {
    memset(resp, 0, sizeof(*resp));
}

static void acme_http_response_cleanup(acme_http_response_t *resp) {
    if (resp && resp->body) {
        free(resp->body);
        resp->body = NULL;
    }
}

static bool acme_parse_url(const char *url, bool *is_https, char *host, size_t host_cap,
                           uint16_t *port, char *path, size_t path_cap) {
    if (url == NULL || host == NULL || port == NULL || path == NULL) {
        return false;
    }

    const char *p = url;
    if (strncmp(p, "https://", 8) == 0) {
        *is_https = true;
        p += 8;
        *port = 443;
    } else if (strncmp(p, "http://", 7) == 0) {
        *is_https = false;
        p += 7;
        *port = 80;
    } else {
        return false;
    }

    const char *slash = strchr(p, '/');
    const char *colon = strchr(p, ':');
    if (colon != NULL && (slash == NULL || colon < slash)) {
        size_t hlen = (size_t)(colon - p);
        if (hlen >= host_cap) return false;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
        *port = (uint16_t)atoi(colon + 1);
    } else {
        size_t hlen = slash != NULL ? (size_t)(slash - p) : strlen(p);
        if (hlen >= host_cap) return false;
        memcpy(host, p, hlen);
        host[hlen] = '\0';
    }

    if (slash != NULL) {
        snprintf(path, path_cap, "%s", slash);
    } else {
        snprintf(path, path_cap, "/");
    }

    return true;
}

static int acme_http_request(const char *url, const char *method, const char *content_type,
                             const char *accept, const char *body, acme_http_response_t *resp,
                             char *err_buf, size_t err_cap) {
    acme_http_response_init(resp);

    bool is_https = false;
    char host[256];
    uint16_t port = 80;
    char path[1024];

    if (!acme_parse_url(url, &is_https, host, sizeof(host), &port, path, sizeof(path))) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "invalid ACME URL: %s", url);
        return -1;
    }

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo *addrs = NULL;
    if (getaddrinfo(host, port_str, &hints, &addrs) != 0 || addrs == NULL) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "cannot resolve host: %s", host);
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *ai = addrs; ai != NULL; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;

        struct timeval tv = {.tv_sec = APEX_ACME_HTTP_TIMEOUT_SEC, .tv_usec = 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(addrs);

    if (sock < 0) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "cannot connect to %s:%u", host, (unsigned)port);
        return -1;
    }

    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    if (is_https) {
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (ssl_ctx == NULL) {
            close(sock);
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "cannot create SSL_CTX");
            return -1;
        }
        SSL_CTX_set_default_verify_paths(ssl_ctx);

        ssl = SSL_new(ssl_ctx);
        if (ssl == NULL) {
            SSL_CTX_free(ssl_ctx);
            close(sock);
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "cannot create SSL");
            return -1;
        }
        SSL_set_tlsext_host_name(ssl, host);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            close(sock);
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "TLS handshake failed with %s", host);
            return -1;
        }
    }

    /* Format HTTP request */
    size_t body_len = body ? strlen(body) : 0;
    char req_hdr[4096];
    int hdr_len = snprintf(req_hdr, sizeof(req_hdr),
                           "%s %s HTTP/1.1\r\n"
                           "Host: %s:%u\r\n"
                           "User-Agent: apex/1.4.0\r\n"
                           "Connection: close\r\n"
                           "%s%s%s"
                           "%s%s%s"
                           "Content-Length: %zu\r\n"
                           "\r\n",
                           method, path, host, (unsigned)port,
                           content_type ? "Content-Type: " : "", content_type ? content_type : "", content_type ? "\r\n" : "",
                           accept ? "Accept: " : "", accept ? accept : "", accept ? "\r\n" : "",
                           body_len);

    if (hdr_len < 0 || (size_t)hdr_len >= sizeof(req_hdr)) {
        if (ssl) SSL_free(ssl);
        if (ssl_ctx) SSL_CTX_free(ssl_ctx);
        close(sock);
        return -1;
    }

    /* Send request */
    if (is_https) {
        SSL_write(ssl, req_hdr, hdr_len);
        if (body_len > 0) {
            SSL_write(ssl, body, (int)body_len);
        }
    } else {
        send(sock, req_hdr, (size_t)hdr_len, 0);
        if (body_len > 0) {
            send(sock, body, body_len, 0);
        }
    }

    /* Read response */
    char raw_resp[65536];
    size_t total_read = 0;
    for (;;) {
        int n = 0;
        if (is_https) {
            n = SSL_read(ssl, raw_resp + total_read, (int)(sizeof(raw_resp) - total_read - 1));
        } else {
            ssize_t sn = recv(sock, raw_resp + total_read, sizeof(raw_resp) - total_read - 1, 0);
            n = (int)sn;
        }
        if (n <= 0) break;
        total_read += (size_t)n;
        if (total_read >= sizeof(raw_resp) - 1) break;
    }
    raw_resp[total_read] = '\0';

    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    close(sock);

    if (total_read == 0) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "empty HTTP response from %s", host);
        return -1;
    }

    /* Parse Status-Line: HTTP/1.x NNN */
    const char *status_p = strchr(raw_resp, ' ');
    if (status_p != NULL) {
        resp->status_code = atoi(status_p + 1);
    }

    /* Find Header / Body separator */
    const char *sep = strstr(raw_resp, "\r\n\r\n");
    if (sep != NULL) {
        size_t hdr_bytes = (size_t)(sep - raw_resp);
        const char *body_p = sep + 4;
        resp->body_len = total_read - (hdr_bytes + 4);
        resp->body = malloc(resp->body_len + 1);
        if (resp->body != NULL) {
            memcpy(resp->body, body_p, resp->body_len);
            resp->body[resp->body_len] = '\0';
        }

        /* Parse Replay-Nonce and Location headers */
        char hdrs_copy[4096];
        size_t copy_len = hdr_bytes < sizeof(hdrs_copy) - 1 ? hdr_bytes : sizeof(hdrs_copy) - 1;
        memcpy(hdrs_copy, raw_resp, copy_len);
        hdrs_copy[copy_len] = '\0';

        char *line = strtok(hdrs_copy, "\r\n");
        while (line != NULL) {
            if (strncasecmp(line, "replay-nonce:", 13) == 0) {
                const char *val = line + 13;
                while (*val == ' ' || *val == '\t') val++;
                snprintf(resp->replay_nonce, sizeof(resp->replay_nonce), "%s", val);
            } else if (strncasecmp(line, "location:", 9) == 0) {
                const char *val = line + 9;
                while (*val == ' ' || *val == '\t') val++;
                snprintf(resp->location, sizeof(resp->location), "%s", val);
            }
            line = strtok(NULL, "\r\n");
        }
    }

    return 0;
}

/* ========================================================================= */
/* JWS ES256 Request Signer (RFC 8555 §6.2 / RFC 7515)                       */
/* ========================================================================= */

static int acme_jws_sign(EVP_PKEY *key, const char *url, const char *nonce, const char *kid,
                         const char *payload_json, char *out_jws, size_t out_jws_cap) {
    if (key == NULL || url == NULL || nonce == NULL || out_jws == NULL || out_jws_cap == 0) {
        return -1;
    }

    /* 1. Construct Protected Header */
    char protected_hdr[1024];
    if (kid != NULL && kid[0] != '\0') {
        snprintf(protected_hdr, sizeof(protected_hdr),
                 "{\"alg\":\"ES256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"url\":\"%s\"}",
                 kid, nonce, url);
    } else {
        char thumbprint[128];
        char x_b64[64];
        char y_b64[64];
        if (!acme_compute_jwk_thumbprint(key, thumbprint, sizeof(thumbprint),
                                         x_b64, sizeof(x_b64), y_b64, sizeof(y_b64))) {
            return -1;
        }
        snprintf(protected_hdr, sizeof(protected_hdr),
                 "{\"alg\":\"ES256\",\"jwk\":{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"},\"nonce\":\"%s\",\"url\":\"%s\"}",
                 x_b64, y_b64, nonce, url);
    }

    char protected_b64[1536];
    if (base64url_encode((const unsigned char *)protected_hdr, strlen(protected_hdr),
                         protected_b64, sizeof(protected_b64)) < 0) {
        return -1;
    }

    /* 2. Encode Payload (or empty for POST-as-GET) */
    char payload_b64[4096];
    if (payload_json != NULL && payload_json[0] != '\0') {
        if (base64url_encode((const unsigned char *)payload_json, strlen(payload_json),
                             payload_b64, sizeof(payload_b64)) < 0) {
            return -1;
        }
    } else {
        payload_b64[0] = '\0';
    }

    /* 3. Signing Input = protected64 + "." + payload64 */
    char signing_input[6144];
    int sig_input_len = snprintf(signing_input, sizeof(signing_input), "%s.%s", protected_b64, payload_b64);
    if (sig_input_len < 0 || (size_t)sig_input_len >= sizeof(signing_input)) {
        return -1;
    }

    /* 4. ECDSA Sign over SHA-256 */
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return -1;
    }
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, key) != 1 ||
        EVP_DigestSignUpdate(md_ctx, signing_input, (size_t)sig_input_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }

    unsigned char der_sig[128];
    size_t der_sig_len = sizeof(der_sig);
    if (EVP_DigestSignFinal(md_ctx, der_sig, &der_sig_len) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return -1;
    }
    EVP_MD_CTX_free(md_ctx);

    /* 5. Convert DER ECDSA signature to IEEE P1363 (64 bytes: 32 R + 32 S) */
    const unsigned char *p = der_sig;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, (long)der_sig_len);
    if (sig == NULL) {
        return -1;
    }

    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    ECDSA_SIG_get0(sig, &r, &s);

    unsigned char raw_sig[64];
    BN_bn2binpad(r, raw_sig, 32);
    BN_bn2binpad(s, raw_sig + 32, 32);
    ECDSA_SIG_free(sig);

    char sig_b64[128];
    if (base64url_encode(raw_sig, sizeof(raw_sig), sig_b64, sizeof(sig_b64)) < 0) {
        return -1;
    }

    /* 6. Produce final JWS JSON */
    int jws_len = snprintf(out_jws, out_jws_cap,
                           "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}",
                           protected_b64, payload_b64, sig_b64);
    if (jws_len < 0 || (size_t)jws_len >= out_jws_cap) {
        return -1;
    }

    return 0;
}

/* ========================================================================= */
/* CSR Generation (RFC 2986 / RFC 8555)                                      */
/* ========================================================================= */

static int acme_generate_csr_b64(EVP_PKEY *key, const char *domains[], size_t domain_count,
                                 char *out_csr_b64, size_t out_cap) {
    if (key == NULL || domains == NULL || domain_count == 0 || out_csr_b64 == NULL || out_cap == 0) {
        return -1;
    }

    X509_REQ *req = X509_REQ_new();
    if (req == NULL) {
        return -1;
    }
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, key);

    X509_NAME *name = X509_NAME_new();
    if (name == NULL) {
        X509_REQ_free(req);
        return -1;
    }
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)domains[0], -1, -1, 0);
    X509_REQ_set_subject_name(req, name);
    X509_NAME_free(name);

    STACK_OF(GENERAL_NAME) *gens = sk_GENERAL_NAME_new_null();
    for (size_t i = 0; i < domain_count; i++) {
        GENERAL_NAME *gen = GENERAL_NAME_new();
        gen->type = GEN_DNS;
        gen->d.dNSName = ASN1_IA5STRING_new();
        ASN1_STRING_set(gen->d.dNSName, domains[i], (int)strlen(domains[i]));
        sk_GENERAL_NAME_push(gens, gen);
    }

    X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
    X509_EXTENSION *ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, gens);
    sk_X509_EXTENSION_push(exts, ext);
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);

    X509_REQ_add_extensions(req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    if (X509_REQ_sign(req, key, EVP_sha256()) <= 0) {
        X509_REQ_free(req);
        return -1;
    }

    unsigned char *der = NULL;
    int der_len = i2d_X509_REQ(req, &der);
    X509_REQ_free(req);

    if (der_len <= 0 || der == NULL) {
        return -1;
    }

    int rc = base64url_encode(der, (size_t)der_len, out_csr_b64, out_cap);
    OPENSSL_free(der);
    return rc;
}

/* ========================================================================= */
/* Certificate Expiry Check                                                  */
/* ========================================================================= */

static bool acme_check_certificate_needs_renewal(const char *cert_path, int days_before) {
    if (cert_path == NULL || cert_path[0] == '\0') {
        return true;
    }

    BIO *bio = BIO_new_file(cert_path, "r");
    if (bio == NULL) {
        return true;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert == NULL) {
        return true;
    }

    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (not_after == NULL) {
        X509_free(cert);
        return true;
    }

    int pday = 0, psec = 0;
    if (ASN1_TIME_diff(&pday, &psec, NULL, not_after) != 1) {
        X509_free(cert);
        return true;
    }

    /* Convert remaining difference to seconds */
    int64_t remaining_seconds = ((int64_t)pday * 86400) + psec;
    X509_free(cert);

    return (remaining_seconds < ((int64_t)days_before * 86400));
}

/* ========================================================================= */
/* ACME Manager Implementation                                               */
/* ========================================================================= */

struct apex_acme_manager {
    apex_acme_config_t config;
    apex_runtime_t *runtime;
    pthread_t worker_thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool thread_started;
    bool running;
    EVP_PKEY *account_key;
};

static void *acme_worker_thread(void *arg);

apex_acme_manager_t *apex_acme_manager_create(const apex_acme_config_t *config, apex_runtime_t *runtime) {
    if (config == NULL || !config->enabled || runtime == NULL) {
        return NULL;
    }

    apex_acme_manager_t *mgr = calloc(1, sizeof(*mgr));
    if (mgr == NULL) {
        return NULL;
    }

    mgr->config = *config;
    mgr->runtime = runtime;
    mgr->running = true;
    pthread_mutex_init(&mgr->mutex, NULL);
    pthread_cond_init(&mgr->cond, NULL);

    /* Load account key if already present, or generate new.
     * RFC 8555 §6.2: Account keys MUST be distinct from domain certificate keys.
     * We store the account key in <key_path>.account.key */
    char acct_key_path[512] = {0};
    if (config->key_path[0] != '\0') {
        snprintf(acct_key_path, sizeof(acct_key_path), "%s.account.key", config->key_path);
        mgr->account_key = acme_load_key_pem(acct_key_path);
    }
    if (mgr->account_key == NULL) {
        mgr->account_key = acme_generate_ec_key();
        if (mgr->account_key != NULL && acct_key_path[0] != '\0') {
            acme_save_key_pem(mgr->account_key, acct_key_path);
        }
    }
    if (mgr->account_key == NULL) {
        pthread_cond_destroy(&mgr->cond);
        pthread_mutex_destroy(&mgr->mutex);
        free(mgr);
        return NULL;
    }

    int rc = pthread_create(&mgr->worker_thread, NULL, acme_worker_thread, mgr);
    if (rc == 0) {
        mgr->thread_started = true;
    } else {
        EVP_PKEY_free(mgr->account_key);
        pthread_cond_destroy(&mgr->cond);
        pthread_mutex_destroy(&mgr->mutex);
        free(mgr);
        return NULL;
    }

    return mgr;
}

void apex_acme_manager_destroy(apex_acme_manager_t *mgr) {
    if (mgr == NULL) {
        return;
    }

    pthread_mutex_lock(&mgr->mutex);
    mgr->running = false;
    pthread_cond_broadcast(&mgr->cond);
    pthread_mutex_unlock(&mgr->mutex);

    if (mgr->thread_started) {
        pthread_join(mgr->worker_thread, NULL);
        mgr->thread_started = false;
    }

    pthread_mutex_destroy(&mgr->mutex);
    pthread_cond_destroy(&mgr->cond);

    if (mgr->account_key != NULL) {
        EVP_PKEY_free(mgr->account_key);
        mgr->account_key = NULL;
    }

    free(mgr);
}

/* Obtains or renews certificate via RFC 8555 */
bool apex_acme_obtain_certificate(apex_acme_manager_t *mgr, char *err_buf, size_t err_cap) {
    if (mgr == NULL) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "null acme manager");
        return false;
    }

    const char *dir_url = mgr->config.directory_url;
    if (dir_url[0] == '\0') {
        dir_url = mgr->config.staging ?
            "https://acme-staging-v02.api.letsencrypt.org/directory" :
            "https://acme-v02.api.letsencrypt.org/directory";
    }

    if (mgr->config.domain_count == 0) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "no ACME domains configured");
        return false;
    }

    /* 1. Fetch Directory */
    acme_http_response_t resp;
    if (acme_http_request(dir_url, "GET", NULL, "application/json", NULL, &resp, err_buf, err_cap) != 0) {
        return false;
    }
    if (resp.status_code != 200 || resp.body == NULL) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "failed to fetch ACME directory: status %d", resp.status_code);
        acme_http_response_cleanup(&resp);
        return false;
    }

    char new_nonce_url[512] = {0};
    char new_account_url[512] = {0};
    char new_order_url[512] = {0};
    acme_json_find_string(resp.body, resp.body_len, "newNonce", new_nonce_url, sizeof(new_nonce_url));
    acme_json_find_string(resp.body, resp.body_len, "newAccount", new_account_url, sizeof(new_account_url));
    acme_json_find_string(resp.body, resp.body_len, "newOrder", new_order_url, sizeof(new_order_url));
    acme_http_response_cleanup(&resp);

    if (new_nonce_url[0] == '\0' || new_account_url[0] == '\0' || new_order_url[0] == '\0') {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "incomplete ACME directory endpoints");
        return false;
    }

    /* 2. Fetch Initial Nonce */
    if (acme_http_request(new_nonce_url, "HEAD", NULL, NULL, NULL, &resp, err_buf, err_cap) != 0) {
        return false;
    }
    char current_nonce[128] = {0};
    snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
    acme_http_response_cleanup(&resp);

    if (current_nonce[0] == '\0') {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "missing Replay-Nonce from directory");
        return false;
    }

    /* 3. Register or Retrieve Account (newAccount) */
    char acct_payload[512];
    snprintf(acct_payload, sizeof(acct_payload),
             "{\"termsOfServiceAgreed\":true,\"contact\":[\"mailto:%s\"]}",
             mgr->config.email);

    char jws_req[8192];
    if (acme_jws_sign(mgr->account_key, new_account_url, current_nonce, NULL, acct_payload, jws_req, sizeof(jws_req)) != 0) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "failed to sign newAccount JWS");
        return false;
    }

    if (acme_http_request(new_account_url, "POST", "application/jose+json", NULL, jws_req, &resp, err_buf, err_cap) != 0) {
        return false;
    }
    if (resp.status_code != 200 && resp.status_code != 201) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "newAccount failed: HTTP %d", resp.status_code);
        acme_http_response_cleanup(&resp);
        return false;
    }

    char account_url[512] = {0};
    snprintf(account_url, sizeof(account_url), "%s", resp.location);
    if (resp.replay_nonce[0] != '\0') {
        snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
    }
    acme_http_response_cleanup(&resp);

    if (account_url[0] == '\0') {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "missing Account URL (Location header)");
        return false;
    }

    /* 4. Create New Order (newOrder) */
    char order_payload[2048] = "{\"identifiers\":[";
    for (size_t i = 0; i < mgr->config.domain_count; i++) {
        char ident[256];
        snprintf(ident, sizeof(ident), "%s{\"type\":\"dns\",\"value\":\"%s\"}",
                 i > 0 ? "," : "", mgr->config.domains[i]);
        strncat(order_payload, ident, sizeof(order_payload) - strlen(order_payload) - 1);
    }
    strncat(order_payload, "]}", sizeof(order_payload) - strlen(order_payload) - 1);

    if (acme_jws_sign(mgr->account_key, new_order_url, current_nonce, account_url, order_payload, jws_req, sizeof(jws_req)) != 0) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "failed to sign newOrder JWS");
        return false;
    }

    if (acme_http_request(new_order_url, "POST", "application/jose+json", NULL, jws_req, &resp, err_buf, err_cap) != 0) {
        return false;
    }
    if (resp.status_code != 201) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "newOrder failed: HTTP %d", resp.status_code);
        acme_http_response_cleanup(&resp);
        return false;
    }

    char order_url[512] = {0};
    snprintf(order_url, sizeof(order_url), "%s", resp.location);
    if (resp.replay_nonce[0] != '\0') {
        snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
    }

    char auth_url[512] = {0};
    char finalize_url[512] = {0};
    acme_json_find_first_array_string(resp.body, resp.body_len, "authorizations", auth_url, sizeof(auth_url));
    acme_json_find_string(resp.body, resp.body_len, "finalize", finalize_url, sizeof(finalize_url));
    acme_http_response_cleanup(&resp);

    if (auth_url[0] == '\0' || finalize_url[0] == '\0') {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "incomplete newOrder response");
        return false;
    }

    /* 5. Fetch Authorization and Complete HTTP-01 Challenge */
    if (acme_jws_sign(mgr->account_key, auth_url, current_nonce, account_url, "", jws_req, sizeof(jws_req)) != 0) {
        return false;
    }
    if (acme_http_request(auth_url, "POST", "application/jose+json", NULL, jws_req, &resp, err_buf, err_cap) != 0) {
        return false;
    }
    if (resp.replay_nonce[0] != '\0') {
        snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
    }

    char auth_status[64] = {0};
    acme_json_find_string(resp.body, resp.body_len, "status", auth_status, sizeof(auth_status));

    if (strcmp(auth_status, "valid") != 0) {
        char chal_token[128] = {0};
        char chal_url[512] = {0};
        acme_json_find_string(resp.body, resp.body_len, "token", chal_token, sizeof(chal_token));
        acme_json_find_string(resp.body, resp.body_len, "url", chal_url, sizeof(chal_url));
        acme_http_response_cleanup(&resp);

        if (chal_token[0] == '\0' || chal_url[0] == '\0') {
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "cannot locate http-01 challenge in authorization");
            return false;
        }

        /* Calculate keyAuthorization = token + "." + thumbprint */
        char thumbprint[128];
        if (!acme_compute_jwk_thumbprint(mgr->account_key, thumbprint, sizeof(thumbprint), NULL, 0, NULL, 0)) {
            return false;
        }
        char key_authorization[256];
        snprintf(key_authorization, sizeof(key_authorization), "%s.%s", chal_token, thumbprint);

        /* Register in Apex HTTP-01 challenge router */
        apex_acme_challenge_register(chal_token, key_authorization);

        /* Notify ACME server that challenge is ready */
        if (acme_jws_sign(mgr->account_key, chal_url, current_nonce, account_url, "{}", jws_req, sizeof(jws_req)) != 0) {
            apex_acme_challenge_unregister(chal_token);
            return false;
        }

        if (acme_http_request(chal_url, "POST", "application/jose+json", NULL, jws_req, &resp, err_buf, err_cap) != 0) {
            apex_acme_challenge_unregister(chal_token);
            return false;
        }
        if (resp.replay_nonce[0] != '\0') {
            snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
        }
        acme_http_response_cleanup(&resp);

        /* Poll Authorization until "valid" */
        bool auth_valid = false;
        for (int attempt = 0; attempt < APEX_ACME_POLL_MAX_ATTEMPTS; attempt++) {
            sleep(1);
            if (acme_jws_sign(mgr->account_key, auth_url, current_nonce, account_url, "", jws_req, sizeof(jws_req)) != 0) {
                break;
            }
            if (acme_http_request(auth_url, "POST", "application/jose+json", NULL, jws_req, &resp, err_buf, err_cap) != 0) {
                break;
            }
            if (resp.replay_nonce[0] != '\0') {
                snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
            }
            acme_json_find_string(resp.body, resp.body_len, "status", auth_status, sizeof(auth_status));
            acme_http_response_cleanup(&resp);

            if (strcmp(auth_status, "valid") == 0) {
                auth_valid = true;
                break;
            } else if (strcmp(auth_status, "invalid") == 0) {
                break;
            }
        }

        apex_acme_challenge_unregister(chal_token);

        if (!auth_valid) {
            if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "ACME authorization challenge failed (status=%s)", auth_status);
            return false;
        }
    } else {
        acme_http_response_cleanup(&resp);
    }

    /* 6. Generate Domain Private Key & CSR */
    EVP_PKEY *domain_key = acme_generate_ec_key();
    if (domain_key == NULL) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "failed to generate domain EC key");
        return false;
    }

    if (mgr->config.key_path[0] != '\0') {
        acme_save_key_pem(domain_key, mgr->config.key_path);
    }

    const char *domains_arr[8];
    for (size_t i = 0; i < mgr->config.domain_count; i++) {
        domains_arr[i] = mgr->config.domains[i];
    }
    char csr_b64[4096];
    if (acme_generate_csr_b64(domain_key, domains_arr, mgr->config.domain_count, csr_b64, sizeof(csr_b64)) < 0) {
        EVP_PKEY_free(domain_key);
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "failed to generate CSR");
        return false;
    }
    EVP_PKEY_free(domain_key);

    /* 7. Finalize Order */
    char finalize_payload[4608];
    snprintf(finalize_payload, sizeof(finalize_payload), "{\"csr\":\"%s\"}", csr_b64);

    if (acme_jws_sign(mgr->account_key, finalize_url, current_nonce, account_url, finalize_payload, jws_req, sizeof(jws_req)) != 0) {
        return false;
    }

    if (acme_http_request(finalize_url, "POST", "application/jose+json", NULL, jws_req, &resp, err_buf, err_cap) != 0) {
        return false;
    }
    if (resp.replay_nonce[0] != '\0') {
        snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
    }
    acme_http_response_cleanup(&resp);

    /* 8. Poll Order for Certificate URL */
    char cert_url[512] = {0};
    for (int attempt = 0; attempt < APEX_ACME_POLL_MAX_ATTEMPTS; attempt++) {
        sleep(1);
        if (acme_jws_sign(mgr->account_key, order_url, current_nonce, account_url, "", jws_req, sizeof(jws_req)) != 0) {
            break;
        }
        if (acme_http_request(order_url, "POST", "application/jose+json", NULL, jws_req, &resp, err_buf, err_cap) != 0) {
            break;
        }
        if (resp.replay_nonce[0] != '\0') {
            snprintf(current_nonce, sizeof(current_nonce), "%s", resp.replay_nonce);
        }
        char order_status[64] = {0};
        acme_json_find_string(resp.body, resp.body_len, "status", order_status, sizeof(order_status));
        acme_json_find_string(resp.body, resp.body_len, "certificate", cert_url, sizeof(cert_url));
        acme_http_response_cleanup(&resp);

        if (strcmp(order_status, "valid") == 0 && cert_url[0] != '\0') {
            break;
        }
    }

    if (cert_url[0] == '\0') {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "order finalize did not produce certificate URL");
        return false;
    }

    /* 9. Download Certificate Chain */
    if (acme_jws_sign(mgr->account_key, cert_url, current_nonce, account_url, "", jws_req, sizeof(jws_req)) != 0) {
        return false;
    }
    if (acme_http_request(cert_url, "POST", "application/jose+json", "application/pem-certificate-chain",
                          jws_req, &resp, err_buf, err_cap) != 0) {
        return false;
    }
    if (resp.status_code != 200 || resp.body == NULL) {
        if (err_buf && err_cap > 0) snprintf(err_buf, err_cap, "failed to download certificate: HTTP %d", resp.status_code);
        acme_http_response_cleanup(&resp);
        return false;
    }

    /* Save certificate chain to disk */
    if (mgr->config.cert_path[0] != '\0') {
        FILE *f = fopen(mgr->config.cert_path, "w");
        if (f != NULL) {
            fwrite(resp.body, 1, resp.body_len, f);
            fclose(f);
        }
    }
    acme_http_response_cleanup(&resp);

    /* 10. Hot reload active TLS context */
    if (mgr->config.cert_path[0] != '\0' && mgr->config.key_path[0] != '\0') {
        return apex_acme_hot_reload_tls(mgr->runtime, mgr->config.cert_path, mgr->config.key_path, err_buf, err_cap);
    }

    return true;
}

/* Background renewal worker loop */
static void *acme_worker_thread(void *arg) {
    apex_acme_manager_t *mgr = (apex_acme_manager_t *)arg;

    /* Give server initial time to bind listeners and initialize TLS context */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 2;

    pthread_mutex_lock(&mgr->mutex);
    pthread_cond_timedwait(&mgr->cond, &mgr->mutex, &ts);

    while (mgr->running) {
        pthread_mutex_unlock(&mgr->mutex);

        if (acme_check_certificate_needs_renewal(mgr->config.cert_path, 30)) {
            char err[256] = {0};
            if (!apex_acme_obtain_certificate(mgr, err, sizeof(err))) {
                fprintf(stderr, "apex: acme renewal failed: %s\n", err[0] ? err : "unknown error");
            } else {
                fprintf(stderr, "apex: acme renewal succeeded for %zu domain(s)\n", mgr->config.domain_count);
            }
        }

        /* Sleep 12 hours between checks, waking immediately if shutdown requested */
        pthread_mutex_lock(&mgr->mutex);
        if (!mgr->running) break;

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += (12 * 3600);
        pthread_cond_timedwait(&mgr->cond, &mgr->mutex, &ts);
    }
    pthread_mutex_unlock(&mgr->mutex);

    return NULL;
}
