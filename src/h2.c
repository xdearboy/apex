/* HTTP/2 session layer: nghttp2 server sessions bridged onto the existing
 * synchronous h1 request pipeline.
 *
 * Each stream is translated to an h1.1 request (:method/:path/:authority to
 * the request line, connection-scoped headers rejected per RFC 9113 §8.2,
 * X-Forwarded-Proto added), dispatched through the unchanged
 * apex_dispatch_runtime, and the fully materialized h1 response is parsed
 * back into structured form and submitted as HEADERS + DATA frames.
 * nghttp2 owns HPACK, framing, and flow control; this file owns the bridge.
 *
 * Virtual conns: dispatch never touches the socket, only buffers, so a
 * heap conn_t with fd == 0 and no transport is a valid response sink. */
#include "internal.h"

#include <nghttp2/nghttp2.h>
#include <strings.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define H2_MAX_STREAMS 128u
#define H2_MAX_HEADERS 64u
#define H2_METHOD_MAX 16u
#define H2_MAX_BODY_BYTES (8u * 1024u * 1024u)
#define H2_MAX_REQUEST_HEADER_BYTES (32u * 1024u)
#define H2_MAX_RESPONSE_BYTES (16u * 1024u * 1024u)
#define H2_WINDOW_INCREMENT (256u * 1024u)

typedef struct {
    char *name;
    size_t name_length;
    char *value;
    size_t value_length;
} h2_header_t;

typedef struct h2_stream {
    int32_t stream_id;
    struct h2_stream *next;

    char method[H2_METHOD_MAX];
    size_t method_length;
    char *path;
    size_t path_length;
    size_t path_capacity;
    char *authority;
    size_t authority_length;
    size_t authority_capacity;

    h2_header_t *headers;
    size_t header_count;
    size_t header_capacity;
    size_t header_bytes;

    char *body;
    size_t body_length;
    size_t body_capacity;

    uint8_t request_dispatched;
    uint8_t pseudo_seen;
    conn_t *virtual_conn;

    /* Response bridge state, filled after dispatch. */
    const char *response_body;
    size_t response_body_length;
    size_t response_offset;
    /* Non-NULL when the response had to be concatenated from the virtual
     * conn's two buffers; freed with the stream. */
    char *response_owned;
} h2_stream_t;

typedef struct h2_conn {
    nghttp2_session *session;
    conn_t *owner;
    worker_arg_t *worker;
    h2_stream_t *streams;
} h2_conn_t;

static void h2_log(const char *message, int error_code) {
    if (error_code != 0) {
        fprintf(stderr, "apex: h2 %s: %s\n", message, nghttp2_strerror(error_code));
    } else {
        fprintf(stderr, "apex: h2 %s\n", message);
    }
}

/* Buffer helpers ---------------------------------------------------------- */

static bool h2_grow(char **buffer, size_t *capacity, size_t needed) {
    if (needed <= *capacity) {
        return true;
    }
    size_t grown = *capacity == 0 ? 64u : *capacity;
    while (grown < needed) {
        if (grown > SIZE_MAX / 2u) {
            return false;
        }
        grown *= 2u;
    }
    char *resized = realloc(*buffer, grown);
    if (resized == NULL) {
        return false;
    }
    *buffer = resized;
    *capacity = grown;
    return true;
}

static bool h2_append(char **buffer, size_t *length, size_t *capacity, const char *data, size_t data_length) {
    if (data_length > SIZE_MAX - *length || !h2_grow(buffer, capacity, *length + data_length)) {
        return false;
    }
    memcpy(*buffer + *length, data, data_length);
    *length += data_length;
    return true;
}

static bool h2_header_add(h2_stream_t *stream, const char *name, size_t name_length, const char *value,
                          size_t value_length) {
    if (stream->header_count == H2_MAX_HEADERS ||
        stream->header_bytes + name_length + value_length > H2_MAX_REQUEST_HEADER_BYTES) {
        return false;
    }
    if (stream->header_count == stream->header_capacity) {
        size_t grown = stream->header_capacity == 0 ? 8u : stream->header_capacity * 2u;
        h2_header_t *resized = realloc(stream->headers, grown * sizeof(*resized));
        if (resized == NULL) {
            return false;
        }
        stream->headers = resized;
        stream->header_capacity = grown;
    }
    char *name_copy = malloc(name_length + 1u);
    char *value_copy = malloc(value_length + 1u);
    if (name_copy == NULL || value_copy == NULL) {
        free(name_copy);
        free(value_copy);
        return false;
    }
    memcpy(name_copy, name, name_length);
    name_copy[name_length] = '\0';
    memcpy(value_copy, value, value_length);
    value_copy[value_length] = '\0';
    h2_header_t *header = &stream->headers[stream->header_count++];
    header->name = name_copy;
    header->name_length = name_length;
    header->value = value_copy;
    header->value_length = value_length;
    stream->header_bytes += name_length + value_length;
    return true;
}

static void h2_stream_free(h2_stream_t *stream) {
    if (stream == NULL) {
        return;
    }
    for (size_t index = 0; index < stream->header_count; index++) {
        free(stream->headers[index].name);
        free(stream->headers[index].value);
    }
    free(stream->headers);
    free(stream->path);
    free(stream->authority);
    free(stream->body);
    free(stream->response_owned);
    if (stream->virtual_conn != NULL) {
        free(stream->virtual_conn->aux_buffer);
        free(stream->virtual_conn);
        stream->virtual_conn = NULL;
    }
    free(stream);
}

static h2_stream_t *h2_find_stream(h2_conn_t *h2, int32_t stream_id) {
    for (h2_stream_t *stream = h2->streams; stream != NULL; stream = stream->next) {
        if (stream->stream_id == stream_id) {
            return stream;
        }
    }
    return NULL;
}

/* Removes the stream from the session list and returns it (NULL if absent). */
static h2_stream_t *h2_stream_take(h2_conn_t *h2, int32_t stream_id) {
    h2_stream_t **link = &h2->streams;
    while (*link != NULL && (*link)->stream_id != stream_id) {
        link = &(*link)->next;
    }
    h2_stream_t *stream = *link;
    if (stream != NULL) {
        *link = stream->next;
    }
    return stream;
}

static void h2_stream_reset(h2_conn_t *h2, int32_t stream_id, uint32_t error_code) {
    nghttp2_submit_rst_stream(h2->session, NGHTTP2_FLAG_NONE, stream_id, error_code);
}

static const h2_header_t *h2_find_host_header(const h2_stream_t *stream) {
    for (size_t index = 0; index < stream->header_count; index++) {
        const h2_header_t *header = &stream->headers[index];
        if (header->name_length == 4u && strncasecmp(header->name, "host", 4u) == 0) {
            return header;
        }
    }
    return NULL;
}

/* Forwarded headers are hop-by-hop trust boundaries: a client-supplied value
 * is never copied across the bridge, the server emits its own. */
static bool h2_header_is_forwarded(const char *name, size_t name_length) {
    return name_length == 17u && strncasecmp(name, "x-forwarded-proto", 17u) == 0;
}

/* Request-side callbacks --------------------------------------------------- */

static bool h2_method_valid(const uint8_t *method, size_t length) {
    if (length == 0 || length >= H2_METHOD_MAX) {
        return false;
    }
    for (size_t index = 0; index < length; index++) {
        uint8_t character = method[index];
        bool token = (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') ||
                     character == '!' || character == '#' || character == '$' || character == '%' ||
                     character == '&' || character == '\'' || character == '*' || character == '+' ||
                     character == '-' || character == '.' || character == '^' || character == '_' ||
                     character == '`' || character == '|' || character == '~';
        if (!token) {
            return false;
        }
    }
    return true;
}

static bool h2_header_is_connection_scoped(const char *name, size_t name_length, const char *value,
                                           size_t value_length) {
    static const char *scoped[] = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"};
    for (size_t index = 0; index < sizeof(scoped) / sizeof(scoped[0]); index++) {
        size_t scoped_length = strlen(scoped[index]);
        if (name_length == scoped_length && strncasecmp(name, scoped[index], scoped_length) == 0) {
            return true;
        }
    }
    if (name_length == 2u && strncasecmp(name, "te", 2u) == 0) {
        return !(value_length == 8u && memcmp(value, "trailers", 8u) == 0);
    }
    return false;
}

/* Creates per-stream state before the first header callback of a HEADERS
 * block; trailers (a second block) and over-limit streams are refused. */
static int h2_on_begin_headers(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    (void)session;
    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }
    h2_conn_t *h2 = user_data;
    if (h2->owner != NULL && h2->owner->close_after_write) {
        h2_stream_reset(h2, frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
        return 0;
    }
    h2_stream_t *existing = h2_find_stream(h2, frame->hd.stream_id);
    if (existing != NULL) {
        h2_stream_reset(h2, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    }
    int active = 0;
    for (h2_stream_t *stream = h2->streams; stream != NULL; stream = stream->next) {
        active++;
    }
    if ((uint32_t)active >= H2_MAX_STREAMS) {
        h2_stream_reset(h2, frame->hd.stream_id, NGHTTP2_REFUSED_STREAM);
        return 0;
    }
    h2_stream_t *stream = calloc(1, sizeof(*stream));
    if (stream == NULL) {
        h2_stream_reset(h2, frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
        return 0;
    }
    stream->stream_id = frame->hd.stream_id;
    stream->next = h2->streams;
    h2->streams = stream;
    return 0;
}

static int h2_on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                        size_t name_length, const uint8_t *value, size_t value_length, uint8_t flags, void *user_data) {
    (void)session;
    (void)flags;
    h2_conn_t *h2 = user_data;
    h2_stream_t *stream = h2_find_stream(h2, frame->hd.stream_id);
    if (stream == NULL || stream->request_dispatched) {
        /* Trailer blocks and headers for unknown streams: protocol violation. */
        h2_stream_reset(h2, frame->hd.stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    }
    if (name_length == 0) {
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    }
    if (name[0] == ':') {
        uint8_t pseudo_bit = 0;
        if (name_length == 7u && memcmp(name, ":method", 7u) == 0) {
            pseudo_bit = 1u;
        } else if (name_length == 5u && memcmp(name, ":path", 5u) == 0) {
            pseudo_bit = 2u;
        } else if (name_length == 10u && memcmp(name, ":authority", 10u) == 0) {
            pseudo_bit = 4u;
        } else if (name_length == 7u && memcmp(name, ":scheme", 7u) == 0) {
            pseudo_bit = 8u;
        } else {
            h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
            return 0;
        }
        if ((stream->pseudo_seen & pseudo_bit) != 0) {
            /* Duplicate pseudo-header: malformed per RFC 9113 §8.3. */
            h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
            return 0;
        }
        stream->pseudo_seen |= pseudo_bit;
        switch (pseudo_bit) {
        case 1u: /* :method */
            if (!h2_method_valid(value, value_length)) {
                h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
                return 0;
            }
            memcpy(stream->method, value, value_length);
            stream->method_length = value_length;
            break;
        case 2u: /* :path */
            if (value_length == 0 || (value[0] != '/' && !(value_length == 1u && value[0] == '*')) ||
                value_length > 8u * 1024u) {
                h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
                return 0;
            }
            if (!h2_append(&stream->path, &stream->path_length, &stream->path_capacity, (const char *)value,
                           value_length)) {
                h2_stream_reset(h2, stream->stream_id, NGHTTP2_INTERNAL_ERROR);
            }
            break;
        case 4u: /* :authority */
            if (value_length == 0 || value_length > 255u) {
                h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
                return 0;
            }
            if (!h2_append(&stream->authority, &stream->authority_length, &stream->authority_capacity,
                           (const char *)value, value_length)) {
                h2_stream_reset(h2, stream->stream_id, NGHTTP2_INTERNAL_ERROR);
            }
            break;
        case 8u: /* :scheme */
            if ((value_length != 5u || memcmp(value, "https", 5u) != 0) &&
                (value_length != 4u || memcmp(value, "http", 4u) != 0)) {
                h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
                return 0;
            }
            break;
        default:
            h2_stream_reset(h2, stream->stream_id, NGHTTP2_INTERNAL_ERROR);
            break;
        }
        return 0;
    }

    if (h2_header_is_connection_scoped((const char *)name, name_length, (const char *)value, value_length)) {
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
        return 0;
    }
    if (!h2_header_add(stream, (const char *)name, name_length, (const char *)value, value_length)) {
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
    }
    return 0;
}

static int h2_on_data_chunk(nghttp2_session *session, uint8_t frame_type, int32_t stream_id, const uint8_t *data,
                            size_t length, void *user_data) {
    (void)session;
    (void)frame_type;
    h2_conn_t *h2 = user_data;
    h2_stream_t *stream = h2_find_stream(h2, stream_id);
    if (stream == NULL || stream->request_dispatched) {
        return 0;
    }
    if (stream->body_length > H2_MAX_BODY_BYTES || length > H2_MAX_BODY_BYTES - stream->body_length) {
        h2_stream_reset(h2, stream_id, NGHTTP2_REFUSED_STREAM);
        return 0;
    }
    if (!h2_append(&stream->body, &stream->body_length, &stream->body_capacity, (const char *)data, length)) {
        h2_stream_reset(h2, stream_id, NGHTTP2_INTERNAL_ERROR);
    }
    /* Release flow-control credit immediately: dispatch waits for END_STREAM,
     * so bodies larger than the initial window would deadlock without this. */
    nghttp2_submit_window_update(h2->session, NGHTTP2_FLAG_NONE, stream_id, (int32_t)length);
    nghttp2_submit_window_update(h2->session, NGHTTP2_FLAG_NONE, 0, (int32_t)length);
    return 0;
}

/* Response bridge -----------------------------------------------------------*/

/* Headers that must not cross the h1 bridge in either direction:
 * connection-scoped framing, plus Content-Length (nghttp2 owns framing and
 * emits its own length implicitly via DATA frame accounting). */
static bool h2_drop_h1_header(const char *name, size_t name_length) {
    static const char *dropped[] = {"connection",  "keep-alive", "proxy-connection",
                                    "transfer-encoding", "upgrade",    "content-length"};
    for (size_t index = 0; index < sizeof(dropped) / sizeof(dropped[0]); index++) {
        size_t dropped_length = strlen(dropped[index]);
        if (name_length == dropped_length && strncasecmp(name, dropped[index], dropped_length) == 0) {
            return true;
        }
    }
    return false;
}

static ssize_t h2_data_read(nghttp2_session *session, int32_t stream_id, uint8_t *destination, size_t max_length,
                            uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    (void)session;
    (void)stream_id;
    (void)user_data;
    h2_stream_t *stream = source->ptr;
    size_t remaining = stream->response_body_length - stream->response_offset;
    if (remaining == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    size_t chunk = remaining < max_length ? remaining : max_length;
    memcpy(destination, stream->response_body + stream->response_offset, chunk);
    stream->response_offset += chunk;
    if (stream->response_offset == stream->response_body_length) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (ssize_t)chunk;
}

static void h2_submit_frames(h2_conn_t *h2, h2_stream_t *stream, const nghttp2_nv *nva, size_t nva_count) {
    nghttp2_data_provider provider = {.source.ptr = stream, .read_callback = h2_data_read};
    int result = nghttp2_submit_response(h2->session, stream->stream_id, nva, nva_count, &provider);
    if (result != 0) {
        h2_log("submit response", result);
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_INTERNAL_ERROR);
        return;
    }
}

/* Resolves the materialized h1 response into one contiguous byte range.
 * apex_conn_write keeps small chunks in write_buffer and spills oversized
 * chunks into aux_buffer, and the h1 path sends them back to back, so a
 * split response is concatenated here; otherwise we point into the single
 * non-empty buffer with zero copies. Returns false on allocation failure. */
static bool h2_response_blob(conn_t *virtual_conn, char **blob, size_t *blob_length, char **owned) {
    char *first = virtual_conn->write_buffer;
    size_t first_length = virtual_conn->write_length;
    char *second = virtual_conn->aux_buffer;
    size_t second_length = virtual_conn->aux_length;

    if (first_length > 0 && second_length > 0) {
        if (first_length > SIZE_MAX - second_length) {
            return false;
        }
        char *joined = malloc(first_length + second_length);
        if (joined == NULL) {
            return false;
        }
        memcpy(joined, first, first_length);
        memcpy(joined + first_length, second, second_length);
        *owned = joined;
        *blob = joined;
        *blob_length = first_length + second_length;
        return true;
    }
    if (second_length > 0) {
        *blob = second;
        *blob_length = second_length;
    } else {
        *blob = first;
        *blob_length = first_length;
    }
    *owned = NULL;
    return true;
}

/* Parses the h1.1 response the pipeline materialized in the virtual conn and
 * submits it as h2 HEADERS + DATA. Malformed responses become stream 500s. */
static void h2_translate_response(h2_conn_t *h2, h2_stream_t *stream) {
    conn_t *virtual_conn = stream->virtual_conn;
    char *blob = NULL;
    char *owned = NULL;
    size_t blob_length = 0;
    if (!h2_response_blob(virtual_conn, &blob, &blob_length, &owned)) {
        owned = NULL;
        goto malformed;
    }

    bool valid_proto =
        (blob_length >= 14u && (memcmp(blob, "HTTP/1.1 ", 9u) == 0 || memcmp(blob, "HTTP/1.0 ", 9u) == 0));
    if (blob_length > H2_MAX_RESPONSE_BYTES || !valid_proto ||
        blob[9] < '1' || blob[9] > '5' || blob[10] < '0' || blob[10] > '9' || blob[11] < '0' || blob[11] > '9') {
        goto malformed;
    }

    const char *line_end = memchr(blob, '\r', blob_length);
    if (line_end == NULL || (size_t)(line_end - blob) + 1u >= blob_length || (size_t)(line_end - blob) < 12u ||
        line_end[1] != '\n') {
        goto malformed;
    }

    const char *headers = line_end + 2u;
    const char *body = NULL;
    for (const char *cursor = headers; (size_t)(cursor - blob) + 4u <= blob_length; cursor++) {
        if (cursor[0] == '\r' && cursor[1] == '\n' && cursor[2] == '\r' && cursor[3] == '\n') {
            body = cursor + 4u;
            break;
        }
    }
    if (body == NULL) {
        goto malformed;
    }

    nghttp2_nv nva[H2_MAX_HEADERS + 1u];
    size_t nva_count = 0;
    nva[nva_count++] = (nghttp2_nv){.name = (uint8_t *)":status", .value = (uint8_t *)(blob + 9u),
                                    .namelen = 7u, .valuelen = 3u, .flags = NGHTTP2_NV_FLAG_NONE};

    for (const char *cursor = headers; cursor + 1u < body - 2u && nva_count < H2_MAX_HEADERS + 1u;) {
        const char *line_end_inner = memchr(cursor, '\r', (size_t)(body - 2u - cursor));
        if (line_end_inner == NULL || line_end_inner[1] != '\n') {
            break;
        }
        if (line_end_inner == cursor) {
            break;
        }
        const char *colon = memchr(cursor, ':', (size_t)(line_end_inner - cursor));
        if (colon == NULL) {
            goto malformed;
        }
        size_t name_length = (size_t)(colon - cursor);
        const char *value = colon + 1u;
        size_t value_length = (size_t)(line_end_inner - colon - 1u);
        while (value_length > 0 && (*value == ' ' || *value == '\t')) {
            value++;
            value_length--;
        }
        if (!h2_drop_h1_header(cursor, name_length)) {
            for (size_t i = 0; i < name_length; i++) {
                ((char *)cursor)[i] = (char)tolower((unsigned char)cursor[i]);
            }
            nva[nva_count++] = (nghttp2_nv){.name = (uint8_t *)cursor, .value = (uint8_t *)value,
                                            .namelen = name_length, .valuelen = value_length,
                                            .flags = NGHTTP2_NV_FLAG_NONE};
        }
        cursor = line_end_inner + 2u;
    }

    stream->response_body = body;
    stream->response_owned = owned;
    stream->response_body_length = blob_length - (size_t)(body - blob);
    stream->response_offset = 0;
    h2_submit_frames(h2, stream, nva, nva_count);
    return;

malformed:
    {
        free(owned);
        stream->response_owned = NULL;
        static const char body_text[] = "upstream produced an invalid response\n";
        static const char type_text[] = "text/plain";
        char length_text[32];
        int length_written = snprintf(length_text, sizeof(length_text), "%zu", sizeof(body_text) - 1u);
        nghttp2_nv fallback[] = {
            {.name = (uint8_t *)":status", .value = (uint8_t *)"500", .namelen = 7u, .valuelen = 3u,
             .flags = NGHTTP2_NV_FLAG_NONE},
            {.name = (uint8_t *)"content-type", .value = (uint8_t *)type_text, .namelen = 12u,
             .valuelen = sizeof(type_text) - 1u, .flags = NGHTTP2_NV_FLAG_NONE},
            {.name = (uint8_t *)"content-length", .value = (uint8_t *)length_text, .namelen = 14u,
             .valuelen = length_written > 0 ? (size_t)length_written : 0u, .flags = NGHTTP2_NV_FLAG_NONE},
        };
        stream->response_body = body_text;
        stream->response_body_length = sizeof(body_text) - 1u;
        stream->response_offset = 0;
        h2_submit_frames(h2, stream, fallback, 3u);
    }
}

static void h2_dispatch_stream(h2_conn_t *h2, h2_stream_t *stream) {
    stream->request_dispatched = 1;

    if (stream->method_length == 0 || stream->path_length == 0 ||
        (stream->authority_length == 0 && h2_find_host_header(stream) == NULL)) {
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_PROTOCOL_ERROR);
        return;
    }

    size_t capacity = stream->method_length + stream->path_length + stream->authority_length + 256u;
    for (size_t index = 0; index < stream->header_count; index++) {
        h2_header_t *header = &stream->headers[index];
        if (h2_drop_h1_header(header->name, header->name_length) ||
            h2_header_is_forwarded(header->name, header->name_length) ||
            (stream->authority_length > 0 && header->name_length == 4u &&
             strncasecmp(header->name, "host", 4u) == 0)) {
            continue;
        }
        capacity += header->name_length + header->value_length + 4u;
    }
    char *request = malloc(capacity);
    if (request == NULL) {
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_INTERNAL_ERROR);
        return;
    }

    size_t offset = 0;
    memcpy(request + offset, stream->method, stream->method_length);
    offset += stream->method_length;
    request[offset++] = ' ';
    memcpy(request + offset, stream->path, stream->path_length);
    offset += stream->path_length;
    memcpy(request + offset, " HTTP/1.1\r\n", 11u);
    offset += 11u;
    if (stream->authority_length > 0) {
        memcpy(request + offset, "Host: ", 6u);
        offset += 6u;
        memcpy(request + offset, stream->authority, stream->authority_length);
        offset += stream->authority_length;
        memcpy(request + offset, "\r\n", 2u);
        offset += 2u;
    }
    for (size_t index = 0; index < stream->header_count; index++) {
        h2_header_t *header = &stream->headers[index];
        if (h2_drop_h1_header(header->name, header->name_length) ||
            h2_header_is_forwarded(header->name, header->name_length) ||
            (stream->authority_length > 0 && header->name_length == 4u &&
             strncasecmp(header->name, "host", 4u) == 0)) {
            continue;
        }
        memcpy(request + offset, header->name, header->name_length);
        offset += header->name_length;
        memcpy(request + offset, ": ", 2u);
        offset += 2u;
        memcpy(request + offset, header->value, header->value_length);
        offset += header->value_length;
        memcpy(request + offset, "\r\n", 2u);
        offset += 2u;
    }
    if (h2->owner != NULL && h2->owner->transport == APEX_TRANSPORT_TLS) {
        memcpy(request + offset, "X-Forwarded-Proto: https\r\n", 26u);
        offset += 26u;
    } else {
        memcpy(request + offset, "X-Forwarded-Proto: http\r\n", 25u);
        offset += 25u;
    }
    int content_length_written =
        snprintf(request + offset, capacity - offset, "Content-Length: %zu\r\n\r\n", stream->body_length);
    if (content_length_written < 0 || offset + (size_t)content_length_written > capacity) {
        free(request);
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_INTERNAL_ERROR);
        return;
    }
    size_t header_length = offset + (size_t)content_length_written;

    stream->virtual_conn = calloc(1, sizeof(*stream->virtual_conn));
    if (stream->virtual_conn == NULL) {
        free(request);
        h2_stream_reset(h2, stream->stream_id, NGHTTP2_INTERNAL_ERROR);
        return;
    }

    apex_res_t response = {.conn = stream->virtual_conn};
    const apex_runtime_t *runtime = h2->worker->generation != NULL ? h2->worker->generation->runtime : NULL;
    apex_dispatch_runtime(h2->worker->app, runtime, request, header_length, stream->body, stream->body_length,
                          &response);
    free(request);

    h2_translate_response(h2, stream);
}

static int h2_on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    (void)session;
    h2_conn_t *h2 = user_data;
    if (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) {
        return 0;
    }
    h2_stream_t *stream = h2_find_stream(h2, frame->hd.stream_id);
    if (stream == NULL || stream->request_dispatched) {
        return 0;
    }
    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
        h2_dispatch_stream(h2, stream);
    }
    return 0;
}

static int h2_on_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    (void)session;
    (void)error_code;
    h2_conn_t *h2 = user_data;
    h2_stream_t *stream = h2_stream_take(h2, stream_id);
    h2_stream_free(stream);
    if (h2->owner != NULL && h2->owner->close_after_write && h2->streams == NULL &&
        !nghttp2_session_want_write(h2->session)) {
        apex_close_connection(h2->worker, h2->owner);
    }
    return 0;
}

static ssize_t h2_send(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    (void)session;
    (void)flags;
    h2_conn_t *h2 = user_data;
    int written = apex_transport_write(h2->owner, data, length);
    if (written > 0) {
        return written;
    }
    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    return NGHTTP2_ERR_CALLBACK_FAILURE;
}

/* Session lifecycle ----------------------------------------------------------*/

int h2_connection_create(conn_t *connection, worker_arg_t *worker) {
    h2_conn_t *h2 = calloc(1, sizeof(*h2));
    if (h2 == NULL) {
        return -1;
    }
    h2->owner = connection;
    h2->worker = worker;

    nghttp2_session_callbacks *callbacks = NULL;
    if (nghttp2_session_callbacks_new(&callbacks) != 0) {
        free(h2);
        return -1;
    }
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame_recv);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, h2_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, h2_on_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, h2_on_stream_close);
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send);

    int result = nghttp2_session_server_new(&h2->session, callbacks, h2);
    nghttp2_session_callbacks_del(callbacks);
    if (result != 0) {
        free(h2);
        return -1;
    }

    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, H2_MAX_STREAMS},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, H2_WINDOW_INCREMENT},
    };
    if (nghttp2_submit_settings(h2->session, NGHTTP2_FLAG_NONE, settings, 2u) != 0 ||
        nghttp2_submit_window_update(h2->session, NGHTTP2_FLAG_NONE, 0, (int32_t)H2_WINDOW_INCREMENT) != 0) {
        nghttp2_session_del(h2->session);
        free(h2);
        return -1;
    }

    connection->h2 = h2;
    return 0;
}

void h2_connection_destroy(conn_t *connection) {
    h2_conn_t *h2 = connection->h2;
    if (h2 == NULL) {
        return;
    }
    h2_stream_t *stream = h2->streams;
    while (stream != NULL) {
        h2_stream_t *next = stream->next;
        h2_stream_free(stream);
        stream = next;
    }
    h2->streams = NULL;
    if (h2->session != NULL) {
        nghttp2_session_del(h2->session);
        h2->session = NULL;
    }
    free(h2);
    connection->h2 = NULL;
}

void h2_read(worker_arg_t *worker, conn_t *connection) {
    h2_conn_t *h2 = connection->h2;
    if (h2 == NULL) {
        return;
    }
    /* Invariant: h2 connections never run the h1 parser, so read_length stays
     * 0 and apex_transport_read hands each batch straight to nghttp2. */
    for (;;) {
        ssize_t received = apex_transport_read(connection);
        if (received > 0) {
            ssize_t consumed = nghttp2_session_mem_recv(h2->session, (const uint8_t *)connection->read_buffer,
                                                        (size_t)received);
            if (consumed < 0) {
                h2_log("mem_recv", (int)consumed);
                apex_close_connection(worker, connection);
                return;
            }
            if (consumed != received) {
                /* Defensive: nghttp2 must consume whole healthy buffers. */
                apex_close_connection(worker, connection);
                return;
            }
        } else if (received == 0) {
            apex_close_connection(worker, connection);
            return;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            apex_close_connection(worker, connection);
            return;
        }
    }
    if (connection->fd < 0) {
        return;
    }
    if (connection->tls_want_write) {
        apex_arm_connection_output(worker, connection);
    }
    h2_flush(worker, connection);
}

void h2_flush(worker_arg_t *worker, conn_t *connection) {
    h2_conn_t *h2 = connection->h2;
    if (h2 == NULL || connection->fd < 0) {
        return;
    }
    if (nghttp2_session_want_write(h2->session)) {
        int result = nghttp2_session_send(h2->session);
        if (result < 0 && result != NGHTTP2_ERR_WOULDBLOCK) {
            h2_log("send", result);
            apex_close_connection(worker, connection);
            return;
        }
    }
    if (connection->fd < 0) {
        return;
    }
    if (nghttp2_session_want_write(h2->session)) {
        apex_arm_connection_output(worker, connection);
    } else {
        if (connection->epollout_active) {
            struct epoll_event event_config;
            event_config.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
            event_config.data.fd = connection->fd;
            if (epoll_ctl(worker->epoll_fd, EPOLL_CTL_MOD, connection->fd, &event_config) != 0) {
                perror("apex: epoll_ctl disarm h2 output");
                apex_close_connection(worker, connection);
                return;
            }
            connection->epollout_active = 0;
        }
        if (connection->close_after_write && h2->streams == NULL) {
            apex_close_connection(worker, connection);
            return;
        }
    }
}

bool h2_has_pending_output(conn_t *connection) {
    return connection->h2 != NULL && nghttp2_session_want_write(connection->h2->session);
}

void h2_drain(worker_arg_t *worker, conn_t *connection) {
    h2_conn_t *h2 = connection->h2;
    if (h2 == NULL || connection->fd < 0) {
        return;
    }
    int32_t last_stream_id = nghttp2_session_get_last_proc_stream_id(h2->session);
    nghttp2_submit_goaway(h2->session, NGHTTP2_FLAG_NONE, last_stream_id, NGHTTP2_NO_ERROR, NULL, 0);
    h2_flush(worker, connection);
}

int h2_start_prior_knowledge(worker_arg_t *worker, conn_t *connection) {
    if (h2_connection_create(connection, worker) != 0) {
        return -1;
    }
    h2_conn_t *h2 = connection->h2;
    ssize_t consumed = nghttp2_session_mem_recv(h2->session, (const uint8_t *)connection->read_buffer,
                                                connection->read_length);
    connection->read_length = 0;
    if (consumed < 0) {
        h2_log("prior knowledge mem_recv", (int)consumed);
        return -1;
    }
    h2_flush(worker, connection);
    if (connection->fd >= 0) {
        h2_read(worker, connection);
    }
    return 0;
}
