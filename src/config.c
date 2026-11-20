#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "apex/config.h"
#include "apex/module.h"
#include "apex/cache.h"
#include "apex/realip.h"
#include "apex/log.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <glob.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define APEX_RATELIMIT_SHARDS 1024u

static bool parse_size_str(const char *text, size_t *value_bytes);

typedef struct rate_entry {
    char key[128];
    uint64_t last_time_us;
    double tokens;
    int32_t active_conns;
    struct rate_entry *next;
} rate_entry_t;

typedef struct {
    pthread_mutex_t lock;
    rate_entry_t *head;
} rate_shard_t;

typedef struct {
    rate_shard_t shards[APEX_RATELIMIT_SHARDS];
} rate_limiter_t;

static inline uint64_t config_monotonic_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

#define APEX_CONFIG_DEFAULT_WORKER_CONNECTIONS 10240u
#define APEX_CONFIG_DEFAULT_KEEPALIVE_MS 75000u
#define APEX_CONFIG_DEFAULT_CLIENT_HEADER_MS 15000u
#define APEX_CONFIG_DEFAULT_CLIENT_BODY_MS 30000u
#define APEX_CONFIG_DEFAULT_UPSTREAM_KEEPALIVE 32u
#define APEX_CONFIG_DEFAULT_CONNECT_MS 2000u
#define APEX_CONFIG_DEFAULT_READ_MS 10000u
#define APEX_CONFIG_DEFAULT_IDLE_MS 60000u
#define APEX_CONFIG_MAX_WEIGHT 1000000u
#define APEX_CONFIG_MAX_KEEPALIVE 65535u
#define APEX_CONFIG_MAX_CONNS 1000000000u

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} config_buffer_t;

static bool config_oom(apex_config_error_t *error);

static void config_error_set(apex_config_error_t *error, apex_config_status_t code, const char *file, int line,
                             int column, const char *format, ...) {
    if (error == NULL) {
        return;
    }

    error->code = code;
    error->line = line;
    error->column = column;
    error->message[0] = '\0';
    error->hint[0] = '\0';
    if (file != NULL) {
        snprintf(error->file, sizeof(error->file), "%s", file);
    } else {
        error->file[0] = '\0';
    }

    va_list arguments;
    va_start(arguments, format);
    vsnprintf(error->message, sizeof(error->message), format, arguments);
    va_end(arguments);
}

static bool config_buffer_reserve(config_buffer_t *buffer, size_t extra) {
    if (extra > SIZE_MAX - buffer->length - 1u) {
        return false;
    }

    size_t needed = buffer->length + extra + 1u;
    if (needed <= buffer->capacity) {
        return true;
    }

    size_t capacity = buffer->capacity ? buffer->capacity : 64u;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2u) {
            capacity = needed;
            break;
        }
        capacity *= 2u;
    }

    char *grown = realloc(buffer->data, capacity);
    if (grown == NULL) {
        return false;
    }
    buffer->data = grown;
    buffer->capacity = capacity;
    return true;
}

static bool config_buffer_append(config_buffer_t *buffer, const void *data, size_t length) {
    if (length == 0) {
        return true;
    }
    if (!config_buffer_reserve(buffer, length)) {
        return false;
    }
    memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return true;
}

static bool config_buffer_append_char(config_buffer_t *buffer, char value) {
    return config_buffer_append(buffer, &value, 1u);
}

static bool config_buffer_append_string(config_buffer_t *buffer, const char *text) {
    return config_buffer_append(buffer, text, strlen(text));
}

static char *config_buffer_release(config_buffer_t *buffer, size_t *length) {
    if (buffer->data == NULL) {
        if (!config_buffer_reserve(buffer, 0u)) {
            return NULL;
        }
        buffer->data[0] = '\0';
    }
    if (length != NULL) {
        *length = buffer->length;
    }
    char *data = buffer->data;
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
    return data;
}

static void config_buffer_free(config_buffer_t *buffer) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->length = 0;
    buffer->capacity = 0;
}

static char *config_strdup_range(const char *text, size_t length) {
    char *copy = malloc(length + 1u);
    if (copy == NULL) {
        return NULL;
    }
    if (length > 0) {
        memcpy(copy, text, length);
    }
    copy[length] = '\0';
    return copy;
}

static bool config_oom(apex_config_error_t *error) {
    config_error_set(error, APEX_CONFIG_ERR_MEMORY, NULL, 0, 0, "out of memory");
    return false;
}

typedef enum {
    TOKEN_WORD = 0,
    TOKEN_STRING,
    TOKEN_LBRACE,
    TOKEN_RBRACE,
    TOKEN_SEMICOLON,
    TOKEN_EOF,
} token_kind_t;

typedef struct {
    token_kind_t kind;
    char *text;
    size_t length;
    int file_index;
    int line;
    int column;
} token_t;

typedef struct {
    token_t *items;
    size_t count;
    size_t capacity;
    char **files;
    size_t file_count;
    size_t file_capacity;
} token_list_t;

typedef struct {
    const char *data;
    size_t length;
    size_t position;
    int line;
    int column;
    int file_index;
    token_list_t *tokens;
    apex_config_error_t *error;
} lexer_t;

static void token_list_init(token_list_t *list) {
    memset(list, 0, sizeof(*list));
}

static void token_list_free(token_list_t *list) {
    for (size_t index = 0; index < list->count; index++) {
        free(list->items[index].text);
    }
    for (size_t index = 0; index < list->file_count; index++) {
        free(list->files[index]);
    }
    free(list->items);
    free(list->files);
    memset(list, 0, sizeof(*list));
}

static int token_list_register_file(token_list_t *list, const char *path, apex_config_error_t *error) {
    for (size_t index = 0; index < list->file_count; index++) {
        if (strcmp(list->files[index], path) == 0) {
            return (int)index;
        }
    }

    if (list->file_count >= (size_t)INT_MAX) {
        config_error_set(error, APEX_CONFIG_ERR_MEMORY, path, 0, 0, "too many source files");
        return -1;
    }

    if (list->file_count == list->file_capacity) {
        size_t capacity = list->file_capacity ? list->file_capacity * 2u : 8u;
        char **grown = realloc(list->files, capacity * sizeof(char *));
        if (grown == NULL) {
            config_oom(error);
            return -1;
        }
        list->files = grown;
        list->file_capacity = capacity;
    }

    char *copy = config_strdup_range(path, strlen(path));
    if (copy == NULL) {
        config_oom(error);
        return -1;
    }
    list->files[list->file_count] = copy;
    return (int)list->file_count++;
}

static bool token_list_push(token_list_t *list, token_t token, apex_config_error_t *error) {
    if (list->count >= APEX_CONFIG_MAX_TOKENS) {
        config_error_set(error, APEX_CONFIG_ERR_SYNTAX, list->files[token.file_index], token.line, token.column,
                         "configuration contains too many tokens");
        free(token.text);
        return false;
    }

    if (list->count == list->capacity) {
        size_t capacity = list->capacity ? list->capacity * 2u : 64u;
        token_t *grown = realloc(list->items, capacity * sizeof(token_t));
        if (grown == NULL) {
            free(token.text);
            config_oom(error);
            return false;
        }
        list->items = grown;
        list->capacity = capacity;
    }

    list->items[list->count++] = token;
    return true;
}

static const char *lexer_file(const lexer_t *lexer) {
    return lexer->tokens->files[lexer->file_index];
}

static bool lexer_error(lexer_t *lexer, int line, int column, const char *format, ...) {
    if (lexer->error != NULL) {
        lexer->error->code = APEX_CONFIG_ERR_SYNTAX;
        lexer->error->line = line;
        lexer->error->column = column;
        lexer->error->message[0] = '\0';
        lexer->error->hint[0] = '\0';
        snprintf(lexer->error->file, sizeof(lexer->error->file), "%s", lexer_file(lexer));

        va_list arguments;
        va_start(arguments, format);
        vsnprintf(lexer->error->message, sizeof(lexer->error->message), format, arguments);
        va_end(arguments);
    }
    return false;
}

static int hex_value(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static bool is_identifier_name(const char *text, size_t length) {
    if (length == 0) {
        return false;
    }
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)text[index];
        if (!(isalnum(byte) || byte == '_' || byte == '-' || byte == '.')) {
            return false;
        }
    }
    return true;
}

static bool is_environment_name(const char *text, size_t length) {
    if (length == 0) {
        return false;
    }
    unsigned char first = (unsigned char)text[0];
    if (!(isalpha(first) || first == '_')) {
        return false;
    }
    for (size_t index = 1; index < length; index++) {
        unsigned char byte = (unsigned char)text[index];
        if (!(isalnum(byte) || byte == '_')) {
            return false;
        }
    }
    return true;
}

static char *expand_environment(lexer_t *lexer, int line, int column, const char *text, size_t length,
                                size_t *expanded_length) {
    config_buffer_t output = {0};
    size_t index = 0;

    while (index < length) {
        if (text[index] == '$' && index + 1u < length && text[index + 1u] == '{') {
            size_t close = index + 2u;
            while (close < length && text[close] != '}') {
                close++;
            }
            if (close == length) {
                lexer_error(lexer, line, column, "unterminated environment expansion");
                config_buffer_free(&output);
                return NULL;
            }

            size_t content_start = index + 2u;
            size_t content_length = close - content_start;
            size_t name_length = content_length;
            const char *default_value = NULL;
            size_t default_length = 0;

            for (size_t cursor = content_start; cursor + 1u < close; cursor++) {
                if (text[cursor] == ':' && text[cursor + 1u] == '-') {
                    name_length = cursor - content_start;
                    default_value = text + cursor + 2u;
                    default_length = close - (cursor + 2u);
                    break;
                }
            }

            if (!is_environment_name(text + content_start, name_length)) {
                lexer_error(lexer, line, column, "invalid environment variable name in expansion");
                config_buffer_free(&output);
                return NULL;
            }

            char name[128];
            if (name_length >= sizeof(name)) {
                lexer_error(lexer, line, column, "environment variable name is too long");
                config_buffer_free(&output);
                return NULL;
            }
            memcpy(name, text + content_start, name_length);
            name[name_length] = '\0';

            const char *value = getenv(name);
            if (value != NULL) {
                if (strchr(value, '\n') != NULL || strchr(value, '\r') != NULL) {
                    lexer_error(lexer, line, column, "environment variable '%s' contains a line break", name);
                    config_buffer_free(&output);
                    return NULL;
                }
                if (!config_buffer_append_string(&output, value)) {
                    config_oom(lexer->error);
                    config_buffer_free(&output);
                    return NULL;
                }
            } else if (default_value != NULL) {
                if (!config_buffer_append(&output, default_value, default_length)) {
                    config_oom(lexer->error);
                    config_buffer_free(&output);
                    return NULL;
                }
            } else {
                lexer_error(lexer, line, column, "environment variable '%s' is not set", name);
                config_buffer_free(&output);
                return NULL;
            }

            index = close + 1u;
            continue;
        }

        if (!config_buffer_append_char(&output, text[index])) {
            config_oom(lexer->error);
            config_buffer_free(&output);
            return NULL;
        }
        index++;
    }

    char *result = config_buffer_release(&output, expanded_length);
    if (result == NULL) {
        config_oom(lexer->error);
        config_buffer_free(&output);
    }
    return result;
}

static bool lexer_emit(lexer_t *lexer, token_kind_t kind, char *text, size_t length, int line, int column) {
    if (text != NULL) {
        size_t expanded_length = length;
        char *expanded = expand_environment(lexer, line, column, text, length, &expanded_length);
        if (expanded == NULL) {
            free(text);
            return false;
        }
        free(text);
        text = expanded;
        length = expanded_length;
    }

    token_t token = {
        .kind = kind,
        .text = text,
        .length = length,
        .file_index = lexer->file_index,
        .line = line,
        .column = column,
    };
    return token_list_push(lexer->tokens, token, lexer->error);
}

static bool lexer_read_string(lexer_t *lexer) {
    char quote = lexer->data[lexer->position];
    int line = lexer->line;
    int column = lexer->column;
    lexer->position++;
    lexer->column++;

    config_buffer_t value = {0};
    bool closed = false;

    while (lexer->position < lexer->length) {
        char byte = lexer->data[lexer->position];
        if (byte == '\n' || byte == '\r') {
            break;
        }
        if (byte == quote) {
            lexer->position++;
            lexer->column++;
            closed = true;
            break;
        }

        if (quote == '"' && byte == '\\') {
            lexer->position++;
            lexer->column++;
            if (lexer->position >= lexer->length) {
                break;
            }
            char escaped = lexer->data[lexer->position];
            lexer->position++;
            lexer->column++;

            char decoded;
            switch (escaped) {
            case '"':
            case '\\':
                decoded = escaped;
                break;
            case 'n':
                decoded = '\n';
                break;
            case 'r':
                decoded = '\r';
                break;
            case 't':
                decoded = '\t';
                break;
            case 'x': {
                if (lexer->position + 1u >= lexer->length) {
                    config_buffer_free(&value);
                    return lexer_error(lexer, line, column, "truncated hexadecimal escape");
                }
                int high = hex_value(lexer->data[lexer->position]);
                int low = hex_value(lexer->data[lexer->position + 1u]);
                if (high < 0 || low < 0) {
                    config_buffer_free(&value);
                    return lexer_error(lexer, line, column, "invalid hexadecimal escape");
                }
                decoded = (char)((high << 4) | low);
                lexer->position += 2u;
                lexer->column += 2;
                break;
            }
            default:
                config_buffer_free(&value);
                return lexer_error(lexer, line, column, "invalid escape sequence '\\%c'", escaped);
            }

            if (!config_buffer_append_char(&value, decoded)) {
                config_buffer_free(&value);
                config_oom(lexer->error);
                return false;
            }
            continue;
        }

        if (!config_buffer_append_char(&value, byte)) {
            config_buffer_free(&value);
            config_oom(lexer->error);
            return false;
        }
        lexer->position++;
        lexer->column++;
    }

    if (!closed) {
        config_buffer_free(&value);
        return lexer_error(lexer, line, column, "unterminated string literal");
    }

    size_t length = 0;
    char *text = config_buffer_release(&value, &length);
    if (text == NULL) {
        config_oom(lexer->error);
        config_buffer_free(&value);
        return false;
    }
    return lexer_emit(lexer, TOKEN_STRING, text, length, line, column);
}

static bool lexer_read_word(lexer_t *lexer) {
    int line = lexer->line;
    int column = lexer->column;
    config_buffer_t value = {0};

    while (lexer->position < lexer->length) {
        char byte = lexer->data[lexer->position];
        if (byte == '$' && lexer->position + 1u < lexer->length &&
            lexer->data[lexer->position + 1u] == '{') {
            if (!config_buffer_append_char(&value, '$') ||
                !config_buffer_append_char(&value, '{')) {
                config_buffer_free(&value);
                config_oom(lexer->error);
                return false;
            }
            lexer->position += 2u;
            lexer->column += 2;

            bool closed = false;
            while (lexer->position < lexer->length) {
                char inner = lexer->data[lexer->position];
                if (inner == '\n' || inner == '\r') {
                    break;
                }
                if (!config_buffer_append_char(&value, inner)) {
                    config_buffer_free(&value);
                    config_oom(lexer->error);
                    return false;
                }
                lexer->position++;
                lexer->column++;
                if (inner == '}') {
                    closed = true;
                    break;
                }
            }
            if (!closed) {
                config_buffer_free(&value);
                return lexer_error(lexer, line, column, "unterminated environment expansion");
            }
            continue;
        }
        if (isspace((unsigned char)byte) || byte == '{' || byte == '}' || byte == ';' || byte == '#' ||
            byte == '"' || byte == '\'') {
            break;
        }
        if (!config_buffer_append_char(&value, byte)) {
            config_buffer_free(&value);
            config_oom(lexer->error);
            return false;
        }
        lexer->position++;
        lexer->column++;
    }

    size_t length = 0;
    char *text = config_buffer_release(&value, &length);
    if (text == NULL) {
        config_oom(lexer->error);
        config_buffer_free(&value);
        return false;
    }
    return lexer_emit(lexer, TOKEN_WORD, text, length, line, column);
}

static bool lexer_run(lexer_t *lexer) {
    while (lexer->position < lexer->length) {
        char byte = lexer->data[lexer->position];

        if (byte == '\n') {
            lexer->line++;
            lexer->column = 1;
            lexer->position++;
            continue;
        }
        if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\f' || byte == '\v') {
            lexer->column++;
            lexer->position++;
            continue;
        }
        if (byte == '#') {
            while (lexer->position < lexer->length && lexer->data[lexer->position] != '\n') {
                lexer->position++;
                lexer->column++;
            }
            continue;
        }
        if (byte == '{' || byte == '}' || byte == ';') {
            int line = lexer->line;
            int column = lexer->column;
            lexer->position++;
            lexer->column++;
            token_kind_t kind = byte == '{' ? TOKEN_LBRACE : (byte == '}' ? TOKEN_RBRACE : TOKEN_SEMICOLON);
            if (!lexer_emit(lexer, kind, NULL, 0, line, column)) {
                return false;
            }
            continue;
        }
        if (byte == '"' || byte == '\'') {
            if (!lexer_read_string(lexer)) {
                return false;
            }
            continue;
        }
        if (!lexer_read_word(lexer)) {
            return false;
        }
    }
    return true;
}

static bool read_file(const char *path, char **data, size_t *length, apex_config_error_t *error) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "cannot open configuration file");
        return false;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "cannot seek configuration file");
        return false;
    }
    long size = ftell(file);
    if (size < 0) {
        fclose(file);
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "cannot determine configuration file size");
        return false;
    }
    if ((unsigned long)size > APEX_CONFIG_MAX_FILE_BYTES) {
        fclose(file);
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "configuration file exceeds %u bytes",
                         (unsigned)APEX_CONFIG_MAX_FILE_BYTES);
        return false;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "cannot rewind configuration file");
        return false;
    }

    char *buffer = malloc((size_t)size + 1u);
    if (buffer == NULL) {
        fclose(file);
        config_oom(error);
        return false;
    }

    size_t read_length = fread(buffer, 1, (size_t)size, file);
    if (read_length != (size_t)size && ferror(file)) {
        free(buffer);
        fclose(file);
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "cannot read configuration file");
        return false;
    }
    fclose(file);

    buffer[read_length] = '\0';
    *data = buffer;
    *length = read_length;
    return true;
}

static bool canonical_path(const char *path, char *output, size_t capacity, apex_config_error_t *error) {
    char *resolved = realpath(path, NULL);
    if (resolved == NULL) {
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "cannot resolve configuration path");
        return false;
    }
    if (strlen(resolved) >= capacity) {
        free(resolved);
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "configuration path is too long");
        return false;
    }
    snprintf(output, capacity, "%s", resolved);
    free(resolved);
    return true;
}

static bool resolve_include_path(const char *base_file, const char *include, char *output, size_t capacity,
                                 apex_config_error_t *error) {
    char combined[APEX_CONFIG_PATH_MAX];
    if (include[0] == '/') {
        if (strlen(include) >= sizeof(combined)) {
            config_error_set(error, APEX_CONFIG_ERR_IO, base_file, 0, 0, "include path is too long");
            return false;
        }
        snprintf(combined, sizeof(combined), "%s", include);
    } else {
        const char *slash = strrchr(base_file, '/');
        size_t directory_length = slash != NULL ? (size_t)(slash - base_file) : 0u;
        if (directory_length == 0) {
            directory_length = 1u;
        }
        if (directory_length + 1u + strlen(include) >= sizeof(combined)) {
            config_error_set(error, APEX_CONFIG_ERR_IO, base_file, 0, 0, "include path is too long");
            return false;
        }
        if (slash != NULL) {
            memcpy(combined, base_file, directory_length);
            combined[directory_length] = '\0';
        } else {
            combined[0] = '.';
            combined[1] = '\0';
        }
        snprintf(combined + strlen(combined), sizeof(combined) - strlen(combined), "/%s", include);
    }
    return canonical_path(combined, output, capacity, error);
}

static bool tokenize_source(const char *path, token_list_t *output, char **stack, size_t depth,
                            apex_config_error_t *error) {
    if (depth >= APEX_CONFIG_MAX_INCLUDE_DEPTH) {
        config_error_set(error, APEX_CONFIG_ERR_SYNTAX, path, 0, 0, "include nesting is too deep");
        return false;
    }

    char canonical[APEX_CONFIG_PATH_MAX];
    if (!canonical_path(path, canonical, sizeof(canonical), error)) {
        return false;
    }

    for (size_t index = 0; index < depth; index++) {
        if (stack[index] != NULL && strcmp(stack[index], canonical) == 0) {
            config_error_set(error, APEX_CONFIG_ERR_SYNTAX, canonical, 0, 0, "include cycle detected");
            return false;
        }
    }

    char *stack_copy = config_strdup_range(canonical, strlen(canonical));
    if (stack_copy == NULL) {
        config_oom(error);
        return false;
    }
    stack[depth] = stack_copy;

    char *data = NULL;
    size_t length = 0;
    if (!read_file(canonical, &data, &length, error)) {
        free(stack[depth]);
        stack[depth] = NULL;
        return false;
    }

    token_list_t local;
    token_list_init(&local);
    int file_index = token_list_register_file(&local, canonical, error);
    if (file_index < 0) {
        free(data);
        free(stack[depth]);
        stack[depth] = NULL;
        token_list_free(&local);
        return false;
    }

    lexer_t lexer = {
        .data = data,
        .length = length,
        .position = 0,
        .line = 1,
        .column = 1,
        .file_index = file_index,
        .tokens = &local,
        .error = error,
    };

    bool ok = lexer_run(&lexer);
    free(data);

    if (!ok) {
        token_list_free(&local);
        free(stack[depth]);
        stack[depth] = NULL;
        return false;
    }

    bool statement_start = true;
    for (size_t index = 0; index < local.count; index++) {
        token_t *token = &local.items[index];

        if (statement_start && token->kind == TOKEN_WORD && token->text != NULL &&
            strcmp(token->text, "include") == 0) {
            if (index + 2u >= local.count || (local.items[index + 1u].kind != TOKEN_WORD &&
                                              local.items[index + 1u].kind != TOKEN_STRING) ||
                local.items[index + 2u].kind != TOKEN_SEMICOLON) {
                config_error_set(error, APEX_CONFIG_ERR_SYNTAX, canonical, token->line, token->column,
                                 "include requires a quoted path followed by ';'");
                token_list_free(&local);
                free(stack[depth]);
                stack[depth] = NULL;
                return false;
            }

            const char *include_pattern = local.items[index + 1u].text;
            bool has_glob = (strchr(include_pattern, '*') != NULL || strchr(include_pattern, '?') != NULL);
            if (has_glob) {
                char pattern_combined[APEX_CONFIG_PATH_MAX];
                if (include_pattern[0] == '/') {
                    if (strlen(include_pattern) >= sizeof(pattern_combined)) {
                        config_error_set(error, APEX_CONFIG_ERR_IO, canonical, token->line, token->column,
                                         "include path is too long");
                        token_list_free(&local);
                        free(stack[depth]);
                        stack[depth] = NULL;
                        return false;
                    }
                    snprintf(pattern_combined, sizeof(pattern_combined), "%s", include_pattern);
                } else {
                    const char *slash = strrchr(canonical, '/');
                    size_t directory_length = slash != NULL ? (size_t)(slash - canonical) : 0u;
                    if (directory_length == 0) {
                        directory_length = 1u;
                    }
                    if (directory_length + 1u + strlen(include_pattern) >= sizeof(pattern_combined)) {
                        config_error_set(error, APEX_CONFIG_ERR_IO, canonical, token->line, token->column,
                                         "include path is too long");
                        token_list_free(&local);
                        free(stack[depth]);
                        stack[depth] = NULL;
                        return false;
                    }
                    if (slash != NULL) {
                        memcpy(pattern_combined, canonical, directory_length);
                        pattern_combined[directory_length] = '\0';
                    } else {
                        pattern_combined[0] = '.';
                        pattern_combined[1] = '\0';
                    }
                    snprintf(pattern_combined + strlen(pattern_combined),
                             sizeof(pattern_combined) - strlen(pattern_combined), "/%s", include_pattern);
                }

                glob_t globbuf;
                memset(&globbuf, 0, sizeof(globbuf));
                int gres = glob(pattern_combined, 0, NULL, &globbuf);
                if (gres == 0) {
                    for (size_t m = 0; m < globbuf.gl_pathc; m++) {
                        char match_canonical[APEX_CONFIG_PATH_MAX];
                        if (canonical_path(globbuf.gl_pathv[m], match_canonical, sizeof(match_canonical), error)) {
                            if (!tokenize_source(match_canonical, output, stack, depth + 1u, error)) {
                                globfree(&globbuf);
                                token_list_free(&local);
                                free(stack[depth]);
                                stack[depth] = NULL;
                                return false;
                            }
                        }
                    }
                    globfree(&globbuf);
                } else if (gres == GLOB_NOMATCH) {
                    globfree(&globbuf);
                } else {
                    globfree(&globbuf);
                    config_error_set(error, APEX_CONFIG_ERR_IO, canonical, token->line, token->column,
                                     "failed to glob include pattern '%s'", include_pattern);
                    token_list_free(&local);
                    free(stack[depth]);
                    stack[depth] = NULL;
                    return false;
                }
            } else {
                char include_path[APEX_CONFIG_PATH_MAX];
                if (!resolve_include_path(canonical, local.items[index + 1u].text, include_path, sizeof(include_path),
                                          error)) {
                    token_list_free(&local);
                    free(stack[depth]);
                    stack[depth] = NULL;
                    return false;
                }

                if (!tokenize_source(include_path, output, stack, depth + 1u, error)) {
                    token_list_free(&local);
                    free(stack[depth]);
                    stack[depth] = NULL;
                    return false;
                }
            }

            index += 2u;
            statement_start = true;
            continue;
        }

        const char *token_file = local.files[token->file_index];
        int file = token_list_register_file(output, token_file, error);
        if (file < 0) {
            token_list_free(&local);
            free(stack[depth]);
            stack[depth] = NULL;
            return false;
        }

        token_t moved = *token;
        moved.file_index = file;
        token->text = NULL;
        if (!token_list_push(output, moved, error)) {
            token_list_free(&local);
            free(stack[depth]);
            stack[depth] = NULL;
            return false;
        }

        statement_start = token->kind == TOKEN_LBRACE || token->kind == TOKEN_SEMICOLON ||
                          token->kind == TOKEN_RBRACE;
    }

    token_list_free(&local);
    free(stack[depth]);
    stack[depth] = NULL;
    return true;
}

typedef struct {
    token_list_t *tokens;
    size_t index;
    apex_config_t *config;
    apex_config_error_t *error;
} parser_t;

static const char *token_file_name(const parser_t *parser, const token_t *token) {
    if (token->file_index < 0 || (size_t)token->file_index >= parser->tokens->file_count) {
        return parser->config->source;
    }
    return parser->tokens->files[token->file_index];
}

static void parser_error(parser_t *parser, apex_config_status_t code, const token_t *token, const char *format, ...) {
    if (parser->error == NULL) {
        return;
    }

    parser->error->code = code;
    parser->error->line = token != NULL ? token->line : 0;
    parser->error->column = token != NULL ? token->column : 0;
    parser->error->message[0] = '\0';
    parser->error->hint[0] = '\0';
    snprintf(parser->error->file, sizeof(parser->error->file), "%s",
             token != NULL ? token_file_name(parser, token) : parser->config->source);

    va_list arguments;
    va_start(arguments, format);
    vsnprintf(parser->error->message, sizeof(parser->error->message), format, arguments);
    va_end(arguments);
}

static void parser_hint(parser_t *parser, const char *format, ...) {
    if (parser->error == NULL) {
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(parser->error->hint, sizeof(parser->error->hint), format, arguments);
    va_end(arguments);
}

static const token_t *parser_peek(const parser_t *parser) {
    return &parser->tokens->items[parser->index < parser->tokens->count ? parser->index
                                                                       : parser->tokens->count - 1u];
}

static const token_t *parser_advance(parser_t *parser) {
    const token_t *token = parser_peek(parser);
    if (token->kind != TOKEN_EOF) {
        parser->index++;
    }
    return token;
}

static bool token_is_word(const token_t *token, const char *word) {
    return token->kind == TOKEN_WORD && token->text != NULL && strcmp(token->text, word) == 0;
}

static bool parser_expect(parser_t *parser, token_kind_t kind, const char *description) {
    const token_t *token = parser_peek(parser);
    if (token->kind != kind) {
        parser_error(parser, APEX_CONFIG_ERR_SYNTAX, token, "expected %s", description);
        return false;
    }
    parser_advance(parser);
    return true;
}

static bool parser_expect_semicolon(parser_t *parser) {
    return parser_expect(parser, TOKEN_SEMICOLON, "';'");
}

static bool parser_expect_lbrace(parser_t *parser) {
    return parser_expect(parser, TOKEN_LBRACE, "'{'");
}

static bool parser_expect_rbrace(parser_t *parser) {
    return parser_expect(parser, TOKEN_RBRACE, "'}'");
}

static const token_t *parser_scalar(parser_t *parser, const char *description) {
    const token_t *token = parser_peek(parser);
    if (token->kind != TOKEN_WORD && token->kind != TOKEN_STRING) {
        parser_error(parser, APEX_CONFIG_ERR_SYNTAX, token, "expected %s", description);
        return NULL;
    }
    parser_advance(parser);
    return token;
}

static const token_t *parser_identifier(parser_t *parser, const char *description) {
    const token_t *token = parser_peek(parser);
    if (token->kind != TOKEN_WORD || !is_identifier_name(token->text, token->length)) {
        parser_error(parser, APEX_CONFIG_ERR_SYNTAX, token, "expected %s", description);
        return NULL;
    }
    parser_advance(parser);
    return token;
}

static bool token_to_u64(const token_t *token, uint64_t minimum, uint64_t maximum, uint64_t *value) {
    if (token->length == 0) {
        return false;
    }

    uint64_t parsed = 0;
    for (size_t index = 0; index < token->length; index++) {
        char byte = token->text[index];
        if (byte < '0' || byte > '9') {
            return false;
        }
        unsigned int digit = (unsigned int)(byte - '0');
        if (parsed > (UINT64_MAX - digit) / 10u) {
            return false;
        }
        parsed = parsed * 10u + digit;
    }

    if (parsed < minimum || parsed > maximum) {
        return false;
    }
    *value = parsed;
    return true;
}

static bool token_to_duration_ms(const token_t *token, uint64_t *value_ms) {
    if (token->length == 0) {
        return false;
    }

    size_t digits = 0;
    uint64_t value = 0;
    while (digits < token->length && token->text[digits] >= '0' && token->text[digits] <= '9') {
        unsigned int digit = (unsigned int)(token->text[digits] - '0');
        if (value > (UINT64_MAX - digit) / 10u) {
            return false;
        }
        value = value * 10u + digit;
        digits++;
    }
    if (digits == 0) {
        return false;
    }

    size_t unit_length = token->length - digits;
    const char *unit = token->text + digits;
    uint64_t multiplier;
    if (unit_length == 0) {
        if (value != 0) {
            return false;
        }
        multiplier = 1u;
    } else if (unit_length == 2u && unit[0] == 'm' && unit[1] == 's') {
        multiplier = 1u;
    } else if (unit_length == 1u && unit[0] == 's') {
        multiplier = 1000u;
    } else if (unit_length == 1u && unit[0] == 'm') {
        multiplier = 60u * 1000u;
    } else if (unit_length == 1u && unit[0] == 'h') {
        multiplier = 60u * 60u * 1000u;
    } else {
        return false;
    }

    if (value > UINT64_MAX / multiplier) {
        return false;
    }
    *value_ms = value * multiplier;
    return true;
}

static bool parse_host_port(const char *text, bool allow_empty_host, bool allow_zero_port, char *host,
                            size_t host_capacity, uint16_t *port) {
    if (text == NULL || text[0] == '\0') {
        return false;
    }

    const char *port_text = NULL;
    const char *host_start = text;
    size_t host_length = 0;

    if (text[0] == '[') {
        const char *close = strchr(text, ']');
        if (close == NULL) {
            return false;
        }
        host_start = text + 1;
        host_length = (size_t)(close - host_start);
        if (close[1] != ':') {
            return false;
        }
        port_text = close + 2;
    } else {
        const char *first_colon = strchr(text, ':');
        const char *last_colon = strrchr(text, ':');
        if (first_colon == NULL || first_colon != last_colon) {
            return false;
        }
        host_length = (size_t)(last_colon - text);
        port_text = last_colon + 1;
    }

    if (host_length >= host_capacity) {
        return false;
    }
    if (host_length == 0 && !allow_empty_host) {
        return false;
    }

    if (host_length > 0) {
        memcpy(host, host_start, host_length);
    }
    host[host_length] = '\0';

    if (port_text == NULL || port_text[0] == '\0') {
        return false;
    }
    uint64_t parsed_port = 0;
    for (const char *cursor = port_text; cursor[0] != '\0'; cursor++) {
        if (cursor[0] < '0' || cursor[0] > '9') {
            return false;
        }
        parsed_port = parsed_port * 10u + (uint64_t)(cursor[0] - '0');
        if (parsed_port > 65535u) {
            return false;
        }
    }
    if (parsed_port == 0 && !allow_zero_port) {
        return false;
    }

    *port = (uint16_t)parsed_port;
    return true;
}

static bool token_to_header_name(const token_t *token) {
    if (token->length == 0) {
        return false;
    }
    for (size_t index = 0; index < token->length; index++) {
        unsigned char byte = (unsigned char)token->text[index];
        if (byte <= 0x20 || byte >= 0x7f || byte == ':' || byte == '(' || byte == ')' || byte == '<' ||
            byte == '>' || byte == '@' || byte == ',' || byte == ';' || byte == '\\' || byte == '"' ||
            byte == '/' || byte == '[' || byte == ']' || byte == '?' || byte == '=' || byte == '{' ||
            byte == '}') {
            return false;
        }
    }
    return true;
}

static bool token_to_header_value(const token_t *token) {
    for (size_t index = 0; index < token->length; index++) {
        if (token->text[index] == '\r' || token->text[index] == '\n') {
            return false;
        }
    }
    return true;
}

static const char *const reserved_words[] = {
    "http",       "upstream",      "server",         "listen",       "server_name",  "location",
    "tls",        "modules",       "include",        "policy",       "weight",       "max_conns",
    "keepalive",  "connect_timeout", "read_timeout", "idle_timeout", "certificate",  "private_key",
    "protocols",  "ciphers",       "client_auth",    "proxy_pass",   "proxy_set_header",
    "proxy_connect_timeout", "proxy_read_timeout", "proxy_http_version", "round_robin", "p2c",
    "index",      "try_files",     "sendfile",       "etag",         "precompressed", "gzip_static",
    "brotli_static",
    "on",         "off",           "optional",       "required",
};

static bool is_reserved_word(const char *text) {
    size_t count = sizeof(reserved_words) / sizeof(reserved_words[0]);
    for (size_t index = 0; index < count; index++) {
        if (strcmp(text, reserved_words[index]) == 0) {
            return true;
        }
    }
    return false;
}

static bool config_reserve_upstreams(parser_t *parser, size_t needed) {
    apex_config_t *config = parser->config;
    if (needed <= config->upstream_capacity) {
        return true;
    }
    size_t capacity = config->upstream_capacity ? config->upstream_capacity * 2u : 8u;
    while (capacity < needed) {
        capacity *= 2u;
    }
    apex_upstream_config_t *grown = realloc(config->upstreams, capacity * sizeof(*grown));
    if (grown == NULL) {
        config_oom(parser->error);
        return false;
    }
    config->upstreams = grown;
    config->upstream_capacity = capacity;
    return true;
}

static apex_upstream_config_t *config_add_upstream(parser_t *parser, const token_t *name) {
    apex_config_t *config = parser->config;
    if (!config_reserve_upstreams(parser, config->upstream_count + 1u)) {
        return NULL;
    }

    apex_upstream_config_t *upstream = &config->upstreams[config->upstream_count];
    memset(upstream, 0, sizeof(*upstream));
    upstream->name = config_strdup_range(name->text, name->length);
    if (upstream->name == NULL) {
        config_oom(parser->error);
        return NULL;
    }
    upstream->line = name->line;
    upstream->policy = APEX_BALANCE_ROUND_ROBIN;
    upstream->keepalive = APEX_CONFIG_DEFAULT_UPSTREAM_KEEPALIVE;
    upstream->connect_timeout_ms = APEX_CONFIG_DEFAULT_CONNECT_MS;
    upstream->read_timeout_ms = APEX_CONFIG_DEFAULT_READ_MS;
    upstream->idle_timeout_ms = APEX_CONFIG_DEFAULT_IDLE_MS;
    config->upstream_count++;
    return upstream;
}

static bool upstream_add_server(parser_t *parser, apex_upstream_config_t *upstream,
                                const apex_upstream_server_config_t *server) {
    if (upstream->server_count >= APEX_CONFIG_MAX_UPSTREAM_SERVERS) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, NULL, "upstream '%s' has too many servers", upstream->name);
        return false;
    }

    if (upstream->server_count == upstream->server_capacity) {
        size_t capacity = upstream->server_capacity ? upstream->server_capacity * 2u : 4u;
        apex_upstream_server_config_t *grown =
            realloc(upstream->servers, capacity * sizeof(*upstream->servers));
        if (grown == NULL) {
            config_oom(parser->error);
            return false;
        }
        upstream->servers = grown;
        upstream->server_capacity = capacity;
    }

    upstream->servers[upstream->server_count++] = *server;
    return true;
}

static bool config_reserve_servers(parser_t *parser, size_t needed) {
    apex_config_t *config = parser->config;
    if (needed <= config->server_capacity) {
        return true;
    }
    size_t capacity = config->server_capacity ? config->server_capacity * 2u : 4u;
    while (capacity < needed) {
        capacity *= 2u;
    }
    apex_server_config_t *grown = realloc(config->servers, capacity * sizeof(*grown));
    if (grown == NULL) {
        return config_oom(parser->error);
    }
    config->servers = grown;
    config->server_capacity = capacity;
    return true;
}

static apex_server_config_t *config_add_server(parser_t *parser, const token_t *begin) {
    apex_config_t *config = parser->config;
    if (!config_reserve_servers(parser, config->server_count + 1u)) {
        return NULL;
    }

    apex_server_config_t *server = &config->servers[config->server_count];
    memset(server, 0, sizeof(*server));
    server->line = begin->line;
    server->tls.client_auth = APEX_TLS_CLIENT_AUTH_OFF;
    config->server_count++;
    return server;
}

static bool server_add_name(parser_t *parser, apex_server_config_t *server, const token_t *name) {
    if (server->server_name_count >= APEX_CONFIG_MAX_SERVER_NAMES) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "server declares too many names");
        return false;
    }
    for (size_t index = 0; index < name->length; index++) {
        unsigned char byte = (unsigned char)name->text[index];
        if (isspace(byte) || byte < 0x21 || byte >= 0x7f || byte == '/' || byte == '\r' || byte == '\n') {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "invalid server name");
            return false;
        }
    }

    if (server->server_name_count == server->server_name_capacity) {
        size_t capacity = server->server_name_capacity ? server->server_name_capacity * 2u : 4u;
        char **grown = realloc(server->server_names, capacity * sizeof(char *));
        if (grown == NULL) {
            config_oom(parser->error);
            return false;
        }
        server->server_names = grown;
        server->server_name_capacity = capacity;
    }

    char *copy = config_strdup_range(name->text, name->length);
    if (copy == NULL) {
        config_oom(parser->error);
        return false;
    }
    server->server_names[server->server_name_count++] = copy;
    return true;
}

static bool server_add_error_page(parser_t *parser, apex_server_config_t *server, int status_code,
                                  const token_t *path) {
    if (server->error_page_count >= 32u) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, path, "server declares too many error pages");
        return false;
    }

    if (server->error_page_count == server->error_page_capacity) {
        size_t capacity = server->error_page_capacity ? server->error_page_capacity * 2u : 4u;
        apex_error_page_config_t *grown = realloc(server->error_pages, capacity * sizeof(*grown));
        if (grown == NULL) {
            config_oom(parser->error);
            return false;
        }
        server->error_pages = grown;
        server->error_page_capacity = capacity;
    }

    char *copy = config_strdup_range(path->text, path->length);
    if (copy == NULL) {
        config_oom(parser->error);
        return false;
    }

    for (size_t index = 0; index < server->error_page_count; index++) {
        if (server->error_pages[index].status_code == status_code) {
            free(server->error_pages[index].path);
            server->error_pages[index].path = copy;
            server->error_pages[index].line = path->line;
            return true;
        }
    }

    apex_error_page_config_t *entry = &server->error_pages[server->error_page_count++];
    entry->status_code = status_code;
    entry->path = copy;
    entry->line = path->line;
    return true;
}

static apex_location_config_t *server_add_location(parser_t *parser, apex_server_config_t *server,
                                                    const token_t *begin) {
    if (server->location_count >= APEX_CONFIG_MAX_LOCATIONS) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, begin, "server declares too many locations");
        return NULL;
    }

    if (server->location_count == server->location_capacity) {
        size_t capacity = server->location_capacity ? server->location_capacity * 2u : 4u;
        apex_location_config_t *grown = realloc(server->locations, capacity * sizeof(*grown));
        if (grown == NULL) {
            config_oom(parser->error);
            return NULL;
        }
        server->locations = grown;
        server->location_capacity = capacity;
    }

    apex_location_config_t *location = &server->locations[server->location_count];
    memset(location, 0, sizeof(*location));
    location->line = begin->line;
    location->target = APEX_PROXY_TARGET_NONE;
    location->upstream_index = SIZE_MAX;
    location->http_version = 11;
    server->location_count++;
    return location;
}

static bool location_add_header(parser_t *parser, apex_location_config_t *location, const token_t *name,
                                const token_t *value) {
    if (!token_to_header_name(name)) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "invalid header name");
        return false;
    }
    if (!token_to_header_value(value)) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "header value contains a line break");
        return false;
    }
    if (location->header_count >= APEX_CONFIG_MAX_HEADERS) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "location declares too many headers");
        return false;
    }

    if (location->header_count == location->header_capacity) {
        size_t capacity = location->header_capacity ? location->header_capacity * 2u : 4u;
        apex_config_header_t *grown = realloc(location->headers, capacity * sizeof(*grown));
        if (grown == NULL) {
            config_oom(parser->error);
            return false;
        }
        location->headers = grown;
        location->header_capacity = capacity;
    }

    char *name_copy = config_strdup_range(name->text, name->length);
    char *value_copy = config_strdup_range(value->text, value->length);
    if (name_copy == NULL || value_copy == NULL) {
        free(name_copy);
        free(value_copy);
        config_oom(parser->error);
        return false;
    }

    apex_config_header_t *header = &location->headers[location->header_count++];
    header->name = name_copy;
    header->value = value_copy;
    header->line = name->line;
    return true;
}

static bool tls_add_protocol(parser_t *parser, apex_tls_config_t *tls, const token_t *protocol) {
    if (tls->protocol_count == tls->protocol_capacity) {
        size_t capacity = tls->protocol_capacity ? tls->protocol_capacity * 2u : 4u;
        char **grown = realloc(tls->protocols, capacity * sizeof(char *));
        if (grown == NULL) {
            config_oom(parser->error);
            return false;
        }
        tls->protocols = grown;
        tls->protocol_capacity = capacity;
    }

    char *copy = config_strdup_range(protocol->text, protocol->length);
    if (copy == NULL) {
        config_oom(parser->error);
        return false;
    }
    tls->protocols[tls->protocol_count++] = copy;
    return true;
}

static bool config_add_module(parser_t *parser, const token_t *name) {
    apex_config_t *config = parser->config;
    if (config->module_count >= APEX_CONFIG_MAX_MODULE_NAMES) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "too many modules declared");
        return false;
    }

    if (config->module_count == config->module_capacity) {
        size_t capacity = config->module_capacity ? config->module_capacity * 2u : 4u;
        char **grown = realloc(config->modules, capacity * sizeof(char *));
        if (grown == NULL) {
            config_oom(parser->error);
            return false;
        }
        config->modules = grown;
        config->module_capacity = capacity;
    }

    char *copy = config_strdup_range(name->text, name->length);
    if (copy == NULL) {
        config_oom(parser->error);
        return false;
    }
    config->modules[config->module_count++] = copy;
    return true;
}

static bool parse_tls_block(parser_t *parser, apex_server_config_t *server) {
    if (!parser_expect_lbrace(parser)) {
        return false;
    }
    server->tls.enabled = true;

    while (parser_peek(parser)->kind != TOKEN_RBRACE) {
        const token_t *directive = parser_peek(parser);
        if (directive->kind == TOKEN_EOF) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unterminated 'tls' block");
            return false;
        }
        if (directive->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "expected a tls directive");
            return false;
        }
        parser_advance(parser);

        if (token_is_word(directive, "certificate") || token_is_word(directive, "private_key") ||
            token_is_word(directive, "ciphers")) {
            const token_t *value = parser_scalar(parser, "a value");
            if (value == NULL) {
                return false;
            }
            char **field = token_is_word(directive, "certificate")   ? &server->tls.certificate
                           : token_is_word(directive, "private_key") ? &server->tls.private_key
                                                                     : &server->tls.ciphers;
            free(*field);
            *field = config_strdup_range(value->text, value->length);
            if (*field == NULL) {
                return config_oom(parser->error);
            }
        } else if (token_is_word(directive, "protocols")) {
            size_t count = 0;
            while (parser_peek(parser)->kind == TOKEN_WORD || parser_peek(parser)->kind == TOKEN_STRING) {
                const token_t *protocol = parser_scalar(parser, "a protocol name");
                if (protocol == NULL) {
                    return false;
                }
                if (!tls_add_protocol(parser, &server->tls, protocol)) {
                    return false;
                }
                count++;
            }
            if (count == 0) {
                parser_error(parser, APEX_CONFIG_ERR_SYNTAX, parser_peek(parser), "expected at least one protocol");
                return false;
            }
        } else if (token_is_word(directive, "client_auth")) {
            const token_t *value = parser_scalar(parser, "a client authentication mode");
            if (value == NULL) {
                return false;
            }
            if (token_is_word(value, "off")) {
                server->tls.client_auth = APEX_TLS_CLIENT_AUTH_OFF;
            } else if (token_is_word(value, "optional")) {
                server->tls.client_auth = APEX_TLS_CLIENT_AUTH_OPTIONAL;
            } else if (token_is_word(value, "required")) {
                server->tls.client_auth = APEX_TLS_CLIENT_AUTH_REQUIRED;
            } else {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "client_auth must be off, optional, or required");
                return false;
            }
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unknown tls directive '%s'", directive->text);
            parser_hint(parser, "tls accepts certificate, private_key, protocols, ciphers, client_auth");
            return false;
        }

        if (!parser_expect_semicolon(parser)) {
            return false;
        }
    }

    if (!parser_expect_rbrace(parser)) {
        return false;
    }
    if (server->tls.certificate == NULL || server->tls.private_key == NULL) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, NULL, "tls block requires certificate and private_key");
        return false;
    }
    return true;
}

static bool location_set_proxy_pass(parser_t *parser, apex_location_config_t *location, const token_t *value) {
    if (location->target != APEX_PROXY_TARGET_NONE) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "location declares proxy_pass more than once");
        return false;
    }
    if (location->root != NULL) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "location cannot combine proxy_pass with root");
        return false;
    }

    const char *target = value->text;
    size_t length = value->length;
    if (length >= 7u && strncmp(target, "http://", 7) == 0) {
        target += 7;
        length -= 7u;
    }

    /* Check if target without port is an upstream name (e.g. "upstream_name" or "http://upstream_name") */
    if (memchr(target, ':', length) == NULL) {
        char name_buf[APEX_CONFIG_NAME_MAX];
        size_t name_len = length;
        if (name_len > 0 && target[name_len - 1] == '/') {
            name_len--;
        }
        if (name_len > 0 && name_len < sizeof(name_buf)) {
            memcpy(name_buf, target, name_len);
            name_buf[name_len] = '\0';
            if (is_identifier_name(name_buf, name_len) && !is_reserved_word(name_buf)) {
                location->target = APEX_PROXY_TARGET_UPSTREAM;
                location->upstream_name = config_strdup_range(name_buf, name_len);
                if (location->upstream_name == NULL) {
                    return config_oom(parser->error);
                }
                return true;
            }
        }
    }

    if (memchr(target, '/', length) != NULL || memchr(target, '?', length) != NULL ||
        memchr(target, '#', length) != NULL) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "proxy_pass endpoint must be host:port or upstream");
        return false;
    }

    char endpoint_text[APEX_CONFIG_HOST_MAX * 2u];
    if (length >= sizeof(endpoint_text)) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "proxy_pass endpoint is too long");
        return false;
    }
    memcpy(endpoint_text, target, length);
    endpoint_text[length] = '\0';

    char host[APEX_CONFIG_HOST_MAX];
    uint16_t port = 0;
    if (!parse_host_port(endpoint_text, false, false, host, sizeof(host), &port)) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid proxy_pass endpoint '%s'", value->text);
        return false;
    }

    location->endpoint_host = config_strdup_range(host, strlen(host));
    if (location->endpoint_host == NULL) {
        return config_oom(parser->error);
    }
    location->endpoint_port = port;
    location->target = APEX_PROXY_TARGET_ENDPOINT;
    return true;
}

static bool location_add_index(parser_t *parser, apex_location_config_t *location, const token_t *value) {
    char *copy = config_strdup_range(value->text, value->length);
    if (copy == NULL) {
        return config_oom(parser->error);
    }
    if (location->index_count >= location->index_capacity) {
        size_t capacity = location->index_capacity ? location->index_capacity * 2u : 4u;
        char **grown = realloc(location->indices, capacity * sizeof(char *));
        if (grown == NULL) {
            free(copy);
            return config_oom(parser->error);
        }
        location->indices = grown;
        location->index_capacity = capacity;
    }
    location->indices[location->index_count++] = copy;
    return true;
}

static bool location_add_try_file(parser_t *parser, apex_location_config_t *location, const token_t *value) {
    char *copy = config_strdup_range(value->text, value->length);
    if (copy == NULL) {
        return config_oom(parser->error);
    }
    if (location->try_files_count >= location->try_files_capacity) {
        size_t capacity = location->try_files_capacity ? location->try_files_capacity * 2u : 4u;
        char **grown = realloc(location->try_files, capacity * sizeof(char *));
        if (grown == NULL) {
            free(copy);
            return config_oom(parser->error);
        }
        location->try_files = grown;
        location->try_files_capacity = capacity;
    }
    location->try_files[location->try_files_count++] = copy;
    return true;
}

static bool config_parse_cidr(const char *text, size_t len, apex_acl_rule_t *rule) {
    if (text == NULL || len == 0 || rule == NULL) {
        return false;
    }
    if (len == 3 && strncmp(text, "all", 3) == 0) {
        rule->is_all = true;
        return true;
    }
    char buf[128];
    if (len >= sizeof(buf)) {
        return false;
    }
    memcpy(buf, text, len);
    buf[len] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = -1;
    if (slash != NULL) {
        *slash = '\0';
        char *endptr = NULL;
        long p = strtol(slash + 1, &endptr, 10);
        if (*endptr != '\0' || p < 0) {
            return false;
        }
        prefix = (int)p;
    }

    /* Try IPv4 first */
    struct in_addr addr4;
    if (inet_pton(AF_INET, buf, &addr4) == 1) {
        rule->is_ipv6 = false;
        if (prefix < 0) {
            prefix = 32;
        }
        if (prefix > 32) {
            return false;
        }
        uint32_t mask_val = (prefix == 0) ? 0 : (uint32_t)(~0ULL << (32 - prefix));
        rule->mask4.s_addr = htonl(mask_val);
        rule->addr4.s_addr = addr4.s_addr & rule->mask4.s_addr;
        return true;
    }

    /* Try IPv6 */
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, buf, &addr6) == 1) {
        rule->is_ipv6 = true;
        if (prefix < 0) {
            prefix = 128;
        }
        if (prefix > 128) {
            return false;
        }
        memset(&rule->mask6, 0, sizeof(rule->mask6));
        int full_bytes = prefix / 8;
        int rem_bits = prefix % 8;
        for (int i = 0; i < full_bytes; i++) {
            rule->mask6.s6_addr[i] = 0xFF;
        }
        if (rem_bits > 0 && full_bytes < 16) {
            rule->mask6.s6_addr[full_bytes] = (uint8_t)(~0U << (8 - rem_bits));
        }
        for (int i = 0; i < 16; i++) {
            rule->addr6.s6_addr[i] = addr6.s6_addr[i] & rule->mask6.s6_addr[i];
        }
        return true;
    }

    return false;
}

static bool config_parse_set_real_ip_from(parser_t *parser, const token_t *directive,
                                          apex_real_ip_rule_t *rules, size_t *count, size_t max_count) {
    const token_t *arg = parser_scalar(parser, "an IP or CIDR");
    if (arg == NULL) return false;
    if (*count >= max_count) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "too many set_real_ip_from rules");
        return false;
    }
    if (!apex_real_ip_parse_rule(arg->text, arg->length, &rules[*count])) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid IP or CIDR '%s'", arg->text);
        return false;
    }
    (*count)++;
    return true;
}

static bool config_parse_real_ip_header(parser_t *parser, char *header_out, size_t header_max) {
    const token_t *arg = parser_scalar(parser, "a header name");
    if (arg == NULL) return false;
    snprintf(header_out, header_max, "%s", arg->text);
    return true;
}

static bool config_parse_real_ip_recursive(parser_t *parser, bool *recursive_out) {
    const token_t *arg = parser_scalar(parser, "on or off");
    if (arg == NULL) return false;
    if (token_is_word(arg, "on")) {
        *recursive_out = true;
    } else if (token_is_word(arg, "off")) {
        *recursive_out = false;
    } else {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "real_ip_recursive must be on or off");
        return false;
    }
    return true;
}

static bool config_parse_access_log(parser_t *parser, const token_t *directive, apex_access_log_config_t *log_cfg) {
    (void)directive;
    memset(log_cfg, 0, sizeof(*log_cfg));
    const token_t *first = parser_scalar(parser, "log path or off");
    if (first == NULL) return false;

    if (token_is_word(first, "off")) {
        log_cfg->off = true;
        return true;
    }

    snprintf(log_cfg->path, sizeof(log_cfg->path), "%s", first->text);
    strncpy(log_cfg->format_name, "combined", sizeof(log_cfg->format_name) - 1);

    while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
        const token_t *arg = parser_scalar(parser, "access_log parameter");
        if (arg == NULL) return false;
        if (strncmp(arg->text, "buffer=", 7) == 0) {
            if (!parse_size_str(arg->text + 7, &log_cfg->buffer_size)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid buffer size '%s'", arg->text + 7);
                return false;
            }
        } else if (strncmp(arg->text, "flush=", 6) == 0) {
            token_t temp_tok = *arg;
            temp_tok.text = arg->text + 6;
            temp_tok.length = strlen(temp_tok.text);
            if (!token_to_duration_ms(&temp_tok, &log_cfg->flush_ms)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid flush duration '%s'", arg->text + 6);
                return false;
            }
        } else {
            snprintf(log_cfg->format_name, sizeof(log_cfg->format_name), "%s", arg->text);
        }
    }
    return true;
}

static bool config_parse_log_format(parser_t *parser, const token_t *directive) {
    if (parser->config->http.log_format_count >= APEX_CONFIG_MAX_LOG_FORMATS) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "too many log_format declarations (max %u)",
                     APEX_CONFIG_MAX_LOG_FORMATS);
        return false;
    }
    const token_t *name_tok = parser_scalar(parser, "format name");
    if (name_tok == NULL) return false;

    apex_log_format_config_t *fmt = &parser->config->http.log_formats[parser->config->http.log_format_count];
    memset(fmt, 0, sizeof(*fmt));
    snprintf(fmt->name, sizeof(fmt->name), "%s", name_tok->text);

    char fmt_buf[512] = "";
    while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
        const token_t *part = parser_scalar(parser, "format string");
        if (part == NULL) return false;
        if (fmt_buf[0] != '\0' && fmt_buf[strlen(fmt_buf) - 1] != ' ') {
            strncat(fmt_buf, " ", sizeof(fmt_buf) - strlen(fmt_buf) - 1);
        }
        strncat(fmt_buf, part->text, sizeof(fmt_buf) - strlen(fmt_buf) - 1);
    }
    snprintf(fmt->format, sizeof(fmt->format), "%s", fmt_buf);
    parser->config->http.log_format_count++;
    return true;
}

static bool parse_location_block(parser_t *parser, apex_server_config_t *server) {
    const token_t *begin = parser_peek(parser);
    bool exact = false;
    const token_t *match = parser_peek(parser);
    if ((match->kind == TOKEN_WORD || match->kind == TOKEN_STRING) && match->text != NULL &&
        strcmp(match->text, "=") == 0) {
        exact = true;
        parser_advance(parser);
    }

    const token_t *path = parser_scalar(parser, "a location path");
    if (path == NULL) {
        return false;
    }
    if (path->length == 0 || path->text[0] != '/') {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, path, "location path must start with '/'");
        return false;
    }
    if (path->text[0] == '~' || path->text[0] == '@') {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, path, "regex and named locations are not supported");
        return false;
    }
    for (size_t index = 0; index < path->length; index++) {
        unsigned char byte = (unsigned char)path->text[index];
        if (byte <= 0x20 || byte == '\r' || byte == '\n') {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, path, "location path contains whitespace");
            return false;
        }
    }

    apex_location_config_t *location = server_add_location(parser, server, begin);
    if (location == NULL) {
        return false;
    }
    location->path = config_strdup_range(path->text, path->length);
    if (location->path == NULL) {
        return config_oom(parser->error);
    }
    location->exact = exact;
    location->sendfile = true;
    location->etag = true;
    location->precompressed = true;

    if (!parser_expect_lbrace(parser)) {
        return false;
    }

    while (parser_peek(parser)->kind != TOKEN_RBRACE) {
        const token_t *directive = parser_peek(parser);
        if (directive->kind == TOKEN_EOF) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unterminated 'location' block");
            return false;
        }
        if (directive->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "expected a location directive");
            return false;
        }
        parser_advance(parser);

        if (token_is_word(directive, "proxy_pass")) {
            const token_t *value = parser_scalar(parser, "an upstream name or host:port");
            if (value == NULL || !location_set_proxy_pass(parser, location, value)) {
                return false;
            }
        } else if (token_is_word(directive, "root")) {
            if (location->target != APEX_PROXY_TARGET_NONE || location->root != NULL) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive,
                             "location cannot declare more than one terminal action");
                return false;
            }
            const token_t *value = parser_scalar(parser, "a filesystem path");
            if (value == NULL) {
                return false;
            }
            location->root = config_strdup_range(value->text, value->length);
            if (location->root == NULL) {
                return config_oom(parser->error);
            }
        } else if (token_is_word(directive, "index")) {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *value = parser_scalar(parser, "an index filename");
                if (value == NULL || !location_add_index(parser, location, value)) {
                    return false;
                }
            }
        } else if (token_is_word(directive, "try_files")) {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *value = parser_scalar(parser, "a try_files pattern");
                if (value == NULL || !location_add_try_file(parser, location, value)) {
                    return false;
                }
            }
        } else if (token_is_word(directive, "sendfile")) {
            const token_t *value = parser_scalar(parser, "on or off");
            if (value == NULL) {
                return false;
            }
            if (token_is_word(value, "on")) {
                location->sendfile = true;
            } else if (token_is_word(value, "off")) {
                location->sendfile = false;
            } else {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "sendfile must be 'on' or 'off'");
                return false;
            }
        } else if (token_is_word(directive, "etag")) {
            const token_t *value = parser_scalar(parser, "on or off");
            if (value == NULL) {
                return false;
            }
            if (token_is_word(value, "on")) {
                location->etag = true;
            } else if (token_is_word(value, "off")) {
                location->etag = false;
            } else {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "etag must be 'on' or 'off'");
                return false;
            }
        } else if (token_is_word(directive, "precompressed") || token_is_word(directive, "gzip_static") ||
                   token_is_word(directive, "brotli_static")) {
            const token_t *value = parser_scalar(parser, "on or off");
            if (value == NULL) {
                return false;
            }
            if (token_is_word(value, "on")) {
                location->precompressed = true;
            } else if (token_is_word(value, "off")) {
                location->precompressed = false;
            } else {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "precompressed must be 'on' or 'off'");
                return false;
            }
        } else if (token_is_word(directive, "proxy_set_header")) {
            const token_t *name = parser_scalar(parser, "a header name");
            const token_t *value = parser_scalar(parser, "a header value");
            if (name == NULL || value == NULL || !location_add_header(parser, location, name, value)) {
                return false;
            }
        } else if (token_is_word(directive, "proxy_connect_timeout") ||
                   token_is_word(directive, "proxy_read_timeout")) {
            const token_t *value = parser_scalar(parser, "a duration");
            if (value == NULL) {
                return false;
            }
            uint64_t milliseconds = 0;
            if (!token_to_duration_ms(value, &milliseconds)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid duration");
                return false;
            }
            if (token_is_word(directive, "proxy_connect_timeout")) {
                location->has_connect_timeout = true;
                location->connect_timeout_ms = milliseconds;
            } else {
                location->has_read_timeout = true;
                location->read_timeout_ms = milliseconds;
            }
        } else if (token_is_word(directive, "proxy_http_version")) {
            const token_t *value = parser_scalar(parser, "1.0 or 1.1");
            if (value == NULL) {
                return false;
            }
            if (token_is_word(value, "1.0")) {
                location->http_version = 10;
            } else if (token_is_word(value, "1.1")) {
                location->http_version = 11;
            } else {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "proxy_http_version must be 1.0 or 1.1");
                return false;
            }
        } else if (token_is_word(directive, "return")) {
            const token_t *first = parser_scalar(parser, "a redirect code or URL");
            if (first == NULL) {
                return false;
            }
            int code = 302;
            const token_t *url_tok = NULL;
            if (first->length > 0 && isdigit((unsigned char)first->text[0])) {
                uint64_t cval = 0;
                if (!token_to_u64(first, 200, 599, &cval)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, first, "invalid return status code");
                    return false;
                }
                code = (int)cval;
                if (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                    url_tok = parser_scalar(parser, "a redirect URL or text");
                    if (url_tok == NULL) {
                        return false;
                    }
                }
            } else {
                url_tok = first;
            }

            location->return_code = code;
            if (url_tok != NULL) {
                if (url_tok->length >= sizeof(location->return_url)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, url_tok, "return URL is too long");
                    return false;
                }
                memcpy(location->return_url, url_tok->text, url_tok->length);
                location->return_url[url_tok->length] = '\0';
            } else {
                location->return_url[0] = '\0';
            }
        } else if (token_is_word(directive, "allow") || token_is_word(directive, "deny")) {
            bool allow = token_is_word(directive, "allow");
            const token_t *val = parser_scalar(parser, "a CIDR address or 'all'");
            if (val == NULL) {
                return false;
            }
            if (location->acl_rule_count >= APEX_CONFIG_MAX_ACL_RULES) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "too many allow/deny rules (max %u)",
                             (unsigned)APEX_CONFIG_MAX_ACL_RULES);
                return false;
            }
            apex_acl_rule_t *rule = &location->acl_rules[location->acl_rule_count];
            memset(rule, 0, sizeof(*rule));
            rule->allow = allow;
            if (!config_parse_cidr(val->text, val->length, rule)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, val, "invalid CIDR address '%s'", val->text);
                return false;
            }
            location->acl_rule_count++;
        } else if (token_is_word(directive, "limit_req")) {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *arg = parser_scalar(parser, "limit_req parameter");
                if (arg == NULL) return false;
                if (strncmp(arg->text, "zone=", 5) == 0) {
                    snprintf(location->limit_req_zone, sizeof(location->limit_req_zone), "%s", arg->text + 5);
                } else if (strncmp(arg->text, "burst=", 6) == 0) {
                    location->limit_req_burst = (uint32_t)strtoul(arg->text + 6, NULL, 10);
                } else if (strcmp(arg->text, "nodelay") == 0) {
                    location->limit_req_nodelay = true;
                } else if (location->limit_req_zone[0] == '\0') {
                    snprintf(location->limit_req_zone, sizeof(location->limit_req_zone), "%s", arg->text);
                }
            }
        } else if (token_is_word(directive, "limit_req_status")) {
            const token_t *val = parser_scalar(parser, "status code");
            if (val == NULL) return false;
            uint64_t code = 0;
            if (!token_to_u64(val, 400, 599, &code)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, val, "invalid limit_req_status");
                return false;
            }
            location->limit_req_status = (int)code;
        } else if (token_is_word(directive, "limit_conn")) {
            const token_t *first = parser_scalar(parser, "zone name");
            if (first == NULL) return false;
            if (strncmp(first->text, "zone=", 5) == 0) {
                snprintf(location->limit_conn_zone, sizeof(location->limit_conn_zone), "%s", first->text + 5);
            } else {
                snprintf(location->limit_conn_zone, sizeof(location->limit_conn_zone), "%s", first->text);
            }
            const token_t *second = parser_scalar(parser, "max connections");
            if (second == NULL) return false;
            location->limit_conn_max = (uint32_t)strtoul(second->text, NULL, 10);
        } else if (token_is_word(directive, "limit_conn_status")) {
            const token_t *val = parser_scalar(parser, "status code");
            if (val == NULL) return false;
            uint64_t code = 0;
            if (!token_to_u64(val, 400, 599, &code)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, val, "invalid limit_conn_status");
                return false;
            }
            location->limit_conn_status = (int)code;
        } else if (token_is_word(directive, "stub_status")) {
            location->stub_status = true;
            if (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *val = parser_scalar(parser, "stub_status arg");
                if (val != NULL && token_is_word(val, "off")) {
                    location->stub_status = false;
                }
            }
        } else if (token_is_word(directive, "metrics")) {
            location->metrics = true;
            if (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *val = parser_scalar(parser, "metrics arg");
                if (val != NULL && token_is_word(val, "off")) {
                    location->metrics = false;
                }
            }
        } else if (token_is_word(directive, "proxy_cache")) {
            const token_t *val = parser_scalar(parser, "cache zone name or off");
            if (val == NULL) return false;
            if (token_is_word(val, "off")) {
                location->proxy_cache[0] = '\0';
            } else {
                snprintf(location->proxy_cache, sizeof(location->proxy_cache), "%s", val->text);
            }
        } else if (token_is_word(directive, "proxy_cache_key")) {
            const token_t *val = parser_scalar(parser, "cache key");
            if (val == NULL) return false;
            snprintf(location->proxy_cache_key, sizeof(location->proxy_cache_key), "%s", val->text);
        } else if (token_is_word(directive, "proxy_cache_bypass")) {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *arg = parser_scalar(parser, "bypass variable");
                if (arg == NULL) return false;
                if (location->proxy_cache_bypass[0] != '\0') {
                    strncat(location->proxy_cache_bypass, " ",
                            sizeof(location->proxy_cache_bypass) - strlen(location->proxy_cache_bypass) - 1);
                }
                strncat(location->proxy_cache_bypass, arg->text,
                        sizeof(location->proxy_cache_bypass) - strlen(location->proxy_cache_bypass) - 1);
            }
        } else if (token_is_word(directive, "proxy_cache_valid")) {
            token_t tokens[8];
            size_t count = 0;
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *tok = parser_scalar(parser, "proxy_cache_valid parameter");
                if (tok == NULL) return false;
                if (count < 8) {
                    tokens[count++] = *tok;
                }
            }
            if (count == 0) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "proxy_cache_valid requires arguments");
                return false;
            }
            uint64_t valid_ms = 0;
            if (!token_to_duration_ms(&tokens[count - 1], &valid_ms)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, &tokens[count - 1],
                             "invalid cache validity duration '%s'", tokens[count - 1].text);
                return false;
            }
            if (count == 1) {
                int default_codes[] = {200, 301, 302};
                for (size_t c = 0; c < 3 && location->cache_valid_rule_count < 8; c++) {
                    location->cache_valid_rules[location->cache_valid_rule_count].status_code = default_codes[c];
                    location->cache_valid_rules[location->cache_valid_rule_count].valid_ms = valid_ms;
                    location->cache_valid_rule_count++;
                }
            } else {
                for (size_t c = 0; c < count - 1 && location->cache_valid_rule_count < 8; c++) {
                    int code = 0;
                    if (token_is_word(&tokens[c], "any")) {
                        code = 0;
                    } else {
                        code = atoi(tokens[c].text);
                    }
                    location->cache_valid_rules[location->cache_valid_rule_count].status_code = code;
                    location->cache_valid_rules[location->cache_valid_rule_count].valid_ms = valid_ms;
                    location->cache_valid_rule_count++;
                }
            }
        } else if (token_is_word(directive, "set_real_ip_from")) {
            if (!config_parse_set_real_ip_from(parser, directive, location->real_ip_rules,
                                              &location->real_ip_rule_count, APEX_CONFIG_MAX_REAL_IP_RULES)) {
                return false;
            }
        } else if (token_is_word(directive, "real_ip_header")) {
            if (!config_parse_real_ip_header(parser, location->real_ip_header, sizeof(location->real_ip_header))) {
                return false;
            }
            location->has_real_ip_header = true;
        } else if (token_is_word(directive, "real_ip_recursive")) {
            if (!config_parse_real_ip_recursive(parser, &location->real_ip_recursive)) {
                return false;
            }
            location->has_real_ip_recursive = true;
        } else if (token_is_word(directive, "access_log")) {
            if (!config_parse_access_log(parser, directive, &location->access_log)) {
                return false;
            }
            location->has_access_log = true;
        } else if (token_is_word(directive, "fastcgi_pass")) {
            const token_t *value = parser_scalar(parser, "a fastcgi backend endpoint (host:port or unix:/path)");
            if (value == NULL) {
                return false;
            }
            if (value->length >= sizeof(location->fastcgi_pass)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "fastcgi_pass endpoint is too long");
                return false;
            }
            snprintf(location->fastcgi_pass, sizeof(location->fastcgi_pass), "%s", value->text);
        } else if (token_is_word(directive, "fastcgi_index")) {
            const token_t *value = parser_scalar(parser, "a fastcgi index filename");
            if (value == NULL) {
                return false;
            }
            if (value->length >= sizeof(location->fastcgi_index)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "fastcgi_index filename is too long");
                return false;
            }
            snprintf(location->fastcgi_index, sizeof(location->fastcgi_index), "%s", value->text);
        } else if (token_is_word(directive, "fastcgi_param")) {
            const token_t *key = parser_scalar(parser, "a fastcgi parameter name");
            if (key == NULL) {
                return false;
            }
            const token_t *val = parser_scalar(parser, "a fastcgi parameter value");
            if (val == NULL) {
                return false;
            }
            if (location->fastcgi_param_count >= location->fastcgi_param_capacity) {
                size_t ncap = location->fastcgi_param_capacity ? location->fastcgi_param_capacity * 2 : 8;
                apex_config_header_t *nparams = realloc(location->fastcgi_params, ncap * sizeof(apex_config_header_t));
                if (!nparams) return config_oom(parser->error);
                location->fastcgi_params = nparams;
                location->fastcgi_param_capacity = ncap;
            }
            apex_config_header_t *p = &location->fastcgi_params[location->fastcgi_param_count++];
            p->name = config_strdup_range(key->text, key->length);
            p->value = config_strdup_range(val->text, val->length);
            p->line = key->line;
            if (!p->name || !p->value) return config_oom(parser->error);
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unknown location directive '%s'",
                         directive->text);
            parser_hint(parser, "location accepts proxy_pass, root, index, try_files, sendfile, etag, precompressed, proxy_set_header, proxy_*_timeout, "
                                "proxy_http_version, return, allow, deny, limit_req, limit_conn, stub_status, metrics, proxy_cache, proxy_cache_key, proxy_cache_bypass, proxy_cache_valid, set_real_ip_from, real_ip_header, real_ip_recursive, access_log, fastcgi_pass, fastcgi_index, fastcgi_param");
            return false;
        }

        if (!parser_expect_semicolon(parser)) {
            return false;
        }
    }

    if (!parser_expect_rbrace(parser)) {
        return false;
    }

    /* Inherit server root if not configured in location */
    if (location->root == NULL && server->root != NULL) {
        location->root = config_strdup_range(server->root, strlen(server->root));
        if (location->root == NULL) return config_oom(parser->error);
    }

    /* Inherit server cache settings if not explicitly configured in location */
    if (location->proxy_cache[0] == '\0' && server->proxy_cache[0] != '\0') {
        snprintf(location->proxy_cache, sizeof(location->proxy_cache), "%s", server->proxy_cache);
        if (location->proxy_cache_key[0] == '\0' && server->proxy_cache_key[0] != '\0') {
            snprintf(location->proxy_cache_key, sizeof(location->proxy_cache_key), "%s", server->proxy_cache_key);
        }
        if (location->proxy_cache_bypass[0] == '\0' && server->proxy_cache_bypass[0] != '\0') {
            snprintf(location->proxy_cache_bypass, sizeof(location->proxy_cache_bypass), "%s", server->proxy_cache_bypass);
        }
        if (location->cache_valid_rule_count == 0 && server->cache_valid_rule_count > 0) {
            location->cache_valid_rule_count = server->cache_valid_rule_count;
            memcpy(location->cache_valid_rules, server->cache_valid_rules, sizeof(server->cache_valid_rules));
        }
    }

    /* Inherit server real_ip and access_log settings if not configured in location */
    if (!location->has_access_log && server->has_access_log) {
        location->access_log = server->access_log;
        location->has_access_log = true;
    }
    if (location->real_ip_rule_count == 0 && server->real_ip_rule_count > 0) {
        location->real_ip_rule_count = server->real_ip_rule_count;
        memcpy(location->real_ip_rules, server->real_ip_rules, sizeof(server->real_ip_rules));
    }
    if (!location->has_real_ip_header && server->has_real_ip_header) {
        snprintf(location->real_ip_header, sizeof(location->real_ip_header), "%s", server->real_ip_header);
        location->has_real_ip_header = true;
    }
    if (!location->has_real_ip_recursive && server->has_real_ip_recursive) {
        location->real_ip_recursive = server->real_ip_recursive;
        location->has_real_ip_recursive = true;
    }

    if (location->target == APEX_PROXY_TARGET_NONE && location->root == NULL && location->return_code == 0 &&
        !location->stub_status && !location->metrics && location->fastcgi_pass[0] == '\0') {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, begin, "location requires proxy_pass, fastcgi_pass, root, return, stub_status, or metrics");
        return false;
    }
    return true;
}

static bool parse_server_block(parser_t *parser) {
    const token_t *begin = parser_peek(parser);
    if (!parser_expect_lbrace(parser)) {
        return false;
    }

    apex_server_config_t *server = config_add_server(parser, begin);
    if (server == NULL) {
        return false;
    }
    bool have_listen = false;

    while (parser_peek(parser)->kind != TOKEN_RBRACE) {
        const token_t *directive = parser_peek(parser);
        if (directive->kind == TOKEN_EOF) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unterminated 'server' block");
            return false;
        }
        if (directive->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "expected a server directive");
            return false;
        }
        parser_advance(parser);

        if (token_is_word(directive, "listen")) {
            if (have_listen) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "server declares listen more than once");
                return false;
            }
            const token_t *value = parser_scalar(parser, "a listen address");
            if (value == NULL) {
                return false;
            }

            char listen_text[APEX_CONFIG_HOST_MAX * 2u];
            if (value->length >= sizeof(listen_text)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "listen address is too long");
                return false;
            }
            memcpy(listen_text, value->text, value->length);
            listen_text[value->length] = '\0';

            uint16_t port = 0;
            if (listen_text[0] == ':' || listen_text[0] == '[') {
                if (!parse_host_port(listen_text, true, true, server->listen_host, sizeof(server->listen_host),
                                     &port)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid listen address '%s'",
                                 value->text);
                    return false;
                }
            } else if (strchr(listen_text, ':') == NULL) {
                uint64_t parsed = 0;
                const token_t *port_token = value;
                if (!token_to_u64(port_token, 0, 65535, &parsed)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid listen port");
                    return false;
                }
                server->listen_host[0] = '\0';
                port = (uint16_t)parsed;
            } else {
                if (!parse_host_port(listen_text, false, true, server->listen_host, sizeof(server->listen_host),
                                     &port)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid listen address '%s'",
                                 value->text);
                    return false;
                }
            }

            server->listen_port = port;
            have_listen = true;

            if (token_is_word(parser_peek(parser), "tls")) {
                parser_advance(parser);
                server->listen_tls = true;
            }
        } else if (token_is_word(directive, "server_name")) {
            size_t count = 0;
            while (parser_peek(parser)->kind == TOKEN_WORD || parser_peek(parser)->kind == TOKEN_STRING) {
                const token_t *name = parser_scalar(parser, "a server name");
                if (name == NULL || !server_add_name(parser, server, name)) {
                    return false;
                }
                count++;
            }
            if (count == 0) {
                parser_error(parser, APEX_CONFIG_ERR_SYNTAX, parser_peek(parser), "server_name requires a name");
                return false;
            }
        } else if (token_is_word(directive, "tls")) {
            if (server->tls.enabled) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "server declares tls more than once");
                return false;
            }
            if (!parse_tls_block(parser, server)) {
                return false;
            }
            continue;
        } else if (token_is_word(directive, "location")) {
            if (!parse_location_block(parser, server)) {
                return false;
            }
            continue;
        } else if (token_is_word(directive, "error_page")) {
            int codes[16];
            size_t code_count = 0;
            while (parser_peek(parser)->kind == TOKEN_WORD &&
                   isdigit((unsigned char)parser_peek(parser)->text[0])) {
                const token_t *code_token = parser_scalar(parser, "an HTTP status code");
                if (code_token == NULL) {
                    return false;
                }
                uint64_t code_val = 0;
                if (!token_to_u64(code_token, 300, 599, &code_val)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, code_token, "invalid HTTP error status code");
                    return false;
                }
                if (code_count < sizeof(codes) / sizeof(codes[0])) {
                    codes[code_count++] = (int)code_val;
                }
            }
            if (code_count == 0) {
                parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "error_page requires at least one status code");
                return false;
            }
            const token_t *path_token = parser_scalar(parser, "a file path for error_page");
            if (path_token == NULL) {
                return false;
            }
            for (size_t c = 0; c < code_count; c++) {
                if (!server_add_error_page(parser, server, codes[c], path_token)) {
                    return false;
                }
            }
        } else if (token_is_word(directive, "return")) {
            const token_t *first = parser_scalar(parser, "a redirect code or URL");
            if (first == NULL) {
                return false;
            }
            int code = 302;
            const token_t *url_tok = NULL;
            if (first->length > 0 && isdigit((unsigned char)first->text[0])) {
                uint64_t cval = 0;
                if (!token_to_u64(first, 200, 599, &cval)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, first, "invalid return status code");
                    return false;
                }
                code = (int)cval;
                if (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                    url_tok = parser_scalar(parser, "a redirect URL or text");
                    if (url_tok == NULL) {
                        return false;
                    }
                }
            } else {
                url_tok = first;
            }

            server->return_code = code;
            if (url_tok != NULL) {
                if (url_tok->length >= sizeof(server->return_url)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, url_tok, "return URL is too long");
                    return false;
                }
                memcpy(server->return_url, url_tok->text, url_tok->length);
                server->return_url[url_tok->length] = '\0';
            } else {
                server->return_url[0] = '\0';
            }
        } else if (token_is_word(directive, "allow") || token_is_word(directive, "deny")) {
            bool allow = token_is_word(directive, "allow");
            const token_t *val = parser_scalar(parser, "a CIDR address or 'all'");
            if (val == NULL) {
                return false;
            }
            if (server->acl_rule_count >= APEX_CONFIG_MAX_ACL_RULES) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "too many allow/deny rules (max %u)",
                             (unsigned)APEX_CONFIG_MAX_ACL_RULES);
                return false;
            }
            apex_acl_rule_t *rule = &server->acl_rules[server->acl_rule_count];
            memset(rule, 0, sizeof(*rule));
            rule->allow = allow;
            if (!config_parse_cidr(val->text, val->length, rule)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, val, "invalid CIDR address '%s'", val->text);
                return false;
            }
            server->acl_rule_count++;
        } else if (token_is_word(directive, "limit_req")) {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *arg = parser_scalar(parser, "limit_req parameter");
                if (arg == NULL) return false;
                if (strncmp(arg->text, "zone=", 5) == 0) {
                    snprintf(server->limit_req_zone, sizeof(server->limit_req_zone), "%s", arg->text + 5);
                } else if (strncmp(arg->text, "burst=", 6) == 0) {
                    server->limit_req_burst = (uint32_t)strtoul(arg->text + 6, NULL, 10);
                } else if (strcmp(arg->text, "nodelay") == 0) {
                    server->limit_req_nodelay = true;
                } else if (server->limit_req_zone[0] == '\0') {
                    snprintf(server->limit_req_zone, sizeof(server->limit_req_zone), "%s", arg->text);
                }
            }
        } else if (token_is_word(directive, "limit_req_status")) {
            const token_t *val = parser_scalar(parser, "status code");
            if (val == NULL) return false;
            uint64_t code = 0;
            if (!token_to_u64(val, 400, 599, &code)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, val, "invalid limit_req_status");
                return false;
            }
            server->limit_req_status = (int)code;
        } else if (token_is_word(directive, "limit_conn")) {
            const token_t *first = parser_scalar(parser, "zone name");
            if (first == NULL) return false;
            if (strncmp(first->text, "zone=", 5) == 0) {
                snprintf(server->limit_conn_zone, sizeof(server->limit_conn_zone), "%s", first->text + 5);
            } else {
                snprintf(server->limit_conn_zone, sizeof(server->limit_conn_zone), "%s", first->text);
            }
            const token_t *second = parser_scalar(parser, "max connections");
            if (second == NULL) return false;
            server->limit_conn_max = (uint32_t)strtoul(second->text, NULL, 10);
        } else if (token_is_word(directive, "limit_conn_status")) {
            const token_t *val = parser_scalar(parser, "status code");
            if (val == NULL) return false;
            uint64_t code = 0;
            if (!token_to_u64(val, 400, 599, &code)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, val, "invalid limit_conn_status");
                return false;
            }
            server->limit_conn_status = (int)code;
        } else if (token_is_word(directive, "proxy_cache")) {
            const token_t *val = parser_scalar(parser, "cache zone name or off");
            if (val == NULL) return false;
            if (token_is_word(val, "off")) {
                server->proxy_cache[0] = '\0';
            } else {
                snprintf(server->proxy_cache, sizeof(server->proxy_cache), "%s", val->text);
            }
        } else if (token_is_word(directive, "proxy_cache_key")) {
            const token_t *val = parser_scalar(parser, "cache key");
            if (val == NULL) return false;
            snprintf(server->proxy_cache_key, sizeof(server->proxy_cache_key), "%s", val->text);
        } else if (token_is_word(directive, "proxy_cache_bypass")) {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *arg = parser_scalar(parser, "bypass variable");
                if (arg == NULL) return false;
                if (server->proxy_cache_bypass[0] != '\0') {
                    strncat(server->proxy_cache_bypass, " ",
                            sizeof(server->proxy_cache_bypass) - strlen(server->proxy_cache_bypass) - 1);
                }
                strncat(server->proxy_cache_bypass, arg->text,
                        sizeof(server->proxy_cache_bypass) - strlen(server->proxy_cache_bypass) - 1);
            }
        } else if (token_is_word(directive, "proxy_cache_valid")) {
            token_t tokens[8];
            size_t count = 0;
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
                const token_t *tok = parser_scalar(parser, "proxy_cache_valid parameter");
                if (tok == NULL) return false;
                if (count < 8) {
                    tokens[count++] = *tok;
                }
            }
            if (count == 0) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "proxy_cache_valid requires arguments");
                return false;
            }
            uint64_t valid_ms = 0;
            if (!token_to_duration_ms(&tokens[count - 1], &valid_ms)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, &tokens[count - 1],
                             "invalid cache validity duration '%s'", tokens[count - 1].text);
                return false;
            }
            if (count == 1) {
                int default_codes[] = {200, 301, 302};
                for (size_t c = 0; c < 3 && server->cache_valid_rule_count < 8; c++) {
                    server->cache_valid_rules[server->cache_valid_rule_count].status_code = default_codes[c];
                    server->cache_valid_rules[server->cache_valid_rule_count].valid_ms = valid_ms;
                    server->cache_valid_rule_count++;
                }
            } else {
                for (size_t c = 0; c < count - 1 && server->cache_valid_rule_count < 8; c++) {
                    int code = 0;
                    if (token_is_word(&tokens[c], "any")) {
                        code = 0;
                    } else {
                        code = atoi(tokens[c].text);
                    }
                    server->cache_valid_rules[server->cache_valid_rule_count].status_code = code;
                    server->cache_valid_rules[server->cache_valid_rule_count].valid_ms = valid_ms;
                    server->cache_valid_rule_count++;
                }
            }
        } else if (token_is_word(directive, "set_real_ip_from")) {
            if (!config_parse_set_real_ip_from(parser, directive, server->real_ip_rules,
                                              &server->real_ip_rule_count, APEX_CONFIG_MAX_REAL_IP_RULES)) {
                return false;
            }
        } else if (token_is_word(directive, "real_ip_header")) {
            if (!config_parse_real_ip_header(parser, server->real_ip_header, sizeof(server->real_ip_header))) {
                return false;
            }
            server->has_real_ip_header = true;
        } else if (token_is_word(directive, "real_ip_recursive")) {
            if (!config_parse_real_ip_recursive(parser, &server->real_ip_recursive)) {
                return false;
            }
            server->has_real_ip_recursive = true;
        } else if (token_is_word(directive, "access_log")) {
            if (!config_parse_access_log(parser, directive, &server->access_log)) {
                return false;
            }
            server->has_access_log = true;
        } else if (token_is_word(directive, "root")) {
            const token_t *value = parser_scalar(parser, "a filesystem path");
            if (value == NULL) return false;
            server->root = config_strdup_range(value->text, value->length);
            if (server->root == NULL) return config_oom(parser->error);
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unknown server directive '%s'", directive->text);
            parser_hint(parser, "server accepts listen, server_name, tls, root, location, error_page, return, allow, deny, limit_req, limit_conn, proxy_cache, proxy_cache_key, proxy_cache_bypass, proxy_cache_valid, set_real_ip_from, real_ip_header, real_ip_recursive, access_log");
            return false;
        }

        if (!parser_expect_semicolon(parser)) {
            return false;
        }
    }

    if (!parser_expect_rbrace(parser)) {
        return false;
    }

    /* Inherit http-level real_ip and access_log settings */
    if (!server->has_access_log && parser->config->http.has_access_log) {
        server->access_log = parser->config->http.access_log;
        server->has_access_log = true;
    }
    if (server->real_ip_rule_count == 0 && parser->config->http.real_ip_rule_count > 0) {
        server->real_ip_rule_count = parser->config->http.real_ip_rule_count;
        memcpy(server->real_ip_rules, parser->config->http.real_ip_rules, sizeof(parser->config->http.real_ip_rules));
    }
    if (!server->has_real_ip_header && parser->config->http.has_real_ip_header) {
        snprintf(server->real_ip_header, sizeof(server->real_ip_header), "%s", parser->config->http.real_ip_header);
        server->has_real_ip_header = true;
    }
    if (!server->has_real_ip_recursive && parser->config->http.has_real_ip_recursive) {
        server->real_ip_recursive = parser->config->http.real_ip_recursive;
        server->has_real_ip_recursive = true;
    }

    if (!have_listen) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, begin, "server requires a listen directive");
        return false;
    }
    if (server->listen_tls && !server->tls.enabled) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, begin, "listen tls requires a tls block");
        return false;
    }
    return true;
}

static bool parse_upstream_server_item(parser_t *parser, apex_upstream_config_t *upstream) {
    const token_t *endpoint = parser_scalar(parser, "a backend address");
    if (endpoint == NULL) {
        return false;
    }

    char endpoint_text[APEX_CONFIG_HOST_MAX * 2u];
    if (endpoint->length >= sizeof(endpoint_text)) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, endpoint, "backend address is too long");
        return false;
    }
    memcpy(endpoint_text, endpoint->text, endpoint->length);
    endpoint_text[endpoint->length] = '\0';

    apex_upstream_server_config_t server;
    memset(&server, 0, sizeof(server));
    server.weight = 1u;
    server.line = endpoint->line;
    if (!parse_host_port(endpoint_text, false, false, server.host, sizeof(server.host), &server.port)) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, endpoint, "invalid backend address '%s'", endpoint->text);
        parser_hint(parser, "backend addresses use host:port or [ipv6]:port");
        return false;
    }

    while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
        const token_t *attribute = parser_peek(parser);
        if (attribute->kind == TOKEN_EOF || attribute->kind == TOKEN_RBRACE) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, attribute, "expected ';' after backend address");
            return false;
        }

        const char *name = attribute->text;
        size_t name_length = attribute->length;
        const char *equals = memchr(name, '=', name_length);
        size_t key_length = name_length;

        if (equals == NULL) {
            if (token_is_word(attribute, "backup")) {
                server.is_backup = true;
                parser_advance(parser);
                continue;
            }
            if (token_is_word(attribute, "down")) {
                server.is_down = true;
                parser_advance(parser);
                continue;
            }
        }

        if (equals != NULL) {
            key_length = (size_t)(equals - name);
        }
        parser_advance(parser);

        char option_text[64];
        const token_t *value_token = NULL;
        token_t inline_value;
        if (equals != NULL) {
            size_t value_length = name_length - key_length - 1u;
            if (value_length >= sizeof(option_text)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, attribute, "backend option value is too long");
                return false;
            }
            memcpy(option_text, equals + 1, value_length);
            option_text[value_length] = '\0';
            memset(&inline_value, 0, sizeof(inline_value));
            inline_value.kind = TOKEN_WORD;
            inline_value.text = option_text;
            inline_value.length = value_length;
            inline_value.line = attribute->line;
            inline_value.column = attribute->column;
            inline_value.file_index = attribute->file_index;
            value_token = &inline_value;
        } else {
            const token_t *equals_token = parser_peek(parser);
            if (equals_token->kind != TOKEN_WORD || strcmp(equals_token->text, "=") != 0) {
                parser_error(parser, APEX_CONFIG_ERR_SYNTAX, attribute,
                             "backend option '%s' requires '=' and a value", name);
                return false;
            }
            parser_advance(parser);
            value_token = parser_scalar(parser, "an option value");
            if (value_token == NULL) {
                return false;
            }
        }

        uint64_t parsed = 0;
        if (key_length == 6u && strncmp(name, "weight", 6u) == 0) {
            if (!token_to_u64(value_token, 1u, APEX_CONFIG_MAX_WEIGHT, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "weight must be between 1 and %u",
                             (unsigned)APEX_CONFIG_MAX_WEIGHT);
                return false;
            }
            server.weight = (uint32_t)parsed;
        } else if (key_length == 9u && strncmp(name, "max_conns", 9u) == 0) {
            if (!token_to_u64(value_token, 0u, APEX_CONFIG_MAX_CONNS, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "max_conns is out of range");
                return false;
            }
            server.max_conns = (uint32_t)parsed;
        } else if (key_length == 9u && strncmp(name, "max_fails", 9u) == 0) {
            if (!token_to_u64(value_token, 1u, 1000u, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "max_fails must be between 1 and 1000");
                return false;
            }
            upstream->max_fails = (uint32_t)parsed;
        } else if (key_length == 12u && strncmp(name, "fail_timeout", 12u) == 0) {
            if (!token_to_duration_ms(value_token, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "invalid duration for fail_timeout");
                return false;
            }
            upstream->fail_timeout_ms = parsed;
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, attribute, "unknown backend option");
            parser_hint(parser, "backend options are weight=<n>, max_conns=<n>, max_fails=<n>, fail_timeout=<dur>, backup, down");
            return false;
        }
    }

    if (!parser_expect_semicolon(parser)) {
        return false;
    }
    return upstream_add_server(parser, upstream, &server);
}

static bool parse_upstream_health_check_item(parser_t *parser, apex_upstream_config_t *upstream) {
    upstream->health_check_enabled = true;
    if (upstream->health_check_interval_ms == 0) {
        upstream->health_check_interval_ms = 5000;
    }
    if (upstream->health_check_timeout_ms == 0) {
        upstream->health_check_timeout_ms = 2000;
    }
    if (upstream->health_check_fall == 0) {
        upstream->health_check_fall = 2;
    }
    if (upstream->health_check_rise == 0) {
        upstream->health_check_rise = 2;
    }
    if (upstream->health_check_uri[0] == '\0') {
        snprintf(upstream->health_check_uri, sizeof(upstream->health_check_uri), "/");
    }

    while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
        const token_t *attribute = parser_peek(parser);
        if (attribute->kind == TOKEN_EOF || attribute->kind == TOKEN_RBRACE) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, attribute, "unterminated 'health_check' directive");
            return false;
        }
        if (attribute->kind != TOKEN_WORD && attribute->kind != TOKEN_STRING) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, attribute, "expected a health_check option");
            return false;
        }

        const char *name = attribute->text;
        size_t name_length = attribute->length;
        const char *equals = strchr(name, '=');
        size_t key_length = name_length;
        if (equals != NULL) {
            key_length = (size_t)(equals - name);
        }
        parser_advance(parser);

        char option_text[128];
        const token_t *value_token = NULL;
        token_t inline_value;
        if (equals != NULL) {
            size_t value_length = name_length - key_length - 1u;
            if (value_length >= sizeof(option_text)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, attribute, "health_check option value is too long");
                return false;
            }
            memcpy(option_text, equals + 1, value_length);
            option_text[value_length] = '\0';
            memset(&inline_value, 0, sizeof(inline_value));
            inline_value.kind = TOKEN_WORD;
            inline_value.text = option_text;
            inline_value.length = value_length;
            inline_value.line = attribute->line;
            inline_value.column = attribute->column;
            inline_value.file_index = attribute->file_index;
            value_token = &inline_value;
        } else {
            const token_t *equals_token = parser_peek(parser);
            if (equals_token->kind != TOKEN_WORD || strcmp(equals_token->text, "=") != 0) {
                parser_error(parser, APEX_CONFIG_ERR_SYNTAX, attribute,
                             "health_check option '%s' requires '=' and a value", name);
                return false;
            }
            parser_advance(parser);
            value_token = parser_scalar(parser, "an option value");
            if (value_token == NULL) {
                return false;
            }
        }

        uint64_t parsed = 0;
        if (key_length == 3u && strncmp(name, "uri", 3u) == 0) {
            if (value_token->length >= sizeof(upstream->health_check_uri)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "health_check uri is too long");
                return false;
            }
            snprintf(upstream->health_check_uri, sizeof(upstream->health_check_uri), "%s", value_token->text);
        } else if (key_length == 8u && strncmp(name, "interval", 8u) == 0) {
            if (!token_to_duration_ms(value_token, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "invalid duration for interval");
                return false;
            }
            upstream->health_check_interval_ms = parsed;
        } else if (key_length == 7u && strncmp(name, "timeout", 7u) == 0) {
            if (!token_to_duration_ms(value_token, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "invalid duration for timeout");
                return false;
            }
            upstream->health_check_timeout_ms = parsed;
        } else if (key_length == 4u && strncmp(name, "fall", 4u) == 0) {
            if (!token_to_u64(value_token, 1u, 100u, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "fall must be between 1 and 100");
                return false;
            }
            upstream->health_check_fall = (uint32_t)parsed;
        } else if (key_length == 4u && strncmp(name, "rise", 4u) == 0) {
            if (!token_to_u64(value_token, 1u, 100u, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value_token, "rise must be between 1 and 100");
                return false;
            }
            upstream->health_check_rise = (uint32_t)parsed;
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, attribute, "unknown health_check option");
            parser_hint(parser, "health_check options are uri=<path>, interval=<dur>, timeout=<dur>, fall=<n>, rise=<n>");
            return false;
        }
    }

    return parser_expect_semicolon(parser);
}

static bool parse_upstream_block(parser_t *parser) {
    const token_t *name = parser_identifier(parser, "an upstream name");
    if (name == NULL) {
        return false;
    }
    if (is_reserved_word(name->text)) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "reserved word '%s' cannot name an upstream",
                     name->text);
        return false;
    }
    if (apex_config_find_upstream(parser->config, name->text) != NULL) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "duplicate upstream '%s'", name->text);
        return false;
    }

    apex_upstream_config_t *upstream = config_add_upstream(parser, name);
    if (upstream == NULL) {
        return false;
    }

    if (!parser_expect_lbrace(parser)) {
        return false;
    }

    while (parser_peek(parser)->kind != TOKEN_RBRACE) {
        const token_t *directive = parser_peek(parser);
        if (directive->kind == TOKEN_EOF) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unterminated 'upstream' block");
            return false;
        }
        if (directive->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "expected an upstream directive");
            return false;
        }
        parser_advance(parser);

        if (token_is_word(directive, "server")) {
            if (!parse_upstream_server_item(parser, upstream)) {
                return false;
            }
            continue;
        }
        if (token_is_word(directive, "health_check")) {
            if (!parse_upstream_health_check_item(parser, upstream)) {
                return false;
            }
            continue;
        }
        if (token_is_word(directive, "least_conn") || token_is_word(directive, "least-conn")) {
            upstream->policy = APEX_BALANCE_LEAST_CONN;
        } else if (token_is_word(directive, "ip_hash") || token_is_word(directive, "ip-hash")) {
            upstream->policy = APEX_BALANCE_IP_HASH;
        } else if (token_is_word(directive, "policy") || token_is_word(directive, "algorithm")) {
            const token_t *value = parser_scalar(parser, "round_robin, p2c, least_conn, or ip_hash");
            if (value == NULL) {
                return false;
            }
            if (token_is_word(value, "round_robin") || token_is_word(value, "round-robin")) {
                upstream->policy = APEX_BALANCE_ROUND_ROBIN;
            } else if (token_is_word(value, "p2c")) {
                upstream->policy = APEX_BALANCE_P2C;
            } else if (token_is_word(value, "least_conn") || token_is_word(value, "least-conn")) {
                upstream->policy = APEX_BALANCE_LEAST_CONN;
            } else if (token_is_word(value, "ip_hash") || token_is_word(value, "ip-hash")) {
                upstream->policy = APEX_BALANCE_IP_HASH;
            } else {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "policy must be round_robin, p2c, least_conn, or ip_hash");
                return false;
            }
        } else if (token_is_word(directive, "keepalive")) {
            const token_t *value = parser_scalar(parser, "a connection count");
            if (value == NULL) {
                return false;
            }
            uint64_t parsed = 0;
            if (!token_to_u64(value, 0u, APEX_CONFIG_MAX_KEEPALIVE, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "keepalive is out of range");
                return false;
            }
            upstream->keepalive = (uint32_t)parsed;
        } else if (token_is_word(directive, "max_fails")) {
            const token_t *value = parser_scalar(parser, "a failure count");
            if (value == NULL) {
                return false;
            }
            uint64_t parsed = 0;
            if (!token_to_u64(value, 1u, 1000u, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "max_fails must be between 1 and 1000");
                return false;
            }
            upstream->max_fails = (uint32_t)parsed;
        } else if (token_is_word(directive, "fail_timeout")) {
            const token_t *value = parser_scalar(parser, "a duration");
            if (value == NULL) {
                return false;
            }
            uint64_t milliseconds = 0;
            if (!token_to_duration_ms(value, &milliseconds)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid duration for fail_timeout");
                return false;
            }
            upstream->fail_timeout_ms = milliseconds;
        } else if (token_is_word(directive, "max_retries")) {
            const token_t *value = parser_scalar(parser, "a retry count");
            if (value == NULL) {
                return false;
            }
            uint64_t parsed = 0;
            if (!token_to_u64(value, 0u, 64u, &parsed)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "max_retries must be between 0 and 64");
                return false;
            }
            upstream->max_retries = (uint32_t)parsed;
        } else if (token_is_word(directive, "connect_timeout") || token_is_word(directive, "read_timeout") ||
                   token_is_word(directive, "idle_timeout")) {
            const token_t *value = parser_scalar(parser, "a duration");
            if (value == NULL) {
                return false;
            }
            uint64_t milliseconds = 0;
            if (!token_to_duration_ms(value, &milliseconds)) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid duration");
                return false;
            }
            if (token_is_word(directive, "connect_timeout")) {
                upstream->connect_timeout_ms = milliseconds;
            } else if (token_is_word(directive, "read_timeout")) {
                upstream->read_timeout_ms = milliseconds;
            } else {
                upstream->idle_timeout_ms = milliseconds;
            }
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unknown upstream directive '%s'",
                         directive->text);
            parser_hint(parser, "upstream accepts server, policy, keepalive, connect_timeout, read_timeout, "
                                "idle_timeout, max_fails, fail_timeout, max_retries, health_check");
            return false;
        }

        if (!parser_expect_semicolon(parser)) {
            return false;
        }
    }

    if (!parser_expect_rbrace(parser)) {
        return false;
    }
    if (upstream->server_count == 0) {
        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, name, "upstream '%s' requires at least one server",
                     upstream->name);
        return false;
    }
    return true;
}

static bool parse_size_str(const char *text, size_t *value_bytes) {
    if (text == NULL || *text == '\0') return false;
    char *endptr = NULL;
    unsigned long long val = strtoull(text, &endptr, 10);
    if (endptr == text) return false;
    size_t multiplier = 1;
    if (*endptr == 'k' || *endptr == 'K') {
        multiplier = 1024ULL;
        endptr++;
    } else if (*endptr == 'm' || *endptr == 'M') {
        multiplier = 1024ULL * 1024ULL;
        endptr++;
    } else if (*endptr == 'g' || *endptr == 'G') {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
        endptr++;
    }
    if (*endptr != '\0') return false;
    *value_bytes = (size_t)(val * multiplier);
    return true;
}

static bool parse_rate_str(const char *text, double *rate_per_sec, uint32_t *rate_r_s) {
    if (text == NULL || *text == '\0') return false;
    char *endptr = NULL;
    double val = strtod(text, &endptr);
    if (endptr == text || val <= 0.0) return false;
    if (strcmp(endptr, "r/s") == 0) {
        *rate_per_sec = val;
        *rate_r_s = (uint32_t)ceil(val);
        return true;
    } else if (strcmp(endptr, "r/m") == 0) {
        *rate_per_sec = val / 60.0;
        *rate_r_s = (uint32_t)ceil(*rate_per_sec);
        if (*rate_r_s == 0) *rate_r_s = 1;
        return true;
    }
    return false;
}

static bool parse_http_directive(parser_t *parser, const token_t *directive) {
    if (token_is_word(directive, "worker_connections")) {
        const token_t *value = parser_scalar(parser, "a connection count");
        if (value == NULL) {
            return false;
        }
        uint64_t parsed = 0;
        if (!token_to_u64(value, 1u, 10000000u, &parsed)) {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "worker_connections is out of range");
            return false;
        }
        parser->config->http.worker_connections = (uint32_t)parsed;
    } else if (token_is_word(directive, "keepalive_timeout") ||
               token_is_word(directive, "client_header_timeout") ||
               token_is_word(directive, "client_body_timeout")) {
        const token_t *value = parser_scalar(parser, "a duration");
        if (value == NULL) {
            return false;
        }
        uint64_t milliseconds = 0;
        if (!token_to_duration_ms(value, &milliseconds)) {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "invalid duration");
            return false;
        }
        if (token_is_word(directive, "keepalive_timeout")) {
            parser->config->http.keepalive_timeout_ms = milliseconds;
        } else if (token_is_word(directive, "client_header_timeout")) {
            parser->config->http.client_header_timeout_ms = milliseconds;
        } else {
            parser->config->http.client_body_timeout_ms = milliseconds;
        }
    } else if (token_is_word(directive, "server_tokens")) {
        const token_t *value = parser_scalar(parser, "on or off");
        if (value == NULL) {
            return false;
        }
        if (token_is_word(value, "on")) {
            parser->config->http.server_tokens = true;
        } else if (token_is_word(value, "off")) {
            parser->config->http.server_tokens = false;
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, value, "server_tokens must be on or off");
            return false;
        }
    } else if (token_is_word(directive, "limit_req_zone")) {
        if (parser->config->http.rate_zone_count >= APEX_CONFIG_MAX_RATE_ZONES) {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "too many rate limit zones (max %u)",
                         APEX_CONFIG_MAX_RATE_ZONES);
            return false;
        }
        apex_rate_limit_zone_t *zone = &parser->config->http.rate_zones[parser->config->http.rate_zone_count];
        memset(zone, 0, sizeof(*zone));

        while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
            const token_t *arg = parser_scalar(parser, "limit_req_zone parameter");
            if (arg == NULL) return false;
            if (arg->text[0] == '$') {
                snprintf(zone->key_var, sizeof(zone->key_var), "%s", arg->text);
            } else if (strncmp(arg->text, "zone=", 5) == 0) {
                const char *spec = arg->text + 5;
                const char *colon = strchr(spec, ':');
                if (colon != NULL) {
                    size_t name_len = (size_t)(colon - spec);
                    if (name_len >= sizeof(zone->name)) name_len = sizeof(zone->name) - 1;
                    memcpy(zone->name, spec, name_len);
                    zone->name[name_len] = '\0';
                    if (!parse_size_str(colon + 1, &zone->size_bytes)) {
                        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid zone size '%s'", colon + 1);
                        return false;
                    }
                } else {
                    snprintf(zone->name, sizeof(zone->name), "%s", spec);
                }
            } else if (strncmp(arg->text, "rate=", 5) == 0) {
                if (!parse_rate_str(arg->text + 5, &zone->rate_per_sec, &zone->rate_r_s)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid rate '%s'", arg->text + 5);
                    return false;
                }
            }
        }
        if (zone->name[0] == '\0') {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "limit_req_zone requires a zone name");
            return false;
        }
        if (zone->rate_per_sec <= 0.0) {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "limit_req_zone requires rate=<num>r/s or rate=<num>r/m");
            return false;
        }
        parser->config->http.rate_zone_count++;
    } else if (token_is_word(directive, "limit_conn_zone")) {
        if (parser->config->http.conn_zone_count >= APEX_CONFIG_MAX_CONN_ZONES) {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "too many conn limit zones (max %u)",
                         APEX_CONFIG_MAX_CONN_ZONES);
            return false;
        }
        apex_conn_limit_zone_t *zone = &parser->config->http.conn_zones[parser->config->http.conn_zone_count];
        memset(zone, 0, sizeof(*zone));

        while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
            const token_t *arg = parser_scalar(parser, "limit_conn_zone parameter");
            if (arg == NULL) return false;
            if (arg->text[0] == '$') {
                snprintf(zone->key_var, sizeof(zone->key_var), "%s", arg->text);
            } else if (strncmp(arg->text, "zone=", 5) == 0) {
                const char *spec = arg->text + 5;
                const char *colon = strchr(spec, ':');
                if (colon != NULL) {
                    size_t name_len = (size_t)(colon - spec);
                    if (name_len >= sizeof(zone->name)) name_len = sizeof(zone->name) - 1;
                    memcpy(zone->name, spec, name_len);
                    zone->name[name_len] = '\0';
                    if (!parse_size_str(colon + 1, &zone->size_bytes)) {
                        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid zone size '%s'", colon + 1);
                        return false;
                    }
                } else {
                    snprintf(zone->name, sizeof(zone->name), "%s", spec);
                }
            }
        }
        if (zone->name[0] == '\0') {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "limit_conn_zone requires a zone name");
            return false;
        }
        parser->config->http.conn_zone_count++;
    } else if (token_is_word(directive, "proxy_cache_path")) {
        if (parser->config->http.cache_zone_count >= APEX_CONFIG_MAX_RATE_ZONES) {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "too many cache zones (max %u)",
                         APEX_CONFIG_MAX_RATE_ZONES);
            return false;
        }
        apex_cache_zone_config_t *zone = &parser->config->http.cache_zones[parser->config->http.cache_zone_count];
        memset(zone, 0, sizeof(*zone));

        const token_t *path_arg = parser_scalar(parser, "cache path");
        if (path_arg == NULL) return false;
        snprintf(zone->path, sizeof(zone->path), "%s", path_arg->text);
        zone->inactive_ms = 600000; /* default 10m */
        zone->max_size = 1024ULL * 1024ULL * 1024ULL; /* default 1GB */
        zone->keys_zone_size = 10 * 1024 * 1024; /* default 10MB */

        while (parser_peek(parser)->kind != TOKEN_SEMICOLON) {
            const token_t *arg = parser_scalar(parser, "proxy_cache_path parameter");
            if (arg == NULL) return false;
            if (strncmp(arg->text, "keys_zone=", 10) == 0) {
                const char *spec = arg->text + 10;
                const char *colon = strchr(spec, ':');
                if (colon != NULL) {
                    size_t name_len = (size_t)(colon - spec);
                    if (name_len >= sizeof(zone->name)) name_len = sizeof(zone->name) - 1;
                    memcpy(zone->name, spec, name_len);
                    zone->name[name_len] = '\0';
                    if (!parse_size_str(colon + 1, &zone->keys_zone_size)) {
                        parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid keys_zone size '%s'", colon + 1);
                        return false;
                    }
                } else {
                    snprintf(zone->name, sizeof(zone->name), "%s", spec);
                }
            } else if (strncmp(arg->text, "max_size=", 9) == 0) {
                if (!parse_size_str(arg->text + 9, &zone->max_size)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid max_size '%s'", arg->text + 9);
                    return false;
                }
            } else if (strncmp(arg->text, "inactive=", 9) == 0) {
                token_t temp_tok = *arg;
                temp_tok.text = arg->text + 9;
                temp_tok.length = strlen(temp_tok.text);
                if (!token_to_duration_ms(&temp_tok, &zone->inactive_ms)) {
                    parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, arg, "invalid inactive duration '%s'", arg->text + 9);
                    return false;
                }
            } else if (strncmp(arg->text, "levels=", 7) == 0) {
                /* standard nginx levels=1:2 (supported) */
            }
        }
        if (zone->name[0] == '\0') {
            parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, directive, "proxy_cache_path requires keys_zone=<name>:<size>");
            return false;
        }
        parser->config->http.cache_zone_count++;
    } else if (token_is_word(directive, "log_format")) {
        if (!config_parse_log_format(parser, directive)) {
            return false;
        }
    } else if (token_is_word(directive, "access_log")) {
        if (!config_parse_access_log(parser, directive, &parser->config->http.access_log)) {
            return false;
        }
        parser->config->http.has_access_log = true;
    } else if (token_is_word(directive, "set_real_ip_from")) {
        if (!config_parse_set_real_ip_from(parser, directive, parser->config->http.real_ip_rules,
                                          &parser->config->http.real_ip_rule_count, APEX_CONFIG_MAX_REAL_IP_RULES)) {
            return false;
        }
    } else if (token_is_word(directive, "real_ip_header")) {
        if (!config_parse_real_ip_header(parser, parser->config->http.real_ip_header,
                                         sizeof(parser->config->http.real_ip_header))) {
            return false;
        }
        parser->config->http.has_real_ip_header = true;
    } else if (token_is_word(directive, "real_ip_recursive")) {
        if (!config_parse_real_ip_recursive(parser, &parser->config->http.real_ip_recursive)) {
            return false;
        }
        parser->config->http.has_real_ip_recursive = true;
    } else {
        parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unknown http directive '%s'", directive->text);
        parser_hint(parser, "http accepts worker_connections, keepalive_timeout, client_header_timeout, "
                            "client_body_timeout, server_tokens, limit_req_zone, limit_conn_zone, proxy_cache_path, log_format, access_log, set_real_ip_from, real_ip_header, real_ip_recursive, upstream, server");
        return false;
    }
    return true;
}

static bool parse_http_block(parser_t *parser) {
    if (!parser_expect_lbrace(parser)) {
        return false;
    }

    while (parser_peek(parser)->kind != TOKEN_RBRACE) {
        const token_t *directive = parser_peek(parser);
        if (directive->kind == TOKEN_EOF) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unterminated 'http' block");
            return false;
        }
        if (directive->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "expected an http item");
            return false;
        }
        parser_advance(parser);

        if (token_is_word(directive, "upstream")) {
            if (!parse_upstream_block(parser)) {
                return false;
            }
        } else if (token_is_word(directive, "server")) {
            if (!parse_server_block(parser)) {
                return false;
            }
        } else if (token_is_word(directive, "http") || token_is_word(directive, "modules") ||
                   token_is_word(directive, "include")) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "'%s' is not allowed inside http",
                         directive->text);
            return false;
        } else {
            if (!parse_http_directive(parser, directive) || !parser_expect_semicolon(parser)) {
                return false;
            }
        }
    }

    return parser_expect_rbrace(parser);
}

static bool parse_modules_block(parser_t *parser) {
    if (!parser_expect_lbrace(parser)) {
        return false;
    }

    while (parser_peek(parser)->kind != TOKEN_RBRACE) {
        const token_t *directive = parser_peek(parser);
        if (directive->kind == TOKEN_EOF) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unterminated 'modules' block");
            return false;
        }
        if (directive->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "expected a modules directive");
            return false;
        }
        parser_advance(parser);

        if (token_is_word(directive, "load") || token_is_word(directive, "enable")) {
            const token_t *name = parser_scalar(parser, "a module name");
            if (name == NULL) {
                return false;
            }
            if (!config_add_module(parser, name)) {
                return false;
            }
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, directive, "unknown modules directive '%s'",
                         directive->text);
            parser_hint(parser, "modules accepts load <name> and enable <name>");
            return false;
        }

        if (!parser_expect_semicolon(parser)) {
            return false;
        }
    }

    return parser_expect_rbrace(parser);
}

static bool validate_config(parser_t *parser) {
    apex_config_t *config = parser->config;

    for (size_t server_index = 0; server_index < config->server_count; server_index++) {
        apex_server_config_t *server = &config->servers[server_index];
        for (size_t location_index = 0; location_index < server->location_count; location_index++) {
            apex_location_config_t *location = &server->locations[location_index];
            if (location->target != APEX_PROXY_TARGET_UPSTREAM) {
                continue;
            }

            const apex_upstream_config_t *upstream =
                apex_config_find_upstream(config, location->upstream_name);
            if (upstream == NULL) {
                parser_error(parser, APEX_CONFIG_ERR_SEMANTIC, NULL, "unresolved upstream '%s'",
                             location->upstream_name);
                parser->error->line = location->line;
                return false;
            }
            location->upstream_index = (size_t)(upstream - config->upstreams);
        }
    }

    return true;
}

static bool parse_events_block(parser_t *parser) {
    if (!parser_expect_lbrace(parser)) {
        return false;
    }
    while (parser_peek(parser)->kind != TOKEN_RBRACE) {
        const token_t *tok = parser_peek(parser);
        if (tok->kind == TOKEN_EOF) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, tok, "unterminated 'events' block");
            return false;
        }
        if (tok->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, tok, "expected an events directive");
            return false;
        }
        parser_advance(parser);
        if (token_is_word(tok, "worker_connections")) {
            const token_t *val = parser_scalar(parser, "number of worker connections");
            if (val == NULL) {
                return false;
            }
            uint64_t conns = 0;
            if (token_to_u64(val, 1, 1000000, &conns)) {
                parser->config->http.worker_connections = (size_t)conns;
            }
            if (!parser_expect_semicolon(parser)) {
                return false;
            }
        } else {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON &&
                   parser_peek(parser)->kind != TOKEN_RBRACE &&
                   parser_peek(parser)->kind != TOKEN_EOF) {
                parser_advance(parser);
            }
            if (!parser_expect_semicolon(parser)) {
                return false;
            }
        }
    }
    return parser_expect_rbrace(parser);
}

static bool parse_tokens(parser_t *parser) {
    while (parser_peek(parser)->kind != TOKEN_EOF) {
        const token_t *item = parser_peek(parser);
        if (item->kind != TOKEN_WORD) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, item, "expected a top-level directive");
            return false;
        }
        parser_advance(parser);

        if (token_is_word(item, "http")) {
            if (!parse_http_block(parser)) {
                return false;
            }
        } else if (token_is_word(item, "modules")) {
            if (!parse_modules_block(parser)) {
                return false;
            }
        } else if (token_is_word(item, "events")) {
            if (!parse_events_block(parser)) {
                return false;
            }
        } else if (token_is_word(item, "worker_processes") || token_is_word(item, "pid") ||
                   token_is_word(item, "error_log") || token_is_word(item, "user") ||
                   token_is_word(item, "worker_rlimit_nofile")) {
            while (parser_peek(parser)->kind != TOKEN_SEMICOLON &&
                   parser_peek(parser)->kind != TOKEN_EOF) {
                parser_advance(parser);
            }
            if (!parser_expect_semicolon(parser)) {
                return false;
            }
        } else if (token_is_word(item, "include")) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, item,
                         "include is only available when parsing a file");
            return false;
        } else if (token_is_word(item, "upstream") || token_is_word(item, "server") ||
                   token_is_word(item, "location") || token_is_word(item, "tls")) {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, item, "'%s' must be declared inside http", item->text);
            return false;
        } else {
            parser_error(parser, APEX_CONFIG_ERR_SYNTAX, item, "unknown top-level directive '%s'", item->text);
            parser_hint(parser, "top-level items are http, events, and modules");
            return false;
        }
    }
    return true;
}

static void config_init_defaults(apex_config_t *config) {
    memset(config, 0, sizeof(*config));
    config->http.worker_connections = APEX_CONFIG_DEFAULT_WORKER_CONNECTIONS;
    config->http.keepalive_timeout_ms = APEX_CONFIG_DEFAULT_KEEPALIVE_MS;
    config->http.client_header_timeout_ms = APEX_CONFIG_DEFAULT_CLIENT_HEADER_MS;
    config->http.client_body_timeout_ms = APEX_CONFIG_DEFAULT_CLIENT_BODY_MS;
    config->http.server_tokens = false;
}

int apex_config_parse_string(const char *name, const char *text, size_t length, apex_config_t **config_out,
                             apex_config_error_t *error) {
    if (config_out == NULL || text == NULL) {
        config_error_set(error, APEX_CONFIG_ERR_IO, name, 0, 0, "invalid configuration input");
        return APEX_CONFIG_ERR_IO;
    }
    *config_out = NULL;
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
    }

    const char *source_name = name != NULL ? name : "<memory>";

    apex_config_t *config = calloc(1, sizeof(*config));
    if (config == NULL) {
        config_oom(error);
        return APEX_CONFIG_ERR_MEMORY;
    }
    config_init_defaults(config);
    snprintf(config->source, sizeof(config->source), "%s", source_name);

    token_list_t tokens;
    token_list_init(&tokens);
    if (token_list_register_file(&tokens, source_name, error) < 0) {
        apex_config_free(config);
        return APEX_CONFIG_ERR_MEMORY;
    }

    lexer_t lexer = {
        .data = text,
        .length = length,
        .position = 0,
        .line = 1,
        .column = 1,
        .file_index = 0,
        .tokens = &tokens,
        .error = error,
    };

    bool ok = lexer_run(&lexer);
    if (ok) {
        token_t eof = {
            .kind = TOKEN_EOF,
            .text = NULL,
            .length = 0,
            .file_index = 0,
            .line = lexer.line,
            .column = lexer.column,
        };
        ok = token_list_push(&tokens, eof, error);
    }

    if (ok) {
        parser_t parser = {
            .tokens = &tokens,
            .index = 0,
            .config = config,
            .error = error,
        };
        ok = parse_tokens(&parser) && validate_config(&parser);
    }

    token_list_free(&tokens);

    if (!ok) {
        apex_config_free(config);
        return error != NULL && error->code != APEX_CONFIG_OK ? error->code : APEX_CONFIG_ERR_SYNTAX;
    }

    *config_out = config;
    return APEX_CONFIG_OK;
}

int apex_config_parse_file(const char *path, apex_config_t **config_out, apex_config_error_t *error) {
    if (config_out == NULL || path == NULL) {
        config_error_set(error, APEX_CONFIG_ERR_IO, path, 0, 0, "invalid configuration path");
        return APEX_CONFIG_ERR_IO;
    }
    *config_out = NULL;
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
    }

    token_list_t tokens;
    token_list_init(&tokens);
    char *stack[APEX_CONFIG_MAX_INCLUDE_DEPTH];
    memset(stack, 0, sizeof(stack));

    bool ok = tokenize_source(path, &tokens, stack, 0, error);
    for (size_t index = 0; index < APEX_CONFIG_MAX_INCLUDE_DEPTH; index++) {
        free(stack[index]);
    }

    if (ok) {
        token_t eof = {
            .kind = TOKEN_EOF,
            .text = NULL,
            .length = 0,
            .file_index = 0,
            .line = 0,
            .column = 0,
        };
        ok = token_list_push(&tokens, eof, error);
    }

    apex_config_t *config = NULL;
    if (ok) {
        config = calloc(1, sizeof(*config));
        if (config == NULL) {
            config_oom(error);
            ok = false;
        } else {
            config_init_defaults(config);
            char canonical[APEX_CONFIG_PATH_MAX];
            if (canonical_path(path, canonical, sizeof(canonical), error)) {
                snprintf(config->source, sizeof(config->source), "%s", canonical);
            } else {
                snprintf(config->source, sizeof(config->source), "%s", path);
                ok = false;
            }
        }
    }

    if (ok) {
        parser_t parser = {
            .tokens = &tokens,
            .index = 0,
            .config = config,
            .error = error,
        };
        ok = parse_tokens(&parser) && validate_config(&parser);
    }

    token_list_free(&tokens);

    if (!ok) {
        apex_config_free(config);
        return error != NULL && error->code != APEX_CONFIG_OK ? error->code : APEX_CONFIG_ERR_SYNTAX;
    }

    if (config->server_count == 0) {
        config_error_set(error, APEX_CONFIG_ERR_SEMANTIC, config->source, 0, 0,
                         "configuration declares no server blocks");
        apex_config_free(config);
        return APEX_CONFIG_ERR_SEMANTIC;
    }

    *config_out = config;
    return APEX_CONFIG_OK;
}

int apex_config_check_file(const char *path, apex_config_error_t *error) {
    apex_config_t *config = NULL;
    int status = apex_config_parse_file(path, &config, error);
    apex_config_free(config);
    return status;
}

void apex_config_free(apex_config_t *config) {
    if (config == NULL) {
        return;
    }

    for (size_t upstream_index = 0; upstream_index < config->upstream_count; upstream_index++) {
        apex_upstream_config_t *upstream = &config->upstreams[upstream_index];
        free(upstream->name);
        free(upstream->servers);
    }
    free(config->upstreams);

    for (size_t server_index = 0; server_index < config->server_count; server_index++) {
        apex_server_config_t *server = &config->servers[server_index];
        for (size_t name_index = 0; name_index < server->server_name_count; name_index++) {
            free(server->server_names[name_index]);
        }
        free(server->server_names);

        free(server->tls.certificate);
        free(server->tls.private_key);
        free(server->tls.ciphers);
        for (size_t protocol_index = 0; protocol_index < server->tls.protocol_count; protocol_index++) {
            free(server->tls.protocols[protocol_index]);
        }
        free(server->tls.protocols);

        for (size_t location_index = 0; location_index < server->location_count; location_index++) {
            apex_location_config_t *location = &server->locations[location_index];
            free(location->path);
            free(location->upstream_name);
            free(location->endpoint_host);
            free(location->root);
            for (size_t idx = 0; idx < location->index_count; idx++) {
                free(location->indices[idx]);
            }
            free(location->indices);
            for (size_t tf = 0; tf < location->try_files_count; tf++) {
                free(location->try_files[tf]);
            }
            free(location->try_files);
            for (size_t header_index = 0; header_index < location->header_count; header_index++) {
                free(location->headers[header_index].name);
                free(location->headers[header_index].value);
            }
            free(location->headers);
            for (size_t p_index = 0; p_index < location->fastcgi_param_count; p_index++) {
                free(location->fastcgi_params[p_index].name);
                free(location->fastcgi_params[p_index].value);
            }
            free(location->fastcgi_params);
        }
        free(server->locations);

        for (size_t ep_index = 0; ep_index < server->error_page_count; ep_index++) {
            free(server->error_pages[ep_index].path);
        }
        free(server->error_pages);
        free(server->root);
    }
    free(config->servers);

    for (size_t module_index = 0; module_index < config->module_count; module_index++) {
        free(config->modules[module_index]);
    }
    free(config->modules);

    free(config);
}

const char *apex_config_strerror(apex_config_status_t code) {
    switch (code) {
    case APEX_CONFIG_OK:
        return "success";
    case APEX_CONFIG_ERR_IO:
        return "configuration I/O error";
    case APEX_CONFIG_ERR_SYNTAX:
        return "configuration syntax error";
    case APEX_CONFIG_ERR_SEMANTIC:
        return "configuration validation error";
    case APEX_CONFIG_ERR_MEMORY:
        return "out of memory";
    case APEX_CONFIG_ERR_RUNTIME:
        return "configuration runtime error";
    default:
        return "unknown configuration error";
    }
}

const apex_upstream_config_t *apex_config_find_upstream(const apex_config_t *config, const char *name) {
    if (config == NULL || name == NULL) {
        return NULL;
    }
    for (size_t index = 0; index < config->upstream_count; index++) {
        if (config->upstreams[index].name != NULL && strcmp(config->upstreams[index].name, name) == 0) {
            return &config->upstreams[index];
        }
    }
    return NULL;
}

int apex_config_first_listen_port(const apex_config_t *config) {
    if (config == NULL) {
        return -1;
    }
    for (size_t index = 0; index < config->server_count; index++) {
        if (config->servers[index].listen_port != 0) {
            return (int)config->servers[index].listen_port;
        }
    }
    return -1;
}

static bool runtime_error_at(apex_config_error_t *error, const char *file, int line, const char *format, ...) {
    if (error == NULL) {
        return false;
    }
    error->code = APEX_CONFIG_ERR_RUNTIME;
    error->line = line;
    error->column = 0;
    error->message[0] = '\0';
    error->hint[0] = '\0';
    snprintf(error->file, sizeof(error->file), "%s", file != NULL ? file : "");
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(error->message, sizeof(error->message), format, arguments);
    va_end(arguments);
    return false;
}

apex_runtime_t *apex_runtime_create(const apex_config_t *config, apex_config_error_t *error) {
    if (config == NULL) {
        runtime_error_at(error, NULL, 0, "configuration is null");
        return NULL;
    }
    if (error != NULL) {
        memset(error, 0, sizeof(*error));
    }

    apex_runtime_t *runtime = calloc(1, sizeof(*runtime));
    if (runtime == NULL) {
        config_oom(error);
        return NULL;
    }
    runtime->config = config;

    if (config->upstream_count > 0) {
        runtime->groups = calloc(config->upstream_count, sizeof(*runtime->groups));
        if (runtime->groups == NULL) {
            config_oom(error);
            apex_runtime_destroy(runtime);
            return NULL;
        }
    }

    for (size_t index = 0; index < config->upstream_count; index++) {
        const apex_upstream_config_t *source = &config->upstreams[index];
        upstream_group_t *group = &runtime->groups[index];
        apex_upstream_group_init(group);
        group->keepalive_capacity = source->keepalive;
        group->connect_timeout_ms = source->connect_timeout_ms;
        group->io_timeout_ms = source->read_timeout_ms;
        group->idle_timeout_ms = source->idle_timeout_ms;
        if (source->max_fails > 0) {
            group->max_fails = source->max_fails;
        }
        if (source->fail_timeout_ms > 0) {
            group->fail_timeout_ms = source->fail_timeout_ms;
        }
        if (source->max_retries > 0) {
            group->max_retries = source->max_retries;
        }
        group->health_check_enabled = source->health_check_enabled;
        if (source->health_check_enabled) {
            snprintf(group->health_check_uri, sizeof(group->health_check_uri), "%s", source->health_check_uri);
            group->health_check_interval_ms = source->health_check_interval_ms;
            group->health_check_timeout_ms = source->health_check_timeout_ms;
            group->health_check_fall = source->health_check_fall;
            group->health_check_rise = source->health_check_rise;
        }
        apex_upstream_set_policy(group, source->policy);

        for (size_t server_index = 0; server_index < source->server_count; server_index++) {
            const apex_upstream_server_config_t *server = &source->servers[server_index];
            if (apex_upstream_add_server_ex(group, server->host, server->port, server->weight,
                                            server->is_backup, server->is_down) < 0) {
                runtime_error_at(error, config->source, server->line, "cannot resolve upstream '%s' server %s:%u",
                                 source->name, server->host, (unsigned)server->port);
                apex_runtime_destroy(runtime);
                return NULL;
            }
        }
        runtime->group_count++;
    }

    size_t endpoint_count = 0;
    for (size_t server_index = 0; server_index < config->server_count; server_index++) {
        const apex_server_config_t *server = &config->servers[server_index];
        for (size_t location_index = 0; location_index < server->location_count; location_index++) {
            if (server->locations[location_index].target == APEX_PROXY_TARGET_ENDPOINT) {
                endpoint_count++;
            }
        }
    }

    if (endpoint_count > 0) {
        runtime->endpoint_groups = calloc(endpoint_count, sizeof(*runtime->endpoint_groups));
        if (runtime->endpoint_groups == NULL) {
            config_oom(error);
            apex_runtime_destroy(runtime);
            return NULL;
        }
    }

    for (size_t server_index = 0; server_index < config->server_count; server_index++) {
        const apex_server_config_t *server = &config->servers[server_index];
        for (size_t location_index = 0; location_index < server->location_count; location_index++) {
            const apex_location_config_t *location = &server->locations[location_index];
            if (location->target != APEX_PROXY_TARGET_ENDPOINT) {
                continue;
            }

            apex_endpoint_group_t *entry = &runtime->endpoint_groups[runtime->endpoint_group_count];
            entry->location = location;
            apex_upstream_group_init(&entry->group);
            entry->group.connect_timeout_ms =
                location->has_connect_timeout ? location->connect_timeout_ms : APEX_CONFIG_DEFAULT_CONNECT_MS;
            entry->group.io_timeout_ms =
                location->has_read_timeout ? location->read_timeout_ms : APEX_CONFIG_DEFAULT_READ_MS;

            if (apex_upstream_add_server(&entry->group, location->endpoint_host, location->endpoint_port, 1u) <
                0) {
                runtime_error_at(error, config->source, location->line, "cannot resolve proxy endpoint %s:%u",
                                 location->endpoint_host, (unsigned)location->endpoint_port);
                apex_runtime_destroy(runtime);
                return NULL;
            }
            runtime->endpoint_group_count++;
        }
    }

    if (apex_module_registry_init(runtime, config, error) != 0) {
        apex_runtime_destroy(runtime);
        return NULL;
    }

    if (config->http.rate_zone_count > 0 || config->http.conn_zone_count > 0) {
        rate_limiter_t *limiter = calloc(1, sizeof(*limiter));
        if (limiter != NULL) {
            for (size_t i = 0; i < APEX_RATELIMIT_SHARDS; i++) {
                pthread_mutex_init(&limiter->shards[i].lock, NULL);
            }
            runtime->rate_limiter = limiter;
        }
    }

    if (config->http.cache_zone_count > 0) {
        runtime->cache_manager = apex_cache_manager_create(config);
    }

    apex_health_prober_start(runtime->groups, runtime->group_count);
    apex_log_manager_init(runtime);
    return runtime;
}

void apex_runtime_destroy(apex_runtime_t *runtime) {
    if (runtime == NULL) {
        return;
    }
    apex_health_prober_stop();
    apex_module_registry_destroy(runtime);
    if (runtime->log_manager != NULL) {
        apex_log_manager_destroy(runtime);
        runtime->log_manager = NULL;
    }
    if (runtime->cache_manager != NULL) {
        apex_cache_manager_destroy((apex_cache_manager_t *)runtime->cache_manager);
        runtime->cache_manager = NULL;
    }
    if (runtime->rate_limiter != NULL) {
        rate_limiter_t *limiter = (rate_limiter_t *)runtime->rate_limiter;
        for (size_t i = 0; i < APEX_RATELIMIT_SHARDS; i++) {
            pthread_mutex_destroy(&limiter->shards[i].lock);
            rate_entry_t *entry = limiter->shards[i].head;
            while (entry != NULL) {
                rate_entry_t *next = entry->next;
                free(entry);
                entry = next;
            }
        }
        free(limiter);
        runtime->rate_limiter = NULL;
    }
    free(runtime->groups);
    free(runtime->endpoint_groups);
    free(runtime);
}

const upstream_group_t *apex_runtime_upstream(const apex_runtime_t *runtime, size_t index) {
    if (runtime == NULL || index >= runtime->group_count) {
        return NULL;
    }
    return &runtime->groups[index];
}

const upstream_group_t *apex_runtime_endpoint_group(const apex_runtime_t *runtime,
                                                    const apex_location_config_t *location) {
    if (runtime == NULL || location == NULL) {
        return NULL;
    }
    for (size_t index = 0; index < runtime->endpoint_group_count; index++) {
        if (runtime->endpoint_groups[index].location == location) {
            return &runtime->endpoint_groups[index].group;
        }
    }
    return NULL;
}

static bool host_matches_name(const char *name, const char *host, size_t host_length) {
    return strlen(name) == host_length && strncasecmp(name, host, host_length) == 0;
}

static void strip_host_port(const char *host, size_t host_length, const char **name, size_t *name_length) {
    *name = host;
    *name_length = host_length;
    if (host_length == 0) {
        return;
    }
    if (host[0] == '[') {
        const char *close = memchr(host, ']', host_length);
        if (close != NULL) {
            *name = host + 1;
            *name_length = (size_t)(close - (host + 1));
        }
        return;
    }
    const char *colon = memchr(host, ':', host_length);
    if (colon != NULL && memchr(colon + 1, ':', (size_t)((host + host_length) - (colon + 1))) == NULL) {
        *name_length = (size_t)(colon - host);
    }
}

static bool server_matches_host(const apex_server_config_t *server, const char *host, size_t host_length) {
    const char *name = NULL;
    size_t name_length = 0;
    strip_host_port(host, host_length, &name, &name_length);
    for (size_t index = 0; index < server->server_name_count; index++) {
        if (host_matches_name(server->server_names[index], name, name_length)) {
            return true;
        }
    }
    return false;
}

static const apex_location_config_t *select_location(const apex_server_config_t *server, const char *path,
                                                     size_t path_length) {
    const apex_location_config_t *best_prefix = NULL;
    size_t best_length = 0;

    for (size_t index = 0; index < server->location_count; index++) {
        const apex_location_config_t *location = &server->locations[index];
        size_t length = strlen(location->path);
        if (location->exact) {
            if (length == path_length && memcmp(location->path, path, path_length) == 0) {
                return location;
            }
            continue;
        }
        if (length <= path_length && memcmp(location->path, path, length) == 0 && length > best_length) {
            best_prefix = location;
            best_length = length;
        }
    }

    return best_prefix;
}

bool apex_runtime_match(const apex_runtime_t *runtime, const char *host, size_t host_length, const char *path,
                        size_t path_length, apex_config_route_t *route) {
    if (runtime == NULL || runtime->config == NULL || route == NULL || path == NULL) {
        return false;
    }

    const apex_config_t *config = runtime->config;
    if (config->server_count == 0) {
        return false;
    }

    const apex_server_config_t *server = NULL;
    for (size_t index = 0; index < config->server_count; index++) {
        if (server_matches_host(&config->servers[index], host, host_length)) {
            server = &config->servers[index];
            break;
        }
    }
    if (server == NULL) {
        server = &config->servers[0];
    }

    const apex_location_config_t *location = select_location(server, path, path_length);
    if (location == NULL) {
        if (server->return_code > 0) {
            memset(route, 0, sizeof(*route));
            route->server = server;
            route->location = NULL;
            return true;
        }
        return false;
    }

    memset(route, 0, sizeof(*route));
    route->server = server;
    route->location = location;
    route->upstream_index = location->upstream_index;

    if (location->target == APEX_PROXY_TARGET_UPSTREAM) {
        route->group = apex_runtime_upstream(runtime, location->upstream_index);
    } else if (location->target == APEX_PROXY_TARGET_ENDPOINT) {
        route->group = apex_runtime_endpoint_group(runtime, location);
    }

    return true;
}

static inline uint32_t ratelimit_hash(const char *zone, const char *key) {
    uint32_t h = 2166136261u;
    if (zone != NULL) {
        for (const char *p = zone; *p; p++) {
            h ^= (uint8_t)*p;
            h *= 16777619u;
        }
    }
    h ^= 0x5c;
    h *= 16777619u;
    if (key != NULL) {
        for (const char *p = key; *p; p++) {
            h ^= (uint8_t)*p;
            h *= 16777619u;
        }
    }
    return h;
}

bool apex_rate_limit_check(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip,
                           uint32_t burst, bool nodelay, uint32_t *retry_after_sec) {
    (void)nodelay;
    if (runtime == NULL || runtime->config == NULL || zone_name == NULL || zone_name[0] == '\0') {
        return true;
    }
    if (runtime->rate_limiter == NULL) {
        return true;
    }

    const apex_rate_limit_zone_t *zone = NULL;
    for (size_t i = 0; i < runtime->config->http.rate_zone_count; i++) {
        if (strcmp(runtime->config->http.rate_zones[i].name, zone_name) == 0) {
            zone = &runtime->config->http.rate_zones[i];
            break;
        }
    }
    if (zone == NULL || zone->rate_per_sec <= 0.0) {
        return true;
    }

    char key_buf[128];
    snprintf(key_buf, sizeof(key_buf), "%s:%s", zone_name,
             client_ip != NULL && client_ip[0] != '\0' ? client_ip : "127.0.0.1");

    rate_limiter_t *limiter = (rate_limiter_t *)runtime->rate_limiter;
    uint32_t shard_idx = ratelimit_hash(zone_name, client_ip) % APEX_RATELIMIT_SHARDS;
    rate_shard_t *shard = &limiter->shards[shard_idx];

    pthread_mutex_lock(&shard->lock);
    rate_entry_t *entry = shard->head;
    while (entry != NULL) {
        if (strcmp(entry->key, key_buf) == 0) {
            break;
        }
        entry = entry->next;
    }

    uint64_t now_us = config_monotonic_us();
    if (entry == NULL) {
        entry = calloc(1, sizeof(*entry));
        if (entry == NULL) {
            pthread_mutex_unlock(&shard->lock);
            return true;
        }
        snprintf(entry->key, sizeof(entry->key), "%s", key_buf);
        entry->last_time_us = now_us;
        entry->tokens = 1.0 + (double)burst;
        entry->next = shard->head;
        shard->head = entry;
    } else {
        uint64_t elapsed_us = (now_us > entry->last_time_us) ? (now_us - entry->last_time_us) : 0;
        entry->last_time_us = now_us;
        double added = ((double)elapsed_us / 1000000.0) * zone->rate_per_sec;
        entry->tokens += added;
        double max_cap = 1.0 + (double)burst;
        if (entry->tokens > max_cap) {
            entry->tokens = max_cap;
        }
    }

    if (entry->tokens >= 1.0) {
        entry->tokens -= 1.0;
        pthread_mutex_unlock(&shard->lock);
        return true;
    }

    if (retry_after_sec != NULL) {
        double needed = 1.0 - entry->tokens;
        double wait_sec = needed / zone->rate_per_sec;
        uint32_t retry = (uint32_t)ceil(wait_sec);
        if (retry == 0) {
            retry = 1;
        }
        *retry_after_sec = retry;
    }
    pthread_mutex_unlock(&shard->lock);
    return false;
}

bool apex_conn_limit_acquire(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip,
                             uint32_t max_conns) {
    if (runtime == NULL || runtime->config == NULL || zone_name == NULL || zone_name[0] == '\0') {
        return true;
    }
    if (runtime->rate_limiter == NULL || max_conns == 0) {
        return true;
    }

    char key_buf[128];
    snprintf(key_buf, sizeof(key_buf), "%s:%s", zone_name,
             client_ip != NULL && client_ip[0] != '\0' ? client_ip : "127.0.0.1");

    rate_limiter_t *limiter = (rate_limiter_t *)runtime->rate_limiter;
    uint32_t shard_idx = ratelimit_hash(zone_name, client_ip) % APEX_RATELIMIT_SHARDS;
    rate_shard_t *shard = &limiter->shards[shard_idx];

    pthread_mutex_lock(&shard->lock);
    rate_entry_t *entry = shard->head;
    while (entry != NULL) {
        if (strcmp(entry->key, key_buf) == 0) {
            break;
        }
        entry = entry->next;
    }

    if (entry == NULL) {
        entry = calloc(1, sizeof(*entry));
        if (entry == NULL) {
            pthread_mutex_unlock(&shard->lock);
            return true;
        }
        snprintf(entry->key, sizeof(entry->key), "%s", key_buf);
        entry->last_time_us = config_monotonic_us();
        entry->active_conns = 1;
        entry->next = shard->head;
        shard->head = entry;
        pthread_mutex_unlock(&shard->lock);
        return true;
    }

    if (entry->active_conns >= (int32_t)max_conns) {
        pthread_mutex_unlock(&shard->lock);
        return false;
    }

    entry->active_conns++;
    pthread_mutex_unlock(&shard->lock);
    return true;
}

void apex_conn_limit_release(const apex_runtime_t *runtime, const char *zone_name, const char *client_ip) {
    if (runtime == NULL || runtime->rate_limiter == NULL || zone_name == NULL || zone_name[0] == '\0') {
        return;
    }

    char key_buf[128];
    snprintf(key_buf, sizeof(key_buf), "%s:%s", zone_name,
             client_ip != NULL && client_ip[0] != '\0' ? client_ip : "127.0.0.1");

    rate_limiter_t *limiter = (rate_limiter_t *)runtime->rate_limiter;
    uint32_t shard_idx = ratelimit_hash(zone_name, client_ip) % APEX_RATELIMIT_SHARDS;
    rate_shard_t *shard = &limiter->shards[shard_idx];

    pthread_mutex_lock(&shard->lock);
    rate_entry_t *entry = shard->head;
    while (entry != NULL) {
        if (strcmp(entry->key, key_buf) == 0) {
            if (entry->active_conns > 0) {
                entry->active_conns--;
            }
            break;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&shard->lock);
}
