#include "apex/module.h"
#include "apex/config.h"
#include "internal.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

typedef struct {
    char path[APEX_CONFIG_PATH_MAX];
    void *dso_handle;
    const apex_module_t *module;
} module_slot_t;

struct apex_module_registry {
    module_slot_t slots[APEX_CONFIG_MAX_MODULE_NAMES];
    size_t count;
};

static bool module_error_at(apex_config_error_t *error, const char *file, const char *format, ...) {
    if (error == NULL) {
        return false;
    }
    error->code = APEX_CONFIG_ERR_RUNTIME;
    error->line = 0;
    error->column = 0;
    snprintf(error->file, sizeof(error->file), "%s", file != NULL ? file : "");
    va_list args;
    va_start(args, format);
    vsnprintf(error->message, sizeof(error->message), format, args);
    va_end(args);
    return false;
}

int apex_module_registry_init(apex_runtime_t *runtime, const apex_config_t *config, apex_config_error_t *error) {
    if (runtime == NULL || config == NULL) {
        return 0;
    }
    if (config->module_count == 0) {
        runtime->module_registry = NULL;
        return 0;
    }

    struct apex_module_registry *registry = calloc(1, sizeof(*registry));
    if (registry == NULL) {
        module_error_at(error, config->source, "out of memory allocating module registry");
        return -1;
    }

    for (size_t index = 0; index < config->module_count; index++) {
        const char *module_path = config->modules[index];
        void *handle = dlopen(module_path, RTLD_NOW | RTLD_LOCAL);
        if (handle == NULL) {
            /* Try relative to current directory if not found */
            char candidate[APEX_CONFIG_PATH_MAX];
            if (module_path[0] != '/' && module_path[0] != '.') {
                snprintf(candidate, sizeof(candidate), "./%s", module_path);
                handle = dlopen(candidate, RTLD_NOW | RTLD_LOCAL);
                if (handle == NULL) {
                    snprintf(candidate, sizeof(candidate), "./%s.so", module_path);
                    handle = dlopen(candidate, RTLD_NOW | RTLD_LOCAL);
                }
            }
        }

        if (handle == NULL) {
            module_error_at(error, config->source, "failed to load module '%s': %s",
                            module_path, dlerror());
            /* Clean up previously opened modules */
            for (size_t rev = 0; rev < registry->count; rev++) {
                if (registry->slots[rev].module != NULL && registry->slots[rev].module->cleanup != NULL) {
                    registry->slots[rev].module->cleanup(runtime);
                }
                dlclose(registry->slots[rev].dso_handle);
            }
            free(registry);
            return -1;
        }

        const apex_module_t *mod = (const apex_module_t *)dlsym(handle, "apex_module");
        if (mod == NULL) {
            typedef const apex_module_t *(*entry_func_t)(void);
            entry_func_t entry_fn = (entry_func_t)dlsym(handle, "apex_module_entry");
            if (entry_fn != NULL) {
                mod = entry_fn();
            }
        }

        if (mod == NULL) {
            module_error_at(error, config->source,
                            "module '%s' is missing 'apex_module' descriptor symbol", module_path);
            dlclose(handle);
            for (size_t rev = 0; rev < registry->count; rev++) {
                if (registry->slots[rev].module != NULL && registry->slots[rev].module->cleanup != NULL) {
                    registry->slots[rev].module->cleanup(runtime);
                }
                dlclose(registry->slots[rev].dso_handle);
            }
            free(registry);
            return -1;
        }

        if (mod->abi_version != APEX_MODULE_ABI_VERSION) {
            module_error_at(error, config->source,
                            "module '%s' ABI mismatch (expected %u, got %u)",
                            module_path, (unsigned)APEX_MODULE_ABI_VERSION, (unsigned)mod->abi_version);
            dlclose(handle);
            for (size_t rev = 0; rev < registry->count; rev++) {
                if (registry->slots[rev].module != NULL && registry->slots[rev].module->cleanup != NULL) {
                    registry->slots[rev].module->cleanup(runtime);
                }
                dlclose(registry->slots[rev].dso_handle);
            }
            free(registry);
            return -1;
        }

        if (mod->init != NULL) {
            int init_rc = mod->init(runtime);
            if (init_rc != 0) {
                module_error_at(error, config->source,
                                "module '%s' init() returned error code %d", module_path, init_rc);
                dlclose(handle);
                for (size_t rev = 0; rev < registry->count; rev++) {
                    if (registry->slots[rev].module != NULL && registry->slots[rev].module->cleanup != NULL) {
                        registry->slots[rev].module->cleanup(runtime);
                    }
                    dlclose(registry->slots[rev].dso_handle);
                }
                free(registry);
                return -1;
            }
        }

        module_slot_t *slot = &registry->slots[registry->count++];
        snprintf(slot->path, sizeof(slot->path), "%s", module_path);
        slot->dso_handle = handle;
        slot->module = mod;
    }

    runtime->module_registry = registry;
    return 0;
}

void apex_module_registry_destroy(apex_runtime_t *runtime) {
    if (runtime == NULL || runtime->module_registry == NULL) {
        return;
    }

    struct apex_module_registry *registry = runtime->module_registry;
    for (size_t rev = registry->count; rev > 0; rev--) {
        module_slot_t *slot = &registry->slots[rev - 1];
        if (slot->module != NULL && slot->module->cleanup != NULL) {
            slot->module->cleanup(runtime);
        }
        if (slot->dso_handle != NULL) {
            dlclose(slot->dso_handle);
            slot->dso_handle = NULL;
        }
    }

    free(registry);
    runtime->module_registry = NULL;
}

apex_action_t apex_pipeline_run_phase(apex_pipeline_ctx_t *ctx, apex_phase_t phase) {
    if (ctx == NULL || ctx->runtime == NULL || ctx->runtime->module_registry == NULL) {
        return APEX_ACTION_CONTINUE;
    }

    struct apex_module_registry *registry = ctx->runtime->module_registry;
    for (size_t index = 0; index < registry->count; index++) {
        const apex_module_t *mod = registry->slots[index].module;
        if (mod == NULL) {
            continue;
        }

        apex_action_t action = APEX_ACTION_CONTINUE;
        switch (phase) {
        case APEX_PHASE_PRE_ROUTING:
            if (mod->on_pre_routing != NULL) {
                action = mod->on_pre_routing(ctx);
            }
            break;
        case APEX_PHASE_TLS_HANDSHAKE:
            if (mod->on_tls_handshake != NULL) {
                action = mod->on_tls_handshake(ctx);
            }
            break;
        case APEX_PHASE_HEADER_FILTER:
            if (mod->on_header_filter != NULL) {
                action = mod->on_header_filter(ctx);
            }
            break;
        case APEX_PHASE_ACCESS_CONTROL:
            if (mod->on_access_control != NULL) {
                action = mod->on_access_control(ctx);
            }
            break;
        case APEX_PHASE_CONTENT_HANDLER:
            if (mod->on_content_handler != NULL) {
                action = mod->on_content_handler(ctx);
            }
            break;
        case APEX_PHASE_RESPONSE_FILTER:
            if (mod->on_response_filter != NULL) {
                action = mod->on_response_filter(ctx);
            }
            break;
        case APEX_PHASE_LOGGING:
            if (mod->on_logging != NULL) {
                mod->on_logging(ctx);
            }
            break;
        default:
            break;
        }

        if (action != APEX_ACTION_CONTINUE) {
            return action;
        }
    }

    return APEX_ACTION_CONTINUE;
}

bool apex_pipeline_add_header(apex_pipeline_ctx_t *ctx, const char *name, const char *value) {
    if (ctx == NULL || name == NULL || value == NULL) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    /* name + ": " + value + "\r\n" */
    size_t needed = name_len + 2u + value_len + 2u;
    if (ctx->extra_headers_len + needed >= sizeof(ctx->extra_headers)) {
        return false;
    }

    memcpy(ctx->extra_headers + ctx->extra_headers_len, name, name_len);
    ctx->extra_headers_len += name_len;
    memcpy(ctx->extra_headers + ctx->extra_headers_len, ": ", 2u);
    ctx->extra_headers_len += 2u;
    memcpy(ctx->extra_headers + ctx->extra_headers_len, value, value_len);
    ctx->extra_headers_len += value_len;
    memcpy(ctx->extra_headers + ctx->extra_headers_len, "\r\n", 2u);
    ctx->extra_headers_len += 2u;
    ctx->extra_headers[ctx->extra_headers_len] = '\0';
    return true;
}

static const char *pipeline_find_crlf(const char *data, size_t length) {
    if (length < 2u) {
        return NULL;
    }
    for (size_t i = 0; i + 1u < length; i++) {
        if (data[i] == '\r' && data[i + 1u] == '\n') {
            return data + i;
        }
    }
    return NULL;
}

bool apex_pipeline_find_header(const apex_pipeline_ctx_t *ctx, const char *name,
                               const char **value, size_t *value_len) {
    if (ctx == NULL || name == NULL || value == NULL || value_len == NULL) {
        return false;
    }
    const char *buffer = ctx->raw_request;
    size_t length = ctx->raw_request_len;
    if (buffer == NULL || length == 0) {
        return false;
    }

    const char *first_end = pipeline_find_crlf(buffer, length);
    if (first_end == NULL) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t position = (size_t)(first_end - buffer) + 2u;
    while (position < length) {
        const char *line = buffer + position;
        const char *line_end = pipeline_find_crlf(line, length - position);
        if (line_end == NULL) {
            return false;
        }
        size_t line_length = (size_t)(line_end - line);
        if (line_length == 0) {
            return false;
        }

        const char *colon = memchr(line, ':', line_length);
        if (colon != NULL) {
            size_t field_len = (size_t)(colon - line);
            while (field_len > 0 && (line[field_len - 1u] == ' ' || line[field_len - 1u] == '\t')) {
                field_len--;
            }
            if (field_len == name_len && strncasecmp(line, name, name_len) == 0) {
                const char *val_start = colon + 1;
                const char *val_end = line + line_length;
                while (val_start < val_end && (*val_start == ' ' || *val_start == '\t')) {
                    val_start++;
                }
                while (val_end > val_start && (val_end[-1] == ' ' || val_end[-1] == '\t')) {
                    val_end--;
                }
                *value = val_start;
                *value_len = (size_t)(val_end - val_start);
                return true;
            }
        }
        position += line_length + 2u;
    }
    return false;
}
