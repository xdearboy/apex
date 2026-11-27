#include "internal.h"
#include "apex/config.h"
#include "apex/ratelimit.h"
#include "apex/file_cache.h"
#include "apex/cache.h"
#include "apex/log.h"
#include "apex/module.h"
#include "apex/proxy.h"
#include "apex/acme.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifndef APEX_CONFIG_DEFAULT_CONNECT_MS
#define APEX_CONFIG_DEFAULT_CONNECT_MS 2000u
#endif

#ifndef APEX_CONFIG_DEFAULT_READ_MS
#define APEX_CONFIG_DEFAULT_READ_MS 10000u
#endif

static bool runtime_oom(apex_config_error_t *error) {
    if (error == NULL) {
        return false;
    }
    error->code = APEX_CONFIG_ERR_MEMORY;
    error->line = 0;
    error->column = 0;
    error->file[0] = '\0';
    error->hint[0] = '\0';
    snprintf(error->message, sizeof(error->message), "out of memory");
    return false;
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
        runtime_oom(error);
        return NULL;
    }
    runtime->config = config;

    if (config->upstream_count > 0) {
        runtime->groups = calloc(config->upstream_count, sizeof(*runtime->groups));
        if (runtime->groups == NULL) {
            runtime_oom(error);
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
            if (server->locations[location_index].target == APEX_PROXY_TARGET_ENDPOINT &&
                !server->locations[location_index].proxy_pass_dynamic) {
                endpoint_count++;
            }
        }
    }

    if (endpoint_count > 0) {
        runtime->endpoint_groups = calloc(endpoint_count, sizeof(*runtime->endpoint_groups));
        if (runtime->endpoint_groups == NULL) {
            runtime_oom(error);
            apex_runtime_destroy(runtime);
            return NULL;
        }
    }

    for (size_t server_index = 0; server_index < config->server_count; server_index++) {
        const apex_server_config_t *server = &config->servers[server_index];
        for (size_t location_index = 0; location_index < server->location_count; location_index++) {
            const apex_location_config_t *location = &server->locations[location_index];
            if (location->target != APEX_PROXY_TARGET_ENDPOINT || location->proxy_pass_dynamic) {
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

            if (location->proxy_pass_ssl) {
                entry->group.use_ssl = true;
                entry->group.servers[0].use_ssl = true;
                if (location->proxy_ssl_name[0] != '\0') {
                    snprintf(entry->group.ssl_server_name, sizeof(entry->group.ssl_server_name), "%s", location->proxy_ssl_name);
                    snprintf(entry->group.servers[0].ssl_server_name, sizeof(entry->group.servers[0].ssl_server_name), "%s", location->proxy_ssl_name);
                } else if (location->proxy_ssl_server_name && location->endpoint_host != NULL) {
                    snprintf(entry->group.ssl_server_name, sizeof(entry->group.ssl_server_name), "%s", location->endpoint_host);
                    snprintf(entry->group.servers[0].ssl_server_name, sizeof(entry->group.servers[0].ssl_server_name), "%s", location->endpoint_host);
                }
                entry->group.use_ssl_sni = location->proxy_ssl_server_name;
                entry->group.servers[0].use_ssl_sni = location->proxy_ssl_server_name;
            }

            runtime->endpoint_group_count++;
        }
    }

    if (apex_module_registry_init(runtime, config, error) != 0) {
        apex_runtime_destroy(runtime);
        return NULL;
    }

    runtime->rate_limiter = apex_ratelimit_create(config);

    if (config->http.cache_zone_count > 0) {
        runtime->cache_manager = apex_cache_manager_create(config);
    }

    apex_open_file_cache_config_t ofc_cfg = config->http.open_file_cache;
    bool ofc_needed = ofc_cfg.enabled;
    if (!ofc_needed) {
        for (size_t s = 0; s < config->server_count; s++) {
            if (config->servers[s].open_file_cache.enabled) {
                ofc_cfg = config->servers[s].open_file_cache;
                ofc_needed = true;
                break;
            }
            for (size_t l = 0; l < config->servers[s].location_count; l++) {
                if (config->servers[s].locations[l].open_file_cache.enabled) {
                    ofc_cfg = config->servers[s].locations[l].open_file_cache;
                    ofc_needed = true;
                    break;
                }
            }
            if (ofc_needed) break;
        }
    }
    if (ofc_needed) {
        runtime->file_cache = apex_file_cache_create(&ofc_cfg);
    }

    apex_acme_config_t acme_cfg = config->http.acme;
    bool acme_needed = acme_cfg.enabled;
    if (!acme_needed) {
        for (size_t s = 0; s < config->server_count; s++) {
            if (config->servers[s].acme.enabled) {
                acme_cfg = config->servers[s].acme;
                acme_needed = true;
                break;
            }
        }
    }
    if (acme_needed) {
        runtime->acme_manager = apex_acme_manager_create(&acme_cfg, runtime);
    }

    apex_health_prober_start(runtime->groups, runtime->group_count);
    apex_log_manager_init(runtime);
    return runtime;
}

void apex_runtime_destroy(apex_runtime_t *runtime) {
    if (runtime == NULL) {
        return;
    }
    if (runtime->acme_manager != NULL) {
        apex_acme_manager_destroy((apex_acme_manager_t *)runtime->acme_manager);
        runtime->acme_manager = NULL;
    }
    apex_health_prober_stop();
    apex_module_registry_destroy(runtime);
    if (runtime->file_cache != NULL) {
        apex_file_cache_destroy((apex_file_cache_t *)runtime->file_cache);
        runtime->file_cache = NULL;
    }
    if (runtime->log_manager != NULL) {
        apex_log_manager_destroy(runtime);
        runtime->log_manager = NULL;
    }
    if (runtime->cache_manager != NULL) {
        apex_cache_manager_destroy((apex_cache_manager_t *)runtime->cache_manager);
        runtime->cache_manager = NULL;
    }
    if (runtime->rate_limiter != NULL) {
        apex_ratelimit_destroy(runtime->rate_limiter);
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

bool apex_runtime_match_ex(const apex_runtime_t *runtime, uint16_t port, bool is_tls,
                           const char *host, size_t host_length, const char *path,
                           size_t path_length, apex_config_route_t *route) {
    if (runtime == NULL || runtime->config == NULL || route == NULL || path == NULL) {
        return false;
    }

    const apex_config_t *config = runtime->config;
    if (config->server_count == 0) {
        return false;
    }

    const apex_server_config_t *server = NULL;
    const apex_server_config_t *default_server_for_port = NULL;

    for (size_t index = 0; index < config->server_count; index++) {
        const apex_server_config_t *s = &config->servers[index];
        if (port != 0) {
            if (s->listen_port != port || s->listen_tls != is_tls) {
                continue;
            }
            if (default_server_for_port == NULL) {
                default_server_for_port = s;
            }
        }
        if (server_matches_host(s, host, host_length)) {
            server = s;
            break;
        }
    }
    if (server == NULL) {
        server = default_server_for_port;
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

bool apex_runtime_match(const apex_runtime_t *runtime, const char *host, size_t host_length, const char *path,
                        size_t path_length, apex_config_route_t *route) {
    return apex_runtime_match_ex(runtime, 0, false, host, host_length, path, path_length, route);
}
