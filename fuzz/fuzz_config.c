#include "apex/config.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0;
    }

    apex_config_t *config = NULL;
    apex_config_error_t error = {0};

    int rc = apex_config_parse_string("fuzz.conf", (const char *)data, size, &config, &error);
    if (rc == 0 && config != NULL) {
        apex_config_first_listen_port(config);
        apex_config_find_upstream(config, "backend");
        apex_map_lookup(config, "$backend_target", "api");

        apex_runtime_t *runtime = apex_runtime_create(config, &error);
        if (runtime != NULL) {
            apex_config_route_t route = {0};
            apex_runtime_match(runtime, "example.com", 11, "/api/test", 9, &route);
            apex_runtime_destroy(runtime);
        }

        apex_config_free(config);
    }

    return 0;
}
