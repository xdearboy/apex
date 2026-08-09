#include "config.h"

static char *trim(char *str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static void unquote(char *val) {
    size_t len = strlen(val);
    if (len >= 2 && ((val[0] == '"' && val[len - 1] == '"') || (val[0] == '\'' && val[len - 1] == '\''))) {
        val[len - 1] = '\0';
        memmove(val, val + 1, len - 1);
    }
}

static int parse_bool(const char *val) {
    if (strcasecmp(val, "true") == 0 || strcasecmp(val, "yes") == 0 ||
        strcasecmp(val, "1") == 0 || strcasecmp(val, "on") == 0)
        return 1;
    return 0;
}

int config_load_file(const char *path, tachyon_config_t *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char section[64] = "";
    char line[512];

    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '\0' || *p == '#') continue;

        if (*p == '[' && p[strlen(p) - 1] == ']') {
            p[strlen(p) - 1] = '\0';
            strncpy(section, trim(p + 1), sizeof(section) - 1);
            section[sizeof(section) - 1] = '\0';
            continue;
        }

        char *eq = strchr(p, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        /* todo: this strips '#' even inside quotes; fine until a value needs a literal one */
        char *comment = strchr(val, '#');
        if (comment) {
            *comment = '\0';
            val = trim(val);
        }

        unquote(val);

        if (strcasecmp(section, "server") == 0 || section[0] == '\0') {
            if (strcasecmp(key, "port") == 0) cfg->port = atoi(val);
            else if (strcasecmp(key, "bind") == 0) str_copy(cfg->bind_addr, val, sizeof(cfg->bind_addr));
            else if (strcasecmp(key, "workers") == 0) cfg->num_workers = atoi(val);
            else if (strcasecmp(key, "status") == 0) cfg->http_status = atoi(val);
            else if (strcasecmp(key, "cpu_steer") == 0) cfg->enable_steer = parse_bool(val);
            else if (strcasecmp(key, "root") == 0) str_copy(cfg->root_dir, val, sizeof(cfg->root_dir));
        }

        if (strcasecmp(section, "tls") == 0 || section[0] == '\0') {
            if (strcasecmp(key, "cert") == 0) str_copy(cfg->cert_file, val, sizeof(cfg->cert_file));
            else if (strcasecmp(key, "key") == 0) str_copy(cfg->key_file, val, sizeof(cfg->key_file));
        }

        if (strcasecmp(section, "stats") == 0 || section[0] == '\0') {
            if (strcasecmp(key, "enabled") == 0) cfg->enable_stats = parse_bool(val);
            else if (strcasecmp(key, "path") == 0) str_copy(cfg->stats_path, val, sizeof(cfg->stats_path));
        }
    }

    fclose(f);
    return 0;
}
