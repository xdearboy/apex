#include "http.h"
#include <dirent.h>
#include <sys/stat.h>

static http_route_t routes[MAX_ROUTES];
static int num_routes = 0;

/* open addressing, linear probing; -1 = empty slot */
static int route_index[ROUTE_HASH_SIZE];

static char resp_404[512];
static size_t resp_404_len = 0;

static uint32_t path_hash(const char *s, size_t len) {
    uint32_t h = 2166136261u;   /* fnv-1a */
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

static void route_index_insert(int idx) {
    uint32_t slot = path_hash(routes[idx].path, routes[idx].path_len) & (ROUTE_HASH_SIZE - 1);
    while (route_index[slot] != -1)
        slot = (slot + 1) & (ROUTE_HASH_SIZE - 1);
    route_index[slot] = idx;
}

static const char *get_mime_type(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "text/plain; charset=utf-8";
    if (strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0) return "text/html; charset=utf-8";
    if (strcasecmp(dot, ".css") == 0) return "text/css; charset=utf-8";
    if (strcasecmp(dot, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcasecmp(dot, ".json") == 0) return "application/json; charset=utf-8";
    if (strcasecmp(dot, ".svg") == 0) return "image/svg+xml";
    if (strcasecmp(dot, ".png") == 0) return "image/png";
    if (strcasecmp(dot, ".jpg") == 0 || strcasecmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(dot, ".ico") == 0) return "image/x-icon";
    if (strcasecmp(dot, ".wasm") == 0) return "application/wasm";
    if (strcasecmp(dot, ".txt") == 0) return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

static int add_file_route(const char *rel_uri, const char *fs_path) {
    if (num_routes >= MAX_ROUTES) return -1;

    FILE *f = fopen(fs_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size < 0 || size > 16777216) { fclose(f); return -1; }

    char *body = NULL;
    if (size > 0) {
        body = malloc((size_t)size);
        if (!body) { fclose(f); return -1; }
        if (fread(body, 1, (size_t)size, f) != (size_t)size) { free(body); fclose(f); return -1; }
    }
    fclose(f);

    const char *mime = get_mime_type(fs_path);
    char hdr[512];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Connection: keep-alive\r\n\r\n",
        mime, size);

    /* todo: mmap the file and writev the header instead of buffering the whole body twice */
    size_t total = (size_t)hdr_len + (size_t)size;
    char *full = malloc(total);
    if (!full) { free(body); return -1; }
    memcpy(full, hdr, (size_t)hdr_len);
    memcpy(full + hdr_len, body, (size_t)size);
    free(body);

    str_copy(routes[num_routes].path, rel_uri, MAX_URI_LEN);
    routes[num_routes].path_len = strlen(routes[num_routes].path);
    routes[num_routes].response_buf = full;
    routes[num_routes].response_len = total;
    route_index_insert(num_routes);
    num_routes++;
    return 0;
}

static void scan_directory(const char *base_dir, const char *sub_path) {
    char full_dir[1024];
    if (sub_path && sub_path[0])
        snprintf(full_dir, sizeof(full_dir), "%s/%s", base_dir, sub_path);
    else
        snprintf(full_dir, sizeof(full_dir), "%s", base_dir);

    DIR *d = opendir(full_dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char fs_path[1024];
        snprintf(fs_path, sizeof(fs_path), "%s/%s", full_dir, ent->d_name);

        struct stat st;
        if (stat(fs_path, &st) < 0) continue;

        if (S_ISDIR(st.st_mode)) {
            char new_sub[512];
            if (sub_path && sub_path[0])
                snprintf(new_sub, sizeof(new_sub), "%s/%s", sub_path, ent->d_name);
            else
                snprintf(new_sub, sizeof(new_sub), "%s", ent->d_name);
            scan_directory(base_dir, new_sub);
        } else if (S_ISREG(st.st_mode)) {
            char uri[MAX_URI_LEN];
            if (sub_path && sub_path[0])
                snprintf(uri, sizeof(uri), "/%s/%s", sub_path, ent->d_name);
            else
                snprintf(uri, sizeof(uri), "/%s", ent->d_name);

            add_file_route(uri, fs_path);
            if (strcmp(ent->d_name, "index.html") == 0) {
                if (!sub_path || !sub_path[0]) {
                    add_file_route("/", fs_path);
                } else {
                    char dir_uri[MAX_URI_LEN];
                    snprintf(dir_uri, sizeof(dir_uri), "/%s/", sub_path);
                    add_file_route(dir_uri, fs_path);
                    snprintf(dir_uri, sizeof(dir_uri), "/%s", sub_path);
                    add_file_route(dir_uri, fs_path);
                }
            }
        }
    }
    closedir(d);
}

int http_init_routes(const char *root_dir) {
    for (int i = 0; i < ROUTE_HASH_SIZE; i++) route_index[i] = -1;

    static const char body_404[] =
        "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
        "<body style=\"font-family:sans-serif;text-align:center;padding:50px\">"
        "<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>"
        "<hr><small>tachyon/" TACHYON_VERSION "</small></body></html>";

    resp_404_len = (size_t)snprintf(resp_404, sizeof(resp_404),
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: keep-alive\r\n\r\n%s",
        sizeof(body_404) - 1, body_404);

    if (root_dir && root_dir[0]) {
        scan_directory(root_dir, "");
    }
    return 0;
}

void http_free_routes(void) {
    for (int i = 0; i < num_routes; i++) {
        if (routes[i].response_buf) {
            free(routes[i].response_buf);
            routes[i].response_buf = NULL;
        }
    }
    num_routes = 0;
    for (int i = 0; i < ROUTE_HASH_SIZE; i++) route_index[i] = -1;
}

const http_route_t *http_find_route(const char *path, size_t path_len) {
    if (num_routes == 0) return NULL;
    uint32_t slot = path_hash(path, path_len) & (ROUTE_HASH_SIZE - 1);
    for (int probe = 0; probe < ROUTE_HASH_SIZE; probe++) {
        int idx = route_index[slot];
        if (idx == -1) return NULL;
        if (routes[idx].path_len == path_len && memcmp(routes[idx].path, path, path_len) == 0)
            return &routes[idx];
        slot = (slot + 1) & (ROUTE_HASH_SIZE - 1);
    }
    return NULL;
}

const char *http_get_404_response(size_t *len) {
    if (len) *len = resp_404_len;
    return resp_404;
}
