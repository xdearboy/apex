#define _GNU_SOURCE
#include <string.h>
#include "test.h"
#include "../src/config.c"

static void test_str_copy(void) {
    char buf[4];
    str_copy(buf, "abcdef", sizeof(buf));
    CHECK(strcmp(buf, "abc") == 0);   /* truncated to fit, still terminated */
    str_copy(buf, "x", sizeof(buf));
    CHECK(strcmp(buf, "x") == 0);
    str_copy(buf, "", sizeof(buf));
    CHECK(buf[0] == '\0');
}

static void test_parse_bool(void) {
    CHECK(parse_bool("true") == 1);
    CHECK(parse_bool("YES") == 1);
    CHECK(parse_bool("1") == 1);
    CHECK(parse_bool("on") == 1);
    CHECK(parse_bool("false") == 0);
    CHECK(parse_bool("0") == 0);
    CHECK(parse_bool("nope") == 0);
}

static void test_trim(void) {
    char a[] = "   hi  ";
    CHECK(strcmp(trim(a), "hi") == 0);
    char b[] = "\t x \r\n";
    CHECK(strcmp(trim(b), "x") == 0);
    char c[] = "    ";
    CHECK(strcmp(trim(c), "") == 0);
}

static void test_unquote(void) {
    char a[] = "\"quoted\"";
    unquote(a); CHECK(strcmp(a, "quoted") == 0);
    char b[] = "'single'";
    unquote(b); CHECK(strcmp(b, "single") == 0);
    char c[] = "bare";
    unquote(c); CHECK(strcmp(c, "bare") == 0);
}

static void write_file(const char *path, const char *contents) {
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (f) { fputs(contents, f); fclose(f); }
}

static void test_load_full(void) {
    const char *path = "/tmp/tachyon_test_cfg.toml";
    write_file(path,
        "[server]\n"
        "port = 1234\n"
        "bind = \"127.0.0.1\"\n"
        "workers = 8\n"
        "status = 200\n"
        "cpu_steer = true\n"
        "root = \"/var/www\"\n\n"
        "[tls]\n"
        "cert = \"c.pem\"\n"
        "key = \"k.pem\"\n\n"
        "[stats]\n"
        "enabled = false\n"
        "path = \"/m\"\n");

    tachyon_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enable_stats = 1;

    CHECK(config_load_file(path, &cfg) == 0);
    CHECK(cfg.port == 1234);
    CHECK(strcmp(cfg.bind_addr, "127.0.0.1") == 0);
    CHECK(cfg.num_workers == 8);
    CHECK(cfg.http_status == 200);
    CHECK(cfg.enable_steer == 1);
    CHECK(strcmp(cfg.root_dir, "/var/www") == 0);
    CHECK(strcmp(cfg.cert_file, "c.pem") == 0);
    CHECK(strcmp(cfg.key_file, "k.pem") == 0);
    CHECK(cfg.enable_stats == 0);
    CHECK(strcmp(cfg.stats_path, "/m") == 0);
    remove(path);
}

static void test_inline_comment(void) {
    const char *path = "/tmp/tachyon_test_cfg2.toml";
    write_file(path, "[server]\nport = 8443  # keep default\n");

    tachyon_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    CHECK(config_load_file(path, &cfg) == 0);
    CHECK(cfg.port == 8443);
    remove(path);
}

static void test_missing_file(void) {
    tachyon_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    CHECK(config_load_file("/tmp/tachyon_no_such_file.toml", &cfg) == -1);
}

int main(void) {
    test_str_copy();
    test_parse_bool();
    test_trim();
    test_unquote();
    test_load_full();
    test_inline_comment();
    test_missing_file();
    TEST_REPORT("config");
}
