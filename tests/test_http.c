#include <string.h>
#include <sys/stat.h>
#include "test.h"
#include "../src/http.c"

static void test_mime(void) {
    CHECK(strcmp(get_mime_type("a.html"), "text/html; charset=utf-8") == 0);
    CHECK(strcmp(get_mime_type("a.HTM"), "text/html; charset=utf-8") == 0);
    CHECK(strcmp(get_mime_type("a.css"), "text/css; charset=utf-8") == 0);
    CHECK(strcmp(get_mime_type("a.js"), "application/javascript; charset=utf-8") == 0);
    CHECK(strcmp(get_mime_type("a.png"), "image/png") == 0);
    CHECK(strcmp(get_mime_type("noext"), "text/plain; charset=utf-8") == 0);
    CHECK(strcmp(get_mime_type("a.bin"), "application/octet-stream") == 0);
}

static void test_hash_stable(void) {
    CHECK(path_hash("/index.html", 11) == path_hash("/index.html", 11));
    CHECK(path_hash("/a", 2) != path_hash("/b", 2));
}

static const http_route_t *find(const char *p) {
    return http_find_route(p, strlen(p));
}

static void test_routing(void) {
    const char *dir = "/tmp/tachyon_http_test";
    mkdir(dir, 0755);
    mkdir("/tmp/tachyon_http_test/sub", 0755);

    FILE *f;
    f = fopen("/tmp/tachyon_http_test/index.html", "w"); fputs("<h1>hi</h1>", f); fclose(f);
    f = fopen("/tmp/tachyon_http_test/style.css", "w");  fputs("body{}", f);     fclose(f);
    f = fopen("/tmp/tachyon_http_test/sub/app.js", "w"); fputs("1;", f);         fclose(f);
    f = fopen("/tmp/tachyon_http_test/empty.txt", "w");                          fclose(f);

    http_init_routes(dir);

    CHECK(find("/") != NULL);            /* index.html mapped to root */
    CHECK(find("/index.html") != NULL);
    CHECK(find("/style.css") != NULL);
    CHECK(find("/sub/app.js") != NULL);
    CHECK(find("/empty.txt") != NULL);   /* zero-length file still served */
    CHECK(find("/missing") == NULL);
    CHECK(find("/inde") == NULL);        /* prefix must not match */

    const http_route_t *css = find("/style.css");
    if (css) {
        CHECK(memmem(css->response_buf, css->response_len, "text/css", 8) != NULL);
        CHECK(memmem(css->response_buf, css->response_len, "200 OK", 6) != NULL);
    }

    size_t l404 = 0;
    const char *r404 = http_get_404_response(&l404);
    CHECK(r404 != NULL && l404 > 0);
    CHECK(memmem(r404, l404, "404", 3) != NULL);

    http_free_routes();
    CHECK(find("/") == NULL);            /* index reset after free */

    remove("/tmp/tachyon_http_test/index.html");
    remove("/tmp/tachyon_http_test/style.css");
    remove("/tmp/tachyon_http_test/sub/app.js");
    remove("/tmp/tachyon_http_test/empty.txt");
    rmdir("/tmp/tachyon_http_test/sub");
    rmdir(dir);
}

int main(void) {
    test_mime();
    test_hash_stable();
    test_routing();
    TEST_REPORT("http");
}
