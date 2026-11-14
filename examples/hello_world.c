#include "apex.h"

static void handle_hello(apex_req_t *req, apex_res_t *res) {
    (void)req;
    static const char msg[] = "Hello from Apex!";
    apex_res_send(res, 200, msg, sizeof(msg) - 1);
}

int main(void) {
    apex_app_t *app = apex_create();
    if (!app) {
        return 1;
    }

    apex_get(app, "/", handle_hello);

    int status = apex_run(app, 8080);
    apex_destroy(app);
    return status;
}
