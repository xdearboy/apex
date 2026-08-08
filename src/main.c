#include "tachyon.h"
#include "net.h"
#include "tls.h"
#include "metrics.h"
#include "worker.h"

tachyon_config_t g_config = {
    .port = DEFAULT_PORT,
    .bind_addr = DEFAULT_BIND_ADDR,
    .cert_file = NULL,
    .key_file = NULL,
    .num_workers = 0,
    .enable_steer = 0,
    .http_status = 204
};

static void print_usage(const char *prog) {
    printf("tachyon v%s\n\n", TACHYON_VERSION);
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p <port>        Port to listen on (default: %d)\n", DEFAULT_PORT);
    printf("  -b <addr>        Bind IP address (default: %s)\n", DEFAULT_BIND_ADDR);
    printf("  -c <cert.pem>    Path to SSL certificate file\n");
    printf("  -k <key.pem>     Path to SSL private key file\n");
    printf("  -w <workers>     Number of worker processes (default: CPU count)\n");
    printf("  -s               Enable BPF CPU affinity steering\n");
    printf("  --status <code>  HTTP status to return (204 or 200, default: 204)\n");
    printf("  -v, --version    Show version\n");
    printf("  -h, --help       Show help\n\n");
}

int main(int argc, char *argv[]) {
    pid_t pids[MAX_WORKERS];
    int lfds[MAX_WORKERS];
    int cpus[MAX_WORKERS];

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            g_config.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            g_config.bind_addr = argv[++i];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            g_config.cert_file = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            g_config.key_file = argv[++i];
        } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            g_config.num_workers = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-s") == 0) {
            g_config.enable_steer = 1;
        } else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
            g_config.http_status = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("tachyon v%s\n", TACHYON_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            if (i == 1) g_config.port = atoi(argv[1]);
            else if (i == 2) g_config.bind_addr = argv[2];
            else if (i == 3) g_config.cert_file = argv[3];
            else if (i == 4) g_config.key_file = argv[4];
        }
    }

    int num_workers = g_config.num_workers;
#ifdef __linux__
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    int detected_workers = 0;
    if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
        for (int c = 0; c < CPU_SETSIZE && detected_workers < MAX_WORKERS; c++) {
            if (CPU_ISSET(c, &allowed)) cpus[detected_workers++] = c;
        }
    }
    if (num_workers <= 0) num_workers = detected_workers;
#else
    for (int i = 0; i < MAX_WORKERS; i++) cpus[i] = -1;
#endif

    if (num_workers <= 0) {
        num_workers = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_workers <= 0) num_workers = 4;
        for (int i = 0; i < num_workers; i++) cpus[i] = -1;
    }
    if (num_workers > MAX_WORKERS) num_workers = MAX_WORKERS;
    g_config.num_workers = num_workers;

    int conn_cap = net_get_max_fds();

    if (metrics_init(num_workers) < 0) {
        fprintf(stderr, "Failed to initialize metrics\n");
        return 1;
    }

    worker_init_batch();

    if (tls_init_server_ctx(g_config.cert_file, g_config.key_file) < 0) {
        fprintf(stderr, "Failed to initialize TLS context\n");
        return 1;
    }

    for (int i = 0; i < num_workers; i++) {
        lfds[i] = net_create_listener(g_config.port, g_config.bind_addr);
        if (lfds[i] < 0) {
            fprintf(stderr, "Failed to bind worker socket %d\n", i);
            return 1;
        }
    }

    int steer = 0;
#ifdef __linux__
    if (g_config.enable_steer || getenv("STEER") != NULL) {
        steer = (net_attach_cpu_steering(lfds[0], num_workers) == 0);
    }
    if (!steer) {
        for (int i = 0; i < num_workers; i++) cpus[i] = -1;
    }
#endif

    printf("===============================================================\n");
    printf("  tachyon v%s\n", TACHYON_VERSION);
    printf("===============================================================\n");
    printf("  Listening on    : %s:%d\n", g_config.bind_addr, g_config.port);
    printf("  Workers count   : %d (CPU steering: %s)\n", num_workers, steer ? "enabled" : "disabled");
    printf("  Max connections : %d\n", conn_cap);
    printf("  HTTP Response   : %d (%s)\n", g_config.http_status, g_config.http_status == 204 ? "No Content" : "OK");
    printf("  Certificate     : %s\n", g_config.cert_file ? g_config.cert_file : "in-memory self-signed (ECDSA)");
    printf("===============================================================\n");
    fflush(stdout);

    for (int i = 0; i < num_workers; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_run(lfds[i], cpus[i], i, conn_cap);
            _exit(0);
        }
        pids[i] = pid;
    }

    signal(SIGPIPE, SIG_IGN);

    for (;;) {
        int status;
        pid_t dead = wait(&status);
        if (dead < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < num_workers; i++) {
            if (pids[i] != dead) continue;
            pid_t pid = fork();
            if (pid == 0) {
                worker_run(lfds[i], cpus[i], i, conn_cap);
                _exit(0);
            }
            pids[i] = pid;
            fprintf(stderr, "[tachyon] worker %d (pid %d) died, respawned as pid %d\n", i, dead, pid);
            fflush(stderr);
        }
    }

    tls_destroy_server_ctx();
    metrics_destroy(num_workers);
    return 0;
}
