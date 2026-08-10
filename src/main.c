#include "tachyon.h"
#include "net.h"
#include "tls.h"
#include "metrics.h"
#include "worker.h"
#include "http.h"
#include "config.h"

tachyon_config_t g_config = {
    .port = DEFAULT_PORT,
    .bind_addr = DEFAULT_BIND_ADDR,
    .cert_file = "",
    .key_file = "",
    .root_dir = "",
    .stats_path = DEFAULT_STATS_PATH,
    .reset_path = "",
    .num_workers = 0,
    .enable_steer = 0,
    .enable_stats = 1,
    .http_status = 204
};

static pid_t g_worker_pids[MAX_WORKERS];
static volatile sig_atomic_t g_num_running = 0;

/* kill workers on the way out so they don't outlive the master as orphans */
static void handle_shutdown(int sig) {
    (void)sig;
    for (int i = 0; i < g_num_running; i++)
        if (g_worker_pids[i] > 0) kill(g_worker_pids[i], SIGTERM);
    _exit(0);
}

static void print_usage(const char *prog) {
    printf("tachyon v%s\n\n", TACHYON_VERSION);
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -C, --config <file>  Load TOML configuration file (e.g. tachyon.toml)\n");
    printf("  -p <port>            Port to listen on (default: %d)\n", DEFAULT_PORT);
    printf("  -b <addr>            Bind IP address (default: %s)\n", DEFAULT_BIND_ADDR);
    printf("  -c <cert.pem>        Path to SSL certificate file\n");
    printf("  -k <key.pem>         Path to SSL private key file\n");
    printf("  -d, --root <dir>     Serve static files from directory\n");
    printf("  -w <workers>         Number of worker processes (default: CPU count)\n");
    printf("  -s                   Enable BPF CPU affinity steering\n");
    printf("  --status <code>      HTTP status to return (204 or 200, default: 204)\n");
    printf("  --stats              Enable /stats endpoint (default: enabled)\n");
    printf("  --no-stats           Disable /stats endpoint\n");
    printf("  --stats-path <path>  Custom stats URL path (default: /stats)\n");
    printf("  --reset-path <path>  Drop connections hitting this path with a TCP RST (444-style)\n");
    printf("  -v, --version        Show version\n");
    printf("  -h, --help           Show help\n\n");
}

int main(int argc, char *argv[]) {
    int lfds[MAX_WORKERS];
    int cpus[MAX_WORKERS];
    time_t started[MAX_WORKERS] = {0};
    int fastfails[MAX_WORKERS] = {0};
    const char *config_file = NULL;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
            config_file = argv[++i];
        }
    }

    if (config_file) {
        if (config_load_file(config_file, &g_config) < 0) {
            fprintf(stderr, "Warning: could not load config file %s: %s\n", config_file, strerror(errno));
        }
    } else if (access("tachyon.toml", R_OK) == 0) {
        config_load_file("tachyon.toml", &g_config);
    }

    if (argc > 1 && argv[1][0] != '-') {
        if (argc > 1) g_config.port = atoi(argv[1]);
        if (argc > 2) str_copy(g_config.bind_addr, argv[2], sizeof(g_config.bind_addr));
        if (argc > 3) str_copy(g_config.cert_file, argv[3], sizeof(g_config.cert_file));
        if (argc > 4) str_copy(g_config.key_file, argv[4], sizeof(g_config.key_file));
    } else {
        for (int i = 1; i < argc; i++) {
            if ((strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
                i++;
            } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
                g_config.port = atoi(argv[++i]);
            } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
                str_copy(g_config.bind_addr, argv[++i], sizeof(g_config.bind_addr));
            } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
                str_copy(g_config.cert_file, argv[++i], sizeof(g_config.cert_file));
            } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
                str_copy(g_config.key_file, argv[++i], sizeof(g_config.key_file));
            } else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--root") == 0) && i + 1 < argc) {
                str_copy(g_config.root_dir, argv[++i], sizeof(g_config.root_dir));
            } else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
                g_config.num_workers = atoi(argv[++i]);
            } else if (strcmp(argv[i], "-s") == 0) {
                g_config.enable_steer = 1;
            } else if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
                g_config.http_status = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--stats") == 0) {
                g_config.enable_stats = 1;
            } else if (strcmp(argv[i], "--no-stats") == 0) {
                g_config.enable_stats = 0;
            } else if (strcmp(argv[i], "--stats-path") == 0 && i + 1 < argc) {
                str_copy(g_config.stats_path, argv[++i], sizeof(g_config.stats_path));
            } else if (strcmp(argv[i], "--reset-path") == 0 && i + 1 < argc) {
                str_copy(g_config.reset_path, argv[++i], sizeof(g_config.reset_path));
            } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
                printf("tachyon v%s\n", TACHYON_VERSION);
                return 0;
            } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                print_usage(argv[0]);
                return 0;
            }
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
    http_init_routes(g_config.root_dir[0] ? g_config.root_dir : NULL);

    const char *cfile = g_config.cert_file[0] ? g_config.cert_file : NULL;
    const char *kfile = g_config.key_file[0] ? g_config.key_file : NULL;
    if (tls_init_server_ctx(cfile, kfile) < 0) {
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
    if (g_config.root_dir[0])
        printf("  Static Root     : %s\n", g_config.root_dir);
    else
        printf("  HTTP Response   : %d (%s)\n", g_config.http_status, g_config.http_status == 204 ? "No Content" : "OK");
    printf("  Live Stats      : %s (%s)\n", g_config.enable_stats ? "enabled" : "disabled", g_config.enable_stats ? g_config.stats_path : "none");
    if (g_config.reset_path[0])
        printf("  RST Path        : %s (444-style drop)\n", g_config.reset_path);
    printf("  Certificate     : %s\n", cfile ? cfile : "in-memory self-signed (ECDSA)");
    printf("===============================================================\n");
    fflush(stdout);

    for (int i = 0; i < num_workers; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            worker_run(lfds[i], cpus[i], i, conn_cap);
            _exit(0);
        }
        g_worker_pids[i] = pid;
        started[i] = time(NULL);
        g_num_running = i + 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handle_shutdown);
    signal(SIGINT, handle_shutdown);

    for (;;) {
        int status;
        pid_t dead = wait(&status);
        if (dead < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < num_workers; i++) {
            if (g_worker_pids[i] != dead) continue;

            /* back off a crash-looping worker so a broken one can't fork-storm the box */
            if (time(NULL) - started[i] < 5) {
                if (fastfails[i] < 6) fastfails[i]++;
            } else {
                fastfails[i] = 0;
            }
            if (fastfails[i] >= 2) {
                unsigned backoff = fastfails[i] >= 5 ? 30u : (1u << fastfails[i]);
                fprintf(stderr, "[tachyon] worker %d keeps dying fast, backing off %us\n", i, backoff);
                fflush(stderr);
                sleep(backoff);
            }

            pid_t pid = fork();
            if (pid == 0) {
                worker_run(lfds[i], cpus[i], i, conn_cap);
                _exit(0);
            }
            g_worker_pids[i] = pid;
            started[i] = time(NULL);
            fprintf(stderr, "[tachyon] worker %d (pid %d) died, respawned as pid %d\n", i, dead, pid);
            fflush(stderr);
        }
    }

    tls_destroy_server_ctx();
    http_free_routes();
    metrics_destroy(num_workers);
    return 0;
}
