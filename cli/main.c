/* main.c — the `mqproxy` CLI: client and server subcommands.
 *
 * Usage:
 *   mqproxy server --listen <udp ip:port> --token <t> [--cert <path> --key <path>]
 *   mqproxy client --server <udp ip:port> --token <t> --socks5 <tcp ip:port>
 *                  [--http-connect <tcp ip:port>] [--path <local ip>]...
 *                  [--client-id <id>]
 *
 * Dispatch is on argv[1] (`client` / `server`). `--help`/`-h` at the top level
 * and per subcommand prints usage and exits 0. An unknown subcommand or a
 * missing required flag prints usage to stderr and exits non-zero.
 *
 * This binary wires the transport (mq_engine + mq_path), the proxy core
 * (mq_client / mq_server), and the ingress listeners (SOCKS5 / HTTP CONNECT)
 * into runnable processes, then runs the libevent loop until SIGINT/SIGTERM.
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <event2/event.h>

#include "ingress/mq_listener.h"
#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "transport/mq_engine.h"
#include "transport/mq_path.h"
#include "util/mq_log.h"

/* Default cert/key for the server when --cert/--key are omitted, taken from the
 * test cert paths the build wires in (so the server is runnable out of the box
 * for local testing). Real deployments pass --cert/--key. */
#ifndef TEST_CERT_FILE
#  define TEST_CERT_FILE ""
#endif
#ifndef TEST_KEY_FILE
#  define TEST_KEY_FILE ""
#endif

/* Internal flow-control windows. Task 17 will apply these via the conn
 * settings; for now they are documented constants only (no --*-window flags). */
#define MQ_STREAM_WINDOW (8u * 1024u * 1024u)  /* 8 MiB per-stream window */
#define MQ_CONN_WINDOW   (16u * 1024u * 1024u) /* 16 MiB per-conn window */

#define MQ_MAX_EXTRA_PATHS 8

/* ── usage text ─────────────────────────────────────────────────────────────*/

static void
usage_top(FILE *out)
{
    fprintf(out, "Usage: mqproxy <command> [options]\n"
                 "\n"
                 "Commands:\n"
                 "  server   Run the mqproxy server (terminates proxied TCP).\n"
                 "  client   Run the mqproxy client with local SOCKS5 / HTTP CONNECT\n"
                 "           ingress listeners.\n"
                 "\n"
                 "Run 'mqproxy <command> --help' for command-specific options.\n");
}

static void
usage_server(FILE *out)
{
    fprintf(out, "Usage: mqproxy server --listen <ip:port> --token <token>\n"
                 "                      [--cert <path>] [--key <path>]\n"
                 "\n"
                 "Options:\n"
                 "  --listen <ip:port>  UDP address to accept MPQUIC connections on "
                 "(required).\n"
                 "  --token  <token>    Shared auth token clients must present "
                 "(required).\n"
                 "  --cert   <path>     TLS certificate (PEM). Defaults to the bundled\n"
                 "                      test cert when omitted.\n"
                 "  --key    <path>     TLS private key (PEM). Defaults to the bundled\n"
                 "                      test key when omitted.\n"
                 "  -h, --help          Show this help and exit.\n");
}

static void
usage_client(FILE *out)
{
    fprintf(out, "Usage: mqproxy client --server <ip:port> --token <token>\n"
                 "                      --socks5 <ip:port> [--http-connect <ip:port>]\n"
                 "                      [--path <local ip>]... [--client-id <id>]\n"
                 "\n"
                 "Options:\n"
                 "  --server       <ip:port>   UDP address of the mqproxy server "
                 "(required).\n"
                 "  --token        <token>     Shared auth token (required).\n"
                 "  --socks5       <ip:port>   Local TCP address for the SOCKS5 ingress "
                 "(required).\n"
                 "  --http-connect <ip:port>   Local TCP address for the HTTP CONNECT "
                 "ingress.\n"
                 "  --path         <local ip>  Local IP to bind a path to (repeatable). "
                 "The\n"
                 "                             first is the primary bind; extras are "
                 "deferred\n"
                 "                             to multipath support (Task 17).\n"
                 "  --client-id    <id>        Client identifier sent at auth "
                 "(default: mqproxy).\n"
                 "  -h, --help                 Show this help and exit.\n");
}

/* ── ip:port parsing ────────────────────────────────────────────────────────*/

/* Split "ip:port" into ip_out (capacity ip_cap) and *port_out. Supports
 * "[v6]:port" bracketed IPv6 form and plain "v4:port". Returns 0 on success,
 * -1 on malformed input. */
static int
parse_ip_port(const char *s, char *ip_out, size_t ip_cap, uint16_t *port_out)
{
    if (!s || !ip_out || !port_out) return -1;

    const char *colon;
    if (s[0] == '[') {
        const char *end = strchr(s, ']');
        if (!end || end[1] != ':') return -1;
        size_t iplen = (size_t)(end - (s + 1));
        if (iplen == 0 || iplen >= ip_cap) return -1;
        memcpy(ip_out, s + 1, iplen);
        ip_out[iplen] = '\0';
        colon = end + 1;
    } else {
        colon = strrchr(s, ':');
        if (!colon || colon == s) return -1;
        size_t iplen = (size_t)(colon - s);
        if (iplen >= ip_cap) return -1;
        memcpy(ip_out, s, iplen);
        ip_out[iplen] = '\0';
    }

    const char *port_str = colon + 1;
    if (*port_str == '\0') return -1;
    char *endp = NULL;
    errno = 0;
    long port = strtol(port_str, &endp, 10);
    if (errno != 0 || endp == port_str || *endp != '\0') return -1;
    if (port < 1 || port > 65535) return -1;

    /* Validate that ip_out parses as a v4 or v6 literal. */
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, ip_out, &a4) != 1 && inet_pton(AF_INET6, ip_out, &a6) != 1) {
        return -1;
    }

    *port_out = (uint16_t)port;
    return 0;
}

/* ── shutdown wiring (SIGINT/SIGTERM → mq_engine_stop) ───────────────────────*/

static void
on_signal(evutil_socket_t sig, short what, void *user)
{
    (void)sig;
    (void)what;
    mq_engine_t *eng = (mq_engine_t *)user;
    MQ_LOGI("signal received, shutting down");
    mq_engine_stop(eng);
}

/* Install SIGINT + SIGTERM handlers that break the loop. The returned events
 * must be freed by the caller after the loop exits. Returns 0 on success. */
static int
install_signal_handlers(struct event_base *base, mq_engine_t *eng, struct event **out_int,
                        struct event **out_term)
{
    struct event *sint = evsignal_new(base, SIGINT, on_signal, eng);
    struct event *sterm = evsignal_new(base, SIGTERM, on_signal, eng);
    if (!sint || !sterm) {
        if (sint) event_free(sint);
        if (sterm) event_free(sterm);
        return -1;
    }
    event_add(sint, NULL);
    event_add(sterm, NULL);
    *out_int = sint;
    *out_term = sterm;
    return 0;
}

/* ── server subcommand ──────────────────────────────────────────────────────*/

static int
cmd_server(int argc, char **argv)
{
    const char *listen = NULL;
    const char *token = NULL;
    const char *cert = NULL;
    const char *key = NULL;

    enum { OPT_LISTEN = 256, OPT_TOKEN, OPT_CERT, OPT_KEY };
    static const struct option longopts[] = {
        {"listen", required_argument, NULL, OPT_LISTEN},
        {"token", required_argument, NULL, OPT_TOKEN},
        {"cert", required_argument, NULL, OPT_CERT},
        {"key", required_argument, NULL, OPT_KEY},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    optind = 1; /* argv here starts at the subcommand */
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case OPT_LISTEN: listen = optarg; break;
        case OPT_TOKEN: token = optarg; break;
        case OPT_CERT: cert = optarg; break;
        case OPT_KEY: key = optarg; break;
        case 'h': usage_server(stdout); return 0;
        default: usage_server(stderr); return 2;
        }
    }

    if (!listen) {
        fprintf(stderr, "mqproxy server: missing required --listen\n\n");
        usage_server(stderr);
        return 2;
    }
    if (!token) {
        fprintf(stderr, "mqproxy server: missing required --token\n\n");
        usage_server(stderr);
        return 2;
    }
    if (!cert) cert = TEST_CERT_FILE;
    if (!key) key = TEST_KEY_FILE;
    if (cert[0] == '\0' || key[0] == '\0') {
        fprintf(stderr, "mqproxy server: --cert and --key are required (no bundled "
                        "default in this build)\n\n");
        usage_server(stderr);
        return 2;
    }

    char listen_ip[INET6_ADDRSTRLEN];
    uint16_t listen_port = 0;
    if (parse_ip_port(listen, listen_ip, sizeof(listen_ip), &listen_port) != 0) {
        fprintf(stderr, "mqproxy server: invalid --listen address: %s\n", listen);
        return 2;
    }

    int rc = 1;
    struct event_base *base = NULL;
    mq_engine_t *eng = NULL;
    mq_path_t *path = NULL;
    mq_server_t *server = NULL;
    struct event *sint = NULL, *sterm = NULL;

    base = event_base_new();
    if (!base) {
        MQ_LOGE("failed to create event base");
        goto out;
    }
    eng = mq_engine_new_server(base, cert, key);
    if (!eng) {
        MQ_LOGE("failed to create server engine (cert=%s key=%s)", cert, key);
        goto out;
    }
    path = mq_path_open(eng, 0, listen_ip, listen_port);
    if (!path) {
        MQ_LOGE("failed to bind listen path %s:%u", listen_ip, listen_port);
        goto out;
    }
    server = mq_server_new(eng, token);
    if (!server) {
        MQ_LOGE("failed to create server");
        goto out;
    }
    if (install_signal_handlers(base, eng, &sint, &sterm) != 0) {
        MQ_LOGE("failed to install signal handlers");
        goto out;
    }

    MQ_LOGI("mqproxy server listening on %s:%u", listen_ip, listen_port);
    mq_engine_run(eng);
    rc = 0;

out:
    /* Teardown order (see cmd_client for the rationale): the server's per-conn
     * state is touched by conn-close callbacks fired while the engine tears down
     * its connections, so the engine must be freed BEFORE the server. Order:
     * signal events -> path -> engine (fires conn-close into the live server) ->
     * server -> base. */
    if (sint) event_free(sint);
    if (sterm) event_free(sterm);
    if (path) mq_path_close(path);
    if (eng) mq_engine_free(eng);
    if (server) mq_server_free(server);
    if (base) event_base_free(base);
    return rc;
}

/* ── client subcommand ──────────────────────────────────────────────────────*/

static int
cmd_client(int argc, char **argv)
{
    const char *server = NULL;
    const char *token = NULL;
    const char *socks5 = NULL;
    const char *http_connect = NULL;
    const char *client_id = "mqproxy";
    const char *paths[MQ_MAX_EXTRA_PATHS];
    size_t npaths = 0;

    enum {
        OPT_SERVER = 256,
        OPT_TOKEN,
        OPT_SOCKS5,
        OPT_HTTP,
        OPT_PATH,
        OPT_CLIENT_ID,
    };
    static const struct option longopts[] = {
        {"server", required_argument, NULL, OPT_SERVER},
        {"token", required_argument, NULL, OPT_TOKEN},
        {"socks5", required_argument, NULL, OPT_SOCKS5},
        {"http-connect", required_argument, NULL, OPT_HTTP},
        {"path", required_argument, NULL, OPT_PATH},
        {"client-id", required_argument, NULL, OPT_CLIENT_ID},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    optind = 1;
    int c;
    while ((c = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (c) {
        case OPT_SERVER: server = optarg; break;
        case OPT_TOKEN: token = optarg; break;
        case OPT_SOCKS5: socks5 = optarg; break;
        case OPT_HTTP: http_connect = optarg; break;
        case OPT_PATH:
            if (npaths < MQ_MAX_EXTRA_PATHS) {
                paths[npaths++] = optarg;
            } else {
                MQ_LOGW("too many --path options (max %d); ignoring %s",
                        MQ_MAX_EXTRA_PATHS, optarg);
            }
            break;
        case OPT_CLIENT_ID: client_id = optarg; break;
        case 'h': usage_client(stdout); return 0;
        default: usage_client(stderr); return 2;
        }
    }

    if (!server) {
        fprintf(stderr, "mqproxy client: missing required --server\n\n");
        usage_client(stderr);
        return 2;
    }
    if (!token) {
        fprintf(stderr, "mqproxy client: missing required --token\n\n");
        usage_client(stderr);
        return 2;
    }
    if (!socks5) {
        fprintf(stderr, "mqproxy client: missing required --socks5\n\n");
        usage_client(stderr);
        return 2;
    }

    char server_ip[INET6_ADDRSTRLEN];
    uint16_t server_port = 0;
    if (parse_ip_port(server, server_ip, sizeof(server_ip), &server_port) != 0) {
        fprintf(stderr, "mqproxy client: invalid --server address: %s\n", server);
        return 2;
    }
    char socks5_ip[INET6_ADDRSTRLEN];
    uint16_t socks5_port = 0;
    if (parse_ip_port(socks5, socks5_ip, sizeof(socks5_ip), &socks5_port) != 0) {
        fprintf(stderr, "mqproxy client: invalid --socks5 address: %s\n", socks5);
        return 2;
    }
    char http_ip[INET6_ADDRSTRLEN];
    uint16_t http_port = 0;
    if (http_connect &&
        parse_ip_port(http_connect, http_ip, sizeof(http_ip), &http_port) != 0) {
        fprintf(stderr, "mqproxy client: invalid --http-connect address: %s\n",
                http_connect);
        return 2;
    }

    /* The primary local bind for the client path. If --path was given, the
     * first one is the primary bind; extras are deferred to Task 17 (multipath
     * add). Otherwise bind to the unspecified IPv4 address with an ephemeral
     * port. */
    const char *primary_ip = (npaths > 0) ? paths[0] : "0.0.0.0";
    for (size_t i = 1; i < npaths; i++) {
        MQ_LOGW("multipath not yet wired (Task 17): ignoring extra --path %s", paths[i]);
    }

    int rc = 1;
    struct event_base *base = NULL;
    mq_engine_t *eng = NULL;
    mq_path_t *path = NULL;
    mq_client_t *client = NULL;
    mq_listener_t *socks5_l = NULL;
    mq_listener_t *http_l = NULL;
    struct event *sint = NULL, *sterm = NULL;

    base = event_base_new();
    if (!base) {
        MQ_LOGE("failed to create event base");
        goto out;
    }
    eng = mq_engine_new(0, base);
    if (!eng) {
        MQ_LOGE("failed to create client engine");
        goto out;
    }
    path = mq_path_open(eng, 0, primary_ip, 0);
    if (!path) {
        MQ_LOGE("failed to bind primary path %s", primary_ip);
        goto out;
    }
    /* TODO(Task 17): apply MQ_STREAM_WINDOW / MQ_CONN_WINDOW via conn settings.
     * mq_client_new manages its own settings internally for Phase 1. */
    (void)MQ_STREAM_WINDOW;
    (void)MQ_CONN_WINDOW;
    client = mq_client_new(eng, server_ip, server_port, client_id, token);
    if (!client) {
        MQ_LOGE("failed to create client");
        goto out;
    }
    if (mq_client_start(client) != 0) {
        MQ_LOGE("failed to start client connection to %s:%u", server_ip, server_port);
        goto out;
    }

    mq_tcp_open_fn open_fn = mq_client_tcp_open_fn();
    void *open_core = mq_client_tcp_open_core(client);

    socks5_l = mq_socks5_listener_new(base, socks5_ip, socks5_port, open_fn, open_core);
    if (!socks5_l) {
        MQ_LOGE("failed to bind SOCKS5 listener on %s:%u", socks5_ip, socks5_port);
        goto out;
    }
    if (http_connect) {
        http_l =
            mq_http_connect_listener_new(base, http_ip, http_port, open_fn, open_core);
        if (!http_l) {
            MQ_LOGE("failed to bind HTTP CONNECT listener on %s:%u", http_ip, http_port);
            goto out;
        }
    }
    if (install_signal_handlers(base, eng, &sint, &sterm) != 0) {
        MQ_LOGE("failed to install signal handlers");
        goto out;
    }

    MQ_LOGI("mqproxy client: server=%s:%u socks5=%s:%u%s%s%s (bind %s)", server_ip,
            server_port, socks5_ip, socks5_port, http_connect ? " http-connect=" : "",
            http_connect ? http_ip : "", http_connect ? "" : "", primary_ip);
    mq_engine_run(eng);
    rc = 0;

out:
    /* Teardown order — verified against the in-flight callback graph (an earlier
     * "free client first" ordering tripped a heap-use-after-free under ASan):
     *
     *   - The client registers client_on_state() on its mq_conn. That callback
     *     is invoked DURING mq_engine_free (conn destroy -> close-notify), and on
     *     MQ_CONN_CLOSED it (a) touches the mq_client and (b) FAILS every
     *     in-flight tcp_open, firing each open-result cb. Those cbs write the
     *     SOCKS5/HTTP reject reply onto the listener's per-conn state.
     *   - Therefore BOTH the client AND the listeners must still be alive while
     *     the engine is torn down. The engine must be freed FIRST so its
     *     callbacks land on live objects.
     *
     * Order: signal events -> path (unregister fd) -> engine (fires all
     * conn-close + in-flight-open callbacks into the live client/listeners) ->
     * client -> listeners -> base. (Matches the integration fixture, which frees
     * paths+engine before the client/server for the same reason.) */
    if (sint) event_free(sint);
    if (sterm) event_free(sterm);
    if (path) mq_path_close(path);
    if (eng) mq_engine_free(eng);
    if (client) mq_client_free(client);
    if (socks5_l) mq_listener_free(socks5_l);
    if (http_l) mq_listener_free(http_l);
    if (base) event_base_free(base);
    return rc;
}

/* ── dispatch ───────────────────────────────────────────────────────────────*/

int
main(int argc, char **argv)
{
    mq_log_set_level(MQ_LOG_INFO);

    if (argc < 2) {
        usage_top(stderr);
        return 2;
    }

    const char *sub = argv[1];
    if (strcmp(sub, "-h") == 0 || strcmp(sub, "--help") == 0) {
        usage_top(stdout);
        return 0;
    }
    if (strcmp(sub, "server") == 0) {
        return cmd_server(argc - 1, argv + 1);
    }
    if (strcmp(sub, "client") == 0) {
        return cmd_client(argc - 1, argv + 1);
    }

    fprintf(stderr, "mqproxy: unknown command '%s'\n\n", sub);
    usage_top(stderr);
    return 2;
}
