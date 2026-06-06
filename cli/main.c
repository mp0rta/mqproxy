// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta

/* main.c — the `mqproxy` CLI: client and server subcommands.
 *
 * Usage:
 *   mqproxy server --listen <udp ip:port> --token <t> [--cert <path> --key <path>]
 *                  [--origin-ca <pem>] [--no-gateway]
 *   mqproxy client --server <udp ip:port> --token <t>
 *                  [--socks5 <tcp ip:port>] [--http-connect <tcp ip:port>]
 *                  [--gateway <tcp ip:port>] [--path <local ip>]...
 *                  [--client-id <id>] [--qlog <dir>]
 *
 *   The client needs at least one ingress: --socks5, --http-connect, or
 *   --gateway. --socks5 / --http-connect drive the TCP-proxy core (mq_client);
 *   --gateway runs the independent HTTP-gateway fetch ingress (mq_gw_client over
 *   its own H3 tunnel) and may be used on its own.
 *
 *   The server runs the HTTP-gateway origin bridge (mq_gw_server: H3→curl→origin)
 *   by DEFAULT alongside the TCP-proxy server core. --no-gateway disables it;
 *   --origin-ca overrides the CA bundle used to verify origin TLS.
 *
 * Dispatch is on argv[1] (`client` / `server`). `--help`/`-h` at the top level
 * and per subcommand prints usage and exits 0. An unknown subcommand or a
 * missing required flag prints usage to stderr and exits non-zero.
 *
 * This binary wires the transport (mq_transport + mq_runtime), the proxy core
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

#include "gateway/mq_fetch_listener.h"
#include "gateway/mq_gw_client.h"
#include "gateway/mq_gw_server.h"
#include "ingress/mq_listener.h"
#include "proxy/mq_client.h"
#include "proxy/mq_server.h"
#include "runtime/mq_runtime_libevent.h"
#include "transport/mq_h3.h"
#include "transport/mq_transport.h"
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

/* Flow-control windows (MQ_STREAM_WINDOW / MQ_CONN_WINDOW) are defined in
 * transport/mq_conn.h and applied by mq_client_new / mq_server_new via
 * mq_conn_apply_mp_settings — no CLI window flags in Phase 1. */

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
                 "                      [--origin-ca <pem>] [--no-gateway]\n"
                 "                      [--udp-idle-timeout <sec>] [--no-udp]\n"
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
                 "  --origin-ca <pem>   CA bundle (PEM) used to verify origin TLS for "
                 "the\n"
                 "                      HTTP gateway. Defaults to the system trust "
                 "store.\n"
                 "  --no-gateway        Disable the HTTP gateway origin bridge "
                 "(enabled by\n"
                 "                      default; the server still serves the TCP-proxy "
                 "core).\n"
                 "  --udp-idle-timeout <sec>\n"
                 "                      Idle timeout for UDP relay sessions in seconds\n"
                 "                      (default: 60; must be > 0).\n"
                 "  --no-udp            Disable UDP relay (do not advertise "
                 "MQ_FEAT_UDP_RELAY).\n"
                 "  --qlog   <dir>      Write xquic qlog (EXTRA importance) to "
                 "<dir>/server.qlog.\n"
                 "  --cc     <algo>     Congestion control: bbr (default) | bbr2 | "
                 "cubic.\n"
                 "  -h, --help          Show this help and exit.\n");
}

static void
usage_client(FILE *out)
{
    fprintf(out,
            "Usage: mqproxy client --server <ip:port> --token <token>\n"
            "                      [--socks5 <ip:port>] [--http-connect <ip:port>]\n"
            "                      [--gateway <ip:port>] [--path <local ip>]...\n"
            "                      [--client-id <id>]\n"
            "\n"
            "At least one ingress is required: --socks5, --http-connect, or "
            "--gateway.\n"
            "\n"
            "Options:\n"
            "  --server       <ip:port>   UDP address of the mqproxy server "
            "(required).\n"
            "  --token        <token>     Shared auth token (required).\n"
            "  --socks5       <ip:port>   Local TCP address for the SOCKS5 ingress\n"
            "                             (UDP ASSOCIATE supported).\n"
            "  --http-connect <ip:port>   Local TCP address for the HTTP CONNECT "
            "ingress.\n"
            "  --gateway      <ip:port>   Local TCP address for the HTTP gateway "
            "fetch\n"
            "                             ingress (POST /_mqproxy/fetch over its own "
            "H3\n"
            "                             tunnel; independent of the SOCKS5/CONNECT "
            "core).\n"
            "  --path         <local ip>  Local IP to bind a path to (repeatable). "
            "The\n"
            "                             first is the primary bind; each extra "
            "becomes a\n"
            "                             second/third MPQUIC path once the "
            "connection is\n"
            "                             multipath-ready.\n"
            "  --client-id    <id>        Client identifier sent at auth "
            "(default: mqproxy).\n"
            "  --qlog         <dir>       Write xquic qlog (EXTRA importance) to "
            "<dir>/client.qlog\n"
            "                             (the 1-B blocked-frame instrument).\n"
            "  --cc           <algo>      Congestion control: bbr (default) | bbr2 "
            "| cubic.\n"
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

/* ── shutdown wiring (SIGINT/SIGTERM → mq_runtime_stop) ──────────────────────*/

static void
on_signal(evutil_socket_t sig, short what, void *user)
{
    (void)sig;
    (void)what;
    mq_runtime_t *rt = (mq_runtime_t *)user;
    MQ_LOGI("signal received, shutting down");
    mq_runtime_stop(rt);
}

/* Install SIGINT + SIGTERM handlers that break the loop. The returned events
 * must be freed by the caller after the loop exits. Returns 0 on success. */
static int
install_signal_handlers(struct event_base *base, mq_runtime_t *rt, struct event **out_int,
                        struct event **out_term)
{
    struct event *sint = evsignal_new(base, SIGINT, on_signal, rt);
    struct event *sterm = evsignal_new(base, SIGTERM, on_signal, rt);
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

/* Default origin connect timeout (seconds) for the gateway bridge. */
#define MQ_GW_ORIGIN_CONNECT_TIMEOUT_DEFAULT_S 10L

/* Resolve the origin connect timeout. The default is
 * MQ_GW_ORIGIN_CONNECT_TIMEOUT_DEFAULT_S; the env var
 * MQ_GW_ORIGIN_CONNECT_TIMEOUT_S is a TEST-ONLY knob (NOT documented in --help)
 * that lets e2e tests force a short timeout so a black-holed origin yields a
 * deterministic 504. Parsed with strtol, clamped to [1, 600]; anything invalid
 * (non-numeric, trailing junk, empty, out of range) is ignored and the default
 * stands. */
static long
gw_origin_connect_timeout_s(void)
{
    const char *env = getenv("MQ_GW_ORIGIN_CONNECT_TIMEOUT_S");
    if (!env || env[0] == '\0') return MQ_GW_ORIGIN_CONNECT_TIMEOUT_DEFAULT_S;
    char *endp = NULL;
    errno = 0;
    long v = strtol(env, &endp, 10);
    if (errno != 0 || endp == env || *endp != '\0') {
        return MQ_GW_ORIGIN_CONNECT_TIMEOUT_DEFAULT_S;
    }
    if (v < 1 || v > 600) return MQ_GW_ORIGIN_CONNECT_TIMEOUT_DEFAULT_S;
    return v;
}

static int
cmd_server(int argc, char **argv)
{
    const char *listen = NULL;
    const char *token = NULL;
    const char *cert = NULL;
    const char *key = NULL;
    const char *origin_ca = NULL; /* nullable: NULL = system trust store */
    const char *qlog_dir = NULL;
    const char *cc_name = NULL;
    mq_cc_t cc = MQ_CC_DEFAULT;
    int gateway_enabled = 1;      /* gateway on by default; --no-gateway opts out */
    long udp_idle_timeout_s = 60; /* --udp-idle-timeout <sec>, default 60 */
    int udp_enabled = 1;          /* --no-udp clears this */

    enum {
        OPT_LISTEN = 256,
        OPT_TOKEN,
        OPT_CERT,
        OPT_KEY,
        OPT_ORIGIN_CA,
        OPT_NO_GATEWAY,
        OPT_UDP_IDLE_TIMEOUT,
        OPT_NO_UDP,
        OPT_QLOG,
        OPT_CC,
    };
    static const struct option longopts[] = {
        {"listen", required_argument, NULL, OPT_LISTEN},
        {"token", required_argument, NULL, OPT_TOKEN},
        {"cert", required_argument, NULL, OPT_CERT},
        {"key", required_argument, NULL, OPT_KEY},
        {"origin-ca", required_argument, NULL, OPT_ORIGIN_CA},
        {"no-gateway", no_argument, NULL, OPT_NO_GATEWAY},
        {"udp-idle-timeout", required_argument, NULL, OPT_UDP_IDLE_TIMEOUT},
        {"no-udp", no_argument, NULL, OPT_NO_UDP},
        {"qlog", required_argument, NULL, OPT_QLOG},
        {"cc", required_argument, NULL, OPT_CC},
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
        case OPT_ORIGIN_CA: origin_ca = optarg; break;
        case OPT_NO_GATEWAY: gateway_enabled = 0; break;
        case OPT_UDP_IDLE_TIMEOUT: {
            char *endp = NULL;
            errno = 0;
            long v = strtol(optarg, &endp, 10);
            if (errno != 0 || endp == optarg || *endp != '\0' || v <= 0) {
                fprintf(
                    stderr,
                    "mqproxy server: invalid --udp-idle-timeout '%s' (must be > 0)\n\n",
                    optarg);
                usage_server(stderr);
                return 2;
            }
            udp_idle_timeout_s = v;
            break;
        }
        case OPT_NO_UDP: udp_enabled = 0; break;
        case OPT_QLOG: qlog_dir = optarg; break;
        case OPT_CC: cc_name = optarg; break;
        case 'h': usage_server(stdout); return 0;
        default: usage_server(stderr); return 2;
        }
    }

    if (cc_name) {
        int ok = 0;
        cc = mq_cc_from_string(cc_name, &ok);
        if (!ok) {
            fprintf(stderr, "mqproxy server: invalid --cc '%s' (bbr2|bbr|cubic)\n\n",
                    cc_name);
            usage_server(stderr);
            return 2;
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
    mq_transport_t *transport = NULL;
    mq_runtime_t *rt = NULL;
    mq_server_t *server = NULL;
    mq_gw_server_t *gws = NULL;
    struct event *sint = NULL, *sterm = NULL;

    base = event_base_new();
    if (!base) {
        MQ_LOGE("failed to create event base");
        goto out;
    }
    /* The runtime installs its callbacks onto the transport via
     * mq_transport_set_callbacks (in mq_runtime_new). */
    transport = mq_transport_new_server(cert, key);
    if (!transport) {
        MQ_LOGE("failed to create server transport (cert=%s key=%s)", cert, key);
        goto out;
    }
    if (qlog_dir) {
        const char *qpath = NULL;
        if (mq_transport_enable_qlog(transport, qlog_dir, &qpath) != 0) {
            MQ_LOGE("failed to enable qlog in %s", qlog_dir);
            goto out;
        }
        MQ_LOGI("server qlog -> %s", qpath);
    }
    rt = mq_runtime_new(transport, base);
    if (!rt) {
        MQ_LOGE("failed to create runtime");
        goto out;
    }
    if (mq_runtime_open_udp_path(rt, listen_ip, listen_port) != 0) {
        MQ_LOGE("failed to bind listen path %s:%u", listen_ip, listen_port);
        goto out;
    }
    server = mq_server_new(transport, rt, token, cc, (uint64_t)udp_idle_timeout_s * 1000u,
                           udp_enabled);
    if (!server) {
        MQ_LOGE("failed to create server");
        goto out;
    }
    /* HTTP gateway origin bridge (mq_gw_server: H3 request → curl → origin). On
     * by default; --no-gateway opts out. Because it is default-on, a failure to
     * stand it up is FATAL (exit non-zero) rather than a silent degrade — a
     * server that was meant to gateway but isn't is worse than a loud failure.
     * mq_gw_server_new calls mq_h3_init internally and owns the H3 hooks; the
     * created mq_h3 is reclaimed in the teardown block per the header contract. */
    if (gateway_enabled) {
        long connect_timeout_s = gw_origin_connect_timeout_s();
        gws = mq_gw_server_new(transport, rt, token, origin_ca, connect_timeout_s);
        if (!gws) {
            MQ_LOGE("failed to create HTTP gateway server (origin_ca=%s, "
                    "connect_timeout=%lds)",
                    origin_ca ? origin_ca : "(system)", connect_timeout_s);
            goto out;
        }
    }
    if (install_signal_handlers(base, rt, &sint, &sterm) != 0) {
        MQ_LOGE("failed to install signal handlers");
        goto out;
    }

    MQ_LOGI(
        "mqproxy server listening on %s:%u (cc=%s, gateway=%s, udp=%s, udp-idle=%lds)",
        listen_ip, listen_port, mq_cc_name(cc), gateway_enabled ? "on" : "off",
        udp_enabled ? "on" : "off", udp_idle_timeout_s);
    mq_runtime_run(rt);
    rc = 0;

out:
    /* Teardown order — the TCP-proxy server core and the HTTP-gateway origin
     * bridge have ordering contracts that pull in OPPOSITE directions across
     * mq_transport_free; both are honored below.
     *
     * (A) TCP-proxy server core (mq_server + runtime): the server's per-conn
     *     state + the runtime are both touched by conn-close callbacks fired
     *     while the engine tears down its connections (inside mq_transport_free):
     *       - the transport's send_udp callback (the runtime, as cbs.user) may be
     *         invoked for a final CONNECTION_CLOSE — so the RUNTIME must outlive
     *         mq_transport_free;
     *       - conn-close fires the server's on_state(CLOSED) which reaps flows and
     *         reads mq_runtime_base(rt) — so the SERVER and the RUNTIME must both
     *         be alive during mq_transport_free.
     *     Therefore free the TRANSPORT first (engine destroy, callbacks land on
     *     the live runtime + server), then the runtime (closes sockets/timer;
     *     does not free base), then the server.
     *
     * (B) HTTP-gateway bridge (mq_gw_server + the mq_h3 it created): the
     *     SANCTIONED order (mq_gw_server.h) is gw_server_free → mq_h3_free →
     *     mq_transport_free. gw_server_free MUST run while the H3 engine is STILL
     *     LIVE (it touches r->req on live in-flight requests via
     *     mq_h3_req_set_cbs(NULL,...)); mq_h3_free MUST precede mq_transport_free.
     *     Capture the h3 handle BEFORE gw_server_free — the accessor reads the
     *     gw_server struct, which free() releases.
     *
     * Combined order:
     *   signal events
     *   -> gw_server_free   (engine live; detaches in-flight H3 req cbs, aborts
     *                        origin requests, frees the origin client)
     *   -> mq_h3_free       (the gw_server's H3 engine; gateway/tcp ALPN conn
     *                        graphs are independent, so this does not disturb the
     *                        tcp conns mq_transport_free later tears down)
     *   -> mq_transport_free (fires graph-A conn-close cbs into live runtime+server)
     *   -> runtime free
     *   -> mq_server_free
     *   -> base free (CLI owns base). */
    if (sint) event_free(sint);
    if (sterm) event_free(sterm);
    {
        mq_h3_t *gw_h3 = gws ? mq_gw_server_h3(gws) : NULL;
        if (gws) mq_gw_server_free(gws);
        if (gw_h3) mq_h3_free(gw_h3);
    }
    if (transport) mq_transport_free(transport);
    if (rt) mq_runtime_free(rt);
    if (server) mq_server_free(server);
    if (base) event_base_free(base);
    return rc;
}

/* ── client subcommand ──────────────────────────────────────────────────────*/

/* Context for the on_auth callback: carries the SOCKS5 listener handle so the
 * callback can drive the UDP-availability tri-state after auth settles.
 * socks5_l may be NULL (HTTP-only client); mq_listener_set_udp_availability
 * is a no-op on NULL, so the glue is always safe to call. */
struct client_auth_ctx {
    mq_client_t *client;
    mq_listener_t *socks5_l;
};

/* Called once by mq_client when the AUTH_RESPONSE arrives.  Drives the SOCKS5
 * listener's UDP-availability tri-state (Task 6.3 supply point):
 *   ok=1  → mq_client_udp_available() — 1 if server advertised the feature AND
 *            datagram mss > 0, else 0.
 *   ok=0  → 0 (auth failed; sweep any pre-auth ASSOCIATE sessions). */
static void
client_on_auth(int ok, mq_auth_err_t err, void *user)
{
    struct client_auth_ctx *ctx = (struct client_auth_ctx *)user;
    (void)err;
    int avail = ok ? mq_client_udp_available(ctx->client) : 0;
    mq_listener_set_udp_availability(ctx->socks5_l, avail);
}

static int
cmd_client(int argc, char **argv)
{
    const char *server = NULL;
    const char *token = NULL;
    const char *socks5 = NULL;
    const char *http_connect = NULL;
    const char *gateway = NULL;
    const char *client_id = "mqproxy";
    const char *qlog_dir = NULL;
    const char *cc_name = NULL;
    mq_cc_t cc = MQ_CC_DEFAULT;
    const char *paths[MQ_MAX_EXTRA_PATHS];
    size_t npaths = 0;

    enum {
        OPT_SERVER = 256,
        OPT_TOKEN,
        OPT_SOCKS5,
        OPT_HTTP,
        OPT_GATEWAY,
        OPT_PATH,
        OPT_CLIENT_ID,
        OPT_QLOG,
        OPT_CC,
    };
    static const struct option longopts[] = {
        {"server", required_argument, NULL, OPT_SERVER},
        {"token", required_argument, NULL, OPT_TOKEN},
        {"socks5", required_argument, NULL, OPT_SOCKS5},
        {"http-connect", required_argument, NULL, OPT_HTTP},
        {"gateway", required_argument, NULL, OPT_GATEWAY},
        {"path", required_argument, NULL, OPT_PATH},
        {"client-id", required_argument, NULL, OPT_CLIENT_ID},
        {"qlog", required_argument, NULL, OPT_QLOG},
        {"cc", required_argument, NULL, OPT_CC},
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
        case OPT_GATEWAY: gateway = optarg; break;
        case OPT_PATH:
            if (npaths < MQ_MAX_EXTRA_PATHS) {
                paths[npaths++] = optarg;
            } else {
                MQ_LOGW("too many --path options (max %d); ignoring %s",
                        MQ_MAX_EXTRA_PATHS, optarg);
            }
            break;
        case OPT_CLIENT_ID: client_id = optarg; break;
        case OPT_QLOG: qlog_dir = optarg; break;
        case OPT_CC: cc_name = optarg; break;
        case 'h': usage_client(stdout); return 0;
        default: usage_client(stderr); return 2;
        }
    }

    if (cc_name) {
        int ok = 0;
        cc = mq_cc_from_string(cc_name, &ok);
        if (!ok) {
            fprintf(stderr, "mqproxy client: invalid --cc '%s' (bbr2|bbr|cubic)\n\n",
                    cc_name);
            usage_client(stderr);
            return 2;
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
    if (!socks5 && !http_connect && !gateway) {
        fprintf(stderr, "mqproxy client: at least one ingress is required "
                        "(--socks5, --http-connect, or --gateway)\n\n");
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
    if (socks5 &&
        parse_ip_port(socks5, socks5_ip, sizeof(socks5_ip), &socks5_port) != 0) {
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
    char gw_ip[INET6_ADDRSTRLEN];
    uint16_t gw_port = 0;
    if (gateway && parse_ip_port(gateway, gw_ip, sizeof(gw_ip), &gw_port) != 0) {
        fprintf(stderr, "mqproxy client: invalid --gateway address: %s\n", gateway);
        return 2;
    }

    /* The TCP-proxy core (mq_client) is needed iff a SOCKS5 or HTTP CONNECT
     * ingress is requested — both ride mq_client's tcp_open core. The gateway
     * ingress is independent (its own mq_gw_client conn + auth), so a gateway-
     * only client skips mq_client entirely. */
    const int need_client = (socks5 != NULL) || (http_connect != NULL);

    /* The primary local bind for the client path. If --path was given, the
     * first one is the primary bind; each extra --path is brought up as an
     * additional MPQUIC path once the connection is multipath-ready (wired
     * below via mq_client_add_paths). Otherwise bind the unspecified IPv4
     * address with an ephemeral port. */
    const char *primary_ip = (npaths > 0) ? paths[0] : "0.0.0.0";

    int rc = 1;
    struct event_base *base = NULL;
    mq_transport_t *transport = NULL;
    mq_runtime_t *rt = NULL;
    mq_client_t *client = NULL;
    mq_listener_t *socks5_l = NULL;
    mq_listener_t *http_l = NULL;
    mq_h3_t *h3 = NULL;
    mq_gw_client_t *gwc = NULL;
    mq_fetch_listener_t *fetch_l = NULL;
    struct event *sint = NULL, *sterm = NULL;
    struct client_auth_ctx auth_ctx = {NULL, NULL};

    base = event_base_new();
    if (!base) {
        MQ_LOGE("failed to create event base");
        goto out;
    }
    /* The runtime installs its callbacks onto the transport via
     * mq_transport_set_callbacks (in mq_runtime_new). */
    transport = mq_transport_new(/*is_server=*/0);
    if (!transport) {
        MQ_LOGE("failed to create client transport");
        goto out;
    }
    if (qlog_dir) {
        const char *qpath = NULL;
        if (mq_transport_enable_qlog(transport, qlog_dir, &qpath) != 0) {
            MQ_LOGE("failed to enable qlog in %s", qlog_dir);
            goto out;
        }
        MQ_LOGI("client qlog -> %s", qpath);
    }
    rt = mq_runtime_new(transport, base);
    if (!rt) {
        MQ_LOGE("failed to create runtime");
        goto out;
    }
    if (mq_runtime_open_udp_path(rt, primary_ip, 0) != 0) {
        MQ_LOGE("failed to bind primary path %s", primary_ip);
        goto out;
    }
    /* TCP-proxy core (mq_client) + its SOCKS5/HTTP CONNECT ingress. Only created
     * when a SOCKS5 or HTTP CONNECT ingress was requested; a gateway-only client
     * skips it (the gateway conn below is independent, with its own auth). */
    if (need_client) {
        /* Window + multipath conn settings are applied inside mq_client_new
         * (mq_conn_apply_mp_settings). */
        client =
            mq_client_new(transport, rt, server_ip, server_port, client_id, token, cc);
        if (!client) {
            MQ_LOGE("failed to create client");
            goto out;
        }
        if (mq_client_start(client) != 0) {
            MQ_LOGE("failed to start client connection to %s:%u", server_ip, server_port);
            goto out;
        }

        /* Bring up each extra --path (paths[1..]) as an additional MPQUIC path
         * once the connection is multipath-ready (deferred internally via
         * mq_conn_add_path). paths[0] is the primary bind handled above. */
        if (npaths > 1) {
            int added = mq_client_add_paths(client, &paths[1], npaths - 1);
            if (added < 0) {
                MQ_LOGE("failed to register extra paths");
                goto out;
            }
            MQ_LOGI("registered %d extra multipath bind(s) (added once mp-ready)", added);
        }

        mq_tcp_open_fn open_fn = mq_client_tcp_open_fn();
        void *open_core = mq_client_tcp_open_core(client);

        if (socks5) {
            /* SOCKS5 listener also services CMD UDP ASSOCIATE via the UDP relay
             * boundary (mq_ingress.h). The UDP `core` is the relay table
             * (mq_udp_cli_t*), distinct from the TCP `core` (mq_client_t*). The
             * availability tri-state stays at its -1 default until the on_auth
             * glue (Task 6.4) calls mq_listener_set_udp_availability. */
            socks5_l = mq_socks5_listener_new(
                base, socks5_ip, socks5_port, open_fn, open_core, mq_client_udp_open_fn(),
                mq_client_udp_send_fn(), mq_client_udp_close_fn(),
                mq_client_udp_open_core(client));
            if (!socks5_l) {
                MQ_LOGE("failed to bind SOCKS5 listener on %s:%u", socks5_ip,
                        socks5_port);
                goto out;
            }
        }
        if (http_connect) {
            /* HTTP CONNECT has no ASSOCIATE; pass the udp quad NULL. */
            http_l = mq_http_connect_listener_new(base, http_ip, http_port, open_fn,
                                                  open_core, NULL, NULL, NULL, NULL);
            if (!http_l) {
                MQ_LOGE("failed to bind HTTP CONNECT listener on %s:%u", http_ip,
                        http_port);
                goto out;
            }
        }

        /* Wire the auth-result callback: on auth settle, propagate the UDP
         * relay availability tri-state to the SOCKS5 listener so it can
         * admit or sweep ASSOCIATE sessions (Task 6.3 supply point).
         * socks5_l may be NULL here (HTTP-only client) — that is safe because
         * mq_listener_set_udp_availability(NULL, ...) is a no-op. */
        auth_ctx.client = client;
        auth_ctx.socks5_l = socks5_l;
        mq_client_set_on_auth(client, client_on_auth, &auth_ctx);
    }

    /* HTTP gateway ingress (--gateway): an independent H3 tunnel to the same
     * server (its own conn + X-Mq-Auth), fronted by a local fetch-API listener.
     * mq_h3_init takes NULL server hooks (pure client). The gateway conn is
     * established EAGERLY inside mq_gw_client_new. */
    if (gateway) {
        h3 = mq_h3_init(transport, NULL, NULL, NULL);
        if (!h3) {
            MQ_LOGE("failed to init H3 stack for gateway");
            goto out;
        }
        gwc = mq_gw_client_new(transport, rt, h3, server_ip, server_port, token, cc);
        if (!gwc) {
            MQ_LOGE("failed to create gateway client (conn to %s:%u)", server_ip,
                    server_port);
            goto out;
        }
        /* The gateway conn gets its OWN extra paths — independent of mq_client's.
         * Use the same --path list (paths[1..]); paths[0] is the primary bind,
         * already in effect on the shared transport. */
        if (npaths > 1) {
            int added = mq_gw_client_add_paths(gwc, &paths[1], npaths - 1);
            if (added < 0) {
                MQ_LOGE("failed to register extra gateway paths");
                goto out;
            }
            MQ_LOGI("registered %d extra gateway multipath bind(s)", added);
        }
        fetch_l =
            mq_fetch_listener_new(mq_runtime_base(rt), gw_ip, gw_port,
                                  mq_gw_client_fetch_cbs(), mq_gw_client_fetch_user(gwc));
        if (!fetch_l) {
            MQ_LOGE("failed to bind gateway fetch listener on %s:%u", gw_ip, gw_port);
            goto out;
        }
    }

    if (install_signal_handlers(base, rt, &sint, &sterm) != 0) {
        MQ_LOGE("failed to install signal handlers");
        goto out;
    }

    {
        char ingress[256];
        int n = 0;
        ingress[0] = '\0';
        if (socks5)
            n += snprintf(ingress + n, sizeof(ingress) - (size_t)n, " socks5=%s:%u",
                          socks5_ip, socks5_port);
        if (http_connect)
            n += snprintf(ingress + n, sizeof(ingress) - (size_t)n, " http-connect=%s:%u",
                          http_ip, http_port);
        if (gateway)
            n += snprintf(ingress + n, sizeof(ingress) - (size_t)n, " gateway=%s:%u",
                          gw_ip, gw_port);
        MQ_LOGI("mqproxy client: server=%s:%u%s (bind %s, cc=%s)", server_ip, server_port,
                ingress, primary_ip, mq_cc_name(cc));
    }
    mq_runtime_run(rt);
    rc = 0;

    /* The loop has broken (SIGINT/SIGTERM) but the conn is still alive (the
     * engine has not been freed yet). Dump per-path byte counters at INFO so
     * external benchmarks (1-B / e2e_multipath.sh) can confirm both paths
     * carried traffic. Safe on a closed/NULL conn (mq_conn_dump_stats guards). */
    {
        mq_conn_t *dump_conn = mq_client_conn(client);
        if (dump_conn) {
            mq_conn_dump_stats(dump_conn);
        }
        /* The gateway tunnel is an INDEPENDENT conn (mq_gw_client's own mq_h3
         * conn), so dump its per-path counters too — e2e_gateway's 2-path smoke
         * greps these to confirm both MPQUIC paths carried gateway traffic. */
        if (gwc) {
            mq_gw_client_dump_stats(gwc);
        }
    }

out:
    /* Teardown order — two distinct callback graphs co-exist here (the TCP-proxy
     * core and the HTTP-gateway ingress), and their ordering contracts pull in
     * OPPOSITE directions across mq_transport_free. Both are honored below.
     *
     * (A) TCP-proxy core (mq_client + SOCKS5/HTTP listeners) — verified against
     *     the in-flight callback graph (an earlier "free client first" ordering
     *     tripped a heap-use-after-free under ASan):
     *       - The client registers client_on_state() on its mq_conn. That cb is
     *         invoked DURING mq_transport_free (conn destroy -> close-notify),
     *         and on MQ_CONN_CLOSED it (a) touches the mq_client and (b) FAILS
     *         every in-flight tcp_open, firing each open-result cb, which writes
     *         the SOCKS5/HTTP reject reply onto the listener's per-conn state.
     *       - So BOTH the client AND its listeners must outlive mq_transport_free
     *         (transport freed FIRST so its callbacks land on live objects), then
     *         runtime, then client, then listeners.
     *       - The transport's send_udp cb (the runtime, as cbs.user) may also
     *         fire during engine destroy (final CONNECTION_CLOSE), so the runtime
     *         must outlive mq_transport_free too.
     *       - UDP ASSOCIATE (mq_udp_assoc, owned by the SOCKS5 listener's active
     *         list) rides the SAME graph-A ordering. Three teardown paths:
     *           1. TCP control-fd EOF → the assoc tears itself down (close_fn on
     *              every live relay session) and self-removes from the list.
     *           2. mq_transport_free (runs FIRST) → conn destroy → every live UDP
     *              relay session's on_err lands on the still-live assoc, which
     *              marks the DST entry dead (and, per the boundary contract, will
     *              NOT call close_fn on a handle after on_err).
     *           3. mq_listener_free (LAST) → reaps any surviving assoc shells
     *              (UDP fd / TCP fd / events); their sessions are already dead
     *              from path 2, so close_fn is a no-op. Order is unchanged.
     *
     * (B) HTTP-gateway ingress (mq_gw_client + mq_h3 + fetch listener) — the
     *     SANCTIONED order is the REVERSE: mq_gw_client_free must run while the
     *     H3 engine is STILL LIVE (it touches r->req for each in-flight request)
     *     AND while the fetch listener is STILL LIVE (it mq_fetch_conn_abort()s
     *     each live local handle). gw_client_free also DETACHES the gateway
     *     conn-state cb, so the gateway conn's later close (fired inside
     *     mq_h3_free / engine teardown) is a no-op back into the freed gw_client.
     *     Therefore: gw_client BEFORE fetch listener BEFORE mq_h3_free BEFORE
     *     mq_transport_free. (mq_h3_free before mq_transport_free is also the
     *     standalone mq_h3.h contract; the gateway and tcp ALPN conn graphs are
     *     independent, so freeing the H3 ctx does not disturb the tcp conns that
     *     mq_transport_free later tears down for graph A.)
     *
     * Combined order:
     *   signal events
     *   -> gw_client_free        (engine+h3+fetch listener live; detaches gw
     *                             conn-state, aborts live local handles)
     *   -> fetch listener free   (gw handles already aborted/detached: safe)
     *   -> mq_h3_free            (engine live; gw conn-close cb detached -> no-op)
     *   -> mq_transport_free     (fires graph-A conn-close + in-flight-open cbs
     *                             into the live runtime/client/socks5/http)
     *   -> runtime free          (closes sockets/timer; does not free base)
     *   -> mq_client_free
     *   -> socks5 / http listener free
     *   -> base free (CLI owns base). */
    if (sint) event_free(sint);
    if (sterm) event_free(sterm);
    if (gwc) mq_gw_client_free(gwc);
    if (fetch_l) mq_fetch_listener_free(fetch_l);
    if (h3) mq_h3_free(h3);
    if (transport) mq_transport_free(transport);
    if (rt) mq_runtime_free(rt);
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
