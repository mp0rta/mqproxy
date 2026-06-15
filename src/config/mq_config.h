// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_config.h — WireGuard-style INI config for mqproxy (server + client).
// Templated on mqvpn/src/config.c conventions; NOT linked to mqvpn.
#ifndef MQ_CONFIG_H
#define MQ_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define MQ_CONFIG_MAX_PATHS 8 /* must equal MQ_MAX_EXTRA_PATHS (cli/main.c) */

typedef struct mq_file_config_t {
    /* shared */
    char token[256];         /* [Auth] Key */
    char cc[16];             /* [Multipath] CC */
    char scheduler[16];      /* [Multipath] Scheduler */
    char qlog[256];          /* [Log] QLog */
    long metrics_interval_s; /* [Metrics] Interval (seconds; 0 = off) */

    /* server */
    char listen[280];        /* [Interface] Listen */
    long max_conns;          /* [Interface] MaxConns */
    char cert[256];          /* [TLS] Cert */
    char key[256];           /* [TLS] Key */
    int gateway_enabled;     /* [Gateway] Enabled */
    char origin_ca[256];     /* [Gateway] OriginCA */
    size_t cache_max_bytes;  /* [Gateway] CacheMaxBytes */
    int udp_enabled;         /* [UDP] Enabled */
    long udp_idle_timeout_s; /* [UDP] IdleTimeout */
    int request_metrics;     /* [Metrics] PerRequest */

    /* client */
    char server_addr[280];               /* [Server] Address */
    char client_id[64];                  /* [Server] ClientId */
    char socks5[280];                    /* [Ingress] Socks5 */
    char http_connect[280];              /* [Ingress] HttpConnect */
    char gw_listen[280];                 /* [Ingress] Gateway */
    char paths[MQ_CONFIG_MAX_PATHS][64]; /* [Multipath] Path (repeatable) */
    int n_paths;
    long keepalive_idle_s;        /* [Interface] KeepaliveIdle */
    int reconnect;                /* [Interface] Reconnect */
    long reconnect_max_backoff_s; /* [Interface] ReconnectMaxBackoff */
} mq_file_config_t;

/* Fill cfg with the same defaults as the CLI locals. */
void mq_config_defaults(mq_file_config_t *cfg);

/* Overlay INI file at path onto cfg. is_server selects which mode's keys are
 * accepted; other-mode keys warn-and-skip. Returns 0 on success, -1 if the
 * file cannot be opened/read (caller should treat as fatal). Bad values inside
 * a readable file warn and are skipped (not fatal). */
int mq_config_load(mq_file_config_t *cfg, const char *path, int is_server);

/* Spec §5.4 secret hygiene: returns 1 if path is readable by group or other
 * (st_mode & 0077), else 0 (incl. on stat failure — never warn about something
 * we cannot check). Pure + testable; caller emits the chmod-0600 warning. */
int mq_config_perms_insecure(const char *path);

#endif /* MQ_CONFIG_H */
