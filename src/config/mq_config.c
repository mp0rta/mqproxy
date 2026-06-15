// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//
// mq_config.c — WireGuard-style INI config parser for mqproxy.
// Templated on mqvpn/src/config.c (INI scanner core); JSON + multi-user
// machinery intentionally dropped. NOT linked to mqvpn (self-contained).
#include "config/mq_config.h"
#include "util/mq_log.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h> /* SIZE_MAX, UINT32_MAX */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h> /* stat() for perms check */

#ifdef _MSC_VER
#  define strcasecmp _stricmp
#endif

void
mq_config_defaults(mq_file_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_conns = 16;
    cfg->gateway_enabled = 1;
    cfg->udp_enabled = 1;
    cfg->udp_idle_timeout_s = 60;
    cfg->reconnect = 1;
    cfg->keepalive_idle_s = 30;
    cfg->reconnect_max_backoff_s = 30;
    snprintf(cfg->client_id, sizeof(cfg->client_id), "%s", "mqproxy");
    /* tproxy defaults: mode=redirect, fwmark=1, table=100, skip_uid=-1 (geteuid()) */
    snprintf(cfg->tproxy_mode, sizeof(cfg->tproxy_mode), "%s", "redirect");
    cfg->tproxy_fwmark = 1;
    cfg->tproxy_table = 100;
    cfg->tproxy_skip_uid = -1;
}

/* ---- helpers (templated from mqvpn/src/config.c) ---- */

static char *
trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        *end-- = '\0';
    return s;
}

static int
parse_bool(const char *v)
{
    return strcmp(v, "true") == 0 || strcmp(v, "yes") == 0 || strcmp(v, "1") == 0;
}

/* strict long; returns 0 ok / -1 bad */
static int
parse_long_strict(const char *v, long *out)
{
    if (!v || *v == '\0') return -1;
    errno = 0;
    char *end = NULL;
    long x = strtol(v, &end, 10);
    if (end == v || *end != '\0' || errno == ERANGE) return -1;
    *out = x;
    return 0;
}

enum {
    SEC_NONE = 0,
    SEC_INTERFACE,
    SEC_SERVER,
    SEC_TLS,
    SEC_AUTH,
    SEC_MULTIPATH,
    SEC_GATEWAY,
    SEC_UDP,
    SEC_INGRESS,
    SEC_METRICS,
    SEC_LOG
};

static int
parse_section(const char *n)
{
    if (strcasecmp(n, "Interface") == 0) return SEC_INTERFACE;
    if (strcasecmp(n, "Server") == 0) return SEC_SERVER;
    if (strcasecmp(n, "TLS") == 0) return SEC_TLS;
    if (strcasecmp(n, "Auth") == 0) return SEC_AUTH;
    if (strcasecmp(n, "Multipath") == 0) return SEC_MULTIPATH;
    if (strcasecmp(n, "Gateway") == 0) return SEC_GATEWAY;
    if (strcasecmp(n, "UDP") == 0) return SEC_UDP;
    if (strcasecmp(n, "Ingress") == 0) return SEC_INGRESS;
    if (strcasecmp(n, "Metrics") == 0) return SEC_METRICS;
    if (strcasecmp(n, "Log") == 0) return SEC_LOG;
    return -1;
}

/* warn + skip for a key that belongs to the other mode */
#define WRONG_MODE(sec)                                                            \
    do {                                                                           \
        MQ_LOGW("%s:%d: key '%s' in [%s] not valid for this mode; ignoring", path, \
                lineno, key, sec);                                                 \
    } while (0)

static void
handle_kv(mq_file_config_t *cfg, int section, const char *key, const char *val,
          int lineno, const char *path, int is_server)
{
/* CSTR copies a string field; LONGV parses bounded ints leniently.
 * Booleans use parse_bool() inline (no macro needed). */
#define CSTR(field) snprintf(cfg->field, sizeof(cfg->field), "%s", val)
#define LONGV(field, lo, hi)                                                            \
    do {                                                                                \
        long _v;                                                                        \
        if (parse_long_strict(val, &_v) < 0 || _v < (lo) || _v > (hi))                  \
            MQ_LOGW("%s:%d: invalid %s '%s'; keeping default", path, lineno, key, val); \
        else                                                                            \
            cfg->field = _v;                                                            \
    } while (0)

    switch (section) {
    case SEC_INTERFACE:
        if (strcasecmp(key, "Listen") == 0) {
            if (is_server)
                CSTR(listen);
            else
                WRONG_MODE("Interface");
        } else if (strcasecmp(key, "MaxConns") == 0) {
            /* Mirror the CLI's unsigned-domain guard (cli/main.c --max-conns):
             * compare in unsigned long long to stay correct where long is 32-bit. */
            if (!is_server)
                WRONG_MODE("Interface");
            else {
                long _v;
                if (parse_long_strict(val, &_v) < 0 || _v < 0 ||
                    (unsigned long long)_v > (unsigned long long)UINT32_MAX)
                    MQ_LOGW("%s:%d: invalid MaxConns '%s'; keeping default", path, lineno,
                            val);
                else
                    cfg->max_conns = _v;
            }
        } else if (strcasecmp(key, "KeepaliveIdle") == 0) {
            if (!is_server)
                LONGV(keepalive_idle_s, 0, LONG_MAX);
            else
                WRONG_MODE("Interface");
        } else if (strcasecmp(key, "Reconnect") == 0) {
            if (!is_server)
                cfg->reconnect = parse_bool(val);
            else
                WRONG_MODE("Interface");
        } else if (strcasecmp(key, "ReconnectMaxBackoff") == 0) {
            if (!is_server)
                LONGV(reconnect_max_backoff_s, 1, LONG_MAX);
            else
                WRONG_MODE("Interface");
        } else
            MQ_LOGW("%s:%d: unknown key '%s' in [Interface]", path, lineno, key);
        break;
    case SEC_SERVER: /* client-side: the server the client dials */
        if (is_server)
            WRONG_MODE("Server");
        else if (strcasecmp(key, "Address") == 0)
            CSTR(server_addr);
        else if (strcasecmp(key, "ClientId") == 0)
            CSTR(client_id);
        else
            MQ_LOGW("%s:%d: unknown key '%s' in [Server]", path, lineno, key);
        break;
    case SEC_TLS:
        if (!is_server)
            WRONG_MODE("TLS");
        else if (strcasecmp(key, "Cert") == 0)
            CSTR(cert);
        else if (strcasecmp(key, "Key") == 0)
            CSTR(key); /* cfg->key (TLS field) */
        else
            MQ_LOGW("%s:%d: unknown key '%s' in [TLS]", path, lineno, key);
        break;
    case SEC_AUTH:
        if (strcasecmp(key, "Key") == 0)
            CSTR(token);
        else
            MQ_LOGW("%s:%d: unknown key '%s' in [Auth]", path, lineno, key);
        break;
    case SEC_MULTIPATH:
        if (strcasecmp(key, "CC") == 0)
            CSTR(cc);
        else if (strcasecmp(key, "Scheduler") == 0)
            CSTR(scheduler);
        else if (strcasecmp(key, "Path") == 0) {
            if (is_server) {
                WRONG_MODE("Multipath");
            } else if (cfg->n_paths < MQ_CONFIG_MAX_PATHS) {
                snprintf(cfg->paths[cfg->n_paths], sizeof(cfg->paths[0]), "%s", val);
                cfg->n_paths++;
            } else
                MQ_LOGW("%s:%d: max %d paths; ignoring '%s'", path, lineno,
                        MQ_CONFIG_MAX_PATHS, val);
        } else
            MQ_LOGW("%s:%d: unknown key '%s' in [Multipath]", path, lineno, key);
        break;
    case SEC_GATEWAY:
        if (!is_server)
            WRONG_MODE("Gateway");
        else if (strcasecmp(key, "Enabled") == 0)
            cfg->gateway_enabled = parse_bool(val);
        else if (strcasecmp(key, "Masquerade") == 0)
            cfg->masquerade = parse_bool(val);
        else if (strcasecmp(key, "OriginCA") == 0)
            CSTR(origin_ca);
        else if (strcasecmp(key, "CacheMaxBytes") == 0) {
            /* mirror CLI SIZE_MAX guard (cli/main.c --cache-max-bytes). NOTE:
             * parse_long_strict uses strtol/long; on the 64-bit target this is
             * identical to the CLI's strtoll. On a 32-bit-long platform it would
             * reject byte counts > LONG_MAX the CLI accepts — acceptable (rejects
             * more, never accepts what the CLI refuses; spec §5.2 floor holds). */
            long v;
            if (parse_long_strict(val, &v) < 0 || v < 0 ||
                (unsigned long long)v > (unsigned long long)SIZE_MAX)
                MQ_LOGW("%s:%d: invalid CacheMaxBytes '%s'; keeping default", path,
                        lineno, val);
            else
                cfg->cache_max_bytes = (size_t)v;
        } else
            MQ_LOGW("%s:%d: unknown key '%s' in [Gateway]", path, lineno, key);
        break;
    case SEC_UDP:
        if (!is_server)
            WRONG_MODE("UDP");
        else if (strcasecmp(key, "Enabled") == 0)
            cfg->udp_enabled = parse_bool(val);
        else if (strcasecmp(key, "IdleTimeout") == 0)
            LONGV(udp_idle_timeout_s, 1, LONG_MAX);
        else
            MQ_LOGW("%s:%d: unknown key '%s' in [UDP]", path, lineno, key);
        break;
    case SEC_INGRESS:
        if (is_server)
            WRONG_MODE("Ingress");
        else if (strcasecmp(key, "Socks5") == 0)
            CSTR(socks5);
        else if (strcasecmp(key, "HttpConnect") == 0)
            CSTR(http_connect);
        else if (strcasecmp(key, "Gateway") == 0)
            CSTR(gw_listen);
        else if (strcasecmp(key, "TProxy") == 0)
            CSTR(tproxy);
        else if (strcasecmp(key, "Mode") == 0)
            CSTR(tproxy_mode);
        else if (strcasecmp(key, "Fwmark") == 0)
            LONGV(tproxy_fwmark, 1, LONG_MAX);
        else if (strcasecmp(key, "Table") == 0)
            LONGV(tproxy_table, 1, 65535);
        else if (strcasecmp(key, "SetupRedirect") == 0)
            cfg->setup_redirect = parse_bool(val);
        else if (strcasecmp(key, "SkipUid") == 0)
            LONGV(tproxy_skip_uid, -1, LONG_MAX);
        else
            MQ_LOGW("%s:%d: unknown key '%s' in [Ingress]", path, lineno, key);
        break;
    case SEC_METRICS:
        if (strcasecmp(key, "Interval") == 0)
            LONGV(metrics_interval_s, 0, LONG_MAX);
        else if (strcasecmp(key, "PerRequest") == 0) {
            if (is_server)
                cfg->request_metrics = parse_bool(val);
            else
                WRONG_MODE("Metrics");
        } else
            MQ_LOGW("%s:%d: unknown key '%s' in [Metrics]", path, lineno, key);
        break;
    case SEC_LOG:
        if (strcasecmp(key, "QLog") == 0)
            CSTR(qlog);
        else
            MQ_LOGW("%s:%d: unknown key '%s' in [Log]", path, lineno, key);
        break;
    default: MQ_LOGW("%s:%d: key '%s' outside any section", path, lineno, key); break;
    }
#undef CSTR
#undef LONGV
}

int
mq_config_load(mq_file_config_t *cfg, const char *path, int is_server)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        MQ_LOGE("config: cannot open '%s'", path);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';

    int lineno = 0, section = SEC_NONE;
    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
        lineno++;
        char *t = trim(line);
        if (*t == '\0' || *t == '#' || *t == ';') continue;
        if (*t == '[') {
            char *end = strchr(t, ']');
            if (!end) {
                MQ_LOGW("%s:%d: malformed section header", path, lineno);
                continue;
            }
            *end = '\0';
            int sec = parse_section(t + 1);
            if (sec < 0) {
                MQ_LOGW("%s:%d: unknown section '%s'", path, lineno, t + 1);
                section = SEC_NONE;
            } else
                section = sec;
            continue;
        }
        char *eq = strchr(t, '=');
        if (!eq) {
            MQ_LOGW("%s:%d: malformed line (no '=')", path, lineno);
            continue;
        }
        *eq = '\0';
        char *k = trim(t), *v = trim(eq + 1);
        if (*v == '\0') continue; /* empty value: treat as not set */
        handle_kv(cfg, section, k, v, lineno, path, is_server);
    }
    free(buf);
    return 0;
}

int
mq_config_perms_insecure(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0; /* can't check -> don't warn */
    return (st.st_mode & 0077) ? 1 : 0;
}
