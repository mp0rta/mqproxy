// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors

/* mq_tproxy_setup.c — optional firewall-rule installer/uninstaller.
 *
 * Modelled on mqvpn/src/platform/linux/routing.c's run_ip_cmd pattern:
 * fork + execvp + waitpid, no shell involvement.
 *
 * REDIRECT mode (nft only):
 *   nft add table ip mqproxy
 *   nft add chain ip mqproxy out '{ type nat hook output priority -100 ; }'
 *   nft add rule  ip mqproxy out meta skuid <uid> return
 *   nft add rule  ip mqproxy out meta l4proto tcp tcp dport <dport> redirect to :<port>
 *
 *   Cleanup: nft delete table ip mqproxy
 *
 * TPROXY mode (ip rule + ip route + nft):
 *   ip rule add fwmark <mark> lookup <table>
 *   ip route add local 0.0.0.0/0 dev lo table <table>
 *   nft add table ip mqproxy
 *   nft add chain ip mqproxy div '{ type filter hook prerouting priority -150 ; }'
 *   nft add rule  ip mqproxy div meta l4proto tcp meta skuid <uid> return
 *   nft add rule  ip mqproxy div meta l4proto tcp tcp dport <dport>
 *                                tproxy to :<port> meta mark set <mark> accept
 *
 *   Cleanup:
 *     nft delete table ip mqproxy
 *     ip rule del fwmark <mark> lookup <table>
 *     ip route del local 0.0.0.0/0 dev lo table <table>
 */

#include "ingress/mq_tproxy_setup.h"
#include "util/mq_log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct mq_tproxy_setup {
    mq_capture_mode_t mode;
    char bind_ip[64]; /* informational */
    uint16_t listener_port;
    uint16_t dport;
    uid_t skip_uid;
    int fwmark;
    int table;
};

/* ── command execution ──────────────────────────────────────────────────────
 *
 * run_cmd: fork + execvp(prog, argv) + waitpid.
 * Returns 0 on success (exit status 0), -1 on fork failure, exec failure,
 * wait interruption, or non-zero exit.  On any failure the error is logged
 * before returning.
 *
 * The argv array must be NULL-terminated.  prog is both the executable name
 * (resolved via PATH) and argv[0].  This matches the mqvpn routing.c style.
 */
static int
run_cmd(const char *prog, const char *const argv[])
{
    /* Log the full command at INFO level so the operator can audit. */
    {
        char buf[512];
        int off = 0;
        for (int i = 0; argv[i] && off < (int)sizeof(buf) - 2; i++) {
            if (i > 0) buf[off++] = ' ';
            int n = snprintf(buf + off, sizeof(buf) - (size_t)off, "%s", argv[i]);
            if (n > 0) off += n;
        }
        buf[off] = '\0';
        MQ_LOGI("mq_tproxy_setup: run: %s", buf);
    }

    pid_t pid = fork();
    if (pid < 0) {
        MQ_LOGE("mq_tproxy_setup: fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execvp(prog, (char *const *)argv);
        /* execvp only returns on failure */
        _exit(127);
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            MQ_LOGE("mq_tproxy_setup: waitpid: %s", strerror(errno));
            return -1;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (WIFEXITED(status))
            MQ_LOGE("mq_tproxy_setup: '%s' exited %d", prog, WEXITSTATUS(status));
        else
            MQ_LOGE("mq_tproxy_setup: '%s' killed by signal %d", prog, WTERMSIG(status));
        return -1;
    }
    return 0;
}

/* ── REDIRECT install ───────────────────────────────────────────────────── */

/* Best-effort, partial-state-tolerated: on a mid-sequence command failure we set
 * rc=-1 but CONTINUE issuing the remaining commands (and the caller logs the
 * failure). uninstall is idempotent and removes whatever did get installed, so a
 * partial install is cleaned up at teardown rather than left to accumulate. */
static int
install_redirect(const mq_tproxy_setup_t *s)
{
    char uid_str[32], port_str[32], dport_str[32], redir_str[32];
    snprintf(uid_str, sizeof(uid_str), "%lu", (unsigned long)s->skip_uid);
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)s->listener_port);
    snprintf(dport_str, sizeof(dport_str), "%u", (unsigned)s->dport);
    snprintf(redir_str, sizeof(redir_str), ":%u", (unsigned)s->listener_port);

    int rc = 0;

    /* nft add table ip mqproxy */
    {
        const char *const a[] = {"nft", "add", "table", "ip", "mqproxy", NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    /* nft add chain ip mqproxy out '{ type nat hook output priority -100 ; }' */
    {
        const char *const a[] = {"nft",
                                 "add",
                                 "chain",
                                 "ip",
                                 "mqproxy",
                                 "out",
                                 "{ type nat hook output priority -100 ; }",
                                 NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    /* nft add rule ip mqproxy out meta skuid <uid> return */
    {
        const char *const a[] = {"nft",  "add",   "rule",  "ip",     "mqproxy", "out",
                                 "meta", "skuid", uid_str, "return", NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    /* nft add rule ip mqproxy out meta l4proto tcp tcp dport <dport> redirect to :<port>
     */
    {
        const char *const a[] = {
            "nft", "add", "rule",  "ip",      "mqproxy",  "out", "meta",    "l4proto",
            "tcp", "tcp", "dport", dport_str, "redirect", "to",  redir_str, NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    if (rc != 0) {
        MQ_LOGE("mq_tproxy_setup: REDIRECT install failed for dport=%s -> :%s", dport_str,
                port_str);
    } else {
        MQ_LOGI("mq_tproxy_setup: REDIRECT rules installed "
                "(uid=%s exempted, dport=%s -> :%s)",
                uid_str, dport_str, port_str);
    }
    return rc;
}

/* ── TPROXY install ─────────────────────────────────────────────────────── */

static int
install_tproxy(const mq_tproxy_setup_t *s)
{
    char uid_str[32], port_str[32], dport_str[32], redir_str[32];
    char mark_str[32], table_str[32];
    snprintf(uid_str, sizeof(uid_str), "%lu", (unsigned long)s->skip_uid);
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)s->listener_port);
    snprintf(dport_str, sizeof(dport_str), "%u", (unsigned)s->dport);
    snprintf(redir_str, sizeof(redir_str), ":%u", (unsigned)s->listener_port);
    snprintf(mark_str, sizeof(mark_str), "%d", s->fwmark);
    snprintf(table_str, sizeof(table_str), "%d", s->table);

    int rc = 0;

    /* ip rule add fwmark <mark> lookup <table> */
    {
        const char *const a[] = {"ip",     "rule",   "add",     "fwmark",
                                 mark_str, "lookup", table_str, NULL};
        if (run_cmd("ip", a) != 0) rc = -1;
    }

    /* ip route add local 0.0.0.0/0 dev lo table <table> */
    {
        const char *const a[] = {"ip",  "route", "add",   "local",   "0.0.0.0/0",
                                 "dev", "lo",    "table", table_str, NULL};
        if (run_cmd("ip", a) != 0) rc = -1;
    }

    /* nft add table ip mqproxy */
    {
        const char *const a[] = {"nft", "add", "table", "ip", "mqproxy", NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    /* nft add chain ip mqproxy div '{ type filter hook prerouting priority -150 ; }' */
    {
        const char *const a[] = {"nft",
                                 "add",
                                 "chain",
                                 "ip",
                                 "mqproxy",
                                 "div",
                                 "{ type filter hook prerouting priority -150 ; }",
                                 NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    /* nft add rule ip mqproxy div meta l4proto tcp meta skuid <uid> return */
    {
        const char *const a[] = {"nft",   "add",   "rule",    "ip",  "mqproxy",
                                 "div",   "meta",  "l4proto", "tcp", "meta",
                                 "skuid", uid_str, "return",  NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    /* nft add rule ip mqproxy div meta l4proto tcp tcp dport <dport>
     *    tproxy to :<port> meta mark set <mark> accept */
    {
        const char *const a[] = {
            "nft",     "add",  "rule", "ip",    "mqproxy", "div",    "meta",
            "l4proto", "tcp",  "tcp",  "dport", dport_str, "tproxy", "to",
            redir_str, "meta", "mark", "set",   mark_str,  "accept", NULL};
        if (run_cmd("nft", a) != 0) rc = -1;
    }

    if (rc != 0) {
        MQ_LOGE("mq_tproxy_setup: TPROXY install failed "
                "(mark=%s table=%s dport=%s -> :%s)",
                mark_str, table_str, dport_str, port_str);
    } else {
        MQ_LOGI("mq_tproxy_setup: TPROXY rules installed "
                "(uid=%s exempted, mark=%s, table=%s, dport=%s -> :%s)",
                uid_str, mark_str, table_str, dport_str, port_str);
    }
    return rc;
}

/* ── REDIRECT uninstall ─────────────────────────────────────────────────── */

static void
uninstall_redirect(const mq_tproxy_setup_t *s)
{
    (void)s; /* table name is fixed ("mqproxy"); no per-instance state needed */

    /* nft delete table ip mqproxy */
    const char *const a[] = {"nft", "delete", "table", "ip", "mqproxy", NULL};
    if (run_cmd("nft", a) != 0)
        MQ_LOGW("mq_tproxy_setup: REDIRECT cleanup: nft delete table failed (tolerated)");
    else
        MQ_LOGI("mq_tproxy_setup: REDIRECT rules removed");
}

/* ── TPROXY uninstall ───────────────────────────────────────────────────── */

static void
uninstall_tproxy(const mq_tproxy_setup_t *s)
{
    char mark_str[32], table_str[32];
    snprintf(mark_str, sizeof(mark_str), "%d", s->fwmark);
    snprintf(table_str, sizeof(table_str), "%d", s->table);

    /* nft delete table ip mqproxy */
    {
        const char *const a[] = {"nft", "delete", "table", "ip", "mqproxy", NULL};
        if (run_cmd("nft", a) != 0)
            MQ_LOGW(
                "mq_tproxy_setup: TPROXY cleanup: nft delete table failed (tolerated)");
    }

    /* ip rule del fwmark <mark> lookup <table> */
    {
        const char *const a[] = {"ip",     "rule",   "del",     "fwmark",
                                 mark_str, "lookup", table_str, NULL};
        if (run_cmd("ip", a) != 0)
            MQ_LOGW("mq_tproxy_setup: TPROXY cleanup: ip rule del failed (tolerated)");
    }

    /* ip route del local 0.0.0.0/0 dev lo table <table> */
    {
        const char *const a[] = {"ip",  "route", "del",   "local",   "0.0.0.0/0",
                                 "dev", "lo",    "table", table_str, NULL};
        if (run_cmd("ip", a) != 0)
            MQ_LOGW("mq_tproxy_setup: TPROXY cleanup: ip route del failed (tolerated)");
    }

    MQ_LOGI("mq_tproxy_setup: TPROXY rules cleanup done (mark=%s table=%s)", mark_str,
            table_str);
}

/* ── public API ─────────────────────────────────────────────────────────── */

mq_tproxy_setup_t *
mq_tproxy_setup_new(mq_capture_mode_t mode, const char *bind_ip, uint16_t listener_port,
                    uint16_t dport, uid_t skip_uid, int fwmark, int table)
{
    mq_tproxy_setup_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->mode = mode;
    s->listener_port = listener_port;
    s->dport = dport;
    s->skip_uid = (skip_uid == (uid_t)-1) ? geteuid() : skip_uid;
    s->fwmark = fwmark;
    s->table = table;
    if (bind_ip) snprintf(s->bind_ip, sizeof(s->bind_ip), "%s", bind_ip);

    return s;
}

int
mq_tproxy_setup_install(mq_tproxy_setup_t *s)
{
    if (!s) return -1;
    if (s->mode == MQ_CAPTURE_TPROXY) return install_tproxy(s);
    return install_redirect(s);
}

void
mq_tproxy_setup_uninstall(mq_tproxy_setup_t *s)
{
    if (!s) return;
    if (s->mode == MQ_CAPTURE_TPROXY)
        uninstall_tproxy(s);
    else
        uninstall_redirect(s);
}

void
mq_tproxy_setup_free(mq_tproxy_setup_t *s)
{
    free(s);
}
