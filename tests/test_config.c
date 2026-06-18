// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta
#include "config/mq_config.h"
#include "mqtest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* write text to a fresh temp file via mkstemp; fills path_out (template form) */
static void
write_tmp(char *path_out, size_t n, const char *text)
{
    snprintf(path_out, n, "/tmp/mqcfg_test_XXXXXX");
    int fd = mkstemp(path_out);
    MQ_CHECK(fd >= 0);
    FILE *f = fdopen(fd, "w");
    MQ_CHECK(f != NULL);
    fputs(text, f);
    fclose(f);
}

static void
test_defaults(void)
{
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(c.max_conns, 16);              /* numeric default */
    MQ_CHECK(strcmp(c.client_id, "mqproxy") == 0); /* string default */
    MQ_CHECK_EQ_INT(c.n_paths, 0);                 /* repeatable empty */
}

static void
test_server_roundtrip(void)
{
    char p[64];
    write_tmp(p, sizeof(p),
              "[Interface]\n"
              "Listen = 0.0.0.0:4433\n"
              "MaxConns = 64\n"
              "[TLS]\n"
              "Cert = /e/c.pem\n"
              "Key  = /e/c.key\n"
              "[Auth]\n"
              "Key = s3cr3t\n"
              "[Multipath]\n"
              "CC = bbr\n"
              "Scheduler = minrtt\n"
              "[Log]\n"
              "QLog = /tmp/q\n");
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(mq_config_load(&c, p, 1 /*server*/), 0);
    MQ_CHECK(strcmp(c.listen, "0.0.0.0:4433") == 0);
    MQ_CHECK(strcmp(c.qlog, "/tmp/q") == 0);
    MQ_CHECK_EQ_INT(c.max_conns, 64);
    MQ_CHECK(strcmp(c.cert, "/e/c.pem") == 0);
    MQ_CHECK(strcmp(c.key, "/e/c.key") == 0);
    MQ_CHECK(strcmp(c.token, "s3cr3t") == 0);
    MQ_CHECK(strcmp(c.cc, "bbr") == 0);
    MQ_CHECK(strcmp(c.scheduler, "minrtt") == 0);
    remove(p);
}

static void
test_client_roundtrip(void)
{
    char p[64];
    /* bracketed IPv6 Address exercises the scanner's bracket+colon handling
     * (spec §7 IPv6 round-trip; parse_ip_port validation happens later in CLI) */
    write_tmp(p, sizeof(p),
              "[Server]\nAddress = [2001:db8::1]:443\nClientId = edge\n"
              "[Auth]\nKey = tok\n"
              "[Ingress]\nSocks5 = 127.0.0.1:1080\n"
              "TProxy = 127.0.0.1:8443\nMode = tproxy\nFwmark = 7\nTable = 200\n"
              "Dport = 8080\nSetupRedirect = true\nSkipUid = 1000\n"
              "[Interface]\nReconnect = false\nKeepaliveIdle = 15\n"
              "[Multipath]\nPath = 10.0.0.1\nPath = 10.0.0.2\n");
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(mq_config_load(&c, p, 0 /*client*/), 0);
    MQ_CHECK(strcmp(c.server_addr, "[2001:db8::1]:443") == 0);
    MQ_CHECK(strcmp(c.client_id, "edge") == 0);
    MQ_CHECK(strcmp(c.socks5, "127.0.0.1:1080") == 0);
    /* [Ingress] transparent-capture keys (Phase 7 Slice 1) round-trip. */
    MQ_CHECK(strcmp(c.tproxy, "127.0.0.1:8443") == 0);
    MQ_CHECK(strcmp(c.tproxy_mode, "tproxy") == 0);
    MQ_CHECK_EQ_INT(c.tproxy_fwmark, 7);
    MQ_CHECK_EQ_INT(c.tproxy_table, 200);
    MQ_CHECK_EQ_INT(c.tproxy_dport, 8080);
    MQ_CHECK_EQ_INT(c.setup_redirect, 1);
    MQ_CHECK_EQ_INT(c.tproxy_skip_uid, 1000);
    MQ_CHECK_EQ_INT(c.reconnect, 0);
    MQ_CHECK_EQ_INT(c.keepalive_idle_s, 15);
    MQ_CHECK_EQ_INT(c.n_paths, 2);
    MQ_CHECK(strcmp(c.paths[0], "10.0.0.1") == 0);
    MQ_CHECK(strcmp(c.paths[1], "10.0.0.2") == 0);
    remove(p);
}

static void
test_bool_variants(void)
{
    char p[64];
    write_tmp(p, sizeof(p),
              "[Gateway]\nEnabled = yes\nMasquerade = true\n[UDP]\nEnabled = 0\n");
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(c.masquerade, 0); /* default off (memset) */
    mq_config_load(&c, p, 1);
    MQ_CHECK_EQ_INT(c.gateway_enabled, 1); /* yes */
    MQ_CHECK_EQ_INT(c.masquerade, 1);      /* true */
    MQ_CHECK_EQ_INT(c.udp_enabled, 0);     /* 0 = off */
    remove(p);
}

static void
test_path_cap(void)
{
    char p[64];
    char big[512] = "[Multipath]\n";
    for (int i = 0; i < 10; i++)
        strcat(big, "Path = x\n"); /* 10 > cap 8 */
    write_tmp(p, sizeof(p), big);
    mq_file_config_t c;
    mq_config_defaults(&c);
    mq_config_load(&c, p, 0);
    MQ_CHECK_EQ_INT(c.n_paths, MQ_CONFIG_MAX_PATHS); /* capped at 8 */
    remove(p);
}

static void
test_lenient_and_comments(void)
{
    char p[64];
    write_tmp(
        p, sizeof(p),
        "# comment\n; also comment\n"
        "[Interface]\nMaxConns = notanumber\n" /* bad value -> keep default 16 */
        "[Bogus]\nFoo = bar\n"                 /* unknown section -> warn */
        "[Auth]\nUnknownKey = x\nKey =\n" /* unknown key -> warn; empty Key ignored */
        "[TLS]\nCert = /c.pem\n");        /* a real value still applies */
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(mq_config_load(&c, p, 1), 0); /* readable -> 0 despite warns */
    MQ_CHECK_EQ_INT(c.max_conns, 16);             /* bad value kept default */
    MQ_CHECK(c.token[0] == '\0');                 /* empty value ignored, not "" set */
    MQ_CHECK(strcmp(c.cert, "/c.pem") == 0);
    remove(p);
}

static void
test_partial_file_keeps_defaults(void)
{
    /* defaults < file: keys absent from the file retain mq_config_defaults values.
     * Falsifiable, pure — covers the precedence floor without exec'ing the binary. */
    char p[64];
    write_tmp(p, sizeof(p), "[Interface]\nListen = :4433\n"); /* only Listen set */
    mq_file_config_t c;
    mq_config_defaults(&c);
    mq_config_load(&c, p, 1);
    MQ_CHECK(strcmp(c.listen, ":4433") == 0); /* file value applied */
    MQ_CHECK_EQ_INT(c.max_conns, 16);         /* untouched -> default */
    MQ_CHECK_EQ_INT(c.gateway_enabled, 1);    /* untouched -> default */
    remove(p);
}

static void
test_perms_warning(void)
{
    char p[64];
    write_tmp(p, sizeof(p), "[Auth]\nKey = tok\n");
    chmod(p, 0644);
    MQ_CHECK_EQ_INT(mq_config_perms_insecure(p), 1); /* group/world readable */
    chmod(p, 0600);
    MQ_CHECK_EQ_INT(mq_config_perms_insecure(p), 0);               /* owner-only */
    MQ_CHECK_EQ_INT(mq_config_perms_insecure("/no/such/file"), 0); /* can't stat */
    remove(p);
}

static void
test_mitm_section(void)
{
    /* [Mitm] is client-only; Enabled bool + CACert/CAKey paths + repeatable
     * IgnoreHosts (mirrors [Multipath] Path accumulation). */
    char p[64];
    write_tmp(p, sizeof(p),
              "[Mitm]\n"
              "Enabled = true\n"
              "CACert = /c\n"
              "CAKey = /k\n"
              "IgnoreHosts = .apple.com\n"
              "IgnoreHosts = signal.org\n");
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(c.mitm_enabled, 0); /* default off (memset) */
    MQ_CHECK_EQ_INT(mq_config_load(&c, p, 0 /*client*/), 0);
    MQ_CHECK_EQ_INT(c.mitm_enabled, 1);
    MQ_CHECK(strcmp(c.ca_cert, "/c") == 0);
    MQ_CHECK(strcmp(c.ca_key, "/k") == 0);
    MQ_CHECK_EQ_INT(c.n_ignore_hosts, 2);
    MQ_CHECK(strcmp(c.ignore_hosts[0], ".apple.com") == 0);
    MQ_CHECK(strcmp(c.ignore_hosts[1], "signal.org") == 0);
    remove(p);
}

static void
test_mitm_server_mode_ignored(void)
{
    /* server-mode load warns + ignores all [Mitm] keys (client-only). */
    char p[64];
    write_tmp(p, sizeof(p),
              "[Mitm]\n"
              "Enabled = true\n"
              "CACert = /c\n"
              "CAKey = /k\n"
              "IgnoreHosts = .apple.com\n");
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(mq_config_load(&c, p, 1 /*server*/), 0);
    MQ_CHECK_EQ_INT(c.mitm_enabled, 0); /* ignored */
    MQ_CHECK(c.ca_cert[0] == '\0');
    MQ_CHECK(c.ca_key[0] == '\0');
    MQ_CHECK_EQ_INT(c.n_ignore_hosts, 0);
    remove(p);
}

static void
test_mitm_enabled_missing_cacert(void)
{
    /* Enabled=true with no CACert: config layer keeps ca_cert empty (no error
     * here — the --mitm-requires-CA check is enforced in CLI, Task 15). */
    char p[64];
    write_tmp(p, sizeof(p), "[Mitm]\nEnabled = true\n");
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(mq_config_load(&c, p, 0 /*client*/), 0);
    MQ_CHECK_EQ_INT(c.mitm_enabled, 1);
    MQ_CHECK(c.ca_cert[0] == '\0'); /* surfaced as empty; CLI enforces */
    MQ_CHECK(c.ca_key[0] == '\0');
    remove(p);
}

static void
test_missing_file_fatal(void)
{
    mq_file_config_t c;
    mq_config_defaults(&c);
    MQ_CHECK_EQ_INT(mq_config_load(&c, "/no/such/file.conf", 1), -1);
}

MQ_TEST_MAIN({
    test_defaults();
    test_server_roundtrip();
    test_client_roundtrip();
    test_bool_variants();
    test_path_cap();
    test_lenient_and_comments();
    test_partial_file_keeps_defaults();
    test_mitm_section();
    test_mitm_server_mode_ignored();
    test_mitm_enabled_missing_cacert();
    test_perms_warning();
    test_missing_file_fatal();
})
