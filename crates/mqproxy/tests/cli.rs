//! spec §6.4: the CLI flag table, in process through `cli::parse`; only the last
//! three tests spawn the binary.

use mq_proxy::client::mitm::MitmTuning;
use mq_proxy::config::GatewayConfig;
use mq_runtime::ListenKind;
use mq_transport_api::{CongestionControl, Scheduler};
use mqproxy::cli::{self, Client, Exit, Mode, Resolved, Server};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

const SERVER: &[&str] = &[
    "mqproxy",
    "server",
    "--listen",
    "127.0.0.1:4433",
    "--token",
    "t",
    "--cert",
    "c.pem",
    "--key",
    "k.pem",
];
const CLIENT: &[&str] = &[
    "mqproxy",
    "client",
    "--server",
    "127.0.0.1:4433",
    "--token",
    "t",
    "--socks5",
    "127.0.0.1:1080",
];

fn parse(base: &[&str], extra: &[&str]) -> Result<Resolved, Exit> {
    let argv: Vec<&str> = base.iter().chain(extra).copied().collect();
    cli::parse(&argv)
}

fn server(r: &Resolved) -> &Server {
    match &r.mode {
        Mode::Server(s) => s,
        m => panic!("not a server: {m:?}"),
    }
}

fn client(r: &Resolved) -> &Client {
    match &r.mode {
        Mode::Client(c) => c,
        m => panic!("not a client: {m:?}"),
    }
}

fn exit(r: Result<Resolved, Exit>) -> Exit {
    match r {
        Ok(r) => panic!("expected an exit, got {r:?}"),
        Err(e) => e,
    }
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn server_implemented_flags_resolve() {
    let r = cli::parse(&[
        "mqproxy",
        "server",
        "--listen",
        "[::1]:9443",
        "--token",
        "secret",
        "--cert",
        "/c.pem",
        "--key",
        "/k.pem",
        "--qlog",
        "/tmp/q",
        "--cc",
        "cubic",
        "--scheduler",
        "wlb",
        "--metrics-interval",
        "5",
        "--max-conns",
        "0",
    ])
    .unwrap();
    let s = server(&r);
    assert_eq!(s.listen, addr("[::1]:9443"));
    assert_eq!(s.config.token, "secret");
    assert_eq!(s.cert, PathBuf::from("/c.pem"));
    assert_eq!(s.key, PathBuf::from("/k.pem"));
    assert_eq!(s.max_conns, 0);
    assert_eq!(s.config.metrics_interval, Some(Duration::from_secs(5)));
    assert_eq!(r.qlog, Some(PathBuf::from("/tmp/q")));
    assert_eq!(r.cc, CongestionControl::Cubic);
    assert_eq!(r.scheduler, Scheduler::Wlb);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    // C parse_ip_port also takes an unbracketed IPv6 literal (split at the last ':').
    let r = cli::parse(&[
        "mqproxy", "server", "--listen", "::1:9443", "--token", "t", "--cert", "c", "--key", "k",
    ])
    .unwrap();
    assert_eq!(server(&r).listen, addr("[::1]:9443"));
}

#[test]
fn client_implemented_flags_resolve() {
    let r = cli::parse(&[
        "mqproxy",
        "client",
        "--server",
        "10.0.0.1:443",
        "--token",
        "secret",
        "--socks5",
        "127.0.0.1:1080",
        "--http-connect",
        "127.0.0.1:8080",
        "--tproxy",
        "0.0.0.0:12345",
        "--path",
        "192.168.1.2",
        "--path=10.1.1.2",
        "--client-id",
        "me",
        "--qlog",
        "/q",
        "--cc",
        "bbr2",
        "--scheduler",
        "backup",
        "--keepalive-idle",
        "60",
        "--no-reconnect",
        "--reconnect-max-backoff",
        "7",
        "--metrics-interval",
        "3",
        "--tproxy-mode",
        "tproxy",
        "--tproxy-fwmark",
        "9",
        "--tproxy-table",
        "200",
        "--tproxy-dport",
        "8443",
        "--setup-redirect",
        "--tproxy-uid",
        "1234",
    ])
    .unwrap();
    let c = client(&r);
    assert_eq!(c.config.server, addr("10.0.0.1:443"));
    assert_eq!(c.config.token, "secret");
    assert_eq!(c.socks5, Some(addr("127.0.0.1:1080")));
    assert_eq!(c.http_connect, Some(addr("127.0.0.1:8080")));
    assert_eq!(c.tproxy, Some(addr("0.0.0.0:12345")));
    assert_eq!(
        c.config.paths,
        vec![
            "192.168.1.2".parse::<IpAddr>().unwrap(),
            "10.1.1.2".parse().unwrap()
        ]
    );
    assert_eq!(c.config.client_id, "me");
    assert_eq!(r.qlog, Some(PathBuf::from("/q")));
    assert_eq!(r.cc, CongestionControl::Bbr2);
    assert_eq!(r.scheduler, Scheduler::Backup);
    assert_eq!(c.config.scheduler, Scheduler::Backup);
    assert_eq!(c.config.keepalive_idle, Some(Duration::from_secs(60)));
    assert!(!c.config.reconnect);
    assert_eq!(c.config.reconnect_max_backoff, Duration::from_secs(7));
    assert_eq!(c.config.metrics_interval, Some(Duration::from_secs(3)));
    assert_eq!(c.tproxy_mode, ListenKind::Tproxy);
    assert_eq!(c.tproxy_fwmark, 9);
    assert_eq!(c.tproxy_table, 200);
    assert_eq!(c.tproxy_dport, 8443);
    assert!(c.setup_redirect);
    assert_eq!(c.tproxy_uid, 1234);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);

    // getopt: a repeated option's last value wins; values may start with '-'.
    let r = parse(
        CLIENT,
        &[
            "--no-reconnect",
            "--reconnect",
            "--token",
            "-x",
            "--cc",
            "cubic",
            "--cc",
            "bbr",
        ],
    )
    .unwrap();
    assert!(client(&r).config.reconnect);
    assert_eq!(client(&r).config.token, "-x");
    assert_eq!(r.cc, CongestionControl::Bbr);
    // Each ingress alone is enough.
    for flag in ["--http-connect", "--tproxy"] {
        let r = cli::parse(&[
            "mqproxy",
            "client",
            "--server",
            "1.2.3.4:5",
            "--token",
            "t",
            flag,
            "127.0.0.1:9",
        ]);
        assert!(r.is_ok(), "{flag}: {r:?}");
    }
    // More than 8 --path: C warns and ignores the extras.
    let mut extra = Vec::new();
    for _ in 0..9 {
        extra.extend(["--path", "10.0.0.1"]);
    }
    let r = parse(CLIENT, &extra).unwrap();
    assert_eq!(client(&r).config.paths.len(), 8);
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
}

/// spec §8: the gateway is on by default, with `GatewayConfig`'s defaults, H3
/// enabled and the `mq_origin:` startup line.
#[test]
fn server_gateway_on_by_default() {
    let r = parse(SERVER, &[]).unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(server(&r).config.gateway, Some(GatewayConfig::default()));
    assert!(cli::wants_h3(&r));
    assert_eq!(
        r.startup_lines,
        vec!["mq_origin: hyper 1.10 + rustls (HTTP3=no)".to_string()]
    );
    // The gateway flags reach `GatewayConfig`.
    let r = parse(
        SERVER,
        &[
            "--origin-ca",
            "/ca.pem",
            "--masquerade",
            "--request-metrics",
        ],
    )
    .unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(
        server(&r).config.gateway,
        Some(GatewayConfig {
            origin_ca: Some(PathBuf::from("/ca.pem")),
            masquerade: true,
            request_metrics: true,
            ..GatewayConfig::default()
        })
    );
}

/// spec §8: `--no-gateway` → `gateway = None`, no H3, no `mq_origin:` line;
/// `--masquerade` / `--request-metrics` with it warn and are ignored (C text).
#[test]
fn no_gateway_disables_h3_and_warns_masquerade_and_metrics() {
    let r = parse(SERVER, &["--no-gateway", "--origin-ca", "/ca.pem"]).unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(server(&r).config.gateway, None);
    assert!(!cli::wants_h3(&r));
    assert!(r.startup_lines.is_empty(), "{:?}", r.startup_lines);
    // C's order: request-metrics, cache, masquerade.
    let r = parse(
        SERVER,
        &[
            "--masquerade",
            "--cache-max-bytes",
            "1",
            "--no-gateway",
            "--request-metrics",
        ],
    )
    .unwrap();
    assert_eq!(server(&r).config.gateway, None);
    assert_eq!(
        r.warnings,
        vec![
            "--request-metrics has no effect with --no-gateway (request metrics are gateway-only); ignoring",
            "--cache-max-bytes ([Gateway] CacheMaxBytes) is ignored: the origin response cache was removed",
            "--masquerade has no effect with --no-gateway (masquerade is gateway-only); ignoring",
        ]
    );
}

/// spec §8: `--gateway` alone is an ingress; it is not a TCP ingress.
#[test]
fn client_gateway_counts_as_ingress() {
    let r = cli::parse(&[
        "mqproxy",
        "client",
        "--server",
        "1.2.3.4:5",
        "--token",
        "t",
        "--gateway",
        "127.0.0.1:8081",
    ])
    .unwrap();
    let c = client(&r);
    assert_eq!(c.config.gateway, Some(addr("127.0.0.1:8081")));
    assert!(!c.config.has_tcp_ingress);
    let r = parse(CLIENT, &["--gateway", "[::1]:8081"]).unwrap();
    assert_eq!(client(&r).config.gateway, Some(addr("[::1]:8081")));
    assert!(client(&r).config.has_tcp_ingress);
    for extra in [
        &["--http-connect", "127.0.0.1:1"][..],
        &["--tproxy", "127.0.0.1:2"],
    ] {
        let argv = [
            &["mqproxy", "client", "--server", "1.2.3.4:5", "--token", "t"][..],
            extra,
        ]
        .concat();
        assert!(
            client(&cli::parse(&argv).unwrap()).config.has_tcp_ingress,
            "{extra:?}"
        );
    }
    // C's validation order: server, socks5, http-connect, gateway, tproxy.
    for (extra, first) in [
        (&["--server", "x", "--socks5", "y"][..], "--server"),
        (&["--socks5", "x", "--gateway", "y"], "--socks5"),
        (&["--http-connect", "x", "--gateway", "y"], "--http-connect"),
        (&["--gateway", "x", "--tproxy", "y"], "--gateway"),
    ] {
        let e = exit(parse(CLIENT, extra));
        assert!(
            e.message.contains(&format!("invalid {first} address")),
            "{extra:?}: {}",
            e.message
        );
    }
    let e = exit(parse(CLIENT, &["--gateway", "127.0.0.1"]));
    assert_eq!(e.code, 2);
    assert!(
        e.message.contains("invalid --gateway address"),
        "{}",
        e.message
    );
}

/// spec §8: the client enables H3 only with `--gateway`.
#[test]
fn client_gateway_enables_h3() {
    let r = parse(CLIENT, &[]).unwrap();
    assert!(!cli::wants_h3(&r));
    assert!(r.startup_lines.is_empty(), "{:?}", r.startup_lines);
    assert!(cli::wants_h3(
        &parse(CLIENT, &["--gateway", "127.0.0.1:8081"]).unwrap()
    ));
}

/// spec §8: `MQ_GW_ORIGIN_CONNECT_TIMEOUT_S` is an integer in [1, 600], else 10 s.
#[test]
fn origin_connect_timeout_pure() {
    for v in [
        None,
        Some(""),
        Some("abc"),
        Some("0"),
        Some("601"),
        Some("-5"),
        Some("5x"),
    ] {
        assert_eq!(
            cli::origin_connect_timeout(v),
            Duration::from_secs(10),
            "{v:?}"
        );
    }
    assert_eq!(
        cli::origin_connect_timeout(Some("2")),
        Duration::from_secs(2)
    );
    assert_eq!(
        cli::origin_connect_timeout(Some("1")),
        Duration::from_secs(1)
    );
    assert_eq!(
        cli::origin_connect_timeout(Some("600")),
        Duration::from_secs(600)
    );
}

/// spec §8: `--no-udp` and `--udp-idle-timeout` reach `ServerConfig` (C defaults: on, 60 s).
#[test]
fn server_udp_flags_change_config() {
    let d = parse(SERVER, &[]).unwrap();
    assert!(server(&d).config.udp_enabled);
    assert_eq!(server(&d).config.udp_idle_timeout, Duration::from_secs(60));
    let r = parse(SERVER, &["--no-udp", "--udp-idle-timeout", "5"]).unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert!(!server(&r).config.udp_enabled);
    assert_eq!(server(&r).config.udp_idle_timeout, Duration::from_secs(5));
    // Each alone, and getopt's last-value-wins.
    let r = parse(SERVER, &["--no-udp"]).unwrap();
    assert!(!server(&r).config.udp_enabled);
    assert_eq!(server(&r).config.udp_idle_timeout, Duration::from_secs(60));
    let r = parse(
        SERVER,
        &["--udp-idle-timeout", "9", "--udp-idle-timeout", "1"],
    )
    .unwrap();
    assert!(server(&r).config.udp_enabled);
    assert_eq!(server(&r).config.udp_idle_timeout, Duration::from_secs(1));
    // Must be > 0 (also in the exit-2 table below).
    let e = exit(parse(SERVER, &["--udp-idle-timeout", "0"]));
    assert_eq!(e.code, 2);
    assert!(e.message.contains("--udp-idle-timeout"), "{}", e.message);
}

#[test]
fn client_accepted_no_effect_flags() {
    let r = parse(
        CLIENT,
        &[
            "--ca-cert",
            "ca.pem",
            "--ca-key",
            "ca.key",
            "--ignore-host",
            ".x.com",
            "--ignore-hosts",
            "a,b",
        ],
    )
    .unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(r, parse(CLIENT, &[]).unwrap());
}

/// `--tproxy` + `--mitm` + a staged P-256 CA (a test-unique 0600 dir), then `extra`.
fn parse_mitm(test: &str, extra: &[&str]) -> Result<Resolved, Exit> {
    let (c, k) = common::stage_ca(test, "ca-p256.crt", "ca-p256.key");
    let argv = [
        &[
            "--tproxy",
            "127.0.0.1:18443",
            "--mitm",
            "--ca-cert",
            &c,
            "--ca-key",
            &k,
        ][..],
        extra,
    ]
    .concat();
    parse(CLIENT, &argv)
}

/// spec §9: `--mitm` needs `--tproxy`, with or without another ingress.
#[test]
fn mitm_without_tproxy_exit2() {
    let (c, k) = common::stage_ca("no-tproxy", "ca-p256.crt", "ca-p256.key");
    for extra in [&[][..], &["--gateway", "127.0.0.1:8081"]] {
        let argv = [extra, &["--mitm", "--ca-cert", &c, "--ca-key", &k]].concat();
        let e = exit(parse(CLIENT, &argv));
        assert_eq!(e.code, 2, "{extra:?}");
        assert!(
            e.message.contains("--mitm requires --tproxy"),
            "{}",
            e.message
        );
        assert!(e.message.contains("Usage"), "{}", e.message);
    }
}

#[test]
fn mitm_without_ca_exit2() {
    let (c, k) = common::stage_ca("no-ca", "ca-p256.crt", "ca-p256.key");
    for (extra, missing) in [
        (vec![], "--ca-cert"),
        (vec!["--ca-key", &k], "--ca-cert"),
        (vec!["--ca-cert", &c], "--ca-key"),
    ] {
        let argv = [&["--tproxy", "127.0.0.1:2", "--mitm"][..], &extra].concat();
        let e = exit(parse(CLIENT, &argv));
        assert_eq!(e.code, 2, "{extra:?}");
        assert!(e.message.contains(missing), "{}", e.message);
    }
}

/// spec §7.1: the `CaError` message reaches the user (PKCS#1 → the openssl hint).
#[test]
fn mitm_bad_ca_exit2_names_error() {
    let (c, k) = common::stage_ca("bad-ca", "ca-p256.crt", "key-rsa-pkcs1.pem");
    let argv = [
        "--tproxy",
        "127.0.0.1:2",
        "--mitm",
        "--ca-cert",
        &c,
        "--ca-key",
        &k,
    ];
    let e = exit(parse(CLIENT, &argv));
    assert_eq!(e.code, 2);
    assert!(
        e.message
            .contains("convert with: openssl pkcs8 -topk8 -nocrypt -in <key> -out <new>"),
        "{}",
        e.message
    );
    // A missing file is an error too, naming the path.
    let argv = [
        "--tproxy",
        "127.0.0.1:2",
        "--mitm",
        "--ca-cert",
        "/nope.crt",
        "--ca-key",
        &k,
    ];
    let e = exit(parse(CLIENT, &argv));
    assert_eq!(e.code, 2);
    assert!(e.message.contains("/nope.crt"), "{}", e.message);
}

#[test]
fn mitm_invalid_ignore_entry_exit2_names_entry() {
    for (flag, value) in [
        ("--ignore-host", "bad host"),
        ("--ignore-hosts", "ok.com,bad host"),
    ] {
        let e = exit(parse_mitm("bad-ignore", &[flag, value]));
        assert_eq!(e.code, 2, "{flag}");
        assert!(
            e.message
                .contains(r#"invalid IgnoreHosts entry "bad host""#),
            "{}",
            e.message
        );
    }
}

/// spec §9: `--mitm` is client-only; the server's parser does not know it.
#[test]
fn mitm_on_server_exit2() {
    let e = exit(parse(SERVER, &["--mitm"]));
    assert_eq!(e.code, 2);
    assert!(e.message.contains("--mitm"), "{}", e.message);
}

/// A good CA + tproxy builds `config.mitm`; repeated and comma-split ignore
/// flags (empty tokens skipped, as in C) are unioned.
#[test]
fn mitm_ok_builds_config() {
    let r = parse_mitm(
        "ok",
        &[
            "--ignore-host",
            "a.org",
            "--ignore-hosts",
            "b.org,,.c.org,",
            "--ignore-host",
            "d.org",
        ],
    )
    .unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let m = client(&r).config.mitm.as_ref().unwrap();
    assert_eq!(m.ignore.len(), 4);
    assert_eq!(m.tuning, MitmTuning::default());
    assert_eq!(client(&r).tproxy, Some(addr("127.0.0.1:18443")));
}

/// spec §8: the MITM front rides the H3 tunnel, so `--mitm` alone wants the H3 layer.
#[test]
fn mitm_only_wants_h3() {
    assert!(!cli::wants_h3(&parse(CLIENT, &[]).unwrap()));
    let r = parse_mitm("wants-h3", &[]).unwrap();
    assert!(client(&r).config.gateway.is_none());
    assert!(cli::wants_h3(&r));
}

/// spec §9: CA and ignore flags without `--mitm` are accepted and do nothing.
#[test]
fn ca_flags_without_mitm_no_effect() {
    let argv = [
        "--ca-cert",
        "/nope",
        "--ca-key",
        "/nope",
        "--ignore-host",
        "bad host",
    ];
    let r = parse(CLIENT, &argv).unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert!(client(&r).config.mitm.is_none());
}

/// The cache was removed: one warning, gateway on or off (it replaces C's
/// "no effect with --no-gateway" warning for this flag).
#[test]
fn cache_max_bytes_warns() {
    for extra in [&[][..], &["--no-gateway"]] {
        let argv = [extra, &["--cache-max-bytes", "67108864"]].concat();
        let r = parse(SERVER, &argv).unwrap();
        assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
        assert!(
            r.warnings[0].contains("--cache-max-bytes"),
            "{:?}",
            r.warnings
        );
    }
}

#[test]
fn abbreviation_accepted_and_exact_beats_prefix() {
    let r = cli::parse(&[
        "mqproxy",
        "server",
        "--lis",
        "127.0.0.1:1",
        "--tok",
        "t",
        "--cer",
        "c",
        "--ke",
        "k",
        "--max-c=3",
    ])
    .unwrap();
    assert_eq!(server(&r).listen, addr("127.0.0.1:1"));
    assert_eq!(server(&r).max_conns, 3);

    // Exact names that are also prefixes of longer ones.
    let r = parse(
        CLIENT,
        &["--no-reconnect", "--reconnect", "--tproxy", "127.0.0.1:2"],
    )
    .unwrap();
    assert!(client(&r).config.reconnect);
    assert_eq!(client(&r).tproxy, Some(addr("127.0.0.1:2")));
    assert!(parse(CLIENT, &["--ignore-host", "x"]).is_ok());
    let r = parse(CLIENT, &["--no-recon", "--reconnect-m", "4"]).unwrap();
    assert!(!client(&r).config.reconnect);
    assert_eq!(
        client(&r).config.reconnect_max_backoff,
        Duration::from_secs(4)
    );

    // Ambiguous prefix: usage error.
    assert_eq!(exit(parse(CLIENT, &["--recon"])).code, 2);
    assert_eq!(exit(parse(CLIENT, &["--tproxy-", "1"])).code, 2);
}

#[test]
fn invalid_cc_rejected() {
    for extra in [
        &["--cc", "reno"][..],
        &["--cc", "BBR"],
        &["--scheduler", "rr"],
        &["--tproxy-mode", "nat"],
        &["--server", "1.2.3.4"],
        &["--server", "host:443"],
        &["--server", "1.2.3.4:0"],
        &["--socks5", "1.2.3.4:70000"],
        &["--path", "not-an-ip"],
        &["--keepalive-idle", "-1"],
        &["--reconnect-max-backoff", "0"],
        &["--metrics-interval", "0"],
        &["--tproxy-fwmark", "0"],
        &["--tproxy-table", "65536"],
        &["--tproxy-dport", "0"],
        &["--tproxy-uid", "-1"],
    ] {
        let e = exit(parse(CLIENT, extra));
        assert_eq!(e.code, 2, "{extra:?}: {}", e.message);
    }
    for extra in [
        &["--listen", "[::1]"][..],
        &["--cc", "x"],
        &["--max-conns", "-1"],
        &["--max-conns", "4294967296"],
        &["--udp-idle-timeout", "0"],
        &["--cache-max-bytes", "-1"],
    ] {
        let e = exit(parse(SERVER, extra));
        assert_eq!(e.code, 2, "{extra:?}: {}", e.message);
    }
    let e = exit(parse(CLIENT, &["--cc", "reno"]));
    assert!(e.message.contains("reno"), "{}", e.message);
    assert!(e.message.contains("Usage"), "{}", e.message);
}

#[test]
fn no_ingress_rejected() {
    let e = exit(cli::parse(&[
        "mqproxy",
        "client",
        "--server",
        "1.2.3.4:5",
        "--token",
        "t",
    ]));
    assert_eq!(e.code, 2);
    // C text, naming --gateway too (tests/test_cli_help.sh greps for it).
    assert!(
        e.message.contains(
            "at least one ingress is required (--socks5, --http-connect, --gateway, or --tproxy)"
        ),
        "{}",
        e.message
    );
    assert!(!e.message.contains("not available"), "{}", e.message);
    // Other missing required flags / unknown subcommand.
    for argv in [
        &[
            "mqproxy",
            "client",
            "--token",
            "t",
            "--socks5",
            "127.0.0.1:1",
        ][..],
        &[
            "mqproxy",
            "client",
            "--server",
            "1.2.3.4:5",
            "--socks5",
            "127.0.0.1:1",
        ],
        &[
            "mqproxy", "server", "--token", "t", "--cert", "c", "--key", "k",
        ],
        &[
            "mqproxy",
            "server",
            "--listen",
            "127.0.0.1:1",
            "--cert",
            "c",
            "--key",
            "k",
        ],
        &[
            "mqproxy",
            "server",
            "--listen",
            "127.0.0.1:1",
            "--token",
            "t",
            "--key",
            "k",
        ],
        &[
            "mqproxy",
            "server",
            "--listen",
            "127.0.0.1:1",
            "--token",
            "t",
            "--cert",
            "c",
        ],
        &["mqproxy", "bogus"],
        &["mqproxy", "help"],
        &["mqproxy"],
    ] {
        assert_eq!(exit(cli::parse(argv)).code, 2, "{argv:?}");
    }
}

#[test]
fn defaults_match_c_usage_text() {
    let r = parse(SERVER, &[]).unwrap();
    assert_eq!(r.cc, CongestionControl::Bbr);
    assert_eq!(r.scheduler, Scheduler::MinRtt);
    assert_eq!(r.qlog, None);
    assert_eq!(r.config, None);
    let s = server(&r);
    assert_eq!(s.max_conns, 16);
    assert_eq!(s.config.metrics_interval, None);

    let r = parse(CLIENT, &[]).unwrap();
    assert_eq!(r.cc, CongestionControl::Bbr);
    assert_eq!(r.scheduler, Scheduler::MinRtt);
    let c = client(&r);
    assert_eq!(c.config.client_id, "mqproxy");
    assert_eq!(c.config.keepalive_idle, Some(Duration::from_secs(30)));
    assert!(c.config.reconnect);
    assert_eq!(c.config.reconnect_max_backoff, Duration::from_secs(30));
    assert_eq!(c.config.metrics_interval, None);
    assert!(c.config.paths.is_empty());
    assert_eq!(c.config.scheduler, Scheduler::MinRtt);
    assert_eq!(c.http_connect, None);
    assert_eq!(c.tproxy, None);
    assert_eq!(c.tproxy_mode, ListenKind::Redirect);
    assert_eq!(c.tproxy_fwmark, 1);
    assert_eq!(c.tproxy_table, 100);
    assert_eq!(c.tproxy_dport, 443);
    assert!(!c.setup_redirect);
    assert_eq!(c.tproxy_uid, mq_linux::geteuid());
    assert!(r.warnings.is_empty());
}

#[test]
fn keepalive_idle_zero_disables_and_le_15s_warns() {
    let r = parse(CLIENT, &["--keepalive-idle", "0"]).unwrap();
    assert_eq!(client(&r).config.keepalive_idle, None);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    for v in [1u64, 15] {
        let r = parse(CLIENT, &["--keepalive-idle", &v.to_string()]).unwrap();
        assert_eq!(
            client(&r).config.keepalive_idle,
            Some(Duration::from_secs(v))
        );
        assert_eq!(r.warnings.len(), 1, "{v}");
        assert!(
            r.warnings[0].contains("--keepalive-idle"),
            "{:?}",
            r.warnings
        );
    }
    assert!(
        parse(CLIENT, &["--keepalive-idle", "16"])
            .unwrap()
            .warnings
            .is_empty()
    );
}

#[test]
fn help_and_version_exit_0_in_process() {
    for argv in [
        &["mqproxy", "--help"][..],
        &["mqproxy", "-h"],
        &["mqproxy", "server", "-h"],
        &["mqproxy", "client", "--help"],
    ] {
        let e = exit(cli::parse(argv));
        assert_eq!(e.code, 0, "{argv:?}");
        assert!(e.message.contains("Usage"), "{}", e.message);
    }
    for argv in [
        &["mqproxy", "-V"][..],
        &["mqproxy", "--version"],
        &["mqproxy", "version"],
    ] {
        let e = exit(cli::parse(argv));
        assert_eq!(
            (e.code, e.message.trim()),
            (0, concat!("mqproxy ", env!("CARGO_PKG_VERSION")))
        );
    }
    // -V is top-level only, as in C.
    assert_eq!(exit(parse(SERVER, &["-V"])).code, 2);
}

// ---- the only tests that spawn the binary ----

/// The C `longopts` tables (cli/main.c `cmd_server` / `cmd_client`).
const SERVER_LONGOPTS: &[&str] = &[
    "listen",
    "token",
    "cert",
    "key",
    "origin-ca",
    "no-gateway",
    "udp-idle-timeout",
    "no-udp",
    "qlog",
    "cc",
    "scheduler",
    "metrics-interval",
    "request-metrics",
    "masquerade",
    "cache-max-bytes",
    "max-conns",
    "config",
    "help",
];
const CLIENT_LONGOPTS: &[&str] = &[
    "server",
    "token",
    "socks5",
    "http-connect",
    "gateway",
    "path",
    "client-id",
    "qlog",
    "cc",
    "scheduler",
    "keepalive-idle",
    "reconnect",
    "no-reconnect",
    "reconnect-max-backoff",
    "metrics-interval",
    "config",
    "tproxy",
    "tproxy-mode",
    "tproxy-fwmark",
    "tproxy-table",
    "tproxy-dport",
    "setup-redirect",
    "tproxy-uid",
    "mitm",
    "ca-cert",
    "ca-key",
    "ignore-host",
    "ignore-hosts",
    "help",
];

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mqproxy"))
        .args(args)
        .output()
        .unwrap()
}

/// spec §9: `--mitm` lost its "(not available in this build)" marker.
#[test]
fn mitm_help_no_unavailable_marker() {
    let out = run(&["client", "--help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("--mitm"), "{text}");
    assert!(!text.contains("not available"), "{text}");
}

/// spec §11.5: every C long option is listed, and no flag carries an old SP1 marker.
#[test]
fn help_lists_every_longopt() {
    for (sub, opts) in [("server", SERVER_LONGOPTS), ("client", CLIENT_LONGOPTS)] {
        let out = run(&[sub, "--help"]);
        assert_eq!(out.status.code(), Some(0));
        let text = String::from_utf8(out.stdout).unwrap();
        let words: Vec<&str> = text
            .split(|ch: char| !(ch.is_alphanumeric() || ch == '-'))
            .collect();
        for o in opts {
            let flag = format!("--{o}");
            assert!(
                words.contains(&flag.as_str()),
                "{sub} --help lacks {flag}:\n{text}"
            );
        }
        // C's wording now that the gateway conn exists.
        let metrics = match sub {
            "server" => "Logs the most-recently-accepted TCP and gateway conn",
            _ => "Logs the proxy conn (and the gateway conn with --gateway)",
        };
        assert!(text.contains(metrics), "{sub}: {text}");
        let entry = |flag: &str| {
            let start = text
                .find(&format!("  {flag} "))
                .unwrap_or_else(|| panic!("{flag}"));
            // Up to the next line that starts an option.
            let entry = &text[start + 2..];
            let end = entry
                .match_indices('\n')
                .find(|(i, _)| entry[i + 1..].trim_start().starts_with('-'))
                .map_or(entry.len(), |(i, _)| i);
            entry[..end].to_string()
        };
        // Nothing is "not available" any more (SP4 shipped `--mitm`).
        assert!(!text.contains("not available in this build"), "{text}");
        for flag in [
            "--origin-ca",
            "--no-gateway",
            "--masquerade",
            "--request-metrics",
            "--gateway",
        ] {
            if opts.contains(&&flag[2..]) {
                let e = entry(flag);
                assert!(!e.contains("not available"), "{e}");
                assert!(!e.contains("(accepted, no effect"), "{e}");
            }
        }
    }
}

#[test]
fn version_exits_0() {
    for arg in ["-V", "--version", "version"] {
        let out = run(&[arg]);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            String::from_utf8(out.stdout).unwrap().trim(),
            concat!("mqproxy ", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn usage_error_exits_2() {
    for args in [
        &["server", "--bogus"][..],
        &["client", "--nope"],
        &["bogus"],
        &[],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("Usage"), "{args:?}: {err}");
        assert!(out.stdout.is_empty(), "{args:?}");
    }
}

// ---- spec §6.4: the running binary (valid fixtures, SIGTERM → exit 0) ----

mod common;
use common::{Proc, cert, free_tcp, free_udp};

/// `--origin-ca` keeps the gateway-on server independent of the native store.
fn server_args(listen: &str, extra: &[&str]) -> Vec<String> {
    let (c, k, ca) = (cert("test.crt"), cert("test.key"), cert("origin-ca.crt"));
    let base = [
        "server",
        "--listen",
        listen,
        "--token",
        "t",
        "--cert",
        &c,
        "--key",
        &k,
        "--origin-ca",
        &ca,
    ];
    base.iter().chain(extra).map(|s| s.to_string()).collect()
}

fn spawn(args: &[String]) -> Proc {
    Proc::spawn(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

#[test]
fn gateway_on_and_udp_lines_logged() {
    let mut p = spawn(&server_args(&format!("127.0.0.1:{}", free_udp()), &[]));
    p.wait_line("[INFO] mq_origin: hyper 1.10 + rustls (HTTP3=no)");
    p.wait_line("gateway=on, udp=on, udp-idle=60s)");
    assert_eq!(p.term(), 0, "{:#?}", p.lines);
}

#[test]
fn server_accepted_flags_start_and_exit_0_on_sigterm() {
    let extra = ["--no-gateway", "--no-udp", "--udp-idle-timeout", "30"];
    let mut p = spawn(&server_args(&format!("127.0.0.1:{}", free_udp()), &extra));
    p.wait_line("[INFO] mqproxy server listening on");
    p.wait_line("gateway=off, udp=off, udp-idle=30s)");
    assert_eq!(p.term(), 0, "{:#?}", p.lines);
}

#[test]
fn client_accepted_flags_start_and_exit_0_on_sigterm() {
    let socks = format!("127.0.0.1:{}", free_tcp());
    let server = format!("127.0.0.1:{}", free_udp());
    let mut p = Proc::spawn(&[
        "client",
        "--server",
        &server,
        "--token",
        "t",
        "--socks5",
        &socks,
        "--ca-cert",
        "ca.pem",
        "--ca-key",
        "ca.key",
        "--ignore-host",
        "a.example",
        "--ignore-hosts",
        "b.example,.c.example",
    ]);
    p.wait_line("[INFO] mqproxy client: server=");
    assert_eq!(p.term(), 0, "{:#?}", p.lines);
}

#[test]
fn bad_cert_path_exits_1() {
    let listen = format!("127.0.0.1:{}", free_udp());
    let mut p = Proc::spawn(&[
        "server",
        "--listen",
        &listen,
        "--token",
        "t",
        "--cert",
        "/nonexistent/test.crt",
        "--key",
        "/nonexistent/test.key",
    ]);
    assert_eq!(p.wait_exit(), 1, "{:#?}", p.lines);
    assert!(
        p.lines.iter().any(|l| l.starts_with("[ERROR] ")),
        "{:#?}",
        p.lines
    );
}

#[test]
fn listen_addr_in_use_exits_1() {
    let busy = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen = busy.local_addr().unwrap().to_string();
    let mut p = spawn(&server_args(&listen, &[]));
    assert_eq!(p.wait_exit(), 1, "{:#?}", p.lines);
    assert!(
        p.lines.iter().any(|l| l.starts_with("[ERROR] ")),
        "{:#?}",
        p.lines
    );
}
