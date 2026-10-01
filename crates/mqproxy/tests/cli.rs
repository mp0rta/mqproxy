//! spec §6.4: the CLI flag table, in process through `cli::parse`; only the last
//! three tests spawn the binary.

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
        "--config",
        "/etc/m.ini",
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
    assert_eq!(r.config, Some(PathBuf::from("/etc/m.ini")));
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
        "--config",
        "c.ini",
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
    assert_eq!(r.config, Some(PathBuf::from("c.ini")));
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

#[test]
fn server_accepted_no_effect_flags() {
    let r = parse(
        SERVER,
        &["--no-gateway", "--no-udp", "--udp-idle-timeout", "5"],
    )
    .unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(r, parse(SERVER, &[]).unwrap());
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

#[test]
fn server_unavailable_flags_exit_2() {
    for extra in [
        &["--origin-ca", "ca.pem"][..],
        &["--masquerade"],
        &["--request-metrics"],
    ] {
        let e = exit(parse(SERVER, extra));
        assert_eq!(e.code, 2, "{extra:?}");
        assert!(e.message.contains(extra[0]), "{}", e.message);
        assert!(e.message.contains("not available"), "{}", e.message);
        assert!(e.message.contains("Usage"), "{}", e.message);
    }
}

#[test]
fn client_unavailable_flags_exit_2() {
    for extra in [&["--gateway", "127.0.0.1:8081"][..], &["--mitm"]] {
        let e = exit(parse(CLIENT, extra));
        assert_eq!(e.code, 2, "{extra:?}");
        assert!(e.message.contains(extra[0]), "{}", e.message);
        assert!(e.message.contains("not available"), "{}", e.message);
    }
}

#[test]
fn cache_max_bytes_warns() {
    let r = parse(SERVER, &["--cache-max-bytes", "67108864"]).unwrap();
    assert_eq!(r.warnings.len(), 1);
    assert!(
        r.warnings[0].contains("--cache-max-bytes"),
        "{:?}",
        r.warnings
    );
}

#[test]
fn server_gateway_udp_off_startup_line() {
    let r = parse(SERVER, &[]).unwrap();
    assert_eq!(r.startup_lines.len(), 1);
    assert!(
        r.startup_lines[0].contains("gateway"),
        "{:?}",
        r.startup_lines
    );
    assert!(r.startup_lines[0].contains("UDP"), "{:?}", r.startup_lines);
    assert!(parse(CLIENT, &[]).unwrap().startup_lines.is_empty());
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
    assert!(e.message.contains("ingress"), "{}", e.message);
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

#[test]
fn help_lists_every_longopt() {
    for (sub, opts, unavailable) in [
        (
            "server",
            SERVER_LONGOPTS,
            &["--origin-ca", "--masquerade", "--request-metrics"][..],
        ),
        ("client", CLIENT_LONGOPTS, &["--gateway", "--mitm"]),
    ] {
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
        // The entry of each unavailable flag says so.
        for flag in unavailable {
            let start = text
                .find(&format!("  {flag} "))
                .unwrap_or_else(|| panic!("{flag}"));
            let entry = &text[start + 2..];
            let entry = &entry[..entry.find("\n  -").unwrap_or(entry.len())];
            assert!(entry.contains("not available in this build"), "{entry}");
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
