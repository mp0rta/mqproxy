//! spec §6.4 "Config file": the INI loader, in process through `cli::parse`
//! with `--config <tempfile>`. Ports C `tests/test_config.c` and gives every
//! row of the SP1 flag table its INI equivalent.

use mq_runtime::ListenKind;
use mq_transport_api::{CongestionControl, Scheduler};
use mqproxy::cli::{self, Client, Exit, Mode, Resolved, Server};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A temp INI file (mode 0600 unless changed), removed on drop.
struct Ini(PathBuf);

impl Ini {
    fn new(text: &str) -> Ini {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "mqproxy-cfg-{}-{}.ini",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, text).unwrap();
        Ini(p).mode(0o600)
    }
    fn mode(self, m: u32) -> Ini {
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(m)).unwrap();
        self
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for Ini {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `mqproxy <sub> --config <file> <extra...>`.
fn run(sub: &str, ini: &Ini, extra: &[&str]) -> Result<Resolved, Exit> {
    let mut argv = vec!["mqproxy", sub, "--config", ini.path()];
    argv.extend_from_slice(extra);
    cli::parse(&argv)
}

/// Minimal valid server/client INI bodies the row tests append to.
const SRV: &str =
    "[Interface]\nListen = 127.0.0.1:4433\n[Auth]\nKey = t\n[TLS]\nCert = c.pem\nKey = k.pem\n";
const CLI: &str =
    "[Server]\nAddress = 127.0.0.1:4433\n[Auth]\nKey = t\n[Ingress]\nSocks5 = 127.0.0.1:1080\n";

fn srv(extra: &str) -> Result<Resolved, Exit> {
    run("server", &Ini::new(&format!("{SRV}{extra}")), &[])
}

fn cli_(extra: &str) -> Result<Resolved, Exit> {
    run("client", &Ini::new(&format!("{CLI}{extra}")), &[])
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

fn warned(r: &Resolved, needle: &str) -> bool {
    r.warnings.iter().any(|w| w.contains(needle))
}

// ---- C tests/test_config.c ports ----

/// C test_defaults + test_partial_file_keeps_defaults: keys absent from the
/// file keep the defaults.
#[test]
fn c_defaults_and_partial_file() {
    let r = srv("").unwrap();
    assert_eq!(server(&r).max_conns, 16);
    let r = cli_("").unwrap();
    let c = client(&r);
    assert_eq!(c.config.client_id, "mqproxy");
    assert!(c.config.paths.is_empty());
    assert!(c.config.reconnect);
    assert_eq!(c.tproxy_mode, ListenKind::Redirect);
    assert_eq!(
        (c.tproxy_fwmark, c.tproxy_table, c.tproxy_dport),
        (1, 100, 443)
    );
}

/// C test_server_roundtrip.
#[test]
fn c_server_roundtrip() {
    let ini = Ini::new(
        "[Interface]\nListen = 0.0.0.0:4433\nMaxConns = 64\n[TLS]\nCert = /e/c.pem\n\
         Key  = /e/c.key\n[Auth]\nKey = s3cr3t\n[Multipath]\nCC = bbr2\nScheduler = wlb\n\
         [Log]\nQLog = /tmp/q\n[Metrics]\nInterval = 5\n",
    );
    let r = run("server", &ini, &[]).unwrap();
    let s = server(&r);
    assert_eq!(r.config.as_deref(), Some(ini.0.as_path()));
    assert_eq!(s.listen, addr("0.0.0.0:4433"));
    assert_eq!(s.max_conns, 64);
    assert_eq!(s.cert, PathBuf::from("/e/c.pem"));
    assert_eq!(s.key, PathBuf::from("/e/c.key"));
    assert_eq!(s.config.token, "s3cr3t");
    assert_eq!(s.config.metrics_interval, Some(Duration::from_secs(5)));
    assert_eq!(r.qlog, Some(PathBuf::from("/tmp/q")));
    assert_eq!(r.cc, CongestionControl::Bbr2);
    assert_eq!(r.scheduler, Scheduler::Wlb);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

/// C test_client_roundtrip (bracketed IPv6 Address).
#[test]
fn c_client_roundtrip() {
    let ini = Ini::new(
        "[Server]\nAddress = [2001:db8::1]:443\nClientId = edge\n[Auth]\nKey = tok\n\
         [Ingress]\nSocks5 = 127.0.0.1:1080\nHttpConnect = 127.0.0.1:8080\n\
         TProxy = 127.0.0.1:8443\nMode = tproxy\nFwmark = 7\nTable = 200\nDport = 8080\n\
         SetupRedirect = true\nSkipUid = 1000\n\
         [Interface]\nReconnect = false\nKeepaliveIdle = 45\nReconnectMaxBackoff = 9\n\
         [Multipath]\nPath = 10.0.0.1\nPath = 10.0.0.2\nCC = cubic\nScheduler = backup\n\
         [Log]\nQLog = /q\n[Metrics]\nInterval = 3\n",
    );
    let r = run("client", &ini, &[]).unwrap();
    let c = client(&r);
    assert_eq!(c.config.server, addr("[2001:db8::1]:443"));
    assert_eq!(c.config.client_id, "edge");
    assert_eq!(c.config.token, "tok");
    assert_eq!(c.socks5, Some(addr("127.0.0.1:1080")));
    assert_eq!(c.http_connect, Some(addr("127.0.0.1:8080")));
    assert_eq!(c.tproxy, Some(addr("127.0.0.1:8443")));
    assert_eq!(c.tproxy_mode, ListenKind::Tproxy);
    assert_eq!(
        (c.tproxy_fwmark, c.tproxy_table, c.tproxy_dport),
        (7, 200, 8080)
    );
    assert!(c.setup_redirect);
    assert_eq!(c.tproxy_uid, 1000);
    assert!(!c.config.reconnect);
    assert_eq!(c.config.keepalive_idle, Some(Duration::from_secs(45)));
    assert_eq!(c.config.reconnect_max_backoff, Duration::from_secs(9));
    assert_eq!(c.config.metrics_interval, Some(Duration::from_secs(3)));
    let p: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
    assert_eq!(c.config.paths, p);
    assert_eq!(r.cc, CongestionControl::Cubic);
    assert_eq!(r.scheduler, Scheduler::Backup);
    assert_eq!(r.qlog, Some(PathBuf::from("/q")));
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

/// C test_bool_variants: `yes`/`0` on the accepted-no-effect bool keys
/// (SP1: `Masquerade = true` is exit 2).
#[test]
fn c_bool_variants() {
    let r = srv("[Gateway]\nEnabled = yes\n[UDP]\nEnabled = 0\n").unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(exit(srv("[Gateway]\nMasquerade = true\n")).code, 2);
}

/// C test_path_cap: 10 file paths → 8 kept, with a warning.
#[test]
fn c_path_cap() {
    let paths: String = (1..=10).map(|i| format!("Path = 10.0.0.{i}\n")).collect();
    let r = cli_(&format!("[Multipath]\n{paths}")).unwrap();
    assert_eq!(client(&r).config.paths.len(), 8);
    assert!(warned(&r, "10.0.0.9"), "{:?}", r.warnings);
}

/// C test_lenient_and_comments.
#[test]
fn c_lenient_and_comments() {
    let ini = Ini::new(&format!(
        "# comment\n; also comment\n{SRV}[Interface]\nMaxConns = notanumber\n\
         [Bogus]\nFoo = bar\n[Auth]\nUnknownKey = x\nKey =\n[TLS]\nCert = /c.pem\n"
    ));
    let r = run("server", &ini, &[]).unwrap();
    let s = server(&r);
    assert_eq!(s.max_conns, 16); // bad value keeps the default
    assert_eq!(s.config.token, "t"); // empty Key does not clear the earlier one
    assert_eq!(s.cert, PathBuf::from("/c.pem"));
    assert!(warned(&r, "MaxConns"), "{:?}", r.warnings);
    assert!(warned(&r, "Bogus"), "{:?}", r.warnings);
    assert!(warned(&r, "UnknownKey"), "{:?}", r.warnings);
    assert!(warned(&r, "Foo"), "{:?}", r.warnings);
}

/// C test_mitm_section → SP1: `[Mitm] Enabled = true` is exit 2.
#[test]
fn c_mitm_section_enabled_exit_2() {
    let e = exit(cli_(
        "[Mitm]\nEnabled = true\nCACert = /c\nCAKey = /k\nIgnoreHosts = .apple.com\nIgnoreHosts = signal.org\n",
    ));
    assert_eq!(e.code, 2);
}

/// C test_mitm_server_mode_ignored: the server warns and skips every [Mitm] key.
#[test]
fn c_mitm_server_mode_ignored() {
    let r =
        srv("[Mitm]\nEnabled = true\nCACert = /c\nCAKey = /k\nIgnoreHosts = .apple.com\n").unwrap();
    assert_eq!(
        r.warnings.iter().filter(|w| w.contains("[Mitm]")).count(),
        4,
        "{:?}",
        r.warnings
    );
}

/// C test_mitm_enabled_missing_cacert → SP1: `Enabled = true` is exit 2;
/// `CACert` without `Enabled` is accepted.
#[test]
fn c_mitm_cacert_without_enabled_accepted() {
    assert_eq!(exit(cli_("[Mitm]\nEnabled = true\n")).code, 2);
    let r =
        cli_("[Mitm]\nCACert = /c\nCAKey = /k\nIgnoreHosts = x.org\nEnabled = false\n").unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

/// C test_perms_warning (+ spec §6.4: 0620 warns too).
#[test]
fn perms_warning() {
    for (mode, warns) in [(0o640, true), (0o620, true), (0o644, true), (0o600, false)] {
        let ini = Ini::new(SRV).mode(mode);
        let r = run("server", &ini, &[]).unwrap();
        assert_eq!(
            warned(&r, "chmod 0600"),
            warns,
            "mode {mode:o}: {:?}",
            r.warnings
        );
    }
}

/// C test_missing_file_fatal.
#[test]
fn unreadable_file_exit_2() {
    let e = exit(cli::parse(&[
        "mqproxy",
        "server",
        "--config",
        "/no/such/file.conf",
    ]));
    assert_eq!(e.code, 2);
    assert!(e.message.contains("/no/such/file.conf"), "{}", e.message);
    let e = exit(cli::parse(&[
        "mqproxy",
        "client",
        "--config",
        "/no/such/file.conf",
    ]));
    assert_eq!(e.code, 2);
}

// ---- spec §6.4 config-file table ----

#[test]
fn cli_overrides_file() {
    let ini = Ini::new(&format!(
        "{SRV}[Interface]\nMaxConns = 64\n[Multipath]\nCC = cubic\n"
    ));
    let r = run(
        "server",
        &ini,
        &[
            "--listen",
            "127.0.0.1:9",
            "--max-conns",
            "3",
            "--cc",
            "bbr2",
        ],
    )
    .unwrap();
    assert_eq!(server(&r).listen, addr("127.0.0.1:9"));
    assert_eq!(server(&r).max_conns, 3);
    assert_eq!(r.cc, CongestionControl::Bbr2);
    assert_eq!(server(&r).config.token, "t"); // the file still fills the rest

    let ini = Ini::new(&format!("{CLI}[Interface]\nReconnect = false\n"));
    let r = run("client", &ini, &["--reconnect"]).unwrap();
    assert!(client(&r).config.reconnect);
    let ini = Ini::new(&format!("{CLI}[Interface]\nReconnect = true\n"));
    let r = run("client", &ini, &["--no-reconnect"]).unwrap();
    assert!(!client(&r).config.reconnect);
    let ini = Ini::new(&format!("{CLI}[Server]\nClientId = file\n"));
    let r = run("client", &ini, &["--client-id", "cli"]).unwrap();
    assert_eq!(client(&r).config.client_id, "cli");
}

#[test]
fn paths_accumulate_file_then_cli_max_8_warn() {
    let paths: String = (1..=6).map(|i| format!("Path = 10.0.0.{i}\n")).collect();
    let ini = Ini::new(&format!("{CLI}[Multipath]\n{paths}"));
    let r = run(
        "client",
        &ini,
        &[
            "--path", "10.0.1.1", "--path", "10.0.1.2", "--path", "10.0.1.3",
        ],
    )
    .unwrap();
    let got: Vec<String> = client(&r)
        .config
        .paths
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(
        got,
        [
            "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.1.1",
            "10.0.1.2"
        ]
    );
    assert!(warned(&r, "10.0.1.3"), "{:?}", r.warnings);
}

#[test]
fn bool_values_exact_case() {
    // C parse_bool: strcmp against "true", "yes", "1" — exact case.
    let redirect = |v: &str| {
        client(&cli_(&format!("[Ingress]\nSetupRedirect = {v}\n")).unwrap()).setup_redirect
    };
    for v in ["true", "yes", "1"] {
        assert!(redirect(v), "{v}");
    }
    for v in ["True", "TRUE", "Yes", "on", "2", "false"] {
        assert!(!redirect(v), "{v}");
    }
}

#[test]
fn cc_validated_exit_2() {
    assert_eq!(exit(srv("[Multipath]\nCC = BBR\n")).code, 2);
    assert_eq!(exit(srv("[Multipath]\nScheduler = fastest\n")).code, 2);
    assert_eq!(exit(cli_("[Ingress]\nMode = nat\n")).code, 2);
    assert_eq!(exit(cli_("[Server]\nAddress = nope\n")).code, 2);
    assert_eq!(exit(srv("[Interface]\nListen = 1.2.3.4\n")).code, 2);
    assert_eq!(exit(cli_("[Multipath]\nPath = not-an-ip\n")).code, 2);
}

#[test]
fn empty_value_not_set() {
    // An empty value neither sets nor clears; a missing required key stays missing.
    let ini = Ini::new("[Interface]\nListen =\n[Auth]\nKey = t\n[TLS]\nCert = c\nKey = k\n");
    assert_eq!(exit(run("server", &ini, &[])).code, 2);
    let r = srv("[Gateway]\nOriginCA =\nMasquerade =\n").unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn names_case_insensitive() {
    let ini = Ini::new(
        "[interface]\nlisten = 127.0.0.1:4433\nMAXCONNS = 5\n[AUTH]\nkey = T\n[tls]\ncert = C\nKEY = K\n",
    );
    let r = run("server", &ini, &[]).unwrap();
    let s = server(&r);
    assert_eq!(s.max_conns, 5);
    assert_eq!(s.config.token, "T"); // values keep their case
    assert_eq!(s.cert, PathBuf::from("C"));
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn number_out_of_range_keeps_previous() {
    let r = cli_("[Ingress]\nTable = 5\nTable = 70000\nDport = 0\nFwmark = 0\n").unwrap();
    let c = client(&r);
    assert_eq!(c.tproxy_table, 5);
    assert_eq!((c.tproxy_dport, c.tproxy_fwmark), (443, 1));
    assert_eq!(r.warnings.len(), 3, "{:?}", r.warnings);
}

#[test]
fn malformed_and_other_mode_lines_warn_skip() {
    let r = srv(
        "no equals sign\n[Unclosed\n[Server]\nAddress = 1.2.3.4:5\n[Ingress]\nSocks5 = 1.2.3.4:5\n",
    )
    .unwrap();
    assert_eq!(r.warnings.len(), 4, "{:?}", r.warnings);
    let r = cli_(
        "[TLS]\nCert = c\n[Interface]\nListen = 1.2.3.4:5\nMaxConns = 3\n[Gateway]\nEnabled = true\n",
    )
    .unwrap();
    assert_eq!(r.warnings.len(), 4, "{:?}", r.warnings);
}

// ---- spec §6.4 "Flags in SP1": every table row through its INI key ----

/// Implemented (server): Listen, [Auth] Key, [TLS] Cert/Key, QLog, CC,
/// Scheduler, [Metrics] Interval, MaxConns — see c_server_roundtrip.
/// `Interval = 0` is off; `MaxConns = 0` is unlimited.
#[test]
fn server_implemented_keys_resolve() {
    let r = srv("[Metrics]\nInterval = 0\n[Interface]\nMaxConns = 0\n").unwrap();
    assert_eq!(server(&r).config.metrics_interval, None);
    assert_eq!(server(&r).max_conns, 0);
}

/// Implemented (client): see c_client_roundtrip. `KeepaliveIdle = 0`
/// disables; `SkipUid = -1` is the effective uid; TProxy alone is an ingress.
#[test]
fn client_implemented_keys_resolve() {
    let r = cli_("[Interface]\nKeepaliveIdle = 0\n[Ingress]\nSkipUid = -1\n").unwrap();
    assert_eq!(client(&r).config.keepalive_idle, None);
    assert_eq!(client(&r).tproxy_uid, mq_linux::geteuid());
    let ini = Ini::new(
        "[Server]\nAddress = 127.0.0.1:1\n[Auth]\nKey = t\n[Ingress]\nTProxy = 127.0.0.1:2\n",
    );
    let r = run("client", &ini, &[]).unwrap();
    assert_eq!(client(&r).tproxy, Some(addr("127.0.0.1:2")));
}

#[test]
fn server_accepted_no_effect_keys() {
    let r = srv("[Gateway]\nEnabled = false\n[UDP]\nEnabled = false\nIdleTimeout = 30\n").unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn client_accepted_no_effect_keys() {
    let r = cli_("[Mitm]\nCACert = /c\nCAKey = /k\nIgnoreHosts = a.org\nIgnoreHosts = .b.org\n")
        .unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn server_unavailable_keys_exit_2_only_when_true_or_set() {
    for k in [
        "[Gateway]\nOriginCA = /ca.pem\n",
        "[Gateway]\nMasquerade = true\n",
        "[Metrics]\nPerRequest = yes\n",
    ] {
        assert_eq!(exit(srv(k)).code, 2, "{k}");
    }
    let r = srv("[Gateway]\nMasquerade = false\n[Metrics]\nPerRequest = 0\n").unwrap();
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn client_unavailable_keys_exit_2_only_when_true_or_set() {
    assert_eq!(exit(cli_("[Ingress]\nGateway = 127.0.0.1:8081\n")).code, 2);
    assert_eq!(exit(cli_("[Mitm]\nEnabled = 1\n")).code, 2);
    assert!(cli_("[Mitm]\nEnabled = no\n").is_ok());
}

#[test]
fn cache_max_bytes_key_warns() {
    let r = srv("[Gateway]\nCacheMaxBytes = 1048576\n").unwrap();
    assert!(warned(&r, "CacheMaxBytes"), "{:?}", r.warnings);
}
