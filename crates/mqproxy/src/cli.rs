//! spec §6.4: the C-identical command line (cli/main.c `usage_*`, `longopts`).
//! `parse` turns argv into a fully resolved `Resolved` or an `Exit`.

use crate::config::{self, FileConfig};
use clap::error::ErrorKind;
use clap::{ArgAction, Args, CommandFactory, Parser, Subcommand};
use mq_proxy::config::{ClientConfig, ServerConfig};
use mq_runtime::ListenKind;
use mq_transport_api::{CongestionControl, Scheduler};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

/// C `MQ_MAX_EXTRA_PATHS`.
const MAX_PATHS: usize = 8;
/// xquic's client PING interval (fixed); an idle timeout at or below it still closes.
const XQUIC_PING_SECS: u64 = 15;

/// spec §6.4: what `main` prints (stdout for code 0, stderr otherwise) before exiting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    pub code: i32,
    pub message: String,
}

/// spec §6.4: the parsed and validated command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub mode: Mode,
    /// `--config`, already applied (spec §6.4: defaults < file < CLI).
    pub config: Option<PathBuf>,
    /// `--qlog <dir>`.
    pub qlog: Option<PathBuf>,
    pub cc: CongestionControl,
    pub scheduler: Scheduler,
    /// To log as warnings at startup.
    pub warnings: Vec<String>,
    /// To log as info at startup (the server's "gateway/UDP off" line).
    pub startup_lines: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Server(Server),
    Client(Client),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    pub config: ServerConfig,
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// 0 = unlimited.
    pub max_conns: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub config: ClientConfig,
    pub socks5: Option<SocketAddr>,
    pub http_connect: Option<SocketAddr>,
    pub tproxy: Option<SocketAddr>,
    /// `--tproxy-mode`: `Redirect` or `Tproxy`.
    pub tproxy_mode: ListenKind,
    pub tproxy_fwmark: u32,
    pub tproxy_table: u32,
    pub tproxy_dport: u16,
    pub setup_redirect: bool,
    /// Defaults to the effective uid.
    pub tproxy_uid: u32,
}

#[derive(Parser, Debug)]
#[command(
    name = "mqproxy",
    version,
    about = "mqproxy: TCP proxy over multipath QUIC.",
    after_help = "Run 'mqproxy <command> --help' for command-specific options.",
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)] // built once per process
enum Cmd {
    /// Run the mqproxy server (terminates proxied TCP).
    Server(ServerArgs),
    /// Run the mqproxy client with local SOCKS5 / HTTP CONNECT ingress listeners.
    Client(ClientArgs),
    /// Print the mqproxy version and exit.
    #[command(hide = true)]
    Version,
}

#[derive(Args, Debug)]
#[command(
    infer_long_args = true,
    args_override_self = true,
    disable_help_flag = true
)]
struct ServerArgs {
    /// Show this help and exit.
    #[arg(short, long, action = ArgAction::Help)]
    help: Option<bool>,
    /// UDP address to accept MPQUIC connections on (required).
    #[arg(long, value_name = "ip:port", allow_hyphen_values = true)]
    listen: Option<String>,
    /// Shared auth token clients must present (required).
    #[arg(long, value_name = "token", allow_hyphen_values = true)]
    token: Option<String>,
    /// TLS certificate (PEM) (required).
    #[arg(long, value_name = "path", allow_hyphen_values = true)]
    cert: Option<String>,
    /// TLS private key (PEM) (required).
    #[arg(long, value_name = "path", allow_hyphen_values = true)]
    key: Option<String>,
    /// (not available in this build) CA bundle (PEM) used to verify origin TLS for the HTTP gateway. Defaults to the system trust store.
    #[arg(long, value_name = "pem", allow_hyphen_values = true)]
    origin_ca: Option<String>,
    /// (accepted, no effect: the gateway is off in this build) Disable the HTTP gateway origin bridge (enabled by default; the server still serves the TCP-proxy core).
    #[arg(long)]
    no_gateway: bool,
    /// (accepted, no effect: UDP relay is off in this build) Idle timeout for UDP relay sessions in seconds (default: 60; must be > 0).
    #[arg(long, value_name = "sec", allow_hyphen_values = true, value_parser = clap::value_parser!(u64).range(1..))]
    udp_idle_timeout: Option<u64>,
    /// (accepted, no effect: UDP relay is off in this build) Disable UDP relay (do not advertise MQ_FEAT_UDP_RELAY).
    #[arg(long)]
    no_udp: bool,
    /// Write xquic qlog (EXTRA importance) to <dir>/server.qlog.
    #[arg(long, value_name = "dir", allow_hyphen_values = true)]
    qlog: Option<PathBuf>,
    /// Congestion control: bbr (default) | bbr2 | cubic.
    #[arg(long, value_name = "algo", allow_hyphen_values = true)]
    cc: Option<String>,
    /// Multipath scheduler: minrtt (default) | backup | wlb.
    #[arg(long, value_name = "s", allow_hyphen_values = true)]
    scheduler: Option<String>,
    /// Periodically log per-path stats (mq.conn/mq.path) every <sec>s (must be > 0; omit to disable). Logs the most-recently-accepted TCP conn.
    #[arg(long, value_name = "sec", allow_hyphen_values = true, value_parser = clap::value_parser!(u64).range(1..))]
    metrics_interval: Option<u64>,
    /// (not available in this build) Emit one mq.req logfmt line per gateway request (method/status/target/ttfb/origin_protocol/cache/…). Opt-in; off by default. Independent of --metrics-interval.
    #[arg(long)]
    request_metrics: bool,
    /// (not available in this build) Answer unauthenticated requests with a bare 404 (hides mqproxy from probes; gateway only).
    #[arg(long)]
    masquerade: bool,
    /// (ignored with a warning: the response cache was removed) In-memory origin response cache bounded to N bytes (0 = off = default).
    #[arg(long, value_name = "N", allow_hyphen_values = true)]
    cache_max_bytes: Option<u64>,
    /// Max simultaneous QUIC connections (default: 16; 0 = unlimited). Caps established connections; excess are refused (CONNECTION_REFUSED).
    #[arg(long, value_name = "N", allow_hyphen_values = true)]
    max_conns: Option<u32>,
    /// Load settings from an INI file (CLI flags override file values).
    #[arg(long, value_name = "path", allow_hyphen_values = true)]
    config: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[command(
    infer_long_args = true,
    disable_help_flag = true,
    args_override_self = true,
    after_help = "At least one ingress is required: --socks5, --http-connect, or --tproxy."
)]
struct ClientArgs {
    /// Show this help and exit.
    #[arg(short, long, action = ArgAction::Help)]
    help: Option<bool>,
    /// UDP address of the mqproxy server (required).
    #[arg(long, value_name = "ip:port", allow_hyphen_values = true)]
    server: Option<String>,
    /// Shared auth token (required).
    #[arg(long, value_name = "token", allow_hyphen_values = true)]
    token: Option<String>,
    /// Local TCP address for the SOCKS5 ingress (UDP ASSOCIATE is not available in this build).
    #[arg(long, value_name = "ip:port", allow_hyphen_values = true)]
    socks5: Option<String>,
    /// Local TCP address for the HTTP CONNECT ingress.
    #[arg(long, value_name = "ip:port", allow_hyphen_values = true)]
    http_connect: Option<String>,
    /// (not available in this build) Local TCP address for the HTTP gateway fetch ingress (POST /_mqproxy/fetch over its own H3 tunnel; independent of the SOCKS5/CONNECT core).
    #[arg(long, value_name = "ip:port", allow_hyphen_values = true)]
    gateway: Option<String>,
    /// Local IP to bind a path to (repeatable, at most 8). The first is the primary bind; each extra becomes a second/third MPQUIC path once the connection is multipath-ready.
    #[arg(long, value_name = "local ip", allow_hyphen_values = true)]
    path: Vec<String>,
    /// Client identifier sent at auth (default: mqproxy).
    #[arg(long, value_name = "id", allow_hyphen_values = true)]
    client_id: Option<String>,
    /// Write xquic qlog (EXTRA importance) to <dir>/client.qlog.
    #[arg(long, value_name = "dir", allow_hyphen_values = true)]
    qlog: Option<PathBuf>,
    /// Congestion control: bbr (default) | bbr2 | cubic.
    #[arg(long, value_name = "algo", allow_hyphen_values = true)]
    cc: Option<String>,
    /// Multipath scheduler: minrtt (default) | backup | wlb.
    #[arg(long, value_name = "s", allow_hyphen_values = true)]
    scheduler: Option<String>,
    /// QUIC idle timeout in seconds, kept alive by PINGs (default: 30; 0 = disable; <= 15 not useful: xquic's PING interval is fixed at 15 s).
    #[arg(long, value_name = "sec", allow_hyphen_values = true)]
    keepalive_idle: Option<u64>,
    /// Re-establish the server connection on loss (default: enabled).
    #[arg(long, overrides_with = "no_reconnect")]
    reconnect: bool,
    /// Disable automatic reconnect on connection loss.
    #[arg(long, overrides_with = "reconnect")]
    no_reconnect: bool,
    /// Maximum reconnect back-off in seconds (default: 30; must be > 0).
    #[arg(long, value_name = "sec", allow_hyphen_values = true, value_parser = clap::value_parser!(u64).range(1..))]
    reconnect_max_backoff: Option<u64>,
    /// Periodically log per-path stats (mq.conn/mq.path) every <sec>s (must be > 0; omit to disable). Logs the proxy conn.
    #[arg(long, value_name = "sec", allow_hyphen_values = true, value_parser = clap::value_parser!(u64).range(1..))]
    metrics_interval: Option<u64>,
    /// Load settings from an INI file (CLI flags override file values).
    #[arg(long, value_name = "path", allow_hyphen_values = true)]
    config: Option<PathBuf>,
    /// Local TCP address for the transparent capture ingress (REDIRECT or TPROXY mode).
    #[arg(long, value_name = "ip:port", allow_hyphen_values = true)]
    tproxy: Option<String>,
    /// Kernel capture mechanism (default: redirect). redirect — nft nat REDIRECT (single-host, no CAP_NET_ADMIN on the socket). tproxy — nft mangle TPROXY (router, needs CAP_NET_ADMIN for IP_TRANSPARENT).
    #[arg(long, value_name = "redirect|tproxy", allow_hyphen_values = true)]
    tproxy_mode: Option<String>,
    /// Packet mark for TPROXY routing (default: 1; tproxy mode only).
    #[arg(long, value_name = "n", allow_hyphen_values = true, value_parser = clap::value_parser!(u32).range(1..=i32::MAX as i64))]
    tproxy_fwmark: Option<u32>,
    /// ip routing table for TPROXY (default: 100; tproxy mode only).
    #[arg(long, value_name = "n", allow_hyphen_values = true, value_parser = clap::value_parser!(u32).range(1..=65535))]
    tproxy_table: Option<u32>,
    /// TCP destination port the --setup-redirect rule captures (default: 443).
    #[arg(long, value_name = "port", allow_hyphen_values = true, value_parser = clap::value_parser!(u16).range(1..))]
    tproxy_dport: Option<u16>,
    /// Install nft/ip-rule firewall rules on start and remove them on exit (requires root or CAP_NET_ADMIN; off by default).
    #[arg(long)]
    setup_redirect: bool,
    /// UID whose outbound traffic is NOT redirected (default: geteuid() of the process).
    #[arg(long, value_name = "uid", allow_hyphen_values = true, value_parser = clap::value_parser!(u32).range(0..=i32::MAX as i64))]
    tproxy_uid: Option<u32>,
    /// (not available in this build) Terminate TLS on captured flows (HTTPS MITM) and re-encrypt to the origin. Requires --tproxy and --ca-cert/--ca-key. Off by default.
    #[arg(long)]
    mitm: bool,
    /// (accepted, no effect without --mitm) Signing CA certificate (PEM) used to forge per-host leaf certs (required with --mitm).
    #[arg(long, value_name = "pem", allow_hyphen_values = true)]
    ca_cert: Option<String>,
    /// (accepted, no effect without --mitm) Signing CA private key (PEM) (required with --mitm).
    #[arg(long, value_name = "pem", allow_hyphen_values = true)]
    ca_key: Option<String>,
    /// (accepted, no effect without --mitm) Leave the named host OPAQUE (no MITM; pass TLS through). Repeatable. Leading-dot suffix matches subdomains (e.g. .example.com).
    #[arg(long, value_name = "pattern", allow_hyphen_values = true)]
    ignore_host: Vec<String>,
    /// (accepted, no effect without --mitm) Comma-separated form of --ignore-host (union with repeated --ignore-host and [Mitm] IgnoreHosts).
    #[arg(long, value_name = "a,b,c", allow_hyphen_values = true)]
    ignore_hosts: Vec<String>,
}

/// spec §6.4: parse argv (argv[0] included) and classify every flag per the SP1 table.
pub fn parse(argv: &[&str]) -> Result<Resolved, Exit> {
    let cli = Cli::try_parse_from(argv).map_err(|e| Exit {
        code: e.exit_code(),
        message: e.render().to_string(),
    })?;
    match cli.cmd {
        Cmd::Version => Err(Exit {
            code: 0,
            message: format!("mqproxy {}\n", env!("CARGO_PKG_VERSION")),
        }),
        Cmd::Server(a) => {
            let f = config::load(a.config.as_deref(), true)?;
            server(a, f).map_err(|m| usage_error("server", m))
        }
        Cmd::Client(a) => {
            let f = config::load(a.config.as_deref(), false)?;
            client(a, f).map_err(|m| usage_error("client", m))
        }
    }
}

/// Exit 2 with the message and the subcommand's usage, like clap's own errors.
fn usage_error(sub: &str, msg: String) -> Exit {
    let mut cmd = Cli::command();
    cmd.build();
    let sub = cmd.find_subcommand_mut(sub).expect("known subcommand");
    let e = sub.error(ErrorKind::ValueValidation, msg);
    Exit {
        code: 2,
        message: e.render().to_string(),
    }
}

fn unavailable(flag: &str) -> String {
    format!("{flag} is not available in this build")
}

// spec §6.4: each value below is `CLI.or(file)`, then the C default.
fn server(a: ServerArgs, f: FileConfig) -> Result<Resolved, String> {
    // spec §6.4 table: startup error, exit 2 (an INI bool only when true).
    if a.origin_ca.is_some() || f.origin_ca.is_some() {
        return Err(unavailable("--origin-ca ([Gateway] OriginCA)"));
    }
    if a.masquerade || f.masquerade {
        return Err(unavailable("--masquerade ([Gateway] Masquerade)"));
    }
    if a.request_metrics || f.request_metrics {
        return Err(unavailable("--request-metrics ([Metrics] PerRequest)"));
    }
    // Accepted, no effect: --no-gateway, --no-udp, --udp-idle-timeout (validated only).
    let _ = (a.no_gateway, a.no_udp, a.udp_idle_timeout);
    let mut warnings = f.warnings;
    // Warning, ignored: the feature was removed.
    if a.cache_max_bytes.or(f.cache_max_bytes).is_some() {
        warnings.push(
            "--cache-max-bytes ([Gateway] CacheMaxBytes) is ignored: the origin response cache was removed"
                .into(),
        );
    }
    let cc = cc(a.cc.or(f.cc).as_deref())?;
    let scheduler = scheduler(a.scheduler.or(f.scheduler).as_deref())?;
    let listen = a.listen.or(f.listen).ok_or("missing required --listen")?;
    let token = a.token.or(f.token).ok_or("missing required --token")?;
    let (Some(cert), Some(key)) = (
        a.cert.or(f.cert).filter(|s| !s.is_empty()),
        a.key.or(f.key).filter(|s| !s.is_empty()),
    ) else {
        return Err("--cert and --key are required".into());
    };
    let listen = ip_port("--listen", &listen)?;
    Ok(Resolved {
        mode: Mode::Server(Server {
            config: ServerConfig {
                token,
                metrics_interval: metrics_interval(a.metrics_interval, f.metrics_interval),
                ..ServerConfig::default()
            },
            listen,
            cert: cert.into(),
            key: key.into(),
            max_conns: a.max_conns.or(f.max_conns).unwrap_or(16), // C default
        }),
        config: a.config,
        qlog: a.qlog.or(f.qlog),
        cc,
        scheduler,
        warnings,
        // spec §6.4: C has both default-on; SP1 has neither (Task 9.3 logs this).
        startup_lines: vec![
            "HTTP gateway and UDP relay are not available in this build; serving the TCP proxy only"
                .into(),
        ],
    })
}

fn client(a: ClientArgs, f: FileConfig) -> Result<Resolved, String> {
    // spec §6.4 table: startup error, exit 2 (an INI bool only when true).
    if a.gateway.is_some() || f.gateway.is_some() {
        return Err(unavailable("--gateway ([Ingress] Gateway)"));
    }
    if a.mitm || f.mitm {
        return Err(unavailable("--mitm ([Mitm] Enabled)"));
    }
    // Accepted, no effect (C accepts them without --mitm).
    let _ = (a.ca_cert, a.ca_key, a.ignore_host, a.ignore_hosts);
    let cc = cc(a.cc.or(f.cc).as_deref())?;
    let scheduler = scheduler(a.scheduler.or(f.scheduler).as_deref())?;
    let tproxy_mode = match a.tproxy_mode.or(f.tproxy_mode).as_deref() {
        None | Some("redirect") => ListenKind::Redirect,
        Some("tproxy") => ListenKind::Tproxy,
        Some(m) => return Err(format!("invalid --tproxy-mode '{m}' (redirect|tproxy)")),
    };
    let server = a.server.or(f.server).ok_or("missing required --server")?;
    let token = a.token.or(f.token).ok_or("missing required --token")?;
    let socks5 = a.socks5.or(f.socks5);
    let http_connect = a.http_connect.or(f.http_connect);
    let tproxy = a.tproxy.or(f.tproxy);
    if socks5.is_none() && http_connect.is_none() && tproxy.is_none() {
        return Err(
            "at least one ingress is required (--socks5, --http-connect, or --tproxy)".into(),
        );
    }
    let opt = |flag, s: Option<String>| s.map(|s| ip_port(flag, &s)).transpose();
    let mut warnings = f.warnings;
    let mut paths = Vec::new();
    // spec §6.4: file entries first, then the CLI's.
    for p in f.paths.into_iter().chain(a.path) {
        if paths.len() == MAX_PATHS {
            warnings.push(format!(
                "too many paths (--path / [Multipath] Path, max {MAX_PATHS}); ignoring {p}"
            ));
            continue;
        }
        paths.push(
            p.parse::<IpAddr>()
                .map_err(|_| format!("invalid --path address: {p}"))?,
        );
    }
    // C default 30; 0 disables the idle timeout (and so the PINGs).
    let ka = a.keepalive_idle.or(f.keepalive_idle).unwrap_or(30);
    let keepalive_idle = (ka > 0).then(|| Duration::from_secs(ka));
    if (1..=XQUIC_PING_SECS).contains(&ka) {
        warnings.push(format!(
            "--keepalive-idle {} is not useful: xquic's client PING interval is fixed at \
             {XQUIC_PING_SECS} s, so an idle timeout of {XQUIC_PING_SECS} s or less still closes idle connections",
            ka
        ));
    }
    Ok(Resolved {
        mode: Mode::Client(Client {
            config: ClientConfig {
                server: ip_port("--server", &server)?,
                paths,
                scheduler,
                keepalive_idle,
                client_id: a
                    .client_id
                    .or(f.client_id)
                    .unwrap_or_else(|| "mqproxy".into()),
                token,
                // The last of --reconnect/--no-reconnect wins; neither → the file.
                reconnect: !a.no_reconnect && (a.reconnect || f.reconnect.unwrap_or(true)),
                reconnect_max_backoff: Duration::from_secs(
                    a.reconnect_max_backoff
                        .or(f.reconnect_max_backoff)
                        .unwrap_or(30),
                ),
                metrics_interval: metrics_interval(a.metrics_interval, f.metrics_interval),
                ..ClientConfig::default()
            },
            socks5: opt("--socks5", socks5)?,
            http_connect: opt("--http-connect", http_connect)?,
            tproxy: opt("--tproxy", tproxy)?,
            tproxy_mode,
            // C defaults: fwmark 1, table 100, dport 443, uid = geteuid().
            tproxy_fwmark: a.tproxy_fwmark.or(f.tproxy_fwmark).unwrap_or(1),
            tproxy_table: a.tproxy_table.or(f.tproxy_table).unwrap_or(100),
            tproxy_dport: a.tproxy_dport.or(f.tproxy_dport).unwrap_or(443),
            setup_redirect: a.setup_redirect || f.setup_redirect,
            tproxy_uid: a
                .tproxy_uid
                .or(f.tproxy_uid)
                .unwrap_or_else(mq_linux::geteuid),
        }),
        config: a.config,
        qlog: a.qlog.or(f.qlog),
        cc,
        scheduler,
        warnings,
        startup_lines: Vec::new(),
    })
}

/// `--metrics-interval`, else the file's `[Metrics] Interval` (0 = off, as in C).
fn metrics_interval(cli: Option<u64>, file: Option<u64>) -> Option<Duration> {
    cli.or(file.filter(|&s| s > 0)).map(Duration::from_secs)
}

/// C `mq_cc_from_string`: exact, case-sensitive.
pub fn cc(s: Option<&str>) -> Result<CongestionControl, String> {
    match s {
        None | Some("bbr") => Ok(CongestionControl::Bbr),
        Some("bbr2") => Ok(CongestionControl::Bbr2),
        Some("cubic") => Ok(CongestionControl::Cubic),
        Some(s) => Err(format!("invalid --cc '{s}' (bbr2|bbr|cubic)")),
    }
}

/// C `mq_sched_from_string`: exact, case-sensitive.
pub fn scheduler(s: Option<&str>) -> Result<Scheduler, String> {
    match s {
        None | Some("minrtt") => Ok(Scheduler::MinRtt),
        Some("backup") => Ok(Scheduler::Backup),
        Some("wlb") => Ok(Scheduler::Wlb),
        Some(s) => Err(format!("invalid --scheduler '{s}' (minrtt|backup|wlb)")),
    }
}

/// C `parse_ip_port`: `[v6]:port`, or `ip:port` split at the last ':'; port 1..=65535.
pub fn ip_port(flag: &str, s: &str) -> Result<SocketAddr, String> {
    let split = match s.strip_prefix('[') {
        Some(rest) => rest.split_once("]:"),
        None => s.rsplit_once(':'),
    };
    split
        .and_then(|(ip, port)| {
            let port = port.parse::<u16>().ok().filter(|&p| p != 0)?;
            Some(SocketAddr::new(ip.parse().ok()?, port))
        })
        .ok_or_else(|| format!("invalid {flag} address: {s}"))
}
