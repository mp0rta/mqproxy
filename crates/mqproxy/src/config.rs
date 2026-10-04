//! spec §6.4 "Config file": C `mq_config_load` — the typed values an INI file
//! sets. `cli` layers the command line on top (defaults < file < CLI). Text
//! values (`CC`, `Scheduler`, addresses, `[Ingress] Mode`, `Path`) are kept as
//! text and validated by `cli` at startup, exactly like the flag values.

use crate::cli::Exit;
use crate::ini::{self, Line};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// C `parse_section` names (compared case-insensitively).
const SECTIONS: &[&str] = &[
    "Interface",
    "Server",
    "TLS",
    "Auth",
    "Multipath",
    "Gateway",
    "UDP",
    "Ingress",
    "Metrics",
    "Log",
    "Mitm",
];

/// What the file set; `None`/`false`/empty = not set. Accepted-no-effect keys
/// (`[Mitm] CACert/CAKey/IgnoreHosts`) are recognised and dropped.
#[derive(Debug, Default)]
pub struct FileConfig {
    pub warnings: Vec<String>,
    // shared
    pub token: Option<String>,
    pub cc: Option<String>,
    pub scheduler: Option<String>,
    pub qlog: Option<PathBuf>,
    /// 0 = off, as in C.
    pub metrics_interval: Option<u64>,
    // server
    pub listen: Option<String>,
    pub max_conns: Option<u32>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub gateway_enabled: Option<bool>,
    pub origin_ca: Option<String>,
    pub masquerade: bool,
    pub cache_max_bytes: Option<u64>,
    pub request_metrics: bool,
    pub udp_enabled: Option<bool>,
    pub udp_idle_timeout: Option<u64>,
    // client
    pub server: Option<String>,
    pub client_id: Option<String>,
    pub socks5: Option<String>,
    pub http_connect: Option<String>,
    pub gateway: Option<String>,
    pub paths: Vec<String>,
    pub keepalive_idle: Option<u64>,
    pub reconnect: Option<bool>,
    pub reconnect_max_backoff: Option<u64>,
    pub tproxy: Option<String>,
    pub tproxy_mode: Option<String>,
    pub tproxy_fwmark: Option<u32>,
    pub tproxy_table: Option<u32>,
    pub tproxy_dport: Option<u16>,
    pub setup_redirect: bool,
    /// `SkipUid = -1` (C's "use geteuid()") is `None`.
    pub tproxy_uid: Option<u32>,
    pub mitm: bool,
}

/// C `parse_bool`: exact `true`, `yes`, `1`.
fn bool_(v: &str) -> bool {
    matches!(v, "true" | "yes" | "1")
}

/// spec §6.4: load `path` for the server (`server = true`) or the client. No
/// path → all unset. An unopenable file is a startup error (exit 2).
pub fn load(path: Option<&Path>, server: bool) -> Result<FileConfig, Exit> {
    let mut f = FileConfig::default();
    let Some(path) = path else { return Ok(f) };
    let text = std::fs::read(path).map_err(|e| Exit {
        code: 2,
        message: format!("error: config: cannot open '{}': {e}\n", path.display()),
    })?;
    // C `mq_config_perms_insecure`: any group/other bit.
    if std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0) {
        f.warnings.push(format!(
            "config {} is group/world-readable; chmod 0600 to protect the token",
            path.display()
        ));
    }
    let text = String::from_utf8_lossy(&text);
    let mut section = None;
    for (n, line) in ini::lines(&text) {
        let at = format!("{}:{n}", path.display());
        match line {
            Line::Malformed(m) => f.warnings.push(format!("{at}: {m}")),
            Line::Section(s) => {
                section = SECTIONS.iter().find(|x| x.eq_ignore_ascii_case(s)).copied();
                if section.is_none() {
                    f.warnings.push(format!("{at}: unknown section '{s}'"));
                }
            }
            Line::Kv(k, _) if section.is_none() => f
                .warnings
                .push(format!("{at}: key '{k}' outside any section")),
            Line::Kv(k, v) => {
                let sec = section.unwrap_or_default();
                let key = k.to_ascii_lowercase();
                if !f.set(&at, sec, &key, k, v, server) {
                    // Known to the other mode? (Probe on a scratch config.)
                    let other = FileConfig::default().set(&at, sec, &key, k, v, !server);
                    f.warnings.push(if other {
                        format!("{at}: key '{k}' in [{sec}] not valid for this mode; ignoring")
                    } else {
                        format!("{at}: unknown key '{k}' in [{sec}]")
                    });
                }
            }
        }
    }
    Ok(f)
}

impl FileConfig {
    /// C LONGV: an integer in `lo..=hi`, else warn and keep the previous value.
    fn num(&mut self, at: &str, k: &str, v: &str, lo: i64, hi: i64) -> Option<i64> {
        let n = v.parse::<i64>().ok().filter(|n| (lo..=hi).contains(n));
        if n.is_none() {
            self.warnings.push(format!(
                "{at}: invalid {k} '{v}'; keeping the previous value"
            ));
        }
        n
    }

    /// C `handle_kv`. `sec` is canonical, `key` lower-cased; `k` is the key as written.
    /// Returns false if the key is unknown for this mode.
    fn set(&mut self, at: &str, sec: &str, key: &str, k: &str, v: &str, server: bool) -> bool {
        let (s, c) = (server, !server);
        let text = || Some(v.to_string());
        const MAX: i64 = i64::MAX;
        match (sec, key) {
            ("Auth", "key") => self.token = text(),
            ("Multipath", "cc") => self.cc = text(),
            ("Multipath", "scheduler") => self.scheduler = text(),
            ("Log", "qlog") => self.qlog = Some(v.into()),
            ("Metrics", "interval") => {
                if let Some(n) = self.num(at, k, v, 0, MAX) {
                    self.metrics_interval = Some(n as u64);
                }
            }
            // server
            ("Interface", "listen") if s => self.listen = text(),
            ("Interface", "maxconns") if s => {
                if let Some(n) = self.num(at, k, v, 0, u32::MAX.into()) {
                    self.max_conns = Some(n as u32);
                }
            }
            ("TLS", "cert") if s => self.cert = text(),
            ("TLS", "key") if s => self.key = text(),
            ("Gateway", "originca") if s => self.origin_ca = text(),
            ("Gateway", "masquerade") if s => self.masquerade = bool_(v),
            ("Gateway", "cachemaxbytes") if s => {
                if let Some(n) = self.num(at, k, v, 0, MAX) {
                    self.cache_max_bytes = Some(n as u64);
                }
            }
            ("Metrics", "perrequest") if s => self.request_metrics = bool_(v),
            ("UDP", "enabled") if s => self.udp_enabled = Some(bool_(v)),
            ("UDP", "idletimeout") if s => {
                if let Some(n) = self.num(at, k, v, 1, MAX) {
                    self.udp_idle_timeout = Some(n as u64);
                }
            }
            ("Gateway", "enabled") if s => self.gateway_enabled = Some(bool_(v)),
            // client
            ("Server", "address") if c => self.server = text(),
            ("Server", "clientid") if c => self.client_id = text(),
            // `cli` appends the CLI's --path after these and caps the list at 8.
            ("Multipath", "path") if c => self.paths.push(v.into()),
            ("Interface", "keepaliveidle") if c => {
                if let Some(n) = self.num(at, k, v, 0, MAX) {
                    self.keepalive_idle = Some(n as u64);
                }
            }
            ("Interface", "reconnect") if c => self.reconnect = Some(bool_(v)),
            ("Interface", "reconnectmaxbackoff") if c => {
                if let Some(n) = self.num(at, k, v, 1, MAX) {
                    self.reconnect_max_backoff = Some(n as u64);
                }
            }
            ("Ingress", "socks5") if c => self.socks5 = text(),
            ("Ingress", "httpconnect") if c => self.http_connect = text(),
            ("Ingress", "gateway") if c => self.gateway = text(),
            ("Ingress", "tproxy") if c => self.tproxy = text(),
            ("Ingress", "mode") if c => self.tproxy_mode = text(),
            ("Ingress", "fwmark") if c => {
                if let Some(n) = self.num(at, k, v, 1, i32::MAX.into()) {
                    self.tproxy_fwmark = Some(n as u32);
                }
            }
            ("Ingress", "table") if c => {
                if let Some(n) = self.num(at, k, v, 1, 65535) {
                    self.tproxy_table = Some(n as u32);
                }
            }
            ("Ingress", "dport") if c => {
                if let Some(n) = self.num(at, k, v, 1, 65535) {
                    self.tproxy_dport = Some(n as u16);
                }
            }
            ("Ingress", "setupredirect") if c => self.setup_redirect = bool_(v),
            ("Ingress", "skipuid") if c => {
                if let Some(n) = self.num(at, k, v, -1, i32::MAX.into()) {
                    self.tproxy_uid = u32::try_from(n).ok();
                }
            }
            ("Mitm", "enabled") if c => self.mitm = bool_(v),
            // Accepted, no effect without --mitm (as in C).
            ("Mitm", "cacert" | "cakey" | "ignorehosts") if c => {}
            _ => return false,
        }
        true
    }
}
