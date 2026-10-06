//! spec §5.3 "Setup", §6.4, §6.6: `run_server` / `run_client` build the
//! transport, the driver and the shard in C `cmd_server` / `cmd_client` order,
//! run the loop and return the exit status (1 for cert/bind/qlog/origin-TLS failures).

use crate::cli::{self, Client as ClientArgs, Mode, Resolved, Server as ServerArgs};
use crate::setup_redirect;
use mq_h3::H3Wire;
use mq_proxy::server::origin::{build_client_config, native_roots};
use mq_proxy::{client, client::Client, server::Server};
use mq_runtime::driver::{Driver, DriverConfig, StdResolver};
use mq_runtime::{App, ListenKind, Shard};
use mq_transport::{Error, Transport};
use mq_transport_api::{CongestionControl, Role, Scheduler, Time, TransportConfig};
use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// spec §6.4: a startup failure after parsing.
const FAIL: i32 = 1;

pub fn run(r: Resolved) -> i32 {
    let res = match &r.mode {
        Mode::Server(s) => run_server(&r, s),
        Mode::Client(c) => run_client(&r, c),
    };
    res.unwrap_or_else(|msg| {
        log::error!("{msg}");
        FAIL
    })
}

fn cc_name(c: CongestionControl) -> &'static str {
    match c {
        CongestionControl::Bbr => "bbr",
        CongestionControl::Bbr2 => "bbr2",
        CongestionControl::Cubic => "cubic",
    }
}

fn sched_name(s: Scheduler) -> &'static str {
    match s {
        Scheduler::MinRtt => "minrtt",
        Scheduler::Backup => "backup",
        Scheduler::Wlb => "wlb",
    }
}

fn now() -> Time {
    Time::from_micros(mq_linux::now_monotonic_micros())
}

/// spec §4.3: wall clock minus monotonic, fixed at creation.
fn realtime_offset_us() -> i64 {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as i64);
    wall - now().as_micros() as i64
}

/// C `getpid() ^ time(NULL)`.
fn seed() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    u64::from(std::process::id()) ^ secs
}

/// The transport (cert/key loaded here, H3 per `cli::wants_h3`), then `--qlog`.
fn transport(
    r: &Resolved,
    role: Role,
    max_conns: u32,
    err: String,
) -> Result<H3Wire<Transport>, String> {
    let name = if matches!(role, Role::Client) {
        "client"
    } else {
        "server"
    };
    let t = Transport::new(TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns,
        scheduler: r.scheduler,
        cc: r.cc,
        realtime_offset_us: realtime_offset_us(),
        h3: cli::wants_h3(r),
        qlog: r.qlog.clone(),
    })
    .map_err(|e| match (&e, &r.qlog) {
        (Error::Qlog(_), Some(dir)) => {
            format!("failed to enable qlog in {} ({e:?})", dir.display())
        }
        _ => format!("{err} ({e:?})"),
    })?;
    if let Some(dir) = &r.qlog {
        log::info!(
            "{name} qlog -> {}",
            dir.join(format!("{name}.qlog")).display()
        );
    }
    Ok(H3Wire::new(t))
}

fn driver() -> Result<Driver, String> {
    Driver::new(DriverConfig {
        resolver: Arc::new(StdResolver),
        emfile_retry: Duration::from_millis(100),
        shutdown_cap: Duration::from_secs(2),
        install_signal_handlers: true,
    })
    .map_err(|e| format!("failed to create runtime ({e})"))
}

/// The startup INFO lines, logged once the signal handlers are in (as C).
fn ready(r: &Resolved, line: String) {
    for l in &r.startup_lines {
        log::info!("{l}");
    }
    log::info!("{line}");
}

/// spec §5.3: `run` → `into_transport` → `Transport::close` with the last `now`.
fn finish<A: App>(d: Driver, shard: Shard<H3Wire<Transport>, A>) -> i32 {
    let (code, shard) = d.run(shard);
    shard.into_transport().into_inner().close(now());
    code
}

/// spec §6.6: the installed `--setup-redirect` rules, removed at most once —
/// by the shutdown hook (sharing `opts`), or on drop: a normal return or a
/// panic unwinding past `finish`.
struct Rules {
    opts: Rc<Cell<Option<setup_redirect::Opts>>>,
    uninstall: fn(&setup_redirect::Opts),
}

impl Rules {
    fn remove(opts: &Cell<Option<setup_redirect::Opts>>, uninstall: fn(&setup_redirect::Opts)) {
        if let Some(o) = opts.take() {
            uninstall(&o);
        }
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        Rules::remove(&self.opts, self.uninstall);
    }
}

fn run_server(r: &Resolved, s: &ServerArgs) -> Result<i32, String> {
    let t = transport(
        r,
        Role::Server {
            cert: s.cert.clone(),
            key: s.key.clone(),
        },
        s.max_conns,
        format!(
            "failed to create server transport (cert={} key={})",
            s.cert.display(),
            s.key.display()
        ),
    )?;
    let mut d = driver()?;
    let udp = d
        .bind_udp(s.listen)
        .map_err(|e| format!("failed to bind listen path {} ({e})", s.listen))?;
    // spec §7.8: the origin TLS config; no usable roots is a startup error.
    let app = match &s.config.gateway {
        Some(g) => {
            let tls = build_client_config(g.origin_ca.as_deref(), &native_roots).map_err(|e| {
                // C's line, plus the cause (as the transport's).
                let ca = g.origin_ca.as_deref().map_or("(system)".into(), |p| p.display().to_string());
                format!(
                    "failed to create HTTP gateway server (origin_ca={ca}, connect_timeout={}s) ({e})",
                    g.origin_connect_timeout.as_secs()
                )
            })?;
            Server::with_gateway(s.config.clone(), tls)
        }
        None => Server::new(s.config.clone()),
    };
    let shard = Shard::new(t, app, udp.local_addr(), seed());
    d.attach_primary_udp(udp, shard.primary_udp())
        .expect("first attach");
    ready(
        r,
        format!(
            "mqproxy server listening on {} (cc={}, sched={}, gateway={}, udp={}, udp-idle={}s)",
            s.listen,
            cc_name(r.cc),
            sched_name(r.scheduler),
            if s.config.gateway.is_some() {
                "on"
            } else {
                "off"
            },
            if s.config.udp_enabled { "on" } else { "off" },
            s.config.udp_idle_timeout.as_secs()
        ),
    );
    Ok(finish(d, shard))
}

fn run_client(r: &Resolved, c: &ClientArgs) -> Result<i32, String> {
    let t = transport(
        r,
        Role::Client,
        0,
        "failed to create client transport".into(),
    )?;
    let mut d = driver()?;
    // C: the first --path is the primary bind, else 0.0.0.0 with an ephemeral port.
    let primary_ip = c
        .config
        .paths
        .first()
        .copied()
        .unwrap_or(Ipv4Addr::UNSPECIFIED.into());
    let udp = d
        .bind_udp(SocketAddr::new(primary_ip, 0))
        .map_err(|e| format!("failed to bind primary path {primary_ip} ({e})"))?;
    let mut shard = Shard::new(t, Client::new(c.config.clone()), udp.local_addr(), seed());
    d.attach_primary_udp(udp, shard.primary_udp())
        .expect("first attach");

    let mut ingress = String::new();
    let rules = Rules {
        opts: Rc::default(),
        uninstall: setup_redirect::uninstall,
    };
    let plain = [
        (c.socks5, client::SOCKS5, "SOCKS5", "socks5"),
        (
            c.http_connect,
            client::HTTP_CONNECT,
            "HTTP CONNECT",
            "http-connect",
        ),
    ];
    for (addr, tag, what, key) in plain {
        let Some(addr) = addr else { continue };
        let l = d
            .listen(addr, ListenKind::Plain)
            .map_err(|e| format!("failed to bind {what} listener on {addr} ({e})"))?;
        d.attach_listener(l, shard.add_listener(tag));
        ingress += &format!(" {key}={addr}");
    }
    // C binds tproxy (and installs its rules) before the fetch listener, but
    // logs the ingress list as socks5, http-connect, gateway, tproxy.
    let mut tproxy = String::new();
    if let Some(addr) = c.tproxy {
        let l = d
            .listen(addr, c.tproxy_mode)
            .map_err(|e| format!("failed to bind tproxy listener on {addr} ({e})"))?;
        let port = l.local_addr().port();
        d.attach_listener(l, shard.add_listener(client::TRANSPARENT));
        let mode = if c.tproxy_mode == ListenKind::Tproxy {
            "tproxy"
        } else {
            "redirect"
        };
        tproxy = format!(" tproxy={}:{port}({mode})", addr.ip());
        if c.setup_redirect {
            let o = setup_redirect::Opts {
                mode: c.tproxy_mode,
                listener_port: port,
                dport: c.tproxy_dport,
                uid: c.tproxy_uid,
                fwmark: c.tproxy_fwmark,
                table: c.tproxy_table,
            };
            // spec §6.4: a failed install is a warning, not an error.
            if !setup_redirect::install(&o) {
                log::warn!("tproxy: firewall setup failed (rules may be partial)");
            }
            rules.opts.set(Some(o));
            let (hook, f) = (rules.opts.clone(), rules.uninstall);
            d.on_shutdown(move || Rules::remove(&hook, f));
        }
    }
    if let Some(addr) = c.config.gateway {
        let l = d
            .listen(addr, ListenKind::Plain)
            .map_err(|e| format!("failed to bind gateway fetch listener on {addr} ({e})"))?;
        d.attach_listener(l, shard.add_listener(client::FETCH));
        ingress += &format!(" gateway={addr}");
    }
    ingress += &tproxy;
    ready(
        r,
        format!(
            "mqproxy client: server={}{ingress} (bind {primary_ip}, cc={}, sched={})",
            c.config.server,
            cc_name(r.cc),
            sched_name(r.scheduler)
        ),
    );
    // spec §6.6: the hook removes the rules in the signal's loop iteration; an
    // exit without a signal (or a panic) removes them when `rules` drops.
    Ok(finish(d, shard))
}

#[cfg(test)]
mod tests {
    use super::*;

    thread_local!(static CALLS: Cell<u32> = const { Cell::new(0) });

    fn count(_: &setup_redirect::Opts) {
        CALLS.with(|c| c.set(c.get() + 1));
    }

    fn rules() -> Rules {
        Rules {
            opts: Rc::new(Cell::new(Some(setup_redirect::Opts {
                mode: ListenKind::Redirect,
                listener_port: 1,
                dport: 443,
                uid: 0,
                fwmark: 1,
                table: 100,
            }))),
            uninstall: count,
        }
    }

    #[test]
    fn rules_removed_once_by_hook_then_drop() {
        CALLS.with(|c| c.set(0));
        let r = rules();
        let hook = r.opts.clone();
        Rules::remove(&hook, r.uninstall); // the shutdown hook
        drop(r);
        assert_eq!(CALLS.with(Cell::get), 1);
    }

    #[test]
    fn rules_removed_on_unwind() {
        CALLS.with(|c| c.set(0));
        let r = std::panic::catch_unwind(|| {
            let _r = rules();
            panic!("boom");
        });
        assert!(r.is_err());
        assert_eq!(CALLS.with(Cell::get), 1);
    }
}
