//! spec §5.3 "Setup", §6.4, §6.6: `run_server` / `run_client` build the
//! transport, the driver and the shard in C `cmd_server` / `cmd_client` order,
//! run the loop and return the exit status (1 for cert/bind/qlog failures).

use crate::cli::{Client as ClientArgs, Mode, Resolved, Server as ServerArgs};
use crate::setup_redirect;
use mq_proxy::{client, client::Client, server::Server};
use mq_runtime::driver::{Driver, DriverConfig, StdResolver};
use mq_runtime::{App, ListenKind, Shard};
use mq_transport::Transport;
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

/// The transport (cert/key loaded here), then `--qlog`.
fn transport(r: &Resolved, role: Role, max_conns: u32, err: String) -> Result<Transport, String> {
    let name = if matches!(role, Role::Client) {
        "client"
    } else {
        "server"
    };
    let mut t = Transport::new(TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns,
        scheduler: r.scheduler,
        cc: r.cc,
        realtime_offset_us: realtime_offset_us(),
    })
    .map_err(|e| format!("{err} ({e:?})"))?;
    if let Some(dir) = &r.qlog {
        let p = t
            .enable_qlog(dir)
            .map_err(|e| format!("failed to enable qlog in {} ({e:?})", dir.display()))?;
        log::info!("{name} qlog -> {}", p.display());
    }
    Ok(t)
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
fn finish<A: App>(d: Driver, shard: Shard<Transport, A>) -> i32 {
    let (code, shard) = d.run(shard);
    shard.into_transport().close(now());
    code
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
    let shard = Shard::new(t, Server::new(s.config.clone()), udp.local_addr(), seed());
    d.attach_primary_udp(udp, shard.primary_udp())
        .expect("first attach");
    ready(
        r,
        format!(
            "mqproxy server listening on {} (cc={}, sched={}, gateway=off, udp=off)",
            s.listen,
            cc_name(r.cc),
            sched_name(r.scheduler)
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
    let rules: Rc<Cell<Option<setup_redirect::Opts>>> = Rc::default();
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
        ingress += &format!(" tproxy={}:{port}({mode})", addr.ip());
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
            rules.set(Some(o));
            let hook = rules.clone();
            d.on_shutdown(move || {
                if let Some(o) = hook.take() {
                    setup_redirect::uninstall(&o);
                }
            });
        }
    }
    ready(
        r,
        format!(
            "mqproxy client: server={}{ingress} (bind {primary_ip}, cc={}, sched={})",
            c.config.server,
            cc_name(r.cc),
            sched_name(r.scheduler)
        ),
    );
    let code = finish(d, shard);
    // spec §6.6: the hook removes the rules in the signal's loop iteration; an
    // exit without a signal removes them here.
    if let Some(o) = rules.take() {
        setup_redirect::uninstall(&o);
    }
    Ok(code)
}
