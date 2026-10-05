//! adoption spec §3 "Raw-H3 backend": ALPN `h3` over raw xquic streams.
mod common;

use common::lockstep::{cfg, server_role};
use common::pair::{MS, Opts, Pair, new_streams, read_all, send};
use mq_transport_api::{
    ConnProto, Error, Event, H3Backend, Role, StreamKind, TransportConfig, TransportOps,
};

fn raw_h3_cfg(role: Role) -> TransportConfig {
    TransportConfig {
        h3: true,
        h3_backend: H3Backend::Raw,
        qlog: None,
        ..cfg(role)
    }
}

fn h3raw_opts() -> Opts {
    Opts {
        server: raw_h3_cfg(server_role()),
        client: raw_h3_cfg(Role::Client),
        proto: ConnProto::H3,
        ..Opts::default()
    }
}

#[test]
fn raw_h3_conn_establishes() {
    let p = Pair::with(h3raw_opts());
    assert!(
        p.sev.contains(&Event::NewConn(p.srv_conn, ConnProto::H3)),
        "{:?}",
        p.sev
    );
}

#[test]
fn raw_h3_bidi_echo() {
    let mut p = Pair::with(h3raw_opts());
    let cs = p.open();
    let data: Vec<u8> = (0..64 * 1024).map(|i| (i * 31 + 7) as u8).collect();
    let (mut off, mut fin_sent) = (0, false);
    let mut ss = None;
    let (mut rx, mut fin) = (Vec::new(), false);
    let done = p.pump_until(MS, 5_000, |p| {
        let now = p.now;
        if !fin_sent && let Ok(n) = send(&p.client, now, cs, data[off..].to_vec(), true) {
            off += n;
            fin_sent = off == data.len();
        }
        p.exchange();
        if ss.is_none() {
            ss = new_streams(&p.sev).first().copied();
        }
        if let Some((s, _)) = ss
            && !fin
        {
            let (b, f) = read_all(&p.server, now, s).expect("server read");
            rx.extend(b);
            fin = f;
        }
        fin
    });
    assert!(done, "no FIN after {} bytes", rx.len());
    assert_eq!(rx, data);
    let (_, info) = ss.unwrap();
    assert_eq!(info.kind, StreamKind::Bidi);
    assert_eq!(info.quic_id, 0);
    assert_eq!(info.conn, p.srv_conn);
}

#[test]
fn raw_h3_rejects_open_h3_request() {
    let p = Pair::with(h3raw_opts());
    let c = p.conn;
    let r = p
        .client
        .call(p.now, move |t, now| t.open_h3_request(now, c));
    assert_eq!(r.err(), Some(Error::Other));
}

#[test]
fn raw_alpn_alongside_raw_h3() {
    let p = Pair::with(Opts {
        client: cfg(Role::Client),
        proto: ConnProto::Raw,
        ..h3raw_opts()
    });
    assert!(
        p.sev.contains(&Event::NewConn(p.srv_conn, ConnProto::Raw)),
        "{:?}",
        p.sev
    );
}
