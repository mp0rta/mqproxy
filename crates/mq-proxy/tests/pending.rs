//! spec §6.2 "Pending requests (before auth)".

use mq_proxy::client::pending::{
    CapExceeded, Full, IngressKind, MAX_PENDING, PREREAD_CAP, Pending, PendingOpen,
};
use mq_proxy::config::ClientConfig;
use mq_runtime::{Host, Target};
use mq_transport_api::Time;
use mq_wire::frames::TcpErr;
use std::net::Ipv4Addr;
use std::time::Duration;

// `TcpId` is shard-allocated only; the queue is generic over the socket key, so tests use u32.
fn open(tcp: u32, kind: IngressKind, at: Time) -> PendingOpen<u32> {
    PendingOpen {
        tcp,
        target: Target {
            host: Host::Ip(Ipv4Addr::new(1, 2, 3, 4).into()),
            port: 80,
        },
        preread: Vec::new(),
        read_eof: false,
        kind,
        enqueued_at: at,
    }
}

fn queue() -> Pending<u32> {
    Pending::new(ClientConfig::default().pending_deadline)
}

#[test]
fn max_256_then_conn_refused_reply() {
    assert_eq!(MAX_PENDING, 256);
    let mut q = queue();
    for i in 0..256 {
        q.push(open(i, IngressKind::Socks5, Time::ZERO)).unwrap();
    }
    let Err(Full(rejected)) = q.push(open(256, IngressKind::Socks5, Time::ZERO)) else {
        panic!("257th push accepted");
    };
    assert_eq!(rejected.tcp, 256);
    assert_eq!(q.len(), 256);
    // The caller answers the rejected request with CONN_REFUSED (SOCKS5 REP 0x05).
    let reply = rejected.kind.error_reply(TcpErr::ConnRefused).unwrap();
    assert_eq!(reply[1], 0x05);
    let http = IngressKind::HttpConnect
        .error_reply(TcpErr::ConnRefused)
        .unwrap();
    assert!(http.starts_with(b"HTTP/1.1 502 "));
    assert_eq!(
        IngressKind::Transparent.error_reply(TcpErr::ConnRefused),
        None
    );
}

#[test]
fn deadline_30s_replies_timeout_and_closes() {
    assert_eq!(
        ClientConfig::default().pending_deadline,
        Duration::from_secs(30)
    );
    let mut q = queue();
    let t0 = Time::ZERO;
    q.push(open(1, IngressKind::Socks5, t0)).unwrap();
    q.push(open(
        2,
        IngressKind::HttpConnect,
        t0 + Duration::from_secs(5),
    ))
    .unwrap();

    assert!(q.expire(t0 + Duration::from_millis(29_999)).is_empty());
    let gone = q.expire(t0 + Duration::from_secs(30));
    assert_eq!(gone.iter().map(|o| o.tcp).collect::<Vec<_>>(), [1]);
    assert_eq!(gone[0].kind.error_reply(TcpErr::Timeout).unwrap()[1], 0x06);
    assert_eq!(q.len(), 1);

    let gone = q.expire(t0 + Duration::from_secs(35));
    assert_eq!(gone[0].tcp, 2);
    let http = gone[0].kind.error_reply(TcpErr::Timeout).unwrap();
    assert!(http.starts_with(b"HTTP/1.1 504 "));
    assert!(q.is_empty());
}

#[test]
fn error_drops_pending_and_read_eof_keeps() {
    let mut q = queue();
    q.push(open(1, IngressKind::Socks5, Time::ZERO)).unwrap();
    q.push(open(2, IngressKind::Socks5, Time::ZERO)).unwrap();

    assert!(q.set_read_eof(&2));
    assert_eq!(q.remove(&1).map(|o| o.tcp), Some(1));
    assert!(q.remove(&1).is_none());
    assert!(!q.set_read_eof(&1));

    let rest = q.drain();
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].tcp, 2);
    assert!(rest[0].read_eof);
}

#[test]
fn kept_across_reconnect() {
    // The queue is owned by the client, not the connection: a tunnel loss touches nothing,
    // and after the next auth success the entries drain in arrival order.
    let mut q = queue();
    for i in 0..3 {
        q.push(open(i, IngressKind::Transparent, Time::ZERO))
            .unwrap();
    }
    assert!(q.expire(Time::ZERO + Duration::from_secs(10)).is_empty());
    assert_eq!(q.len(), 3);
    let order: Vec<u32> = q.drain().into_iter().map(|o| o.tcp).collect();
    assert_eq!(order, [0, 1, 2]);
    assert!(q.is_empty());
}

#[test]
fn preread_cap_8k() {
    assert_eq!(PREREAD_CAP, 8 * 1024);
    let mut q = queue();
    q.push(open(1, IngressKind::Socks5, Time::ZERO)).unwrap();
    q.push_preread(&1, &[0xAA; 8000]).unwrap();
    q.push_preread(&1, &[0xBB; 192]).unwrap();
    assert_eq!(q.push_preread(&1, &[0xCC]), Err(CapExceeded));
    assert_eq!(q.push_preread(&9, b"x"), Err(CapExceeded));
    let o = q.drain().pop().unwrap();
    assert_eq!(o.preread.len(), 8192);
    assert_eq!(o.preread[8191], 0xBB);
}
