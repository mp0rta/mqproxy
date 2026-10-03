//! spec §7.2/§7.3/§7.6/§7.7: the origin bridge's dial, TLS handshake and
//! connect deadline, driven through `OriginHost` on a scripted shard.

mod origin_harness;

use mq_http::headers::HttpVer;
use mq_proxy::server::origin::host::BridgeEv;
use mq_proxy::server::origin::{OriginFailure, RecordState, TlsOutcome};
use mq_runtime::{DialError, Host, IoRequest, Target};
use mq_transport_api::H3ReqId;
use origin_harness::{OH, ORIGIN_CRT, ORIGIN_KEY, TlsPeer, cfg, get, tls};
use std::io;
use std::time::Duration;

fn oh() -> OH {
    OH::new(cfg(), tls())
}

/// The single event, a failure before the head.
fn failure(oh: &OH, h3: H3ReqId) -> OriginFailure {
    match &oh.events()[..] {
        [BridgeEv::Failure(x, f, false)] if *x == h3 => f.clone(),
        ev => panic!("want one failure of {h3:?}, got {ev:?}"),
    }
}

fn assert_connect_fail(f: &OriginFailure, curl: u32, status: u16, tls: TlsOutcome) {
    assert_eq!((f.curl, f.status, f.tls), (curl, status, tls), "{f:?}");
    assert_eq!(f.proto, None, "nothing negotiated");
    assert!(!f.upstream_protocol && !f.start_failed, "{f:?}");
}

#[test]
fn dial_err_mapping() {
    let rows = [
        (DialError::Dns, 6, 502),
        (DialError::Refused, 7, 502),
        (DialError::Other, 7, 502),
        (DialError::Timeout, 28, 504),
    ];
    for (e, curl, status) in rows {
        for (url, tls) in [
            ("http://o.test/", TlsOutcome::Na),
            ("https://o.test/", TlsOutcome::ConnectFail),
        ] {
            let mut oh = oh();
            let h3 = oh.start(get(url));
            let (op, target, deadline) = oh.dial().expect("a dial");
            assert_eq!(target.host, Host::Domain("o.test".into()));
            assert_eq!(
                deadline,
                Duration::from_secs(10),
                "DNS + connect under one deadline"
            );
            oh.dial_err(op, e);
            assert_connect_fail(&failure(&oh, h3), curl, status, tls);
            assert_eq!(oh.with_host(|h, _| h.origin().record_state(h3)), None);
        }
    }
    // The socket cap is §6.2's 502 origin-start-failed, not a §7.6 error.
    let mut oh = oh();
    let h3 = oh.start(get("https://o.test:8443/"));
    let (op, target, _) = oh.dial().unwrap();
    assert_eq!(target.port, 8443);
    oh.dial_err(op, DialError::Limit);
    let f = failure(&oh, h3);
    assert!(f.start_failed, "{f:?}");
    assert_eq!((f.status, f.tls, f.proto), (502, TlsOutcome::Na, None));
}

#[test]
fn tls_handshake_eof_is_35_at_once() {
    let mut oh = oh();
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    let tcp = oh.dial_ok(op);
    assert!(!oh.tcp_out_all(tcp).is_empty(), "the ClientHello went out");
    oh.tcp_eof(tcp);
    assert_connect_fail(&failure(&oh, h3), 35, 502, TlsOutcome::ConnectFail);
    assert!(oh.aborted(tcp), "class E′: tcp_abort");
    assert_eq!(oh.with_host(|h, _| h.origin().record_state(h3)), None);
    oh.advance(Duration::from_secs(10));
    assert_eq!(oh.events().len(), 1, "no curl:28 after the EOF");

    // A socket error mid-handshake: the same row.
    let mut oh = self::oh();
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    let tcp = oh.dial_ok(op);
    oh.tcp_error(tcp, io::ErrorKind::ConnectionReset);
    assert_connect_fail(&failure(&oh, h3), 35, 502, TlsOutcome::ConnectFail);
    oh.advance(Duration::from_secs(10));
    assert_eq!(oh.events().len(), 1);
}

#[test]
fn connect_deadline_covers_tls() {
    let mut oh = oh();
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    oh.advance(Duration::from_secs(3));
    let tcp = oh.dial_ok(op);
    let conn = oh
        .with_host(|h, _| h.origin().conn_of(h3))
        .expect("handshaking conn");
    oh.advance(Duration::from_millis(6_999));
    assert!(
        oh.events().is_empty(),
        "the deadline is absolute from the start"
    );
    assert_eq!(
        oh.with_host(|h, _| h.origin().record_state(h3)),
        Some(RecordState::Connecting)
    );
    oh.advance(Duration::from_millis(1));
    assert_connect_fail(&failure(&oh, h3), 28, 504, TlsOutcome::ConnectFail);
    assert!(oh.aborted(tcp), "class E′: tcp_abort");
    assert!(oh.with_host(|h, _| h.origin().pipe_dead(conn)));
    assert_eq!(oh.with_host(|h, _| h.origin().record_state(h3)), None);
}

#[test]
fn plain_http_connect_ms_is_dial_duration() {
    let mut oh = oh();
    let h3 = oh.start(get("http://127.0.0.1:8080/"));
    let (op, target, _) = oh.dial().unwrap();
    assert_eq!(
        target.host,
        Host::Ip([127, 0, 0, 1].into()),
        "an IP literal is not resolved"
    );
    assert_eq!(target.port, 8080);
    oh.advance(Duration::from_millis(250));
    oh.dial_ok(op);
    assert_eq!(
        oh.with_host(|h, _| h.origin().record_state(h3)),
        Some(RecordState::Assigned),
        "plain http: no TLS, the hyper handshake completes at once"
    );
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).unwrap();
    assert_eq!(oh.with_host(|h, _| h.origin().connect_ms(conn)), Some(250));
    assert!(
        oh.events().is_empty(),
        "the request is not sent here (Task 5.4)"
    );
}

#[test]
fn tls_handshake_assigns_with_connect_ms() {
    for (alpn, ver) in [
        (&[b"http/1.1" as &[u8]][..], HttpVer::Default),
        (&[b"h2" as &[u8], b"http/1.1"][..], HttpVer::Default),
        (&[b"h2" as &[u8], b"http/1.1"][..], HttpVer::H1),
    ] {
        let mut oh = oh();
        let mut spec = get("https://localhost/");
        spec.ver = ver;
        let h3 = oh.start(spec);
        let (op, _, _) = oh.dial().unwrap();
        oh.advance(Duration::from_millis(40));
        let tcp = oh.dial_ok(op);
        oh.advance(Duration::from_millis(60));
        let mut peer = TlsPeer::new(ORIGIN_CRT, ORIGIN_KEY, alpn);
        peer.pump(&mut oh, tcp);
        assert_eq!(
            oh.with_host(|h, _| h.origin().record_state(h3)),
            Some(RecordState::Assigned),
            "{alpn:?} {ver:?}"
        );
        let want: &[u8] = if alpn.len() == 2 && ver == HttpVer::Default {
            b"h2"
        } else {
            b"http/1.1"
        };
        assert_eq!(
            peer.conn.alpn_protocol(),
            Some(want),
            "the request's ALPN list"
        );
        let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).unwrap();
        assert_eq!(oh.with_host(|h, _| h.origin().connect_ms(conn)), Some(100));
        assert!(oh.events().is_empty());
    }
}

#[test]
fn tls_bad_cert_is_60_verify_fail() {
    let mut oh = oh();
    // The leaf is for localhost / 127.0.0.1 only.
    let h3 = oh.start(get("https://other.test/"));
    let (op, _, _) = oh.dial().unwrap();
    let tcp = oh.dial_ok(op);
    TlsPeer::h1().pump(&mut oh, tcp);
    assert_connect_fail(&failure(&oh, h3), 60, 502, TlsOutcome::VerifyFail);
    assert!(oh.aborted(tcp));
}

#[test]
fn invalid_servername_after_dial_is_6() {
    let mut oh = oh();
    let h3 = oh.start(get("https://a..b/"));
    let (op, target, _) = oh.dial().unwrap();
    assert_eq!(target.host, Host::Domain("a..b".into()), "dialled first");
    let tcp = oh.dial_ok(op);
    assert_connect_fail(&failure(&oh, h3), 6, 502, TlsOutcome::ConnectFail);
    assert!(oh.aborted(tcp), "class E′: tcp_abort");
}

#[test]
fn cancel_during_handshake_aborts_socket_class_d() {
    let mut oh = oh();
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    let tcp = oh.dial_ok(op);
    let conn = oh.with_host(|h, _| h.origin().conn_of(h3)).unwrap();
    oh.cancel(h3);
    assert!(oh.aborted(tcp), "class D: tcp_abort, never pooled");
    assert!(oh.with_host(|h, _| h.origin().pipe_dead(conn)));
    assert_eq!(oh.with_host(|h, _| h.origin().record_state(h3)), None);
    assert_eq!(oh.with_host(|h, _| h.origin().pool_len()), 0);
    oh.advance(Duration::from_secs(10));
    assert!(
        oh.events().is_empty(),
        "a cancelled requester gets no event"
    );
}

#[test]
fn cancel_while_dialing_cancels_dial() {
    let mut oh = oh();
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    oh.cancel(h3);
    assert!(oh.io().contains(&IoRequest::CancelDial { op }));
    assert_eq!(oh.with_host(|h, _| h.origin().record_state(h3)), None);
    oh.advance(Duration::from_secs(10));
    assert!(oh.events().is_empty());
}

#[test]
fn connect_timer_cancelled_at_assignment_and_failure() {
    let mut oh = oh();
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    let tcp = oh.dial_ok(op);
    TlsPeer::h1().pump(&mut oh, tcp);
    assert_eq!(
        oh.with_host(|h, _| h.origin().record_state(h3)),
        Some(RecordState::Assigned)
    );
    oh.advance(Duration::from_secs(10));
    assert!(oh.events().is_empty(), "no curl:28 after assignment");
    assert_eq!(
        oh.with_host(|h, _| h.origin().record_state(h3)),
        Some(RecordState::Assigned)
    );
    assert!(!oh.closed(tcp));

    let mut oh = self::oh();
    let h3 = oh.start(get("https://localhost/"));
    let (op, _, _) = oh.dial().unwrap();
    oh.dial_err(op, DialError::Refused);
    oh.advance(Duration::from_secs(10));
    assert_eq!(failure(&oh, h3).curl, 7, "the dial error only, no curl:28");
}

/// 5.1b gap: callbacks for ids the bridge does not own are declined and the
/// host ignores them.
#[test]
fn foreign_ids_are_declined_and_ignored() {
    let mut oh = oh();
    let op = oh.with_host(|_, cx| {
        cx.set_timer(Duration::from_millis(5));
        let target = Target {
            host: Host::Ip([127, 0, 0, 1].into()),
            port: 9,
        };
        cx.dial(target, Duration::from_secs(1))
    });
    assert_eq!(oh.dial().map(|d| d.0), Some(op));
    let tcp = oh.dial_ok(op);
    oh.tcp_in(tcp, b"stray");
    oh.tcp_eof(tcp);
    oh.advance(Duration::from_millis(5));
    oh.tcp_error(tcp, io::ErrorKind::ConnectionReset);
    assert!(oh.events().is_empty());
}
