//! The origin bridge against a real hyper h2 origin (spec §7.7 "h2 conns",
//! §10.3), on the `OriginLoop` / `OriginServer` harness.

use mq_http::headers::HttpVer;
use mq_integration::origin_loop::OriginLoop;
use mq_integration::origin_server::{Handler, ORIGIN_CA, OriginServer, OriginServerMode, Proto};
use mq_proxy::server::origin::host::{BodySpec, BridgeEv, StartSpec, upload_byte};
use mq_proxy::server::origin::{OriginCfg, OriginProto, SWEEP, build_client_config};
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(5);

fn origin_loop() -> OriginLoop {
    let cfg = OriginCfg {
        connect_timeout: Duration::from_secs(10),
        sweep: SWEEP,
    };
    let tls = build_client_config(Some(ORIGIN_CA.as_ref()), &Vec::new).unwrap();
    OriginLoop::new(cfg, tls)
}

fn spec(method: &'static str, url: String, body: BodySpec) -> StartSpec {
    StartSpec {
        method,
        url,
        headers: Vec::new(),
        ver: HttpVer::Default,
        body,
    }
}

fn ended(evs: &[BridgeEv]) -> bool {
    evs.iter()
        .any(|e| matches!(e, BridgeEv::End(..) | BridgeEv::Failure(..)))
}

#[test]
fn h2_tls_alpn_echo() {
    const N: u64 = 100_000;
    let srv = OriginServer::spawn(OriginServerMode::new(Proto::H2Tls, Handler::Echo));
    let mut lp = origin_loop();
    let url = format!("https://{}/echo", srv.addr);
    let h3 = lp.start(spec("POST", url, BodySpec::Known(N)));
    assert!(
        lp.run_until(T, |h| ended(h.events())),
        "{:?}",
        lp.host().events()
    );
    let mut body = Vec::new();
    let mut head = None;
    for e in lp.host().events() {
        match e {
            BridgeEv::Response(id, h) if *id == h3 => head = Some(h.clone()),
            BridgeEv::Frame(id, d) if *id == h3 => body.extend_from_slice(d),
            BridgeEv::End(_, done) => assert_eq!(done.delivered, N),
            BridgeEv::Failure(..) => panic!("{e:?}"),
            _ => {}
        }
    }
    let head = head.expect("on_response");
    assert_eq!(head.status, 200);
    assert_eq!(head.proto, OriginProto::H2);
    assert_eq!(head.version, "h2");
    assert_eq!(body.len() as u64, N);
    assert!(
        body.iter()
            .enumerate()
            .all(|(i, b)| *b == upload_byte(i as u64))
    );
}

/// `RawH2Tls`: the head arrives without END_STREAM; `release()` sends
/// SETTINGS(MAX_CONCURRENT_STREAMS = 1), GOAWAY(1) and DATA(END_STREAM) for
/// stream 1, so the response ends cleanly; the client ACKs both SETTINGS.
#[test]
fn raw_h2_frame_order() {
    const DATA: u8 = 0;
    const HEADERS: u8 = 1;
    const SETTINGS: u8 = 4;
    const GOAWAY: u8 = 7;
    const ACK: u8 = 0x1;
    const END_STREAM: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;
    let settings_in =
        |srv: &OriginServer| srv.frames().iter().filter(|f| **f == (SETTINGS, 0)).count();
    let srv = OriginServer::spawn(OriginServerMode::new(Proto::RawH2Tls, Handler::Echo));
    let mut lp = origin_loop();
    let url = format!("https://{}/", srv.addr);
    let h3 = lp.start(spec("GET", url, BodySpec::None));
    let head = |evs: &[BridgeEv]| evs.iter().any(|e| matches!(e, BridgeEv::Response(..)));
    assert!(
        lp.run_until(T, |h| head(h.events())),
        "{:?}",
        lp.host().events()
    );
    let before = srv.frames();
    assert_eq!(
        before.first(),
        Some(&(SETTINGS, 0)),
        "the client's SETTINGS"
    );
    assert!(before.contains(&(HEADERS, 1)), "{before:?}");
    srv.release();
    assert!(
        lp.run_until(T, |h| ended(h.events())),
        "{:?}",
        lp.host().events()
    );
    match lp.host().events().last() {
        Some(BridgeEv::End(id, done)) => assert_eq!((*id, done.delivered), (h3, 0)),
        e => panic!("{e:?}"),
    }
    assert_eq!(
        srv.sent(),
        [
            (SETTINGS, 0),
            (SETTINGS, ACK),
            (HEADERS, END_HEADERS),
            (SETTINGS, 0),
            (GOAWAY, 0),
            (DATA, END_STREAM),
        ]
    );
    // Inbound SETTINGS frames: the client's own, its ACK of the server's
    // first SETTINGS and its ACK of the released one. Keep the loop running
    // (in short slices) so the last ACK is written.
    let end = Instant::now() + T;
    while settings_in(&srv) < 3 && Instant::now() < end {
        lp.run_until(Duration::from_millis(20), |_| false);
    }
    assert_eq!(settings_in(&srv), 3, "{:?}", srv.frames());
}
