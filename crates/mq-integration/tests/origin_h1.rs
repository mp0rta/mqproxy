//! The origin bridge against a real hyper h1 origin (spec §7.7 "h1 conns",
//! §10.3), on the `OriginLoop` / `OriginServer` harness.

use mq_http::headers::HttpVer;
use mq_integration::origin_loop::OriginLoop;
use mq_integration::origin_server::{Handler, ORIGIN_CA, OriginServer, OriginServerMode, Proto};
use mq_proxy::server::origin::host::{BodySpec, BridgeEv, StartSpec, upload_byte};
use mq_proxy::server::origin::{OriginCfg, OriginProto, SWEEP, build_client_config};
use std::cell::Cell;
use std::time::{Duration, Instant};

const T: Duration = Duration::from_secs(5);

fn cfg() -> OriginCfg {
    OriginCfg {
        connect_timeout: Duration::from_secs(10),
        sweep: SWEEP,
    }
}

/// A bridge trusting the test origin CA only.
fn plain_loop() -> OriginLoop {
    let tls = build_client_config(Some(ORIGIN_CA.as_ref()), &Vec::new).unwrap();
    OriginLoop::new(cfg(), tls)
}

#[test]
fn h1_plain_echo_relays() {
    const N: u64 = 100_000;
    let srv = OriginServer::spawn(OriginServerMode::new(Proto::H1Plain, Handler::Echo));
    let mut lp = plain_loop();
    let h3 = lp.start(StartSpec {
        method: "POST",
        url: format!("http://{}/echo", srv.addr),
        headers: Vec::new(),
        ver: HttpVer::Default,
        body: BodySpec::Known(N),
    });
    let ended = |evs: &[BridgeEv]| evs.iter().any(|e| matches!(e, BridgeEv::End(..)));
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
            BridgeEv::End(id, done) => {
                assert_eq!(*id, h3);
                assert_eq!(done.delivered, N);
            }
            BridgeEv::Failure(..) => panic!("{e:?}"),
            _ => {}
        }
    }
    let head = head.expect("on_response");
    assert_eq!(head.status, 200);
    assert_eq!(head.proto, OriginProto::H1);
    assert_eq!(body.len() as u64, N);
    assert!(
        body.iter()
            .enumerate()
            .all(|(i, b)| *b == upload_byte(i as u64))
    );
}

#[test]
fn run_until_times_out_when_pred_never_true() {
    let mut lp = plain_loop();
    let limit = Duration::from_millis(200);
    let t0 = Instant::now();
    assert!(!lp.run_until(limit, |_| false));
    let took = t0.elapsed();
    assert!(took >= limit, "returned early: {took:?}");
    assert!(took < limit + Duration::from_millis(50), "took {took:?}");
}

#[test]
fn run_until_twice_second_call_does_not_wait_for_first_limit() {
    let mut lp = plain_loop();
    // True on the second check: one iteration ran with the 5 s limit armed,
    // so the loop's cached wait is that limit.
    let checks = Cell::new(0);
    let t0 = Instant::now();
    assert!(lp.run_until(Duration::from_secs(5), |_| {
        checks.set(checks.get() + 1);
        checks.get() >= 2
    }));
    assert!(t0.elapsed() < Duration::from_secs(1));
    let t1 = Instant::now();
    assert!(!lp.run_until(Duration::from_millis(200), |_| false));
    let took = t1.elapsed();
    assert!(took < Duration::from_millis(300), "took {took:?}");
}
