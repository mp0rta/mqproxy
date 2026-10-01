//! spec §4.6, §4.9: engine creation, threading rule, destroy-once, qlog.
use mq_transport::{Error, Transport};
use mq_transport_api::{CongestionControl, Role, Scheduler, Time, TransportConfig};
use std::path::PathBuf;

const CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/test.crt");
const KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/test.key");

fn cfg(role: Role) -> TransportConfig {
    TransportConfig {
        role,
        alpn: "mqproxy-tcp/1",
        max_conns: 0,
        scheduler: Scheduler::MinRtt,
        cc: CongestionControl::Bbr,
        realtime_offset_us: 0,
    }
}

fn server(cert: &str, key: &str) -> Role {
    Role::Server {
        cert: PathBuf::from(cert),
        key: PathBuf::from(key),
    }
}

#[test]
fn client_engine_creates_and_closes() {
    let t = Transport::new(cfg(Role::Client)).unwrap();
    t.close(Time(1));
}

#[test]
fn server_engine_requires_cert_and_key() {
    assert!(Transport::new(cfg(server("/nonexistent/test.crt", KEY))).is_err());
    assert!(Transport::new(cfg(server(CERT, "/nonexistent/test.key"))).is_err());
    let t = Transport::new(cfg(server(CERT, KEY))).unwrap();
    t.close(Time(1));
}

#[test]
fn second_transport_on_thread_refused() {
    let t = Transport::new(cfg(Role::Client)).unwrap();
    assert!(matches!(
        Transport::new(cfg(Role::Client)),
        Err(Error::EngineAlreadyOnThread)
    ));
    t.close(Time(1));
    Transport::new(cfg(Role::Client)).unwrap().close(Time(1));
}

#[test]
fn transport_is_not_send_nor_sync() {
    static_assertions::assert_not_impl_any!(Transport: Send, Sync);
}

#[test]
fn close_then_drop_does_not_destroy_twice() {
    // `close` consumes the transport, so its Drop runs right after the destroy; a second
    // xqc_engine_destroy would be a double free (caught by scripts/rust-asan.sh).
    let t = Transport::new(cfg(Role::Client)).unwrap();
    t.close(Time(5));
    // Dropping without close destroys once too, and frees the thread claim.
    drop(Transport::new(cfg(Role::Client)).unwrap());
    Transport::new(cfg(Role::Client)).unwrap().close(Time(1));
}

#[test]
fn enable_qlog_opens_role_file() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("enable_qlog_opens_role_file");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("client.qlog");
    std::fs::write(&file, b"stale").unwrap();
    let mut t = Transport::new(cfg(Role::Client)).unwrap();
    assert_eq!(t.enable_qlog(&dir).unwrap(), file);
    assert_eq!(std::fs::metadata(&file).unwrap().len(), 0, "O_TRUNC");
    t.close(Time(1));
}
