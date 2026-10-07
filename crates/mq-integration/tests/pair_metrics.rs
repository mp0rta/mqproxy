//! Active-connection metrics on the shard pair (spec §8.1 "Shard pair",
//! §6.5: the server reports the most recently *accepted* connection — set at
//! `NewConn`, before auth — and clears it only when that same connection
//! closes), plus a `conn_stats` + formatter smoke.
#![forbid(unsafe_code)]

use mq_integration::shard_pair::*;
use mq_proxy::metrics::format_metrics;
use mq_proxy::server::Server;
use mq_runtime::App;
use mq_transport_api::{ConnId, TransportOps};

fn active<C: App + 'static>(p: &Pair<Server, C>) -> Option<ConnId> {
    p.with_server(|n| n.app().active_conn())
}

#[test]
fn pair_metrics_active_conn() {
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_client(client_cfg()));
    assert!(p.run_until(5 * SEC, |p| p.auth_attempts() == 1));
    let srv = p.server_conns()[0];
    assert_eq!(active(&p), Some(srv));

    let lines = p.with_server(move |n| {
        let st = n.transport().conn_stats(srv).expect("live connection");
        format_metrics(Some(&st))
    });
    assert!(lines[0].starts_with("mq.conn "), "{lines:?}");

    // Reconnect is off: nothing re-sets it after the close.
    p.close_client_conn(p.client_conns()[0]);
    assert!(p.run_until(3 * SEC, |p| active(p).is_none()));
}

/// A authenticates; an unauthenticated B is accepted and becomes the active
/// connection; B's auth deadline closes it, and the active connection is
/// then none — not A, which is still open.
#[test]
fn pair_metrics_active_conn_replaced_by_unauthenticated_accept() {
    let mut p = Pair::new(spawn_server(server_cfg(), 0), spawn_raw(false));
    p.raw_connect(true);
    let a = p.server_conns()[0];
    assert_eq!(active(&p), Some(a));

    // B: the SilentClient behaviour (control stream opened, no AUTH_REQUEST).
    p.with_client(|n| n.with_app(|r, cx| r.connect(cx, false)));
    assert!(p.run_until(5 * SEC, |p| p.server_conns().len() == 2));
    let b = p.server_conns()[1];
    assert_eq!(active(&p), Some(b));
    assert_eq!(p.auth_attempts(), 1, "B is unauthenticated");

    assert!(
        p.run_until(15 * SEC, move |p| p.with_server(move |n| n.tap().closed(b))
            == 1)
    );
    assert_eq!(active(&p), None);
    assert_eq!(p.server_conns(), [a], "A is still open");
}
