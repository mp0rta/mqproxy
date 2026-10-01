//! spec §4.2, §4.8: a released id is stale — every call on it fails with `Stale` or is a
//! no-op, and it never resolves to the slot's next occupant.
mod common;

use common::pair::{MS, Pair, conn_cfg, new_streams, recv, send, stream_count};
use mq_transport_api::{Error, PathError, StreamError, StreamId, TransportOps};

/// One request/response with FIN both ways; returns once the client's slot is released.
fn finished_stream(p: &mut Pair) -> StreamId {
    let s = p.open();
    assert_eq!(send(&p.client, p.now, s, b"q".to_vec(), true), Ok(1));
    p.exchange();
    let ss = new_streams(&p.sev).last().unwrap().0;
    assert_eq!(recv(&p.server, p.now, ss, 8), Ok((b"q".to_vec(), true)));
    assert_eq!(send(&p.server, p.now, ss, b"a".to_vec(), true), Ok(1));
    p.exchange();
    assert_eq!(recv(&p.client, p.now, s, 8), Ok((b"a".to_vec(), true)));
    let c = p.conn;
    assert!(p.pump_until(MS, 1000, |p| stream_count(&p.client, c) == 0));
    s
}

#[test]
fn stale_stream_id_never_reaches_the_reused_slot() {
    let mut p = Pair::new();
    let old = finished_stream(&mut p);
    let new = p.open();
    assert_eq!(new.index(), old.index(), "the slot is reused");
    assert_ne!(new, old);

    let now = p.now;
    let r = p.client.call(now, move |t, now| {
        (
            t.stream_send(now, old, b"x", false),
            t.stream_recv(now, old, &mut [0u8; 8]),
            t.stream_recv(now, old, &mut []),
            t.stream_info(old),
        )
    });
    assert_eq!(
        r,
        (
            Err(StreamError::Stale),
            Err(StreamError::Stale),
            Err(StreamError::Stale),
            Err(Error::Stale)
        )
    );
    // A reset of the stale id leaves the new occupant alone.
    p.client.call(now, move |t, now| t.stream_reset(now, old));
    assert_eq!(
        send(&p.client, p.now, new, b"still mine".to_vec(), true),
        Ok(10)
    );
    p.exchange();
    let ss = new_streams(&p.sev).last().unwrap().0;
    assert_eq!(
        recv(&p.server, p.now, ss, 64),
        Ok((b"still mine".to_vec(), true))
    );
}

#[test]
fn stale_conn_id_never_reaches_the_reused_slot() {
    let mut p = Pair::new();
    let old = p.conn;
    p.client.call(p.now, move |t, now| t.close_conn(now, old));
    assert!(p.pump_until(10 * MS, 1000, |p| p.client_closed().is_some()));

    let now = p.now;
    let r = p.client.call(now, move |t, now| {
        (
            t.open_stream(now, old),
            t.conn_stats(old).map(|_| ()),
            t.add_path(now, old, false),
        )
    });
    assert_eq!(
        r,
        (Err(Error::Stale), Err(Error::Stale), Err(PathError::Stale))
    );
    p.client.call(now, move |t, now| t.close_conn(now, old)); // no-op

    // A new connection takes the slot; the old id still resolves to nothing.
    let cc = conn_cfg(None);
    let new = p
        .client
        .call(now, move |t, now| t.connect(now, &cc))
        .unwrap();
    assert_eq!(new.index(), old.index());
    assert_ne!(new, old);
    p.client.call(now, move |t, now| t.close_conn(now, old)); // must not close `new`
    p.exchange();
    assert!(
        p.cev
            .contains(&mq_transport_api::Event::ConnEstablished(new))
    );
    assert!(p.client.call(p.now, move |t, _| t.conn_stats(new)).is_ok());
    assert_eq!(
        p.client
            .call(p.now, move |t, _| t.conn_stats(old).map(|_| ())),
        Err(Error::Stale)
    );
}
