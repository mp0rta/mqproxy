// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! spec §4.2: a zero-capacity `stream_recv` is a probe — it reports a reset and otherwise
//! consumes nothing.
mod common;

use common::pair::{Pair, new_streams, recv, send};
use mq_transport_api::{StreamError, StreamId, TransportOps};

fn probe(p: &Pair, s: StreamId) -> Result<(Vec<u8>, bool), StreamError> {
    recv(&p.server, p.now, s, 0)
}

/// Client sends `data` (+FIN); returns the server's stream.
fn stream_with(p: &mut Pair, data: &[u8], fin: bool) -> (StreamId, StreamId) {
    let cs = p.open();
    assert_eq!(
        send(&p.client, p.now, cs, data.to_vec(), fin),
        Ok(data.len())
    );
    p.exchange();
    (cs, new_streams(&p.sev).last().unwrap().0)
}

fn client_reset(p: &mut Pair, cs: StreamId) {
    p.client.call(p.now, move |t, now| t.stream_reset(now, cs));
    p.exchange();
}

#[test]
fn probe_on_buffered_data_is_blocked_and_consumes_nothing() {
    let mut p = Pair::new();
    let (_, ss) = stream_with(&mut p, b"buffered", false);
    assert_eq!(probe(&p, ss), Err(StreamError::Blocked));
    assert_eq!(probe(&p, ss), Err(StreamError::Blocked));
    assert_eq!(
        recv(&p.server, p.now, ss, 64),
        Ok((b"buffered".to_vec(), false))
    );
}

#[test]
fn probe_after_fin_is_zero_true() {
    let mut p = Pair::new();
    let (_, ss) = stream_with(&mut p, b"x", true);
    assert_eq!(recv(&p.server, p.now, ss, 64), Ok((b"x".to_vec(), true)));
    assert_eq!(probe(&p, ss), Ok((vec![], true)));
}

#[test]
fn probe_sees_reset_without_fin() {
    let mut p = Pair::new();
    let (cs, ss) = stream_with(&mut p, b"unread", false);
    client_reset(&mut p, cs);
    assert_eq!(probe(&p, ss), Err(StreamError::Reset));
}

#[test]
fn probe_sees_reset_after_fin() {
    let mut p = Pair::new();
    let (cs, ss) = stream_with(&mut p, b"done", true);
    assert_eq!(recv(&p.server, p.now, ss, 64), Ok((b"done".to_vec(), true)));
    client_reset(&mut p, cs);
    assert_eq!(probe(&p, ss), Err(StreamError::Reset));
}
