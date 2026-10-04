//! spec §5.6: the flow relay, driven by `ScriptedTransport` on the QUIC side
//! and `FakeTcp` (which applies commits the way the driver does) on the TCP side.
//!
//! Mapping of `tests/test_relay.c` (side A = TCP, side B = the QUIC stream):
//! `happy_both_directions`, `backpressure`, `eof_one_side` (inverted: half-close
//! keeps the other direction open), `hard_error` (B's writer = `stream_send`),
//! `read_hard_error`, `read_would_block_chunked`, `data_and_eof_same_read`.

use mq_runtime::testing::{Call, ScriptedHandle, ScriptedTransport};
use mq_runtime::{
    Interest, IoResult, PrereadTooLarge, PumpOutcome, RELAY_BUF, Relay, RelayEnd, ShardState,
    StreamPreread, TCP_BUF,
};
use mq_transport_api::{Event, StreamError, StreamId, Time, TransportOps};
use proptest::prelude::*;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

const T: Time = Time(1);
const BIG: usize = usize::MAX;
const NO_PREREAD: StreamPreread<'static> = StreamPreread {
    bytes: &[],
    fin: false,
};

#[derive(Copy, Clone)]
enum End {
    WouldBlock,
    Eof,
    Error,
}

/// The TCP socket as the driver sees it: reads only while read interest is on,
/// writes only while write interest is on, and runs owed shutdowns.
struct FakeTcp {
    input: Vec<u8>,
    pos: usize,
    /// Bytes deliverable before `end` is returned.
    limit: usize,
    end: End,
    /// Max bytes per read (0 = unlimited).
    chunk: usize,
    /// Every `wb_every`-th read returns `WouldBlock` (0 = never).
    wb_every: usize,
    reads: usize,
    out: Vec<u8>,
    write_budget: usize,
    write_err: bool,
    shut_wr: bool,
}

impl FakeTcp {
    fn new(input: &[u8]) -> FakeTcp {
        FakeTcp {
            input: input.to_vec(),
            pos: 0,
            limit: input.len(),
            end: End::WouldBlock,
            chunk: 0,
            wb_every: 0,
            reads: 0,
            out: Vec::new(),
            write_budget: BIG,
            write_err: false,
            shut_wr: false,
        }
    }
    fn would_block_after(mut self, n: usize) -> FakeTcp {
        (self.limit, self.end) = (n, End::WouldBlock);
        self
    }
    fn eof_after(mut self, n: usize) -> FakeTcp {
        (self.limit, self.end) = (n, End::Eof);
        self
    }
    fn error_after(mut self, n: usize) -> FakeTcp {
        (self.limit, self.end) = (n, End::Error);
        self
    }

    fn read(&mut self, r: &mut Relay, t: &mut dyn TransportOps) {
        while r.tcp_interest().read {
            self.reads += 1;
            let buf = r.tcp_rx_space();
            assert!(!buf.is_empty(), "read interest with an empty rx slice");
            let avail = self.limit - self.pos;
            let res = if self.wb_every > 0 && self.reads.is_multiple_of(self.wb_every) {
                IoResult::WouldBlock
            } else if avail == 0 {
                match self.end {
                    End::WouldBlock => IoResult::WouldBlock,
                    End::Eof => IoResult::Eof,
                    End::Error => IoResult::Error(ErrorKind::ConnectionReset),
                }
            } else {
                let mut n = avail.min(buf.len());
                if self.chunk > 0 {
                    n = n.min(self.chunk);
                }
                buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
                self.pos += n;
                IoResult::Bytes(n)
            };
            r.tcp_rx_commit(res, t, T);
            if !matches!(res, IoResult::Bytes(_)) {
                break;
            }
        }
    }

    fn write(&mut self, r: &mut Relay) {
        while r.tcp_interest().write {
            let data = r.tcp_tx_data();
            assert!(!data.is_empty(), "write interest with nothing to write");
            let res = if self.write_err {
                IoResult::Error(ErrorKind::BrokenPipe)
            } else if self.write_budget == 0 {
                IoResult::WouldBlock
            } else {
                let n = data.len().min(self.write_budget);
                self.out.extend_from_slice(&data[..n]);
                self.write_budget -= n;
                IoResult::Bytes(n)
            };
            r.tcp_tx_commit(res);
            if !matches!(res, IoResult::Bytes(_)) {
                break;
            }
        }
        if r.take_owed_shutdown() {
            assert!(!self.shut_wr, "shutdown owed twice");
            self.shut_wr = true;
            r.shutdown_done();
        }
    }
}

fn setup() -> (ScriptedTransport, ScriptedHandle, StreamId) {
    let (t, h) = ScriptedTransport::new();
    let s = h.new_stream_id();
    (t, h, s)
}

fn start_with(
    h: &ScriptedHandle,
    s: StreamId,
    prebuf: &[u8],
    eof: bool,
    queued: &[u8],
    preread: StreamPreread<'_>,
) -> Result<Relay, PrereadTooLarge> {
    let mut st = ShardState::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)), 0);
    Relay::start(
        h.new_conn_id(),
        st.insert_tcp(),
        s,
        prebuf,
        eof,
        queued,
        preread,
    )
}

fn relay(h: &ScriptedHandle, s: StreamId) -> Relay {
    start_with(h, s, &[], false, &[], NO_PREREAD).unwrap()
}

fn deliver(t: &mut ScriptedTransport, r: &mut Relay) {
    while let Some(ev) = t.poll_event() {
        r.on_stream_event(&ev);
    }
}

/// One driver iteration: events, pump, TCP reads, TCP writes (+ shutdown).
fn step(t: &mut ScriptedTransport, r: &mut Relay, tcp: &mut FakeTcp, budget: usize) {
    deliver(t, r);
    if r.is_runnable() {
        r.pump(t, T, budget);
    }
    tcp.read(r, t);
    tcp.write(r);
}

fn run(t: &mut ScriptedTransport, r: &mut Relay, tcp: &mut FakeTcp) {
    for _ in 0..200 {
        if r.end_reason().is_some() {
            return;
        }
        step(t, r, tcp, BIG);
    }
}

fn sends(h: &ScriptedHandle) -> Vec<(Vec<u8>, bool)> {
    h.log()
        .into_iter()
        .filter_map(|c| match c {
            Call::StreamSend { bytes, fin, .. } => Some((bytes, fin)),
            _ => None,
        })
        .collect()
}
fn fin_sends(h: &ScriptedHandle) -> usize {
    sends(h).iter().filter(|(_, f)| *f).count()
}
fn recv_caps(h: &ScriptedHandle) -> Vec<usize> {
    h.log()
        .into_iter()
        .filter_map(|c| match c {
            Call::StreamRecv { cap, .. } => Some(cap),
            _ => None,
        })
        .collect()
}
const NONE: Interest = Interest {
    read: false,
    write: false,
};

// ---- the seven cases of tests/test_relay.c ----

#[test]
fn happy_both_directions() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"world".to_vec(), true)));
    h.push_event(Event::StreamReadable(s));
    let mut tcp = FakeTcp::new(b"hello").eof_after(5);
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(h.sent_bytes(s), b"hello");
    assert_eq!(fin_sends(&h), 1);
    assert_eq!(tcp.out, b"world");
    assert!(tcp.shut_wr);
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
    // done exactly once: further pumps report it and touch nothing
    let n = h.log().len();
    assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Closed(RelayEnd::Clean));
    assert_eq!(h.log().len(), n);
}

#[test]
fn backpressure() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    let data: Vec<u8> = (0..100).collect();
    let mut tcp = FakeTcp::new(&data).would_block_after(100);
    h.expect_stream_send(s, Ok(10));
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(h.sent_bytes(s), &data[..10]);
    assert!(
        !r.tcp_interest().read,
        "stream not writable: read interest off"
    );
    assert_eq!(r.end_reason(), None);
    h.push_event(Event::StreamWritable(s));
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(h.sent_bytes(s), data);
    assert_eq!(r.end_reason(), None, "neither side ended");
}

#[test]
fn eof_one_side() {
    // Inverted from C: TCP EOF sends FIN but the relay stays open.
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    let mut tcp = FakeTcp::new(b"hi").eof_after(2);
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(h.sent_bytes(s), b"hi");
    assert_eq!(fin_sends(&h), 1);
    assert_eq!(r.end_reason(), None, "QUIC -> TCP not finished yet");
    h.expect_stream_recv(s, Ok((b"morebytes".to_vec(), true)));
    h.push_event(Event::StreamReadable(s));
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(tcp.out, b"morebytes");
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
}

#[test]
fn hard_error() {
    // B's writer is stream_send.
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_send(s, Err(StreamError::Conn));
    let mut tcp = FakeTcp::new(b"data");
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
    let (reads, n) = (tcp.reads, h.log().len());
    h.push_event(Event::StreamReadable(s));
    h.push_event(Event::StreamWritable(s));
    for _ in 0..3 {
        step(&mut t, &mut r, &mut tcp, BIG);
    }
    assert_eq!(tcp.reads, reads, "no more reads");
    assert_eq!(h.log().len(), n, "no more transport calls");
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
}

#[test]
fn read_hard_error() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    let mut tcp = FakeTcp::new(b"abcdefghij").error_after(4);
    tcp.chunk = 4;
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(h.sent_bytes(s), b"abcd");
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
    tcp.limit = 10;
    h.push_event(Event::StreamWritable(s));
    for _ in 0..3 {
        step(&mut t, &mut r, &mut tcp, BIG);
    }
    assert_eq!(h.sent_bytes(s), b"abcd", "nothing further");
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
}

#[test]
fn read_would_block_chunked() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    let data = b"the quick brown fox jumps";
    let mut tcp = FakeTcp::new(data).eof_after(25);
    (tcp.chunk, tcp.wb_every) = (3, 3);
    // B's source EOFs at once.
    h.expect_stream_recv(s, Ok((vec![], true)));
    h.push_event(Event::StreamReadable(s));
    deliver(&mut t, &mut r);
    r.pump(&mut t, T, BIG);
    tcp.write(&mut r);
    assert!(tcp.shut_wr);
    // one readable edge stops at the would-block
    tcp.read(&mut r, &mut t);
    let sent = h.sent_bytes(s);
    assert!(sent.len() < 25);
    assert_eq!(&data[..sent.len()], &sent[..]);
    assert_eq!(r.end_reason(), None);
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(h.sent_bytes(s), data);
    assert_eq!(fin_sends(&h), 1);
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
    step(&mut t, &mut r, &mut tcp, BIG);
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
}

#[test]
fn data_and_eof_same_read() {
    // A Rust read returns bytes or EOF, never both: two reads in one pass.
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((vec![], true)));
    h.push_event(Event::StreamReadable(s));
    let mut tcp = FakeTcp::new(b"final").eof_after(5);
    deliver(&mut t, &mut r);
    r.pump(&mut t, T, BIG);
    tcp.write(&mut r);
    tcp.read(&mut r, &mut t);
    assert_eq!(tcp.reads, 2);
    assert_eq!(h.sent_bytes(s), b"final");
    assert_eq!(fin_sends(&h), 1);
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
    step(&mut t, &mut r, &mut tcp, BIG);
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
}

// ---- named cases (plan task 6.3) ----

#[test]
fn tcp_eof_fin_coalesced_with_last_write() {
    // prebuffer + EOF inherited at start
    let (mut t, h, s) = setup();
    let mut r = start_with(&h, s, b"abc", true, &[], NO_PREREAD).unwrap();
    r.pump(&mut t, T, BIG);
    assert_eq!(sends(&h), vec![(b"abc".to_vec(), true)]);

    // EOF committed while the data still waits for a writable stream
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_send(s, Err(StreamError::Blocked));
    r.tcp_rx_space()[..3].copy_from_slice(b"xyz");
    r.tcp_rx_commit(IoResult::Bytes(3), &mut t, T);
    r.tcp_rx_commit(IoResult::Eof, &mut t, T);
    assert_eq!(sends(&h), vec![(b"xyz".to_vec(), false)]);
    h.push_event(Event::StreamWritable(s));
    deliver(&mut t, &mut r);
    r.pump(&mut t, T, BIG);
    assert_eq!(
        sends(&h),
        vec![(b"xyz".to_vec(), false), (b"xyz".to_vec(), true)]
    );
}

#[test]
fn fin_only_after_partial_accept() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_send(s, Ok(3));
    let mut tcp = FakeTcp::new(b"hello").would_block_after(5);
    tcp.read(&mut r, &mut t);
    assert_eq!(h.sent_bytes(s), b"hel");
    h.push_event(Event::StreamWritable(s));
    deliver(&mut t, &mut r);
    r.pump(&mut t, T, BIG);
    assert_eq!(h.sent_bytes(s), b"hello");
    tcp.end = End::Eof;
    tcp.read(&mut r, &mut t);
    let log = sends(&h);
    assert_eq!(log.last(), Some(&(vec![], true)), "FIN-only write");
    assert_eq!(fin_sends(&h), 1);
}

#[test]
fn quic_fin_shuts_tcp_write_after_drain() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"data".to_vec(), true)));
    h.push_event(Event::StreamReadable(s));
    deliver(&mut t, &mut r);
    r.pump(&mut t, T, BIG);
    let mut tcp = FakeTcp::new(b"");
    tcp.write_budget = 2;
    tcp.write(&mut r);
    assert!(!tcp.shut_wr, "not drained yet");
    tcp.write_budget = 10;
    tcp.write(&mut r);
    assert_eq!(tcp.out, b"data");
    assert!(tcp.shut_wr);
    assert!(!r.take_owed_shutdown(), "owed once");
    assert_eq!(r.end_reason(), None, "TCP -> QUIC still open");
}

#[test]
fn both_finished_closes_clean() {
    let (mut t, h, s) = setup();
    let fin = StreamPreread {
        bytes: &[],
        fin: true,
    };
    let mut r = start_with(&h, s, &[], true, &[], fin).unwrap();
    assert!(r.is_runnable());
    r.pump(&mut t, T, BIG);
    assert_eq!(sends(&h), vec![(vec![], true)]);
    assert!(r.take_owed_shutdown());
    assert_eq!(r.end_reason(), None);
    r.shutdown_done();
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
    assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Closed(RelayEnd::Clean));
    assert_eq!(r.tcp_interest(), NONE);
    assert!(!r.is_runnable());
}

#[test]
fn tcp_error_aborts_and_requests_reset() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    r.tcp_rx_commit(IoResult::Error(ErrorKind::ConnectionReset), &mut t, T);
    // Abort is the shard's cue for stream_reset + TcpClose{abort}.
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
    assert_eq!(r.tcp_interest(), NONE);
    assert!(!r.is_runnable());
    assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Closed(RelayEnd::Abort));
    assert!(h.log().is_empty());
}

#[test]
fn stream_closed_before_fin_aborts() {
    let (_, h, s) = setup();
    let mut r = relay(&h, s);
    r.on_stream_event(&Event::StreamClosed(s));
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));

    // FIN received but ours not sent: still an abort
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((vec![], true)));
    r.on_stream_event(&Event::StreamReadable(s));
    r.pump(&mut t, T, BIG);
    assert_eq!(r.end_reason(), None);
    r.on_stream_event(&Event::StreamClosed(s));
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
}

#[test]
fn stream_closed_after_both_fins_keeps_draining_tcp() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    let mut tcp = FakeTcp::new(b"").eof_after(0);
    tcp.write_budget = 0;
    h.expect_stream_recv(s, Ok((b"reply".to_vec(), true)));
    h.push_event(Event::StreamReadable(s));
    for _ in 0..5 {
        step(&mut t, &mut r, &mut tcp, BIG);
    }
    assert_eq!(fin_sends(&h), 1);
    assert!(tcp.out.is_empty());
    h.push_event(Event::StreamClosed(s));
    h.push_event(Event::StreamReadable(s));
    deliver(&mut t, &mut r);
    assert_eq!(r.end_reason(), None, "reply still buffered");
    assert!(r.tcp_interest().write);
    assert!(!r.is_runnable(), "the stream is gone: no probe, no read");
    let n = h.log().len();
    r.pump(&mut t, T, BIG);
    assert_eq!(h.log().len(), n);
    tcp.write_budget = 100;
    tcp.write(&mut r);
    assert_eq!(tcp.out, b"reply");
    assert!(tcp.shut_wr);
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
}

#[test]
fn blocked_clears_writable_and_writable_event_resumes() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    r.pump(&mut t, T, BIG); // the inherited read latch: Blocked clears it
    h.expect_stream_send(s, Err(StreamError::Blocked));
    let mut tcp = FakeTcp::new(b"abc");
    tcp.read(&mut r, &mut t);
    assert!(h.sent_bytes(s).is_empty());
    assert!(!r.tcp_interest().read);
    assert!(!r.is_runnable());
    h.push_event(Event::StreamWritable(s));
    deliver(&mut t, &mut r);
    assert!(r.is_runnable());
    assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Progressed);
    assert_eq!(h.sent_bytes(s), b"abc");
    assert!(r.tcp_interest().read);
}

#[test]
fn bounded_recv_keeps_readable_until_blocked() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"0123456789".to_vec(), false)));
    r.on_stream_event(&Event::StreamReadable(s));
    r.pump(&mut t, T, 4);
    assert_eq!(r.tcp_tx_data(), b"0123");
    assert_eq!(recv_caps(&h).len(), 1, "budget stops before a Blocked read");
    assert!(r.is_runnable(), "readable stays latched");
    r.pump(&mut t, T, 4);
    assert_eq!(r.tcp_tx_data(), b"01234567");
    r.pump(&mut t, T, 4);
    assert_eq!(r.tcp_tx_data(), b"0123456789");
    assert!(!r.is_runnable(), "Blocked cleared the latch");
}

#[test]
fn fin_seen_makes_read_side_not_runnable() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"x".to_vec(), true)));
    r.on_stream_event(&Event::StreamReadable(s));
    r.pump(&mut t, T, BIG);
    let mut tcp = FakeTcp::new(b"");
    tcp.write(&mut r);
    assert!(tcp.shut_wr);
    assert!(!r.is_runnable());
    let n = h.log().len();
    r.pump(&mut t, T, BIG);
    assert_eq!(h.log().len(), n, "no stream_recv after FIN");
}

#[test]
fn readable_after_fin_probes_once_and_reset_aborts() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"x".to_vec(), true)));
    r.on_stream_event(&Event::StreamReadable(s));
    r.pump(&mut t, T, BIG);
    FakeTcp::new(b"").write(&mut r);
    // a readable after FIN: one probe, answered (0, fin)
    h.expect_stream_recv(s, Ok((vec![], true)));
    r.on_stream_event(&Event::StreamReadable(s));
    assert!(r.is_runnable());
    r.pump(&mut t, T, BIG);
    assert_eq!(recv_caps(&h).last(), Some(&0));
    assert_eq!(r.end_reason(), None);
    assert!(!r.is_runnable());
    let n = recv_caps(&h).len();
    r.pump(&mut t, T, BIG);
    assert_eq!(recv_caps(&h).len(), n, "probe is one-shot");
    // next readable: the probe finds the reset
    h.expect_stream_recv(s, Err(StreamError::Reset));
    r.on_stream_event(&Event::StreamReadable(s));
    assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Closed(RelayEnd::Abort));
    assert_eq!(recv_caps(&h)[n..], [0]);
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
}

/// Fills QUIC -> TCP to the brim with TCP writes blocked and TCP idle.
fn full_to_tcp(t: &mut ScriptedTransport, h: &ScriptedHandle, s: StreamId) -> (Relay, FakeTcp) {
    let mut r = relay(h, s);
    h.expect_stream_recv(s, Ok((vec![7; RELAY_BUF], false)));
    h.push_event(Event::StreamReadable(s));
    let mut tcp = FakeTcp::new(b"");
    tcp.write_budget = 0;
    for _ in 0..3 {
        step(t, &mut r, &mut tcp, BIG);
    }
    assert_eq!(r.tcp_tx_data().len(), RELAY_BUF);
    assert!(!r.is_runnable());
    (r, tcp)
}

#[test]
fn reset_probe_runs_with_full_tcp_buffer_and_blocked_writes() {
    let (mut t, h, s) = setup();
    let (mut r, tcp) = full_to_tcp(&mut t, &h, s);
    h.expect_stream_recv(s, Err(StreamError::Reset));
    h.push_event(Event::StreamReadable(s));
    deliver(&mut t, &mut r);
    assert!(r.is_runnable(), "the probe needs no buffer room");
    assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Closed(RelayEnd::Abort));
    assert_eq!(recv_caps(&h).last(), Some(&0));
    assert_eq!(tcp.pos, 0, "TCP idle");
    assert!(sends(&h).is_empty());
}

#[test]
fn probe_blocked_keeps_read_latch() {
    let (mut t, h, s) = setup();
    let (mut r, mut tcp) = full_to_tcp(&mut t, &h, s);
    h.expect_stream_recv(s, Err(StreamError::Blocked));
    h.expect_stream_recv(s, Ok((b"more".to_vec(), false)));
    r.on_stream_event(&Event::StreamReadable(s));
    r.pump(&mut t, T, BIG);
    assert_eq!(recv_caps(&h).last(), Some(&0));
    assert_eq!(r.end_reason(), None);
    assert!(!r.is_runnable(), "probe spent, buffer still full");
    tcp.write_budget = BIG;
    tcp.write(&mut r);
    assert!(
        r.is_runnable(),
        "stream_readable survived the Blocked probe"
    );
    r.pump(&mut t, T, BIG);
    assert_eq!(r.tcp_tx_data(), b"more");
}

#[test]
fn fin_only_blocked_not_runnable_until_writable() {
    let (mut t, h, s) = setup();
    let mut r = start_with(&h, s, &[], true, &[], NO_PREREAD).unwrap();
    h.expect_stream_send(s, Err(StreamError::Blocked));
    assert!(r.is_runnable());
    r.pump(&mut t, T, BIG);
    assert!(!r.is_runnable());
    h.push_event(Event::StreamWritable(s));
    deliver(&mut t, &mut r);
    assert!(r.is_runnable());
    r.pump(&mut t, T, BIG);
    assert_eq!(sends(&h), vec![(vec![], true), (vec![], true)]);
    assert!(!r.is_runnable(), "FIN sent");
}

#[test]
fn full_rx_buffer_turns_read_interest_off_and_is_not_eof() {
    let (mut t, h, s) = setup();
    let pre = vec![1u8; RELAY_BUF];
    let mut r = start_with(&h, s, &pre, false, &[], NO_PREREAD).unwrap();
    assert!(!r.tcp_interest().read);
    assert!(r.tcp_rx_space().is_empty());
    r.pump(&mut t, T, BIG);
    assert_eq!(sends(&h), vec![(pre, false)], "a full buffer is not EOF");
    assert!(r.tcp_interest().read);
    assert_eq!(r.tcp_rx_space().len(), RELAY_BUF);
}

#[test]
fn empty_tx_buffer_turns_write_interest_off() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    assert!(!r.tcp_interest().write);
    h.expect_stream_recv(s, Ok((b"ab".to_vec(), false)));
    r.on_stream_event(&Event::StreamReadable(s));
    r.pump(&mut t, T, BIG);
    assert!(r.tcp_interest().write);
    r.tcp_tx_commit(IoResult::Bytes(2));
    assert!(!r.tcp_interest().write);
    assert!(r.tcp_tx_data().is_empty());
}

#[test]
fn aborted_relay_has_no_write_interest() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"ab".to_vec(), false)));
    r.on_stream_event(&Event::StreamReadable(s));
    r.pump(&mut t, T, BIG);
    assert!(r.tcp_interest().write);
    r.tcp_tx_commit(IoResult::Error(ErrorKind::BrokenPipe));
    assert_eq!(r.end_reason(), Some(RelayEnd::Abort));
    assert_eq!(r.tcp_interest(), NONE, "bytes left, but no spin");
}

#[test]
fn prebuffer_runnable_without_tcp_event() {
    let (mut t, h, s) = setup();
    let mut r = start_with(&h, s, b"GET /", false, &[], NO_PREREAD).unwrap();
    assert!(r.is_runnable());
    r.pump(&mut t, T, BIG);
    assert_eq!(h.sent_bytes(s), b"GET /");
    assert!(!r.is_runnable());
}

#[test]
fn start_hands_over_read_readiness() {
    // spec §5.4: the app may have consumed the only StreamReadable.
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"left in xquic".to_vec(), false)));
    assert!(r.is_runnable(), "no StreamReadable needed");
    r.pump(&mut t, T, BIG);
    assert_eq!(r.tcp_tx_data(), b"left in xquic");

    // ...but not after the preread already carried FIN
    let (_, h, s) = setup();
    let fin = StreamPreread {
        bytes: &[],
        fin: true,
    };
    let mut r = start_with(&h, s, &[], false, &[], fin).unwrap();
    assert!(r.take_owed_shutdown());
    r.shutdown_done();
    assert!(!r.is_runnable());
}

#[test]
fn queued_reply_goes_out_before_preread() {
    let (_, h, s) = setup();
    let pre = StreamPreread {
        bytes: b"body",
        fin: false,
    };
    let r = start_with(&h, s, &[], false, b"HTTP/1.1 200 OK\r\n\r\n", pre).unwrap();
    assert_eq!(r.tcp_tx_data(), b"HTTP/1.1 200 OK\r\n\r\nbody");
    assert!(r.tcp_interest().write);
}

#[test]
fn preread_too_large_rejected() {
    let (_, h, s) = setup();
    let q = [0u8; 10];
    let big = vec![0u8; RELAY_BUF - 9];
    let pre = |b| StreamPreread {
        bytes: b,
        fin: false,
    };
    assert_eq!(
        start_with(&h, s, &[], false, &q, pre(&big)).err(),
        Some(PrereadTooLarge)
    );
    assert!(start_with(&h, s, &[], false, &q, pre(&big[1..])).is_ok());
    let pb = vec![0u8; RELAY_BUF + 1];
    assert!(start_with(&h, s, &pb, false, &[], NO_PREREAD).is_err());
    assert_eq!(RELAY_BUF, TCP_BUF);
}

#[test]
fn preread_fin_recorded_and_shut_wr_owed() {
    let (mut t, h, s) = setup();
    let pre = StreamPreread {
        bytes: b"x",
        fin: true,
    };
    let mut r = start_with(&h, s, &[], false, &[], pre).unwrap();
    assert!(!r.take_owed_shutdown(), "not drained");
    r.pump(&mut t, T, BIG);
    assert!(recv_caps(&h).is_empty(), "read side already finished");
    r.tcp_tx_commit(IoResult::Bytes(1));
    assert!(r.is_runnable(), "SHUT_WR owed");
    assert!(r.take_owed_shutdown());
    assert!(!r.take_owed_shutdown());
    r.shutdown_done();
    assert!(!r.is_runnable());
}

#[test]
fn rx_commit_forwards_immediately() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    r.pump(&mut t, T, BIG); // the inherited read latch: Blocked clears it
    r.tcp_rx_space()[..3].copy_from_slice(b"abc");
    r.tcp_rx_commit(IoResult::Bytes(3), &mut t, T);
    assert_eq!(sends(&h), vec![(b"abc".to_vec(), false)]);
    assert!(!r.is_runnable());
    r.tcp_rx_commit(IoResult::WouldBlock, &mut t, T);
    assert_eq!(sends(&h).len(), 1);
}

#[test]
fn would_block_and_partial_tcp_write_no_loss() {
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    let data: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    for c in data.chunks(300) {
        h.expect_stream_recv(s, Ok((c.to_vec(), false)));
    }
    h.push_event(Event::StreamReadable(s));
    let mut tcp = FakeTcp::new(b"");
    for i in 0..400 {
        tcp.write_budget = [7, 0, 13, 0, 1][i % 5];
        step(&mut t, &mut r, &mut tcp, 50);
    }
    assert_eq!(tcp.out, data);
    assert_eq!(r.end_reason(), None);
}

#[test]
fn one_direction_fin_other_keeps_flowing() {
    // TCP EOF first: QUIC -> TCP keeps flowing over several reads.
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    let mut tcp = FakeTcp::new(b"req").eof_after(3);
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(fin_sends(&h), 1);
    for (c, fin) in [(&b"aa"[..], false), (b"bb", false), (b"cc", true)] {
        h.expect_stream_recv(s, Ok((c.to_vec(), fin)));
        h.push_event(Event::StreamReadable(s));
        step(&mut t, &mut r, &mut tcp, BIG);
    }
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(tcp.out, b"aabbcc");
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));

    // QUIC FIN first: TCP -> QUIC keeps flowing.
    let (mut t, h, s) = setup();
    let mut r = relay(&h, s);
    h.expect_stream_recv(s, Ok((b"resp".to_vec(), true)));
    h.push_event(Event::StreamReadable(s));
    let mut tcp = FakeTcp::new(b"uploadmore").would_block_after(6);
    run(&mut t, &mut r, &mut tcp);
    assert!(tcp.shut_wr);
    assert_eq!(h.sent_bytes(s), b"upload");
    assert_eq!(r.end_reason(), None);
    tcp = FakeTcp {
        shut_wr: true,
        ..FakeTcp::new(b"uploadmore").eof_after(10)
    };
    tcp.pos = 6;
    run(&mut t, &mut r, &mut tcp);
    assert_eq!(h.sent_bytes(s), b"uploadmore");
    assert_eq!(fin_sends(&h), 1);
    assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
}

#[test]
fn stream_error_reset_aborts() {
    for e in [StreamError::Reset, StreamError::Stale, StreamError::Conn] {
        // send side
        let (mut t, h, s) = setup();
        let mut r = start_with(&h, s, b"x", false, &[], NO_PREREAD).unwrap();
        h.expect_stream_send(s, Err(e));
        assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Closed(RelayEnd::Abort));
        // recv side
        let (mut t, h, s) = setup();
        let mut r = relay(&h, s);
        h.expect_stream_recv(s, Err(e));
        r.on_stream_event(&Event::StreamReadable(s));
        assert_eq!(r.pump(&mut t, T, BIG), PumpOutcome::Closed(RelayEnd::Abort));
        assert_eq!(r.tcp_interest(), NONE);
    }
}

proptest! {
    #[test]
    fn proptest_bytes_in_equal_bytes_out(
        tcp_in in prop::collection::vec(any::<u8>(), 0..3000),
        quic_in in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..500), 0..8),
        accept in prop::collection::vec(prop::option::weighted(0.8, 1usize..600), 0..10),
        wbud in prop::collection::vec(0usize..700, 1..10),
        chunk in 1usize..800,
        wb_every in prop_oneof![Just(0usize), 2usize..5],
        budget in 1usize..2000,
    ) {
        let mut wbud = wbud;
        wbud.push(1000); // TCP writes always make progress eventually
        let (mut t, h, s) = setup();
        let mut r = relay(&h, s);
        // stream_send accepts per `accept` (None = Blocked), cycling; a partial
        // accept or Blocked is followed by StreamWritable, as xquic does.
        let mut accept = accept;
        accept.push(Some(64));
        let state = Arc::new(Mutex::new(0usize));
        h.on_stream_send(move |h, s, data, _fin| {
            let mut i = state.lock().unwrap();
            let a = accept[*i % accept.len()];
            *i += 1;
            match a {
                None => {
                    h.push_event(Event::StreamWritable(s));
                    Err(StreamError::Blocked)
                }
                Some(k) => {
                    let n = k.min(data.len());
                    if n < data.len() {
                        h.push_event(Event::StreamWritable(s));
                    }
                    Ok(n)
                }
            }
        });
        let n = quic_in.len();
        for (i, c) in quic_in.iter().enumerate() {
            h.expect_stream_recv(s, Ok((c.clone(), i + 1 == n)));
        }
        if n == 0 {
            h.expect_stream_recv(s, Ok((vec![], true)));
        }
        h.push_event(Event::StreamReadable(s));
        let mut tcp = FakeTcp::new(&tcp_in).eof_after(tcp_in.len());
        (tcp.chunk, tcp.wb_every) = (chunk, wb_every);
        for i in 0..20_000 {
            if r.end_reason().is_some() {
                break;
            }
            tcp.write_budget = wbud[i % wbud.len()];
            step(&mut t, &mut r, &mut tcp, budget);
        }
        prop_assert_eq!(r.end_reason(), Some(RelayEnd::Clean));
        prop_assert_eq!(h.sent_bytes(s), tcp_in);
        prop_assert_eq!(tcp.out, quic_in.concat());
        prop_assert!(tcp.shut_wr);
    }
}
