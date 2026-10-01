//! The flow relay (spec §5.6): one QUIC stream bound to one TCP socket.

use super::ringbuf::RingBuf;
use crate::app::{Interest, IoResult, PrereadTooLarge, StreamPreread};
use crate::ids::TcpId;
use mq_transport_api::{ConnId, Event, StreamError, StreamId, Time, TransportOps};

/// spec §5.6: each direction's buffer (the same 64 KiB as `TCP_BUF`, spec §5.4).
pub const RELAY_BUF: usize = super::TCP_BUF;

/// spec §5.6: how a relay ended.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RelayEnd {
    /// Both directions finished: graceful TCP close.
    Clean,
    /// Error or reset: the shard resets the stream and aborts TCP.
    Abort,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum RelayState {
    Open,
    Closed(RelayEnd),
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum PumpOutcome {
    Progressed,
    Idle,
    Closed(RelayEnd),
}

/// spec §5.6: one QUIC stream bound to one TCP socket.
#[derive(Debug)]
pub struct Relay {
    pub conn: ConnId,
    pub tcp: TcpId,
    pub stream: StreamId,
    /// TCP → QUIC.
    to_quic: RingBuf,
    /// QUIC → TCP.
    to_tcp: RingBuf,
    /// Latched by `StreamReadable`; cleared by `Blocked` or once FIN is read.
    stream_readable: bool,
    /// Starts set; cleared by a short or `Blocked` send; set by `StreamWritable`.
    stream_writable: bool,
    /// The peer's FIN has been read: the QUIC → TCP read side is finished.
    fin_seen: bool,
    /// `StreamClosed` after both FINs: no more stream calls, `to_tcp` still drains.
    stream_gone: bool,
    /// One zero-capacity `stream_recv` owed: a `StreamReadable` the relay could
    /// not act on by reading (read side finished, or `to_tcp` full).
    reset_probe: bool,
    tcp_read_eof: bool,
    tcp_write_shut: bool,
    fin_sent: bool,
    shut_wr_requested: bool,
    state: RelayState,
}

impl Relay {
    /// spec §5.4/§5.6. `tcp_prebuf`: bytes already read from TCP, sent first
    /// toward the stream. `to_tcp_queued`: output the app already queued on the
    /// socket (its success reply), written before `preread`. Err if
    /// `to_tcp_queued + preread.bytes`, or `tcp_prebuf`, exceeds `RELAY_BUF`.
    ///
    /// `stream_writable` starts set (spec §5.6). `stream_readable` starts set
    /// unless `preread.fin` (spec §5.4): the app may have consumed a
    /// `StreamReadable` and read only part of what xquic holds, and xquic will
    /// not notify again.
    pub fn start(
        conn: ConnId,
        tcp: TcpId,
        stream: StreamId,
        tcp_prebuf: &[u8],
        tcp_read_eof: bool,
        to_tcp_queued: &[u8],
        preread: StreamPreread<'_>,
    ) -> Result<Relay, PrereadTooLarge> {
        let mut to_quic = RingBuf::new(RELAY_BUF);
        let mut to_tcp = RingBuf::new(RELAY_BUF);
        if to_tcp_queued.len() + preread.bytes.len() > to_tcp.capacity()
            || tcp_prebuf.len() > to_quic.capacity()
        {
            return Err(PrereadTooLarge);
        }
        push(&mut to_quic, tcp_prebuf);
        push(&mut to_tcp, to_tcp_queued);
        push(&mut to_tcp, preread.bytes);
        Ok(Relay {
            conn,
            tcp,
            stream,
            to_quic,
            to_tcp,
            stream_readable: !preread.fin,
            stream_writable: true,
            fin_seen: preread.fin,
            stream_gone: false,
            reset_probe: false,
            tcp_read_eof,
            tcp_write_shut: false,
            fin_sent: false,
            shut_wr_requested: false,
            state: RelayState::Open,
        })
    }

    fn open(&self) -> bool {
        self.state == RelayState::Open
    }

    fn abort(&mut self) {
        if self.open() {
            self.state = RelayState::Closed(RelayEnd::Abort);
        }
    }

    /// spec §5.6 "Half-close": both directions finished.
    fn check_clean(&mut self) {
        if self.open() && self.fin_sent && self.tcp_write_shut && self.to_tcp.is_empty() {
            self.state = RelayState::Closed(RelayEnd::Clean);
        }
    }

    fn fin_owed(&self) -> bool {
        self.tcp_read_eof && self.to_quic.is_empty() && !self.fin_sent
    }

    /// spec §5.6 (c).
    fn shut_wr_owed(&self) -> bool {
        self.fin_seen && self.to_tcp.is_empty() && !self.tcp_write_shut && !self.shut_wr_requested
    }

    /// spec §5.6 "runnable". The probe is the only condition needing no buffer room.
    /// An owed SHUT_WR keeps the relay runnable until `take_owed_shutdown`
    /// takes it, so the shard must call that after every pump (else it spins).
    pub fn is_runnable(&self) -> bool {
        self.open()
            && ((!self.to_quic.is_empty() && self.stream_writable)
                || (self.stream_readable && self.to_tcp.space() > 0 && !self.stream_gone)
                || self.reset_probe
                || (self.fin_owed() && self.stream_writable)
                || self.shut_wr_owed())
    }

    /// spec §5.6: (0) reset probe, (a) TCP → QUIC, (b) QUIC → TCP, (c) SHUT_WR
    /// (taken by `take_owed_shutdown`, which the shard calls after every pump).
    /// Each direction stops on `Blocked`, on a result that moved nothing, or
    /// after `budget_per_dir` bytes.
    pub fn pump(
        &mut self,
        t: &mut dyn TransportOps,
        now: Time,
        budget_per_dir: usize,
    ) -> PumpOutcome {
        let mut progressed = false;
        // (0) spec §5.6/§4.2: zero-capacity recv, regardless of `to_tcp` space.
        if self.open() && self.reset_probe {
            self.reset_probe = false;
            progressed = true;
            match t.stream_recv(now, self.stream, &mut []) {
                // (0, fin): the read side is (now) finished.
                Ok((_, true)) => {
                    self.fin_seen = true;
                    self.stream_readable = false;
                }
                // Blocked (or nothing moved): the read latch stays.
                Ok((_, false)) | Err(StreamError::Blocked) => {}
                Err(_) => self.abort(),
            }
        }
        progressed |= self.pump_to_quic(t, now, budget_per_dir);
        progressed |= self.pump_to_tcp(t, now, budget_per_dir);
        // (c) is reported by `take_owed_shutdown`.
        self.check_clean();
        match self.state {
            RelayState::Closed(e) => PumpOutcome::Closed(e),
            RelayState::Open if progressed => PumpOutcome::Progressed,
            RelayState::Open => PumpOutcome::Idle,
        }
    }

    /// spec §5.6 (a): data, the FIN coalesced with the write that drains the
    /// buffer, or a FIN-only write.
    fn pump_to_quic(&mut self, t: &mut dyn TransportOps, now: Time, budget: usize) -> bool {
        let mut left = budget;
        let mut progressed = false;
        while self.open() && self.stream_writable && !self.to_quic.is_empty() && left > 0 {
            let data = self.to_quic.read_slice();
            let chunk = &data[..data.len().min(left)];
            let fin = self.tcp_read_eof && chunk.len() == data.len();
            match t.stream_send(now, self.stream, chunk, fin) {
                Ok(n) => {
                    let n = n.min(chunk.len());
                    let short = n < chunk.len();
                    self.fin_sent |= fin && !short;
                    self.to_quic.consume(n);
                    left -= n;
                    progressed |= n > 0 || self.fin_sent;
                    if short {
                        self.stream_writable = false;
                    }
                }
                Err(StreamError::Blocked) => self.stream_writable = false,
                Err(_) => self.abort(),
            }
        }
        if self.open() && self.stream_writable && self.fin_owed() {
            match t.stream_send(now, self.stream, &[], true) {
                Ok(_) => {
                    self.fin_sent = true;
                    progressed = true;
                }
                Err(StreamError::Blocked) => self.stream_writable = false,
                Err(_) => self.abort(),
            }
        }
        progressed
    }

    /// spec §5.6 (b).
    fn pump_to_tcp(&mut self, t: &mut dyn TransportOps, now: Time, budget: usize) -> bool {
        let mut left = budget;
        let mut progressed = false;
        while self.open()
            && self.stream_readable
            && self.to_tcp.space() > 0
            && !self.stream_gone
            && left > 0
        {
            let buf = self.to_tcp.write_slice();
            let cap = buf.len().min(left);
            match t.stream_recv(now, self.stream, &mut buf[..cap]) {
                Ok((n, fin)) => {
                    debug_assert!(n <= cap, "stream_recv returned more than offered");
                    let n = n.min(cap);
                    self.to_tcp.commit(n);
                    left -= n;
                    progressed |= n > 0 || fin;
                    if fin {
                        self.fin_seen = true;
                        self.stream_readable = false;
                    } else if n == 0 {
                        // Moved nothing: treated as Blocked so the relay cannot spin.
                        self.stream_readable = false;
                    }
                }
                Err(StreamError::Blocked) => self.stream_readable = false,
                Err(_) => self.abort(),
            }
        }
        progressed
    }

    /// spec §5.5 step 5: where the driver reads TCP into. Empty only while
    /// read interest is off.
    pub fn tcp_rx_space(&mut self) -> &mut [u8] {
        self.to_quic.write_slice()
    }

    /// Commits the read and immediately forwards toward the stream (spec §5.5 step 5).
    pub fn tcp_rx_commit(&mut self, r: IoResult, t: &mut dyn TransportOps, now: Time) {
        if !self.open() {
            return;
        }
        match r {
            IoResult::Bytes(n) => self.to_quic.commit(n),
            IoResult::Eof => self.tcp_read_eof = true,
            IoResult::WouldBlock => return,
            IoResult::Error(_) => return self.abort(),
        }
        self.pump_to_quic(t, now, RELAY_BUF);
        self.check_clean();
    }

    /// spec §5.5 step 5: what the driver writes to TCP.
    pub fn tcp_tx_data(&self) -> &[u8] {
        self.to_tcp.read_slice()
    }

    /// spec §5.5 step 5. `Eof` cannot come from a write; it aborts like an error.
    pub fn tcp_tx_commit(&mut self, r: IoResult) {
        if !self.open() {
            return;
        }
        match r {
            IoResult::Bytes(n) => {
                debug_assert!(n <= self.to_tcp.len(), "wrote more than tcp_tx_data");
                self.to_tcp.consume(n.min(self.to_tcp.len()));
            }
            IoResult::WouldBlock => {}
            IoResult::Eof | IoResult::Error(_) => self.abort(),
        }
    }

    /// spec §5.2 "Interest". Never read interest with an empty rx slice (a
    /// zero-length read would be taken for EOF), never write interest with
    /// nothing to write or after the relay closed (a spin).
    pub fn tcp_interest(&self) -> Interest {
        Interest {
            read: self.open()
                && !self.tcp_read_eof
                && self.stream_writable
                && self.to_quic.space() > 0,
            write: self.open() && !self.to_tcp.is_empty(),
        }
    }

    /// spec §5.6 latches and `StreamClosed` handling. Events for other streams
    /// are ignored; `ConnClosed` for the relay's connection aborts it.
    pub fn on_stream_event(&mut self, ev: &Event) {
        if !self.open() {
            return;
        }
        match *ev {
            Event::StreamReadable(s) if s == self.stream && !self.stream_gone => {
                // After FIN the read side is finished: the latch stays clear
                // and only the probe runs (spec §5.6, §4.2).
                self.stream_readable = !self.fin_seen;
                if self.fin_seen || self.to_tcp.space() == 0 {
                    self.reset_probe = true;
                }
            }
            Event::StreamWritable(s) if s == self.stream => self.stream_writable = true,
            Event::StreamClosed(s) if s == self.stream => {
                if self.fin_seen && self.fin_sent {
                    // xquic may close after both FINs with `to_tcp` still full:
                    // keep draining it (aborting would truncate the reply).
                    self.stream_gone = true;
                    self.stream_readable = false;
                    self.reset_probe = false;
                    self.check_clean();
                } else {
                    self.abort();
                }
            }
            Event::ConnClosed(c, _) if c == self.conn => self.abort(),
            _ => {}
        }
    }

    /// spec §5.6 (c): true once, when SHUT_WR is owed; the shard then emits
    /// `TcpShutdownWrite` and calls `shutdown_done`.
    pub fn take_owed_shutdown(&mut self) -> bool {
        let owed = self.open() && self.shut_wr_owed();
        if owed {
            self.shut_wr_requested = true;
        }
        owed
    }

    /// spec §5.6: the TCP write side is shut down.
    pub fn shutdown_done(&mut self) {
        self.tcp_write_shut = true;
        self.check_clean();
    }

    /// `Abort` ⇒ the shard resets the stream and aborts TCP; `Clean` ⇒ graceful close.
    pub fn end_reason(&self) -> Option<RelayEnd> {
        match self.state {
            RelayState::Open => None,
            RelayState::Closed(e) => Some(e),
        }
    }
}

fn push(b: &mut RingBuf, bytes: &[u8]) {
    b.write_slice()[..bytes.len()].copy_from_slice(bytes);
    b.commit(bytes.len());
}
