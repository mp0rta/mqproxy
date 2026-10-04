//! SP4 spec §2.1: the rustls ⇄ pipe ⇄ TCP pump, generic over the rustls side
//! (client for the origin bridge, server for the MITM conn). The origin
//! pump's TLS logic, moved; one change: ciphertext staging is capped.

use super::{PIPE_CAP, PipeHandle, SLICE};
use mq_runtime::{Cx, TcpId};
use std::io::{self, Read, Write};
use std::ops::DerefMut;

/// The TLS connection, the plaintext pipe and the ciphertext staging `out`
/// (≤ `PIPE_CAP`, SP3 §7.3).
pub struct TlsIo<C> {
    pub tls: C,
    pipe: PipeHandle,
    out: Vec<u8>,
}

/// What one `input` call did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct In {
    /// Bytes of `rx` handed to rustls; the caller `tcp_consume`s them.
    pub consumed: usize,
    /// Bytes moved: TLS records read, plaintext into the pipe, or EOF published.
    pub moved: bool,
    /// This call published the pipe's EOF.
    pub eof_published: bool,
}

/// A `write_tls` sink that takes at most `room` bytes. rustls keeps what the
/// sink does not take (`conn.rs:788`), so a record may straddle the cap.
struct Capped<'a> {
    out: &'a mut Vec<u8>,
    room: usize,
}

impl Write for Capped<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = b.len().min(self.room);
        self.out.extend_from_slice(&b[..n]);
        self.room -= n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<C, D> TlsIo<C>
where
    C: DerefMut<Target = rustls::ConnectionCommon<D>>,
    D: rustls::SideData,
{
    pub fn new(tls: C, pipe: PipeHandle) -> Self {
        TlsIo {
            tls,
            pipe,
            out: Vec::new(),
        }
    }

    pub fn pipe(&self) -> &PipeHandle {
        &self.pipe
    }

    /// TLS in: drain `reader()` first, then `read_tls` from `rx` (never an empty
    /// reader unless `eof`), `process_new_packets`. `eof = true` = TCP read EOF:
    /// one empty `read_tls` after `rx` is exhausted, pipe EOF published once the
    /// buffered plaintext drained (spec §2.1, SP3 §7.3).
    pub fn input(&mut self, mut rx: &[u8], eof: bool) -> Result<In, rustls::Error> {
        let total = rx.len();
        let mut r = In::default();
        self.drain(&mut r);
        while self.tls.wants_read() && !rx.is_empty() {
            match self.tls.read_tls(&mut rx) {
                Ok(0) => break,
                Ok(_) => {}
                // Never "plaintext full" here (`wants_read` requires empty
                // plaintext): the deframer's sticky "message buffer full",
                // e.g. an oversized handshake message. Fatal; waiting would
                // hang the conn.
                Err(e) => return Err(rustls::Error::General(e.to_string())),
            }
            r.moved = true;
            self.tls.process_new_packets()?;
            self.drain(&mut r);
        }
        if eof && rx.is_empty() {
            // A zero-byte `read_tls` marks EOF inside rustls. `Err` while
            // its plaintext is full: retried on a later call.
            let _ = self.tls.read_tls(&mut &[][..]);
            self.drain(&mut r);
        }
        r.consumed = total - rx.len();
        Ok(r)
    }

    /// SP3 §7.3 step 1: rustls's plaintext → the pipe while it has room; a
    /// `close_notify` (`Ok(0)`) or a close_notify-less EOF (`UnexpectedEof`,
    /// after the buffered plaintext) publishes the pipe's EOF.
    fn drain(&mut self, r: &mut In) {
        let mut buf = [0u8; SLICE];
        loop {
            let room = self.pipe.rx_room().min(SLICE);
            if room == 0 {
                return;
            }
            match self.tls.reader().read(&mut buf[..room]) {
                Ok(n) if n > 0 => {
                    self.pipe.push_rx(&buf[..n]);
                    r.moved = true;
                }
                Ok(_) => return self.publish_eof(r),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return self.publish_eof(r),
                Err(_) => return, // WouldBlock: nothing buffered
            }
        }
    }

    fn publish_eof(&mut self, r: &mut In) {
        if self.pipe.set_eof() {
            r.moved = true;
            r.eof_published = true;
        }
    }

    /// TLS out: capped `write_tls` into `out` (room = PIPE_CAP − out.len(); stop on
    /// room 0, Ok(0) or WouldBlock), plaintext fed while room, then `flush_out`.
    /// Returns whether bytes moved.
    pub fn output(&mut self, cx: &mut Cx<'_>, tcp: TcpId) -> bool {
        let before = self.out.len();
        let mut fed = false;
        loop {
            // Bytes `write_tls` produced stay in `out` until TCP takes them;
            // it is only called with room, so none is ever dropped.
            while self.tls.wants_write() {
                let room = PIPE_CAP - self.out.len();
                let sink = &mut Capped {
                    out: &mut self.out,
                    room,
                };
                if room == 0 || !matches!(self.tls.write_tls(sink), Ok(n) if n > 0) {
                    break;
                }
            }
            if self.out.len() >= PIPE_CAP
                || self
                    .pipe
                    .with_tx(SLICE, |s| self.tls.writer().write(s).unwrap_or(0))
                    == 0
            {
                break;
            }
            fed = true;
        }
        let staged = self.out.len();
        self.flush_out(cx, tcp);
        fed || staged != before || self.out.len() != staged
    }

    /// SP3 §7.3 step 3: `tcp_write` is all-or-nothing, so `out` goes in
    /// slices of ≤ `SLICE` until one does not fit; the rest waits for
    /// `on_tcp_writable`.
    fn flush_out(&mut self, cx: &mut Cx<'_>, tcp: TcpId) {
        let mut sent = 0;
        for chunk in self.out.chunks(SLICE) {
            if cx.tcp_write(tcp, chunk).is_err() {
                break;
            }
            sent += chunk.len();
        }
        self.out.drain(..sent);
    }

    /// Room for more: `out` and the pipe's `tx` are both below `PIPE_CAP`.
    pub fn out_has_room(&self) -> bool {
        self.out.len() < PIPE_CAP && self.pipe.tx_len() < PIPE_CAP
    }

    /// Nothing left to send: `out`, the pipe's `tx` and rustls are empty.
    pub fn drained(&self) -> bool {
        self.out.is_empty() && self.pipe.tx_len() == 0 && !self.tls.wants_write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_pipe::{PipeIo, pipe};
    use mq_runtime::testing::{RecordingApp, ScriptedTransport};
    use mq_runtime::{Host, IoResult, Shard, Target};
    use mq_transport_api::Time;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ClientConnection, ServerConnection};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    const NOW: Time = Time(1);

    /// A handshaken in-memory client/server pair (the origin test certs).
    fn handshaken() -> (ClientConnection, ServerConnection) {
        let certs = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/");
        let ca = std::path::PathBuf::from(format!("{certs}origin-ca.crt"));
        let ccfg = crate::server::origin::build_client_config(Some(&ca), &Vec::new).unwrap();
        let chain = CertificateDer::pem_file_iter(format!("{certs}origin.crt"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(format!("{certs}origin.key")).unwrap();
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut c = ClientConnection::new(ccfg, name).unwrap();
        let mut s = ServerConnection::new(Arc::new(scfg)).unwrap();
        while c.is_handshaking() || s.is_handshaking() {
            let mut buf = Vec::new();
            while c.wants_write() {
                c.write_tls(&mut buf).unwrap();
            }
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets().unwrap();
            let mut buf = Vec::new();
            while s.wants_write() {
                s.write_tls(&mut buf).unwrap();
            }
            c.read_tls(&mut &buf[..]).unwrap();
            c.process_new_packets().unwrap();
        }
        (c, s)
    }

    /// A shard with one app socket (`tcp_tx_buf` observes the wire), the
    /// client-side `TlsIo` over it, hyper's pipe end and the server peer.
    struct Rig {
        sh: Shard<ScriptedTransport, RecordingApp>,
        tcp: TcpId,
        io: TlsIo<ClientConnection>,
        hio: PipeIo,
        srv: ServerConnection,
    }

    fn rig() -> Rig {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let target = Target {
            host: Host::Ip(addr.ip()),
            port: 80,
        };
        let op = sh.with_app(NOW, |_, cx| cx.dial(target, Duration::from_secs(1)));
        let tcp = sh.on_dial_result(NOW, op, Ok(addr)).expect("a live dial");
        let (c, srv) = handshaken();
        let (hio, handle) = pipe();
        Rig {
            sh,
            tcp,
            io: TlsIo::new(c, handle),
            hio,
            srv,
        }
    }

    fn cx() -> Context<'static> {
        Context::from_waker(Waker::noop())
    }

    impl Rig {
        fn output(&mut self) -> bool {
            let (io, tcp) = (&mut self.io, self.tcp);
            self.sh.with_app(NOW, |_, cx| io.output(cx, tcp))
        }

        /// Takes up to `n` bytes off the TCP send buffer (the peer's wire).
        fn wire(&mut self, n: usize) -> Vec<u8> {
            let b = self.sh.tcp_tx_buf(self.tcp);
            let v = b[..n.min(b.len())].to_vec();
            self.sh
                .tcp_tx_commit(NOW, self.tcp, IoResult::Bytes(v.len()));
            v
        }

        /// hyper writes plaintext; returns how many bytes the pipe took.
        fn hyper_write(&mut self, b: &[u8]) -> usize {
            match hyper::rt::Write::poll_write(Pin::new(&mut self.hio), &mut cx(), b) {
                Poll::Ready(r) => r.unwrap(),
                Poll::Pending => 0,
            }
        }

        /// Everything hyper can read now (`None` = Pending, `Some(vec![])` = EOF).
        fn hyper_read(&mut self) -> Option<Vec<u8>> {
            let mut out = Vec::new();
            loop {
                let mut store = vec![0; 8192];
                let mut rb = hyper::rt::ReadBuf::new(&mut store);
                match hyper::rt::Read::poll_read(Pin::new(&mut self.hio), &mut cx(), rb.unfilled())
                {
                    Poll::Pending => return (!out.is_empty()).then_some(out),
                    Poll::Ready(r) => {
                        r.unwrap();
                        if rb.filled().is_empty() {
                            return Some(out);
                        }
                        out.extend_from_slice(rb.filled());
                    }
                }
            }
        }

        /// The server peer decrypts `wire` and returns the plaintext.
        fn peer_decrypt(&mut self, mut wire: &[u8]) -> Vec<u8> {
            let mut got = Vec::new();
            while !wire.is_empty() {
                self.srv.read_tls(&mut wire).unwrap();
                self.srv.process_new_packets().unwrap();
                let mut buf = [0; 4096];
                while let Ok(n) = self.srv.reader().read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
            }
            got
        }

        /// The server peer's ciphertext after it wrote `plain`.
        fn peer_send(&mut self, plain: &[u8]) -> Vec<u8> {
            self.srv.writer().write_all(plain).unwrap();
            let mut buf = Vec::new();
            while self.srv.wants_write() {
                self.srv.write_tls(&mut buf).unwrap();
            }
            buf
        }
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// hyper writes more of `data[*at..]` (the pipe takes up to `PIPE_CAP`).
    fn fill(r: &mut Rig, data: &[u8], at: &mut usize) {
        *at += r.hyper_write(&data[*at..]);
    }

    #[test]
    fn output_never_exceeds_pipe_cap() {
        let mut r = rig();
        let data = pattern(4 * PIPE_CAP);
        let mut at = 0;
        // TCP is never drained: its 64 KiB buffer fills, so `out` must stop
        // at the cap while rustls and the pipe keep the rest.
        for _ in 0..16 {
            fill(&mut r, &data, &mut at);
            r.output();
            assert!(r.io.out.len() <= PIPE_CAP, "out = {}", r.io.out.len());
        }
        assert_eq!(r.io.out.len(), PIPE_CAP, "staging filled to the cap");
        assert!(!r.io.drained());
        assert!(!r.io.out_has_room());
    }

    #[test]
    fn tcp_refusing_midway_loses_no_ciphertext() {
        let mut r = rig();
        let data = pattern(300_000);
        let (mut at, mut got) = (0, Vec::new());
        for round in 0..2000 {
            fill(&mut r, &data, &mut at);
            r.output();
            // The wire takes a ragged amount, so TCP keeps refusing midway.
            let w = r.wire(5000 + (round * 7919) % 20_000);
            got.extend(r.peer_decrypt(&w));
            if got.len() == data.len() && r.io.drained() {
                break;
            }
        }
        assert_eq!(got.len(), data.len());
        assert!(got == data, "plaintext intact and in order");
        assert!(r.io.drained());
    }

    #[test]
    fn record_crossing_staging_boundary_completes() {
        let mut r = rig();
        let data = pattern(2 * PIPE_CAP);
        let mut at = 0;
        for _ in 0..4 {
            fill(&mut r, &data, &mut at);
            r.output();
        }
        // 64 KiB is not a whole number of records: the rest of the record
        // that straddles the cap is still inside rustls.
        assert_eq!(r.io.out.len(), PIPE_CAP);
        assert!(r.io.tls.wants_write(), "the straddling record's tail");
        let mut got = Vec::new();
        for _ in 0..200 {
            let w = r.wire(usize::MAX);
            got.extend(r.peer_decrypt(&w));
            fill(&mut r, &data, &mut at);
            r.output();
            if got.len() == data.len() && r.io.drained() {
                break;
            }
        }
        assert!(got == data, "every record decrypts, byte-exact");
    }

    #[test]
    fn zero_room_stops_without_spin() {
        let mut r = rig();
        let data = pattern(2 * PIPE_CAP);
        let mut at = 0;
        for _ in 0..4 {
            fill(&mut r, &data, &mut at);
            r.output();
        }
        assert_eq!(r.io.out.len(), PIPE_CAP);
        assert!(r.io.tls.wants_write());
        // `wants_write` stays true with room 0: each call returns at once
        // and moves nothing.
        for _ in 0..8 {
            assert!(!r.output(), "no room, TCP refusing: nothing moves");
            assert_eq!(r.io.out.len(), PIPE_CAP);
        }
    }

    #[test]
    fn input_drains_reader_before_read_tls() {
        let mut r = rig();
        let first = pattern(10 * 1024);
        let second: Vec<u8> = pattern(2048).iter().map(|b| b ^ 0xff).collect();
        let w1 = r.peer_send(&first);
        let w2 = r.peer_send(&second);
        // 4 KiB of pipe room: part of `first` stays inside rustls, so
        // `wants_read` is false and `w2` must not be read yet.
        r.io.pipe().push_rx(&vec![0; PIPE_CAP - 4096]);
        let a = r.io.input(&w1, false).unwrap();
        assert_eq!(a.consumed, w1.len());
        assert!(a.moved && !a.eof_published);
        let b = r.io.input(&w2, false).unwrap();
        assert_eq!(b.consumed, 0, "reader not empty: no read_tls");
        assert!(!b.moved, "pipe still full");
        // hyper reads the old bytes; the reader drains before more records.
        assert_eq!(r.hyper_read().unwrap().len(), PIPE_CAP);
        let c = r.io.input(&w2, false).unwrap();
        assert_eq!(c.consumed, w2.len());
        let got = r.hyper_read().unwrap();
        let expect: Vec<u8> = first[4096..].iter().chain(&second).copied().collect();
        assert!(got[..] == expect[..], "arrival order kept");
    }

    #[test]
    fn empty_input_without_eof_publishes_nothing() {
        let mut r = rig();
        let i = r.io.input(&[], false).unwrap();
        assert_eq!(i, In::default());
        assert!(r.hyper_read().is_none(), "no EOF, no bytes: Pending");
    }

    #[test]
    fn eof_published_after_buffered_plaintext_drained() {
        let mut r = rig();
        let plain = pattern(10 * 1024);
        let w = r.peer_send(&plain);
        r.io.pipe().push_rx(&vec![0; PIPE_CAP - 4096]);
        let a = r.io.input(&w, true).unwrap();
        assert_eq!(a.consumed, w.len());
        assert!(!a.eof_published, "plaintext still buffered in rustls");
        assert_eq!(r.hyper_read().unwrap().len(), PIPE_CAP);
        let b = r.io.input(&[], true).unwrap();
        assert!(b.eof_published && b.moved);
        let got = r.hyper_read().unwrap();
        assert!(got[..] == plain[4096..], "the rest, then EOF");
        assert_eq!(r.hyper_read(), Some(vec![]));
    }

    #[test]
    fn eof_published_once() {
        let mut r = rig();
        assert!(r.io.input(&[], true).unwrap().eof_published);
        let again = r.io.input(&[], true).unwrap();
        assert!(!again.eof_published && !again.moved);
    }
}
