//! SP3 spec §7.3–§7.5: the pump — TCP ↔ pipe ↔ rustls, hyper polled with
//! the `Dirty` waker and `ShardExec`, the `PUMP_CAP` budget, EOF ordering —
//! request assignment and send, and response delivery to `BridgeEvents`.

use super::*;
use http_body::Body;
use std::io::{self, Read, Write};

impl Origin {
    /// spec §7.3: steps 1–3 repeated while the `Dirty` flag was set or any
    /// buffer changed, at most `PUMP_CAP` rounds (then a zero-delay
    /// `OriginTimer::Pump` re-enters); step 5 settles after every call.
    pub fn pump(&mut self, cx: &mut Cx<'_>, ev: &mut dyn BridgeEvents) {
        let waker = Waker::from(self.dirty.clone());
        let mut tcx = Context::from_waker(&waker);
        let mut rounds = 0;
        loop {
            self.dirty.take();
            let mut changed = false;
            for id in self.conns.ids() {
                changed |= self.tcp_to_pipe(cx, id, ev);
            }
            // Step 2 in the §7.3 order: handshakes and public `Connection`s,
            // then the executor tasks, then the exchanges.
            for id in self.conns.ids() {
                changed |= self.poll_driver(cx, id, &mut tcx, ev);
            }
            changed |= self.exec.poll_all(&mut tcx);
            for id in self.conns.ids() {
                changed |= self.poll_exchanges(cx, id, &mut tcx, ev);
            }
            for id in self.conns.ids() {
                changed |= self.pipe_to_tcp(cx, id);
            }
            changed |= self.refill(cx, ev);
            changed |= self.rx_movable();
            if !(changed | self.dirty.take()) {
                break;
            }
            rounds += 1;
            if rounds == PUMP_CAP {
                // The shard's runnable check cannot see `Dirty` (§7.3 step 4).
                if !self.timers.values().any(|t| *t == OriginTimer::Pump) {
                    let t = cx.set_timer(Duration::ZERO);
                    self.timers.insert(t, OriginTimer::Pump);
                }
                break;
            }
        }
        self.settle(cx);
    }

    /// Liveness: step 1 stopped for lack of pipe room and hyper has freed
    /// some since; one more round then runs. Spin-safe: the flag is set again
    /// only by a step 1 that fills the pipe.
    fn rx_movable(&self) -> bool {
        self.conns.ids().into_iter().any(|id| {
            let c = self.conns.get(id).expect("live conn");
            !self.closing.contains(&id) && c.rx_blocked && c.io.rx_room() > 0
        })
    }

    /// §7.7 settling point (Task 5.5a).
    fn settle(&mut self, _cx: &mut Cx<'_>) {}

    /// The gateway drained a `Partial` frame: the next pump polls the body again.
    pub fn resume(&mut self, h3: H3ReqId) {
        let Some(&Where::Conn(id)) = self.by_h3.get(&h3) else {
            return;
        };
        let Some(c) = self.conns.get_mut(id) else {
            return;
        };
        for rec in &mut c.reqs {
            if let OriginReq::Assigned { h3: x, held, .. } = rec
                && *x == h3
            {
                *held = false;
            }
        }
    }

    /// §7.3 step 1, TCP → pipe. TLS: `reader()` first, `read_tls` only with
    /// bytes and `wants_read` (a zero-byte read would mark EOF inside
    /// rustls); a TLS error ends the handshake (`curl:35`/`60`, E′) or, after
    /// it, the conn (class E). `rx_eof` is published only once `tcp_rx` and
    /// rustls are empty. Returns whether bytes moved.
    fn tcp_to_pipe(
        &mut self,
        cx: &mut Cx<'_>,
        id: OriginConnId,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        let moved = self.move_in(cx, id, ev);
        if let Some(c) = self.conns.get_mut(id) {
            c.rx_blocked = c.io.rx_room() == 0;
        }
        moved
    }

    /// `tcp_to_pipe` without the `rx_blocked` upkeep.
    fn move_in(&mut self, cx: &mut Cx<'_>, id: OriginConnId, ev: &mut dyn BridgeEvents) -> bool {
        if self.closing.contains(&id) {
            return false; // its socket is gone (class E)
        }
        let Some(c) = self.conns.get_mut(id) else {
            return false;
        };
        let tcp = c.tcp;
        let Some(tls) = c.tls.as_mut() else {
            let n = c.io.push_rx(cx.tcp_rx(tcp));
            if n > 0 {
                cx.tcp_consume(tcp, n);
            }
            let eof = c.tcp_eof && cx.tcp_rx(tcp).is_empty() && c.io.set_eof();
            return n > 0 || eof;
        };
        let connecting = matches!(c.driver, Driver::Tls(_));
        let mut moved = drain_plaintext(tls, &c.io);
        let mut failed = None;
        while tls.wants_read() && !cx.tcp_rx(tcp).is_empty() {
            let mut rx = cx.tcp_rx(tcp);
            match tls.read_tls(&mut rx) {
                Ok(0) => break,
                Ok(n) => cx.tcp_consume(tcp, n),
                // Never "plaintext full" here (`wants_read` requires empty
                // plaintext): the deframer's sticky "message buffer full",
                // e.g. an oversized handshake message. Fatal in both phases;
                // waiting would hang the request.
                Err(e) => {
                    failed = Some(rustls::Error::General(e.to_string()));
                    break;
                }
            }
            moved = true;
            if let Err(e) = tls.process_new_packets() {
                failed = Some(e);
                break;
            }
            moved |= drain_plaintext(tls, &c.io);
        }
        if let Some(e) = failed {
            if connecting {
                let curl = match e {
                    rustls::Error::InvalidCertificate(_) => 60,
                    _ => 35,
                };
                self.fail_conn(cx, id, curl, e.to_string(), ev);
            } else {
                // Fatal and sticky in rustls: the socket is useless (§7.3).
                self.remove(cx, id, Removal::E { abort: true });
            }
            return true;
        }
        let eof = c.tcp_eof && cx.tcp_rx(tcp).is_empty();
        if connecting && !tls.is_handshaking() {
            let proto = match tls.alpn_protocol() {
                Some(b"h2") => OriginProto::H2,
                _ => OriginProto::H1,
            };
            self.begin_hyper(cx, id, proto);
            moved = true;
        } else if connecting && eof {
            let cause = "EOF during the TLS handshake".to_string();
            self.fail_conn(cx, id, 35, cause, ev);
            return true;
        }
        if eof {
            let c = self.conns.get_mut(id).expect("live conn");
            let tls = c.tls.as_mut().expect("TLS conn");
            // `Err` while rustls's plaintext is full: retried on a later pump.
            let _ = tls.read_tls(&mut &[][..]);
            moved |= drain_plaintext(tls, &c.io);
        }
        moved
    }

    /// §7.3 step 3, pipe → TCP, in slices of ≤ `SLICE`. TLS: `write_tls`
    /// whenever `wants_write`, plaintext fed while `out` < 64 KiB. Returns
    /// whether bytes moved.
    fn pipe_to_tcp(&mut self, cx: &mut Cx<'_>, id: OriginConnId) -> bool {
        if self.closing.contains(&id) {
            return false;
        }
        let Some(OriginConn {
            tcp, tls, io, out, ..
        }) = self.conns.get_mut(id)
        else {
            return false;
        };
        let tcp = *tcp;
        let Some(tls) = tls else {
            let mut moved = false;
            while io.with_tx(SLICE, |s| match cx.tcp_write(tcp, s) {
                Ok(()) => s.len(),
                Err(_) => 0,
            }) > 0
            {
                moved = true;
            }
            return moved;
        };
        let before = out.len();
        let mut fed = false;
        loop {
            while tls.wants_write() && tls.write_tls(out).is_ok() {}
            if out.len() >= PIPE_CAP
                || io.with_tx(SLICE, |s| tls.writer().write(s).unwrap_or(0)) == 0
            {
                break;
            }
            fed = true;
        }
        let staged = out.len();
        flush_out(cx, tcp, out);
        fed || staged != before || out.len() != staged
    }

    /// §7.3 step 2 for one conn's driver: a `Handshaking` future (done →
    /// `H1`/`H2` + `send`, the requester assigned and its request sent;
    /// `Err` → `curl:56`, class E′), then the public `Connection` unless held
    /// (5.1b `hold_public_poll`); its completion → `Completed`, `send`
    /// dropped (§7.7). Returns whether the driver changed.
    fn poll_driver(
        &mut self,
        cx: &mut Cx<'_>,
        id: OriginConnId,
        tcx: &mut Context<'_>,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        let Some(c) = self.conns.get_mut(id) else {
            return false;
        };
        let mut changed = false;
        if let Driver::Handshaking(fut) = &mut c.driver {
            match fut.as_mut().poll(tcx) {
                Poll::Pending => return false,
                Poll::Ready(Err(e)) => {
                    self.fail_conn(cx, id, 56, e.to_string(), ev);
                    return true;
                }
                Poll::Ready(Ok(hs)) => {
                    (c.driver, c.send) = match hs {
                        Handshaked::H1(s, conn) => (Driver::H1(conn), Some(Sender::H1(s))),
                        Handshaked::H2(s, conn) => (Driver::H2(conn), Some(Sender::H2(s))),
                    };
                    self.assign(cx, id, ev);
                    changed = true;
                }
            }
        }
        let c = self.conns.get_mut(id).expect("live conn");
        if c.hold_public {
            return changed;
        }
        let done = match &mut c.driver {
            Driver::H1(conn) => conn.as_mut().poll(tcx).is_ready(),
            Driver::H2(conn) => conn.as_mut().poll(tcx).is_ready(),
            _ => false,
        };
        if done {
            c.driver = Driver::Completed;
            c.send = None;
        }
        changed || done
    }

    /// §7.7: the conn's `pending` requester → `Assigned` and its request is
    /// sent (§7.4: built now, in the conn's URI form); `Tm::OriginConnect`
    /// is cancelled.
    fn assign(&mut self, cx: &mut Cx<'_>, id: OriginConnId, ev: &mut dyn BridgeEvents) {
        let c = self.conns.get_mut(id).expect("live conn");
        let Some(OriginReq::Connecting {
            h3,
            timer,
            payload,
            retried,
            ..
        }) = c.pending.take()
        else {
            return;
        };
        if let Some(t) = timer {
            cx.cancel_timer(t);
            self.timers.remove(&t);
        }
        let ConnectingPayload::Stored(stored) = payload else {
            unreachable!("Ready is the h1 retry's payload (Task 5.5b)");
        };
        let proto = c.proto.expect("negotiated");
        let Ok(req) = request::build_request(&stored, proto) else {
            self.by_h3.remove(&h3);
            ev.on_failure(cx, h3, start_failed("request build"), false);
            return;
        };
        let send = c.send.as_mut().expect("H1/H2 driver");
        let fut = send_request(send, req, false);
        match proto {
            OriginProto::H2 => c.active += 1,
            OriginProto::H1 => {
                c.busy = true;
                c.io.reset_rx_since_send();
            }
        }
        c.idle_since = None;
        c.reqs.push(OriginReq::Assigned {
            h3,
            fut: Some(fut),
            body: None,
            upload: stored.body.clone(),
            stored: Some(stored),
            head_seen: false,
            reused: false,
            retried,
            held: false,
            delivered: 0,
            cl: None,
        });
    }

    /// §7.3 step 2 for one conn's exchanges (§7.5): the response future →
    /// `on_response` (or `head_error` / the §7.6 mapping → `on_failure`),
    /// then body frames one at a time until `Pending`, a `Partial` answer
    /// (`held`), the end or an error. An exchange that ended becomes `Ended`.
    fn poll_exchanges(
        &mut self,
        cx: &mut Cx<'_>,
        id: OriginConnId,
        tcx: &mut Context<'_>,
        ev: &mut dyn BridgeEvents,
    ) -> bool {
        let Some(c) = self.conns.get_mut(id) else {
            return false;
        };
        let (Some(proto), https) = (c.proto, c.key.0 == Scheme::Https) else {
            return false;
        };
        let mut changed = false;
        for rec in &mut c.reqs {
            let OriginReq::Assigned {
                h3,
                fut,
                body,
                upload,
                head_seen,
                reused,
                held,
                delivered,
                cl,
                ..
            } = rec
            else {
                continue;
            };
            let h3 = *h3;
            let mut ended = false;
            if let Some(f) = fut
                && let Poll::Ready(r) = f.as_mut().poll(tcx)
            {
                *fut = None;
                changed = true;
                match r {
                    Ok(resp) => {
                        let (parts, incoming) = resp.into_parts();
                        match response::normalise(&parts) {
                            Ok(head) => {
                                (*head_seen, *cl, *body) = (true, head.cl, Some(incoming));
                                ev.on_response(cx, h3, head);
                            }
                            Err(e) => {
                                drop(incoming);
                                let f = errors::head_error(e, proto, https);
                                ev.on_failure(cx, h3, f, false);
                                ended = true;
                            }
                        }
                    }
                    // A hand-back (`returned`) is the h1 retry's (Task 5.5b).
                    Err(SendFailure { err, returned }) => {
                        drop(returned);
                        let rx = c.io.rx_since_send();
                        let f = failure(&err, false, proto, rx, https);
                        ev.on_failure(cx, h3, f, false);
                        ended = true;
                    }
                }
            }
            while !*held && let Some(b) = body {
                match Pin::new(b).poll_frame(tcx) {
                    Poll::Pending => break,
                    Poll::Ready(Some(Ok(frame))) => {
                        changed = true;
                        // Trailers are dropped (§7.5).
                        let Ok(data) = frame.into_data() else {
                            continue;
                        };
                        if data.is_empty() {
                            continue;
                        }
                        *delivered += data.len() as u64;
                        *held = matches!(ev.on_body_frame(cx, h3, &data), Accepted::Partial(_));
                    }
                    Poll::Ready(None) => {
                        *body = None;
                        let tls = if https {
                            TlsOutcome::Ok
                        } else {
                            TlsOutcome::Na
                        };
                        let done = Completion {
                            reused: *reused,
                            connect_ms: c.connect_ms,
                            tls,
                            delivered: *delivered,
                            cl: *cl,
                        };
                        ev.on_body_end(cx, h3, done);
                        ended = true;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        *body = None;
                        let rx = c.io.rx_since_send();
                        ev.on_failure(cx, h3, failure(&e, true, proto, rx, https), true);
                        ended = true;
                    }
                }
            }
            if ended {
                // §7.7: settling (Task 5.5a) drops it once `released`.
                let upload = upload.clone();
                *rec = OriginReq::Ended {
                    upload,
                    since: cx.now(),
                };
                changed = true;
            }
        }
        changed
    }

    /// §7.4: the uploads hyper found empty before their fin are refilled by
    /// the gateway (`want_h3`); a refill that added nothing changes nothing.
    fn refill(&mut self, cx: &mut Cx<'_>, ev: &mut dyn BridgeEvents) -> bool {
        let mut wanted = Vec::new();
        for id in self.conns.ids() {
            for rec in &self.conns.get(id).expect("live conn").reqs {
                if let OriginReq::Assigned { h3, upload, .. } = rec
                    && std::mem::take(&mut upload.borrow_mut().want_h3)
                {
                    wanted.push((*h3, upload.clone()));
                }
            }
        }
        let mut changed = false;
        for (h3, upload) in wanted {
            let state = |u: &UploadBuf| (u.data.len(), u.fin, u.is_aborted());
            let before = state(&upload.borrow());
            ev.want_h3(cx, h3);
            changed |= state(&upload.borrow()) != before;
        }
        changed
    }
}

/// §7.6 for an exchange on a negotiated conn, with hyper's error text.
fn failure(
    e: &hyper::Error,
    after_head: bool,
    proto: OriginProto,
    rx_since_send: u64,
    https: bool,
) -> OriginFailure {
    let c = errors::classify(e);
    OriginFailure {
        cause: e.to_string(),
        ..errors::map_error(c, after_head, proto, rx_since_send, https)
    }
}

/// §7.4/§7.7: `try_send_request` on a reused h1 conn (hyper may hand the
/// request back), `send_request` otherwise; the future is boxed as §7.1.
fn send_request(send: &mut Sender, req: Request<UploadBody>, reused: bool) -> ResponseFut {
    let plain = |err| SendFailure {
        err,
        returned: None,
    };
    match send {
        Sender::H1(s) if reused => {
            let f = s.try_send_request(req);
            Box::pin(async move {
                f.await.map_err(|mut e| SendFailure {
                    returned: e.take_message(),
                    err: e.into_error(),
                })
            })
        }
        Sender::H1(s) => {
            let f = s.send_request(req);
            Box::pin(async move { f.await.map_err(plain) })
        }
        Sender::H2(s) => {
            let f = s.send_request(req);
            Box::pin(async move { f.await.map_err(plain) })
        }
    }
}

/// §7.3 step 1: rustls's plaintext → `rx` while the pipe has room; a
/// `close_notify` (`Ok(0)`) or a close_notify-less EOF (`UnexpectedEof`,
/// after the buffered plaintext) publishes `rx_eof`. Returns whether
/// anything moved.
fn drain_plaintext(tls: &mut rustls::ClientConnection, io: &PipeHandle) -> bool {
    let mut buf = [0u8; SLICE];
    let mut moved = false;
    loop {
        let room = io.rx_room().min(SLICE);
        if room == 0 {
            return moved;
        }
        match tls.reader().read(&mut buf[..room]) {
            Ok(0) => return io.set_eof() || moved,
            Ok(n) => {
                io.push_rx(&buf[..n]);
                moved = true;
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return io.set_eof() || moved,
            Err(_) => return moved, // WouldBlock: nothing buffered
        }
    }
}

/// §7.3 step 3: `tcp_write` is all-or-nothing, so `out` goes in slices of
/// ≤ `SLICE` until one does not fit; the rest waits for `on_tcp_writable`.
fn flush_out(cx: &mut Cx<'_>, tcp: TcpId, out: &mut Vec<u8>) {
    let mut sent = 0;
    for chunk in out.chunks(SLICE) {
        if cx.tcp_write(tcp, chunk).is_err() {
            break;
        }
        sent += chunk.len();
    }
    out.drain(..sent);
}

#[cfg(test)]
mod tests {
    use super::super::tests::{NoEvents, bare_conn, test_origin};
    use super::*;
    use mq_runtime::testing::{RecordingApp, ScriptedTransport};
    use mq_runtime::{Host, IoResult, Shard};
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr};

    const NOW: Time = Time(1);

    /// A shard with one live app socket whose `tcp_rx` holds `rx`.
    fn socket_with_rx(rx: &[u8]) -> (Shard<ScriptedTransport, RecordingApp>, TcpId) {
        let (t, _) = ScriptedTransport::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        let mut sh = Shard::new(t, RecordingApp::new().0, addr, 7);
        let target = Target {
            host: Host::Ip(addr.ip()),
            port: 80,
        };
        let op = sh.with_app(NOW, |_, cx| cx.dial(target, Duration::from_secs(1)));
        let tcp = sh.on_dial_result(NOW, op, Ok(addr)).expect("a live dial");
        if !rx.is_empty() {
            sh.tcp_rx_buf(tcp)[..rx.len()].copy_from_slice(rx);
            sh.tcp_rx_commit(NOW, tcp, IoResult::Bytes(rx.len()));
        }
        (sh, tcp)
    }

    /// spec §7.3: plain `rx_eof` waits until `tcp_rx` is empty, even when
    /// the pipe is full and nothing moves (an end-to-end test cannot see an
    /// early EOF: each round refills the pipe before hyper reads again).
    #[test]
    fn plain_eof_waits_for_tcp_rx() {
        let (mut sh, tcp) = socket_with_rx(b"abc");
        let now = NOW;
        let mut origin = test_origin();
        sh.with_app(now, |_, cx| {
            let id = origin.conns.insert(|id| OriginConn {
                tcp,
                tcp_eof: true,
                ..bare_conn(id)
            });
            let c = origin.conns.get(id).unwrap();
            assert_eq!(c.io.push_rx(&[0; PIPE_CAP]), PIPE_CAP, "pipe full");
            assert!(
                !origin.tcp_to_pipe(cx, id, &mut NoEvents),
                "nothing moved, no EOF while tcp_rx holds bytes"
            );
            assert_eq!(cx.tcp_rx(tcp), b"abc");
            cx.tcp_consume(tcp, 3);
            assert!(origin.tcp_to_pipe(cx, id, &mut NoEvents), "now published");
            assert!(!origin.conns.get(id).unwrap().io.set_eof(), "already set");
        });
    }

    /// Moves every pending TLS record from `a` to `b`.
    fn xfer(a: &mut rustls::Connection, b: &mut rustls::Connection) {
        let mut buf = Vec::new();
        while a.wants_write() {
            a.write_tls(&mut buf).unwrap();
        }
        let mut s = &buf[..];
        while !s.is_empty() {
            b.read_tls(&mut s).unwrap();
            b.process_new_packets().unwrap();
        }
    }

    /// A client past its handshake holding `n` bytes of decrypted plaintext
    /// it has not handed out (so `wants_read()` is false).
    fn client_with_plaintext(n: usize) -> rustls::ClientConnection {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let certs = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/certs/");
        let ca = std::path::PathBuf::from(format!("{certs}origin-ca.crt"));
        let ccfg = build_client_config(Some(&ca), &Vec::new).unwrap();
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
        let mut c = rustls::Connection::from(rustls::ClientConnection::new(ccfg, name).unwrap());
        let mut s =
            rustls::Connection::from(rustls::ServerConnection::new(Arc::new(scfg)).unwrap());
        while c.is_handshaking() || s.is_handshaking() {
            xfer(&mut c, &mut s);
            xfer(&mut s, &mut c);
        }
        s.writer().write_all(&vec![9; n]).unwrap();
        xfer(&mut s, &mut c);
        let rustls::Connection::Client(c) = c else {
            unreachable!()
        };
        assert!(!c.wants_read(), "plaintext pending");
        c
    }

    /// §7.3 step 4 liveness: a step 1 that stopped for lack of pipe room
    /// makes the next round run once hyper freed room — whether the rest
    /// waits in `tcp_rx` (plain) or as decrypted plaintext inside rustls
    /// (`wants_read()` false). Spin-safe: no flag without a full pipe.
    #[test]
    fn rx_movable_after_step1_stopped_for_room() {
        let (mut sh, tcp) = socket_with_rx(b"abc");
        let mut origin = test_origin();
        let free_room = |o: &mut Origin, id| o.conns.get_mut(id).unwrap().io = pipe::pipe().1;
        sh.with_app(NOW, |_, cx| {
            // Plain: the rest waits in `tcp_rx`.
            let id = origin.conns.insert(|id| OriginConn {
                tcp,
                driver: Driver::Completed,
                ..bare_conn(id)
            });
            origin.conns.get(id).unwrap().io.push_rx(&[0; PIPE_CAP]);
            origin.tcp_to_pipe(cx, id, &mut NoEvents);
            assert!(!origin.rx_movable(), "blocked, the pipe still full");
            free_room(&mut origin, id);
            assert!(origin.rx_movable(), "plain: room freed");
            assert!(origin.tcp_to_pipe(cx, id, &mut NoEvents));
            assert!(cx.tcp_rx(tcp).is_empty());
            assert!(!origin.rx_movable(), "step 1 did not hit the room limit");
            origin.closing.push(id);
            origin.conns.get_mut(id).unwrap().rx_blocked = true;
            assert!(!origin.rx_movable(), "a closing conn has no socket");
        });
        let (mut sh, tcp) = socket_with_rx(b"");
        let mut origin = test_origin();
        sh.with_app(NOW, |_, cx| {
            // TLS: 10 KiB decrypted, 4 KiB of pipe room.
            let id = origin.conns.insert(|id| OriginConn {
                tcp,
                tls: Some(client_with_plaintext(10 * 1024)),
                driver: Driver::Completed,
                ..bare_conn(id)
            });
            let c = origin.conns.get(id).unwrap();
            c.io.push_rx(&[0; PIPE_CAP - 4096]);
            assert!(origin.tcp_to_pipe(cx, id, &mut NoEvents), "4 KiB moved");
            assert!(!origin.rx_movable(), "blocked, the pipe still full");
            free_room(&mut origin, id);
            assert!(cx.tcp_rx(tcp).is_empty());
            assert!(origin.rx_movable(), "TLS: residual plaintext, room freed");
            assert!(origin.tcp_to_pipe(cx, id, &mut NoEvents), "the 6 KiB rest");
            assert_eq!(origin.conns.get(id).unwrap().io.rx_room(), PIPE_CAP - 6144);
            assert!(!origin.rx_movable(), "drained: no spin");
        });
    }
}
