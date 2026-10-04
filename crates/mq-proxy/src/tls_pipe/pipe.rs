//! SP3 spec §7.1: the pipe between an origin socket and hyper. hyper's
//! `Connection` owns its IO object, so the state is shared: `PipeIo` is
//! hyper's end, `PipeHandle` (kept in `OriginConn`) the pump's.

use super::PIPE_CAP;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

#[derive(Debug, Default)]
pub struct PipeState {
    /// Plaintext from the origin, not yet read by hyper (≤ `PIPE_CAP`).
    rx: VecDeque<u8>,
    /// Plaintext hyper wrote, not yet taken by the pump (≤ `PIPE_CAP`).
    tx: Vec<u8>,
    rx_eof: bool,
    /// hyper's `poll_shutdown`: recorded and ignored (§7.3 step 1).
    tx_shutdown: bool,
    /// The conn was removed: reads and writes fail, so every hyper task of
    /// the conn completes on the next pump (§7.7).
    dead: bool,
    /// Bytes handed to hyper since the current request was written — h1 only;
    /// decides `curl:52` vs `56` and the bodiless retry (§7.6, §7.7).
    rx_since_send: u64,
    rx_waker: Option<Waker>,
    tx_waker: Option<Waker>,
}

impl PipeState {
    fn wake_reader(&mut self) {
        if let Some(w) = self.rx_waker.take() {
            w.wake();
        }
    }
}

fn dead_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "origin conn removed")
}

/// The IO end handed to hyper, h2 or rustls. With `peer` set (`pipe_pair`)
/// its writes land in the peer's `rx` instead of its own `tx`.
#[derive(Debug)]
pub struct PipeIo {
    st: Rc<RefCell<PipeState>>,
    peer: Option<Rc<RefCell<PipeState>>>,
}

/// The pump's end of the pipe (cloneable: a `TlsIo` and its conn share it).
#[derive(Clone, Debug)]
pub struct PipeHandle(Rc<RefCell<PipeState>>);

/// A fresh pipe: the IO end and the pump's.
pub fn pipe() -> (PipeIo, PipeHandle) {
    let st = Rc::new(RefCell::new(PipeState::default()));
    let io = PipeIo {
        st: st.clone(),
        peer: None,
    };
    (io, PipeHandle(st))
}

/// Two cross-wired ends for in-memory peers: what one writes the other reads
/// (≤ `PIPE_CAP` in flight), and `poll_shutdown` is the peer's EOF.
#[cfg(any(test, feature = "test-support"))]
pub fn pipe_pair() -> (PipeIo, PipeIo) {
    let a = Rc::new(RefCell::new(PipeState::default()));
    let b = Rc::new(RefCell::new(PipeState::default()));
    let end = |st: &Rc<_>, peer: &Rc<_>| PipeIo {
        st: Rc::clone(st),
        peer: Some(Rc::clone(peer)),
    };
    (end(&a, &b), end(&b, &a))
}

impl PipeHandle {
    /// Appends origin bytes up to `PIPE_CAP`; returns how many were taken.
    pub fn push_rx(&self, bytes: &[u8]) -> usize {
        let mut st = self.0.borrow_mut();
        let n = bytes.len().min(PIPE_CAP - st.rx.len());
        st.rx.extend(&bytes[..n]);
        if n > 0 {
            st.wake_reader();
        }
        n
    }

    /// Plaintext hyper wrote that the pump has not taken yet.
    pub fn tx_len(&self) -> usize {
        self.0.borrow().tx.len()
    }

    /// Free room in `rx`.
    pub fn rx_room(&self) -> usize {
        PIPE_CAP - self.0.borrow().rx.len()
    }

    /// The origin's plaintext stream ended (published once nothing is left
    /// below the pipe, §7.3). Returns whether this call published it.
    pub fn set_eof(&self) -> bool {
        let mut st = self.0.borrow_mut();
        if st.rx_eof {
            return false;
        }
        st.rx_eof = true;
        st.wake_reader();
        true
    }

    /// hyper's `poll_shutdown` was seen (recorded and ignored, §7.3 step 1).
    #[cfg(feature = "test-support")]
    pub fn tx_shutdown(&self) -> bool {
        self.0.borrow().tx_shutdown
    }

    /// Offers the first `max` bytes hyper wrote to `sink`, which returns how
    /// many it accepted; exactly that many leave `tx`, the rest stay in order
    /// (spec §7.3 step 3: plain `tcp_write` is all-or-nothing, rustls's
    /// `writer().write` may take fewer). Returns the accepted count.
    pub fn with_tx(&self, max: usize, sink: impl FnOnce(&[u8]) -> usize) -> usize {
        let mut st = self.0.borrow_mut();
        let len = max.min(st.tx.len());
        let n = sink(&st.tx[..len]);
        assert!(n <= len, "sink accepted more than offered");
        st.tx.drain(..n);
        if n > 0 {
            if let Some(w) = st.tx_waker.take() {
                w.wake();
            }
        }
        n
    }

    /// spec §7.7 "every removal": reads and writes fail from now on.
    pub fn mark_dead(&self) {
        let mut st = self.0.borrow_mut();
        st.dead = true;
        st.wake_reader();
        if let Some(w) = st.tx_waker.take() {
            w.wake();
        }
    }

    pub fn rx_since_send(&self) -> u64 {
        self.0.borrow().rx_since_send
    }

    /// The current request was written (h1).
    pub fn reset_rx_since_send(&self) {
        self.0.borrow_mut().rx_since_send = 0;
    }
}

impl PipeIo {
    /// The one read op behind both trait families: offers the next <= `room`
    /// bytes as the deque's two slices to `put`.
    fn poll_read_with(
        &self,
        cx: &mut Context<'_>,
        room: usize,
        put: impl FnOnce(&[u8], &[u8]),
    ) -> Poll<io::Result<()>> {
        let mut st = self.st.borrow_mut();
        if st.dead {
            return Poll::Ready(Err(dead_err()));
        }
        if st.rx.is_empty() {
            if st.rx_eof {
                return Poll::Ready(Ok(()));
            }
            st.rx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(st.rx.len());
        let (a, b) = st.rx.as_slices();
        let na = n.min(a.len());
        put(&a[..na], &b[..n - na]);
        st.rx.drain(..n);
        st.rx_since_send += n as u64;
        if n > 0 && self.peer.is_some() {
            // a pair's writer parks on the room in *our* rx
            if let Some(w) = st.tx_waker.take() {
                w.wake();
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_write_inner(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.st.borrow().dead {
            return Poll::Ready(Err(dead_err()));
        }
        let Some(peer) = &self.peer else {
            let mut st = self.st.borrow_mut();
            let n = buf.len().min(PIPE_CAP - st.tx.len());
            if n == 0 && !buf.is_empty() {
                st.tx_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            st.tx.extend_from_slice(&buf[..n]);
            return Poll::Ready(Ok(n));
        };
        let mut p = peer.borrow_mut();
        let n = buf.len().min(PIPE_CAP - p.rx.len());
        if n == 0 && !buf.is_empty() {
            p.tx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        p.rx.extend(&buf[..n]);
        if n > 0 {
            p.wake_reader();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_shutdown_inner(&self) -> Poll<io::Result<()>> {
        self.st.borrow_mut().tx_shutdown = true;
        if let Some(peer) = &self.peer {
            let mut p = peer.borrow_mut();
            p.rx_eof = true;
            p.wake_reader();
        }
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Read for PipeIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let room = buf.remaining();
        self.poll_read_with(cx, room, |a, b| {
            buf.put_slice(a);
            buf.put_slice(b);
        })
    }
}

impl hyper::rt::Write for PipeIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_inner(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_inner()
    }
}

impl tokio::io::AsyncRead for PipeIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let room = buf.remaining();
        self.poll_read_with(cx, room, |a, b| {
            buf.put_slice(a);
            buf.put_slice(b);
        })
    }
}

impl tokio::io::AsyncWrite for PipeIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_inner(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::rt::{Read, Write};
    use std::sync::Arc;
    use std::task::Wake;

    struct Flag(std::sync::atomic::AtomicBool);
    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn flag() -> (Arc<Flag>, Waker) {
        let f = Arc::new(Flag(Default::default()));
        (f.clone(), Waker::from(f))
    }

    fn woke(f: &Flag) -> bool {
        f.0.swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// One `poll_read` into a `cap`-byte buffer: `None` = Pending.
    fn read(io: &mut PipeIo, cx: &mut Context<'_>, cap: usize) -> Option<io::Result<Vec<u8>>> {
        let mut store = vec![0; cap];
        let mut rb = hyper::rt::ReadBuf::new(&mut store);
        match Pin::new(io).poll_read(cx, rb.unfilled()) {
            Poll::Pending => None,
            Poll::Ready(r) => Some(r.map(|()| rb.filled().to_vec())),
        }
    }

    fn write(io: &mut PipeIo, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(io).poll_write(cx, b)
    }

    #[test]
    fn pipe_read_pending_then_bytes_then_eof() {
        let (mut io, h) = pipe();
        let (f, w) = flag();
        let mut cx = Context::from_waker(&w);
        assert!(
            read(&mut io, &mut cx, 16).is_none(),
            "empty, no eof → Pending"
        );
        assert_eq!(h.push_rx(b"hello world"), 11);
        assert!(woke(&f), "push_rx wakes the parked reader");
        assert_eq!(read(&mut io, &mut cx, 5).unwrap().unwrap(), b"hello");
        assert_eq!(read(&mut io, &mut cx, 16).unwrap().unwrap(), b" world");
        h.set_eof();
        assert_eq!(
            read(&mut io, &mut cx, 16).unwrap().unwrap(),
            b"",
            "eof → 0 bytes"
        );
        assert_eq!(read(&mut io, &mut cx, 16).unwrap().unwrap(), b"");
    }

    #[test]
    fn pipe_write_pending_at_cap_64k() {
        let (mut io, h) = pipe();
        let (f, w) = flag();
        let mut cx = Context::from_waker(&w);
        let big = vec![7u8; PIPE_CAP + 100];
        assert!(matches!(write(&mut io, &mut cx, &big), Poll::Ready(Ok(n)) if n == PIPE_CAP));
        assert!(write(&mut io, &mut cx, b"x").is_pending(), "full → Pending");
        assert_eq!(h.with_tx(16 * 1024, |s| s.len()), 16 * 1024);
        assert!(woke(&f), "consuming wakes the parked writer");
        assert!(matches!(write(&mut io, &mut cx, &big), Poll::Ready(Ok(n)) if n == 16 * 1024));
        assert_eq!(h.with_tx(usize::MAX, |s| s.len()), PIPE_CAP);
        assert_eq!(h.with_tx(usize::MAX, |s| s.len()), 0);
        assert!(Pin::new(&mut io).poll_flush(&mut cx).is_ready());
        assert!(Pin::new(&mut io).poll_shutdown(&mut cx).is_ready());
    }

    #[test]
    fn pipe_dead_errors_reads_and_writes() {
        let (mut io, h) = pipe();
        let (f, w) = flag();
        let mut cx = Context::from_waker(&w);
        assert!(read(&mut io, &mut cx, 16).is_none());
        h.push_rx(b"left over");
        woke(&f);
        h.mark_dead();
        let e = read(&mut io, &mut cx, 16).unwrap().unwrap_err();
        assert_eq!(
            e.kind(),
            io::ErrorKind::BrokenPipe,
            "dead beats buffered bytes"
        );
        assert!(matches!(write(&mut io, &mut cx, b"x"), Poll::Ready(Err(_))));
        // a writer parked on a full pipe is woken by the death
        let (mut io, h) = pipe();
        assert!(write(&mut io, &mut cx, &vec![0; PIPE_CAP]).is_ready());
        assert!(write(&mut io, &mut cx, b"x").is_pending());
        h.mark_dead();
        assert!(woke(&f));
        assert!(matches!(write(&mut io, &mut cx, b"x"), Poll::Ready(Err(_))));
    }

    #[test]
    fn pipe_rx_since_send_counts() {
        let (mut io, h) = pipe();
        let mut cx = Context::from_waker(Waker::noop());
        h.push_rx(&[1; 10]);
        assert_eq!(
            h.rx_since_send(),
            0,
            "counts bytes handed to hyper, not pushed"
        );
        read(&mut io, &mut cx, 4).unwrap().unwrap();
        assert_eq!(h.rx_since_send(), 4);
        h.reset_rx_since_send();
        read(&mut io, &mut cx, 16).unwrap().unwrap();
        assert_eq!(h.rx_since_send(), 6);
        assert_eq!(
            h.push_rx(&vec![0; PIPE_CAP + 1]),
            PIPE_CAP,
            "rx bounded by PIPE_CAP"
        );
    }

    #[test]
    fn pipe_tx_partial_consume_keeps_rest_in_order() {
        let (mut io, h) = pipe();
        let (f, w) = flag();
        let mut cx = Context::from_waker(&w);
        assert!(write(&mut io, &mut cx, b"0123456789").is_ready());
        // an all-or-nothing sink that refuses the slice leaves tx untouched
        assert_eq!(
            h.with_tx(4, |s| {
                assert_eq!(s, b"0123");
                0
            }),
            0
        );
        assert!(!woke(&f));
        // a sink that takes fewer than offered drops exactly that count
        assert_eq!(
            h.with_tx(6, |s| {
                assert_eq!(s, b"012345");
                2
            }),
            2
        );
        assert_eq!(
            h.with_tx(usize::MAX, |s| {
                assert_eq!(s, b"23456789", "the rest stays in order");
                s.len()
            }),
            8
        );
    }

    #[test]
    fn pipe_read_across_vecdeque_wrap() {
        let (mut io, h) = pipe();
        let mut cx = Context::from_waker(Waker::noop());
        let a: Vec<u8> = (0..200u8).collect();
        // fill to the cap, read all but 10: the live bytes sit at the ring's end
        assert_eq!(h.push_rx(&[9; PIPE_CAP]), PIPE_CAP);
        assert_eq!(h.0.borrow().rx.capacity(), PIPE_CAP);
        let n = PIPE_CAP - 10;
        assert_eq!(read(&mut io, &mut cx, n).unwrap().unwrap().len(), n);
        assert_eq!(h.push_rx(&a[..150]), 150);
        assert!(
            !h.0.borrow().rx.as_slices().1.is_empty(),
            "the ring wrapped"
        );
        let mut want = vec![9; 10];
        want.extend(&a[..30]);
        assert_eq!(
            read(&mut io, &mut cx, 40).unwrap().unwrap(),
            want,
            "one read across the wrap"
        );
        assert_eq!(h.push_rx(&a[150..]), 50);
        assert_eq!(read(&mut io, &mut cx, 1000).unwrap().unwrap(), &a[30..]);
    }

    #[test]
    fn pipe_eof_after_buffered_bytes() {
        let (mut io, h) = pipe();
        let mut cx = Context::from_waker(Waker::noop());
        h.push_rx(b"tail");
        h.set_eof();
        assert_eq!(
            read(&mut io, &mut cx, 2).unwrap().unwrap(),
            b"ta",
            "bytes before eof"
        );
        assert_eq!(read(&mut io, &mut cx, 16).unwrap().unwrap(), b"il");
        assert_eq!(
            read(&mut io, &mut cx, 16).unwrap().unwrap(),
            b"",
            "then the 0-byte read"
        );
    }

    /// spec §2.1: the MITM front polls h2 over a `PipeIo` by hand with the
    /// `Dirty` waker; here both ends are h2 peers over `pipe_pair`.
    #[test]
    fn h2_handshake_over_pipe_pair() {
        use super::super::Dirty;
        use std::future::Future;

        let (a, b) = pipe_pair();
        let server = async move {
            let mut conn = h2::server::handshake(a).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            assert_eq!(req.uri().path(), "/ping");
            let rsp = http::Response::builder().status(200).body(()).unwrap();
            let mut body = respond.send_response(rsp, false).unwrap();
            body.send_data(bytes::Bytes::from_static(b"pong"), true)
                .unwrap();
            while conn.accept().await.is_some() {}
        };
        let client = async move {
            let (send, conn) = h2::client::handshake(b).await.unwrap();
            let req = async move {
                let req = http::Request::get("http://mq.test/ping").body(()).unwrap();
                let (rsp, _) = send.ready().await.unwrap().send_request(req, true).unwrap();
                let rsp = rsp.await.unwrap();
                assert_eq!(rsp.status(), 200);
                let mut body = rsp.into_body();
                let mut got = Vec::new();
                while let Some(chunk) = body.data().await {
                    got.extend_from_slice(&chunk.unwrap());
                }
                assert_eq!(got, b"pong");
            };
            let (_, r) = tokio::join!(req, conn);
            r.unwrap();
        };
        let mut both = std::pin::pin!(async { tokio::join!(server, client) });
        let dirty = Arc::new(Dirty::default());
        let waker = Waker::from(dirty.clone());
        let mut cx = Context::from_waker(&waker);
        for _ in 0..1000 {
            if both.as_mut().poll(&mut cx).is_ready() {
                return;
            }
            assert!(dirty.take(), "pending without a wake would hang");
        }
        panic!("h2 over pipe_pair did not finish");
    }

    #[test]
    fn pipe_pair_backpressure_and_shutdown_eof() {
        let (mut a, mut b) = pipe_pair();
        let (f, w) = flag();
        let mut cx = Context::from_waker(&w);
        assert!(
            matches!(write(&mut a, &mut cx, &vec![1; PIPE_CAP + 9]), Poll::Ready(Ok(n)) if n == PIPE_CAP)
        );
        assert!(write(&mut a, &mut cx, b"x").is_pending(), "peer's rx full");
        assert_eq!(read(&mut b, &mut cx, 10).unwrap().unwrap().len(), 10);
        assert!(woke(&f), "the peer's read wakes the parked writer");
        assert!(Pin::new(&mut a).poll_shutdown(&mut cx).is_ready());
        assert_eq!(
            read(&mut b, &mut cx, PIPE_CAP).unwrap().unwrap().len(),
            PIPE_CAP - 10
        );
        assert_eq!(
            read(&mut b, &mut cx, 1).unwrap().unwrap(),
            b"",
            "shutdown is EOF"
        );
    }
}
