//! SP3 spec §7.1: the pipe between an origin socket and hyper. hyper's
//! `Connection` owns its IO object, so the state is shared: `HyperIo` is
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

/// hyper's end of the pipe.
#[derive(Debug)]
pub struct HyperIo(Rc<RefCell<PipeState>>);

/// The pump's end of the pipe.
#[derive(Debug)]
pub struct PipeHandle(Rc<RefCell<PipeState>>);

/// A fresh pipe: hyper's end and the pump's.
pub fn pipe() -> (HyperIo, PipeHandle) {
    let st = Rc::new(RefCell::new(PipeState::default()));
    (HyperIo(st.clone()), PipeHandle(st))
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

    /// The origin's plaintext stream ended (published once nothing is left
    /// below the pipe, §7.3).
    pub fn set_eof(&self) {
        let mut st = self.0.borrow_mut();
        st.rx_eof = true;
        st.wake_reader();
    }

    /// Removes and returns up to `max` bytes hyper wrote.
    pub fn take_tx(&self, max: usize) -> Vec<u8> {
        let mut st = self.0.borrow_mut();
        let n = max.min(st.tx.len());
        let out: Vec<u8> = st.tx.drain(..n).collect();
        if n > 0 {
            if let Some(w) = st.tx_waker.take() {
                w.wake();
            }
        }
        out
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

impl hyper::rt::Read for HyperIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut st = self.0.borrow_mut();
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
        let n = buf.remaining().min(st.rx.len());
        let (a, b) = st.rx.as_slices();
        let na = n.min(a.len());
        buf.put_slice(&a[..na]);
        buf.put_slice(&b[..n - na]);
        st.rx.drain(..n);
        st.rx_since_send += n as u64;
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for HyperIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.0.borrow_mut();
        if st.dead {
            return Poll::Ready(Err(dead_err()));
        }
        let n = buf.len().min(PIPE_CAP - st.tx.len());
        if n == 0 && !buf.is_empty() {
            st.tx_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        st.tx.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.borrow_mut().tx_shutdown = true;
        Poll::Ready(Ok(()))
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
    fn read(io: &mut HyperIo, cx: &mut Context<'_>, cap: usize) -> Option<io::Result<Vec<u8>>> {
        let mut store = vec![0; cap];
        let mut rb = hyper::rt::ReadBuf::new(&mut store);
        match Pin::new(io).poll_read(cx, rb.unfilled()) {
            Poll::Pending => None,
            Poll::Ready(r) => Some(r.map(|()| rb.filled().to_vec())),
        }
    }

    fn write(io: &mut HyperIo, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
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
        assert_eq!(h.take_tx(16 * 1024).len(), 16 * 1024);
        assert!(woke(&f), "take_tx wakes the parked writer");
        assert!(matches!(write(&mut io, &mut cx, &big), Poll::Ready(Ok(n)) if n == 16 * 1024));
        assert_eq!(h.take_tx(usize::MAX).len(), PIPE_CAP);
        assert!(h.take_tx(usize::MAX).is_empty());
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
}
