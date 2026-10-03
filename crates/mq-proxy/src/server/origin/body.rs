//! SP3 spec §7.4: the request body hyper polls. The gateway fills the shared
//! `UploadBuf` from `h3_recv_body` (§6.3); hyper owns the `UploadBody`.

use super::SLICE;
use super::exec::Dirty;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

/// The upload of one request, shared by the gateway, the bridge's record and
/// every `UploadBody` built for it. Built only by `Origin::new_upload`, which
/// hands it the bridge's `Dirty`.
#[derive(Debug)]
pub struct UploadBuf {
    /// Body bytes from H3, not yet yielded to hyper (≤ `UPLOAD_CAP`, the gateway's bound).
    pub data: VecDeque<u8>,
    /// The H3 body reached its fin: `data` is the rest of the body.
    pub fin: bool,
    /// Set by `poll_frame` when it found the buffer empty before `fin`: the
    /// gateway refills it from `h3_recv_body` (§6.3).
    pub want_h3: bool,
    /// The declared `content-length`, when known.
    pub cl: Option<u64>,
    aborted: bool,
    /// `UploadBody`s alive for this buffer (§7.4 `released`).
    live_bodies: u32,
    /// Bytes yielded to hyper so far (for `size_hint`).
    yielded: u64,
    dirty: Arc<Dirty>,
}

impl UploadBuf {
    pub(super) fn new(cl: Option<u64>, dirty: Arc<Dirty>) -> UploadBuf {
        UploadBuf {
            data: VecDeque::new(),
            fin: false,
            want_h3: false,
            cl,
            aborted: false,
            live_bodies: 0,
            yielded: 0,
            dirty,
        }
    }

    /// The upload will not complete: hyper's next poll of the body fails the
    /// request (h1) / resets the stream (h2). Marks `Dirty` — the waker every
    /// hyper task was polled with — so the next pump re-polls it (§7.4).
    pub fn abort(&mut self) {
        self.aborted = true;
        self.dirty.set();
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    /// No `UploadBody` for this buffer is alive: the only proof that hyper
    /// no longer owns the body (§7.4).
    pub fn released(&self) -> bool {
        self.live_bodies == 0
    }

    fn is_end_stream(&self) -> bool {
        self.fin && self.data.is_empty() && !self.aborted
    }
}

/// `http_body::Body` over an `UploadBuf`; frames ≤ `SLICE`.
#[derive(Debug)]
pub struct UploadBody(Rc<RefCell<UploadBuf>>);

impl UploadBody {
    pub fn new(buf: &Rc<RefCell<UploadBuf>>) -> UploadBody {
        buf.borrow_mut().live_bodies += 1;
        UploadBody(buf.clone())
    }
}

impl Drop for UploadBody {
    fn drop(&mut self) {
        self.0.borrow_mut().live_bodies -= 1;
    }
}

impl Body for UploadBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let mut b = self.0.borrow_mut();
        if b.aborted {
            return Poll::Ready(Some(Err(io::Error::other("upload aborted"))));
        }
        if b.data.is_empty() {
            if b.fin {
                return Poll::Ready(None);
            }
            // No waker kept: the refill happens in the pump, which re-polls (§7.3).
            b.want_h3 = true;
            return Poll::Pending;
        }
        let n = b.data.len().min(SLICE);
        let chunk: Bytes = b.data.drain(..n).collect();
        b.yielded += n as u64;
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.borrow().is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let b = self.0.borrow();
        if b.is_end_stream() {
            SizeHint::with_exact(0)
        } else if let Some(cl) = b.cl {
            SizeHint::with_exact(cl.saturating_sub(b.yielded))
        } else {
            SizeHint::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;

    fn buf(cl: Option<u64>) -> (Rc<RefCell<UploadBuf>>, Arc<Dirty>) {
        let d = Arc::new(Dirty::default());
        (Rc::new(RefCell::new(UploadBuf::new(cl, d.clone()))), d)
    }

    fn poll(b: &mut UploadBody) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        Pin::new(b).poll_frame(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn upload_body_pending_sets_want_h3() {
        let (u, _) = buf(None);
        let mut body = UploadBody::new(&u);
        assert!(poll(&mut body).is_pending());
        assert!(u.borrow().want_h3);
        u.borrow_mut().want_h3 = false;
        u.borrow_mut().data.extend(vec![1u8; SLICE + 5]);
        let Poll::Ready(Some(Ok(f))) = poll(&mut body) else {
            panic!("data frame expected")
        };
        assert_eq!(f.into_data().unwrap().len(), SLICE, "frames ≤ SLICE");
        assert!(matches!(poll(&mut body), Poll::Ready(Some(Ok(_)))));
        assert!(!u.borrow().want_h3);
        u.borrow_mut().fin = true;
        assert!(matches!(poll(&mut body), Poll::Ready(None)));
    }

    #[test]
    fn upload_body_abort_yields_err_and_marks_dirty() {
        let (u, d) = buf(None);
        u.borrow_mut().data.extend(b"abc");
        let mut body = UploadBody::new(&u);
        assert!(!d.take());
        u.borrow_mut().abort();
        assert!(d.take(), "abort marks the bridge's Dirty");
        assert!(u.borrow().is_aborted());
        assert!(matches!(poll(&mut body), Poll::Ready(Some(Err(_)))));
        u.borrow_mut().fin = true;
        u.borrow_mut().data.clear();
        assert!(
            !body.is_end_stream(),
            "an aborted body is never a clean end"
        );
    }

    #[test]
    fn upload_body_is_end_stream_bodiless() {
        let (u, _) = buf(None);
        u.borrow_mut().fin = true;
        let body = UploadBody::new(&u);
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        u.borrow_mut().data.extend(b"x");
        assert!(!body.is_end_stream(), "data still queued");
    }

    #[test]
    fn upload_body_size_hint_is_remaining() {
        let (u, _) = buf(Some(10));
        u.borrow_mut().data.extend(b"abcd");
        let mut body = UploadBody::new(&u);
        assert_eq!(body.size_hint().exact(), Some(10));
        assert!(matches!(poll(&mut body), Poll::Ready(Some(Ok(_)))));
        assert_eq!(body.size_hint().exact(), Some(6));
        let (u, _) = buf(None);
        u.borrow_mut().data.extend(b"abcd");
        let body = UploadBody::new(&u);
        assert_eq!(
            body.size_hint().exact(),
            None,
            "unknown length → default hint"
        );
    }

    #[test]
    fn upload_body_live_bodies_counts_drops() {
        let (u, _) = buf(None);
        assert!(u.borrow().released(), "no body built yet");
        let a = UploadBody::new(&u);
        let b = UploadBody::new(&u);
        assert!(!u.borrow().released());
        drop(a);
        assert!(!u.borrow().released(), "the second body still owned");
        drop(b);
        assert!(u.borrow().released());
    }
}
