//! spec §5.4 "App-owned streams": every `StreamReadable` on a stream the app holds
//! is answered with `stream_recv`, in every phase, so xquic can retire a reset
//! stream (§4.2). Shared by the client (§6.2) and the server (§6.3).

use mq_runtime::Cx;
use mq_transport_api::{StreamError, StreamId};

/// spec §6.2: responses are read 1 KiB at a time.
pub(crate) const CHUNK: usize = 1024;

/// The outcome of one `stream_recv`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Recv {
    Data {
        n: usize,
        fin: bool,
    },
    Blocked,
    /// `Err(Reset)` or a dead stream: the stream has been reset; the caller
    /// takes its phase's failure path.
    Failed,
}

/// spec §5.4: one `stream_recv` of at most `cap` bytes appended to `buf`
/// (`cap == 0` is a reset probe).
pub(crate) fn recv(cx: &mut Cx<'_>, s: StreamId, buf: &mut Vec<u8>, cap: usize) -> Recv {
    let at = buf.len();
    buf.resize(at + cap, 0);
    let r = cx.stream_recv(s, &mut buf[at..]);
    let n = *r.as_ref().map(|(n, _)| n).unwrap_or(&0);
    buf.truncate(at + n);
    match r {
        Ok((n, fin)) => Recv::Data { n, fin },
        Err(StreamError::Blocked) => Recv::Blocked,
        Err(_) => {
            cx.stream_reset(s);
            Recv::Failed
        }
    }
}

/// spec §5.4: a settled stream (the control stream after auth): read and
/// discard until `Blocked` or FIN. `false` when the stream failed (and was reset).
pub(crate) fn drain(cx: &mut Cx<'_>, s: StreamId) -> bool {
    let mut scratch = Vec::with_capacity(CHUNK);
    loop {
        scratch.clear();
        match recv(cx, s, &mut scratch, CHUNK) {
            Recv::Data { n, fin: false } if n > 0 => {}
            Recv::Data { .. } | Recv::Blocked => return true,
            Recv::Failed => return false,
        }
    }
}

/// spec §6.2 "Handshake writes": send what is left of `tx`; a partial or
/// blocked write keeps the rest for `StreamWritable`. `false` on a hard error.
pub(crate) fn flush(cx: &mut Cx<'_>, s: StreamId, tx: &mut Vec<u8>) -> bool {
    if tx.is_empty() {
        return true;
    }
    match cx.stream_send(s, tx, false) {
        Ok(n) => {
            tx.drain(..n.min(tx.len()));
            true
        }
        Err(StreamError::Blocked) => true,
        Err(_) => false,
    }
}
