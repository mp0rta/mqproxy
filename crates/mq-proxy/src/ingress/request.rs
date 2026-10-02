//! spec §6.1: the parser result and the 8 KiB ingress input cap shared by both parsers.

use mq_runtime::Target;

/// spec §6.1: a parser looks at no more than this many buffered bytes (C `MQ_LISTENER_RXCAP`).
pub const INGRESS_CAP: usize = 8192;

/// spec §6.1: what one `feed` over the buffered bytes produced. `consumed` counts bytes
/// from the start of the buffer; anything after it (pipelined data) is left for the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress<'a> {
    /// Incomplete; feed again with more bytes (the same prefix included).
    Need,
    /// A complete request for `target`.
    Done { consumed: usize, target: Target },
    /// A complete SOCKS5 UDP ASSOCIATE request; its DST is ignored (RFC 1928).
    Associate { consumed: usize },
    /// Write `bytes`; then close if `close`, else drop `consumed` bytes and feed again.
    Reply {
        consumed: usize,
        bytes: &'a [u8],
        close: bool,
    },
    /// Protocol error: close without writing anything.
    Close,
}

/// spec §6.1: parse at most `INGRESS_CAP` bytes; a full cap without a complete request
/// closes without a reply, as `mq_listener.c:346` does.
pub(crate) fn capped<'a>(buf: &[u8], parse: impl FnOnce(&[u8]) -> Progress<'a>) -> Progress<'a> {
    match parse(&buf[..buf.len().min(INGRESS_CAP)]) {
        Progress::Need if buf.len() >= INGRESS_CAP => Progress::Close,
        p => p,
    }
}
