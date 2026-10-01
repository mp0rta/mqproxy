//! spec §6.1: per accepted socket, feed the listener's parser from `tcp_rx`,
//! write its replies with `tcp_write`, and turn read interest off once the
//! request is complete (bytes behind it stay as the prebuffer).

use super::pending::IngressKind;
use super::{HTTP_CONNECT, SOCKS5, TRANSPARENT};
use crate::ingress::{HttpConnectParser, Progress, Socks5Parser};
use mq_runtime::{Cx, ListenerTag, Target, TcpId, TimerId};

/// spec §6.1: which ingress a listener tag is.
pub(super) fn kind_of(l: ListenerTag) -> Option<IngressKind> {
    match l {
        SOCKS5 => Some(IngressKind::Socks5),
        HTTP_CONNECT => Some(IngressKind::HttpConnect),
        TRANSPARENT => Some(IngressKind::Transparent),
        _ => None,
    }
}

enum Parser {
    Socks5(Socks5Parser),
    Http(HttpConnectParser),
}

/// `Progress` without the borrow of the parser.
enum Step {
    Need,
    Done(usize, Target),
    Reply(usize, Vec<u8>, bool),
    Close,
}

fn own(p: Progress<'_>) -> Step {
    match p {
        Progress::Need => Step::Need,
        Progress::Done { consumed, target } => Step::Done(consumed, target),
        Progress::Reply {
            consumed,
            bytes,
            close,
        } => Step::Reply(consumed, bytes.to_vec(), close),
        Progress::Close => Step::Close,
    }
}

/// What one `feed` came to.
pub(super) enum Fed {
    /// Incomplete; wait for more bytes.
    Wait,
    /// Complete; read interest is off.
    Done(Target),
    /// The socket was closed (protocol error, refusal, or the 8 KiB cap).
    Closed,
}

/// spec §6.1: a socket still reading its request (SOCKS5 or HTTP CONNECT).
pub(super) struct Ingress {
    pub(super) kind: IngressKind,
    parser: Parser,
    /// spec §6.1: the 10 s request deadline.
    pub(super) timer: TimerId,
}

impl Ingress {
    /// `None` for transparent capture, which has no parser.
    pub(super) fn new(kind: IngressKind, timer: TimerId) -> Option<Ingress> {
        let parser = match kind {
            IngressKind::Socks5 => Parser::Socks5(Socks5Parser::default()),
            IngressKind::HttpConnect => Parser::Http(HttpConnectParser),
            IngressKind::Transparent => return None,
        };
        Some(Ingress {
            kind,
            parser,
            timer,
        })
    }

    /// spec §6.1: parse what is buffered, consuming and replying as the parser says.
    pub(super) fn feed(&mut self, cx: &mut Cx<'_>, tcp: TcpId) -> Fed {
        loop {
            let step = match &mut self.parser {
                Parser::Socks5(p) => own(p.feed(cx.tcp_rx(tcp))),
                Parser::Http(p) => own(p.feed(cx.tcp_rx(tcp))),
            };
            match step {
                Step::Need => return Fed::Wait,
                Step::Done(consumed, target) => {
                    cx.tcp_consume(tcp, consumed);
                    cx.tcp_set_read(tcp, false);
                    return Fed::Done(target);
                }
                Step::Reply(consumed, bytes, close) => {
                    cx.tcp_consume(tcp, consumed);
                    if cx.tcp_write(tcp, &bytes).is_err() || close {
                        cx.tcp_close(tcp);
                        return Fed::Closed;
                    }
                }
                Step::Close => {
                    cx.tcp_close(tcp);
                    return Fed::Closed;
                }
            }
        }
    }
}
