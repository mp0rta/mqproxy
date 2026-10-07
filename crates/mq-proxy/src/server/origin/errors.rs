// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §7.6: hyper errors → `curl:<n>`, status and `origin_tls`.

use super::response::HeadError;
use super::{OriginFailure, OriginProto, TlsOutcome};
use mq_http::headers::status_from_curl;
use std::error::Error as _;
use std::io;

/// What the public `hyper::Error` predicates can tell apart. hyper's kinds
/// are private and `h2_reason()` is `pub(super)`: there is no h2 class —
/// `map_error` derives the h2 rows from the conn's protocol.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ErrClass {
    Incomplete,
    ParseTooLarge,
    Parse,
    Io,
    Canceled,
    Other,
}

/// `is_parse_too_large` before `is_parse`: it is a sub-kind of it.
pub(super) fn classify(e: &hyper::Error) -> ErrClass {
    if e.is_incomplete_message() {
        ErrClass::Incomplete
    } else if e.is_parse_too_large() {
        ErrClass::ParseTooLarge
    } else if e.is_parse() {
        ErrClass::Parse
    } else if e.is_canceled() {
        ErrClass::Canceled
    } else if e.source().is_some_and(|s| s.is::<io::Error>()) {
        ErrClass::Io
    } else {
        ErrClass::Other
    }
}

/// The §7.6 table for an exchange on a negotiated conn. After the head every
/// class is the same reset marker (`curl:56`): the gateway resets the H3
/// request on `after_head` and only logs the code. `rx_since_send` is h1-only.
/// `cause` names the class; the bridge may replace it with the error text.
pub(super) fn map_error(
    c: ErrClass,
    after_head: bool,
    proto: OriginProto,
    rx_since_send: u64,
    https: bool,
) -> OriginFailure {
    let curl = match (c, after_head, proto) {
        (_, true, _) | (_, false, OriginProto::H2) => 56,
        (ErrClass::ParseTooLarge, ..) => return upstream_protocol(proto, https, "head too large"),
        (ErrClass::Incomplete, ..) if rx_since_send == 0 => 52,
        (ErrClass::Parse, ..) => 8,
        _ => 56,
    };
    OriginFailure {
        curl,
        status: status_from_curl(curl),
        tls: TlsOutcome::failure(https),
        proto: Some(proto),
        upstream_protocol: false,
        start_failed: false,
        cause: format!("{c:?}"),
    }
}

/// A head the gateway cannot relay (§7.5): 502 `upstream-protocol` after
/// negotiating, delivered as `on_failure(.., after_head: false)`.
pub(super) fn head_error(e: HeadError, proto: OriginProto, https: bool) -> OriginFailure {
    let cause = match e {
        HeadError::Upgrade101 => "101 response",
        HeadError::Overflow => "response head over the gateway caps",
    };
    upstream_protocol(proto, https, cause)
}

fn upstream_protocol(proto: OriginProto, https: bool, cause: &str) -> OriginFailure {
    OriginFailure {
        curl: 0,
        status: 502,
        tls: TlsOutcome::failure(https),
        proto: Some(proto),
        upstream_protocol: true,
        start_failed: false,
        cause: cause.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ErrClass::*;
    use OriginProto::{H1, H2};

    const ALL: [ErrClass; 6] = [Incomplete, ParseTooLarge, Parse, Io, Canceled, Other];

    /// (curl, status, upstream_protocol, tls, proto)
    fn row(f: &OriginFailure) -> (u32, u16, bool, TlsOutcome, Option<OriginProto>) {
        (f.curl, f.status, f.upstream_protocol, f.tls, f.proto)
    }

    #[test]
    fn map_error_table() {
        let tls = |https| {
            if https {
                TlsOutcome::ConnectFail
            } else {
                TlsOutcome::Na
            }
        };
        for https in [false, true] {
            let t = tls(https);
            // h1 rows before the head.
            let cases = [
                (Incomplete, 0, 52),
                (Incomplete, 1, 56),
                (Incomplete, 4096, 56),
                (Parse, 0, 8),
                (Parse, 7, 8),
                (Io, 0, 56),
                (Io, 9, 56),
                (Canceled, 0, 56),
                (Other, 3, 56),
            ];
            for (c, rx, curl) in cases {
                let f = map_error(c, false, H1, rx, https);
                assert_eq!(row(&f), (curl, 502, false, t, Some(H1)), "{c:?} rx={rx}");
                assert!(!f.start_failed);
            }
            // h1 head too large for hyper → 502 upstream-protocol.
            let f = map_error(ParseTooLarge, false, H1, 70_000, https);
            assert_eq!(row(&f), (0, 502, true, t, Some(H1)));
            // h2 before the head: curl:56 whatever the class.
            for c in ALL {
                for rx in [0, 5] {
                    let f = map_error(c, false, H2, rx, https);
                    assert_eq!(row(&f), (56, 502, false, t, Some(H2)), "h2 {c:?}");
                }
            }
            // After the head: the reset marker for every class and protocol.
            for proto in [H1, H2] {
                for c in ALL {
                    let f = map_error(c, true, proto, 0, https);
                    assert_eq!(row(&f), (56, 502, false, t, Some(proto)), "{c:?} after");
                }
            }
        }
        assert!(!map_error(Io, false, H1, 0, false).cause.is_empty());
    }

    #[test]
    fn head_error_is_upstream_protocol() {
        for e in [HeadError::Upgrade101, HeadError::Overflow] {
            let f = head_error(e, H1, false);
            assert_eq!(row(&f), (0, 502, true, TlsOutcome::Na, Some(H1)), "{e:?}");
            assert!(!f.start_failed);
            let f = head_error(e, H1, true);
            assert_eq!(row(&f), (0, 502, true, TlsOutcome::ConnectFail, Some(H1)));
            let f = head_error(e, H2, true);
            assert_eq!(row(&f), (0, 502, true, TlsOutcome::ConnectFail, Some(H2)));
        }
    }
}
