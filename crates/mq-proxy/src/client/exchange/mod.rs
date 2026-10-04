//! SP4 spec §4: the pull-based H3 exchange core shared by the fetch front and
//! the MITM front. Types only so far; the `Exchanges` state machine follows.

pub mod resp;
pub(crate) mod wire;

use mq_http::headers::{HttpVer, Method, Target};

/// What the request body is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyLen {
    Empty,
    Known(u64),
    Unknown,
}

/// A front-neutral request head. Validated as a whole when rendered
/// (`wire::render`, spec §4.4).
#[derive(Debug)]
pub struct ReqHead {
    /// At most `METHOD_MAX`, case as given; never CONNECT.
    pub method: Method,
    pub target: Target,
    /// `Bearer <token>`.
    pub auth: Vec<u8>,
    /// `x-mq-class`.
    pub class: Option<Vec<u8>>,
    /// Parsed version plus the raw token (the wire carries the token).
    pub origin_proto: Option<(HttpVer, Vec<u8>)>,
    /// Raw valid TTL token (wire identity only).
    pub cache: Option<Vec<u8>>,
    /// Non-empty `X-Mq-Accept-Encoding`.
    pub accept_encoding: Option<Vec<u8>>,
    /// End-to-end headers, filtered by the front.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub body: BodyLen,
}
