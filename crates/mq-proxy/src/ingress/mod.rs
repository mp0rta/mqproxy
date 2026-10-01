//! spec §6.1: ingress parsers (SOCKS5, HTTP CONNECT) and transparent capture.

mod http_connect;
mod request;
mod socks5;
mod transparent;

pub use http_connect::{HttpConnectParser, http_error_reply, http_success_reply};
pub use request::{INGRESS_CAP, Progress};
pub use socks5::{Socks5Parser, socks5_error_reply, socks5_success_reply};
pub use transparent::target_from_original_dst;
