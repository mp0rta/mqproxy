//! Pure HTTP/1.1 helpers for the gateway (spec §2). No I/O.
#![forbid(unsafe_code)]
pub mod h1;
pub mod headers;
pub mod metrics;
