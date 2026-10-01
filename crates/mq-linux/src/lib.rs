//! spec §2.2

pub mod udp;

pub use udp::{MAX_GSO_BYTES, MAX_GSO_SEGMENTS, RecvMeta, UdpSocket};
