//! SP4 spec §7: the MITM front.

pub mod ca;
pub mod policy;

use mq_runtime::KeepAlive;
use std::time::Duration;

/// SP4 spec Global Constraints: the MITM limits and deadlines. Tests lower
/// them through `MitmConfig.tuning`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MitmTuning {
    pub max_conns: usize,
    pub mstream_max: usize,
    /// Deadline for the ClientHello peek.
    pub peek: Duration,
    /// Deadline for the TLS + h2 handshake.
    pub handshake: Duration,
    /// Idle close, counted only while no stream is open.
    pub idle: Duration,
    /// Send one PING after this much inbound silence (open streams only).
    pub ping_after: Duration,
    /// Close after this much inbound silence (open streams only).
    pub dead_after: Duration,
    /// Closing deadline before `tcp_abort`.
    pub closing: Duration,
    pub keepalive: KeepAlive,
}

impl Default for MitmTuning {
    fn default() -> Self {
        let s = Duration::from_secs;
        Self {
            max_conns: 256,
            mstream_max: 128,
            peek: s(5),
            handshake: s(5),
            idle: s(60),
            ping_after: s(60),
            dead_after: s(90),
            closing: s(1),
            keepalive: KeepAlive {
                idle: s(60),
                interval: s(10),
                count: 3,
                user_timeout: s(90),
            },
        }
    }
}
