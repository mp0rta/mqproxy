//! spec §5: shared UDP lane pieces — constants, `SessionEnd`, `Counters`.

pub mod defrag;
pub mod preopen;
pub mod send;
pub mod socks5udp;

use mq_runtime::Host;
use mq_wire::frames::{AddrType, UdpErr};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub use mq_wire::udp_msg::UDP_MSG_HDR;

pub const MAX_SESSIONS_PER_CONN: usize = 1024;
pub const NEG_CACHE: Duration = Duration::from_secs(2);
pub const PREAUTH_SENDQ_DGRAMS: usize = 8;
pub const PREAUTH_SENDQ_BYTES: usize = 8 * 1024;
pub const PREOPEN_DGRAMS: usize = 16;
pub const PREOPEN_BYTES: usize = 32 * 1024;
pub const PREOPEN_TTL: Duration = Duration::from_millis(250);
pub const DEFAULT_IDLE: Duration = Duration::from_secs(60);
pub const SESSION_RESP_WAIT: Duration = Duration::from_secs(10);
/// Successful emits between `datagram_mss` refreshes (C `MQ_MSS_REFRESH_INTERVAL`).
pub const MSS_REFRESH: u32 = 64;
/// Per association, live sessions and negative-cache entries together (C `MQ_UDP_ASSOC_MAX_DST`).
pub const MAX_DST_PER_ASSOC: usize = 64;
/// The largest UDP datagram: the `datagram_recv` scratch, and the bound of a reply.
pub(crate) const MAX_DGRAM: usize = 65_535;

/// The host that wire address bytes name (C `srv_resolve_target`); `None` for a
/// wrong address length or a non-UTF-8 name. An empty name is left to the caller.
pub(crate) fn host_of(atype: AddrType, addr: &[u8]) -> Option<Host> {
    Some(match atype {
        AddrType::Ipv4 => Host::Ip(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(addr).ok()?))),
        AddrType::Ipv6 => Host::Ip(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(addr).ok()?))),
        AddrType::Domain => Host::Domain(std::str::from_utf8(addr).ok()?.to_owned()),
    })
}

/// How a session ended, as seen by the owner of its DST mapping.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionEnd {
    /// The server answered the OPEN with an error RESP.
    Refused(UdpErr),
    /// Everything else: idle, reset, connection loss.
    Closed,
}

/// The fields of the `mq_udp_srv:` (§7.3) and `mq_udp_cli:` (§6.5) stats lines; `u32` as C `%u`.
/// The first eight are the server line, the last two exist on the client only.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Counters {
    pub frags_sent: u32,
    pub frags_reassembled: u32,
    pub drops_send_fail: u32,
    pub drops_oversize: u32,
    pub defrag_drops: u32,
    pub preopen_evictions: u32,
    pub drops_preauth: u32,
    pub drops_empty: u32,
    pub drops_unknown_sid: u32,
    pub sendq_evictions: u32,
}
