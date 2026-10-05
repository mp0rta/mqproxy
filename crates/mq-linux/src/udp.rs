//! UDP sockets with GSO (`UDP_SEGMENT`) send and GRO (`UDP_GRO`) batched
//! receive. spec §2.2. IPv4 or IPv6 by the bind address (C supports
//! `AF_INET6` QUIC paths). An IPv6 socket is dual-stack (`IPV6_V6ONLY` = 0,
//! as C's default socket): it sends to IPv4 destinations as v4-mapped
//! addresses and reports IPv4 peers as `SocketAddr::V4`. An IPv4 socket
//! sends only to IPv4.
//!
//! Every OS error is returned to the caller unchanged: the driver owns the
//! GSO-off decision (spec §5.3), so this layer never retries or degrades.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::sockopt::{cvt, from_sockaddr_storage, setsockopt_int, sockaddr_storage};

/// Kernel per-call segment limit we commit to (`UDP_MAX_SEGMENTS` was 64
/// before Linux 6.x raised it; we keep the portable value). spec §5.3.
pub const MAX_GSO_SEGMENTS: usize = 64;
/// IPv4 UDP payload maximum; also the cap for IPv6 (whose maximum, 65527,
/// is larger), so one conservative limit serves both families.
pub const MAX_GSO_BYTES: usize = 65507;

/// Room per received message: the largest GRO-coalesced payload.
const SLOT: usize = 65535;
/// Messages per `recvmmsg`.
const BATCH: usize = 16;
/// `SO_SNDBUF` / `SO_RCVBUF` request, mqvpn's value.
const SOCKET_BUF_BYTES: libc::c_int = 1 << 20;

/// One received datagram. `range` indexes the caller's buffer, so the buffer
/// and the `Vec<RecvMeta>` are reusable across calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvMeta {
    pub src: SocketAddr,
    pub local: SocketAddr,
    pub range: Range<usize>,
}

/// Non-blocking UDP socket with `UDP_GRO` and `IP_PKTINFO` (IPv4) or
/// `IPV6_RECVPKTINFO` (IPv6) enabled.
#[derive(Debug)]
pub struct UdpSocket {
    inner: std::net::UdpSocket,
    port: u16,
    v4: bool,
}

impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl UdpSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let inner = if addr.is_ipv4() {
            std::net::UdpSocket::bind(addr)?
        } else {
            bind_dual_stack(addr)?
        };
        inner.set_nonblocking(true)?;
        let fd = inner.as_raw_fd();
        setsockopt_int(fd, libc::SOL_UDP, libc::UDP_GRO, 1)?;
        // As mqvpn: the 208 KiB default send buffer fills in ~2 ms at 900 Mbps and every
        // EAGAIN behind it makes xquic retry. The kernel caps this at net.core.{w,r}mem_max.
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, SOCKET_BUF_BYTES)?;
        setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, SOCKET_BUF_BYTES)?;
        if addr.is_ipv4() {
            setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
        } else {
            setsockopt_int(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
        }
        let port = inner.local_addr()?.port();
        Ok(Self {
            inner,
            port,
            v4: addr.is_ipv4(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// One `sendmsg` with a `UDP_SEGMENT` cmsg: the kernel splits `payload`
    /// into `segment_size` datagrams (the last may be shorter).
    /// `InvalidInput` above `MAX_GSO_BYTES` / `MAX_GSO_SEGMENTS`, for a zero
    /// segment size or for an IPv6 destination on an IPv4 socket; any OS
    /// error (incl. `WouldBlock`, `EIO`, `EINVAL`, `EMSGSIZE`) is returned
    /// as is.
    pub fn send_gso(&self, dst: SocketAddr, segment_size: usize, payload: &[u8]) -> io::Result<()> {
        let seg = u16::try_from(segment_size).ok().filter(|&s| s > 0);
        let Some(seg) = seg else {
            return Err(invalid("segment_size must be in 1..=65535"));
        };
        if payload.len() > MAX_GSO_BYTES || payload.len().div_ceil(segment_size) > MAX_GSO_SEGMENTS
        {
            return Err(invalid("GSO batch exceeds 64 segments or 65507 bytes"));
        }
        let (mut name, namelen) = sockaddr_storage(self.dst(dst)?);
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut _,
            iov_len: payload.len(),
        };
        let mut ctrl = [0u64; 4]; // 32 bytes, 8-aligned: >= CMSG_SPACE(2)
        // SAFETY: an all-zero msghdr is valid.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = &mut name as *mut _ as *mut _;
        msg.msg_namelen = namelen;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl.as_mut_ptr() as *mut _;
        // SAFETY: CMSG_SPACE is pure arithmetic.
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<u16>() as _) } as _;
        // SAFETY: msg_control points at `ctrl`, which is aligned and at least
        // msg_controllen bytes, so CMSG_FIRSTHDR is non-null and the header plus
        // a u16 of data fit inside it.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_UDP;
            (*c).cmsg_type = libc::UDP_SEGMENT;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<u16>() as _) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut u16, seg);
        }
        // SAFETY: every pointer in `msg` refers to a live local or to `payload`.
        let n = unsafe { libc::sendmsg(self.as_raw_fd(), &msg, 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// One plain `sendto`.
    pub fn send_one(&self, dst: SocketAddr, payload: &[u8]) -> io::Result<()> {
        self.inner.send_to(payload, self.dst(dst)?).map(drop)
    }

    /// `dst` in this socket's family: v4-mapped on an IPv6 socket.
    fn dst(&self, dst: SocketAddr) -> io::Result<SocketAddr> {
        match dst {
            SocketAddr::V4(a) if !self.v4 => Ok((a.ip().to_ipv6_mapped(), a.port()).into()),
            SocketAddr::V6(_) if self.v4 => Err(invalid("IPv6 destination on an IPv4 socket")),
            _ => Ok(dst),
        }
    }

    /// One `recvmmsg` pass into `buf` (up to 16 slots of 65535 bytes; `buf`
    /// must hold at least one slot). Appends one `RecvMeta` per datagram,
    /// splitting GRO-coalesced payloads at the `UDP_GRO` segment size (a
    /// zero-length datagram gets one meta with an empty `range`), and
    /// returns the bytes received. `WouldBlock` when nothing is readable, with
    /// `out` unchanged. A single syscall, so a call either appends a whole
    /// batch or fails; an error the kernel hit after some messages is reported
    /// by the next call, and what earlier calls appended stays in `out`.
    pub fn recv_batch(&self, buf: &mut [u8], out: &mut Vec<RecvMeta>) -> io::Result<usize> {
        let slots = (buf.len() / SLOT).min(BATCH);
        if slots == 0 {
            return Err(invalid("recv_batch buffer smaller than 65535 bytes"));
        }
        // SAFETY: all-zero is valid for these plain C structs.
        let mut names: [libc::sockaddr_storage; BATCH] = unsafe { zeroed() };
        let mut iovs: [libc::iovec; BATCH] = unsafe { zeroed() };
        let mut hdrs: [libc::mmsghdr; BATCH] = unsafe { zeroed() };
        // 64 bytes each >= CMSG_SPACE(int) + CMSG_SPACE(in6_pktinfo) = 24 + 40
        // (and > CMSG_SPACE(int) + CMSG_SPACE(in_pktinfo) = 24 + 32).
        let mut ctrls = [[0u64; 8]; BATCH];
        for i in 0..slots {
            iovs[i] = libc::iovec {
                iov_base: buf[i * SLOT..].as_mut_ptr() as *mut _,
                iov_len: SLOT,
            };
            let h = &mut hdrs[i].msg_hdr;
            h.msg_name = &mut names[i] as *mut _ as *mut _;
            h.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
            h.msg_iov = &mut iovs[i];
            h.msg_iovlen = 1;
            h.msg_control = ctrls[i].as_mut_ptr() as *mut _;
            h.msg_controllen = size_of::<[u64; 8]>() as _;
        }
        // SAFETY: each of the first `slots` headers points at live, disjoint
        // name/iov/control storage; the iovs cover disjoint parts of `buf`.
        let n = unsafe {
            libc::recvmmsg(
                self.as_raw_fd(),
                hdrs.as_mut_ptr(),
                slots as _,
                0,
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut total = 0;
        for (i, h) in hdrs.iter().enumerate().take(n as usize) {
            let len = h.msg_len as usize;
            let (stride, dst_ip) = parse_cmsgs(&h.msg_hdr);
            let src = unmap(from_sockaddr_storage(&names[i])?);
            let local = unmap(match dst_ip {
                Some(ip) => SocketAddr::new(ip, self.port),
                None => self.local_addr()?,
            });
            let stride = stride.unwrap_or(len).max(1);
            let base = i * SLOT;
            let mut off = 0;
            // At least once: a zero-length datagram still gets its meta.
            loop {
                let end = (off + stride).min(len);
                out.push(RecvMeta {
                    src,
                    local,
                    range: base + off..base + end,
                });
                off = end;
                if off >= len {
                    break;
                }
            }
            total += len;
        }
        Ok(total)
    }
}

/// Reads the `UDP_GRO` segment size and the `IP_PKTINFO` / `IPV6_PKTINFO`
/// destination address.
fn parse_cmsgs(msg: &libc::msghdr) -> (Option<usize>, Option<IpAddr>) {
    let (mut stride, mut dst) = (None, None);
    // SAFETY: `msg` was filled by recvmmsg; CMSG_FIRSTHDR/CMSG_NXTHDR stay within
    // msg_control..msg_controllen, and the data reads are sized by cmsg type.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(msg);
        while !c.is_null() {
            match ((*c).cmsg_level, (*c).cmsg_type) {
                (libc::SOL_UDP, libc::UDP_GRO) => {
                    let s: libc::c_int = std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const _);
                    stride = Some(s as usize);
                }
                (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                    let p: libc::in_pktinfo =
                        std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const _);
                    dst = Some(Ipv4Addr::from(u32::from_be(p.ipi_addr.s_addr)).into());
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                    let p: libc::in6_pktinfo =
                        std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const _);
                    dst = Some(Ipv6Addr::from(p.ipi6_addr.s6_addr).into());
                }
                _ => {}
            }
            c = libc::CMSG_NXTHDR(msg, c);
        }
    }
    (stride, dst)
}

/// An IPv4 peer of a dual-stack socket arrives v4-mapped; report it as V4
/// so it matches the address the transport dialled.
fn unmap(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v) => match v.ip().to_ipv4_mapped() {
            Some(ip) => (ip, v.port()).into(),
            None => a,
        },
        a => a,
    }
}

/// An `AF_INET6` socket with `IPV6_V6ONLY` = 0 set before `bind` (it cannot
/// change after), so the result does not depend on `net.ipv6.bindv6only`.
fn bind_dual_stack(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    // SAFETY: plain socket(2); the fd is owned immediately below.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh socket we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    setsockopt_int(fd.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, 0)?;
    let (name, len) = sockaddr_storage(addr);
    // SAFETY: `name` holds a sockaddr_in6 of length `len`.
    cvt(unsafe { libc::bind(fd.as_raw_fd(), &name as *const _ as *const _, len) })?;
    Ok(fd.into())
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
