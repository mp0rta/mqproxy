//! UDP sockets with GSO (`UDP_SEGMENT`) send and GRO (`UDP_GRO`) batched
//! receive. spec §2.2. IPv4 only (SP1 needs IPv4); an IPv6 bind returns
//! `Unsupported`.
//!
//! Every OS error is returned to the caller unchanged: the driver owns the
//! GSO-off decision (spec §5.3), so this layer never retries or degrades.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};

use crate::sockopt::{from_sockaddr_in, setsockopt_int, sockaddr_in};

/// Kernel per-call segment limit we commit to (`UDP_MAX_SEGMENTS` was 64
/// before Linux 6.x raised it; we keep the portable value). spec §5.3.
pub const MAX_GSO_SEGMENTS: usize = 64;
/// IPv4 UDP payload maximum.
pub const MAX_GSO_BYTES: usize = 65507;

/// Room per received message: the largest GRO-coalesced payload.
const SLOT: usize = 65535;
/// Messages per `recvmmsg`.
const BATCH: usize = 16;

/// One received datagram. `range` indexes the caller's buffer, so the buffer
/// and the `Vec<RecvMeta>` are reusable across calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecvMeta {
    pub src: SocketAddr,
    pub local: SocketAddr,
    pub range: Range<usize>,
}

/// Non-blocking IPv4 UDP socket with `UDP_GRO` and `IP_PKTINFO` enabled.
#[derive(Debug)]
pub struct UdpSocket {
    inner: std::net::UdpSocket,
    port: u16,
}

impl AsRawFd for UdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl UdpSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        if addr.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mq-linux UDP is IPv4-only",
            ));
        }
        let inner = std::net::UdpSocket::bind(addr)?;
        inner.set_nonblocking(true)?;
        let fd = inner.as_raw_fd();
        setsockopt_int(fd, libc::SOL_UDP, libc::UDP_GRO, 1)?;
        setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
        let port = inner.local_addr()?.port();
        Ok(Self { inner, port })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// One `sendmsg` with a `UDP_SEGMENT` cmsg: the kernel splits `payload`
    /// into `segment_size` datagrams (the last may be shorter).
    /// `InvalidInput` above `MAX_GSO_BYTES` / `MAX_GSO_SEGMENTS` or for a zero
    /// segment size; any OS error (incl. `WouldBlock`, `EIO`, `EINVAL`,
    /// `EMSGSIZE`) is returned as is.
    pub fn send_gso(&self, dst: SocketAddr, segment_size: usize, payload: &[u8]) -> io::Result<()> {
        let seg = u16::try_from(segment_size).ok().filter(|&s| s > 0);
        let Some(seg) = seg else {
            return Err(invalid("segment_size must be in 1..=65535"));
        };
        if payload.len() > MAX_GSO_BYTES || payload.len().div_ceil(segment_size) > MAX_GSO_SEGMENTS
        {
            return Err(invalid("GSO batch exceeds 64 segments or 65507 bytes"));
        }
        let SocketAddr::V4(dst) = dst else {
            return Err(invalid("IPv6 destination on an IPv4 socket"));
        };
        let mut name = sockaddr_in(dst);
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut _,
            iov_len: payload.len(),
        };
        let mut ctrl = [0u64; 4]; // 32 bytes, 8-aligned: >= CMSG_SPACE(2)
        // SAFETY: an all-zero msghdr is valid.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = &mut name as *mut _ as *mut _;
        msg.msg_namelen = size_of::<libc::sockaddr_in>() as _;
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
        self.inner.send_to(payload, dst).map(drop)
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
        let mut names: [libc::sockaddr_in; BATCH] = unsafe { zeroed() };
        let mut iovs: [libc::iovec; BATCH] = unsafe { zeroed() };
        let mut hdrs: [libc::mmsghdr; BATCH] = unsafe { zeroed() };
        let mut ctrls = [[0u64; 8]; BATCH]; // 64 bytes each >= CMSG_SPACE(int) + CMSG_SPACE(in_pktinfo)
        for i in 0..slots {
            iovs[i] = libc::iovec {
                iov_base: buf[i * SLOT..].as_mut_ptr() as *mut _,
                iov_len: SLOT,
            };
            let h = &mut hdrs[i].msg_hdr;
            h.msg_name = &mut names[i] as *mut _ as *mut _;
            h.msg_namelen = size_of::<libc::sockaddr_in>() as _;
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
            let src = SocketAddr::V4(from_sockaddr_in(&names[i]));
            let local = match dst_ip {
                Some(ip) => SocketAddr::new(ip.into(), self.port),
                None => self.local_addr()?,
            };
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

/// Reads the `UDP_GRO` segment size and the `IP_PKTINFO` destination address.
fn parse_cmsgs(msg: &libc::msghdr) -> (Option<usize>, Option<Ipv4Addr>) {
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
                    dst = Some(Ipv4Addr::from(u32::from_be(p.ipi_addr.s_addr)));
                }
                _ => {}
            }
            c = libc::CMSG_NXTHDR(msg, c);
        }
    }
    (stride, dst)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}
