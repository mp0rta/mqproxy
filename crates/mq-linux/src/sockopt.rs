//! Socket options and sockaddr conversion. spec §2.2.
//!
//! `original_dst` reads the pre-NAT destination of a REDIRECTed TCP flow
//! (port of `src/ingress/mq_listener.c`); `set_linger_zero` makes the next
//! close abort with RST (spec §5.2).

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};

/// `original_dst` of a socket: `getsockopt(SOL_IP, SO_ORIGINAL_DST)`. IPv4
/// only in SP1 (an IPv6 flow would need `IP6T_SO_ORIGINAL_DST`).
pub fn original_dst(fd: &impl AsRawFd) -> io::Result<SocketAddr> {
    // SAFETY: all-zero is a valid sockaddr_storage.
    let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
    getsockopt_raw(fd.as_raw_fd(), libc::SOL_IP, libc::SO_ORIGINAL_DST, &mut ss)?;
    from_sockaddr_storage(&ss)
}

/// Pending socket error (`SO_ERROR`), e.g. a non-blocking connect's result.
pub fn so_error(fd: &impl AsRawFd) -> io::Result<Option<io::Error>> {
    let mut v: libc::c_int = 0;
    getsockopt_raw(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_ERROR, &mut v)?;
    Ok((v != 0).then(|| io::Error::from_raw_os_error(v)))
}

/// `SO_LINGER { on, 0 }`: the next close sends RST instead of FIN. spec §5.2.
pub fn set_linger_zero(fd: &impl AsRawFd) -> io::Result<()> {
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    setsockopt_raw(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, &l)
}

pub(crate) fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    v: libc::c_int,
) -> io::Result<()> {
    setsockopt_raw(fd, level, name, &v)
}

fn setsockopt_raw<T>(fd: RawFd, level: libc::c_int, name: libc::c_int, v: &T) -> io::Result<()> {
    // SAFETY: passes a pointer to a live T with its exact size.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            v as *const T as *const _,
            size_of::<T>() as _,
        )
    };
    cvt(r)
}

fn getsockopt_raw<T>(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    v: &mut T,
) -> io::Result<()> {
    let mut len = size_of::<T>() as libc::socklen_t;
    // SAFETY: the kernel writes at most `len` bytes into the live T.
    let r = unsafe { libc::getsockopt(fd, level, name, v as *mut T as *mut _, &mut len) };
    cvt(r)
}

pub(crate) fn cvt(r: libc::c_int) -> io::Result<()> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn sockaddr_in(a: SocketAddrV4) -> libc::sockaddr_in {
    // SAFETY: all-zero is a valid sockaddr_in.
    let mut s: libc::sockaddr_in = unsafe { zeroed() };
    s.sin_family = libc::AF_INET as _;
    s.sin_port = a.port().to_be();
    s.sin_addr.s_addr = u32::from(*a.ip()).to_be();
    s
}

pub(crate) fn from_sockaddr_in(s: &libc::sockaddr_in) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr)),
        u16::from_be(s.sin_port),
    )
}

/// Rejects every family but `AF_INET` (the `unsupported_family` case of
/// `tests/test_origdst.c`).
fn from_sockaddr_storage(ss: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    if ss.ss_family != libc::AF_INET as libc::sa_family_t {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "original_dst: address family not AF_INET",
        ));
    }
    // SAFETY: AF_INET storage holds a sockaddr_in; storage is larger and
    // suitably aligned.
    let sin = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
    Ok(SocketAddr::V4(from_sockaddr_in(sin)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_conversion_rejects_unix_family() {
        // SAFETY: all-zero is a valid sockaddr_storage.
        let mut ss: libc::sockaddr_storage = unsafe { zeroed() };
        ss.ss_family = libc::AF_UNIX as _;
        let e = from_sockaddr_storage(&ss).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);

        ss.ss_family = libc::AF_INET as _;
        assert_eq!(
            from_sockaddr_storage(&ss).unwrap(),
            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
        );
    }
}
