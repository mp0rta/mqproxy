// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! IPv4 TCP listener construction. spec §2.2 / §5.3: `SO_REUSEADDR` and
//! optional `IP_TRANSPARENT` are set before `bind`; backlog 64; non-blocking.

use crate::sockopt::{cvt, setsockopt_int, sockaddr_in};
use std::io;
use std::mem::size_of;
use std::net::{SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Debug, Clone)]
pub struct TcpListenerBuilder {
    addr: SocketAddrV4,
    reuseaddr: bool,
    transparent: bool,
    backlog: i32,
}

impl TcpListenerBuilder {
    pub fn new(addr: SocketAddrV4) -> Self {
        Self {
            addr,
            reuseaddr: true,
            transparent: false,
            backlog: 64,
        }
    }

    pub fn reuseaddr(mut self, on: bool) -> Self {
        self.reuseaddr = on;
        self
    }

    /// `IP_TRANSPARENT` (needs `CAP_NET_ADMIN`; `PermissionDenied` without).
    pub fn transparent(mut self, on: bool) -> Self {
        self.transparent = on;
        self
    }

    pub fn backlog(mut self, n: i32) -> Self {
        self.backlog = n;
        self
    }

    pub fn build(self) -> io::Result<TcpListener> {
        // SAFETY: plain socket(2).
        let raw = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a fresh, valid, unowned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if self.reuseaddr {
            setsockopt_int(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        }
        if self.transparent {
            setsockopt_int(raw, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;
        }
        let sa = sockaddr_in(self.addr);
        // SAFETY: sa is a live sockaddr_in of the stated size.
        cvt(unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sa as *const _ as *const _,
                size_of::<libc::sockaddr_in>() as _,
            )
        })?;
        // SAFETY: plain listen(2) on an owned fd.
        cvt(unsafe { libc::listen(fd.as_raw_fd(), self.backlog) })?;
        Ok(TcpListener::from(fd))
    }
}
