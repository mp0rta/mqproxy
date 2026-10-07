// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! Non-blocking `CLOCK_MONOTONIC` timerfd armed at absolute deadlines.
//! spec §2.2.

use crate::sockopt::cvt;
use std::io;
use std::mem::zeroed;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[derive(Debug)]
pub struct TimerFd {
    fd: OwnedFd,
}

impl AsRawFd for TimerFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl TimerFd {
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain timerfd_create(2).
        let fd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh, valid, unowned descriptor.
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Arms at absolute `CLOCK_MONOTONIC` µs. A past deadline fires at once;
    /// 0 is clamped to 1 because an all-zero `it_value` disarms.
    pub fn arm_at_micros(&self, at: u64) -> io::Result<()> {
        let at = at.max(1);
        let value = libc::timespec {
            tv_sec: (at / 1_000_000) as _,
            tv_nsec: ((at % 1_000_000) * 1_000) as _,
        };
        self.settime(libc::TFD_TIMER_ABSTIME, value)
    }

    pub fn disarm(&self) -> io::Result<()> {
        // SAFETY: all-zero is a valid timespec.
        self.settime(0, unsafe { zeroed() })
    }

    /// Expirations since the last read; `WouldBlock` when none.
    pub fn read_expirations(&self) -> io::Result<u64> {
        let mut n: u64 = 0;
        // SAFETY: reads exactly 8 bytes into a live u64.
        let r = unsafe { libc::read(self.as_raw_fd(), &mut n as *mut u64 as *mut _, 8) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n)
    }

    fn settime(&self, flags: libc::c_int, value: libc::timespec) -> io::Result<()> {
        // SAFETY: all-zero is a valid itimerspec (no interval).
        let mut spec: libc::itimerspec = unsafe { zeroed() };
        spec.it_value = value;
        // SAFETY: spec is live; old value not requested.
        cvt(unsafe { libc::timerfd_settime(self.as_raw_fd(), flags, &spec, std::ptr::null_mut()) })
    }
}

/// `clock_gettime(CLOCK_MONOTONIC)` in µs — the timerfd's time base.
pub fn now_monotonic_micros() -> u64 {
    // SAFETY: all-zero is a valid timespec.
    let mut ts: libc::timespec = unsafe { zeroed() };
    // SAFETY: ts is live; CLOCK_MONOTONIC cannot fail.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
}
