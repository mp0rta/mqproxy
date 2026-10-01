//! Process helpers. spec §2.2.

use crate::sockopt::cvt;
use std::io;

pub fn geteuid() -> u32 {
    // SAFETY: geteuid(2) cannot fail.
    unsafe { libc::geteuid() }
}

/// Raises the `RLIMIT_NOFILE` soft limit to `n`, capped at the hard limit.
/// Never lowers it.
pub fn set_rlimit_nofile(n: u64) -> io::Result<()> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: rl is live.
    cvt(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) })?;
    let want = (n as libc::rlim_t).min(rl.rlim_max);
    if want <= rl.rlim_cur {
        return Ok(());
    }
    rl.rlim_cur = want;
    // SAFETY: rl is live.
    cvt(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) })
}

/// Sets the `RLIMIT_NOFILE` soft limit to exactly `n` (lowering allowed;
/// capped at the hard limit). Returns the previous soft limit. For tests
/// that provoke `EMFILE`.
pub fn set_rlimit_nofile_exact(n: u64) -> io::Result<u64> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: rl is live.
    cvt(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) })?;
    let prev = rl.rlim_cur;
    rl.rlim_cur = (n as libc::rlim_t).min(rl.rlim_max);
    // SAFETY: rl is live.
    cvt(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) })?;
    Ok(prev)
}
