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

/// Pins glibc's `M_MMAP_THRESHOLD` so large allocations are always fresh
/// mmaps. Setting it explicitly disables glibc's dynamic raise (to the size
/// of the first freed mmapped chunk), after which large `calloc`s come from
/// the heap and are memset in full. Returns whether the call took effect;
/// always true on non-glibc targets (musl already mmaps large allocations).
pub fn pin_mmap_threshold() -> bool {
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: mallopt(3) only adjusts allocator tunables.
        unsafe { libc::mallopt(libc::M_MMAP_THRESHOLD, 128 * 1024) == 1 }
    }
    #[cfg(not(target_env = "gnu"))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pin_mmap_threshold_takes_effect() {
        assert!(super::pin_mmap_threshold());
    }
}
