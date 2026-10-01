// spec §2.2: timerfd armed at an absolute CLOCK_MONOTONIC deadline.
use mq_linux::{TimerFd, now_monotonic_micros};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

fn poll_in(t: &TimerFd) -> i32 {
    let mut pfd = libc::pollfd {
        fd: t.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live pollfd; the 1 s timeout bounds the test.
    unsafe { libc::poll(&mut pfd, 1, 1000) }
}

#[test]
fn timerfd_not_early() {
    let t = TimerFd::new().unwrap();
    assert_eq!(
        t.read_expirations().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    let start = Instant::now();
    t.arm_at_micros(now_monotonic_micros() + 2_000).unwrap();
    assert_eq!(poll_in(&t), 1, "timer did not fire within 1 s");
    let elapsed = start.elapsed();
    assert!(t.read_expirations().unwrap() >= 1);
    eprintln!("timerfd elapsed: {elapsed:?}");
    assert!(elapsed >= Duration::from_millis(2), "early: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(500), "late: {elapsed:?}");

    // Disarmed timers never fire.
    t.arm_at_micros(now_monotonic_micros() + 50_000).unwrap();
    t.disarm().unwrap();
    assert_eq!(
        t.read_expirations().unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    // A deadline already past (0 is clamped to 1, not a disarm) still fires.
    t.arm_at_micros(0).unwrap();
    assert_eq!(poll_in(&t), 1);
    assert!(t.read_expirations().unwrap() >= 1);
}
