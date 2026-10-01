//! spec §5.3 `EMFILE` retry, alone in its binary: it lowers the
//! process-wide `RLIMIT_NOFILE`.

use mq_integration::driver_harness::{DriverHarness, HarnessConfig, install_echo};
use mq_runtime::testing::Recorded;
use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

/// Restores the soft limit even when the test fails.
struct Restore(u64);

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = mq_linux::set_rlimit_nofile_exact(self.0);
    }
}

fn highest_fd() -> u64 {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .max()
        .unwrap()
}

#[test]
fn driver_emfile_pauses_then_resumes_accepting() {
    let mut h = DriverHarness::spawn(HarnessConfig {
        emfile_retry: Duration::from_millis(100),
        ..HarnessConfig::default()
    });
    install_echo(&h.record);
    // Not accepting until a timer, so the client connects (into the backlog)
    // before the descriptor limit is lowered.
    h.record.on(|r, cx| match r {
        Recorded::Start => {
            cx.set_accepting(false);
            cx.set_timer(Duration::from_millis(400));
        }
        Recorded::Timer(_) => cx.set_accepting(true),
        _ => {}
    });
    h.start();
    let mut c = TcpStream::connect(h.listen_addrs[0]).unwrap();

    // No free descriptor at all: the driver's accept fails with EMFILE.
    // Filled twice, so a descriptor another thread (libtest's main thread
    // reads cgroup files at startup) held briefly during the first pass is
    // taken too.
    let _restore = Restore(mq_linux::set_rlimit_nofile_exact(highest_fd() + 16).unwrap());
    let mut fill = Vec::new();
    for _ in 0..2 {
        loop {
            match File::open("/dev/null") {
                Ok(f) => fill.push(f),
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(24), "{e}"); // EMFILE
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    h.wait_for(Duration::from_secs(2), |r| matches!(r, Recorded::Timer(_)))
        .expect("accepting turned on");
    thread::sleep(Duration::from_millis(300)); // several retries, all EMFILE
    assert!(
        !h.record
            .records()
            .iter()
            .any(|r| matches!(r, Recorded::Accepted { .. })),
        "accepted without a free descriptor"
    );

    drop(fill);
    h.wait_for(Duration::from_secs(2), |r| {
        matches!(r, Recorded::Accepted { .. })
    })
    .expect("accepting resumed after the retry");
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c.write_all(b"ping").unwrap();
    let mut b = [0u8; 4];
    c.read_exact(&mut b).unwrap();
    assert_eq!(&b, b"ping");
    drop(c);
    h.shutdown.trigger();
    assert_eq!(h.join(), 0);
}
