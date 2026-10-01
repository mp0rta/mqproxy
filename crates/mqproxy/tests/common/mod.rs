//! Running-binary helpers: spawn `mqproxy`, watch stderr with a deadline, SIGTERM.
#![allow(dead_code)] // each test binary uses a subset

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

pub const T: Duration = Duration::from_secs(10);

pub fn cert(name: &str) -> String {
    format!("{}/../../tests/certs/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// A free loopback UDP port (bound, then released).
pub fn free_udp() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A free loopback TCP port (bound, then released).
pub fn free_tcp() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub struct Proc {
    pub child: Child,
    rx: Receiver<String>,
    /// Every stderr line seen so far.
    pub lines: Vec<String>,
}

impl Proc {
    pub fn spawn(args: &[&str]) -> Proc {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mqproxy"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn mqproxy");
        let err = child.stderr.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for l in BufReader::new(err).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        Proc {
            child,
            rx,
            lines: Vec::new(),
        }
    }

    /// Reads stderr until a line contains `needle` (panics after `T`).
    pub fn wait_line(&mut self, needle: &str) -> String {
        if let Some(l) = self.lines.iter().find(|l| l.contains(needle)) {
            return l.clone();
        }
        let end = Instant::now() + T;
        while let Some(left) = end.checked_duration_since(Instant::now()) {
            match self.rx.recv_timeout(left) {
                Ok(l) => {
                    self.lines.push(l.clone());
                    if l.contains(needle) {
                        return l;
                    }
                }
                Err(_) => break,
            }
        }
        panic!(
            "no stderr line containing {needle:?}; got {:#?}",
            self.lines
        );
    }

    /// The exit code within `T` (panics otherwise); drains stderr into `lines`.
    pub fn wait_exit(&mut self) -> i32 {
        let end = Instant::now() + T;
        let st = loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                break st;
            }
            if Instant::now() > end {
                let _ = self.child.kill();
                panic!("mqproxy did not exit; stderr {:#?}", self.lines);
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        while let Ok(l) = self.rx.recv_timeout(Duration::from_millis(200)) {
            self.lines.push(l);
        }
        st.code().expect("exited, not killed by a signal")
    }

    /// SIGTERM through kill(1) (the crate forbids unsafe), then the exit code.
    pub fn term(&mut self) -> i32 {
        let ok = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap()
            .success();
        assert!(ok, "kill -TERM failed");
        self.wait_exit()
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
