// spec §2.2 / §5.2 / §5.3: listener construction and socket options.
use mq_linux::{TcpListenerBuilder, geteuid, original_dst, set_linger_zero, so_error};
use std::io::{ErrorKind, Read};
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

fn loopback() -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
}

fn tcp_socket() -> OwnedFd {
    // SAFETY: plain socket(2).
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    assert!(fd >= 0);
    // SAFETY: fd is a fresh, valid, unowned descriptor.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

#[test]
fn listener_builder_pins_backlog_64() {
    let l = TcpListenerBuilder::new(loopback()).build().unwrap();
    let SocketAddr::V4(addr) = l.local_addr().unwrap() else {
        panic!("not v4")
    };
    // SAFETY: all-zero is a valid sockaddr_in.
    let mut sa: libc::sockaddr_in = unsafe { zeroed() };
    sa.sin_family = libc::AF_INET as _;
    sa.sin_port = addr.port().to_be();
    sa.sin_addr.s_addr = u32::from(*addr.ip()).to_be();

    let socks: Vec<OwnedFd> = (0..70)
        .map(|_| {
            let s = tcp_socket();
            // SAFETY: sa is a live sockaddr_in of the stated size.
            let r = unsafe {
                libc::connect(
                    s.as_raw_fd(),
                    &sa as *const _ as *const _,
                    size_of::<libc::sockaddr_in>() as _,
                )
            };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                assert_eq!(e.raw_os_error(), Some(libc::EINPROGRESS), "{e}");
            }
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(200));
    let mut done = 0;
    for s in &socks {
        let mut pfd = libc::pollfd {
            fd: s.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one live pollfd, zero timeout (the 200 ms wait is above).
        unsafe { libc::poll(&mut pfd, 1, 0) };
        if pfd.revents & libc::POLLOUT != 0 {
            match so_error(s).unwrap() {
                None => done += 1,
                Some(e) => assert_ne!(e.kind(), ErrorKind::ConnectionRefused),
            }
        }
    }
    eprintln!("completed connects: {done}/70");
    assert!((61..=66).contains(&done), "completed {done}");
}

#[test]
fn transparent_requires_cap() {
    if geteuid() == 0 {
        eprintln!("skipped: running as root");
        return;
    }
    let e = TcpListenerBuilder::new(loopback())
        .transparent(true)
        .build()
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
}

#[test]
fn so_error_none_on_fresh_socket() {
    assert!(so_error(&tcp_socket()).unwrap().is_none());
}

#[test]
fn original_dst_unconnected_socket_is_error() {
    let e = original_dst(&tcp_socket()).unwrap_err();
    let errno = e.raw_os_error();
    assert!(
        errno == Some(libc::ENOENT) || errno == Some(libc::ENOPROTOOPT),
        "{e}"
    );
}

#[test]
fn linger_zero_makes_peer_see_reset() {
    let l = TcpListenerBuilder::new(loopback()).build().unwrap();
    let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    l.set_nonblocking(false).unwrap();
    let (a, _) = l.accept().unwrap();
    set_linger_zero(&a).unwrap();
    drop(a);
    let mut buf = [0u8; 8];
    let e = c.read(&mut buf).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionReset, "{e}");
}
