// spec §2.2: UDP GSO/GRO sockets on loopback.
use mq_linux::{MAX_GSO_BYTES, RecvMeta, UdpSocket};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn loopback() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap()
}
fn loopback6() -> UdpSocket {
    UdpSocket::bind("[::1]:0".parse().unwrap()).unwrap()
}

/// Drains `sock` until `want` datagrams arrived (or 2 s pass). Returns the
/// datagrams' (meta, bytes).
fn recv_n(sock: &UdpSocket, want: usize) -> Vec<(RecvMeta, Vec<u8>)> {
    let mut buf = vec![0u8; 16 * 65535];
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while got.len() < want && Instant::now() < deadline {
        let mut out = Vec::new();
        match sock.recv_batch(&mut buf, &mut out) {
            Ok(n) => {
                assert_eq!(n, out.iter().map(|m| m.range.len()).sum::<usize>());
                for w in out.windows(2) {
                    assert!(w[0].range.end <= w[1].range.start, "ranges overlap");
                }
                got.extend(out.into_iter().map(|m| {
                    let bytes = buf[m.range.clone()].to_vec();
                    (m, bytes)
                }));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(out.is_empty());
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("recv_batch: {e}"),
        }
    }
    got
}

// 60 × 1000 bytes: 60 × 1200 = 72000 would exceed MAX_GSO_BYTES (65507).
#[test]
fn gso_send_arrives_as_segments() {
    let (a, b) = (loopback(), loopback());
    let b_addr = b.local_addr().unwrap();
    let mut payload = vec![0u8; 60 * 1000];
    for (i, seg) in payload.chunks_mut(1000).enumerate() {
        seg.fill(i as u8);
    }
    a.send_gso(b_addr, 1000, &payload).unwrap();
    let got = recv_n(&b, 60);
    assert_eq!(got.len(), 60);
    for (i, (meta, bytes)) in got.iter().enumerate() {
        assert_eq!(bytes, &vec![i as u8; 1000], "segment {i}");
        assert_eq!(meta.local, b_addr);
        assert_eq!(meta.src, a.local_addr().unwrap());
    }
}

#[test]
fn gro_recv_reports_each_datagram_with_local_addr() {
    let (a, b) = (loopback(), loopback());
    let b_addr = b.local_addr().unwrap();
    const N: usize = 40;
    for i in 0..N {
        a.send_one(b_addr, &[i as u8; 500]).unwrap();
    }
    let got = recv_n(&b, N);
    assert_eq!(got.len(), N);
    let a_addr: SocketAddr = a.local_addr().unwrap();
    for (i, (meta, bytes)) in got.iter().enumerate() {
        assert_eq!(meta.src, a_addr);
        assert_eq!(meta.local, b_addr);
        assert_eq!(bytes, &vec![i as u8; 500]);
    }
}

#[test]
fn zero_length_datagram_yields_empty_meta() {
    let (a, b) = (loopback(), loopback());
    let b_addr = b.local_addr().unwrap();
    a.send_one(b_addr, &[]).unwrap();
    a.send_one(b_addr, &[]).unwrap();
    a.send_one(b_addr, b"x").unwrap();
    let got = recv_n(&b, 3);
    let lens: Vec<usize> = got.iter().map(|(_, d)| d.len()).collect();
    assert_eq!(lens, [0, 0, 1]);
    assert!(got.iter().all(|(m, _)| m.local == b_addr));
}

#[test]
fn send_gso_rejects_more_than_64_segments_or_65507_bytes() {
    let (a, b) = (loopback(), loopback());
    let b_addr = b.local_addr().unwrap();
    let kind = |r: std::io::Result<()>| r.unwrap_err().kind();
    assert_eq!(
        kind(a.send_gso(b_addr, 100, &[0; 65 * 100])),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        kind(a.send_gso(b_addr, 1200, &vec![0; MAX_GSO_BYTES + 1])),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        kind(a.send_gso(b_addr, 0, &[0; 100])),
        ErrorKind::InvalidInput
    );
    // Nothing was sent, and the socket still works.
    a.send_gso(b_addr, 100, &[7; 64 * 100]).unwrap();
    let got = recv_n(&b, 64);
    assert_eq!(got.len(), 64);
    assert!(got.iter().all(|(_, d)| d == &vec![7u8; 100]));
}

// --- IPv6 (C supports AF_INET6 QUIC paths): the same three on [::1]. ---

#[test]
fn v6_gso_send_arrives_as_segments() {
    let (a, b) = (loopback6(), loopback6());
    let b_addr = b.local_addr().unwrap();
    assert!(b_addr.is_ipv6());
    let mut payload = vec![0u8; 60 * 1000];
    for (i, seg) in payload.chunks_mut(1000).enumerate() {
        seg.fill(i as u8);
    }
    a.send_gso(b_addr, 1000, &payload).unwrap();
    let got = recv_n(&b, 60);
    assert_eq!(got.len(), 60);
    for (i, (meta, bytes)) in got.iter().enumerate() {
        assert_eq!(bytes, &vec![i as u8; 1000], "segment {i}");
        assert_eq!(meta.local, b_addr);
        assert_eq!(meta.src, a.local_addr().unwrap());
    }
}

#[test]
fn v6_gro_recv_reports_each_datagram_with_local_addr() {
    let (a, b) = (loopback6(), loopback6());
    let b_addr = b.local_addr().unwrap();
    const N: usize = 40;
    for i in 0..N {
        a.send_one(b_addr, &[i as u8; 500]).unwrap();
    }
    let got = recv_n(&b, N);
    assert_eq!(got.len(), N);
    for (i, (meta, bytes)) in got.iter().enumerate() {
        assert_eq!(meta.src, a.local_addr().unwrap());
        assert_eq!(meta.local, b_addr);
        assert_eq!(bytes, &vec![i as u8; 500]);
    }
}

#[test]
fn v6_send_gso_rejects_oversize_and_other_family() {
    let (a, b) = (loopback6(), loopback6());
    let b_addr = b.local_addr().unwrap();
    let kind = |r: std::io::Result<()>| r.unwrap_err().kind();
    assert_eq!(
        kind(a.send_gso(b_addr, 100, &[0; 65 * 100])),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        kind(a.send_gso(b_addr, 1200, &vec![0; MAX_GSO_BYTES + 1])),
        ErrorKind::InvalidInput
    );
    let v4 = loopback().local_addr().unwrap();
    assert_eq!(
        kind(a.send_gso(v4, 100, &[0; 100])),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        kind(loopback().send_gso(b_addr, 100, &[0; 100])),
        ErrorKind::InvalidInput
    );
    a.send_gso(b_addr, 100, &[7; 64 * 100]).unwrap();
    let got = recv_n(&b, 64);
    assert_eq!(got.len(), 64);
    assert!(got.iter().all(|(_, d)| d == &vec![7u8; 100]));
}
