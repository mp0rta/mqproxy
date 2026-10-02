// spec §2.3; ports the non-UDP cases of tests/test_wire.c
use mq_wire::frames::*;
use mq_wire::varint;
use proptest::prelude::*;

const BIG: u64 = varint::MAX + 1;

type Enc<'a> = &'a dyn Fn(&mut [u8]) -> Result<usize, EncodeError>;

fn enc(f: Enc) -> ([u8; MAX_FRAME], usize) {
    let mut buf = [0u8; MAX_FRAME];
    let n = f(&mut buf).unwrap();
    (buf, n)
}

fn tcp_req(at: AddrType, host: &[u8]) -> ConnectTcpReq<'_> {
    ConnectTcpReq {
        flags: 0xAA55,
        address_type: at,
        host,
        port: 8443,
    }
}

// ---- test_auth_req_roundtrip ----
#[test]
fn auth_req_roundtrip() {
    let f = AuthReq {
        version: 1,
        client_id: b"client-abc",
        auth_token: b"secrettoken-1234567890",
        features: 0xDEAD_BEEF,
    };
    let (buf, n) = enc(&|b| f.encode(b));
    assert_eq!(AuthReq::decode(&buf[..n]), Ok((f, n)));
}

// ---- test_auth_resp_roundtrip ----
#[test]
fn auth_resp_roundtrip() {
    for (status, err) in [
        (STATUS_OK, AuthErr::Ok),
        (STATUS_ERROR, AuthErr::Failed),
        (STATUS_ERROR, AuthErr::TokenExpired),
        (STATUS_ERROR, AuthErr::PolicyDenied),
    ] {
        let f = AuthResp {
            status,
            error_code: err as u64,
            server_id: b"server-xyz",
            features: 0x12345,
        };
        let (buf, n) = enc(&|b| f.encode(b));
        let (out, m) = AuthResp::decode(&buf[..n]).unwrap();
        assert_eq!((out, m), (f, n));
        assert_eq!(out.error(), Some(err));
        assert_eq!(out.is_ok(), status == STATUS_OK);
    }
}

// ---- test_connect_tcp_req_roundtrip ----
#[test]
fn connect_tcp_req_roundtrip() {
    let v6 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    for (at, host) in [
        (AddrType::Ipv4, &[192, 168, 0, 1][..]),
        (AddrType::Domain, &b"example.com"[..]),
        (AddrType::Ipv6, &v6[..]),
    ] {
        let f = tcp_req(at, host);
        let (buf, n) = enc(&|b| f.encode(b));
        assert_eq!(ConnectTcpReq::decode(&buf[..n]), Ok((f, n)));
    }
}

// ---- test_connect_tcp_resp_roundtrip ----
#[test]
fn connect_tcp_resp_roundtrip() {
    for (status, err, msg) in [
        (STATUS_OK, TcpErr::Ok, &b"connected"[..]),
        (STATUS_ERROR, TcpErr::DnsFailed, &b"dns lookup failed"[..]),
        (STATUS_ERROR, TcpErr::ConnRefused, &b"refused"[..]),
        (STATUS_ERROR, TcpErr::Timeout, &b"timed out"[..]),
        (STATUS_ERROR, TcpErr::PolicyDenied, &b"denied by policy"[..]),
    ] {
        let f = ConnectTcpResp {
            status,
            error_code: err as u64,
            message: msg,
        };
        let (buf, n) = enc(&|b| f.encode(b));
        let (out, m) = ConnectTcpResp::decode(&buf[..n]).unwrap();
        assert_eq!((out, m), (f, n));
        assert_eq!(out.error(), Some(err));
        assert_eq!(out.is_ok(), status == STATUS_OK);
    }
}

// ---- test_truncation (C covers AUTH_REQUEST; extended to all four frames) ----
#[test]
fn truncation() {
    let ar = AuthReq {
        version: 1,
        client_id: b"abc",
        auth_token: b"token",
        features: 7,
    };
    let (buf, n) = enc(&|b| ar.encode(b));
    for k in 0..n {
        assert_eq!(
            AuthReq::decode(&buf[..k]),
            Err(DecodeError::Short),
            "auth_req k={k}"
        );
    }
    let rs = AuthResp {
        status: 0,
        error_code: 0,
        server_id: b"s",
        features: 9,
    };
    let (buf, n) = enc(&|b| rs.encode(b));
    for k in 0..n {
        assert_eq!(
            AuthResp::decode(&buf[..k]),
            Err(DecodeError::Short),
            "auth_resp k={k}"
        );
    }
    let tq = tcp_req(AddrType::Domain, b"example.com");
    let (buf, n) = enc(&|b| tq.encode(b));
    for k in 0..n {
        assert_eq!(
            ConnectTcpReq::decode(&buf[..k]),
            Err(DecodeError::Short),
            "tcp_req k={k}"
        );
    }
    let tr = ConnectTcpResp {
        status: 1,
        error_code: 2,
        message: b"refused",
    };
    let (buf, n) = enc(&|b| tr.encode(b));
    for k in 0..n {
        assert_eq!(
            ConnectTcpResp::decode(&buf[..k]),
            Err(DecodeError::Short),
            "tcp_resp k={k}"
        );
    }
}

// ---- test_host_too_long ----
#[test]
fn host_too_long() {
    // flags=0, Domain, declared host len 256 (2-byte varint 0x41 0x00), no bytes supplied.
    let buf = [0x00, 0x03, 0x41, 0x00];
    assert_eq!(ConnectTcpReq::decode(&buf), Err(DecodeError::BadValue));
}

// ---- test_bad_addr_type ----
#[test]
fn bad_addr_type() {
    let buf = [0x00, 0x02, 0x04, 10, 0, 0, 1, 0x01, 0xBB, 0x00];
    assert_eq!(ConnectTcpReq::decode(&buf), Err(DecodeError::BadValue));
    for t in [0x00u8, 0x02, 0x05, 0xFF] {
        assert_eq!(AddrType::from_raw(t), None);
    }
    assert_eq!(AddrType::from_raw(1), Some(AddrType::Ipv4));
    assert_eq!(AddrType::from_raw(3), Some(AddrType::Domain));
    assert_eq!(AddrType::from_raw(4), Some(AddrType::Ipv6));
}

// ---- test_padding_skipped ----
#[test]
fn padding_skipped() {
    let buf = [
        0x80, 0x00, 0xAA, 0x55, 0x01, 0x04, 192, 168, 0, 1, 0x20, 0xFB, 0x05, 0xEE, 0xEE, 0xEE,
        0xEE, 0xEE,
    ];
    let (out, m) = ConnectTcpReq::decode(&buf).unwrap();
    assert_eq!(m, buf.len());
    assert_eq!(
        out,
        ConnectTcpReq {
            flags: 0xAA55,
            address_type: AddrType::Ipv4,
            host: &[192, 168, 0, 1],
            port: 8443
        }
    );
}

// ---- test_padding_overflow (C covers CONNECT_TCP_REQUEST; extended to all four) ----
#[test]
fn padding_overflow() {
    let buf = [0x00, 0x01, 0x04, 1, 2, 3, 4, 0x00, 0x50, 0x40, 99];
    assert_eq!(ConnectTcpReq::decode(&buf), Err(DecodeError::Short));
    assert_eq!(
        AuthReq::decode(&[0x01, 0x00, 0x00, 0x00, 0x05, 0xEE]),
        Err(DecodeError::Short)
    );
    assert_eq!(
        AuthResp::decode(&[0x00, 0x00, 0x00, 0x00, 0x05, 0xEE]),
        Err(DecodeError::Short)
    );
    assert_eq!(
        ConnectTcpResp::decode(&[0x00, 0x00, 0x00, 0x05, 0xEE]),
        Err(DecodeError::Short)
    );
}

// ---- brief extras ----
#[test]
fn matches_c_golden_bytes() {
    let (b, n) = enc(&|b| {
        AuthReq {
            version: 1,
            client_id: b"c",
            auth_token: b"t",
            features: 0,
        }
        .encode(b)
    });
    assert_eq!(&b[..n], &[0x01, 0x01, b'c', 0x01, b't', 0x00, 0x00]);
    let (b, n) = enc(&|b| {
        AuthResp {
            status: 1,
            error_code: 2,
            server_id: b"s",
            features: 3,
        }
        .encode(b)
    });
    assert_eq!(&b[..n], &[0x01, 0x02, 0x01, b's', 0x03, 0x00]);
    let (b, n) = enc(&|b| {
        ConnectTcpReq {
            flags: 0,
            address_type: AddrType::Domain,
            host: b"ab",
            port: 443,
        }
        .encode(b)
    });
    assert_eq!(&b[..n], &[0x00, 0x03, 0x02, b'a', b'b', 0x01, 0xBB, 0x00]);
    let (b, n) = enc(&|b| {
        ConnectTcpResp {
            status: 0,
            error_code: 0,
            message: b"ok",
        }
        .encode(b)
    });
    assert_eq!(&b[..n], &[0x00, 0x00, 0x02, b'o', b'k', 0x00]);
}

#[test]
fn decode_accepts_non_minimal_varints() {
    // AuthReq version=1 as a 2-byte varint, features=0 as an 8-byte varint.
    let buf = [0x40, 0x01, 0x00, 0x00, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0x00];
    let (f, n) = AuthReq::decode(&buf).unwrap();
    assert_eq!(n, buf.len());
    assert_eq!((f.version, f.features), (1, 0));
}

/// prefix | varint len | len zero bytes | suffix
fn long_string_frame(prefix: &[u8], len: usize, suffix: &[u8], buf: &mut [u8; 1024]) -> usize {
    buf.fill(0);
    let mut off = prefix.len();
    buf[..off].copy_from_slice(prefix);
    off += varint::encode(&mut buf[off..], len as u64).unwrap();
    off += len;
    buf[off..off + suffix.len()].copy_from_slice(suffix);
    off + suffix.len()
}

fn want(ok: bool) -> Result<(), DecodeError> {
    if ok {
        Ok(())
    } else {
        Err(DecodeError::BadValue)
    }
}

#[test]
fn rejects_overlong_string() {
    let mut buf = [0u8; 1024];
    // decode: cap accepted, cap+1 rejected with BadValue
    for (len, ok) in [(63, true), (64, false)] {
        // AuthReq client_id (63)
        let n = long_string_frame(&[0x01], len, &[0x00, 0x00, 0x00], &mut buf);
        assert_eq!(AuthReq::decode(&buf[..n]).map(|_| ()), want(ok));
        // AuthResp server_id (63)
        let n = long_string_frame(&[0x00, 0x00], len, &[0x00, 0x00], &mut buf);
        assert_eq!(AuthResp::decode(&buf[..n]).map(|_| ()), want(ok));
    }
    for (len, ok) in [(255, true), (256, false)] {
        // AuthReq auth_token (255)
        let n = long_string_frame(&[0x01, 0x00], len, &[0x00, 0x00], &mut buf);
        assert_eq!(AuthReq::decode(&buf[..n]).map(|_| ()), want(ok));
        // ConnectTcpReq host (255)
        let n = long_string_frame(&[0x00, 0x03], len, &[0x00, 0x50, 0x00], &mut buf);
        assert_eq!(ConnectTcpReq::decode(&buf[..n]).map(|_| ()), want(ok));
        // ConnectTcpResp message (255)
        let n = long_string_frame(&[0x01, 0x01], len, &[0x00], &mut buf);
        assert_eq!(ConnectTcpResp::decode(&buf[..n]).map(|_| ()), want(ok));
    }

    // encode: cap+1 rejected with TooLong; cap fits
    let z = [0u8; 256];
    let mut out = [0u8; 1024];
    let e = Err(EncodeError::TooLong);
    assert_eq!(
        AuthReq {
            version: 0,
            client_id: &z[..64],
            auth_token: b"",
            features: 0
        }
        .encode(&mut out),
        e
    );
    assert_eq!(
        AuthReq {
            version: 0,
            client_id: b"",
            auth_token: &z[..256],
            features: 0
        }
        .encode(&mut out),
        e
    );
    assert_eq!(
        AuthResp {
            status: 0,
            error_code: 0,
            server_id: &z[..64],
            features: 0
        }
        .encode(&mut out),
        e
    );
    assert_eq!(
        ConnectTcpReq {
            flags: 0,
            address_type: AddrType::Domain,
            host: &z[..256],
            port: 0
        }
        .encode(&mut out),
        e
    );
    assert_eq!(
        ConnectTcpResp {
            status: 0,
            error_code: 0,
            message: &z[..256]
        }
        .encode(&mut out),
        e
    );
    assert!(
        AuthReq {
            version: 0,
            client_id: &z[..63],
            auth_token: &z[..255],
            features: 0
        }
        .encode(&mut out)
        .is_ok()
    );
    assert!(
        AuthResp {
            status: 0,
            error_code: 0,
            server_id: &z[..63],
            features: 0
        }
        .encode(&mut out)
        .is_ok()
    );
    assert!(
        ConnectTcpReq {
            flags: 0,
            address_type: AddrType::Domain,
            host: &z[..255],
            port: 0
        }
        .encode(&mut out)
        .is_ok()
    );
    assert!(
        ConnectTcpResp {
            status: 0,
            error_code: 0,
            message: &z[..255]
        }
        .encode(&mut out)
        .is_ok()
    );
}

/// Encode, then rewrite padding_length 0 -> 3, append 3 pad bytes and one trailing byte.
fn padded(e: Enc) -> ([u8; 64], usize) {
    let mut b = [0u8; 64];
    let n = e(&mut b).unwrap();
    assert_eq!(b[n - 1], 0x00); // encoder wrote padding_length = 0
    b[n - 1] = 0x03;
    b[n..n + 3].copy_from_slice(&[0xEE; 3]);
    b[n + 3] = 0x99; // not part of the frame
    (b, n + 3)
}

#[test]
fn skips_padding() {
    let ar = AuthReq {
        version: 1,
        client_id: b"c",
        auth_token: b"t",
        features: 0,
    };
    let rs = AuthResp {
        status: 0,
        error_code: 0,
        server_id: b"s",
        features: 1,
    };
    let tq = tcp_req(AddrType::Ipv4, &[1, 2, 3, 4]);
    let tr = ConnectTcpResp {
        status: 0,
        error_code: 0,
        message: b"m",
    };
    let (b, n) = padded(&|o| ar.encode(o));
    assert_eq!(AuthReq::decode(&b[..n + 1]), Ok((ar, n)));
    let (b, n) = padded(&|o| rs.encode(o));
    assert_eq!(AuthResp::decode(&b[..n + 1]), Ok((rs, n)));
    let (b, n) = padded(&|o| tq.encode(o));
    assert_eq!(ConnectTcpReq::decode(&b[..n + 1]), Ok((tq, n)));
    let (b, n) = padded(&|o| tr.encode(o));
    assert_eq!(ConnectTcpResp::decode(&b[..n + 1]), Ok((tr, n)));
}

#[test]
fn encode_short_buffer() {
    let ar = AuthReq {
        version: 1,
        client_id: b"abc",
        auth_token: b"token",
        features: 7,
    };
    let rs = AuthResp {
        status: 0,
        error_code: 0,
        server_id: b"srv",
        features: 1,
    };
    let tq = tcp_req(AddrType::Domain, b"example.com");
    let tr = ConnectTcpResp {
        status: 1,
        error_code: 3,
        message: b"timed out",
    };
    let encs: [Enc; 4] = [
        &|o| ar.encode(o),
        &|o| rs.encode(o),
        &|o| tq.encode(o),
        &|o| tr.encode(o),
    ];
    for e in encs {
        let mut b = [0u8; 64];
        let n = e(&mut b).unwrap();
        for k in 0..n {
            assert_eq!(e(&mut b[..k]), Err(EncodeError::Short), "k={k}");
        }
        assert_eq!(e(&mut b[..n]), Ok(n));
    }
}

#[test]
fn encode_rejects_varint_above_max() {
    let mut b = [0u8; MAX_FRAME];
    let e = Err(EncodeError::BadValue);
    assert_eq!(
        AuthReq {
            version: BIG,
            client_id: b"",
            auth_token: b"",
            features: 0
        }
        .encode(&mut b),
        e
    );
    assert_eq!(
        AuthReq {
            version: 0,
            client_id: b"",
            auth_token: b"",
            features: BIG
        }
        .encode(&mut b),
        e
    );
    assert_eq!(
        AuthResp {
            status: 0,
            error_code: BIG,
            server_id: b"",
            features: 0
        }
        .encode(&mut b),
        e
    );
    assert_eq!(
        AuthResp {
            status: 0,
            error_code: 0,
            server_id: b"",
            features: BIG
        }
        .encode(&mut b),
        e
    );
    assert_eq!(
        ConnectTcpReq {
            flags: BIG,
            address_type: AddrType::Ipv4,
            host: b"",
            port: 0
        }
        .encode(&mut b),
        e
    );
    assert_eq!(
        ConnectTcpResp {
            status: 0,
            error_code: BIG,
            message: b""
        }
        .encode(&mut b),
        e
    );
    let max = varint::MAX;
    assert!(
        AuthReq {
            version: max,
            client_id: b"",
            auth_token: b"",
            features: max
        }
        .encode(&mut b)
        .is_ok()
    );
}

#[test]
fn unknown_status_and_error_code_kept_raw() {
    let f = AuthResp {
        status: 0x7F,
        error_code: 0x1234,
        server_id: b"",
        features: 0,
    };
    let (b, n) = enc(&|o| f.encode(o));
    let (out, _) = AuthResp::decode(&b[..n]).unwrap();
    assert_eq!((out.status, out.error_code), (0x7F, 0x1234));
    assert_eq!(out.error(), None);
    assert!(!out.is_ok());
    assert_eq!(AuthErr::from_raw(4), None);

    let f = ConnectTcpResp {
        status: 0xFF,
        error_code: varint::MAX,
        message: b"",
    };
    let (b, n) = enc(&|o| f.encode(o));
    let (out, _) = ConnectTcpResp::decode(&b[..n]).unwrap();
    assert_eq!((out.status, out.error_code), (0xFF, varint::MAX));
    assert_eq!(out.error(), None);
    assert!(!out.is_ok());
    assert_eq!(TcpErr::from_raw(5), None);
}

#[test]
fn constants() {
    assert_eq!(
        (STREAM_TYPE_CONNECT_TCP, STREAM_TYPE_UDP_SESSION),
        (0x01, 0x02)
    );
    assert_eq!((STATUS_OK, STATUS_ERROR, MAX_FRAME), (0, 1, 512));
}

// ---- UDP_SESSION_OPEN / UDP_SESSION_RESP (spec §2.1; unlike the TCP frames, both
// sides validate semantics as src/wire/mq_wire.c does) ----
fn udp_open(at: AddrType, host: &[u8]) -> UdpSessionOpen<'_> {
    UdpSessionOpen {
        session_id: 0xDEAD_BEEF,
        flags: 0,
        address_type: at,
        host,
        port: 5353,
        idle_timeout_ms: 30_000,
    }
}

fn udp_resp(status: u8, code: u64, message: &[u8]) -> UdpSessionResp<'_> {
    UdpSessionResp {
        status,
        error_code: code,
        message,
        idle_timeout_ms: 60_000,
    }
}

#[test]
fn udp_open_roundtrip() {
    let v6 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    for (at, host) in [
        (AddrType::Ipv4, &[192, 168, 0, 1][..]),
        (AddrType::Domain, &b"example.com"[..]),
        (AddrType::Ipv6, &v6[..]),
    ] {
        let f = udp_open(at, host);
        let (buf, n) = enc(&|b| f.encode(b));
        assert_eq!(UdpSessionOpen::decode(&buf[..n]), Ok((f, n)));
    }
}

#[test]
fn udp_open_rejects_sid_over_u32() {
    // session_id as a varint | flags 0 | Ipv4 | 1.2.3.4 | port 80 | idle 0 | pad 0
    let rest = [0x00, 0x01, 0x04, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x00];
    let frame = |sid: u64| {
        let mut buf = [0u8; 32];
        let n = varint::encode(&mut buf, sid).unwrap();
        buf[n..n + rest.len()].copy_from_slice(&rest);
        (buf, n + rest.len())
    };
    let (buf, n) = frame(1 << 32);
    assert_eq!(UdpSessionOpen::decode(&buf[..n]), Err(DecodeError::Invalid));
    let (buf, n) = frame(u32::MAX as u64);
    let (f, _) = UdpSessionOpen::decode(&buf[..n]).unwrap();
    assert_eq!(f.session_id, u32::MAX);
}

#[test]
fn udp_open_rejects_unknown_atype() {
    for t in [0x00u8, 0x02, 0x05, 0xFF] {
        // sid 1 | flags 0 | atype t | host 1.2.3.4 | port 80 | idle 0 | pad 0
        let buf = [0x01, 0x00, t, 0x04, 1, 2, 3, 4, 0x00, 0x50, 0x00, 0x00];
        assert_eq!(UdpSessionOpen::decode(&buf), Err(DecodeError::Invalid));
    }
}

#[test]
fn udp_resp_roundtrip() {
    let long = [b'm'; 255];
    for (status, err, msg) in [
        (STATUS_OK, None, &b"ok"[..]),
        (STATUS_OK, None, &b""[..]),
        (STATUS_ERROR, Some(UdpErr::DnsFailed), &b"dns failed"[..]),
        (STATUS_ERROR, Some(UdpErr::SocketFailed), &b"socket"[..]),
        (STATUS_ERROR, Some(UdpErr::PolicyDenied), &b"denied"[..]),
        (STATUS_ERROR, Some(UdpErr::SessionLimit), &long[..]),
    ] {
        let f = udp_resp(status, err.map_or(0, |e| e as u64), msg);
        let (buf, n) = enc(&|b| f.encode(b));
        let (out, m) = UdpSessionResp::decode(&buf[..n]).unwrap();
        assert_eq!((out, m), (f, n));
        assert_eq!(out.error(), err);
        assert_eq!(out.is_ok(), status == STATUS_OK);
    }
}

#[test]
fn udp_resp_rejects_code_5() {
    // status ERROR | code 5 | msg "" | idle 0 | pad 0
    assert_eq!(
        UdpSessionResp::decode(&[0x01, 0x05, 0x00, 0x00, 0x00]),
        Err(DecodeError::Invalid)
    );
    // status OK with code 5, and a code beyond one byte
    assert_eq!(
        UdpSessionResp::decode(&[0x00, 0x05, 0x00, 0x00, 0x00]),
        Err(DecodeError::Invalid)
    );
    assert_eq!(
        UdpSessionResp::decode(&[0x01, 0x40, 0x64, 0x00, 0x00, 0x00]),
        Err(DecodeError::Invalid)
    );
    // C checks the pairing before the message: Invalid wins over a truncated or over-long message.
    assert_eq!(
        UdpSessionResp::decode(&[0x01, 0x05]),
        Err(DecodeError::Invalid)
    );
    assert_eq!(
        UdpSessionResp::decode(&[0x01, 0x05, 0x41, 0x00]),
        Err(DecodeError::Invalid)
    );
}

#[test]
fn udp_resp_rejects_ok_with_code() {
    for code in 1..=4u8 {
        assert_eq!(
            UdpSessionResp::decode(&[0x00, code, 0x00, 0x00, 0x00]),
            Err(DecodeError::Invalid)
        );
    }
}

#[test]
fn udp_resp_rejects_error_with_code_0() {
    assert_eq!(
        UdpSessionResp::decode(&[0x01, 0x00, 0x00, 0x00, 0x00]),
        Err(DecodeError::Invalid)
    );
    // an unknown status is neither OK nor ERROR
    for st in [0x02u8, 0x7F, 0xFF] {
        for code in 0..=4u8 {
            assert_eq!(
                UdpSessionResp::decode(&[st, code, 0x00, 0x00, 0x00]),
                Err(DecodeError::Invalid)
            );
        }
    }
}

#[test]
fn udp_resp_rejects_message_256() {
    // status ERROR | code 1 | declared message len 256 (0x41 0x00), no bytes supplied
    assert_eq!(
        UdpSessionResp::decode(&[0x01, 0x01, 0x41, 0x00]),
        Err(DecodeError::BadValue)
    );
}

#[test]
fn udp_resp_encode_rejects_inconsistent() {
    let mut b = [0u8; MAX_FRAME];
    let e = Err(EncodeError::BadValue);
    assert_eq!(udp_resp(STATUS_OK, 1, b"").encode(&mut b), e);
    assert_eq!(udp_resp(STATUS_OK, 5, b"").encode(&mut b), e);
    assert_eq!(udp_resp(STATUS_ERROR, 0, b"").encode(&mut b), e);
    assert_eq!(udp_resp(STATUS_ERROR, 5, b"").encode(&mut b), e);
    assert_eq!(udp_resp(0x02, 1, b"").encode(&mut b), e);
    assert_eq!(udp_resp(0x02, 0, b"").encode(&mut b), e);
    // a code that is not a valid varint is rejected the same way
    assert_eq!(udp_resp(STATUS_ERROR, BIG, b"").encode(&mut b), e);
    // the semantic check precedes the buffer check, as in C
    assert_eq!(udp_resp(STATUS_OK, 1, b"").encode(&mut b[..0]), e);
}

#[test]
fn udp_frames_encode_limits() {
    let z = [0u8; 256];
    let mut b = [0u8; MAX_FRAME];
    assert_eq!(
        udp_open(AddrType::Domain, &z).encode(&mut b),
        Err(EncodeError::TooLong)
    );
    assert!(udp_open(AddrType::Domain, &z[..255]).encode(&mut b).is_ok());
    assert_eq!(
        udp_resp(STATUS_OK, 0, &z).encode(&mut b),
        Err(EncodeError::TooLong)
    );
    let big = UdpSessionOpen {
        flags: BIG,
        ..udp_open(AddrType::Ipv4, &[1, 2, 3, 4])
    };
    assert_eq!(big.encode(&mut b), Err(EncodeError::BadValue));
    let big = UdpSessionOpen {
        idle_timeout_ms: BIG,
        ..big
    };
    assert_eq!(big.encode(&mut b), Err(EncodeError::BadValue));
    let big = UdpSessionResp {
        idle_timeout_ms: BIG,
        ..udp_resp(STATUS_OK, 0, b"")
    };
    assert_eq!(big.encode(&mut b), Err(EncodeError::BadValue));
}

#[test]
fn udp_frames_skip_padding() {
    let o = udp_open(AddrType::Ipv4, &[1, 2, 3, 4]);
    let r = udp_resp(STATUS_ERROR, 2, b"m");
    let (b, n) = padded(&|d| o.encode(d));
    assert_eq!(UdpSessionOpen::decode(&b[..n + 1]), Ok((o, n)));
    let (b, n) = padded(&|d| r.encode(d));
    assert_eq!(UdpSessionResp::decode(&b[..n + 1]), Ok((r, n)));
    // padding_length beyond the buffer is truncation
    assert_eq!(
        UdpSessionOpen::decode(&[0x01, 0x00, 0x01, 0x01, 9, 0x00, 0x50, 0x00, 0x05, 0xEE]),
        Err(DecodeError::Short)
    );
    assert_eq!(
        UdpSessionResp::decode(&[0x00, 0x00, 0x00, 0x00, 0x05, 0xEE]),
        Err(DecodeError::Short)
    );
}

#[test]
fn udp_frames_truncation_is_short() {
    let o = udp_open(AddrType::Domain, b"example.com");
    let (buf, n) = enc(&|b| o.encode(b));
    for k in 0..n {
        assert_eq!(
            UdpSessionOpen::decode(&buf[..k]),
            Err(DecodeError::Short),
            "udp_open k={k}"
        );
    }
    let r = udp_resp(STATUS_ERROR, 4, b"session limit");
    let (buf, n) = enc(&|b| r.encode(b));
    for k in 0..n {
        assert_eq!(
            UdpSessionResp::decode(&buf[..k]),
            Err(DecodeError::Short),
            "udp_resp k={k}"
        );
    }
}

#[test]
fn udp_frames_encode_short_buffer() {
    let o = udp_open(AddrType::Domain, b"example.com");
    let r = udp_resp(STATUS_ERROR, 3, b"denied");
    let encs: [Enc; 2] = [&|d| o.encode(d), &|d| r.encode(d)];
    for e in encs {
        let mut b = [0u8; 64];
        let n = e(&mut b).unwrap();
        for k in 0..n {
            assert_eq!(e(&mut b[..k]), Err(EncodeError::Short), "k={k}");
        }
        assert_eq!(e(&mut b[..n]), Ok(n));
    }
}

#[test]
fn udp_frames_fit_512() {
    let host = [b'h'; 255];
    let o = UdpSessionOpen {
        session_id: u32::MAX,
        flags: varint::MAX,
        address_type: AddrType::Domain,
        host: &host,
        port: u16::MAX,
        idle_timeout_ms: varint::MAX,
    };
    let (_, n) = enc(&|b| o.encode(b));
    assert!(n <= MAX_FRAME, "open {n}");
    let r = UdpSessionResp {
        status: STATUS_ERROR,
        error_code: UdpErr::SessionLimit as u64,
        message: &host,
        idle_timeout_ms: varint::MAX,
    };
    let (_, n) = enc(&|b| r.encode(b));
    assert!(n <= MAX_FRAME, "resp {n}");
}

#[test]
fn udp_matches_c_golden_bytes() {
    // varint sid | varint flags | u8 atype | string host | u16be port | varint idle | varint pad
    let (b, n) = enc(&|b| {
        UdpSessionOpen {
            session_id: 7,
            flags: 0,
            address_type: AddrType::Domain,
            host: b"ab",
            port: 443,
            idle_timeout_ms: 60_000,
        }
        .encode(b)
    });
    assert_eq!(
        &b[..n],
        &[
            0x07, 0x00, 0x03, 0x02, b'a', b'b', 0x01, 0xBB, 0x80, 0x00, 0xEA, 0x60, 0x00
        ]
    );
    // u8 status | varint code | string message | varint idle | varint pad
    let (b, n) = enc(&|b| {
        UdpSessionResp {
            status: 1,
            error_code: 3,
            message: b"no",
            idle_timeout_ms: 0,
        }
        .encode(b)
    });
    assert_eq!(&b[..n], &[0x01, 0x03, 0x02, b'n', b'o', 0x00, 0x00]);
}

#[test]
fn udp_err_from_raw() {
    assert_eq!(UdpErr::from_raw(0), None); // OK is not an error
    assert_eq!(UdpErr::from_raw(1), Some(UdpErr::DnsFailed));
    assert_eq!(UdpErr::from_raw(2), Some(UdpErr::SocketFailed));
    assert_eq!(UdpErr::from_raw(3), Some(UdpErr::PolicyDenied));
    assert_eq!(UdpErr::from_raw(4), Some(UdpErr::SessionLimit));
    assert_eq!(UdpErr::from_raw(5), None); // MQ_UDP_CLOSED never goes on the wire
    assert_eq!(FEAT_UDP_RELAY, 1);
}

fn addr() -> impl Strategy<Value = AddrType> {
    prop_oneof![
        Just(AddrType::Ipv4),
        Just(AddrType::Domain),
        Just(AddrType::Ipv6)
    ]
}

proptest! {
    #[test]
    fn proptest_roundtrip(
        a in 0..=varint::MAX, b in 0..=varint::MAX, st in any::<u8>(), port in any::<u16>(), at in addr(),
        s63 in proptest::collection::vec(any::<u8>(), 0..=63),
        s255 in proptest::collection::vec(any::<u8>(), 0..=255),
    ) {
        let mut buf = [0u8; MAX_FRAME];
        let f = AuthReq { version: a, client_id: &s63, auth_token: &s255, features: b };
        let n = f.encode(&mut buf).unwrap();
        prop_assert_eq!(AuthReq::decode(&buf[..n]), Ok((f, n)));
        let f = AuthResp { status: st, error_code: a, server_id: &s63, features: b };
        let n = f.encode(&mut buf).unwrap();
        prop_assert_eq!(AuthResp::decode(&buf[..n]), Ok((f, n)));
        let f = ConnectTcpReq { flags: a, address_type: at, host: &s255, port };
        let n = f.encode(&mut buf).unwrap();
        prop_assert_eq!(ConnectTcpReq::decode(&buf[..n]), Ok((f, n)));
        let f = ConnectTcpResp { status: st, error_code: b, message: &s255 };
        let n = f.encode(&mut buf).unwrap();
        prop_assert_eq!(ConnectTcpResp::decode(&buf[..n]), Ok((f, n)));
    }

    #[test]
    fn proptest_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = AuthReq::decode(&bytes);
        let _ = AuthResp::decode(&bytes);
        let _ = ConnectTcpReq::decode(&bytes);
        let _ = ConnectTcpResp::decode(&bytes);
        let _ = UdpSessionOpen::decode(&bytes);
        let _ = UdpSessionResp::decode(&bytes);
    }

    #[test]
    fn proptest_udp_roundtrip(
        sid in any::<u32>(), a in 0..=varint::MAX, b in 0..=varint::MAX, port in any::<u16>(), at in addr(),
        err in 0u64..=4,
        s255 in proptest::collection::vec(any::<u8>(), 0..=255),
    ) {
        let mut buf = [0u8; MAX_FRAME];
        let f = UdpSessionOpen { session_id: sid, flags: a, address_type: at, host: &s255, port, idle_timeout_ms: b };
        let n = f.encode(&mut buf).unwrap();
        prop_assert_eq!(UdpSessionOpen::decode(&buf[..n]), Ok((f, n)));
        let status = if err == 0 { STATUS_OK } else { STATUS_ERROR };
        let f = UdpSessionResp { status, error_code: err, message: &s255, idle_timeout_ms: b };
        let n = f.encode(&mut buf).unwrap();
        prop_assert_eq!(UdpSessionResp::decode(&buf[..n]), Ok((f, n)));
    }
}
