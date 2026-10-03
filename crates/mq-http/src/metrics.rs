//! `mq.req` log-line formatter (spec §2.4), byte-for-byte as C `mq_gw_format_req_line`.
//! Works on bytes: no `String`, truncation is bytewise.
use std::io::Write;

/// C's `char line[1024]` including the NUL: a line of this length or more is dropped.
pub const LINE_MAX: usize = 1024;
const AUTHORITY_CAP: usize = 128;
const PATH_CAP: usize = 256;
const RESET_CAP: usize = 64;
const CONTENT_ENCODING_CAP: usize = 23;

pub struct ReqLine<'a> {
    pub sid: u64,
    pub method: &'a [u8],
    pub status: i32,
    pub authority: &'a [u8],
    /// Already cut at `?` and at 256 bytes by the caller.
    pub path: &'a [u8],
    pub req_bytes: u64,
    pub resp_bytes: u64,
    pub begin_us: u64,
    pub header_send_us: u64,
    pub fin_send_us: u64,
    pub fin_ack_us: u64,
    /// `h1|h2|h3|none`.
    pub origin_protocol: &'static str,
    pub origin_tls: &'static str,
    pub content_encoding: &'a [u8],
    pub origin_reuse: u8,
    pub origin_connect_ms: i64,
    pub mp_state: i32,
    pub reset: &'a [u8],
}

/// Milliseconds from `begin` to `later` (µs stamps); −1 when either is unset or `later < begin`.
pub fn ms_since(begin: u64, later: u64) -> i64 {
    if begin == 0 || later == 0 || later < begin {
        -1
    } else {
        ((later - begin) / 1000) as i64
    }
}

/// ` key="value"`, value capped at `cap` source bytes (+ U+2026 when cut), `"` and `\` escaped.
fn quoted(out: &mut Vec<u8>, key: &str, val: &[u8], cap: usize) {
    out.extend_from_slice(b" ");
    out.extend_from_slice(key.as_bytes());
    out.extend_from_slice(b"=\"");
    for &b in &val[..val.len().min(cap)] {
        if b == b'"' || b == b'\\' {
            out.push(b'\\');
        }
        out.push(b);
    }
    if val.len() > cap {
        out.extend_from_slice("\u{2026}".as_bytes());
    }
    out.push(b'"');
}

/// `None` = the line is 1024 bytes or more and must be dropped.
pub fn format_req(l: &ReqLine<'_>) -> Option<Vec<u8>> {
    let mut o = Vec::with_capacity(512);
    o.extend_from_slice(b"mq.req cid=- sid=");
    let _ = write!(o, "{} method=", l.sid);
    o.extend_from_slice(l.method);
    let _ = write!(o, " status={}", l.status);
    quoted(&mut o, "authority", l.authority, AUTHORITY_CAP);
    quoted(&mut o, "path", l.path, PATH_CAP);
    let _ = write!(
        o,
        " req_bytes={} resp_bytes={} ttfb_ms={} duration_ms={} origin_protocol={} origin_tls={} content_encoding=",
        l.req_bytes,
        l.resp_bytes,
        ms_since(l.begin_us, l.header_send_us),
        ms_since(l.begin_us, l.fin_send_us),
        l.origin_protocol,
        l.origin_tls,
    );
    if l.content_encoding.is_empty() {
        o.extend_from_slice(b"none");
    } else {
        o.extend_from_slice(
            &l.content_encoding[..l.content_encoding.len().min(CONTENT_ENCODING_CAP)],
        );
    }
    let _ = write!(
        o,
        " cache=bypass origin_reuse={} origin_connect_ms={} mp_state={} completion_ms={}",
        l.origin_reuse,
        l.origin_connect_ms,
        l.mp_state,
        ms_since(l.begin_us, l.fin_ack_us),
    );
    quoted(&mut o, "reset", l.reset, RESET_CAP);
    (o.len() < LINE_MAX).then_some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ReqLine<'static> {
        ReqLine {
            sid: 4,
            method: b"GET",
            status: 200,
            authority: b"example.com",
            path: b"/big.bin",
            req_bytes: 0,
            resp_bytes: 104857600,
            begin_us: 1_000_000,
            header_send_us: 1_042_999,
            fin_send_us: 2_200_000,
            fin_ack_us: 2_201_000,
            origin_protocol: "h2",
            origin_tls: "ok",
            content_encoding: b"gzip",
            origin_reuse: 0,
            origin_connect_ms: 7,
            mp_state: 1,
            reset: b"",
        }
    }

    fn fmt(l: &ReqLine<'_>) -> Vec<u8> {
        format_req(l).expect("line fits")
    }

    #[test]
    fn golden_minimal() {
        let l = ReqLine {
            method: b"-",
            status: 0,
            authority: b"-",
            path: b"-",
            resp_bytes: 0,
            begin_us: 0,
            header_send_us: 0,
            fin_send_us: 0,
            fin_ack_us: 0,
            origin_protocol: "none",
            origin_tls: "na",
            content_encoding: b"",
            origin_connect_ms: -1,
            mp_state: 0,
            ..base()
        };
        assert_eq!(
            fmt(&l),
            b"mq.req cid=- sid=4 method=- status=0 authority=\"-\" path=\"-\" req_bytes=0 resp_bytes=0 \
ttfb_ms=-1 duration_ms=-1 origin_protocol=none origin_tls=na content_encoding=none cache=bypass \
origin_reuse=0 origin_connect_ms=-1 mp_state=0 completion_ms=-1 reset=\"\""
        );
    }

    #[test]
    fn golden_full() {
        let l = ReqLine {
            reset: b"client-reset",
            ..base()
        };
        assert_eq!(
            fmt(&l),
            b"mq.req cid=- sid=4 method=GET status=200 authority=\"example.com\" path=\"/big.bin\" \
req_bytes=0 resp_bytes=104857600 ttfb_ms=42 duration_ms=1200 origin_protocol=h2 origin_tls=ok \
content_encoding=gzip cache=bypass origin_reuse=0 origin_connect_ms=7 mp_state=1 completion_ms=1201 \
reset=\"client-reset\""
                .to_vec()
        );
    }

    #[test]
    fn authority_128_cut_with_ellipsis() {
        let a = [b'a'; 129];
        let out = fmt(&ReqLine {
            authority: &a,
            ..base()
        });
        let mut want = b"authority=\"".to_vec();
        want.extend_from_slice(&[b'a'; 128]);
        want.extend_from_slice("\u{2026}\"".as_bytes());
        assert!(out.windows(want.len()).any(|w| w == want));
        // exactly 128: no marker
        let out = fmt(&ReqLine {
            authority: &a[..128],
            ..base()
        });
        assert!(!out.windows(3).any(|w| w == "\u{2026}".as_bytes()));
    }

    #[test]
    fn path_256_cut() {
        let p = [b'p'; 300];
        let out = fmt(&ReqLine { path: &p, ..base() });
        let mut want = b"path=\"".to_vec();
        want.extend_from_slice(&[b'p'; 256]);
        want.extend_from_slice("\u{2026}\"".as_bytes());
        assert!(out.windows(want.len()).any(|w| w == want));
    }

    #[test]
    fn reset_64_cut() {
        let r = [b'r'; 65];
        let out = fmt(&ReqLine {
            reset: &r,
            ..base()
        });
        let mut want = b"reset=\"".to_vec();
        want.extend_from_slice(&[b'r'; 64]);
        want.extend_from_slice("\u{2026}\"".as_bytes());
        assert!(out.ends_with(&want));
    }

    #[test]
    fn quotes_and_backslash_escaped() {
        let out = fmt(&ReqLine {
            path: b"a\"b\\c",
            ..base()
        });
        assert!(
            out.windows(14)
                .any(|w| w == b"path=\"a\\\"b\\\\c\"" as &[u8])
        );
    }

    #[test]
    fn content_encoding_23_verbatim() {
        let ce = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let out = fmt(&ReqLine {
            content_encoding: ce,
            ..base()
        });
        let want = b"content_encoding=0123456789abcdefghijklm cache=bypass";
        assert!(out.windows(want.len()).any(|w| w == want));
    }

    #[test]
    fn content_encoding_empty_is_none() {
        let out = fmt(&ReqLine {
            content_encoding: b"",
            ..base()
        });
        assert!(out.windows(21).any(|w| w == b"content_encoding=none"));
    }

    #[test]
    fn timings_minus_one_rules() {
        assert_eq!(ms_since(0, 5000), -1);
        assert_eq!(ms_since(5000, 0), -1);
        assert_eq!(ms_since(5000, 4999), -1);
        assert_eq!(ms_since(5000, 5000), 0);
        assert_eq!(ms_since(1_000_000, 1_042_999), 42);
        let out = fmt(&ReqLine {
            fin_send_us: 999_999,
            ..base()
        });
        assert!(out.windows(14).any(|w| w == b"duration_ms=-1"));
    }

    #[test]
    fn line_1024_dropped() {
        // inflate `method` (uncapped, like C's %s) to hit the boundary.
        let l = base();
        let len = fmt(&l).len();
        let m1023 = vec![b'M'; 3 + 1023 - len];
        let m1024 = vec![b'M'; 3 + 1024 - len];
        assert_eq!(
            fmt(&ReqLine {
                method: &m1023,
                ..base()
            })
            .len(),
            1023
        );
        assert!(
            format_req(&ReqLine {
                method: &m1024,
                ..base()
            })
            .is_none()
        );
    }

    #[test]
    fn multibyte_cut_is_bytewise() {
        let mut a = vec![b'a'; 127];
        a.extend_from_slice("é".as_bytes()); // 0xC3 0xA9: cap 128 falls inside it
        let out = fmt(&ReqLine {
            authority: &a,
            ..base()
        });
        let mut want = b"authority=\"".to_vec();
        want.extend_from_slice(&[b'a'; 127]);
        want.extend_from_slice(&[0xC3]);
        want.extend_from_slice("\u{2026}\"".as_bytes());
        assert!(out.windows(want.len()).any(|w| w == want));
    }

    #[test]
    fn non_utf8_passthrough() {
        let out = fmt(&ReqLine {
            authority: b"a\xffb",
            ..base()
        });
        assert!(out.windows(4).any(|w| w == b"a\xffb\"" as &[u8]));
    }
}
