//! SP3 spec §5.4: the fetch download's response head — collected from the H3
//! header section under C's caps (`dl_each_header`), rendered as the local
//! HTTP/1.1 head (`adp_resp_head`) — and the body check's exemptions.

use mq_http::h1;
use mq_http::headers::{Method, is_hop_by_hop};

/// C `MQ_GW_RESP_NAME_CAP` / `MQ_GW_RESP_VAL_CAP`: a name ≥ 128 or a value
/// ≥ 2048 bytes is malformed.
const RESP_NAME_CAP: usize = 128;
const RESP_VAL_CAP: usize = 2048;
/// C `MQ_GW_RESP_MAX_HDRS` / `MQ_GW_RESP_ARENA` (`name\0value\0` per header):
/// sized so that the 8192-byte render cap is what binds.
const RESP_MAX_HDRS: usize = 2048;
const RESP_ARENA: usize = 16 * 1024;
/// C `adp_resp_head`'s `char head[8192]`.
const RESP_RENDER_MAX: usize = 8192;

/// The response head cannot be relayed: 502 `upstream-protocol` (spec §5.4).
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

/// A collected response head (spec §5.4).
#[derive(Debug, PartialEq, Eq)]
pub struct RespHead {
    /// `:status`, 502 when outside 100..=599 (as C).
    pub status: u16,
    /// Every relayed header, as received (pseudo and hop-by-hop dropped).
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    /// A single, strictly numeric `content-length` (the body check's input).
    pub cl: Option<u64>,
    /// Some `content-length` was received (else the body is framed chunked).
    pub has_cl: bool,
    /// FIN on the header section.
    pub fin: bool,
}

/// Collects one H3 response header section, applying the caps as it goes.
#[derive(Default)]
pub struct HeadCollector {
    status: Option<u16>,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    arena: usize,
    cl_count: usize,
    cl: Option<u64>,
    bad: bool,
}

impl HeadCollector {
    pub fn push(&mut self, name: &[u8], value: &[u8]) {
        if self.bad {
            return;
        }
        // Exactly three ASCII digits (C: no overflow on a hostile value).
        if name == b":status" {
            match value {
                [a, b, c] if value.iter().all(u8::is_ascii_digit) => {
                    let code = [a, b, c]
                        .iter()
                        .fold(0u16, |n, &&d| n * 10 + u16::from(d - b'0'));
                    self.status = Some(if (100..=599).contains(&code) {
                        code
                    } else {
                        502
                    });
                }
                _ => self.bad = true,
            }
            return;
        }
        // Other pseudo-headers and hop-by-hop: dropped; `x-mq-*` kept (as C).
        if name.first() == Some(&b':') || is_hop_by_hop(name) {
            return;
        }
        let ctl = |s: &[u8]| s.iter().any(|&c| matches!(c, b'\r' | b'\n' | 0));
        self.arena += name.len() + value.len() + 2;
        if name.len() >= RESP_NAME_CAP
            || value.len() >= RESP_VAL_CAP
            || ctl(name)
            || ctl(value)
            || self.headers.len() >= RESP_MAX_HDRS
            || self.arena > RESP_ARENA
        {
            self.bad = true;
            return;
        }
        if name.eq_ignore_ascii_case(b"content-length") {
            self.cl_count += 1;
            self.cl = h1::parse_content_length(value);
        }
        self.headers.push((name.to_vec(), value.to_vec()));
    }

    /// `Malformed` when a cap was hit or `:status` is missing.
    pub fn finish(self, fin: bool) -> Result<RespHead, Malformed> {
        match self.status {
            Some(status) if !self.bad => Ok(RespHead {
                status,
                headers: self.headers,
                cl: self.cl.filter(|_| self.cl_count == 1),
                has_cl: self.cl_count > 0,
                fin,
            }),
            _ => Err(Malformed),
        }
    }
}

/// Status line (empty reason), the headers as received (`content-length`
/// rewritten to `0` for a `HEAD` fetch, §12), `Transfer-Encoding: chunked`
/// without a `content-length`, `Connection: close`, blank line; > 8192 bytes
/// is malformed.
pub fn render_head(h: &RespHead, fetch_method_is_head: bool) -> Result<Vec<u8>, Malformed> {
    let mut o = Vec::with_capacity(512);
    h1::write_status(&mut o, h.status, "");
    for (n, v) in &h.headers {
        let v: &[u8] = if fetch_method_is_head && n.eq_ignore_ascii_case(b"content-length") {
            b"0"
        } else {
            v
        };
        h1::write_header(&mut o, n, v).map_err(|_| Malformed)?;
    }
    if !h.has_cl {
        h1::write_header(&mut o, b"Transfer-Encoding", b"chunked").map_err(|_| Malformed)?;
    }
    h1::write_header(&mut o, b"Connection", b"close").map_err(|_| Malformed)?;
    o.extend_from_slice(b"\r\n");
    if o.len() > RESP_RENDER_MAX {
        return Err(Malformed);
    }
    Ok(o)
}

/// The fetch method is `HEAD` (the head render and the body check).
pub fn is_head(method: &Method) -> bool {
    method.as_bytes() == b"HEAD"
}

/// The response may carry a body: the fetch method is not `HEAD` and the
/// status is not 1xx/204/304 (spec §5.4 body check).
pub fn body_check_applies(method: &Method, status: u16) -> bool {
    !is_head(method) && !(100..200).contains(&status) && status != 204 && status != 304
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_http::headers::parse_method;

    fn collect(hs: &[(&str, &str)], fin: bool) -> Result<RespHead, Malformed> {
        let mut c = HeadCollector::default();
        for (n, v) in hs {
            c.push(n.as_bytes(), v.as_bytes());
        }
        c.finish(fin)
    }

    fn render(hs: &[(&str, &str)], is_head: bool) -> Result<Vec<u8>, Malformed> {
        render_head(&collect(hs, false)?, is_head)
    }

    #[test]
    fn head_render_golden_cl() {
        let got = render(
            &[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("content-length", "5"),
            ],
            false,
        );
        assert_eq!(
            got.unwrap(),
            b"HTTP/1.1 200 \r\ncontent-type: text/plain\r\ncontent-length: 5\r\nConnection: close\r\n\r\n"
        );
        let h = collect(&[(":status", "200"), ("content-length", "5")], true).unwrap();
        assert_eq!((h.cl, h.has_cl, h.fin), (Some(5), true, true));
    }

    #[test]
    fn head_render_golden_chunked() {
        let got = render(&[("content-type", "text/plain"), (":status", "404")], false);
        assert_eq!(
            got.unwrap(),
            b"HTTP/1.1 404 \r\ncontent-type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn head_status_out_of_range_is_502() {
        for s in ["000", "099", "600", "999"] {
            assert_eq!(
                collect(&[(":status", s)], false).unwrap().status,
                502,
                "{s}"
            );
        }
        for s in ["100", "599"] {
            assert_eq!(
                collect(&[(":status", s)], false)
                    .unwrap()
                    .status
                    .to_string(),
                s
            );
        }
        for s in ["20", "2000", "2x0", "", "+20", "99999999999"] {
            assert_eq!(collect(&[(":status", s)], false), Err(Malformed), "{s:?}");
        }
        assert_eq!(collect(&[("x", "y")], false), Err(Malformed), "no :status");
        // C: the last `:status` wins.
        let two = collect(&[(":status", "200"), (":status", "404")], false);
        assert_eq!(two.unwrap().status, 404);
    }

    #[test]
    fn head_drops_pseudo_and_hop_by_hop_keeps_xmq() {
        let long = "v".repeat(4000);
        let h = collect(
            &[
                (":status", "200"),
                (":path", "/x"),
                ("connection", "keep-alive"),
                ("transfer-encoding", "chunked"),
                ("proxy-connection", &long), // dropped before the caps apply
                ("keep-alive", "t\r\n"),
                ("x-mq-origin-protocol", "h2"),
                ("server", "s"),
            ],
            false,
        )
        .unwrap();
        let names: Vec<&[u8]> = h.headers.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(names, [&b"x-mq-origin-protocol"[..], b"server"]);
        assert!(!h.has_cl);
    }

    #[test]
    fn head_cr_lf_nul_malformed() {
        for bad in ["a\rb", "a\nb", "a\0b"] {
            let st = (":status", "200");
            assert_eq!(collect(&[st, ("x", bad)], false), Err(Malformed));
            assert_eq!(collect(&[st, (bad, "v")], false), Err(Malformed));
        }
        // HEAD rewriting the value does not launder it.
        let h = collect(&[(":status", "200"), ("content-length", "5\r\n")], false);
        assert_eq!(h, Err(Malformed));
    }

    #[test]
    fn head_name_128_value_2048_malformed() {
        let st = (":status", "200");
        let n127 = "n".repeat(127);
        let v2047 = "v".repeat(2047);
        assert!(collect(&[st, (&n127, &v2047)], false).is_ok());
        assert_eq!(
            collect(&[st, (&"n".repeat(128), "v")], false),
            Err(Malformed)
        );
        assert_eq!(
            collect(&[st, ("n", &"v".repeat(2048))], false),
            Err(Malformed)
        );
        // 2048 headers is the count cap (the render cap binds long before).
        let mut c = HeadCollector::default();
        c.push(b":status", b"200");
        for _ in 0..2048 {
            c.push(b"a", b"");
        }
        assert!(c.finish(false).is_ok());
        let mut c = HeadCollector::default();
        c.push(b":status", b"200");
        for _ in 0..2049 {
            c.push(b"a", b"");
        }
        assert_eq!(c.finish(false), Err(Malformed));
        // The 16 KiB arena (`name\0value\0`).
        let mut c = HeadCollector::default();
        c.push(b":status", b"200");
        for _ in 0..8 {
            c.push(b"n", &[b'v'; 2045]); // 2048 arena bytes each
        }
        assert!(c.finish(false).is_ok());
        let mut c = HeadCollector::default();
        c.push(b":status", b"200");
        for _ in 0..8 {
            c.push(b"n", &[b'v'; 2045]);
        }
        c.push(b"n", b"");
        assert_eq!(c.finish(false), Err(Malformed));
    }

    #[test]
    fn head_render_over_8192_malformed() {
        // Fixed part: "HTTP/1.1 200 \r\n" (15) + "content-length: 0\r\n" (19)
        // + "Connection: close\r\n" (19) + "\r\n" (2) = 55; "x: <v>\r\n" = 5 + len.
        let fits = "v".repeat(8192 - 55 - 5 - 4 * 2005);
        let mut hs = vec![(":status", "200"), ("content-length", "0")];
        let big = "v".repeat(2000);
        hs.extend([("x", big.as_str()); 4]);
        hs.push(("x", &fits));
        assert_eq!(render(&hs, false).unwrap().len(), 8192);
        let over = format!("{fits}v");
        *hs.last_mut().unwrap() = ("x", &over);
        assert_eq!(render(&hs, false), Err(Malformed));
    }

    #[test]
    fn head_fetch_method_head_rewrites_cl_to_0() {
        let hs = [(":status", "200"), ("content-length", "1234")];
        assert_eq!(
            render(&hs, true).unwrap(),
            b"HTTP/1.1 200 \r\ncontent-length: 0\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(
            render(&hs, false).unwrap(),
            b"HTTP/1.1 200 \r\ncontent-length: 1234\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn head_cl_single_strictly_numeric() {
        let cl = |hs: &[(&str, &str)]| {
            let mut v = vec![(":status", "200")];
            v.extend_from_slice(hs);
            let h = collect(&v, false).unwrap();
            (h.cl, h.has_cl)
        };
        assert_eq!(cl(&[("content-length", "100")]), (Some(100), true));
        assert_eq!(cl(&[("content-length", "1x0")]), (None, true));
        assert_eq!(cl(&[("content-length", "")]), (None, true));
        assert_eq!(
            cl(&[("content-length", "100"), ("content-length", "100")]),
            (None, true),
            "not single"
        );
        assert_eq!(cl(&[]), (None, false));
    }

    #[test]
    fn body_check_exempts_head_1xx_204_304() {
        let m = |s: &str| parse_method(s.as_bytes()).unwrap();
        for st in [100, 101, 199, 204, 304] {
            assert!(!body_check_applies(&m("GET"), st), "{st}");
        }
        for st in [200, 206, 404, 502] {
            assert!(!body_check_applies(&m("HEAD"), st), "{st}");
            assert!(body_check_applies(&m("GET"), st), "{st}");
            assert!(body_check_applies(&m("POST"), st), "{st}");
        }
    }
}
