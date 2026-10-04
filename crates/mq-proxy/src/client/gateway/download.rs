//! SP3 spec §5.4: the fetch download's response head — collected from the H3
//! header section under the shared limits (SP4 spec §5), rendered as the local
//! HTTP/1.1 head (`adp_resp_head`).

use mq_http::h1;
use mq_http::headers::is_hop_by_hop;
use mq_http::limits::{SECTION_MAX, SectionBudget};

/// SP4 spec §5: the render buffer, `SECTION_MAX` plus room for the status line
/// and the `Transfer-Encoding` / `Connection` lines.
const RESP_RENDER_MAX: usize = SECTION_MAX + 1024;

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
    /// Over the whole section, `:status` included (SP4 spec §5).
    budget: SectionBudget,
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
                    self.bad = self.budget.add(name, value).is_err();
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
        if self.budget.add(name, value).is_err() || ctl(name) || ctl(value) {
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
/// without a `content-length`, `Connection: close`, blank line; over `RESP_RENDER_MAX` bytes
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

#[cfg(test)]
mod tests {
    use super::*;
    use mq_http::limits::{COUNT_MAX, FIELD_MAX};

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
    fn head_field_over_field_max_malformed() {
        let st = (":status", "200");
        // name + value = FIELD_MAX fits, one byte more does not.
        let v_fits = "v".repeat(FIELD_MAX - 1);
        assert!(collect(&[st, ("n", &v_fits)], false).is_ok());
        assert_eq!(
            collect(&[st, ("n", &format!("{v_fits}v"))], false),
            Err(Malformed)
        );
        let n_fits = "n".repeat(FIELD_MAX);
        assert!(collect(&[st, (&n_fits, "")], false).is_ok());
        assert_eq!(
            collect(&[st, (&format!("{n_fits}n"), "")], false),
            Err(Malformed)
        );
    }

    #[test]
    fn collector_6k_value_ok() {
        let six_k = "v".repeat(6 * 1024);
        let h = collect(&[(":status", "200"), ("x-big", &six_k)], false).unwrap();
        assert_eq!(h.headers, [(b"x-big".to_vec(), six_k.into_bytes())]);
    }

    #[test]
    fn collector_257_headers_malformed() {
        // `:status` counts: 255 more headers make 256 fields, 256 more make 257.
        let fill = |n: usize| {
            let mut c = HeadCollector::default();
            c.push(b":status", b"200");
            for _ in 0..n {
                c.push(b"a", b"");
            }
            c.finish(false)
        };
        assert!(fill(COUNT_MAX - 1).is_ok());
        assert_eq!(fill(COUNT_MAX), Err(Malformed));
    }

    /// `:status: 200` costs 7 + 3 + 32 = 42; seven 4032-byte fields and one of 4502
    /// fill SECTION_MAX exactly.
    fn full_section<'a>(v: &'a str, last: &'a str) -> Vec<(&'a str, &'a str)> {
        let mut hs = vec![(":status", "200")];
        hs.extend([("n", v); 7]);
        hs.push(("n", last));
        hs
    }

    #[test]
    fn collector_section_budget_counts_status_and_32k_binds() {
        let (v, last) = ("v".repeat(3999), "v".repeat(4469));
        let mut hs = full_section(&v, &last);
        assert!(collect(&hs, false).is_ok());
        hs.push(("a", ""));
        assert_eq!(collect(&hs, false), Err(Malformed));
        let over = format!("{last}v");
        assert_eq!(
            collect(&full_section(&v, &over), false),
            Err(Malformed),
            "one byte over"
        );
    }

    #[test]
    fn render_head_near_section_max_fits() {
        // A section filling SECTION_MAX renders (about 32.5 KiB) within the cap.
        let (v, last) = ("v".repeat(3999), "v".repeat(4469));
        let got = render(&full_section(&v, &last), false).unwrap();
        assert!(
            got.len() > 32_000 && got.len() <= RESP_RENDER_MAX,
            "{}",
            got.len()
        );
    }

    #[test]
    fn head_render_over_8192_ok() {
        // SP3's 8 KiB render cap is gone: the old at-the-cap fixture plus one byte.
        let fits = "v".repeat(8192 - 55 - 5 - 4 * 2005 + 1);
        let big = "v".repeat(2000);
        let mut hs = vec![(":status", "200"), ("content-length", "0")];
        hs.extend([("x", big.as_str()); 4]);
        hs.push(("x", &fits));
        assert_eq!(render(&hs, false).unwrap().len(), 8193);
    }

    #[test]
    fn head_render_over_render_max_malformed() {
        // The collector cannot produce this (a rendered field is 4 bytes over its
        // content, the budget's is 32), so build the head directly.
        let mk = |n: usize| RespHead {
            status: 200,
            headers: vec![(b"x".to_vec(), vec![b'v'; n])],
            cl: None,
            has_cl: true,
            fin: false,
        };
        // "HTTP/1.1 200 \r\n" (15) + "x: <v>\r\n" (5 + n) + "Connection: close\r\n" (19) + "\r\n" (2).
        let fits = RESP_RENDER_MAX - 15 - 5 - 19 - 2;
        let at_cap = render_head(&mk(fits), false).unwrap();
        assert_eq!(at_cap.len(), RESP_RENDER_MAX);
        assert_eq!(render_head(&mk(fits + 1), false), Err(Malformed));
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
}
