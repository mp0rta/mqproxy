//! The collected H3 response head (SP4 spec §4.2 / §5; moved from the SP3
//! fetch download). `fin` goes away in Task 5.1, once the gateway stops using it.

use mq_http::h1;
use mq_http::headers::is_hop_by_hop;
use mq_http::limits::SectionBudget;

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

    /// `:status: 200` costs 7 + 3 + 32 = 42; seven 4032-byte fields and one of 4502
    /// fill SECTION_MAX exactly.
    fn full_section<'a>(v: &'a str, last: &'a str) -> Vec<(&'a str, &'a str)> {
        let mut hs = vec![(":status", "200")];
        hs.extend([("n", v); 7]);
        hs.push(("n", last));
        hs
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
