// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §6.2: an H3 request's header section — captured header by
//! header (`Capture::each`), then judged in the spec's order (`decide`,
//! steps 2–8). Step 1 (the recv error) and step 9 (`origin.start`) are the
//! caller's. Every value is the full slice xquic delivered: an embedded NUL
//! is just a control byte (§12.41).

use super::ReqMeta;
use crate::server::origin::{BodyKind, Scheme};
use mq_http::h1::parse_content_length;
use mq_http::headers::{
    AUTHORITY_MAX, HttpVer, Method, name_ok, parse_http_ver, parse_method, strip_server,
    uri_field_ok, value_ok,
};
use mq_http::limits::{SectionBudget, TARGET_PATH_MAX};
use subtle::ConstantTimeEq;

/// The only two values truncated instead of rejected (§9.3).
const AUTH_CAP: usize = 511;
const CLASS_CAP: usize = 127;
const CLASS_LOG: usize = 64;

/// What one header section said, before any judgement.
#[derive(Default)]
pub(super) struct Capture {
    /// FIN on the header section (step 8).
    pub(super) fin: bool,
    method: Option<Vec<u8>>,
    scheme: Option<Vec<u8>>,
    authority: Option<Vec<u8>>,
    path: Option<Vec<u8>>,
    auth: Option<Vec<u8>>,
    class: Option<Vec<u8>>,
    ver: Option<HttpVer>,
    cl: Option<u64>,
    cl_seen: bool,
    /// Empty / non-digit / above `i64::MAX` / duplicate `content-length`.
    bad_cl: bool,
    /// The forwarded set, in order.
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    bad_header: bool,
    /// The pseudo-headers and every forwarded field (SP4 spec §5).
    budget: SectionBudget,
}

impl Capture {
    /// One header; names compare case-insensitively, a repeated
    /// pseudo-header or control header keeps the last value.
    pub(super) fn each(&mut self, n: &[u8], v: &[u8]) {
        let is = |s: &[u8]| n.eq_ignore_ascii_case(s);
        let cut = |cap: usize| Some(v[..v.len().min(cap)].to_vec());
        if n.first() == Some(&b':') {
            let slot = match () {
                _ if is(b":method") => &mut self.method,
                _ if is(b":scheme") => &mut self.scheme,
                _ if is(b":authority") => &mut self.authority,
                _ if is(b":path") => &mut self.path,
                _ => return, // other pseudo-headers: ignored
            };
            // A pseudo-header is a field too (`:path` at 8188 overflows here).
            self.bad_header |= self.budget.add(n, v).is_err();
            *slot = Some(v.to_vec());
        } else if is(b"x-mq-auth") {
            self.auth = cut(AUTH_CAP);
        } else if is(b"x-mq-class") {
            self.class = cut(CLASS_CAP);
        } else if is(b"x-mq-origin-protocol") {
            self.ver = Some(parse_http_ver(v));
        } else if is(b"content-length") {
            // Parsed strictly and not forwarded; a second one (even equal) is bad.
            match parse_content_length(v) {
                Some(cl) if !self.cl_seen => self.cl = Some(cl),
                _ => self.bad_cl = true,
            }
            self.cl_seen = true;
        } else if is(b"host") || strip_server(n) {
            // `host` is synthesised from `:authority` (§7.4, §12.14); `x-mq-cache`
            // (the response cache is gone) and hop-by-hop go with `strip_server`.
        } else if !name_ok(n) || !value_ok(v) || http::HeaderName::from_bytes(n).is_err() {
            self.bad_header = true;
        } else if self.budget.add(n, v).is_err() {
            // Field, section or count (`COUNT_MAX`) overflow.
            self.bad_header = true;
        } else {
            self.headers.push((n.to_vec(), v.to_vec()));
        }
    }
}

/// A request intake let through: everything `origin.start` needs.
pub(super) struct Admitted {
    pub(super) scheme: Scheme,
    pub(super) authority: Vec<u8>,
    pub(super) path: Vec<u8>,
    pub(super) method: Method,
    pub(super) headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub(super) ver: HttpVer,
    pub(super) body: BodyKind,
}

pub(super) struct Decision {
    /// Step 4 passed (the masquerade boundary, §6.5).
    pub(super) authed: bool,
    /// `Some` once steps 6–7 passed (§6.6: `-` in `mq.req` before).
    pub(super) meta: Option<ReqMeta>,
    pub(super) outcome: Result<Admitted, (u16, &'static str)>,
}

/// spec §6.2 steps 2–8, in order; step 5 logs `x-mq-class`.
pub(super) fn decide(c: &Capture, token: &[u8]) -> Decision {
    let reject = |authed, status, xmq| Decision {
        authed,
        meta: None,
        outcome: Err((status, xmq)),
    };
    if c.bad_header {
        return reject(false, 400, "bad-header");
    }
    if c.bad_cl {
        return reject(false, 400, "bad-request");
    }
    let tok = c.auth.as_deref().and_then(|a| a.strip_prefix(b"Bearer "));
    if !tok.is_some_and(|t| !t.is_empty() && bool::from(t.ct_eq(token))) {
        return reject(false, 403, "auth-failed");
    }
    if let Some(cls) = &c.class {
        let safe: String = cls
            .iter()
            .take(CLASS_LOG)
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '?'
                }
            })
            .collect();
        log::info!("mq_gw_server: x-mq-class='{safe}'");
    }
    let field = |f: &Option<Vec<u8>>| f.clone().filter(|v| !v.is_empty());
    let (Some(m), Some(scheme), Some(authority), Some(path)) = (
        field(&c.method),
        field(&c.scheme),
        field(&c.authority),
        field(&c.path),
    ) else {
        return reject(true, 400, "bad-request");
    };
    let scheme = match scheme.as_slice() {
        b"http" => Scheme::Http,
        b"https" => Scheme::Https,
        _ => return reject(true, 400, "bad-request"),
    };
    // Case preserved (SP4 spec §5); only the exact token CONNECT is refused (§12.34).
    let method = match parse_method(&m) {
        Some(m) if m.as_bytes() != b"CONNECT" && path[0] == b'/' => m,
        _ => return reject(true, 400, "bad-request"),
    };
    // `PathAndQuery` alone would cut at `#` and accept `"{}` (§12.14).
    if authority.len() > AUTHORITY_MAX
        || path.len() > TARGET_PATH_MAX
        || !uri_field_ok(&authority)
        || !uri_field_ok(&path)
        || path.iter().any(|b| b"#\"<>{}`".contains(b))
        || http::uri::PathAndQuery::try_from(path.as_slice()).is_err()
    {
        return reject(true, 400, "bad-target");
    }
    let meta = ReqMeta {
        method,
        authority: authority.clone(),
        path: path.clone(),
        origin_is_tls: scheme == Scheme::Https,
    };
    // Step 8: FIN on the headers wins over any `content-length`.
    let body = match (c.fin, c.cl) {
        (true, _) => BodyKind::None,
        (false, Some(n)) => BodyKind::Known(n),
        (false, None) => BodyKind::Unknown,
    };
    Decision {
        authed: true,
        meta: Some(meta),
        outcome: Ok(Admitted {
            scheme,
            authority,
            path,
            method,
            headers: c.headers.clone(),
            ver: c.ver.unwrap_or(HttpVer::Default),
            body,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_runtime::testing::log_capture;

    const TOK: &[u8] = b"secret";

    /// A valid authenticated GET; `edit` replaces (Some) or removes (None) a name.
    fn req(edit: &[(&str, Option<&[u8]>)], fin: bool) -> Capture {
        let mut hs: Vec<(String, Vec<u8>)> = [
            (":method", &b"GET"[..]),
            (":scheme", b"http"),
            (":authority", b"o.test"),
            (":path", b"/p?q=1"),
            ("x-mq-auth", b"Bearer secret"),
            ("accept", b"*/*"),
        ]
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_vec()))
        .collect();
        for (n, v) in edit {
            hs.retain(|(x, _)| x != n);
            if let Some(v) = v {
                hs.push((n.to_string(), v.to_vec()));
            }
        }
        let mut c = Capture::default();
        for (n, v) in &hs {
            c.each(n.as_bytes(), v);
        }
        c.fin = fin;
        c
    }

    fn outcome(c: &Capture) -> Result<(), (u16, &'static str)> {
        decide(c, TOK).outcome.map(|_| ())
    }

    fn admitted(c: &Capture) -> Admitted {
        decide(c, TOK).outcome.expect("admitted")
    }

    /// `n` distinct forwarded headers, appended to a valid request.
    fn many(n: usize) -> Capture {
        let mut c = req(&[], true);
        for i in 0..n {
            c.each(format!("x-h{i}").as_bytes(), b"v");
        }
        c
    }

    #[test]
    fn intake_order_2_to_8() {
        let bad_auth: (&str, Option<&[u8]>) = ("x-mq-auth", Some(b"Bearer nope"));
        let no_method: (&str, Option<&[u8]>) = (":method", None);
        let long_auth = vec![b'a'; 256];
        let long: (&str, Option<&[u8]>) = (":authority", Some(&long_auth));
        // 2 before 3 and 4.
        let mut c = req(&[bad_auth, ("a b", Some(b"v"))], false);
        c.each(b"content-length", b"x");
        let d = decide(&c, TOK);
        assert_eq!(d.outcome.map(|_| ()), Err((400, "bad-header")));
        assert!(!d.authed && d.meta.is_none());
        // Count overflow (SP4 spec §5) is a step-2 `bad-header`, before auth.
        let mut c = many(257);
        c.each(b"x-mq-auth", b"Bearer nope");
        assert_eq!(outcome(&c), Err((400, "bad-header")));
        // 3 before 4: a bad content-length.
        let mut c = req(&[bad_auth], false);
        c.each(b"content-length", b"");
        assert_eq!(outcome(&c), Err((400, "bad-request")));
        // 4 before 6.
        let d = decide(&req(&[bad_auth, no_method], false), TOK);
        assert_eq!(d.outcome.map(|_| ()), Err((403, "auth-failed")));
        assert!(!d.authed);
        // 6 before 7; authed from here on.
        let d = decide(&req(&[no_method, long], false), TOK);
        assert_eq!(d.outcome.map(|_| ()), Err((400, "bad-request")));
        assert!(d.authed && d.meta.is_none());
        // 7.
        let d = decide(&req(&[long], false), TOK);
        assert_eq!(d.outcome.map(|_| ()), Err((400, "bad-target")));
        assert!(d.authed && d.meta.is_none());
        // 8 never rejects.
        let d = decide(&req(&[], false), TOK);
        assert!(d.authed && d.meta.is_some());
        assert_eq!(d.outcome.expect("admitted").body, BodyKind::Unknown);
    }

    #[test]
    fn step_6_pseudo_headers_bad_request() {
        for (n, v) in [
            (":method", None),
            (":method", Some(&b""[..])),
            (":method", Some(b"G T")),
            (":method", Some(&[b'A'; 33])), // 33
            (":scheme", None),
            (":scheme", Some(b"HTTP")),
            (":scheme", Some(b"ftp")),
            (":scheme", Some(b"httpsxyz")),
            (":authority", None),
            (":authority", Some(b"")),
            (":path", None),
            (":path", Some(b"")),
            (":path", Some(b"p")),
            (":path", Some(b"*")),
        ] {
            let c = req(&[(n, v)], false);
            assert_eq!(outcome(&c), Err((400, "bad-request")), "{n} {v:?}");
        }
        let c = req(&[(":method", Some(b"ABCDEFGHIJKLMNOP"))], false); // 16
        assert_eq!(outcome(&c), Ok(()));
        let c = req(&[(":method", Some(&[b'A'; 32]))], false); // 32
        assert_eq!(outcome(&c), Ok(()));
    }

    #[test]
    fn auth_constant_time_and_truncated_511() {
        for v in [
            &b"Bearer secreT"[..],
            b"Bearer secre",
            b"Bearer secret ",
            b"bearer secret",
            b"Bearer ",
            b"Bearer",
            b"secret",
            b"Basic secret",
        ] {
            let c = req(&[("x-mq-auth", Some(v))], false);
            assert_eq!(outcome(&c), Err((403, "auth-failed")), "{v:?}");
        }
        assert_eq!(
            outcome(&req(&[("x-mq-auth", None)], false)),
            Err((403, "auth-failed"))
        );
        assert_eq!(outcome(&req(&[], false)), Ok(()));
        // An empty configured token never matches.
        assert!(
            decide(&req(&[("x-mq-auth", Some(b"Bearer "))], false), b"")
                .outcome
                .is_err()
        );
        // The value is cut at 511 bytes before the compare.
        let token = vec![b't'; 504];
        let mut v = b"Bearer ".to_vec();
        v.extend_from_slice(&token);
        v.extend_from_slice(b"junk");
        let c = req(&[("x-mq-auth", Some(&v))], false);
        assert_eq!(c.auth.as_ref().map(Vec::len), Some(511));
        assert!(decide(&c, &token).authed, "the cut value matches");
        // Header names match case-insensitively.
        let mut c = req(&[("x-mq-auth", None)], false);
        c.each(b"X-Mq-Auth", b"Bearer secret");
        assert_eq!(outcome(&c), Ok(()));
    }

    #[test]
    fn nul_in_auth_fails_auth() {
        let c = req(&[("x-mq-auth", Some(b"Bearer secret\0junk"))], false);
        assert_eq!(outcome(&c), Err((403, "auth-failed")));
    }

    #[test]
    fn class_logged_sanitised_64() {
        log_capture::install();
        let class_line = |v: &[u8], auth: &[u8]| {
            log_capture::take();
            decide(
                &req(&[("x-mq-class", Some(v)), ("x-mq-auth", Some(auth))], false),
                TOK,
            );
            log_capture::take()
                .into_iter()
                .filter(|l| l.contains("x-mq-class"))
                .collect::<Vec<_>>()
        };
        let ok = b"Bearer secret";
        assert_eq!(
            class_line(b"a\0b", ok),
            ["INFO mq_gw_server: x-mq-class='a?b'"]
        );
        assert_eq!(
            class_line("é\x7f\t~".as_bytes(), ok),
            ["INFO mq_gw_server: x-mq-class='????~'"]
        );
        let long = class_line(&[b'c'; 100], ok);
        assert_eq!(
            long,
            [format!(
                "INFO mq_gw_server: x-mq-class='{}'",
                "c".repeat(64)
            )]
        );
        assert!(
            class_line(b"x", b"Bearer nope").is_empty(),
            "step 5 follows auth"
        );
        // The class is cut at 127 bytes.
        let c = req(&[("x-mq-class", Some(&[b'c'; 200]))], false);
        assert_eq!(c.class.as_ref().map(Vec::len), Some(127));
    }

    #[test]
    fn method_case_preserved() {
        let c = req(&[(":method", Some(b"pAtCh"))], false);
        let d = decide(&c, TOK);
        assert_eq!(d.meta.expect("meta").method.as_bytes(), b"pAtCh");
        assert_eq!(d.outcome.expect("admitted").method.as_bytes(), b"pAtCh");
    }

    #[test]
    fn intake_lowercase_custom_method_preserved() {
        let c = req(&[(":method", Some(b"purge"))], false);
        let d = decide(&c, TOK);
        assert_eq!(d.meta.expect("meta").method.as_bytes(), b"purge");
        assert_eq!(d.outcome.expect("admitted").method.as_bytes(), b"purge");
    }

    #[test]
    fn connect_rejected_400_bad_request() {
        // Only the exact token; `connect` is an ordinary method here.
        let c = req(&[(":method", Some(b"CONNECT"))], false);
        assert_eq!(outcome(&c), Err((400, "bad-request")));
        for m in [&b"connect"[..], b"Connect"] {
            let c = req(&[(":method", Some(m))], false);
            assert_eq!(outcome(&c), Ok(()), "{m:?}");
        }
    }

    #[test]
    fn path_byte_check_rejects_hash_quote_braces_backtick_lt_gt() {
        for p in [
            &b"/a#b"[..],
            b"/a?b#c",
            b"/a\"b",
            b"/a<b",
            b"/a>b",
            b"/a{b",
            b"/a}b",
            b"/a`b",
            b"/a?q=`",
            b"/a b",
            b"/a\x7fb",
            b"/a\rb",
        ] {
            let c = req(&[(":path", Some(p))], false);
            assert_eq!(outcome(&c), Err((400, "bad-target")), "{p:?}");
        }
        let c = req(&[(":path", Some(b"/a/b.c?x=1&y=%20"))], false);
        assert_eq!(outcome(&c), Ok(()));
    }

    #[test]
    fn path_valid_utf8_accepted_invalid_rejected() {
        let c = req(&[(":path", Some("/é?ü=1".as_bytes()))], false);
        assert_eq!(admitted(&c).path, "/é?ü=1".as_bytes());
        for p in [&b"/\xff"[..], b"/\xc3", b"/a?\xc3("] {
            let c = req(&[(":path", Some(p))], false);
            assert_eq!(outcome(&c), Err((400, "bad-target")), "{p:?}");
        }
    }

    #[test]
    fn authority_overlong_bad_target() {
        let a255 = vec![b'a'; 255];
        let a256 = vec![b'a'; 256];
        assert_eq!(outcome(&req(&[(":authority", Some(&a255))], false)), Ok(()));
        assert_eq!(
            outcome(&req(&[(":authority", Some(&a256))], false)),
            Err((400, "bad-target"))
        );
        assert_eq!(
            outcome(&req(&[(":authority", Some(b"o test"))], false)),
            Err((400, "bad-target"))
        );
    }

    fn path_of(n: usize) -> Vec<u8> {
        let mut p = b"/".to_vec();
        p.resize(n, b'p');
        p
    }

    #[test]
    fn intake_path_8187_ok_8188_bad_header() {
        // `:path` is a field too: name 5 + value 8187 = FIELD_MAX exactly.
        let ok = path_of(TARGET_PATH_MAX);
        assert_eq!(outcome(&req(&[(":path", Some(&ok))], false)), Ok(()));
        // At 8188 the field budget trips first (step 2), not the target check.
        let over = path_of(TARGET_PATH_MAX + 1);
        assert_eq!(
            outcome(&req(&[(":path", Some(&over))], false)),
            Err((400, "bad-header"))
        );
        // The 1 KiB-era boundary is gone.
        let p1024 = path_of(1024);
        assert_eq!(outcome(&req(&[(":path", Some(&p1024))], false)), Ok(()));
    }

    #[test]
    fn nul_in_path_bad_target() {
        let c = req(&[(":path", Some(b"/ok\0junk"))], false);
        assert_eq!(outcome(&c), Err((400, "bad-target")));
    }

    #[test]
    fn host_header_dropped() {
        let mut c = req(&[], true);
        c.each(b"host", b"evil.test");
        c.each(b"Host", b"evil.test");
        c.each(b"x-a", b"1");
        let a = admitted(&c);
        assert_eq!(
            a.headers,
            [
                (b"accept".to_vec(), b"*/*".to_vec()),
                (b"x-a".to_vec(), b"1".to_vec())
            ]
        );
    }

    #[test]
    fn forwarded_set_strips_and_caps() {
        let mut c = req(&[], true);
        for (n, v) in [
            (&b"authorization"[..], &b"Basic x"[..]),
            (b"connection", b"close"),
            (b"te", b"trailers"),
            (b"proxy-connection", b"x"),
            (b"x-mq-cache", b"60"),
            (b"x-mq-other", b"1"),
            (b"x-mq-origin-protocol", b"h2"),
            (b"content-length", b"5"),
            (b"x-tab", b"a\tb"),
        ] {
            c.each(n, v);
        }
        let a = admitted(&c);
        let names: Vec<&[u8]> = a.headers.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(names, [&b"accept"[..], b"authorization", b"x-tab"]);
        assert_eq!(a.ver, HttpVer::H2);
        // control bytes / non-tchar names → bad-header.
        let ok = |n: &[u8], v: &[u8]| {
            let mut c = req(&[], true);
            c.each(n, v);
            outcome(&c)
        };
        for (n, v) in [
            (&b"x"[..], &b"a\rb"[..]),
            (b"x", b"a\0b"),
            (b"x\tb", b"v"),
            (b"x(y", b"v"),
            (b"x:y", b"v"),
        ] {
            assert_eq!(ok(n, v), Err((400, "bad-header")), "{n:?} {v:?}");
        }
    }

    #[test]
    fn intake_6k_cookie_admitted() {
        let mut c = req(&[], true);
        c.each(b"cookie", &vec![b'c'; 6 * 1024]);
        let a = admitted(&c);
        assert_eq!(a.headers.last().map(|(_, v)| v.len()), Some(6 * 1024));
    }

    #[test]
    fn intake_field_8192_ok_8193_bad_header() {
        let ok = |v: usize| {
            let mut c = req(&[], true);
            c.each(b"x", &vec![b'v'; v]);
            outcome(&c)
        };
        assert_eq!(ok(8191), Ok(()));
        assert_eq!(ok(8192), Err((400, "bad-header")));
    }

    #[test]
    fn intake_section_over_32k_bad_header() {
        // Each field is under FIELD_MAX; together they pass SECTION_MAX.
        let mut c = req(&[], true);
        for i in 0..4 {
            c.each(format!("x-{i}").as_bytes(), &vec![b'v'; 8000]);
        }
        assert_eq!(
            outcome(&c),
            Ok(()),
            "~32.1 KiB with the pseudo-headers fits"
        );
        c.each(b"x-4", &vec![b'v'; 8000]);
        assert_eq!(outcome(&c), Err((400, "bad-header")));
    }

    #[test]
    fn intake_count_256_incl_pseudo_then_bad_header() {
        // 4 pseudo-headers + accept already count: 251 more reach COUNT_MAX.
        assert_eq!(outcome(&many(251)), Ok(()));
        assert_eq!(outcome(&many(252)), Err((400, "bad-header")));
    }

    #[test]
    fn cl_duplicate_or_overflow_bad_request() {
        for vs in [
            &[&b"5"[..], b"5"][..],
            &[b"9223372036854775808"],
            &[b""],
            &[b"1a"],
            &[b"-1"],
            &[b" 5"],
        ] {
            let mut c = req(&[], false);
            for v in vs {
                c.each(b"Content-Length", v);
            }
            assert_eq!(outcome(&c), Err((400, "bad-request")), "{vs:?}");
        }
        let mut c = req(&[], false);
        c.each(b"content-length", b"9223372036854775807");
        let a = admitted(&c);
        assert_eq!(a.body, BodyKind::Known(i64::MAX as u64));
        assert!(
            a.headers.iter().all(|(n, _)| n != b"content-length"),
            "not forwarded"
        );
    }

    #[test]
    fn fin_on_headers_overrides_cl() {
        let with_cl = |fin| {
            let mut c = req(&[], fin);
            c.each(b"content-length", b"10");
            admitted(&c).body
        };
        assert_eq!(with_cl(true), BodyKind::None);
        assert_eq!(with_cl(false), BodyKind::Known(10));
        assert_eq!(admitted(&req(&[], true)).body, BodyKind::None);
        assert_eq!(admitted(&req(&[], false)).body, BodyKind::Unknown);
    }

    #[test]
    fn decision_success_records_meta() {
        let c = req(
            &[(":scheme", Some(b"https")), (":method", Some(b"post"))],
            false,
        );
        let d = decide(&c, TOK);
        assert!(d.authed);
        let m = d.meta.expect("meta");
        assert_eq!(m.method.as_bytes(), b"post");
        assert_eq!(m.authority, b"o.test");
        assert_eq!(
            m.path, b"/p?q=1",
            "the query is cut for the log by §6.6, not here"
        );
        assert!(m.origin_is_tls);
        let a = d.outcome.expect("admitted");
        assert_eq!(a.scheme, Scheme::Https);
        assert_eq!(
            (a.authority.as_slice(), a.path.as_slice()),
            (&b"o.test"[..], &b"/p?q=1"[..])
        );
        assert_eq!(a.ver, HttpVer::Default);
        assert!(
            !decide(&req(&[], false), TOK)
                .meta
                .expect("meta")
                .origin_is_tls
        );
    }
}
