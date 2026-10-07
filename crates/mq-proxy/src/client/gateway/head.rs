//! SP3 spec §5.2: the fetch request head — the gateway reject sequence (steps
//! 1–8) building the front-neutral `ReqHead` (SP4 spec §6.2); §5.6 the
//! synthesised error reply.

use crate::client::exchange::{BodyLen, ReqHead};
use mq_http::h1;
use mq_http::headers::{
    HttpVer, Reject, forward_cookie_requested, has_dup_xmq, parse_cache_ttl, parse_http_ver,
    parse_method, parse_method_upper, parse_target, strip_client,
};

/// A control value (auth, class, accept-encoding) of this many bytes is too long
/// (SP4 spec §5: unchanged; the forwarded headers use `mq_http::limits`).
const CTL_VAL_MAX: usize = 1024;

/// SP3 spec §5.2 reject steps 1–8, in that order, building the front-neutral
/// head (SP4 spec §6.2). A control value is the first header of its name. The
/// sizes are checked by `render` (SP4 spec §4.4), except the control values'.
pub fn fetch_head(h: &h1::Head<'_>) -> Result<ReqHead, Reject> {
    let find = |name: &[u8]| {
        (h.headers.iter())
            .find(|x| x.name.eq_ignore_ascii_case(name))
            .map(|x| x.value)
    };
    if has_dup_xmq(h.headers.iter().map(|x| x.name)) {
        return Err(Reject::DupControl);
    }
    let auth = find(b"x-mq-auth").ok_or(Reject::MissingAuth)?;
    // Case-sensitive prefix, non-empty token.
    if auth.len() <= 7 || !auth.starts_with(b"Bearer ") {
        return Err(Reject::BadAuthFormat);
    }
    let target = find(b"x-mq-target")
        .and_then(parse_target)
        .ok_or(Reject::BadTarget)?;
    let method = match find(b"x-mq-method") {
        None => parse_method(b"GET").expect("a token"),
        // CONNECT: an upgrade the bridge does not implement (§12).
        Some(m) => parse_method_upper(m)
            .filter(|m| m.as_bytes() != b"CONNECT")
            .ok_or(Reject::BadMethod)?,
    };
    // Empty control values are absent; the wire carries the raw tokens.
    let origin_proto = match find(b"x-mq-origin-protocol") {
        Some(v) if !v.is_empty() => match parse_http_ver(v) {
            HttpVer::Default => return Err(Reject::BadOriginProto),
            ver => Some((ver, v.to_vec())),
        },
        _ => None,
    };
    let cache = match find(b"x-mq-cache") {
        Some(v) if !v.is_empty() => match parse_cache_ttl(v) {
            0 => return Err(Reject::BadCacheTtl),
            _ => Some(v.to_vec()),
        },
        _ => None,
    };
    let class = find(b"x-mq-class");
    let ae = find(b"x-mq-accept-encoding");
    let long = |v: Option<&[u8]>| v.is_some_and(|v| v.len() >= CTL_VAL_MAX);
    if long(Some(auth)) || long(class) || long(ae) {
        return Err(Reject::HeaderTooLong);
    }
    // An empty control header leaves the caller's `Accept-Encoding` alone; a
    // non-empty one replaces it, so the caller's is not forwarded.
    let ae = ae.filter(|v| !v.is_empty());
    let cookie = forward_cookie_requested(h.headers.iter().map(|x| (x.name, x.value)));
    let headers = (h.headers.iter())
        .filter(|x| {
            !strip_client(x.name, cookie)
                && !(ae.is_some() && x.name.eq_ignore_ascii_case(b"accept-encoding"))
        })
        .map(|x| (x.name.to_vec(), x.value.to_vec()))
        .collect();
    Ok(ReqHead {
        method,
        target,
        auth: auth.to_vec(),
        class: class.map(<[u8]>::to_vec),
        origin_proto,
        cache,
        accept_encoding: ae.map(<[u8]>::to_vec),
        headers,
        body: match h.content_length {
            None | Some(0) => BodyLen::Empty,
            Some(n) => BodyLen::Known(n),
        },
    })
}

/// Spec §5.6: `HTTP/1.1 <code> \r\nX-Mq-Error: <xmq>\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`.
pub fn synth_error(code: u16, xmq: &str) -> Vec<u8> {
    let mut o = Vec::with_capacity(96);
    h1::write_status(&mut o, code, "");
    // fixed names, §9.1 constants: cannot fail
    let _ = h1::write_header(&mut o, b"X-Mq-Error", xmq.as_bytes());
    let _ = h1::write_header(&mut o, b"Content-Length", b"0");
    let _ = h1::write_header(&mut o, b"Connection", b"close");
    o.extend_from_slice(b"\r\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::exchange::wire::render;
    use mq_http::limits::FIELD_MAX;

    type Hs = Vec<(Vec<u8>, Vec<u8>)>;

    /// SP3's `check` + `forwarded_headers`, frozen as the oracle of
    /// `fetch_head_equivalent_to_sp3_check` (the 72-header cap is never hit there).
    mod sp3 {
        use mq_http::h1;
        use mq_http::headers::{
            HttpVer, Method, Reject, Target, forward_cookie_requested, has_dup_xmq,
            parse_cache_ttl, parse_http_ver, parse_method, parse_method_upper, parse_target,
            strip_client,
        };
        use mq_http::limits::SectionBudget;

        const CTL_VAL_MAX: usize = 1024;

        /// spec §5.2: at most 64 + 8 headers.
        const MAX_FWD: usize = h1::MAX_HEADERS + 8;

        /// The request head, owned (spec §5.2: the parser's borrows end at
        /// `tcp_consume`). The control values are raw; `None` = header absent, so the
        /// reject steps can tell absent from invalid.
        #[derive(Debug)]
        pub struct Head {
            /// `X-Mq-Method`.
            pub method: Option<Vec<u8>>,
            /// `X-Mq-Target`.
            pub target: Option<Vec<u8>>,
            /// Every header line, in request order.
            pub headers: Vec<(Vec<u8>, Vec<u8>)>,
            /// `Content-Length`; absent = 0 (no body).
            pub content_length: u64,
            pub auth: Option<Vec<u8>>,
            pub origin_proto: Option<Vec<u8>>,
            pub cache: Option<Vec<u8>>,
            pub class: Option<Vec<u8>>,
            pub accept_encoding: Option<Vec<u8>>,
            pub forward_cookie: bool,
        }

        impl Head {
            /// Copy a parsed head; a control value is the first header of its name.
            pub fn from_h1(h: &h1::Head<'_>) -> Head {
                let find = |name: &[u8]| {
                    h.headers
                        .iter()
                        .find(|x| x.name.eq_ignore_ascii_case(name))
                        .map(|x| x.value.to_vec())
                };
                Head {
                    method: find(b"x-mq-method"),
                    target: find(b"x-mq-target"),
                    headers: h
                        .headers
                        .iter()
                        .map(|x| (x.name.to_vec(), x.value.to_vec()))
                        .collect(),
                    content_length: h.content_length.unwrap_or(0),
                    auth: find(b"x-mq-auth"),
                    origin_proto: find(b"x-mq-origin-protocol"),
                    cache: find(b"x-mq-cache"),
                    class: find(b"x-mq-class"),
                    accept_encoding: find(b"x-mq-accept-encoding"),
                    forward_cookie: forward_cookie_requested(
                        h.headers.iter().map(|x| (x.name, x.value)),
                    ),
                }
            }
        }

        /// The values the reject sequence parsed (spec §5.2).
        #[derive(Debug)]
        pub struct Checked {
            pub method: Method,
            pub target: Target,
            /// `Default` = no (or an empty) `X-Mq-Origin-Protocol`.
            pub http_ver: HttpVer,
            /// 0 = no (or an empty) `X-Mq-Cache`.
            pub cache_ttl: u32,
            /// The original `X-Mq-Auth` value.
            pub auth: Vec<u8>,
        }

        /// Spec §5.2 reject steps 1–8, in that order.
        pub fn check(head: &Head) -> Result<Checked, Reject> {
            if has_dup_xmq(head.headers.iter().map(|(n, _)| n.as_slice())) {
                return Err(Reject::DupControl);
            }
            let auth = head.auth.as_ref().ok_or(Reject::MissingAuth)?;
            // Case-sensitive prefix, non-empty token.
            if auth.len() <= 7 || !auth.starts_with(b"Bearer ") {
                return Err(Reject::BadAuthFormat);
            }
            let target = head
                .target
                .as_deref()
                .and_then(parse_target)
                .ok_or(Reject::BadTarget)?;
            let method = match &head.method {
                None => parse_method(b"GET").expect("a token"),
                // CONNECT: an upgrade the bridge does not implement (§12).
                Some(m) => parse_method_upper(m)
                    .filter(|m| m.as_bytes() != b"CONNECT")
                    .ok_or(Reject::BadMethod)?,
            };
            let http_ver = match head.origin_proto.as_deref() {
                Some(v) if !v.is_empty() => match parse_http_ver(v) {
                    HttpVer::Default => return Err(Reject::BadOriginProto),
                    ver => ver,
                },
                _ => HttpVer::Default,
            };
            let cache_ttl = match head.cache.as_deref() {
                Some(v) if !v.is_empty() => match parse_cache_ttl(v) {
                    0 => return Err(Reject::BadCacheTtl),
                    ttl => ttl,
                },
                _ => 0,
            };
            // An empty value is never too long, so presence is all that matters here.
            let long = |v: &Option<Vec<u8>>| v.as_ref().is_some_and(|v| v.len() >= CTL_VAL_MAX);
            if long(&head.auth) || long(&head.class) || long(&head.accept_encoding) {
                return Err(Reject::HeaderTooLong);
            }
            let checked = Checked {
                method,
                target,
                http_ver,
                cache_ttl,
                auth: auth.clone(),
            };
            // SP4 spec §5: the budget covers exactly what is forwarded, pseudo-headers included.
            let mut budget = SectionBudget::default();
            if forwarded_headers(head, &checked)
                .iter()
                .any(|(n, v)| budget.add(n, v).is_err())
            {
                return Err(Reject::HeaderTooLong);
            }
            Ok(checked)
        }

        /// Spec §5.2: the forwarded H3 header list, in order.
        pub fn forwarded_headers(head: &Head, c: &Checked) -> Vec<(Vec<u8>, Vec<u8>)> {
            let h = |n: &str, v: &[u8]| (n.as_bytes().to_vec(), v.to_vec());
            let mut out = vec![
                h(":method", c.method.as_bytes()),
                h(":scheme", c.target.scheme.as_bytes()),
                h(":authority", &c.target.authority),
                h(":path", &c.target.path),
                h("x-mq-auth", &c.auth),
            ];
            if let Some(v) = &head.class {
                out.push(h("x-mq-class", v));
            }
            // The raw tokens, only when valid ones were parsed.
            if c.http_ver != HttpVer::Default
                && let Some(v) = &head.origin_proto
            {
                out.push(h("x-mq-origin-protocol", v));
            }
            if c.cache_ttl != 0
                && let Some(v) = &head.cache
            {
                out.push(h("x-mq-cache", v));
            }
            // An empty control header leaves the caller's `Accept-Encoding` alone.
            let ae = head.accept_encoding.as_ref().filter(|v| !v.is_empty());
            if let Some(v) = ae {
                out.push(h("accept-encoding", v));
            }
            if head.content_length > 0 {
                out.push(h(
                    "content-length",
                    head.content_length.to_string().as_bytes(),
                ));
            }
            for (n, v) in &head.headers {
                if strip_client(n, head.forward_cookie)
                    || (ae.is_some() && n.eq_ignore_ascii_case(b"accept-encoding"))
                {
                    continue;
                }
                out.push((n.to_ascii_lowercase(), v.clone()));
            }
            out.truncate(MAX_FWD);
            out
        }
    }

    /// An `h1::Head` with `hs` as its header lines, built directly (no
    /// `HEAD_MAX` / 64-header parse caps), `content_length` as the parser sets it.
    fn h1head<'a>(hs: &'a [(&'a str, &'a str)]) -> h1::Head<'a> {
        let cl = hs
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| h1::parse_content_length(v.as_bytes()));
        h1::Head {
            method: b"POST",
            target: b"/_mqproxy/fetch",
            headers: hs
                .iter()
                .map(|(n, v)| h1::Header {
                    name: n.as_bytes(),
                    value: v.as_bytes(),
                })
                .collect(),
            content_length: cl,
            has_chunked_te: false,
        }
    }

    fn fetch(hs: &[(&str, &str)]) -> Result<ReqHead, Reject> {
        fetch_head(&h1head(hs))
    }

    /// The front plus the core's render: the wire header list or the reject.
    fn wire(hs: &[(&str, &str)]) -> Result<Hs, Reject> {
        let w = render(&fetch(hs)?)?;
        Ok(w.headers()
            .map(|x| (x.name.to_vec(), x.value.to_vec()))
            .collect())
    }

    fn rej(hs: &[(&str, &str)]) -> Reject {
        wire(hs).expect_err("rejected")
    }

    fn fwd(hs: &[(&str, &str)]) -> Hs {
        wire(hs).expect("accepted")
    }

    fn hs(pairs: &[(&str, &str)]) -> Hs {
        pairs
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    const AUTH: (&str, &str) = ("X-Mq-Auth", "Bearer t");
    const TARGET: (&str, &str) = ("X-Mq-Target", "https://example.com/p");

    #[test]
    fn reject_order_1_to_8() {
        let long = "x".repeat(FIELD_MAX);
        let cases: [(&[(&str, &str)], Reject); 8] = [
            (
                &[AUTH, ("x-mq-auth", "Bearer u"), ("X-Mq-Target", "bad")],
                Reject::DupControl,
            ),
            (&[("X-Mq-Target", "bad")], Reject::MissingAuth),
            (
                &[("X-Mq-Auth", "Basic t"), ("X-Mq-Target", "bad")],
                Reject::BadAuthFormat,
            ),
            (
                &[AUTH, ("X-Mq-Target", "ftp://h/"), ("X-Mq-Method", "G(T")],
                Reject::BadTarget,
            ),
            (
                &[
                    AUTH,
                    TARGET,
                    ("X-Mq-Method", "G(T"),
                    ("X-Mq-Origin-Protocol", "h4"),
                ],
                Reject::BadMethod,
            ),
            (
                &[
                    AUTH,
                    TARGET,
                    ("X-Mq-Origin-Protocol", "h4"),
                    ("X-Mq-Cache", "x"),
                ],
                Reject::BadOriginProto,
            ),
            (
                &[AUTH, TARGET, ("X-Mq-Cache", "0"), ("X-Long", &long)],
                Reject::BadCacheTtl,
            ),
            (
                &[
                    AUTH,
                    TARGET,
                    ("X-Mq-Accept-Encoding", "gzip"),
                    ("X-Long", &long),
                ],
                Reject::HeaderTooLong,
            ),
        ];
        for (hs, want) in cases {
            assert_eq!(rej(hs), want, "{hs:?}");
        }
        // A missing target is step 4 too.
        assert_eq!(rej(&[AUTH]), Reject::BadTarget);
    }

    #[test]
    fn header_too_long_caps() {
        let v = |n: usize| "v".repeat(n);
        let auth = format!("Bearer {}", v(1024 - 7));
        // A forwarded field is `name + value`, at most FIELD_MAX bytes.
        let other = v(FIELD_MAX - "x-other".len());
        let over_other = v(FIELD_MAX - "x-other".len() + 1);
        let name = "n".repeat(FIELD_MAX + 1);
        let too_long: [&[(&str, &str)]; 5] = [
            &[("X-Mq-Auth", &auth), TARGET],
            &[AUTH, TARGET, ("X-Mq-Class", &v(1024))],
            &[AUTH, TARGET, ("X-Mq-Accept-Encoding", &v(1024))],
            &[AUTH, TARGET, (&name, "")],
            &[AUTH, TARGET, ("X-Other", &over_other)],
        ];
        for hs in too_long {
            assert_eq!(rej(hs), Reject::HeaderTooLong);
        }
        let auth = format!("Bearer {}", v(1023 - 7));
        let name = "n".repeat(FIELD_MAX);
        let fits: [&[(&str, &str)]; 5] = [
            &[("X-Mq-Auth", &auth), TARGET],
            &[AUTH, TARGET, ("X-Mq-Class", &v(1023))],
            &[AUTH, TARGET, (&name, "")],
            &[AUTH, TARGET, ("X-Other", &other)],
            &[
                AUTH,
                TARGET,
                ("X-Mq-Forward-Cookie", "true"),
                ("Cookie", &v(FIELD_MAX - "cookie".len())),
            ],
        ];
        for hs in fits {
            assert!(wire(hs).is_ok(), "{hs:?}");
        }
        let cookie = [
            AUTH,
            TARGET,
            ("X-Mq-Forward-Cookie", "true"),
            ("Cookie", &v(FIELD_MAX - "cookie".len() + 1)),
        ];
        assert_eq!(
            rej(&cookie),
            Reject::HeaderTooLong,
            "a forwarded cookie counts"
        );
        // Stripped headers are not forwarded, so their size does not matter.
        let big = v(FIELD_MAX + 1);
        assert!(wire(&[AUTH, TARGET, ("cookie", &big), ("host", &big)]).is_ok());
    }

    #[test]
    fn fetch_head_6k_header_forwarded() {
        let six_k = "v".repeat(6 * 1024);
        let got = fwd(&[AUTH, TARGET, ("X-Big", &six_k)]);
        assert_eq!(
            got.last().unwrap(),
            &(b"x-big".to_vec(), six_k.into_bytes())
        );
    }

    #[test]
    fn fetch_head_section_over_32k_header_too_long() {
        // Five fields of 8000 bytes: each under FIELD_MAX, together over SECTION_MAX.
        let big: Vec<(String, String)> = (0..5)
            .map(|i| (format!("x-h{i}"), "v".repeat(8000)))
            .collect();
        let mut hs = vec![AUTH, TARGET];
        hs.extend(big.iter().map(|(n, v)| (n.as_str(), v.as_str())));
        assert_eq!(rej(&hs), Reject::HeaderTooLong);
        // The same section minus one field fits.
        hs.pop();
        assert!(wire(&hs).is_ok());
    }

    #[test]
    fn overridden_oversized_accept_encoding_accepted() {
        // `X-Mq-Accept-Encoding` replaces the caller's header, which the front
        // drops (`render` does not), so its size does not count.
        let big = "x".repeat(FIELD_MAX);
        let hs = [
            AUTH,
            TARGET,
            ("X-Mq-Accept-Encoding", "gzip"),
            ("Accept-Encoding", &big),
        ];
        let req = fetch(&hs).unwrap();
        assert_eq!(req.accept_encoding.as_deref(), Some(&b"gzip"[..]));
        assert!(
            !req.headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(b"accept-encoding"))
        );
        let got = fwd(&hs);
        let ae: Vec<_> = got
            .iter()
            .filter(|(n, _)| n == b"accept-encoding")
            .collect();
        assert_eq!(ae, [&(b"accept-encoding".to_vec(), b"gzip".to_vec())]);
    }

    #[test]
    fn present_empty_auth_is_bad_auth_format() {
        assert_eq!(rej(&[("X-Mq-Auth", ""), TARGET]), Reject::BadAuthFormat);
        assert_eq!(
            rej(&[("X-Mq-Auth", "Bearer "), TARGET]),
            Reject::BadAuthFormat
        );
        assert_eq!(
            rej(&[("X-Mq-Auth", "bearer t"), TARGET]),
            Reject::BadAuthFormat
        );
        assert_eq!(rej(&[TARGET]), Reject::MissingAuth);
        assert!(wire(&[("X-Mq-Auth", "Bearer x"), TARGET]).is_ok());
    }

    #[test]
    fn reject_connect_is_bad_method() {
        for m in ["CONNECT", "connect", ""] {
            assert_eq!(rej(&[AUTH, TARGET, ("X-Mq-Method", m)]), Reject::BadMethod);
        }
        let r = fetch(&[AUTH, TARGET]).unwrap();
        assert_eq!(r.method.as_bytes(), b"GET", "absent = GET");
    }

    #[test]
    fn forwarded_order_golden() {
        let got = fwd(&[
            ("X-Mq-Auth", "Bearer tok"),
            ("X-Mq-Target", "https://example.com:8443/a?b=1"),
            ("X-Mq-Method", "post"),
            ("Host", "local"),
            ("Content-Length", "5"),
            ("X-Custom", "V"),
            ("X-Mq-Class", "bulk"),
            ("X-Mq-Origin-Protocol", "H2"),
            ("X-Mq-Cache", "60"),
            ("X-Mq-Accept-Encoding", "br"),
            ("Accept-Encoding", "gzip"),
            ("Cookie", "c=1"),
            ("Connection", "keep-alive"),
            ("User-Agent", "t"),
        ]);
        let want = hs(&[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "example.com:8443"),
            (":path", "/a?b=1"),
            ("x-mq-auth", "Bearer tok"),
            ("x-mq-class", "bulk"),
            ("x-mq-origin-protocol", "H2"),
            ("x-mq-cache", "60"),
            ("accept-encoding", "br"),
            ("content-length", "5"),
            ("x-custom", "V"),
            ("user-agent", "t"),
        ]);
        assert_eq!(got, want);

        // Empty control values and CL 0 add nothing; an opted-in cookie is kept.
        let got = fwd(&[
            AUTH,
            ("X-Mq-Target", "http://h"),
            ("X-Mq-Origin-Protocol", ""),
            ("X-Mq-Cache", ""),
            ("Content-Length", "0"),
            ("X-Mq-Forward-Cookie", "TRUE"),
            ("Cookie", "c=1"),
        ]);
        let want = hs(&[
            (":method", "GET"),
            (":scheme", "http"),
            (":authority", "h"),
            (":path", "/"),
            ("x-mq-auth", "Bearer t"),
            ("cookie", "c=1"),
        ]);
        assert_eq!(got, want);
    }

    #[test]
    fn empty_accept_encoding_control_keeps_callers_header() {
        let hs = [
            AUTH,
            TARGET,
            ("X-Mq-Accept-Encoding", ""),
            ("Accept-Encoding", "gzip"),
        ];
        let req = fetch(&hs).unwrap();
        assert_eq!(req.accept_encoding, None);
        assert_eq!(
            req.headers.last().unwrap(),
            &(b"Accept-Encoding".to_vec(), b"gzip".to_vec())
        );
        let got = fwd(&hs);
        let ae: Vec<_> = got
            .iter()
            .filter(|(n, _)| n.as_slice() == b"accept-encoding")
            .collect();
        assert_eq!(ae, [&(b"accept-encoding".to_vec(), b"gzip".to_vec())]);
        assert_eq!(
            got.last().unwrap().0,
            b"accept-encoding",
            "in request order"
        );
    }

    /// SP4 spec §6.2: over the SP3 `check()` table, the new front plus the
    /// core's `render` give the same reject, or the same wire header list.
    #[test]
    fn fetch_head_equivalent_to_sp3_check() {
        let v = |n: usize| "v".repeat(n);
        let (fmax, ck) = (v(FIELD_MAX), v(FIELD_MAX - "cookie".len()));
        let (ck1, other1) = (v(FIELD_MAX - 5), v(FIELD_MAX - "x-other".len() + 1));
        let auth_long = format!("Bearer {}", v(1024 - 7));
        let auth_fits = format!("Bearer {}", v(1023 - 7));
        let (v1024, v1023, v6k) = (v(1024), v(1023), v(6 * 1024));
        let big8k: Vec<(String, String)> = (0..5).map(|i| (format!("x-h{i}"), v(8000))).collect();
        let big8k: Vec<(&str, &str)> = [AUTH, TARGET]
            .into_iter()
            .chain(big8k.iter().map(|(n, v)| (n.as_str(), v.as_str())))
            .collect();
        let many: Vec<String> = (0..60).map(|i| format!("x-h{i}")).collect();
        let many: Vec<(&str, &str)> = [AUTH, TARGET, ("Content-Length", "1")]
            .into_iter()
            .chain(many.iter().map(|n| (n.as_str(), "v")))
            .collect();
        let table: Vec<Vec<(&str, &str)>> = vec![
            vec![AUTH, ("x-mq-auth", "Bearer u"), ("X-Mq-Target", "bad")],
            vec![("X-Mq-Target", "bad")],
            vec![("X-Mq-Auth", "Basic t"), TARGET],
            vec![("X-Mq-Auth", ""), TARGET],
            vec![("X-Mq-Auth", "Bearer "), TARGET],
            vec![("X-Mq-Auth", "bearer t"), TARGET],
            vec![AUTH],
            vec![AUTH, ("X-Mq-Target", "ftp://h/"), ("X-Mq-Method", "G(T")],
            vec![AUTH, TARGET, ("X-Mq-Method", "G(T")],
            vec![AUTH, TARGET, ("X-Mq-Method", "CONNECT")],
            vec![AUTH, TARGET, ("X-Mq-Method", "connect")],
            vec![AUTH, TARGET, ("X-Mq-Method", "")],
            vec![AUTH, TARGET, ("X-Mq-Origin-Protocol", "h4")],
            vec![AUTH, TARGET, ("X-Mq-Cache", "0"), ("X-Long", &fmax)],
            vec![
                AUTH,
                TARGET,
                ("X-Mq-Accept-Encoding", "gzip"),
                ("X-Long", &fmax),
            ],
            vec![("X-Mq-Auth", &auth_long), TARGET],
            vec![("X-Mq-Auth", &auth_fits), TARGET],
            vec![AUTH, TARGET, ("X-Mq-Class", &v1024)],
            vec![AUTH, TARGET, ("X-Mq-Class", &v1023)],
            vec![AUTH, TARGET, ("X-Mq-Accept-Encoding", &v1024)],
            vec![AUTH, TARGET, ("X-Other", &other1)],
            vec![
                AUTH,
                TARGET,
                ("X-Mq-Forward-Cookie", "true"),
                ("Cookie", &ck),
            ],
            vec![
                AUTH,
                TARGET,
                ("X-Mq-Forward-Cookie", "true"),
                ("Cookie", &ck1),
            ],
            vec![AUTH, TARGET, ("Cookie", &fmax), ("Host", &fmax)],
            vec![AUTH, TARGET, ("X-Big", &v6k)],
            big8k[..6].to_vec(),
            big8k.clone(),
            vec![
                AUTH,
                TARGET,
                ("X-Mq-Accept-Encoding", "gzip"),
                ("Accept-Encoding", &fmax),
            ],
            vec![
                AUTH,
                TARGET,
                ("X-Mq-Accept-Encoding", ""),
                ("Accept-Encoding", "gzip"),
            ],
            vec![
                ("X-Mq-Auth", "Bearer tok"),
                ("X-Mq-Target", "https://example.com:8443/a?b=1"),
                ("X-Mq-Method", "post"),
                ("Host", "local"),
                ("Content-Length", "5"),
                ("X-Custom", "V"),
                ("X-Mq-Class", "bulk"),
                ("X-Mq-Origin-Protocol", "H2"),
                ("X-Mq-Cache", "60"),
                ("X-Mq-Accept-Encoding", "br"),
                ("Accept-Encoding", "gzip"),
                ("Cookie", "c=1"),
                ("Connection", "keep-alive"),
                ("User-Agent", "t"),
            ],
            vec![
                AUTH,
                ("X-Mq-Target", "http://h"),
                ("X-Mq-Origin-Protocol", ""),
                ("X-Mq-Cache", ""),
                ("X-Mq-Class", ""),
                ("Content-Length", "0"),
                ("X-Mq-Forward-Cookie", "TRUE"),
                ("Cookie", "c=1"),
            ],
            many,
        ];
        for hs in &table {
            let h = h1head(hs);
            let old = sp3::Head::from_h1(&h);
            let want = sp3::check(&old).map(|c| sp3::forwarded_headers(&old, &c));
            assert_eq!(wire(hs), want, "{:?}", &hs[..hs.len().min(4)]);
        }
    }

    #[test]
    fn synth_error_golden() {
        assert_eq!(
            synth_error(502, "upstream-reset"),
            b"HTTP/1.1 502 \r\nX-Mq-Error: upstream-reset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }
}
