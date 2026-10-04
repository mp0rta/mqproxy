//! SP3 spec §5.2: the fetch request head — the gateway reject sequence (steps
//! 1–8) and the forwarded H3 header list; §5.6 the synthesised error reply.

use mq_http::h1;
use mq_http::headers::{
    HttpVer, Method, NAME_CAP, Reject, Target, VAL_CAP, forward_cookie_requested, has_dup_xmq,
    parse_cache_ttl, parse_http_ver, parse_method, parse_method_upper, parse_target, strip_client,
};

/// C `MQ_GW_MAX_SEND_HDRS` (spec §5.2: at most 64 + 8 headers).
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
            forward_cookie: forward_cookie_requested(h.headers.iter().map(|x| (x.name, x.value))),
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
    // C `mq_gw_client_prevalidate`: case-sensitive prefix, non-empty token.
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
    let long = |v: &Option<Vec<u8>>| v.as_ref().is_some_and(|v| v.len() >= VAL_CAP);
    let long_fwd = head.headers.iter().any(|(n, v)| {
        !strip_client(n, head.forward_cookie) && (n.len() >= NAME_CAP || v.len() >= VAL_CAP)
    });
    if long(&head.auth) || long(&head.class) || long(&head.accept_encoding) || long_fwd {
        return Err(Reject::HeaderTooLong);
    }
    Ok(Checked {
        method,
        target,
        http_ver,
        cache_ttl,
        auth: auth.clone(),
    })
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
    // An empty control header leaves the caller's `Accept-Encoding` alone (as C).
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
    use mq_http::h1::{Progress, parse_head};

    type Hs = Vec<(Vec<u8>, Vec<u8>)>;

    /// A fetch head with `hs` as its header lines (through the real parser).
    fn head(hs: &[(&str, &str)]) -> Head {
        let mut b = b"POST /_mqproxy/fetch HTTP/1.1\r\n".to_vec();
        for (n, v) in hs {
            b.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
        }
        b.extend_from_slice(b"\r\n");
        match parse_head(&b) {
            Progress::Done { head, .. } => Head::from_h1(&head),
            p => panic!("{p:?}"),
        }
    }

    fn rej(hs: &[(&str, &str)]) -> Reject {
        check(&head(hs)).expect_err("rejected")
    }

    fn fwd(hs: &[(&str, &str)]) -> Hs {
        let h = head(hs);
        let c = check(&h).expect("accepted");
        forwarded_headers(&h, &c)
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
        let long = "x".repeat(1024);
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
                    ("Accept-Encoding", &long),
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
        let name = "n".repeat(128);
        let too_long: [&[(&str, &str)]; 5] = [
            &[("X-Mq-Auth", &auth), TARGET],
            &[AUTH, TARGET, ("X-Mq-Class", &v(1024))],
            &[AUTH, TARGET, ("X-Mq-Accept-Encoding", &v(1024))],
            &[AUTH, TARGET, (&name, "v")],
            &[AUTH, TARGET, ("X-Other", &v(1024))],
        ];
        for hs in too_long {
            assert_eq!(rej(hs), Reject::HeaderTooLong);
        }
        let auth = format!("Bearer {}", v(1023 - 7));
        let name = "n".repeat(127);
        let fits: [&[(&str, &str)]; 5] = [
            &[("X-Mq-Auth", &auth), TARGET],
            &[AUTH, TARGET, ("X-Mq-Class", &v(1023))],
            &[AUTH, TARGET, (&name, &v(1023))],
            // stripped headers are not forwarded, so their size does not matter
            &[AUTH, TARGET, ("Cookie", &v(2000)), ("Host", &v(2000))],
            &[
                AUTH,
                TARGET,
                ("X-Mq-Forward-Cookie", "true"),
                ("Cookie", &v(1023)),
            ],
        ];
        for hs in fits {
            assert!(check(&head(hs)).is_ok(), "{hs:?}");
        }
        let cookie = [
            AUTH,
            TARGET,
            ("X-Mq-Forward-Cookie", "true"),
            ("Cookie", &v(1024)),
        ];
        assert_eq!(
            rej(&cookie),
            Reject::HeaderTooLong,
            "a forwarded cookie counts"
        );
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
        assert!(check(&head(&[("X-Mq-Auth", "Bearer x"), TARGET])).is_ok());
    }

    #[test]
    fn reject_connect_is_bad_method() {
        for m in ["CONNECT", "connect", ""] {
            assert_eq!(rej(&[AUTH, TARGET, ("X-Mq-Method", m)]), Reject::BadMethod);
        }
        let c = check(&head(&[AUTH, TARGET])).unwrap();
        assert_eq!(c.method.as_bytes(), b"GET", "absent = GET");
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
        let got = fwd(&[
            AUTH,
            TARGET,
            ("X-Mq-Accept-Encoding", ""),
            ("Accept-Encoding", "gzip"),
        ]);
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

    #[test]
    fn at_most_72_headers() {
        let mut h = head(&[AUTH, TARGET, ("Content-Length", "1")]);
        h.headers
            .extend((0..100).map(|i| (format!("x-h{i}").into_bytes(), b"v".to_vec())));
        let c = check(&h).unwrap();
        let got = forwarded_headers(&h, &c);
        assert_eq!(got.len(), 72);
        assert_eq!(got[5], (b"content-length".to_vec(), b"1".to_vec()));
        assert_eq!(got[71].0, b"x-h65");
    }

    #[test]
    fn synth_error_golden() {
        assert_eq!(
            synth_error(502, "upstream-reset"),
            b"HTTP/1.1 502 \r\nX-Mq-Error: upstream-reset\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
    }
}
