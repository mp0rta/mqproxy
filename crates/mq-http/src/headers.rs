//! Gateway header rules (spec §2.3), port of `src/gateway/mq_gw_headers.c`.

use crate::h1::{METHOD_MAX, PATH_MAX, is_tchar};

/// Longest `X-Mq-Cache` TTL in seconds (1 year).
pub const CACHE_TTL_MAX: u32 = 31_536_000;
/// Longest target authority, both intakes (C `char authority[256]`).
pub const AUTHORITY_MAX: usize = 255;

/// Parsed `X-Mq-Target` (bytes: any non-control, non-DEL, non-space byte round-trips).
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub scheme: &'static str,
    pub authority: Vec<u8>,
    pub path: Vec<u8>,
}

/// Control bytes, DEL and SP.
fn forbidden_uri_byte(c: u8) -> bool {
    c < 0x20 || c == 0x7f || c == b' '
}

fn has_prefix_ci(n: &[u8], pfx: &[u8]) -> bool {
    n.len() >= pfx.len() && n[..pfx.len()].eq_ignore_ascii_case(pfx)
}

fn is_xmq(n: &[u8]) -> bool {
    has_prefix_ci(n, b"x-mq-")
}

/// `X-Mq-Target` → scheme / authority / canonical path (spec §2.3); `None` = reject.
pub fn parse_target(s: &[u8]) -> Option<Target> {
    let (scheme, off) = if s.starts_with(b"https://") {
        ("https", 8)
    } else if s.starts_with(b"http://") {
        ("http", 7)
    } else {
        return None;
    };

    // Authority ends at the first '/' or '?' outside brackets; '[' is honoured only at offset 0.
    let mut i = off;
    let mut in_brackets = false;
    while i < s.len() {
        match s[i] {
            b'[' if i == off => in_brackets = true,
            b'[' => return None,
            b']' => in_brackets = false,
            b'/' | b'?' if !in_brackets => break,
            _ => {}
        }
        i += 1;
    }
    let auth = &s[off..i];
    if auth.is_empty() || auth.len() > AUTHORITY_MAX {
        return None;
    }
    let bracketed = auth[0] == b'[';
    for &c in auth {
        // '@' = userinfo (credential injection); ']' only closes a leading IPv6 literal.
        if c == b'@' || c == b'#' || forbidden_uri_byte(c) || (c == b']' && !bracketed) {
            return None;
        }
    }

    // host:port split: after ']' for an IPv6 literal, else the last ':'.
    let mut scan_from = 0;
    if bracketed {
        let rb = 1 + auth[1..].iter().position(|&c| c == b']')?;
        if rb == 1 {
            return None; // "[]"
        }
        scan_from = rb + 1;
        if scan_from < auth.len() && auth[scan_from] != b':' {
            return None;
        }
    }
    if let Some(pc) = auth[scan_from..]
        .iter()
        .rposition(|&c| c == b':')
        .map(|p| p + scan_from)
    {
        let port = &auth[pc + 1..];
        // No numeric range check (as C).
        if port.is_empty() || !port.iter().all(u8::is_ascii_digit) || pc == 0 {
            return None;
        }
        if !bracketed && auth[..pc].contains(&b':') {
            return None;
        }
    }

    let rest = &s[i..];
    if rest.iter().any(|&c| c == b'#' || forbidden_uri_byte(c)) {
        return None;
    }
    let path = match rest.first() {
        None => b"/".to_vec(),
        Some(b'?') => [&b"/"[..], rest].concat(),
        Some(_) => rest.to_vec(),
    };
    if path.len() > PATH_MAX {
        return None;
    }
    Some(Target {
        scheme,
        authority: auth.to_vec(),
        path,
    })
}

/// Uppercased method, 1..=15 tchars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    pub bytes: [u8; 16],
    pub len: usize,
}

impl Method {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub fn parse_method(s: &[u8]) -> Option<Method> {
    if s.is_empty() || s.len() > METHOD_MAX || !s.iter().all(|&c| is_tchar(c)) {
        return None;
    }
    let mut bytes = [0u8; 16];
    bytes[..s.len()].copy_from_slice(s);
    bytes.make_ascii_uppercase();
    Some(Method {
        bytes,
        len: s.len(),
    })
}

/// The method is `HEAD` (the head render and the body check).
pub fn is_head(method: &Method) -> bool {
    method.as_bytes() == b"HEAD"
}

/// The response may carry a body: the method is not `HEAD` and the
/// status is not 1xx/204/304 (SP3 spec §5.4/§6.4 body check).
pub fn body_check_applies(method: &Method, status: u16) -> bool {
    !is_head(method) && !(100..200).contains(&status) && status != 204 && status != 304
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVer {
    Default,
    H1,
    H2,
    H3,
}

pub fn parse_http_ver(v: &[u8]) -> HttpVer {
    if v.eq_ignore_ascii_case(b"h3") {
        HttpVer::H3
    } else if v.eq_ignore_ascii_case(b"h2") {
        HttpVer::H2
    } else if v.eq_ignore_ascii_case(b"h1") {
        HttpVer::H1
    } else {
        HttpVer::Default
    }
}

/// Strict decimal seconds in `1..=CACHE_TTL_MAX`; 0 = absent / invalid.
pub fn parse_cache_ttl(v: &[u8]) -> u32 {
    let mut n: u32 = 0;
    for &c in v {
        if !c.is_ascii_digit() {
            return 0;
        }
        n = n * 10 + u32::from(c - b'0');
        if n > CACHE_TTL_MAX {
            return 0; // also keeps n * 10 far from u32 overflow
        }
    }
    n
}

/// RFC 7230 §6.1 hop-by-hop names plus `Proxy-Connection` (spec §12.24).
pub fn is_hop_by_hop(name: &[u8]) -> bool {
    const HOP: [&[u8]; 9] = [
        b"connection",
        b"keep-alive",
        b"proxy-authenticate",
        b"proxy-authorization",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
    ];
    HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

/// Client → tunnel: hop-by-hop, `X-Mq-*`, `Host`, `Content-Length`, `Cookie` unless opted in.
pub fn strip_client(name: &[u8], forward_cookie: bool) -> bool {
    is_hop_by_hop(name)
        || is_xmq(name)
        || name.eq_ignore_ascii_case(b"host")
        || name.eq_ignore_ascii_case(b"content-length")
        || (!forward_cookie && name.eq_ignore_ascii_case(b"cookie"))
}

/// Server → origin: hop-by-hop and `X-Mq-*`.
pub fn strip_server(name: &[u8]) -> bool {
    is_hop_by_hop(name) || is_xmq(name)
}

/// Two `X-Mq-*` names equal case-insensitively.
pub fn has_dup_xmq<'a>(names: impl Iterator<Item = &'a [u8]>) -> bool {
    let seen: Vec<&[u8]> = names.filter(|n| is_xmq(n)).collect();
    // ponytail: O(n^2); n <= 64 headers (HEAD_MAX / MAX_HEADERS).
    seen.iter()
        .enumerate()
        .any(|(i, a)| seen[i + 1..].iter().any(|b| a.eq_ignore_ascii_case(b)))
}

/// First `X-Mq-Forward-Cookie` equals `true` (values arrive OWS-trimmed).
pub fn forward_cookie_requested<'a>(
    headers: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
) -> bool {
    headers
        .into_iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(b"x-mq-forward-cookie"))
        .is_some_and(|(_, v)| v.eq_ignore_ascii_case(b"true"))
}

/// No byte < 0x20 (incl. HTAB) and no DEL.
pub fn name_ok(s: &[u8]) -> bool {
    s.iter().all(|&c| c >= 0x20 && c != 0x7f)
}

/// Like [`name_ok`] but HTAB is allowed; CR, LF and NUL are rejected.
pub fn value_ok(s: &[u8]) -> bool {
    s.iter().all(|&c| c == b'\t' || (c >= 0x20 && c != 0x7f))
}

/// No SP, control byte or DEL.
pub fn uri_field_ok(s: &[u8]) -> bool {
    !s.iter().any(|&c| forbidden_uri_byte(c))
}

/// libcurl result code → HTTP status: `CURLE_OPERATION_TIMEDOUT` (28) → 504, else 502.
pub fn status_from_curl(n: u32) -> u16 {
    if n == 28 { 504 } else { 502 }
}

/// Client-side rejects (spec §9.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    DupControl,
    MissingAuth,
    BadAuthFormat,
    BadTarget,
    BadMethod,
    BadOriginProto,
    BadCacheTtl,
    HeaderTooLong,
    TunnelUnavailable,
    InternalError,
    UpstreamReset,
    UpstreamProtocol,
}

/// Byte-exact `X-Mq-Error` string.
pub fn reject_xmq(r: Reject) -> &'static str {
    match r {
        Reject::DupControl => "duplicate-control-header",
        Reject::MissingAuth => "missing-auth",
        Reject::BadAuthFormat => "bad-auth-format",
        Reject::BadTarget => "bad-target",
        Reject::BadMethod => "bad-method",
        Reject::BadOriginProto => "bad-origin-protocol",
        Reject::BadCacheTtl => "bad-cache-ttl",
        Reject::HeaderTooLong => "header-too-long",
        Reject::TunnelUnavailable => "tunnel-unavailable",
        Reject::InternalError => "internal-error",
        Reject::UpstreamReset => "upstream-reset",
        Reject::UpstreamProtocol => "upstream-protocol",
    }
}

pub fn reject_status(r: Reject) -> u16 {
    match r {
        Reject::DupControl
        | Reject::MissingAuth
        | Reject::BadAuthFormat
        | Reject::BadTarget
        | Reject::BadMethod
        | Reject::BadOriginProto
        | Reject::BadCacheTtl
        | Reject::HeaderTooLong => 400,
        _ => 502,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn t(s: &str) -> Option<Target> {
        parse_target(s.as_bytes())
    }
    fn ok(s: &str) -> Target {
        t(s).unwrap_or_else(|| panic!("expected Some for {s:?}"))
    }

    // ---- parse_target (test_gw_headers.c) ----
    #[test]
    fn target_https_full() {
        let x = ok("https://example.com/foo/bar?x=1&y=2");
        assert_eq!(x.scheme, "https");
        assert_eq!(x.authority, b"example.com");
        assert_eq!(x.path, b"/foo/bar?x=1&y=2");
    }
    #[test]
    fn target_http_ok() {
        let x = ok("http://example.com/x");
        assert_eq!(
            (x.scheme, &x.authority[..], &x.path[..]),
            ("http", &b"example.com"[..], &b"/x"[..])
        );
    }
    #[test]
    fn target_https_minimal() {
        let x = ok("https://h");
        assert_eq!((&x.authority[..], &x.path[..]), (&b"h"[..], &b"/"[..]));
        assert_eq!(ok("https://example.com").path, b"/");
    }
    #[test]
    fn target_query_only_prepends_slash() {
        assert_eq!(ok("https://h?x=1").path, b"/?x=1");
        let x = ok("https://example.com?q=1");
        assert_eq!(
            (&x.authority[..], &x.path[..]),
            (&b"example.com"[..], &b"/?q=1"[..])
        );
    }
    #[test]
    fn target_port_kept() {
        let x = ok("https://h:8443/x");
        assert_eq!(
            (&x.authority[..], &x.path[..]),
            (&b"h:8443"[..], &b"/x"[..])
        );
    }
    #[test]
    fn target_ipv6_bracket_port() {
        assert_eq!(ok("https://[::1]:443/").authority, b"[::1]:443");
        assert_eq!(ok("https://[::1]:443/").path, b"/");
        let x = ok("https://[2001:db8::1]/p");
        assert_eq!(
            (&x.authority[..], &x.path[..]),
            (&b"[2001:db8::1]"[..], &b"/p"[..])
        );
    }
    #[test]
    fn target_stray_bracket_bad() {
        assert!(t("https://foo[bar/x").is_none());
        assert!(t("https://]nobracket/x").is_none());
        assert!(t("https://]/x").is_none());
        assert!(t("https://[unclosed/").is_none());
    }
    #[test]
    fn target_empty_brackets_bad() {
        assert!(t("https://[]:80/").is_none());
        assert!(t("https://[]/").is_none());
    }
    #[test]
    fn target_after_bracket_only_port_bad() {
        assert!(t("https://[::1]x80/").is_none());
        assert!(t("https://[::1]:/").is_none());
        assert!(t("https://[::1]:80x/").is_none());
    }
    #[test]
    fn target_userinfo_bad() {
        assert!(t("https://u@h/x").is_none());
        assert!(t("https://u:p@h/x").is_none());
    }
    #[test]
    fn target_fragment_bad() {
        assert!(t("https://h/x#frag").is_none());
        assert!(t("https://h#frag").is_none());
        assert!(t("https://h?q#frag").is_none());
    }
    #[test]
    fn target_port_digits_only() {
        assert_eq!(ok("https://h:80").authority, b"h:80");
        assert!(t("https://h:8x").is_none());
        assert!(t("https://h:12ab/x").is_none());
        assert!(t("https://h:").is_none());
        assert!(t("https://h:/x").is_none());
        assert!(t("https://:80").is_none());
        assert!(t("https://h:80:90").is_none());
        // no numeric range check, as C
        assert_eq!(ok("https://h:99999").authority, b"h:99999");
    }
    #[test]
    fn target_double_colon_port_bad() {
        assert!(t("https://h:80:90/x").is_none());
        assert!(t("https://h::80/x").is_none());
    }
    #[test]
    fn target_forbidden_bytes_bad() {
        for bad in [b' ', 0x7f, 0x01, 0x1f] {
            let a = [&b"https://h"[..], &[bad], b"ost/x"].concat();
            let p = [&b"https://h/a"[..], &[bad], b"b"].concat();
            assert!(parse_target(&a).is_none(), "authority {bad:#x}");
            assert!(parse_target(&p).is_none(), "path {bad:#x}");
        }
        assert!(t("https://h/a b").is_none());
        assert!(t("https://h ost/x").is_none());
    }
    #[test]
    fn target_non_utf8_roundtrips() {
        let x = parse_target(b"https://h/\xff").expect("non-utf8 path");
        assert_eq!(x.path, b"/\xff");
    }
    #[test]
    fn target_authority_255_ok_256_bad() {
        let mk = |n: usize| [&b"https://"[..], &vec![b'a'; n], b"/x"].concat();
        assert_eq!(parse_target(&mk(255)).expect("255").authority.len(), 255);
        assert!(parse_target(&mk(256)).is_none());
    }
    #[test]
    fn target_path_1023_ok() {
        // canonical "/?" + 1021 = 1023 bytes
        let s = [&b"https://h?"[..], &vec![b'a'; 1021]].concat();
        assert_eq!(parse_target(&s).expect("1023").path.len(), 1023);
        // slash form: "/" + 1022
        let s = [&b"https://h/"[..], &vec![b'a'; 1022]].concat();
        assert_eq!(parse_target(&s).expect("1023").path.len(), 1023);
    }
    #[test]
    fn target_path_1024_after_prefix_bad() {
        // canonical "/?" + 1022 = 1024 bytes (the rest alone is 1023)
        let s = [&b"https://h?"[..], &vec![b'a'; 1022]].concat();
        assert!(parse_target(&s).is_none());
        // C test_target_path_too_long: "/" + 1024
        let s = [&b"https://h/"[..], &vec![b'a'; 1024]].concat();
        assert!(parse_target(&s).is_none());
    }
    #[test]
    fn target_ftp_bad() {
        assert!(t("ftp://example.com/x").is_none());
    }
    #[test]
    fn target_upper_scheme() {
        assert!(t("HTTPS://example.com/x").is_none());
    }
    #[test]
    fn target_empty_bad() {
        assert!(t("").is_none());
        assert!(t("https://").is_none());
        assert!(t("https:///path").is_none());
    }

    // ---- parse_method ----
    #[test]
    fn method_uppercased() {
        let m = parse_method(b"PuT").expect("PuT");
        assert_eq!(m.as_bytes(), b"PUT");
        assert_eq!(parse_method(b"get").expect("get").as_bytes(), b"GET");
        assert_eq!(
            parse_method(b"M-E.T!").expect("tchars").as_bytes(),
            b"M-E.T!"
        );
    }
    #[test]
    fn method_15_ok_16_bad() {
        assert_eq!(parse_method(b"ABCDEFGHIJKLMNO").expect("15").len, 15);
        assert!(parse_method(b"ABCDEFGHIJKLMNOP").is_none());
        assert!(parse_method(b"").is_none());
    }
    #[test]
    fn method_non_tchar_bad() {
        assert!(parse_method(b"GE T").is_none());
        assert!(parse_method(b"G\"T").is_none());
    }

    // ---- http_ver / cache_ttl ----
    #[test]
    fn http_ver_case_insensitive() {
        assert_eq!(parse_http_ver(b"h3"), HttpVer::H3);
        assert_eq!(parse_http_ver(b"H3"), HttpVer::H3);
        assert_eq!(parse_http_ver(b"H2"), HttpVer::H2);
        assert_eq!(parse_http_ver(b"h1"), HttpVer::H1);
        for d in [&b"h4"[..], b"h0", b"h3x", b"http3", b""] {
            assert_eq!(parse_http_ver(d), HttpVer::Default, "{d:?}");
        }
    }
    #[test]
    fn cache_ttl() {
        assert_eq!(parse_cache_ttl(b"1"), 1);
        assert_eq!(parse_cache_ttl(b"60"), 60);
        assert_eq!(parse_cache_ttl(b"31536000"), CACHE_TTL_MAX);
        for z in [
            &b"0"[..],
            b"",
            b"x",
            b"-5",
            b"+1",
            b" 1",
            b"60 ",
            b"31536001",
            b"99999999999999999999",
        ] {
            assert_eq!(parse_cache_ttl(z), 0, "{z:?}");
        }
    }

    // ---- strip predicates ----
    #[test]
    fn hop_by_hop_set_incl_proxy_connection() {
        for h in [
            "Connection",
            "keep-alive",
            "Proxy-Authenticate",
            "proxy-authorization",
            "TE",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade",
            "CoNnEcTiOn",
            "TRANSFER-ENCODING",
            "Proxy-Connection",
        ] {
            assert!(is_hop_by_hop(h.as_bytes()), "{h}");
            assert!(strip_client(h.as_bytes(), false), "{h}");
            assert!(strip_client(h.as_bytes(), true), "{h}");
            assert!(strip_server(h.as_bytes()), "{h}");
        }
        for h in [
            "Authorization",
            "Accept",
            "Content-Length",
            "Host",
            "Cookie",
            "Content-Type",
        ] {
            assert!(!is_hop_by_hop(h.as_bytes()), "{h}");
        }
    }
    #[test]
    fn strip_client_rules() {
        for h in [
            "X-Mq-Target",
            "X-Mq-Anything",
            "x-mq-auth",
            "Host",
            "host",
            "Content-Length",
            "Cookie",
            "COOKIE",
        ] {
            assert!(strip_client(h.as_bytes(), false), "{h}");
        }
        // opt-in flips only Cookie
        assert!(!strip_client(b"Cookie", true));
        assert!(!strip_client(b"cookie", true));
        assert!(strip_client(b"Host", true));
        assert!(strip_client(b"X-Mq-Forward-Cookie", true));
        // Authorization / Accept are forwarded
        for h in ["Authorization", "authorization", "Accept"] {
            assert!(!strip_client(h.as_bytes(), false), "{h}");
        }
        // prefix boundary
        for h in ["X-Mq", "X-Mqq", ""] {
            assert!(!strip_client(h.as_bytes(), false), "{h:?}");
        }
    }
    #[test]
    fn strip_server_rules() {
        assert!(strip_server(b"X-Mq-Target"));
        assert!(strip_server(b"x-mq-auth"));
        for h in [
            "Host",
            "Cookie",
            "Content-Length",
            "Authorization",
            "Accept",
            "X-Mq",
            "X-Mqq",
        ] {
            assert!(!strip_server(h.as_bytes()), "{h}");
        }
    }

    // ---- dup X-Mq-* / forward cookie ----
    fn dup(names: &[&str]) -> bool {
        has_dup_xmq(names.iter().map(|n| n.as_bytes()))
    }
    #[test]
    fn dup_xmq_case_insensitive() {
        assert!(dup(&["X-Mq-Auth", "X-Mq-Auth"]));
        assert!(dup(&["x-mq-auth", "X-MQ-AUTH"]));
        assert!(dup(&["X-Mq-Auth", "Accept", "x-mq-auth"]));
        assert!(!dup(&["X-Mq-Auth", "X-Mq-Target"]));
        assert!(!dup(&["Accept", "Accept"]));
        assert!(!dup(&[]));
    }
    fn fc(h: &[(&str, &str)]) -> bool {
        forward_cookie_requested(h.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())))
    }
    #[test]
    fn forward_cookie_true_case_insensitive() {
        assert!(fc(&[("X-Mq-Forward-Cookie", "true")]));
        assert!(fc(&[("x-mq-forward-cookie", "TRUE")]));
        assert!(fc(&[("Accept", "*/*"), ("X-Mq-Forward-Cookie", "True")]));
        for v in ["false", "1", "", " true"] {
            assert!(!fc(&[("X-Mq-Forward-Cookie", v)]), "{v:?}");
        }
        assert!(!fc(&[("Accept", "*/*")]));
        assert!(!fc(&[]));
        // first match decides (a duplicate is rejected upstream by has_dup_xmq)
        assert!(!fc(&[
            ("X-Mq-Forward-Cookie", "no"),
            ("X-Mq-Forward-Cookie", "true")
        ]));
    }

    // ---- byte validators ----
    #[test]
    fn name_ok_rejects_controls_and_del() {
        assert!(name_ok(b"Accept-Language"));
        assert!(name_ok(b""));
        for bad in [0x00, 0x09, 0x0a, 0x0d, 0x1f, 0x7f] {
            assert!(!name_ok(&[b'a', bad, b'b']), "{bad:#x}");
        }
    }
    #[test]
    fn value_ok_allows_htab_only() {
        assert!(value_ok(b"a\tb c"));
        assert!(value_ok(b"\xff"));
        for bad in [0x00, 0x0a, 0x0d, 0x1f, 0x7f] {
            assert!(!value_ok(&[b'a', bad, b'b']), "{bad:#x}");
        }
    }
    #[test]
    fn uri_field_ok_rejects_space() {
        assert!(uri_field_ok(b"/a/b?c=d"));
        for bad in [b' ', b'\r', b'\n', 0x00, 0x09, 0x1f, 0x7f] {
            assert!(!uri_field_ok(&[b'a', bad]), "{bad:#x}");
        }
    }

    // ---- curl map / reject table ----
    #[test]
    fn status_from_curl_28_is_504() {
        assert_eq!(status_from_curl(28), 504);
        for n in [0, 6, 7, 60, 999] {
            assert_eq!(status_from_curl(n), 502, "{n}");
        }
    }
    #[test]
    fn reject_table_golden() {
        use Reject::*;
        let table = [
            (DupControl, "duplicate-control-header", 400),
            (MissingAuth, "missing-auth", 400),
            (BadAuthFormat, "bad-auth-format", 400),
            (BadTarget, "bad-target", 400),
            (BadMethod, "bad-method", 400),
            (BadOriginProto, "bad-origin-protocol", 400),
            (BadCacheTtl, "bad-cache-ttl", 400),
            (HeaderTooLong, "header-too-long", 400),
            (TunnelUnavailable, "tunnel-unavailable", 502),
            (InternalError, "internal-error", 502),
            (UpstreamReset, "upstream-reset", 502),
            (UpstreamProtocol, "upstream-protocol", 502),
        ];
        for (r, s, st) in table {
            assert_eq!((reject_xmq(r), reject_status(r)), (s, st), "{r:?}");
        }
    }
}
