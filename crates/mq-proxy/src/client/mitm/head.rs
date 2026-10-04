//! SP4 spec §7.5 / §7.7: the browser's h2 request head → the exchange core's
//! `ReqHead`, and the core's `RespHead` → an h2 response head.

use super::policy::Sni;
use crate::client::exchange::resp::{Malformed, RespHead};
use crate::client::exchange::{BodyLen, ReqHead};
use http::header::{CONTENT_LENGTH, COOKIE, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};
use mq_http::h1::parse_content_length;
use mq_http::headers::{
    Reject, is_hop_by_hop, parse_method, parse_target, reject_status, reject_xmq, strip_client,
};

/// Why a browser head cannot be forwarded.
#[derive(Debug, PartialEq, Eq)]
pub enum MapErr {
    /// Answer with this reject (`reject_response`).
    Reject(Reject),
    /// 421: the `:authority` is not this connection's SNI (`misdirected_response`).
    Misdirected,
    /// `RST_STREAM(PROTOCOL_ERROR)`: the request is malformed (RFC 9110 §8.6).
    Malformed,
}

/// `"Bearer " + token`; a token that already has the prefix is used as is (C dedup).
pub fn auth_value(token: &str) -> Vec<u8> {
    if token.starts_with("Bearer ") {
        token.as_bytes().to_vec()
    } else {
        format!("Bearer {token}").into_bytes()
    }
}

/// SP4 spec §7.5 steps 1–6. Sizes are `render`'s business (§4.4).
pub fn map_request(
    parts: &http::request::Parts,
    end_stream: bool,
    sni: &Sni,
    auth: &[u8],
) -> Result<ReqHead, MapErr> {
    let bad = MapErr::Reject(Reject::BadTarget);
    // 1. Method.
    let method = match parts.method.as_str() {
        "CONNECT" => return Err(MapErr::Reject(Reject::BadMethod)),
        m => parse_method(m.as_bytes()).ok_or(MapErr::Reject(Reject::BadMethod))?,
    };
    // 2. Target: origin-form path; `:authority`, else `host`. `host` is ignored
    // when `:authority` is present (Review Focus 5).
    let path = parts.uri.path_and_query().map_or("", |p| p.as_str());
    if !path.starts_with('/') {
        return Err(bad);
    }
    let authority = match parts.uri.authority() {
        Some(a) => a.as_str().as_bytes(),
        None => parts.headers.get(HOST).ok_or(bad)?.as_bytes(),
    };
    // h2 keeps `:scheme` only together with `:authority` (h2 `server.rs`), so a
    // `host`-only request has no scheme to check; the conn is TLS anyway.
    if parts.uri.scheme().is_some_and(|s| s != "https") {
        return Err(MapErr::Reject(Reject::BadTarget));
    }
    let target = parse_target(&[b"https://", authority, path.as_bytes()].concat())
        .ok_or(MapErr::Reject(Reject::BadTarget))?;
    // 3. Misdirected: the host part (port removed) must canonicalise to the SNI.
    // `parse_target` has validated the authority; a bracketed IPv6 never matches.
    let host = match target.authority.iter().rposition(|&c| c == b':') {
        Some(i) if !target.authority.ends_with(b"]") => &target.authority[..i],
        _ => &target.authority[..],
    };
    if Sni::canonical(host).as_ref() != Some(sni) {
        return Err(MapErr::Misdirected);
    }
    Ok(ReqHead {
        method,
        target,
        auth: auth.to_vec(),
        class: None,
        origin_proto: None,
        cache: None,
        accept_encoding: None,
        // 4.
        headers: forwarded_headers(&parts.headers),
        // 6.
        body: body_len(&parts.headers, end_stream)?,
    })
}

/// Spec §7.5 step 4: drop the hop-by-hop set (`te` included), `host`,
/// `content-length` and `x-mq-*`; join `cookie` with `"; "` at its first place.
fn forwarded_headers(map: &HeaderMap) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::with_capacity(map.len());
    for (name, value) in map {
        if *name == COOKIE {
            if out.iter().any(|(n, _): &(Vec<u8>, _)| n == b"cookie") {
                continue;
            }
            let all = map.get_all(COOKIE).iter().map(HeaderValue::as_bytes);
            out.push((b"cookie".to_vec(), all.collect::<Vec<_>>().join(&b"; "[..])));
        } else if !strip_client(name.as_str().as_bytes(), true) {
            out.push((name.as_str().into(), value.as_bytes().to_vec()));
        }
    }
    out
}

/// Spec §7.5 step 6: every `content-length` value is checked before END_STREAM.
fn body_len(map: &HeaderMap, end_stream: bool) -> Result<BodyLen, MapErr> {
    let mut cl = None;
    for v in map.get_all(CONTENT_LENGTH) {
        let n = parse_content_length(v.as_bytes()).ok_or(MapErr::Malformed)?;
        if *cl.get_or_insert(n) != n {
            return Err(MapErr::Malformed);
        }
    }
    match (cl, end_stream) {
        (Some(n), true) if n > 0 => Err(MapErr::Malformed),
        (_, true) => Ok(BodyLen::Empty),
        (Some(n), false) => Ok(BodyLen::Known(n)),
        (None, false) => Ok(BodyLen::Unknown),
    }
}

/// Spec §7.7: `:status` and the headers of `h`, minus the connection-specific
/// set and `alt-svc` (D9). `x-mq-*` and `content-length` pass through.
pub fn map_response(h: &RespHead) -> Result<Response<()>, Malformed> {
    let mut r = Response::new(());
    *r.status_mut() = StatusCode::from_u16(h.status).map_err(|_| Malformed)?;
    for (n, v) in &h.headers {
        if is_hop_by_hop(n) || n.eq_ignore_ascii_case(b"alt-svc") {
            continue;
        }
        r.headers_mut().append(
            HeaderName::from_bytes(n).map_err(|_| Malformed)?,
            HeaderValue::from_bytes(v).map_err(|_| Malformed)?,
        );
    }
    Ok(r)
}

/// Spec §7.5 Rejects: `:status`, `x-mq-error`, `content-length: 0`.
pub fn reject_response(r: Reject) -> Response<()> {
    let mut resp = bare(reject_status(r));
    resp.headers_mut()
        .insert("x-mq-error", HeaderValue::from_static(reject_xmq(r)));
    resp
}

/// 421, with no `x-mq-error` (spec §7.5 step 3).
pub fn misdirected_response() -> Response<()> {
    bare(421)
}

fn bare(status: u16) -> Response<()> {
    let mut r = Response::new(());
    *r.status_mut() = StatusCode::from_u16(status).expect("a valid status");
    r.headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sni() -> Sni {
        Sni::canonical(b"example.com").unwrap()
    }

    fn req(method: &str, uri: &str, hs: &[(&str, &str)]) -> http::request::Parts {
        let mut b = http::Request::builder().method(method).uri(uri);
        for (n, v) in hs {
            b = b.header(*n, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn get(hs: &[(&str, &str)]) -> Result<ReqHead, MapErr> {
        map_request(
            &req("GET", "https://example.com/p?q=1", hs),
            true,
            &sni(),
            b"Bearer t",
        )
    }

    fn hdr<'a>(h: &'a ReqHead, n: &str) -> Vec<&'a [u8]> {
        (h.headers.iter())
            .filter(|(k, _)| k == n.as_bytes())
            .map(|(_, v)| v.as_slice())
            .collect()
    }

    #[test]
    fn xmq_host_cl_dropped() {
        let h = get(&[
            ("x-mq-auth", "evil"),
            ("X-Mq-Target", "http://evil/"),
            ("host", "example.com"),
            ("content-length", "0"),
            ("connection", "close"),
            ("keep-alive", "1"),
            ("x-keep", "1"),
        ])
        .unwrap();
        assert_eq!(h.headers, vec![(b"x-keep".to_vec(), b"1".to_vec())]);
    }

    #[test]
    fn cookies_joined_semicolon_space() {
        let h = get(&[
            ("cookie", "a=1"),
            ("x-a", "1"),
            ("cookie", "b=2"),
            ("cookie", "c=3"),
        ])
        .unwrap();
        assert_eq!(hdr(&h, "cookie"), [&b"a=1; b=2; c=3"[..]]);
        assert_eq!(hdr(&h, "x-a").len(), 1);
    }

    #[test]
    fn te_trailers_dropped() {
        let h = get(&[("te", "trailers"), ("x-a", "1")]).unwrap();
        assert!(hdr(&h, "te").is_empty());
    }

    #[test]
    fn empty_value_kept() {
        let h = get(&[("x-empty", "")]).unwrap();
        assert_eq!(hdr(&h, "x-empty"), [&b""[..]]);
    }

    #[test]
    fn authorization_kept() {
        let h = get(&[("authorization", "Basic abc")]).unwrap();
        assert_eq!(hdr(&h, "authorization"), [&b"Basic abc"[..]]);
    }

    #[test]
    fn auth_injected_and_deduped() {
        assert_eq!(auth_value("tok"), b"Bearer tok");
        assert_eq!(auth_value("Bearer tok"), b"Bearer tok");
        assert_eq!(get(&[]).unwrap().auth, b"Bearer t");
    }

    #[test]
    fn forward_cookie_true_controls_none() {
        let h = get(&[("cookie", "a=1"), ("accept-encoding", "gzip")]).unwrap();
        assert_eq!(hdr(&h, "cookie"), [&b"a=1"[..]]);
        assert_eq!(hdr(&h, "accept-encoding"), [&b"gzip"[..]]);
        assert!(h.class.is_none() && h.origin_proto.is_none());
        assert!(h.cache.is_none() && h.accept_encoding.is_none());
    }

    fn post(end_stream: bool, cls: &[&str]) -> Result<ReqHead, MapErr> {
        let hs: Vec<_> = cls.iter().map(|v| ("content-length", *v)).collect();
        map_request(
            &req("POST", "https://example.com/", &hs),
            end_stream,
            &sni(),
            b"Bearer t",
        )
    }

    #[test]
    fn body_len_end_stream_empty() {
        assert_eq!(post(true, &[]).unwrap().body, BodyLen::Empty);
        assert_eq!(post(true, &["0"]).unwrap().body, BodyLen::Empty);
    }

    #[test]
    fn body_len_known_from_all_equal_cl() {
        assert_eq!(post(false, &["5"]).unwrap().body, BodyLen::Known(5));
        assert_eq!(post(false, &["5", "05"]).unwrap().body, BodyLen::Known(5));
    }

    #[test]
    fn conflicting_cl_malformed() {
        assert_eq!(post(false, &["5", "6"]).unwrap_err(), MapErr::Malformed);
        assert_eq!(post(true, &["0", "x"]).unwrap_err(), MapErr::Malformed);
        assert_eq!(post(false, &["5, 5"]).unwrap_err(), MapErr::Malformed);
    }

    #[test]
    fn end_stream_with_cl_positive_malformed() {
        assert_eq!(post(true, &["5"]).unwrap_err(), MapErr::Malformed);
    }

    #[test]
    fn no_cl_unknown() {
        assert_eq!(post(false, &[]).unwrap().body, BodyLen::Unknown);
    }

    fn map(m: &str, uri: &str, hs: &[(&str, &str)]) -> Result<ReqHead, MapErr> {
        map_request(&req(m, uri, hs), true, &sni(), b"Bearer t")
    }

    #[test]
    fn connect_bad_method() {
        let e = map("CONNECT", "example.com:443", &[]).unwrap_err();
        assert_eq!(e, MapErr::Reject(Reject::BadMethod));
    }

    #[test]
    fn asterisk_form_bad_target() {
        let e = map("OPTIONS", "*", &[("host", "example.com")]).unwrap_err();
        assert_eq!(e, MapErr::Reject(Reject::BadTarget));
    }

    #[test]
    fn http_scheme_bad_target() {
        let e = map("GET", "http://example.com/", &[]).unwrap_err();
        assert_eq!(e, MapErr::Reject(Reject::BadTarget));
    }

    #[test]
    fn no_authority_bad_target() {
        let e = map("GET", "/x", &[]).unwrap_err();
        assert_eq!(e, MapErr::Reject(Reject::BadTarget));
    }

    #[test]
    fn method_case_preserved() {
        let h = map("Get", "https://example.com/", &[]).unwrap();
        assert_eq!(h.method.as_bytes(), b"Get");
        assert_eq!(h.target.path, b"/");
        assert_eq!(h.target.authority, b"example.com");
    }

    #[test]
    fn trailing_dot_authority_no_421() {
        assert!(map("GET", "https://Example.COM.:443/", &[]).is_ok());
        assert!(map("GET", "https://example.com./", &[]).is_ok());
    }

    #[test]
    fn authority_mismatch_421() {
        let e = map("GET", "https://other.com/", &[]).unwrap_err();
        assert_eq!(e, MapErr::Misdirected);
        let e = map("GET", "https://[::1]/", &[]).unwrap_err();
        assert_eq!(e, MapErr::Misdirected);
    }

    /// Review Focus 5.
    #[test]
    fn host_header_ignored_when_authority_present() {
        let h = map("GET", "https://example.com/", &[("host", "evil.com")]).unwrap();
        assert!(hdr(&h, "host").is_empty());
        assert_eq!(h.target.authority, b"example.com");
        // `host` stands in only when `:authority` is absent (h2 then drops the scheme).
        let h = map("GET", "/x", &[("host", "Example.com:443")]).unwrap();
        assert_eq!(h.target.authority, b"Example.com:443");
        assert_eq!(
            map("GET", "/x", &[("host", "evil.com")]).unwrap_err(),
            MapErr::Misdirected
        );
    }

    fn resp(status: u16, hs: &[(&str, &str)]) -> RespHead {
        RespHead {
            status,
            headers: hs
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
            cl: None,
            has_cl: false,
        }
    }

    #[test]
    fn map_response_drops_alt_svc_and_connection_set_keeps_xmq() {
        let r = map_response(&resp(
            200,
            &[
                ("alt-svc", "h3=\":443\""),
                ("Connection", "close"),
                ("keep-alive", "1"),
                ("proxy-connection", "x"),
                ("transfer-encoding", "chunked"),
                ("upgrade", "h2c"),
                ("te", "trailers"),
                ("x-mq-error", "upstream-reset"),
                ("set-cookie", "a=1"),
                ("set-cookie", "b=2"),
            ],
        ))
        .unwrap();
        assert_eq!(r.status(), 200);
        let names: Vec<_> = r.headers().keys().map(|k| k.as_str()).collect();
        assert_eq!(names, ["x-mq-error", "set-cookie"]);
        assert_eq!(r.headers().get_all("set-cookie").iter().count(), 2);
        assert!(map_response(&resp(200, &[("bad name", "x")])).is_err());
    }

    #[test]
    fn map_response_head_keeps_content_length() {
        let r = map_response(&resp(200, &[("content-length", "42")])).unwrap();
        assert_eq!(r.headers()["content-length"], "42");
    }

    #[test]
    fn reject_response_shape() {
        let r = reject_response(Reject::HeaderTooLong);
        assert_eq!(r.status(), 400);
        assert_eq!(r.headers()["x-mq-error"], "header-too-long");
        assert_eq!(r.headers()["content-length"], "0");
        let r = reject_response(Reject::TunnelUnavailable);
        assert_eq!(r.status(), 502);
        assert_eq!(r.headers()["x-mq-error"], "tunnel-unavailable");
        let m = misdirected_response();
        assert_eq!(m.status(), 421);
        assert!(m.headers().get("x-mq-error").is_none());
        assert_eq!(m.headers()["content-length"], "0");
    }
}
