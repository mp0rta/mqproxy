//! SP3 spec §7.4: the `http::Request` hyper sends, built at assignment time
//! from the stored request in the conn's URI form.

use super::{OriginProto, Scheme, StartErr, StoredRequest, UploadBody};
use http::Request;

/// Origin-form for h1, absolute URI for h2; `host` first, empty-valued
/// forwarded headers dropped, `accept: */*` unless present or suppressed,
/// `content-length` for a known length, `transfer-encoding: chunked` for an
/// unknown length on h1 only. A residual build error is
/// 502 `origin-start-failed` (§7.4): intake already validated every part.
pub(super) fn build_request(
    req: &StoredRequest,
    proto: OriginProto,
) -> Result<Request<UploadBody>, StartErr> {
    let split = req.path.iter().position(|&b| b == b'?');
    let (path, query) = req.path.split_at(split.unwrap_or(req.path.len()));
    let mut uri = Vec::with_capacity(req.authority.len() + req.path.len() + 8);
    if proto == OriginProto::H2 {
        uri.extend_from_slice(match req.scheme {
            Scheme::Http => b"http://",
            Scheme::Https => b"https://",
        });
        uri.extend_from_slice(&req.authority);
    }
    uri.extend(remove_dot_segments(path));
    uri.extend_from_slice(query);

    let blank = |v: &[u8]| v.iter().all(|&b| b == b' ' || b == b'\t');
    let mut b = Request::builder()
        .method(req.method.as_bytes())
        .uri(uri)
        .header("host", req.authority.as_slice());
    // libcurl: `name:` suppresses, so an empty `accept` suppresses the default too.
    if !req
        .headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(b"accept"))
    {
        b = b.header("accept", "*/*");
    }
    for (n, v) in req.headers.iter().filter(|(_, v)| !blank(v)) {
        b = b.header(n.as_slice(), v.as_slice());
    }
    let buf = req.body.borrow();
    if !(buf.fin && buf.data.is_empty()) {
        match buf.cl {
            Some(cl) => b = b.header("content-length", cl),
            // hyper's h1 encoder would send an unknown-length GET body as empty; h2 strips it.
            None if proto == OriginProto::H1 => b = b.header("transfer-encoding", "chunked"),
            None => {}
        }
    }
    drop(buf);
    b.body(UploadBody::new(&req.body))
        .map_err(|_| StartErr::BadPath)
}

/// RFC 3986 §5.2.4 `remove_dot_segments`, on the path component only.
fn remove_dot_segments(mut input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let pop = |out: &mut Vec<u8>| out.truncate(out.iter().rposition(|&b| b == b'/').unwrap_or(0));
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix(b"../") {
            input = rest;
        } else if let Some(rest) = input.strip_prefix(b"./") {
            input = rest;
        } else if input.starts_with(b"/./") {
            input = &input[2..];
        } else if input == b"/." {
            input = b"/";
        } else if input.starts_with(b"/../") {
            input = &input[3..];
            pop(&mut out);
        } else if input == b"/.." {
            input = b"/";
            pop(&mut out);
        } else if input == b"." || input == b".." {
            input = b"";
        } else {
            let end = input[1..]
                .iter()
                .position(|&b| b == b'/')
                .map_or(input.len(), |i| i + 1);
            out.extend_from_slice(&input[..end]);
            input = &input[end..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::origin::{Dirty, UploadBuf};
    use http_body::Body;
    use mq_http::headers::parse_method;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    fn stored(method: &str, path: &str, headers: &[(&str, &str)]) -> StoredRequest {
        let buf = UploadBuf::new(None, Arc::new(Dirty::default()));
        StoredRequest {
            method: parse_method(method.as_bytes()).unwrap(),
            scheme: Scheme::Https,
            authority: b"o.test:8443".to_vec(),
            path: path.as_bytes().to_vec(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect(),
            body: Rc::new(RefCell::new(buf)),
        }
    }

    /// Bodiless: FIN on the header section.
    fn bodiless(s: StoredRequest) -> StoredRequest {
        s.body.borrow_mut().fin = true;
        s
    }

    fn names(r: &Request<UploadBody>) -> Vec<&str> {
        r.headers().iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn build_h1_origin_form_and_host_first() {
        let s = bodiless(stored("get", "/x?q=1", &[("user-agent", "t")]));
        let r = build_request(&s, OriginProto::H1).unwrap();
        assert_eq!(r.method(), http::Method::GET);
        assert_eq!(r.uri().to_string(), "/x?q=1");
        assert_eq!(r.uri().scheme(), None);
        assert_eq!(names(&r), ["host", "accept", "user-agent"]);
        assert_eq!(r.headers()["host"], "o.test:8443");
    }

    #[test]
    fn build_h2_absolute_uri() {
        let s = bodiless(stored("GET", "/x?q=1", &[]));
        let r = build_request(&s, OriginProto::H2).unwrap();
        assert_eq!(r.uri().to_string(), "https://o.test:8443/x?q=1");
        let mut s = bodiless(stored("GET", "/", &[]));
        s.scheme = Scheme::Http;
        let r = build_request(&s, OriginProto::H2).unwrap();
        assert_eq!(r.uri().to_string(), "http://o.test:8443/");
    }

    #[test]
    fn dot_segments_removed_path_only() {
        for (path, want) in [
            ("/a/../b?../c", "/b?../c"),
            ("/a/./b/../../c/", "/c/"),
            ("/..", "/"),
            ("/a/..", "/"),
            ("/a/.", "/a/"),
            ("/../../x", "/x"),
            ("/a/.b/..c/...", "/a/.b/..c/..."),
            ("/?/../x", "/?/../x"),
        ] {
            let s = bodiless(stored("GET", path, &[]));
            let r = build_request(&s, OriginProto::H1).unwrap();
            assert_eq!(r.uri().to_string(), want, "{path}");
        }
    }

    #[test]
    fn empty_value_header_dropped_and_suppresses_accept_default() {
        let s = bodiless(stored(
            "GET",
            "/",
            &[("x-a", ""), ("x-b", " \t "), ("x-c", "1")],
        ));
        let r = build_request(&s, OriginProto::H1).unwrap();
        assert_eq!(names(&r), ["host", "accept", "x-c"]);
        let s = bodiless(stored("GET", "/", &[("accept", "")]));
        let r = build_request(&s, OriginProto::H1).unwrap();
        assert_eq!(
            names(&r),
            ["host"],
            "an empty accept suppresses the default"
        );
    }

    #[test]
    fn accept_default_added() {
        let s = bodiless(stored("GET", "/", &[]));
        let r = build_request(&s, OriginProto::H1).unwrap();
        assert_eq!(r.headers()["accept"], "*/*");
        let s = bodiless(stored("GET", "/", &[("Accept", "text/html")]));
        let r = build_request(&s, OriginProto::H1).unwrap();
        let v: Vec<_> = r.headers().get_all("accept").iter().collect();
        assert_eq!(v, ["text/html"], "a forwarded accept wins, no default");
    }

    #[test]
    fn forwarded_order_and_known_length() {
        let s = stored("POST", "/", &[("x-a", "1"), ("x-b", "2"), ("x-a", "3")]);
        s.body.borrow_mut().cl = Some(5);
        let r = build_request(&s, OriginProto::H1).unwrap();
        let all: Vec<_> = r
            .headers()
            .iter()
            .map(|(n, v)| (n.as_str(), v.to_str().unwrap()))
            .collect();
        assert_eq!(
            all,
            [
                ("host", "o.test:8443"),
                ("accept", "*/*"),
                ("x-a", "1"),
                ("x-a", "3"),
                ("x-b", "2"),
                ("content-length", "5"),
            ],
            "HeaderMap groups repeated names (§12.14)"
        );
        assert!(!r.headers().contains_key("transfer-encoding"));
        assert_eq!(r.body().size_hint().exact(), Some(5));
    }

    #[test]
    fn chunked_only_on_h1_unknown_length() {
        let s = stored("GET", "/", &[]);
        s.body.borrow_mut().data.extend(b"abc");
        let r = build_request(&s, OriginProto::H1).unwrap();
        assert_eq!(r.headers()["transfer-encoding"], "chunked");
        assert!(!r.headers().contains_key("content-length"));
        let r = build_request(&s, OriginProto::H2).unwrap();
        assert!(!r.headers().contains_key("transfer-encoding"));
        assert!(!r.headers().contains_key("content-length"));
    }

    #[test]
    fn bodiless_has_no_cl_and_end_stream() {
        for proto in [OriginProto::H1, OriginProto::H2] {
            let s = bodiless(stored("POST", "/", &[]));
            let r = build_request(&s, proto).unwrap();
            assert!(!r.headers().contains_key("content-length"));
            assert!(!r.headers().contains_key("transfer-encoding"));
            assert!(r.body().is_end_stream());
        }
    }

    #[test]
    fn body_counts_as_live() {
        let s = bodiless(stored("GET", "/", &[]));
        let r = build_request(&s, OriginProto::H1).unwrap();
        assert!(
            !s.body.borrow().released(),
            "the request owns an UploadBody"
        );
        drop(r);
        assert!(s.body.borrow().released());
    }
}
