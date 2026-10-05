//! SP4 spec §4.4: the request head on the wire. `WireHead` exists only after
//! the complete list (pseudo and control headers included) passed the shared
//! limits; this is the single place where request sizes are checked.

use super::{BodyLen, ReqHead};
use mq_http::headers::Reject;
use mq_http::limits::SectionBudget;
use mq_transport_api::H3Header;

pub(crate) struct WireHead(Vec<(Vec<u8>, Vec<u8>)>);

impl WireHead {
    pub(crate) fn headers(&self) -> impl Iterator<Item = H3Header<'_>> {
        self.0.iter().map(|(name, value)| H3Header { name, value })
    }
}

/// SP4 spec §4.4 order: pseudo-headers, `x-mq-auth`, the optional control
/// headers, `accept-encoding`, `content-length` (`Known(n > 0)` only), then the
/// front's headers lowercased.
pub(crate) fn render(h: &ReqHead) -> Result<WireHead, Reject> {
    let pair = |n: &str, v: &[u8]| (n.as_bytes().to_vec(), v.to_vec());
    let mut out = vec![
        pair(":method", h.method.as_bytes()),
        pair(":scheme", h.target.scheme.as_bytes()),
        pair(":authority", &h.target.authority),
        pair(":path", &h.target.path),
        pair("x-mq-auth", &h.auth),
    ];
    if let Some(v) = &h.class {
        out.push(pair("x-mq-class", v));
    }
    if let Some((_, v)) = &h.origin_proto {
        out.push(pair("x-mq-origin-protocol", v));
    }
    if let Some(v) = &h.cache {
        out.push(pair("x-mq-cache", v));
    }
    if let Some(v) = &h.accept_encoding {
        out.push(pair("accept-encoding", v));
    }
    if let BodyLen::Known(n @ 1..) = h.body {
        out.push(pair("content-length", n.to_string().as_bytes()));
    }
    out.extend(
        h.headers
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v.clone())),
    );
    let mut budget = SectionBudget::default();
    if out.iter().any(|(n, v)| budget.add(n, v).is_err()) {
        return Err(Reject::HeaderTooLong);
    }
    Ok(WireHead(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mq_http::headers::{HttpVer, parse_method, parse_target};
    use mq_http::limits::{COUNT_MAX, FIELD_MAX, SECTION_MAX};

    type Hs = Vec<(Vec<u8>, Vec<u8>)>;

    fn hs(pairs: &[(&str, &str)]) -> Hs {
        pairs
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    fn req() -> ReqHead {
        ReqHead {
            method: parse_method(b"GET").unwrap(),
            target: parse_target(b"https://example.com/p").unwrap(),
            auth: b"Bearer t".to_vec(),
            class: None,
            origin_proto: None,
            cache: None,
            accept_encoding: None,
            headers: vec![],
            body: BodyLen::Empty,
        }
    }

    fn got(h: &ReqHead) -> Hs {
        render(h)
            .expect("renders")
            .headers()
            .map(|h| (h.name.to_vec(), h.value.to_vec()))
            .collect()
    }

    fn too_long(h: &ReqHead) -> bool {
        matches!(render(h), Err(Reject::HeaderTooLong))
    }

    #[test]
    fn render_order_matches_spec() {
        let mut h = req();
        h.method = parse_method(b"POST").unwrap();
        h.target = parse_target(b"https://example.com:8443/a?b=1").unwrap();
        h.auth = b"Bearer tok".to_vec();
        h.class = Some(b"bulk".to_vec());
        h.origin_proto = Some((HttpVer::H2, b"H2".to_vec()));
        h.cache = Some(b"60".to_vec());
        h.accept_encoding = Some(b"br".to_vec());
        h.body = BodyLen::Known(5);
        h.headers = hs(&[("X-Custom", "V"), ("User-Agent", "t")]);
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
        assert_eq!(got(&h), want);
    }

    #[test]
    fn render_minimal_head() {
        let want = hs(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/p"),
            ("x-mq-auth", "Bearer t"),
        ]);
        assert_eq!(got(&req()), want);
    }

    #[test]
    fn render_cl_only_for_known_positive() {
        let cl = |body| {
            let mut h = req();
            h.body = body;
            got(&h)
                .into_iter()
                .find(|(n, _)| n == b"content-length")
                .map(|(_, v)| v)
        };
        assert_eq!(cl(BodyLen::Known(7)), Some(b"7".to_vec()));
        assert_eq!(
            cl(BodyLen::Known(u64::MAX)),
            Some(u64::MAX.to_string().into_bytes())
        );
        for body in [BodyLen::Empty, BodyLen::Known(0), BodyLen::Unknown] {
            assert_eq!(cl(body), None, "{body:?}");
        }
    }

    #[test]
    fn render_method_case_preserved() {
        let mut h = req();
        h.method = parse_method(b"mKcOl").unwrap();
        assert_eq!(got(&h)[0], (b":method".to_vec(), b"mKcOl".to_vec()));
    }

    #[test]
    fn render_lowercases_names_keeps_values_and_empty_values() {
        let mut h = req();
        h.headers = hs(&[("X-Big", "V"), ("X-Empty", "")]);
        assert_eq!(got(&h)[5..], hs(&[("x-big", "V"), ("x-empty", "")])[..]);
    }

    #[test]
    fn render_6k_header_forwarded() {
        let six_k = "v".repeat(6 * 1024);
        let mut h = req();
        h.headers = hs(&[("X-Big", &six_k)]);
        assert_eq!(
            got(&h).last().unwrap(),
            &(b"x-big".to_vec(), six_k.into_bytes())
        );
    }

    #[test]
    fn render_field_limit_boundary() {
        let mut h = req();
        let fits = FIELD_MAX - "x-other".len();
        h.headers = hs(&[("x-other", &"v".repeat(fits))]);
        assert!(!too_long(&h));
        h.headers = hs(&[("x-other", &"v".repeat(fits + 1))]);
        assert!(too_long(&h));
        h.headers = hs(&[(&"n".repeat(FIELD_MAX), "")]);
        assert!(!too_long(&h));
        h.headers = hs(&[(&"n".repeat(FIELD_MAX + 1), "")]);
        assert!(too_long(&h));
    }

    #[test]
    fn render_section_over_32k_header_too_long() {
        // Five fields of 8000 bytes: each under FIELD_MAX, together over SECTION_MAX.
        let mut h = req();
        h.headers = (0..5)
            .map(|i| (format!("x-h{i}").into_bytes(), vec![b'v'; 8000]))
            .collect();
        assert!(too_long(&h));
        h.headers.pop();
        assert!(!too_long(&h));
    }

    #[test]
    fn render_count_limit_boundary() {
        // Five pseudo/control fields count: 251 more make 256, 252 make 257.
        let mut h = req();
        h.headers = vec![(b"a".to_vec(), vec![]); COUNT_MAX - 5];
        assert_eq!(got(&h).len(), COUNT_MAX);
        h.headers.push((b"a".to_vec(), vec![]));
        assert!(too_long(&h));
    }

    #[test]
    fn render_counts_pseudo_and_control_in_budget() {
        // The headers alone fill SECTION_MAX exactly (4 x (4 + 8156 + 32)); the
        // pseudo and control fields push the whole list over.
        let mut h = req();
        h.headers = (0..4)
            .map(|i| (format!("x-h{i}").into_bytes(), vec![b'v'; 8156]))
            .collect();
        let mut alone = SectionBudget::default();
        assert!(h.headers.iter().all(|(n, v)| alone.add(n, v).is_ok()));
        assert_eq!(alone.size(), SECTION_MAX);
        assert!(too_long(&h));
        // Control headers count too: pseudo-headers alone leave room for three
        // 8150-byte fields, a large accept-encoding tips it over.
        h.headers.truncate(3);
        h.headers.iter_mut().for_each(|(_, v)| v.truncate(8150));
        assert!(!too_long(&h));
        h.accept_encoding = Some(vec![b'a'; 8000]);
        assert!(too_long(&h));
    }
}
