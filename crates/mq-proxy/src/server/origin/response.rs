// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP3 spec §7.5 / §6.4: the origin's response head, normalised for the
//! gateway — or the reason it cannot be relayed (502 `upstream-protocol`).

use super::{OriginProto, RelayHead};
use mq_http::h1;
use mq_http::headers::is_hop_by_hop;
use mq_http::limits::SectionBudget;

/// Why a response head cannot be relayed (§7.5, §6.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// A `101`: hyper surfaces it as an upgrade (§12.33).
    Upgrade101,
    /// The forwarded head passes a `mq_http::limits` bound (SP4 spec §5).
    Overflow,
}

pub(super) fn normalise(parts: &http::response::Parts) -> Result<RelayHead, HeadError> {
    if parts.status == http::StatusCode::SWITCHING_PROTOCOLS {
        return Err(HeadError::Upgrade101);
    }
    let (version, proto) = match parts.version {
        http::Version::HTTP_2 => ("h2", OriginProto::H2),
        http::Version::HTTP_10 => ("http/1.0", OriginProto::H1),
        _ => ("http/1.1", OriginProto::H1),
    };
    let mut head = RelayHead {
        status: parts.status.as_u16(),
        version,
        proto,
        headers: Vec::new(),
        content_encoding: None,
        cl: None,
    };
    // The gateway adds `:status` and `x-mq-origin-protocol` after us, so they
    // are measured up front (SP4 spec §5); both seeds fit an empty budget.
    let mut budget = SectionBudget::default();
    let status = parts.status.as_u16().to_string();
    for (n, v) in [
        (&b":status"[..], status.as_bytes()),
        (b"x-mq-origin-protocol", version.as_bytes()),
    ] {
        budget.add(n, v).map_err(|_| HeadError::Overflow)?;
    }
    let mut cls = 0;
    for (n, v) in &parts.headers {
        let (n, v) = (n.as_str().as_bytes(), v.as_bytes());
        if is_hop_by_hop(n) || n == b"x-mq-origin-protocol" {
            continue;
        }
        budget.add(n, v).map_err(|_| HeadError::Overflow)?;
        match n {
            b"content-encoding" => head.content_encoding = Some(v.to_vec()),
            b"content-length" => {
                cls += 1;
                head.cl = h1::parse_content_length(v);
            }
            _ => {}
        }
        head.headers.push((n.to_vec(), v.to_vec()));
    }
    // The body check's input: a single numeric `content-length` (§6.4).
    if cls != 1 {
        head.cl = None;
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Response, Version};
    use mq_http::limits::{FIELD_MAX, SECTION_MAX};

    fn parts(status: u16, version: Version, headers: &[(&str, &str)]) -> http::response::Parts {
        let mut b = Response::builder().status(status).version(version);
        for (n, v) in headers {
            b = b.header(*n, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn normalise_drops_hop_by_hop_and_xmq_origin_protocol() {
        let p = parts(
            200,
            Version::HTTP_11,
            &[
                ("content-type", "text/plain"),
                ("connection", "keep-alive"),
                ("keep-alive", "timeout=5"),
                ("proxy-connection", "x"),
                ("transfer-encoding", "chunked"),
                ("upgrade", "h2c"),
                ("x-mq-origin-protocol", "h2"),
                ("x-mq-other", "kept"),
                ("content-length", "5"),
            ],
        );
        let h = normalise(&p).unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.version, "http/1.1");
        assert_eq!(h.proto, OriginProto::H1);
        let names: Vec<&[u8]> = h.headers.iter().map(|(n, _)| n.as_slice()).collect();
        assert_eq!(
            names,
            [&b"content-type"[..], b"x-mq-other", b"content-length"]
        );
        assert_eq!(h.cl, Some(5));
        assert_eq!(h.content_encoding, None);
    }

    #[test]
    fn normalise_versions() {
        let h = normalise(&parts(204, Version::HTTP_10, &[])).unwrap();
        assert_eq!((h.version, h.proto), ("http/1.0", OriginProto::H1));
        let h = normalise(&parts(200, Version::HTTP_2, &[])).unwrap();
        assert_eq!((h.version, h.proto), ("h2", OriginProto::H2));
    }

    #[test]
    fn normalise_cl_single_numeric_only() {
        let two = [("content-length", "5"), ("content-length", "5")];
        assert_eq!(
            normalise(&parts(200, Version::HTTP_2, &two)).unwrap().cl,
            None
        );
        let bad = [("content-length", "5x")];
        let h = normalise(&parts(200, Version::HTTP_2, &bad)).unwrap();
        assert_eq!(h.cl, None);
        assert_eq!(h.headers.len(), 1, "still relayed");
    }

    #[test]
    fn normalise_6k_csp_ok() {
        let csp = "c".repeat(6 * 1024);
        let h = normalise(&parts(
            200,
            Version::HTTP_11,
            &[("content-security-policy", &csp)],
        ))
        .unwrap();
        assert_eq!(h.headers[0].1.len(), 6 * 1024);
    }

    #[test]
    fn normalise_field_8192_ok_8193_overflow() {
        let v = |n: usize| "v".repeat(n);
        let ok = parts(200, Version::HTTP_11, &[("x", &v(8191))]);
        assert!(normalise(&ok).is_ok());
        let over = parts(200, Version::HTTP_11, &[("x", &v(8192))]);
        assert_eq!(normalise(&over), Err(HeadError::Overflow));
    }

    #[test]
    fn normalise_count_counts_status_and_origin_protocol() {
        // 254 forwarded headers + `:status` + `x-mq-origin-protocol` = COUNT_MAX.
        let names: Vec<String> = (0..255).map(|i| format!("x-h{i}")).collect();
        let hs: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "v")).collect();
        assert!(normalise(&parts(200, Version::HTTP_2, &hs[..254])).is_ok());
        assert_eq!(
            normalise(&parts(200, Version::HTTP_2, &hs)),
            Err(HeadError::Overflow)
        );
    }

    #[test]
    fn normalise_section_counts_status_and_origin_protocol() {
        // HTTP/2 origin: `x-mq-origin-protocol: h2`.
        let seed = (7 + 3 + 32) + (b"x-mq-origin-protocol".len() + 2 + 32);
        // Four 8000-byte fields, then one filler sized to land exactly.
        let big = "v".repeat(8000);
        let mut hs = vec![
            ("x-a", big.as_str()),
            ("x-b", big.as_str()),
            ("x-c", big.as_str()),
            ("x-d", big.as_str()),
        ];
        let used: usize = hs.iter().map(|(n, v)| n.len() + v.len() + 32).sum();
        let fill = SECTION_MAX - seed - used - ("x-e".len() + 32);
        let filler = "f".repeat(fill);
        hs.push(("x-e", filler.as_str()));
        assert!(fill + 3 <= FIELD_MAX);
        assert!(normalise(&parts(200, Version::HTTP_2, &hs)).is_ok());
        let one_more = "f".repeat(fill + 1);
        hs[4].1 = one_more.as_str();
        assert_eq!(
            normalise(&parts(200, Version::HTTP_2, &hs)),
            Err(HeadError::Overflow)
        );
    }

    #[test]
    fn normalise_dropped_headers_do_not_count() {
        // A long hop-by-hop value and an origin-sent x-mq-origin-protocol are
        // dropped before the budget.
        let long = "v".repeat(9000);
        let hs = [
            ("keep-alive", long.as_str()),
            ("x-mq-origin-protocol", long.as_str()),
        ];
        assert!(normalise(&parts(200, Version::HTTP_11, &hs)).is_ok());
    }

    #[test]
    fn normalise_101_is_upgrade_error() {
        assert_eq!(
            normalise(&parts(101, Version::HTTP_11, &[("upgrade", "websocket")])),
            Err(HeadError::Upgrade101)
        );
    }

    #[test]
    fn normalise_content_encoding_last_wins() {
        let hs = [
            ("content-encoding", "gzip"),
            ("x-a", "1"),
            ("content-encoding", "br"),
        ];
        let h = normalise(&parts(200, Version::HTTP_11, &hs)).unwrap();
        assert_eq!(h.content_encoding.as_deref(), Some(&b"br"[..]));
        let ce: Vec<_> = h
            .headers
            .iter()
            .filter(|(n, _)| n == b"content-encoding")
            .collect();
        assert_eq!(ce.len(), 2, "both relayed");
    }
}
