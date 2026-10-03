//! SP3 spec §7.5 / §6.4: the origin's response head, normalised for the
//! gateway — or the reason it cannot be relayed (502 `upstream-protocol`).

use super::{MAX_FWD, OriginProto, RelayHead};
use mq_http::h1;
use mq_http::headers::is_hop_by_hop;
use mq_http::headers::{NAME_CAP, VAL_CAP};

/// Why a response head cannot be relayed (§7.5, §6.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeadError {
    /// A `101`: hyper surfaces it as an upgrade (§12.33).
    Upgrade101,
    /// More than 64 forwarded headers, a name ≥ 128 or a value ≥ 1024 bytes.
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
    let mut cls = 0;
    for (n, v) in &parts.headers {
        let (n, v) = (n.as_str().as_bytes(), v.as_bytes());
        if is_hop_by_hop(n) || n == b"x-mq-origin-protocol" {
            continue;
        }
        if head.headers.len() == MAX_FWD || n.len() >= NAME_CAP || v.len() >= VAL_CAP {
            return Err(HeadError::Overflow);
        }
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
    fn normalise_caps_64_128_1024() {
        let names: Vec<String> = (0..65).map(|i| format!("x-h{i}")).collect();
        let mut hs: Vec<(&str, &str)> = names[..64].iter().map(|n| (n.as_str(), "v")).collect();
        // Dropped headers do not count (C counted the forwardable ones only).
        hs.extend([("connection", "close"), ("x-mq-origin-protocol", "h1")]);
        let h = normalise(&parts(200, Version::HTTP_11, &hs)).unwrap();
        assert_eq!(h.headers.len(), 64);
        hs.push((names[64].as_str(), "v"));
        assert_eq!(
            normalise(&parts(200, Version::HTTP_11, &hs)),
            Err(HeadError::Overflow)
        );

        let n127 = "n".repeat(127);
        let n128 = "n".repeat(128);
        let v1023 = "v".repeat(1023);
        let v1024 = "v".repeat(1024);
        assert!(normalise(&parts(200, Version::HTTP_11, &[(&n127, &v1023)])).is_ok());
        for h in [(&n128, "v"), (&n127, v1024.as_str())] {
            assert_eq!(
                normalise(&parts(200, Version::HTTP_11, &[(h.0.as_str(), h.1)])),
                Err(HeadError::Overflow)
            );
        }
        // A long hop-by-hop value is dropped before the caps.
        let ok = [("keep-alive", v1024.as_str())];
        assert!(normalise(&parts(200, Version::HTTP_11, &ok)).is_ok());
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
