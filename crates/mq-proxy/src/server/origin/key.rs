//! SP3 spec §7.2 step 1: the bridge's own authority split (`http::uri::Authority`
//! accepts `user@host` and answers `None` for `host:99999`), the request's
//! acceptable protocols and its ALPN list.

use super::{OriginProto, Scheme};
use crate::ingress::parse_host;
use mq_http::headers::HttpVer;
use mq_runtime::Host;
use rustls::pki_types::ServerName;
use std::net::IpAddr;

/// `[v6]` (only `:port` may follow) or the host before the last `:`; a port
/// is 1–5 digits ≤ 65535; no userinfo. The host goes through `parse_host`.
pub(super) fn split_authority(scheme: Scheme, authority: &[u8]) -> Result<(Host, u16), ()> {
    if authority.contains(&b'@') {
        return Err(());
    }
    let (host, port) = match authority.iter().position(|&b| b == b']') {
        Some(close) if authority.first() == Some(&b'[') => match &authority[close + 1..] {
            [] => (&authority[..=close], None),
            [b':', p @ ..] => (&authority[..=close], Some(p)),
            _ => return Err(()),
        },
        _ => match authority.iter().rposition(|&b| b == b':') {
            Some(i) => (&authority[..i], Some(&authority[i + 1..])),
            None => (authority, None),
        },
    };
    let port = match port {
        None if scheme == Scheme::Https => 443,
        None => 80,
        Some(p) if (1..=5).contains(&p.len()) && p.iter().all(u8::is_ascii_digit) => {
            std::str::from_utf8(p).unwrap().parse().map_err(|_| ())?
        }
        Some(_) => return Err(()),
    };
    Ok((parse_host(host).ok_or(())?, port))
}

/// The `ConnKey` host: an IP literal's text (brackets stripped) or the name.
pub(super) fn host_key(h: &Host) -> String {
    match h {
        Host::Ip(ip) => ip.to_string(),
        Host::Domain(d) => d.clone(),
    }
}

/// The dial host of a `ConnKey` host (the inverse of `host_key`: a domain
/// never parses as an IP, `parse_host` made it `Host::Ip`).
pub(super) fn host_of(key_host: &str) -> Host {
    key_host
        .parse::<IpAddr>()
        .map_or_else(|_| Host::Domain(key_host.to_owned()), Host::Ip)
}

/// §7.2 step 4, from the `ConnKey` host: an IP literal → `IpAddress`, else
/// `DnsName`; `None` = invalid (`curl:6`).
pub(super) fn server_name(host: &str) -> Option<ServerName<'static>> {
    match host.parse::<IpAddr>() {
        Ok(ip) => Some(ServerName::from(ip)),
        Err(_) => rustls::pki_types::DnsName::try_from(host.to_owned())
            .ok()
            .map(ServerName::DnsName),
    }
}

/// The ALPN list of a new https dial (plain http sends none).
pub(super) fn alpn_for(scheme: Scheme, ver: HttpVer) -> &'static [&'static [u8]] {
    match (scheme, ver) {
        (Scheme::Http, _) => &[],
        (Scheme::Https, HttpVer::H1) => &[b"http/1.1"],
        (Scheme::Https, _) => &[b"h2", b"http/1.1"],
    }
}

/// Whether a conn that negotiated `proto` may carry a request of `ver`.
pub(super) fn accepts(ver: HttpVer, proto: OriginProto) -> bool {
    ver != HttpVer::H1 || proto == OriginProto::H1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn host_of_inverts_host_key() {
        for a in ["o.test", "127.0.0.1", "[::1]:8443"] {
            let (h, _) = split_authority(Scheme::Https, a.as_bytes()).unwrap();
            assert_eq!(host_of(&host_key(&h)), h, "{a}");
        }
    }

    #[test]
    fn split_authority_cases() {
        let d = |s: &str| Host::Domain(s.into());
        let v6 = Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let ok = [
            (Scheme::Https, "h", d("h"), 443),
            (Scheme::Http, "h", d("h"), 80),
            (Scheme::Https, "h:8443", d("h"), 8443),
            (Scheme::Http, "h:65535", d("h"), 65535),
            (
                Scheme::Http,
                "127.0.0.1",
                Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                80,
            ),
            (Scheme::Https, "[::1]", v6.clone(), 443),
            (Scheme::Http, "[::1]:443", v6, 443),
        ];
        for (scheme, a, host, port) in ok {
            assert_eq!(
                split_authority(scheme, a.as_bytes()),
                Ok((host, port)),
                "{a}"
            );
        }
        for a in [
            "h:", "h:99999", "h:65536", "h:123456", "h:abc", "h:+80", "u@h", "u@h:80", "[::1]x",
            "[::1]:", "[::1", "[h]", "",
        ] {
            assert_eq!(split_authority(Scheme::Https, a.as_bytes()), Err(()), "{a}");
        }
    }

    #[test]
    fn server_name_from_the_key_host() {
        for (h, want) in [
            ("localhost", Some("DnsName")),
            ("127.0.0.1", Some("IpAddress")),
            ("::1", Some("IpAddress")),
            ("a..b", None),
        ] {
            let got = server_name(h).map(|n| match n {
                ServerName::DnsName(_) => "DnsName",
                ServerName::IpAddress(_) => "IpAddress",
                _ => "other",
            });
            assert_eq!(got, want, "{h}");
        }
        let v6 = Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(host_key(&v6), "::1", "brackets stripped");
    }

    #[test]
    fn alpn_for_h1_vs_default() {
        let both: &[&[u8]] = &[b"h2", b"http/1.1"];
        assert_eq!(
            alpn_for(Scheme::Https, HttpVer::H1),
            &[b"http/1.1" as &[u8]]
        );
        for v in [HttpVer::Default, HttpVer::H2, HttpVer::H3] {
            assert_eq!(alpn_for(Scheme::Https, v), both, "{v:?}");
        }
        for v in [HttpVer::Default, HttpVer::H1, HttpVer::H2, HttpVer::H3] {
            assert!(alpn_for(Scheme::Http, v).is_empty(), "plain http: no ALPN");
        }
    }

    #[test]
    fn accepts_matrix() {
        assert!(accepts(HttpVer::H1, OriginProto::H1));
        assert!(!accepts(HttpVer::H1, OriginProto::H2), "H1 rejects h2");
        for v in [HttpVer::Default, HttpVer::H2, HttpVer::H3] {
            assert!(accepts(v, OriginProto::H1), "{v:?}");
            assert!(accepts(v, OriginProto::H2), "{v:?}");
        }
    }
}
