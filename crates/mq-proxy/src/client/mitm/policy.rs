// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP4 spec §7.3: routing — MITM or opaque relay for one captured TLS flow.

use std::borrow::Borrow;
use std::collections::HashSet;
use std::net::IpAddr;

/// A canonical DNS host name: lowercase, no trailing dot, `[a-z0-9-.]` only.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Sni(Box<str>);

// Sound: the derived `Hash` of a one-field newtype hashes exactly as the `str`.
impl Borrow<str> for Sni {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Sni {
    /// The one canonicaliser (SNI, IgnoreHosts entries, `:authority` host).
    pub fn canonical(b: &[u8]) -> Option<Sni> {
        let b = b.strip_suffix(b".").unwrap_or(b);
        if b.is_empty() || b.len() > 253 {
            return None;
        }
        let s = std::str::from_utf8(b).ok()?.to_ascii_lowercase();
        let ok = s.split('.').all(|l| {
            (1..=63).contains(&l.len()) && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        });
        if !ok || s.parse::<IpAddr>().is_ok() {
            return None;
        }
        Some(Sni(s.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `self == base` or `self` ends with `"." + base`.
    fn is_under_or_eq(&self, base: &Sni) -> bool {
        self == base || self.is_under(base)
    }

    /// `self` ends with `"." + base`.
    fn is_under(&self, base: &Sni) -> bool {
        self.0
            .strip_suffix(base.as_str())
            .is_some_and(|p| p.ends_with('.'))
    }
}

/// IgnoreHosts (D4): an exact entry matches the apex only, a leading-dot entry
/// strict subdomains only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IgnoreHosts {
    exact: HashSet<Sni>,
    suffix: HashSet<Sni>,
}

impl IgnoreHosts {
    /// An invalid entry is an error naming it.
    pub fn parse<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        let mut h = Self::default();
        for e in entries {
            let (dot, host) = match e.strip_prefix('.') {
                Some(r) => (true, r),
                None => (false, e),
            };
            let sni = Sni::canonical(host.as_bytes())
                .ok_or_else(|| format!("invalid IgnoreHosts entry {e:?}"))?;
            if dot { &mut h.suffix } else { &mut h.exact }.insert(sni);
        }
        Ok(h)
    }

    /// Exact once, then each proper parent domain in `suffix`: O(labels).
    pub fn matches(&self, s: &Sni) -> bool {
        let n = s.as_str();
        self.exact.contains(n)
            || n.match_indices('.')
                .any(|(i, _)| self.suffix.contains(&n[i + 1..]))
    }

    pub fn len(&self) -> usize {
        self.exact.len() + self.suffix.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One NameConstraints dNSName subtree (RFC 5280 §4.2.1.10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsSubtree {
    /// The empty constraint: matches every name.
    All,
    /// Equal, or under it.
    Domain(Sni),
    /// Leading dot: strict subdomains.
    Under(Sni),
}

impl DnsSubtree {
    fn matches(&self, s: &Sni) -> bool {
        match self {
            Self::All => true,
            Self::Domain(c) => s.is_under_or_eq(c),
            Self::Under(c) => s.is_under(c),
        }
    }
}

/// The CA's NameConstraints. Empty `permitted` allows everything.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CaScope {
    pub permitted: Vec<DnsSubtree>,
    pub excluded: Vec<DnsSubtree>,
}

impl CaScope {
    pub fn covers(&self, s: &Sni) -> bool {
        (self.permitted.is_empty() || self.permitted.iter().any(|t| t.matches(s)))
            && !self.excluded.iter().any(|t| t.matches(s))
    }
}

/// Why a flow goes to the opaque relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    NotTls,
    NoSni,
    BadSni,
    NoH2,
    Ignored,
    OutOfCaScope,
    TlsIncompatible,
    Timeout,
    TooLarge,
    Eof,
    AtCapacity,
}

impl Why {
    /// Every variant, in `mq.mitm` line order (`opaque` counters index by `as usize`).
    pub const ALL: [Why; 11] = [
        Why::NotTls,
        Why::NoSni,
        Why::BadSni,
        Why::NoH2,
        Why::Ignored,
        Why::OutOfCaScope,
        Why::TlsIncompatible,
        Why::Timeout,
        Why::TooLarge,
        Why::Eof,
        Why::AtCapacity,
    ];

    /// The `opaque_<key>` name in the `mq.mitm` line.
    pub fn key(self) -> &'static str {
        match self {
            Why::NotTls => "not_tls",
            Why::NoSni => "no_sni",
            Why::BadSni => "bad_sni",
            Why::NoH2 => "no_h2",
            Why::Ignored => "ignored",
            Why::OutOfCaScope => "ca_scope",
            Why::TlsIncompatible => "tls_incompat",
            Why::Timeout => "timeout",
            Why::TooLarge => "too_large",
            Why::Eof => "eof",
            Why::AtCapacity => "capacity",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Mitm(Sni),
    Opaque(Why),
}

#[derive(Clone, Debug, Default)]
pub struct MitmPolicy {
    pub ignore: IgnoreHosts,
    pub scope: CaScope,
}

impl MitmPolicy {
    /// SP4 spec §7.3 (plan R4): the first failing check wins, in this order.
    pub fn route(&self, sni: Option<&str>, offers_h2: bool) -> Route {
        let Some(raw) = sni else {
            return Route::Opaque(Why::NoSni);
        };
        let Some(sni) = Sni::canonical(raw.as_bytes()) else {
            return Route::Opaque(Why::BadSni);
        };
        if !offers_h2 {
            return Route::Opaque(Why::NoH2);
        }
        if self.ignore.matches(&sni) {
            return Route::Opaque(Why::Ignored);
        }
        if !self.scope.covers(&sni) {
            return Route::Opaque(Why::OutOfCaScope);
        }
        Route::Mitm(sni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::mitm::MitmTuning;
    use mq_runtime::KeepAlive;
    use proptest::prelude::*;
    use std::time::Duration;

    fn sni(s: &str) -> Sni {
        Sni::canonical(s.as_bytes()).unwrap()
    }

    #[test]
    fn why_all_is_in_discriminant_order() {
        for (i, w) in Why::ALL.iter().enumerate() {
            assert_eq!(*w as usize, i, "{w:?}");
        }
    }

    fn dom(s: &str) -> DnsSubtree {
        DnsSubtree::Domain(sni(s))
    }

    fn under(s: &str) -> DnsSubtree {
        DnsSubtree::Under(sni(s))
    }

    #[test]
    fn canonical_lowercases_strips_one_dot() {
        assert_eq!(sni("ExAmple.COM").as_str(), "example.com");
        assert_eq!(sni("example.com.").as_str(), "example.com");
        assert!(Sni::canonical(b"example.com..").is_none());
    }

    #[test]
    fn canonical_rejects_ip_star_underscore_long_label_254_total() {
        for bad in [
            &b"1.2.3.4"[..],
            b"::1",
            b"[::1]",
            b"*.example.com",
            b"a_b.example.com",
            b"",
            b".",
            b"a..b",
            b".a",
            b"a b",
            b"\xff.example.com",
        ] {
            assert!(Sni::canonical(bad).is_none(), "{bad:?}");
        }
        let l63 = "a".repeat(63);
        assert!(Sni::canonical(l63.as_bytes()).is_some());
        assert!(Sni::canonical("a".repeat(64).as_bytes()).is_none());
        // 253 total is the longest accepted; 254 is not.
        let n253 = format!("{l63}.{l63}.{l63}.{}", "a".repeat(61));
        assert_eq!(n253.len(), 253);
        assert!(Sni::canonical(n253.as_bytes()).is_some());
        let n254 = format!("{l63}.{l63}.{l63}.{}", "a".repeat(62));
        assert_eq!(n254.len(), 254);
        assert!(Sni::canonical(n254.as_bytes()).is_none());
        // One trailing dot is stripped before the length check.
        assert!(Sni::canonical(format!("{n253}.").as_bytes()).is_some());
    }

    #[test]
    fn ignore_exact_apex_only() {
        let h = IgnoreHosts::parse(["example.com"]).unwrap();
        assert!(h.matches(&sni("example.com")));
        assert!(h.matches(&sni("EXAMPLE.com.")));
        assert!(!h.matches(&sni("www.example.com")));
        assert!(!h.matches(&sni("badexample.com")));
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn ignore_dot_strict_subdomains_only() {
        let h = IgnoreHosts::parse([".example.com"]).unwrap();
        assert!(h.matches(&sni("www.example.com")));
        assert!(!h.matches(&sni("example.com")));
        assert!(!h.matches(&sni("badexample.com")));
    }

    #[test]
    fn ignore_deep_subdomain_matches() {
        let h = IgnoreHosts::parse([".example.com"]).unwrap();
        assert!(h.matches(&sni("a.b.c.example.com")));
    }

    #[test]
    fn ignore_invalid_entry_error_names_it() {
        for bad in ["", ".", "a..b", "*.x"] {
            let e = IgnoreHosts::parse(["ok.com", bad]).unwrap_err();
            assert!(e.contains(&format!("{bad:?}")), "{e}");
        }
    }

    #[test]
    fn scope_permitted_excluded() {
        let s = CaScope {
            permitted: vec![dom("example.com")],
            excluded: vec![dom("secret.example.com")],
        };
        assert!(s.covers(&sni("example.com")));
        assert!(s.covers(&sni("www.example.com")));
        assert!(!s.covers(&sni("badexample.com")));
        assert!(!s.covers(&sni("other.org")));
        assert!(!s.covers(&sni("secret.example.com")));
        assert!(!s.covers(&sni("x.secret.example.com")));
    }

    #[test]
    fn scope_all_permitted_matches_every_name() {
        for permitted in [vec![], vec![DnsSubtree::All]] {
            let s = CaScope {
                permitted,
                excluded: vec![],
            };
            assert!(s.covers(&sni("anything.example")));
        }
    }

    #[test]
    fn scope_all_excluded_matches_none() {
        let s = CaScope {
            permitted: vec![],
            excluded: vec![DnsSubtree::All],
        };
        assert!(!s.covers(&sni("anything.example")));
    }

    #[test]
    fn scope_leading_dot_strict() {
        let s = CaScope {
            permitted: vec![under("example.com")],
            excluded: vec![],
        };
        assert!(s.covers(&sni("www.example.com")));
        assert!(s.covers(&sni("a.b.example.com")));
        assert!(!s.covers(&sni("example.com")));
        assert!(!s.covers(&sni("badexample.com")));
    }

    #[test]
    fn route_order() {
        let p = MitmPolicy {
            ignore: IgnoreHosts::parse(["ign.com"]).unwrap(),
            scope: CaScope {
                permitted: vec![dom("ok.com"), dom("ign.com")],
                excluded: vec![],
            },
        };
        // NoSni wins even without h2.
        assert_eq!(p.route(None, false), Route::Opaque(Why::NoSni));
        // BadSni before NoH2.
        assert_eq!(p.route(Some("1.2.3.4"), false), Route::Opaque(Why::BadSni));
        // NoH2 before Ignored and OutOfCaScope.
        assert_eq!(p.route(Some("ign.com"), false), Route::Opaque(Why::NoH2));
        assert_eq!(p.route(Some("out.org"), false), Route::Opaque(Why::NoH2));
        // Ignored before OutOfCaScope: out.org is both ignored and out of scope.
        let q = MitmPolicy {
            ignore: IgnoreHosts::parse(["out.org"]).unwrap(),
            scope: CaScope {
                permitted: vec![dom("ok.com")],
                excluded: vec![],
            },
        };
        assert_eq!(q.route(Some("out.org"), true), Route::Opaque(Why::Ignored));
        assert_eq!(p.route(Some("ign.com"), true), Route::Opaque(Why::Ignored));
        assert_eq!(
            p.route(Some("out.org"), true),
            Route::Opaque(Why::OutOfCaScope)
        );
        assert_eq!(
            p.route(Some("WWW.OK.com."), true),
            Route::Mitm(sni("www.ok.com"))
        );
    }

    #[test]
    fn tuning_defaults_match_spec() {
        let s = Duration::from_secs;
        assert_eq!(
            MitmTuning::default(),
            MitmTuning {
                max_conns: 256,
                mstream_max: 128,
                peek: s(5),
                handshake: s(5),
                idle: s(60),
                ping_after: s(60),
                dead_after: s(90),
                closing: s(1),
                keepalive: KeepAlive {
                    idle: s(60),
                    interval: s(10),
                    count: 3,
                    user_timeout: s(90),
                },
            }
        );
    }

    fn name() -> impl Strategy<Value = String> {
        prop::collection::vec("[a-c]{1,2}", 1..5).prop_map(|l| l.join("."))
    }

    fn subtree() -> impl Strategy<Value = DnsSubtree> {
        prop_oneof![
            Just(DnsSubtree::All),
            name().prop_map(|n| dom(&n)),
            name().prop_map(|n| under(&n)),
        ]
    }

    /// Naive label-wise reference.
    fn ref_matches(t: &DnsSubtree, n: &str) -> bool {
        let nl: Vec<&str> = n.split('.').collect();
        let (c, strict) = match t {
            DnsSubtree::All => return true,
            DnsSubtree::Domain(c) => (c.as_str(), false),
            DnsSubtree::Under(c) => (c.as_str(), true),
        };
        let cl: Vec<&str> = c.split('.').collect();
        nl.len() >= cl.len()
            && nl[nl.len() - cl.len()..] == cl[..]
            && !(strict && nl.len() == cl.len())
    }

    proptest! {
        #[test]
        fn canonical_idempotent(
            b in prop_oneof![
                prop::collection::vec(any::<u8>(), 0..300),
                "[A-Za-z0-9.-]{0,40}".prop_map(String::into_bytes),
            ],
        ) {
            if let Some(s) = Sni::canonical(&b) {
                prop_assert_eq!(Sni::canonical(s.as_str().as_bytes()), Some(s));
            }
        }

        #[test]
        fn covers_matches_reference(
            n in name(),
            permitted in prop::collection::vec(subtree(), 0..3),
            excluded in prop::collection::vec(subtree(), 0..3),
        ) {
            let want = (permitted.is_empty() || permitted.iter().any(|t| ref_matches(t, &n)))
                && !excluded.iter().any(|t| ref_matches(t, &n));
            let scope = CaScope { permitted, excluded };
            prop_assert_eq!(scope.covers(&sni(&n)), want);
        }
    }
}
