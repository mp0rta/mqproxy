// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqproxy contributors
//! SP4 spec §7.2: per-SNI forged leaves and their rustls `ServerConfig`s.

use super::ca::Ca;
use super::policy::Sni;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Cached leaves per shard; also the size of the shared session cache.
const LEAF_CAP: usize = 256;
/// Leaf lifetime from the forge time.
const TTL: Duration = Duration::from_secs(24 * 3600);
/// `not_before = now − BACKDATE`, for clients whose clock is a little behind.
const BACKDATE: Duration = Duration::from_secs(3600);
/// A cached leaf is re-forged this long before its `not_after`.
const REFORGE: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ForgeError {
    #[error("forging the leaf: {0}")]
    Cert(#[from] rcgen::Error),
    #[error("building the leaf's TLS config: {0}")]
    Tls(#[from] rustls::Error),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeafStats {
    pub hit: u64,
    pub miss: u64,
}

/// Shard-local: forged leaves for one CA, cached as ready `ServerConfig`s.
pub struct LeafStore {
    ca: Arc<Ca>,
    /// P-256, generated at start and shared by every leaf.
    leaf_key: KeyPair,
    /// ring: builds every config and draws the serials.
    provider: Arc<CryptoProvider>,
    /// One session cache shared by all configs. Safe: rustls never resumes a
    /// session under a different SNI (`server/hs.rs` `can_resume`).
    sessions: Arc<dyn StoresServerSessions>,
    cache: HashMap<Sni, Entry>,
    tick: u64,
    stats: LeafStats,
    clock: fn() -> SystemTime,
    clock_warned: bool,
}

struct Entry {
    cfg: Arc<ServerConfig>,
    not_before: SystemTime,
    not_after: SystemTime,
    used: u64,
}

impl LeafStore {
    /// # Panics
    /// If generating the shard's P-256 leaf key fails.
    pub fn new(ca: Arc<Ca>, clock: fn() -> SystemTime) -> Self {
        Self {
            ca,
            leaf_key: KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .expect("P-256 key generation"),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            sessions: ServerSessionMemoryCache::new(LEAF_CAP),
            cache: HashMap::new(),
            tick: 0,
            stats: LeafStats::default(),
            clock,
            clock_warned: false,
        }
    }

    /// The cached config for `sni`, or a freshly forged one (SP4 spec §7.2).
    pub fn config_for(&mut self, sni: &Sni) -> Result<Arc<ServerConfig>, ForgeError> {
        let now = (self.clock)();
        self.tick += 1;
        // A hit is `not_before ≤ now < not_after − 30 s`; the lower bound also
        // catches a clock that moved back after the forge.
        if let Some(e) = self.cache.get_mut(sni)
            && e.not_before <= now
            && now < e.not_after - REFORGE
        {
            e.used = self.tick;
            self.stats.hit += 1;
            return Ok(e.cfg.clone());
        }
        self.stats.miss += 1;
        let leaf = self.forge(sni, now)?;
        let cfg = self.server_config(leaf)?;
        if self.cache.len() >= LEAF_CAP && !self.cache.contains_key(sni) {
            // ponytail: O(256) scan for the least recently used entry, run only
            // on a miss with a full map; switch to an intrusive LRU if misses
            // show up in a profile.
            let lru = self.cache.iter().min_by_key(|(_, e)| e.used);
            if let Some(k) = lru.map(|(k, _)| k.clone()) {
                self.cache.remove(&k);
            }
        }
        let entry = Entry {
            cfg: cfg.clone(),
            not_before: now - BACKDATE,
            not_after: now + TTL,
            used: self.tick,
        };
        self.cache.insert(sni.clone(), entry);
        Ok(cfg)
    }

    pub fn stats(&self) -> LeafStats {
        self.stats
    }

    /// One leaf for `sni`, signed by the CA, valid `now − 1 h .. now + 24 h`.
    fn forge(&mut self, sni: &Sni, now: SystemTime) -> Result<CertificateDer<'static>, ForgeError> {
        if now < self.ca.not_before && !self.clock_warned {
            self.clock_warned = true;
            log::warn!(
                "mq_mitm: clock is before CA {:?} notBefore; leaves fail until it is set (NTP?)",
                self.ca.subject
            );
        }
        let mut p = CertificateParams::new(vec![sni.as_str().to_owned()])?;
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name
            .push(DnType::CommonName, "mqproxy-mitm");
        // Random, not rcgen's default: that hashes the public key, which every
        // leaf shares. The top bit set keeps it a non-zero 64-bit magnitude.
        let mut serial = [0u8; 8];
        self.provider
            .secure_random
            .fill(&mut serial)
            .map_err(rustls::Error::from)?;
        serial[0] |= 0x80;
        p.serial_number = Some(SerialNumber::from_slice(&serial));
        p.not_before = (now - BACKDATE).into();
        p.not_after = (now + TTL).into();
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        Ok(p.signed_by(&self.leaf_key, &self.ca.issuer)?.der().clone())
    }

    /// ring, TLS 1.2 + 1.3, no client auth, chain = leaf + CA, ALPN `h2` only,
    /// the shared session cache.
    fn server_config(
        &self,
        leaf: CertificateDer<'static>,
    ) -> Result<Arc<ServerConfig>, ForgeError> {
        let key = PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der());
        let mut cfg = ServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_no_client_auth()
            .with_single_cert(vec![leaf, self.ca.ca_der.clone()], key.into())?;
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        cfg.session_storage = self.sessions.clone();
        Ok(Arc::new(cfg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::mitm::ca::tests::stage;
    use mq_runtime::testing::log_capture;
    use rustls::{
        ClientConfig, Connection, RootCertStore, ServerConnection, SupportedProtocolVersion,
    };
    use rustls_pki_types::{ServerName, UnixTime};
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::UNIX_EPOCH;
    use x509_parser::extensions::GeneralName;
    use x509_parser::oid_registry::OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER;
    use x509_parser::prelude::{FromDer, X509Certificate};

    /// 2027-01-15, after every fixture CA's notBefore.
    const T0: u64 = 1_800_000_000;

    thread_local! {
        static NOW: Cell<SystemTime> = const { Cell::new(UNIX_EPOCH) };
    }
    fn fake() -> SystemTime {
        NOW.with(Cell::get)
    }
    /// Sets the fake clock to `T0 + secs`.
    fn set(secs: i64) -> SystemTime {
        let t = UNIX_EPOCH + Duration::from_secs(T0.checked_add_signed(secs).unwrap());
        NOW.with(|c| c.set(t));
        t
    }

    fn load_ca(name: &str) -> Arc<Ca> {
        static N: AtomicUsize = AtomicUsize::new(0);
        let (c, k) = (format!("{name}.crt"), format!("{name}.key"));
        let d = stage(
            &format!("leaf{}", N.fetch_add(1, Ordering::Relaxed)),
            &[&c, &k],
        );
        let ca = Ca::load(&d.join(&c), &d.join(&k)).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        Arc::new(ca)
    }

    fn sni(s: &str) -> Sni {
        Sni::canonical(s.as_bytes()).unwrap()
    }

    /// webpki: `leaf` chains to `ca` alone at `now`, for serverAuth and `host`.
    fn verify(
        ca: &Ca,
        leaf: &CertificateDer<'_>,
        host: &str,
        now: SystemTime,
    ) -> Result<(), webpki::Error> {
        let anchor = webpki::anchor_from_trusted_cert(&ca.ca_der).unwrap();
        let ee = webpki::EndEntityCert::try_from(leaf).unwrap();
        let now = UnixTime::since_unix_epoch(now.duration_since(UNIX_EPOCH).unwrap());
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &[],
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;
        ee.verify_is_valid_for_subject_name(&ServerName::try_from(host).unwrap())
    }

    fn transfer(from: &mut Connection, to: &mut Connection) {
        let mut b = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut b).unwrap();
        }
        let mut rd = &b[..];
        while !rd.is_empty() {
            to.read_tls(&mut rd).unwrap();
            to.process_new_packets().unwrap();
        }
    }

    /// An in-memory handshake from a rustls client that trusts only `ca` and
    /// offers ALPN `http/1.1, h2`; returns the client side.
    fn handshake(
        cfg: Arc<ServerConfig>,
        ca: &Ca,
        host: &str,
        v: &'static SupportedProtocolVersion,
    ) -> Connection {
        let mut roots = RootCertStore::empty();
        roots.add(ca.ca_der.clone()).unwrap();
        let mut cc =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[v])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        cc.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
        let name = ServerName::try_from(host.to_owned()).unwrap();
        let mut c = Connection::from(rustls::ClientConnection::new(Arc::new(cc), name).unwrap());
        let mut s = Connection::from(ServerConnection::new(cfg).unwrap());
        for _ in 0..10 {
            if !c.is_handshaking() && !s.is_handshaking() {
                return c;
            }
            transfer(&mut c, &mut s);
            transfer(&mut s, &mut c);
        }
        panic!("handshake did not finish");
    }

    fn parse<'a>(der: &'a CertificateDer<'_>) -> X509Certificate<'a> {
        X509Certificate::from_der(der).unwrap().1
    }

    #[test]
    fn forged_chain_verifies_with_webpki() {
        let ca = load_ca("ca-p256");
        let mut s = LeafStore::new(ca.clone(), SystemTime::now);
        let cfg = s.config_for(&sni("www.example.com")).unwrap();
        for v in [&rustls::version::TLS13, &rustls::version::TLS12] {
            let c = handshake(cfg.clone(), &ca, "www.example.com", v);
            assert_eq!(c.protocol_version(), Some(v.version));
            // Chain = leaf + CA (SP4 spec §7.2).
            let chain = c.peer_certificates().unwrap();
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[1], ca.ca_der);
            let now = SystemTime::now();
            verify(&ca, &chain[0], "www.example.com", now).unwrap();
            assert!(verify(&ca, &chain[0], "other.example.com", now).is_err());

            let x = parse(&chain[0]);
            assert_eq!(x.subject().to_string(), "CN=mqproxy-mitm");
            let san = x.subject_alternative_name().unwrap().unwrap();
            assert_eq!(
                san.value.general_names,
                vec![GeneralName::DNSName("www.example.com")]
            );
            let eku = x.extended_key_usage().unwrap().unwrap().value;
            assert!(eku.server_auth && !eku.client_auth && !eku.any);
            let bc = x.basic_constraints().unwrap().unwrap();
            assert!(bc.critical && !bc.value.ca);
            let ku = x.key_usage().unwrap().unwrap();
            assert!(ku.critical && ku.value.digital_signature() && !ku.value.key_cert_sign());
            assert!(
                x.extensions()
                    .iter()
                    .any(|e| e.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
            );
        }
    }

    #[test]
    fn validity_window_minus1h_plus24h() {
        let ca = load_ca("ca-p256");
        let mut s = LeafStore::new(ca, fake);
        let now = set(0);
        let leaf = s.forge(&sni("a.test"), now).unwrap();
        let v = parse(&leaf).validity().clone();
        assert_eq!(v.not_before.timestamp(), T0 as i64 - 3600);
        assert_eq!(v.not_after.timestamp(), T0 as i64 + 24 * 3600);
    }

    #[test]
    fn serials_unique() {
        let ca = load_ca("ca-p256");
        let mut s = LeafStore::new(ca, fake);
        let now = set(0);
        let mut seen = HashSet::new();
        for i in 0..32 {
            // Same key for every leaf, and the same SNI for half of them.
            let leaf = s.forge(&sni(&format!("h{}.test", i % 2)), now).unwrap();
            let serial = parse(&leaf).serial.clone();
            assert_eq!(serial.bits(), 64, "64-bit positive serial");
            assert!(seen.insert(serial));
        }
    }

    #[test]
    fn hit_returns_same_arc() {
        let mut s = LeafStore::new(load_ca("ca-p256"), fake);
        set(0);
        let a = s.config_for(&sni("a.test")).unwrap();
        set(3600);
        let b = s.config_for(&sni("a.test")).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(s.stats(), LeafStats { hit: 1, miss: 1 });
    }

    #[test]
    fn reforge_30s_before_not_after() {
        let mut s = LeafStore::new(load_ca("ca-p256"), fake);
        set(0);
        let a = s.config_for(&sni("a.test")).unwrap();
        set(24 * 3600 - 31);
        assert!(Arc::ptr_eq(&a, &s.config_for(&sni("a.test")).unwrap()));
        set(24 * 3600 - 30);
        let b = s.config_for(&sni("a.test")).unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(s.stats(), LeafStats { hit: 1, miss: 2 });
        // The re-forged entry replaced the old one.
        assert_eq!(s.cache.len(), 1);
        assert!(Arc::ptr_eq(&b, &s.config_for(&sni("a.test")).unwrap()));
    }

    #[test]
    fn reforge_when_clock_before_not_before() {
        let mut s = LeafStore::new(load_ca("ca-p256"), fake);
        set(0);
        let a = s.config_for(&sni("a.test")).unwrap();
        // not_before = T0 − 1 h is still inside the window.
        set(-3600);
        assert!(Arc::ptr_eq(&a, &s.config_for(&sni("a.test")).unwrap()));
        // The clock moved back past it.
        set(-3601);
        assert!(!Arc::ptr_eq(&a, &s.config_for(&sni("a.test")).unwrap()));
        assert_eq!(s.stats(), LeafStats { hit: 1, miss: 2 });
    }

    #[test]
    fn churn_257_hosts_evicts_lru() {
        let mut s = LeafStore::new(load_ca("ca-p256"), fake);
        set(0);
        let host = |i: usize| sni(&format!("h{i}.test"));
        for i in 0..256 {
            s.config_for(&host(i)).unwrap();
        }
        // h0 is recently used again, so h1 is now the least recently used.
        s.config_for(&host(0)).unwrap();
        s.config_for(&host(256)).unwrap();
        assert_eq!(s.cache.len(), 256);
        assert_eq!(s.stats(), LeafStats { hit: 1, miss: 257 });
        s.config_for(&host(0)).unwrap();
        s.config_for(&host(256)).unwrap();
        assert_eq!(s.stats(), LeafStats { hit: 3, miss: 257 });
        s.config_for(&host(1)).unwrap();
        assert_eq!(s.stats(), LeafStats { hit: 3, miss: 258 });
        assert_eq!(s.cache.len(), 256);
    }

    #[test]
    fn canonical_variants_share_leaf() {
        let mut s = LeafStore::new(load_ca("ca-p256"), fake);
        set(0);
        let a = s.config_for(&sni("WWW.Example.COM.")).unwrap();
        let b = s.config_for(&sni("www.example.com")).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(s.stats(), LeafStats { hit: 1, miss: 1 });
    }

    #[test]
    fn session_storage_shared() {
        let mut s = LeafStore::new(load_ca("ca-p256"), fake);
        set(0);
        let a = s.config_for(&sni("a.test")).unwrap();
        let b = s.config_for(&sni("b.test")).unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(&a.session_storage, &b.session_storage));
        assert!(Arc::ptr_eq(&a.session_storage, &s.sessions));
    }

    #[test]
    fn alpn_is_h2_only() {
        let ca = load_ca("ca-p256");
        let mut s = LeafStore::new(ca.clone(), SystemTime::now);
        let cfg = s.config_for(&sni("a.test")).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
        // The client prefers http/1.1; the server still picks h2.
        let c = handshake(cfg, &ca, "a.test", &rustls::version::TLS13);
        assert_eq!(c.alpn_protocol(), Some(&b"h2"[..]));
    }

    #[test]
    fn dns_constrained_ca_leaf_in_scope_verifies() {
        // permitted .example.com, excluded bad.example.com.
        let ca = load_ca("ca-dns-constraint");
        let mut s = LeafStore::new(ca.clone(), SystemTime::now);
        let now = SystemTime::now();
        let ok = sni("www.example.com");
        assert!(ca.scope.covers(&ok));
        let leaf = s.forge(&ok, now).unwrap();
        verify(&ca, &leaf, "www.example.com", now).unwrap();
        // Out of scope: the policy sends it opaque, and webpki agrees.
        let bad = sni("bad.example.com");
        assert!(!ca.scope.covers(&bad));
        let leaf = s.forge(&bad, now).unwrap();
        assert!(matches!(
            verify(&ca, &leaf, "bad.example.com", now),
            Err(webpki::Error::NameConstraintViolation)
        ));
    }

    #[test]
    fn empty_permitted_ca_leaf_verifies() {
        let ca = load_ca("ca-empty-permitted");
        let mut s = LeafStore::new(ca.clone(), SystemTime::now);
        let now = SystemTime::now();
        let host = sni("anything.test");
        assert!(ca.scope.covers(&host));
        let leaf = s.forge(&host, now).unwrap();
        verify(&ca, &leaf, "anything.test", now).unwrap();
    }

    #[test]
    fn empty_excluded_ca_scope_covers_nothing() {
        let ca = load_ca("ca-empty-excluded");
        let mut s = LeafStore::new(ca.clone(), SystemTime::now);
        let now = SystemTime::now();
        for h in ["anything.test", "www.example.com"] {
            assert!(!ca.scope.covers(&sni(h)));
            let leaf = s.forge(&sni(h), now).unwrap();
            assert!(matches!(
                verify(&ca, &leaf, h, now),
                Err(webpki::Error::NameConstraintViolation)
            ));
        }
    }

    #[test]
    fn clock_before_ca_not_before_warns_once() {
        log_capture::install();
        log_capture::take();
        let mut s = LeafStore::new(load_ca("ca-p256"), fake);
        // 2001: before the fixture CA's notBefore.
        NOW.with(|c| c.set(UNIX_EPOCH + Duration::from_secs(1_000_000_000)));
        s.config_for(&sni("a.test")).unwrap();
        s.config_for(&sni("b.test")).unwrap();
        let warns = log_capture::take()
            .into_iter()
            .filter(|l| l.starts_with("WARN") && l.contains("notBefore"))
            .count();
        assert_eq!(warns, 1);
    }
}
