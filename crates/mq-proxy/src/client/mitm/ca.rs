//! SP4 spec §7.1: load and check the MITM CA.

use super::policy::{CaScope, DnsSubtree, Sni};
use rcgen::{CertificateParams, Issuer, KeyPair, PublicKeyData};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_parser::extensions::{GeneralName, GeneralSubtree};
use x509_parser::prelude::{FromDer, X509Certificate, X509Version};

/// Largest accepted cert or key file.
const FILE_MAX: u64 = 1 << 20;
/// Warn when the CA expires within this.
const EXPIRY_WARN: Duration = Duration::from_secs(30 * 86400);

/// The loaded CA. Shared by the shards as `Arc<Ca>`.
pub struct Ca {
    pub(crate) issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    pub(crate) ca_der: CertificateDer<'static>,
    pub scope: CaScope,
    pub subject: String,
    pub(crate) not_before: SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("{0}: {1}")]
    Io(String, #[source] std::io::Error),
    #[error("{0}: not a regular file")]
    NotRegular(String),
    #[error("{0}: larger than 1 MiB")]
    TooLarge(String),
    #[error("CA key file is not owned by the effective user ({0})")]
    BadOwner(String),
    #[error("CA key file is accessible by group or others (mode {0}); chmod 600 it")]
    BadMode(String),
    #[error("CA key file has no PRIVATE KEY block")]
    NoKey,
    #[error("CA key file has more than one private key block")]
    TwoKeys,
    #[error("CA key is encrypted; an unencrypted PKCS#8 key is required")]
    Encrypted,
    #[error(
        "CA key is not PKCS#8; convert with: openssl pkcs8 -topk8 -nocrypt -in <key> -out <new>"
    )]
    NotPkcs8,
    #[error("CA key: {0}")]
    BadKey(String),
    #[error("CA certificate file has no CERTIFICATE block")]
    NoCert,
    #[error("CA certificate: {0}")]
    BadCert(String),
    #[error("CA certificate is not X.509 v3")]
    NotV3,
    #[error("CA certificate lacks basicConstraints CA:TRUE")]
    NotCa,
    #[error("CA certificate keyUsage lacks keyCertSign")]
    NoKeyCertSign,
    #[error("CA certificate has expired")]
    Expired,
    #[error("CA key does not match the CA certificate")]
    KeyMismatch,
    #[error("CA nameConstraints may only hold valid dNSName and iPAddress subtrees")]
    UnsupportedConstraints,
    #[error(
        "CA subject {0:?} cannot be reproduced as a leaf issuer; use a CA without repeated attribute types"
    )]
    IssuerNotRepresentable(String),
}

impl Ca {
    pub fn load(cert: &Path, key: &Path) -> Result<Ca, CaError> {
        Self::load_at(cert, key, SystemTime::now())
    }

    pub(crate) fn load_at(cert: &Path, key: &Path, now: SystemTime) -> Result<Ca, CaError> {
        let key_pem = read_file(key, true)?;
        let cert_pem = read_file(cert, false)?;
        let key = load_key(&key_pem)?;
        let ca_der = first_cert(&cert_pem, cert)?;
        let (rest, x) =
            X509Certificate::from_der(&ca_der).map_err(|e| CaError::BadCert(e.to_string()))?;
        if !rest.is_empty() {
            return Err(CaError::BadCert(
                "trailing data after the certificate".into(),
            ));
        }
        let bad = |e: x509_parser::error::X509Error| CaError::BadCert(e.to_string());
        if x.version() != X509Version::V3 {
            return Err(CaError::NotV3);
        }
        if !x
            .basic_constraints()
            .map_err(bad)?
            .is_some_and(|b| b.value.ca)
        {
            return Err(CaError::NotCa);
        }
        if x.key_usage()
            .map_err(bad)?
            .is_some_and(|k| !k.value.key_cert_sign())
        {
            return Err(CaError::NoKeyCertSign);
        }
        let subject = x.subject().to_string();
        match unix(x.validity().not_after.timestamp()).duration_since(now) {
            Err(_) | Ok(Duration::ZERO) => return Err(CaError::Expired),
            Ok(left) if left <= EXPIRY_WARN => log::warn!(
                "mq_mitm: CA {subject:?} expires in {} day(s)",
                left.as_secs() / 86400
            ),
            Ok(_) => {}
        }
        if key.subject_public_key_info() != x.public_key().raw {
            return Err(CaError::KeyMismatch);
        }
        let scope = match x.name_constraints().map_err(bad)? {
            None => CaScope::default(),
            Some(nc) => CaScope {
                permitted: subtrees(nc.value.permitted_subtrees.as_deref())?,
                excluded: subtrees(nc.value.excluded_subtrees.as_deref())?,
            },
        };
        let not_before = unix(x.validity().not_before.timestamp());
        let subject_der = x.subject().as_raw();

        // SP4 spec §7.1: rcgen rebuilds the subject as a map, which loses
        // repeated attribute types, so forge one probe leaf and compare its
        // issuer DER with the CA's subject DER.
        let unrepresentable = || CaError::IssuerNotRepresentable(subject.clone());
        let issuer = Issuer::from_ca_cert_der(&ca_der, key).map_err(|_| unrepresentable())?;
        let probe = CertificateParams::default()
            .signed_by(issuer.key(), &issuer)
            .map_err(|e| CaError::BadKey(e.to_string()))?;
        let (_, p) = X509Certificate::from_der(probe.der()).map_err(|_| unrepresentable())?;
        if p.issuer().as_raw() != subject_der {
            return Err(unrepresentable());
        }
        Ok(Ca {
            issuer,
            ca_der,
            scope,
            subject,
            not_before,
        })
    }
}

/// The key file's ownership and mode rule (SP4 spec §7.1).
pub(crate) fn check_key_meta(mode: u32, uid: u32, euid: u32) -> Result<(), CaError> {
    if uid != euid {
        return Err(CaError::BadOwner(format!("owner uid {uid}, euid {euid}")));
    }
    if mode & 0o077 != 0 {
        return Err(CaError::BadMode(format!("{:o}", mode & 0o7777)));
    }
    Ok(())
}

/// No symlink, a regular file, at most `FILE_MAX`; for the key also the
/// owner/mode rule. Every check is on the opened fd.
fn read_file(path: &Path, key: bool) -> Result<Vec<u8>, CaError> {
    let p = || path.display().to_string();
    let io = |e| CaError::Io(p(), e);
    let f = mq_linux::open_nofollow(path).map_err(io)?;
    let m = f.metadata().map_err(io)?;
    if !m.file_type().is_file() {
        return Err(CaError::NotRegular(p()));
    }
    if m.len() > FILE_MAX {
        return Err(CaError::TooLarge(p()));
    }
    if key {
        check_key_meta(m.mode(), m.uid(), mq_linux::geteuid())?;
    }
    let mut buf = Vec::new();
    f.take(FILE_MAX + 1).read_to_end(&mut buf).map_err(io)?;
    if buf.len() as u64 > FILE_MAX {
        return Err(CaError::TooLarge(p()));
    }
    Ok(buf)
}

/// Every `-----BEGIN <label>-----` label, split into lines as the
/// rustls-pki-types decoder does (at CR or LF).
fn pem_labels(b: &[u8]) -> Vec<&[u8]> {
    b.split(|&c| c == b'\n' || c == b'\r')
        .filter_map(|l| {
            l.strip_prefix(b"-----BEGIN ")?
                .trim_ascii_end()
                .strip_suffix(b"-----")
        })
        .collect()
}

/// Exactly one key block, and it is an unencrypted PKCS#8 `PRIVATE KEY`.
fn load_key(pem: &[u8]) -> Result<KeyPair, CaError> {
    let keys: Vec<&[u8]> = pem_labels(pem)
        .into_iter()
        .filter(|l| l.ends_with(b"PRIVATE KEY"))
        .collect();
    match keys[..] {
        [] => return Err(CaError::NoKey),
        [b"PRIVATE KEY"] => {}
        [b"ENCRYPTED PRIVATE KEY"] => return Err(CaError::Encrypted),
        [b"RSA PRIVATE KEY" | b"EC PRIVATE KEY"] => return Err(CaError::NotPkcs8),
        [other] => {
            let l = String::from_utf8_lossy(other);
            return Err(CaError::BadKey(format!("unsupported block {l:?}")));
        }
        _ => return Err(CaError::TwoKeys),
    }
    let der =
        PrivatePkcs8KeyDer::from_pem_slice(pem).map_err(|e| CaError::BadKey(e.to_string()))?;
    KeyPair::try_from(&der).map_err(|e| CaError::BadKey(e.to_string()))
}

/// The first `CERTIFICATE` block; further ones are ignored with a warning.
fn first_cert(pem: &[u8], path: &Path) -> Result<CertificateDer<'static>, CaError> {
    let n = pem_labels(pem)
        .into_iter()
        .filter(|l| *l == b"CERTIFICATE")
        .count();
    if n == 0 {
        return Err(CaError::NoCert);
    }
    if n > 1 {
        log::warn!(
            "mq_mitm: {}: {} extra certificate block(s) ignored; the first is the CA",
            path.display(),
            n - 1
        );
    }
    CertificateDer::from_pem_slice(pem).map_err(|e| CaError::BadCert(e.to_string()))
}

/// NameConstraints subtrees → dNSName scope (SP4 spec §7.1, D9). iPAddress
/// is ignored (an SNI is never an IP); any other type, or a dNSName that is
/// not a canonical host name, is unsupported.
fn subtrees(t: Option<&[GeneralSubtree<'_>]>) -> Result<Vec<DnsSubtree>, CaError> {
    let mut out = Vec::new();
    for s in t.unwrap_or_default() {
        match s.base {
            GeneralName::IPAddress(_) => {}
            GeneralName::DNSName("") => out.push(DnsSubtree::All),
            GeneralName::DNSName(d) => {
                let (under, host) = match d.strip_prefix('.') {
                    Some(h) => (true, h),
                    None => (false, d),
                };
                let sni = Sni::canonical(host.as_bytes()).ok_or(CaError::UnsupportedConstraints)?;
                out.push(if under {
                    DnsSubtree::Under(sni)
                } else {
                    DnsSubtree::Domain(sni)
                });
            }
            _ => return Err(CaError::UnsupportedConstraints),
        }
    }
    Ok(out)
}

fn unix(t: i64) -> SystemTime {
    let d = Duration::from_secs(t.unsigned_abs());
    if t < 0 {
        UNIX_EPOCH - d
    } else {
        UNIX_EPOCH + d
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::mitm::policy::{DnsSubtree, Sni};
    use mq_runtime::testing::log_capture;
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, UNIX_EPOCH};
    use x509_parser::prelude::{FromDer, X509Certificate};

    const HINT: &str = "convert with: openssl pkcs8 -topk8 -nocrypt -in <key> -out <new>";

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/certs/rust-mitm")
    }

    /// A fresh dir under the temp dir holding copies of `files`; keys are 0600.
    pub(crate) fn stage(test: &str, files: &[&str]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mq-ca-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for f in files {
            let to = d.join(f);
            std::fs::copy(fixtures().join(f), &to).unwrap();
            std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        d
    }

    fn load(test: &str, cert: &str, key: &str) -> Result<Ca, CaError> {
        let d = stage(test, &[cert, key]);
        Ca::load(&d.join(cert), &d.join(key))
    }

    fn not_after(cert: &str) -> SystemTime {
        let pem = std::fs::read(fixtures().join(cert)).unwrap();
        let der = {
            use rustls_pki_types::pem::PemObject;
            CertificateDer::from_pem_slice(&pem).unwrap()
        };
        let (_, x) = X509Certificate::from_der(&der).unwrap();
        UNIX_EPOCH + Duration::from_secs(x.validity().not_after.timestamp() as u64)
    }

    #[test]
    fn symlinked_key_rejected() {
        let d = stage("symlink", &["ca-p256.crt", "ca-p256.key"]);
        std::os::unix::fs::symlink(d.join("ca-p256.key"), d.join("link.key")).unwrap();
        match Ca::load(&d.join("ca-p256.crt"), &d.join("link.key")) {
            Err(CaError::Io(p, e)) => {
                assert!(p.ends_with("link.key"), "{p}");
                assert_eq!(e.raw_os_error(), Some(40)); // ELOOP
            }
            other => panic!("{:?}", other.err()),
        }
    }

    #[test]
    fn non_regular_rejected() {
        let d = stage("nonreg", &["ca-p256.crt"]);
        std::fs::create_dir(d.join("dir.key")).unwrap();
        assert!(matches!(
            Ca::load(&d.join("ca-p256.crt"), &d.join("dir.key")),
            Err(CaError::NotRegular(p)) if p.ends_with("dir.key")
        ));
    }

    #[test]
    fn over_1mib_rejected() {
        let d = stage("big", &["ca-p256.crt", "ca-p256.key"]);
        let big = std::fs::OpenOptions::new()
            .append(true)
            .open(d.join("ca-p256.crt"))
            .unwrap();
        big.set_len((1 << 20) + 1).unwrap();
        assert!(matches!(
            Ca::load(&d.join("ca-p256.crt"), &d.join("ca-p256.key")),
            Err(CaError::TooLarge(p)) if p.ends_with("ca-p256.crt")
        ));
    }

    #[test]
    fn check_key_meta_wrong_owner() {
        assert!(matches!(
            check_key_meta(0o100600, 1001, 1000),
            Err(CaError::BadOwner(_))
        ));
    }

    #[test]
    fn check_key_meta_group_bits() {
        for mode in [0o100640, 0o100604, 0o100610, 0o100601, 0o100660] {
            assert!(
                matches!(check_key_meta(mode, 1000, 1000), Err(CaError::BadMode(_))),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn check_key_meta_ok() {
        for mode in [0o100600, 0o100400, 0o100700] {
            assert!(check_key_meta(mode, 1000, 1000).is_ok(), "{mode:o}");
        }
    }

    #[test]
    fn key_mode_checked_on_load() {
        let d = stage("mode", &["ca-p256.crt", "ca-p256.key"]);
        let k = d.join("ca-p256.key");
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            Ca::load(&d.join("ca-p256.crt"), &k),
            Err(CaError::BadMode(_))
        ));
    }

    fn assert_not_pkcs8(key: &str, test: &str) {
        let e = load(test, "ca-p256.crt", key).err().unwrap();
        assert!(matches!(e, CaError::NotPkcs8), "{e:?}");
        assert!(e.to_string().ends_with(HINT), "{e}");
    }

    #[test]
    fn pkcs1_key_not_pkcs8_with_exact_hint() {
        assert_not_pkcs8("key-rsa-pkcs1.pem", "pkcs1");
    }

    #[test]
    fn sec1_key_not_pkcs8_with_exact_hint() {
        assert_not_pkcs8("key-ec-sec1.pem", "sec1");
    }

    #[test]
    fn encrypted_label_detected() {
        assert!(matches!(
            load("enc", "ca-p256.crt", "key-encrypted-pkcs8.pem"),
            Err(CaError::Encrypted)
        ));
    }

    #[test]
    fn two_key_blocks_rejected() {
        assert!(matches!(
            load("two", "ca-p256.crt", "two-keys.pem"),
            Err(CaError::TwoKeys)
        ));
        // A cert file is not a key file: no key block.
        assert!(matches!(
            load("nokey", "ca-p256.crt", "ca-p384.crt"),
            Err(CaError::NoKey)
        ));
    }

    #[test]
    fn v1_cert_rejected() {
        assert!(matches!(
            load("v1", "cert-v1.crt", "ca-p256.key"),
            Err(CaError::NotV3)
        ));
    }

    #[test]
    fn ca_false_rejected() {
        assert!(matches!(
            load("cafalse", "cert-ca-false.crt", "ca-p256.key"),
            Err(CaError::NotCa)
        ));
    }

    #[test]
    fn key_usage_without_cert_sign_rejected() {
        assert!(matches!(
            load("noks", "cert-no-keycertsign.crt", "ca-p256.key"),
            Err(CaError::NoKeyCertSign)
        ));
    }

    #[test]
    fn mismatched_key_rejected() {
        assert!(matches!(
            load("mismatch", "ca-p256.crt", "ca-p384.key"),
            Err(CaError::KeyMismatch)
        ));
        // Same algorithm, different key.
        assert!(matches!(
            load("mismatch2", "ca-p256.crt", "ca-expiring.key"),
            Err(CaError::KeyMismatch)
        ));
        // And no cert block at all.
        assert!(matches!(
            load("nocert", "ca-p256.key", "ca-p384.key"),
            Err(CaError::NoCert)
        ));
    }

    #[test]
    fn uri_constraint_unsupported() {
        assert!(matches!(
            load("uri", "ca-uri-constraint.crt", "ca-uri-constraint.key"),
            Err(CaError::UnsupportedConstraints)
        ));
    }

    #[test]
    fn expiring_ca_warns() {
        log_capture::install();
        log_capture::take();
        let d = stage("expiring", &["ca-expiring.crt", "ca-expiring.key"]);
        let now = not_after("ca-expiring.crt") - Duration::from_secs(5 * 86400);
        let ca = Ca::load_at(&d.join("ca-expiring.crt"), &d.join("ca-expiring.key"), now);
        assert!(ca.is_ok(), "{:?}", ca.err());
        let lines = log_capture::take();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("WARN") && l.contains("expires")),
            "{lines:?}"
        );
        // More than 30 days out: no warning.
        let now = not_after("ca-expiring.crt") - Duration::from_secs(31 * 86400);
        Ca::load_at(&d.join("ca-expiring.crt"), &d.join("ca-expiring.key"), now).unwrap();
        assert!(!log_capture::take().iter().any(|l| l.contains("expires")));
    }

    #[test]
    fn expired_ca_rejected() {
        let d = stage("expired", &["ca-expiring.crt", "ca-expiring.key"]);
        let at = not_after("ca-expiring.crt");
        for now in [at, at + Duration::from_secs(1)] {
            assert!(matches!(
                Ca::load_at(&d.join("ca-expiring.crt"), &d.join("ca-expiring.key"), now),
                Err(CaError::Expired)
            ));
        }
    }

    #[test]
    fn repeated_ou_issuer_not_representable() {
        match load("repou", "ca-repeated-ou.crt", "ca-repeated-ou.key") {
            Err(CaError::IssuerNotRepresentable(s)) => assert!(s.contains("OU=two"), "{s}"),
            other => panic!("{:?}", other.err()),
        }
    }

    /// Forges a leaf for `host` the way the leaf store will, and verifies it
    /// with webpki against the CA as the only anchor.
    fn webpki_verify(ca: &Ca, host: &str) -> Result<(), webpki::Error> {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![host.to_string()]).unwrap();
        p.insert_extended_key_usage(ExtendedKeyUsagePurpose::ServerAuth);
        p.use_authority_key_identifier_extension = true;
        let leaf = p.signed_by(&key, &ca.issuer).unwrap();
        let anchor = webpki::anchor_from_trusted_cert(&ca.ca_der).unwrap();
        let ee = webpki::EndEntityCert::try_from(leaf.der()).unwrap();
        let now = rustls_pki_types::UnixTime::now();
        ee.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &[anchor],
            &[],
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;
        let name = rustls_pki_types::ServerName::try_from(host).unwrap();
        ee.verify_is_valid_for_subject_name(&name)
    }

    #[test]
    fn loads_p256_p384_ed25519_rsa2048() {
        for n in ["ca-p256", "ca-p384", "ca-ed25519", "ca-rsa2048"] {
            let (c, k) = (format!("{n}.crt"), format!("{n}.key"));
            let ca = load(n, &c, &k).unwrap_or_else(|e| panic!("{n}: {e}"));
            assert_eq!(ca.subject, format!("CN=mqproxy test {n}"));
            assert_eq!(ca.scope, CaScope::default());
            assert!(ca.not_before < SystemTime::now());
            webpki_verify(&ca, "www.example.com").unwrap_or_else(|e| panic!("{n}: {e:?}"));
        }
    }

    fn sni(s: &str) -> Sni {
        Sni::canonical(s.as_bytes()).unwrap()
    }

    #[test]
    fn dns_constraints_parsed_into_scope() {
        let ca = load("dns", "ca-dns-constraint.crt", "ca-dns-constraint.key").unwrap();
        // The iPAddress subtree is ignored.
        assert_eq!(
            ca.scope,
            CaScope {
                permitted: vec![DnsSubtree::Under(sni("example.com"))],
                excluded: vec![DnsSubtree::Domain(sni("bad.example.com"))],
            }
        );
    }

    #[test]
    fn empty_permitted_is_all() {
        let ca = load("emptyp", "ca-empty-permitted.crt", "ca-empty-permitted.key").unwrap();
        assert_eq!(ca.scope.permitted, vec![DnsSubtree::All]);
        assert!(ca.scope.covers(&sni("anything.test")));
        webpki_verify(&ca, "anything.test").unwrap();
    }

    #[test]
    fn empty_excluded_is_all() {
        let ca = load("emptyx", "ca-empty-excluded.crt", "ca-empty-excluded.key").unwrap();
        assert_eq!(ca.scope.excluded, vec![DnsSubtree::All]);
        assert!(!ca.scope.covers(&sni("anything.test")));
        assert!(matches!(
            webpki_verify(&ca, "anything.test"),
            Err(webpki::Error::NameConstraintViolation)
        ));
    }

    #[test]
    fn extra_cert_blocks_warned_first_used() {
        log_capture::install();
        log_capture::take();
        let ca = load("extra", "ca-plus-extra.crt", "ca-p256.key").unwrap();
        assert_eq!(ca.subject, "CN=mqproxy test ca-p256");
        let lines = log_capture::take();
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("WARN") && l.contains("ca-plus-extra.crt")),
            "{lines:?}"
        );
    }
}
