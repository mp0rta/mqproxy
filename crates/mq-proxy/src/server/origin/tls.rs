//! SP3 spec §7.8: the origin client's TLS configuration — ring only, roots
//! from the native store or, with `--origin-ca`, from that PEM file **only**.

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A startup error (§7.8): no usable root store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsSetupError {
    /// The `--origin-ca` file could not be read or parsed.
    Unreadable(PathBuf),
    /// Zero certificates.
    NoCerts,
}

impl fmt::Display for TlsSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsSetupError::Unreadable(p) => write!(f, "cannot read origin CA {}", p.display()),
            TlsSetupError::NoCerts => f.write_str("no origin CA certificates"),
        }
    }
}

impl std::error::Error for TlsSetupError {}

/// Installs ring as the process default provider; a provider already
/// installed is kept (only ring is compiled in, so it is ring).
pub fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// The binary's native-root loader; load errors are logged at warn.
pub fn native_roots() -> Vec<CertificateDer<'static>> {
    let r = rustls_native_certs::load_native_certs();
    for e in &r.errors {
        log::warn!("mq_origin: native root certificates: {e}");
    }
    r.certs
}

/// spec §7.8: `native` is called only without `origin_ca`.
pub fn build_client_config(
    origin_ca: Option<&Path>,
    native: &dyn Fn() -> Vec<CertificateDer<'static>>,
) -> Result<Arc<ClientConfig>, TlsSetupError> {
    install_ring();
    let roots = roots(origin_ca, native)?;
    Ok(Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

fn roots(
    origin_ca: Option<&Path>,
    native: &dyn Fn() -> Vec<CertificateDer<'static>>,
) -> Result<RootCertStore, TlsSetupError> {
    let certs = match origin_ca {
        Some(p) => {
            let bad = || TlsSetupError::Unreadable(p.to_path_buf());
            CertificateDer::pem_file_iter(p)
                .map_err(|_| bad())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| bad())?
        }
        None => native(),
    };
    let mut store = RootCertStore::empty();
    store.add_parsable_certificates(certs);
    if store.is_empty() {
        return Err(TlsSetupError::NoCerts);
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn cert_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/certs")
            .join(name)
    }

    fn scratch(name: &str, body: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("mq-origin-tls-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn roots_from_pem_only_when_origin_ca() {
        let calls = Cell::new(0);
        let native = || {
            calls.set(calls.get() + 1);
            Vec::new()
        };
        let store = roots(Some(&cert_path("origin-ca.crt")), &native).unwrap();
        assert_eq!(store.len(), 1, "the PEM's one CA, nothing else");
        assert_eq!(calls.get(), 0, "the native loader is not called");
        install_ring();
        assert!(build_client_config(Some(&cert_path("origin-ca.crt")), &native).is_ok());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn roots_empty_pem_is_error() {
        let p = scratch("empty.pem", b"no certificate here\n");
        assert_eq!(
            roots(Some(&p), &Vec::new).err(),
            Some(TlsSetupError::NoCerts)
        );
        std::fs::remove_file(p).unwrap();
    }

    #[test]
    fn roots_unreadable_pem_is_error() {
        let p = cert_path("does-not-exist.pem");
        assert_eq!(
            roots(Some(&p), &Vec::new).err(),
            Some(TlsSetupError::Unreadable(p.clone()))
        );
    }

    #[test]
    fn roots_native_empty_is_error() {
        let calls = Cell::new(0);
        let native = || {
            calls.set(calls.get() + 1);
            Vec::new()
        };
        assert_eq!(roots(None, &native).err(), Some(TlsSetupError::NoCerts));
        assert_eq!(calls.get(), 1, "the native loader is the source");
        let ca = CertificateDer::from_pem_file(cert_path("origin-ca.crt")).unwrap();
        assert_eq!(roots(None, &|| vec![ca.clone()]).unwrap().len(), 1);
    }
}
