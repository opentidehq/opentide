//! TLS for one tenant: rustls on ring, verifying or not as the tenant says.
//!
//! With verification on, a tenant trusts the system's certificates
//! (rustls-native-certs), the CA bundles the environment names
//! (`SSL_CERT_FILE`, which Python's `urllib` reads, and `REQUESTS_CA_BUNDLE`
//! and `CURL_CA_BUNDLE`, which `requests` reads: a corporate proxy's CA, as
//! in the agent proxy), and its own CA bundle when its settings name one.
//! With verification off (`ssl = false`), any certificate is accepted, as
//! `requests` does with `verify=False`, and an exported bundle does not turn
//! it back on (psf/requests#3829, the reason `TenantSession` exists).

#[cfg(not(target_os = "wasi"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(target_os = "wasi"))]
use std::sync::{Arc, OnceLock};

#[cfg(not(target_os = "wasi"))]
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(not(target_os = "wasi"))]
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
#[cfg(not(target_os = "wasi"))]
use rustls::pki_types::pem::PemObject;
#[cfg(not(target_os = "wasi"))]
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(not(target_os = "wasi"))]
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::Environment;

/// The variables that name a CA bundle, in the order they are read.
pub const CA_BUNDLE_VARIABLES: [&str; 3] =
    ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"];

/// A tenant's TLS settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsSettings {
    /// Verify the tenant's certificate (`ssl`, true by default).
    pub verify: bool,
    /// A CA bundle (PEM) this tenant trusts besides the system's.
    pub ca_bundle: Option<PathBuf>,
}

impl Default for TlsSettings {
    fn default() -> Self {
        Self {
            verify: true,
            ca_bundle: None,
        }
    }
}

#[cfg(not(target_os = "wasi"))]
/// The crypto provider every client uses: ring.
pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

#[cfg(not(target_os = "wasi"))]
/// The system's root certificates, read once per process.
fn native_roots() -> &'static [CertificateDer<'static>] {
    static ROOTS: OnceLock<Vec<CertificateDer<'static>>> = OnceLock::new();
    ROOTS.get_or_init(|| rustls_native_certs::load_native_certs().certs)
}

#[cfg(not(target_os = "wasi"))]
/// The certificates of the PEM bundle at *path*.
pub fn read_bundle(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_file_iter(path)
        .map_err(|error| format!("cannot read the CA bundle {}: {error}", path.display()))?
        .collect();
    let certs =
        certs.map_err(|error| format!("cannot read the CA bundle {}: {error}", path.display()))?;
    if certs.is_empty() {
        return Err(format!(
            "the CA bundle {} holds no certificate",
            path.display()
        ));
    }
    Ok(certs)
}

/// The CA bundles *settings* and *env* name, in order, each once.
pub fn bundles(settings: &TlsSettings, env: &Environment) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let named = CA_BUNDLE_VARIABLES
        .iter()
        .filter_map(|name| env.get(name))
        .map(PathBuf::from)
        .chain(settings.ca_bundle.clone());
    for path in named {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

#[cfg(not(target_os = "wasi"))]
/// The rustls configuration of one tenant.
///
/// An environment bundle that cannot be read is skipped, as a client that
/// does not need it would not notice it; the tenant's own bundle is an
/// error.
pub fn client_config(settings: &TlsSettings, env: &Environment) -> Result<ClientConfig, String> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?;
    if !settings.verify {
        let verifier = AcceptAny {
            algorithms: provider.signature_verification_algorithms,
        };
        return Ok(builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth());
    }
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(native_roots().iter().cloned());
    for path in bundles(settings, env) {
        let own = settings.ca_bundle.as_ref() == Some(&path);
        match read_bundle(&path) {
            Ok(certs) => {
                roots.add_parsable_certificates(certs);
            }
            Err(message) if own => return Err(message),
            Err(_) => {}
        }
    }
    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

#[cfg(not(target_os = "wasi"))]
/// Accepts any certificate; checks the handshake's signatures still.
#[derive(Debug)]
struct AcceptAny {
    algorithms: WebPkiSupportedAlgorithms,
}

#[cfg(not(target_os = "wasi"))]
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
