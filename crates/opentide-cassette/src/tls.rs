//! A certificate authority made for one run: it signs a certificate for each
//! host the proxy stands in for, and the client under test trusts it through
//! a CA bundle file (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// The run's certificate authority.
pub struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
    der: CertificateDer<'static>,
    configs: Mutex<BTreeMap<String, Arc<ServerConfig>>>,
}

impl std::fmt::Debug for TestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCa").finish_non_exhaustive()
    }
}

impl TestCa {
    /// A new authority, with a key of its own.
    pub fn new() -> Result<Self, String> {
        let key = KeyPair::generate().map_err(|error| error.to_string())?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "opentide cassette CA");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params
            .self_signed(&key)
            .map_err(|error| error.to_string())?;
        let pem = cert.pem();
        let der = cert.der().clone();
        Ok(Self {
            issuer: Issuer::new(params, key),
            pem,
            der,
            configs: Mutex::new(BTreeMap::new()),
        })
    }

    /// The authority's certificate, PEM.
    pub fn pem(&self) -> &str {
        &self.pem
    }

    /// The authority's certificate, DER.
    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    /// A server configuration presenting a certificate for *host*, signed
    /// by this authority; one per host, made on first use.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let mut configs = self
            .configs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(config) = configs.get(host) {
            return Ok(config.clone());
        }
        let key = KeyPair::generate().map_err(|error| error.to_string())?;
        let mut params =
            CertificateParams::new(vec![host.to_owned()]).map_err(|error| error.to_string())?;
        params.distinguished_name.push(DnType::CommonName, host);
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(|error| error.to_string())?;
        let chain = vec![cert.der().clone(), self.der.clone()];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .map_err(|error| error.to_string())?;
        let config = Arc::new(config);
        configs.insert(host.to_owned(), config.clone());
        Ok(config)
    }
}
