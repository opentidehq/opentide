//! RS256 JSON Web Tokens (RFC 7515 and 7518: RSASSA-PKCS1-v1_5 with
//! SHA-256), the one kind a service account signs, on ring.
//!
//! The header is `{"typ":"JWT","alg":"RS256"}` with the key's `kid` when it
//! has one, and each part is base64url without padding. PKCS#1 v1.5 signs
//! deterministically, so a key, a header and claims give one token.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject as _;
use serde::Serialize;

/// An RSA private key read from PEM: PKCS#8 (`BEGIN PRIVATE KEY`, the form
/// of Google's service-account keys) or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
pub(super) struct SigningKey(RsaKeyPair);

impl SigningKey {
    /// The key a PEM text holds.
    ///
    /// # Errors
    ///
    /// Why the text is not an RSA private key: no PEM private key in it, a
    /// key of another algorithm, or one ring refuses (too short, malformed).
    pub(super) fn from_pem(pem: &str) -> Result<Self, String> {
        let der = PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|error| format!("no PEM private key: {error}"))?;
        let pair = match &der {
            PrivateKeyDer::Pkcs8(key) => RsaKeyPair::from_pkcs8(key.secret_pkcs8_der()),
            PrivateKeyDer::Pkcs1(key) => RsaKeyPair::from_der(key.secret_pkcs1_der()),
            _ => return Err("not an RSA key".to_owned()),
        }
        .map_err(|error| format!("not a usable RSA key: {error}"))?;
        Ok(Self(pair))
    }
}

/// The JOSE header, in the order the fields are written.
#[derive(Serialize)]
struct Header<'a> {
    typ: &'static str,
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
}

/// The compact JWT `header.claims.signature` for `claims`, signed with `key`.
///
/// # Errors
///
/// Why it cannot be signed: the claims do not serialize, or ring's
/// signature fails.
pub(super) fn encode<C: Serialize>(
    key: &SigningKey,
    kid: Option<&str>,
    claims: &C,
) -> Result<String, String> {
    let header = Header {
        typ: "JWT",
        alg: "RS256",
        kid,
    };
    let header = serde_json::to_vec(&header).map_err(|error| error.to_string())?;
    let claims = serde_json::to_vec(claims).map_err(|error| error.to_string())?;
    let mut token = URL_SAFE_NO_PAD.encode(header);
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(claims));
    let mut signature = vec![0; key.0.public().modulus_len()];
    key.0
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            token.as_bytes(),
            &mut signature,
        )
        .map_err(|_| "the RSA signature failed".to_owned())?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}
