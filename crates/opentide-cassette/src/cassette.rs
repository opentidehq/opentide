//! A cassette: the HTTP a client sent in one scenario, and what it was
//! answered, in order.
//!
//! JSON, under `tests/cassettes/<scenario>.json`. A cassette is written by
//! the recorder (`cargo xtask cassettes record`) and never by hand: its
//! `digest` is the SHA-256 of its interactions as written, and `cargo xtask
//! cassettes check` fails on one that does not match, or on one that holds
//! anything [`crate::redact`] would still redact.

use std::fmt::Write as _;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The format this crate reads and writes.
pub const FORMAT: u32 = 1;

/// A body: text when it is UTF-8, else base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Body {
    /// UTF-8 text.
    Text(String),
    /// Any other bytes.
    Binary {
        /// The bytes, base64 (standard alphabet, padded).
        base64: String,
    },
}

impl Body {
    /// The body of *bytes*.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => Self::Text(text.to_owned()),
            Err(_) => Self::Binary {
                base64: base64::engine::general_purpose::STANDARD.encode(bytes),
            },
        }
    }

    /// Its bytes; a base64 body that does not decode is empty.
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Text(text) => text.as_bytes().to_vec(),
            Self::Binary { base64 } => base64::engine::general_purpose::STANDARD
                .decode(base64)
                .unwrap_or_default(),
        }
    }
}

/// A request as recorded: method, full URL, headers (names in lower case,
/// sorted, transport headers left out, secrets redacted) and body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// `GET`, `POST`.
    pub method: String,
    /// The URL, credentials in it redacted.
    pub url: String,
    /// `[name, value]` pairs.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Body,
}

/// An answer as recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// `[name, value]` pairs, as received, secrets redacted.
    pub headers: Vec<(String, String)>,
    /// The body, secrets redacted.
    pub body: Body,
}

/// One request and its answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interaction {
    /// What the client sent.
    pub request: Request,
    /// What it got.
    pub response: Response,
}

/// A recorded scenario.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cassette {
    /// [`FORMAT`].
    pub format: u32,
    /// The scenario's name (`skills/manifest`).
    pub scenario: String,
    /// What recorded it: the command line of the client.
    pub recorded_from: Vec<String>,
    /// `sha256:<hex>` of `interactions` as written ([`Cassette::compute_digest`]).
    pub digest: String,
    /// The interactions, in the order they happened.
    pub interactions: Vec<Interaction>,
}

impl Cassette {
    /// A cassette of *interactions*, with its digest.
    pub fn new(scenario: &str, recorded_from: Vec<String>, interactions: Vec<Interaction>) -> Self {
        let mut cassette = Self {
            format: FORMAT,
            scenario: scenario.to_owned(),
            recorded_from,
            digest: String::new(),
            interactions,
        };
        cassette.digest = cassette.compute_digest();
        cassette
    }

    /// `sha256:<hex>` of the interactions' JSON.
    pub fn compute_digest(&self) -> String {
        let bytes = serde_json::to_vec(&self.interactions).unwrap_or_default();
        let hash = Sha256::digest(&bytes);
        let mut hex = String::with_capacity(64);
        for byte in hash {
            let _ = write!(hex, "{byte:02x}");
        }
        format!("sha256:{hex}")
    }

    /// The cassette's text: pretty JSON, one trailing newline.
    pub fn to_text(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Reads a cassette, checking its format and digest.
    pub fn parse(text: &str) -> Result<Self, String> {
        let cassette: Self =
            serde_json::from_str(text).map_err(|error| format!("not a cassette: {error}"))?;
        if cassette.format != FORMAT {
            return Err(format!(
                "format {} is not {FORMAT}: record it again",
                cassette.format
            ));
        }
        let digest = cassette.compute_digest();
        if cassette.digest != digest {
            return Err(format!(
                "its digest is {}, its interactions hash to {digest}: a cassette is recorded \
                 (cargo xtask cassettes record), never edited",
                cassette.digest
            ));
        }
        Ok(cassette)
    }
}
