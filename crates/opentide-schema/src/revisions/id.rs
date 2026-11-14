//! `SchemaId`: a schema identifier, `family::major.minor`
//! (`models/version.py` `SchemaVersion`).

use std::fmt;

/// Why a text is not a schema identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaIdError {
    /// The text has no `::` between a family and a version.
    #[error("invalid schema identifier: {0:?}")]
    Invalid(String),
    /// The family is empty once trimmed.
    #[error("schema family must not be empty")]
    EmptyFamily,
    /// The major or minor version is not a number of ASCII digits that fits in
    /// 32 bits.
    #[error("invalid schema version: {0:?}")]
    Version(String),
}

/// A schema identifier: a family and a version, `rule::1.1`.
///
/// The family is trimmed and lower-cased, and must not be empty, as
/// `SchemaVersion._normalise_family` does. Identifiers order by family, then
/// major, then minor (`SchemaVersion.sort_key`): the derived order compares
/// the fields in that order, and a family compares by code point.
///
/// Two choices differ from `SchemaVersion.parse`, neither visible to a user
/// (the oracle parses only identifiers its registry already holds, ADR 0009):
///
/// - The version is the text after the **last** `::`, so a platform block's
///   identifier, `platform::sentinel::1.0`, is the family `platform::sentinel`
///   at 1.0. `SchemaVersion.parse` splits at the first `::` and fails on it.
/// - A version number is ASCII digits only. Python's `int()` also took a sign,
///   `_` separators, surrounding blanks and other scripts' digits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaId {
    family: String,
    major: u32,
    minor: u32,
}

impl SchemaId {
    /// An identifier from its parts; the family is normalised.
    pub fn new(family: &str, major: u32, minor: u32) -> Result<Self, SchemaIdError> {
        let family = family.trim().to_lowercase();
        if family.is_empty() {
            return Err(SchemaIdError::EmptyFamily);
        }
        Ok(Self {
            family,
            major,
            minor,
        })
    }

    /// Parses `rule::1.0`, `objective::1`, `platform::sentinel::1.0`. A
    /// version without a minor (`1`) is minor 0.
    pub fn parse(identifier: &str) -> Result<Self, SchemaIdError> {
        let Some((family, version)) = identifier.rsplit_once("::") else {
            return Err(SchemaIdError::Invalid(identifier.to_owned()));
        };
        Self::from_version_string(family, version)
    }

    /// An identifier from a family and a version text, `1.0` or `1`
    /// (`SchemaVersion.from_version_string`).
    pub fn from_version_string(family: &str, version: &str) -> Result<Self, SchemaIdError> {
        let (major, minor) = match version.split_once('.') {
            Some((major, minor)) => (number(major, version)?, number(minor, version)?),
            None => (number(version, version)?, 0),
        };
        Self::new(family, major, minor)
    }

    /// The family, normalised: `rule`, `platform::sentinel`.
    pub fn family(&self) -> &str {
        &self.family
    }

    /// The major version.
    pub fn major(&self) -> u32 {
        self.major
    }

    /// The minor version.
    pub fn minor(&self) -> u32 {
        self.minor
    }

    /// `family::major.minor` (`SchemaVersion.as_identifier`).
    pub fn as_identifier(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for SchemaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}.{}", self.family, self.major, self.minor)
    }
}

impl std::str::FromStr for SchemaId {
    type Err = SchemaIdError;

    fn from_str(identifier: &str) -> Result<Self, Self::Err> {
        Self::parse(identifier)
    }
}

/// One version number: ASCII digits, at least one, within `u32`.
fn number(text: &str, version: &str) -> Result<u32, SchemaIdError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SchemaIdError::Version(version.to_owned()));
    }
    text.parse()
        .map_err(|_| SchemaIdError::Version(version.to_owned()))
}
