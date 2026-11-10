//! Vocabulary versions and contracts (RFC 0003): `M.m`, and `field::M.m`.

use std::fmt;
use std::str::FromStr;

use super::VocabError;

/// A vocabulary version, `major.minor`. Minor versions are cumulative: an entry
/// added in `1.1` is part of `1.2`, and of no `2.x` unless it is still there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// The major version.
    pub major: u32,
    /// The minor version.
    pub minor: u32,
}

impl Version {
    /// `major.minor`.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

impl FromStr for Version {
    type Err = VocabError;

    /// `M.m`, or `M` for `M.0`, each part decimal digits around optional
    /// whitespace.
    fn from_str(text: &str) -> Result<Self, VocabError> {
        let invalid = || VocabError::InvalidVersion(text.to_owned());
        let number = |part: &str| {
            let part = part.trim();
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid());
            }
            part.parse::<u32>().map_err(|_| invalid())
        };
        match text.split_once('.') {
            Some((major, minor)) => Ok(Self::new(number(major)?, number(minor)?)),
            None => Ok(Self::new(number(text)?, 0)),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A vocabulary contract, `field::M.m`: the vocabulary a field draws from and
/// the version it is held to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Contract {
    /// The vocabulary's field name (`tlp`, `att&ck`).
    pub field: String,
    /// The version.
    pub version: Version,
}

impl FromStr for Contract {
    type Err = VocabError;

    fn from_str(text: &str) -> Result<Self, VocabError> {
        let (field, version) = text
            .split_once("::")
            .ok_or_else(|| VocabError::InvalidContract(text.to_owned()))?;
        let field = field.trim();
        let version = version.trim();
        if field.is_empty() || version.is_empty() {
            return Err(VocabError::InvalidContract(text.to_owned()));
        }
        Ok(Self {
            field: field.to_owned(),
            version: version
                .parse()
                .map_err(|_| VocabError::InvalidContract(text.to_owned()))?,
        })
    }
}

impl fmt::Display for Contract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.field, self.version)
    }
}

/// A field's vocabulary reference, as a schema's `tide.vocab` names it: a
/// contract (`tlp::1.0`), or a bare field name (`objective`) for every entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VocabRef {
    /// The vocabulary's field name.
    pub field: String,
    /// The pinned version, if any.
    pub pin: Option<Version>,
}

impl FromStr for VocabRef {
    type Err = VocabError;

    fn from_str(text: &str) -> Result<Self, VocabError> {
        if text.contains("::") {
            let contract: Contract = text.parse()?;
            Ok(Self {
                field: contract.field,
                pin: Some(contract.version),
            })
        } else {
            Ok(Self {
                field: text.to_owned(),
                pin: None,
            })
        }
    }
}

impl From<Contract> for VocabRef {
    fn from(contract: Contract) -> Self {
        Self {
            field: contract.field,
            pin: Some(contract.version),
        }
    }
}

impl fmt::Display for VocabRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pin {
            Some(pin) => write!(f, "{}::{pin}", self.field),
            None => f.write_str(&self.field),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_parse_and_order() {
        assert_eq!("1.2".parse::<Version>().unwrap(), Version::new(1, 2));
        assert_eq!("2".parse::<Version>().unwrap(), Version::new(2, 0));
        assert_eq!(" 1 . 10 ".parse::<Version>().unwrap(), Version::new(1, 10));
        assert!(Version::new(1, 10) > Version::new(1, 9));
        assert!(Version::new(2, 0) > Version::new(1, 99));
        for bad in ["", "x", "1.", ".1", "1.2.3", "-1.0", "1.a"] {
            assert!(bad.parse::<Version>().is_err(), "{bad}");
        }
        assert_eq!(Version::new(1, 0).to_string(), "1.0");
    }

    #[test]
    fn contracts_parse() {
        let contract: Contract = "att&ck::1.2".parse().unwrap();
        assert_eq!(contract.field, "att&ck");
        assert_eq!(contract.version, Version::new(1, 2));
        assert_eq!(contract.to_string(), "att&ck::1.2");
        assert_eq!(
            " tlp :: 1 ".parse::<Contract>().unwrap().to_string(),
            "tlp::1.0"
        );
        for bad in ["tlp", "::1.0", "tlp::", "tlp::one"] {
            assert!(bad.parse::<Contract>().is_err(), "{bad}");
        }
    }

    #[test]
    fn references_with_and_without_a_pin() {
        let pinned: VocabRef = "tlp::1.0".parse().unwrap();
        assert_eq!(pinned.pin, Some(Version::new(1, 0)));
        let bare: VocabRef = "objective".parse().unwrap();
        assert_eq!(bare.pin, None);
        assert_eq!(bare.to_string(), "objective");
        assert_eq!(pinned.to_string(), "tlp::1.0");
    }
}
