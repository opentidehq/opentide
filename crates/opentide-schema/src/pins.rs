//! The validation context: the vocabulary contracts a schema revision pins.
//!
//! Every model validates with `garde`'s context set to [`Pins`]
//! (`#[garde(context(Pins))]`), so a custom validator can ask which version of
//! a vocabulary the object's revision is checked against (RFC 0003,
//! `src/opentide/data/pins/`). Pins are keyed by field path within a revision
//! ([`Pins::contract`]: `threat.severity` → `severity::1.0`): each revision's
//! validator receives its own [`Pins`] ([`PinTable::get`]), so a sub-struct
//! shared by two revisions resolves the version of the revision it is
//! validated in.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::vocab::{Contract, VocabError};

/// The vocabulary contracts one schema revision pins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pins {
    /// Vocabulary name → version, for [`Pins::version`].
    versions: BTreeMap<String, String>,
    /// Field path → contract.
    contracts: BTreeMap<String, Contract>,
}

impl Pins {
    /// Pins from `(vocabulary, version)` pairs.
    pub fn new<N, V>(pairs: impl IntoIterator<Item = (N, V)>) -> Self
    where
        N: Into<String>,
        V: Into<String>,
    {
        Self {
            versions: pairs
                .into_iter()
                .map(|(name, version)| (name.into(), version.into()))
                .collect(),
            contracts: BTreeMap::new(),
        }
    }

    /// Pins from `(field path, contract)` pairs, as a pin file's revision
    /// table holds them. [`Pins::version`] answers for a vocabulary every
    /// path pins at one version; one pinned at two versions is asked by path.
    pub fn from_contracts<P: Into<String>>(pairs: impl IntoIterator<Item = (P, Contract)>) -> Self {
        let contracts: BTreeMap<String, Contract> = pairs
            .into_iter()
            .map(|(path, contract)| (path.into(), contract))
            .collect();
        let mut by_vocabulary: BTreeMap<&str, Option<String>> = BTreeMap::new();
        for contract in contracts.values() {
            let version = contract.version.to_string();
            by_vocabulary
                .entry(contract.field.as_str())
                .and_modify(|seen| {
                    if seen.as_deref() != Some(version.as_str()) {
                        *seen = None;
                    }
                })
                .or_insert(Some(version));
        }
        let versions = by_vocabulary
            .into_iter()
            .filter_map(|(name, version)| Some((name.to_owned(), version?)))
            .collect();
        Self {
            versions,
            contracts,
        }
    }

    /// The version pinned for `vocabulary`, if the revision pins it at one.
    pub fn version(&self, vocabulary: &str) -> Option<&str> {
        self.versions.get(vocabulary).map(String::as_str)
    }

    /// The contract pinned for the field at `path` (`threat.severity`).
    pub fn contract(&self, path: &str) -> Option<&Contract> {
        self.contracts.get(path)
    }

    /// Every `(field path, contract)`, by path.
    pub fn contracts(&self) -> impl Iterator<Item = (&str, &Contract)> {
        self.contracts.iter().map(|(path, c)| (path.as_str(), c))
    }
}

/// The bundled pin files: `(file name, text)`.
pub const FILES: [(&str, &str); 3] = [
    (
        "objective.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/pins/objective.toml"
        )),
    ),
    (
        "rule.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/pins/rule.toml"
        )),
    ),
    (
        "threat.toml",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/pins/threat.toml"
        )),
    ),
];

/// A pin file that cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    /// Not TOML.
    #[error("could not read pins {file}: {message}")]
    Toml {
        /// The file.
        file: String,
        /// The parser's message.
        message: String,
    },
    /// A value that is not a string, or a string that is not `field::M.m`.
    #[error("{file}: [{revision}] {path}: {error}")]
    Contract {
        /// The file.
        file: String,
        /// The revision.
        revision: String,
        /// The field path.
        path: String,
        /// What is wrong.
        error: String,
    },
    /// Two files pin the same revision.
    #[error("{file}: [{revision}] is pinned by another file too")]
    Duplicate {
        /// The file.
        file: String,
        /// The revision.
        revision: String,
    },
}

/// Every revision's pins, by revision (`threat::1.0`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PinTable {
    revisions: BTreeMap<String, Pins>,
}

impl PinTable {
    /// Reads pin files: each top-level table is a revision (`["threat::1.0"]`)
    /// of `"field.path" = "vocabulary::M.m"`. A top-level key that is not a
    /// table is not a revision and is ignored.
    pub fn parse<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, PinError> {
        let mut revisions = BTreeMap::new();
        for (source, text) in files {
            let document: toml::Table = toml::from_str(text).map_err(|error| PinError::Toml {
                file: source.to_owned(),
                message: error.to_string(),
            })?;
            for (revision, table) in document {
                let toml::Value::Table(table) = table else {
                    continue;
                };
                let mut pairs = Vec::with_capacity(table.len());
                for (path, value) in table {
                    let contract = value
                        .as_str()
                        .ok_or_else(|| VocabError::InvalidContract(value.to_string()))
                        .and_then(str::parse::<Contract>)
                        .map_err(|error| PinError::Contract {
                            file: source.to_owned(),
                            revision: revision.clone(),
                            path: path.clone(),
                            error: error.to_string(),
                        })?;
                    pairs.push((path, contract));
                }
                if revisions.contains_key(&revision) {
                    return Err(PinError::Duplicate {
                        file: source.to_owned(),
                        revision,
                    });
                }
                revisions.insert(revision, Pins::from_contracts(pairs));
            }
        }
        Ok(Self { revisions })
    }

    /// The bundled pins ([`FILES`]).
    #[expect(
        clippy::expect_used,
        reason = "the pin files are compiled in and read by a test (`the_bundled_pins_read`)"
    )]
    pub fn bundled() -> &'static Self {
        static TABLE: OnceLock<PinTable> = OnceLock::new();
        TABLE.get_or_init(|| Self::parse(FILES).expect("the bundled pin files read"))
    }

    /// The pins of `revision` (`threat::1.0`).
    pub fn get(&self, revision: &str) -> Option<&Pins> {
        self.revisions.get(revision)
    }

    /// Every revision with its pins, by revision.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Pins)> {
        self.revisions.iter().map(|(r, p)| (r.as_str(), p))
    }

    /// The newest version any revision pins `vocabulary` at.
    pub fn newest(&self, vocabulary: &str) -> Option<crate::vocab::Version> {
        self.revisions
            .values()
            .flat_map(|pins| pins.contracts.values())
            .filter(|contract| contract.field == vocabulary)
            .map(|contract| contract.version)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::{PinError, PinTable, Pins};
    use crate::vocab::{Contract, Version};

    #[test]
    fn looks_up_by_name() {
        let pins = Pins::new([("alert_severity", "1.0")]);
        assert_eq!(pins.version("alert_severity"), Some("1.0"));
        assert_eq!(pins.version("tlp"), None);
        assert_eq!(Pins::default().version("tlp"), None);
    }

    fn contract(text: &str) -> Contract {
        text.parse().unwrap()
    }

    #[test]
    fn looks_up_by_path() {
        let pins = Pins::from_contracts([
            ("severity", contract("alert_severity::1.0")),
            ("response.alert_severity", contract("alert_severity::1.0")),
            ("a", contract("x::1.0")),
            ("b", contract("x::1.1")),
        ]);
        assert_eq!(
            pins.contract("severity"),
            Some(&contract("alert_severity::1.0"))
        );
        assert_eq!(pins.version("alert_severity"), Some("1.0"));
        // Pinned at two versions: only the path answers.
        assert_eq!(pins.version("x"), None);
        assert_eq!(pins.contract("b").unwrap().version, Version::new(1, 1));
        assert_eq!(pins.contract("nowhere"), None);
    }

    #[test]
    fn the_bundled_pins_read() {
        let table = PinTable::bundled();
        let revisions: Vec<&str> = table.iter().map(|(r, _)| r).collect();
        assert!(revisions.contains(&"threat::1.0"), "{revisions:?}");
        assert!(revisions.contains(&"objective::1.1"));
        assert!(revisions.contains(&"rule::1.1"));
        let threat = table.get("threat::1.0").unwrap();
        assert_eq!(
            threat.contract("threat.severity"),
            Some(&contract("severity::1.0"))
        );
        assert_eq!(threat.version("att&ck"), Some("1.2"));
        assert_eq!(table.newest("att&ck"), Some(Version::new(1, 2)));
        assert_eq!(table.newest("nothing"), None);
    }

    #[test]
    fn pin_file_errors() {
        let bad = PinTable::parse([("t.toml", "[\"t::1.0\"]\nx = 3\n")]).unwrap_err();
        assert!(matches!(bad, PinError::Contract { .. }), "{bad}");
        let bad = PinTable::parse([("t.toml", "[\"t::1.0\"]\nx = \"tlp\"\n")]).unwrap_err();
        assert!(matches!(bad, PinError::Contract { .. }), "{bad}");
        let twice = [("a.toml", "[\"t::1.0\"]\n"), ("b.toml", "[\"t::1.0\"]\n")];
        assert!(matches!(
            PinTable::parse(twice).unwrap_err(),
            PinError::Duplicate { .. }
        ));
        assert!(matches!(
            PinTable::parse([("t.toml", "[")]).unwrap_err(),
            PinError::Toml { .. }
        ));
        let ignored = PinTable::parse([("t.toml", "note = \"x\"\n")]).unwrap();
        assert_eq!(ignored.iter().count(), 0);
    }
}
