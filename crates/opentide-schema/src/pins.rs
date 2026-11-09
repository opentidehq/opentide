//! The validation context: the vocabulary versions a revision pins.
//!
//! Every model validates with `garde`'s context set to [`Pins`]
//! (`#[garde(context(Pins))]`), so a custom validator can ask which version of
//! a vocabulary the object's revision is checked against (RFC 0003,
//! `src/opentide/data/pins/`). UC-1.6 (#812) loads the pins and the
//! vocabularies; the skeleton carries only the map.

use std::collections::BTreeMap;

/// The vocabulary versions one schema revision pins, by vocabulary name
/// (`alert_severity` → `1.0`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pins {
    versions: BTreeMap<String, String>,
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
        }
    }

    /// The version pinned for `vocabulary`, if the revision pins it.
    pub fn version(&self, vocabulary: &str) -> Option<&str> {
        self.versions.get(vocabulary).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::Pins;

    #[test]
    fn looks_up_by_name() {
        let pins = Pins::new([("alert_severity", "1.0")]);
        assert_eq!(pins.version("alert_severity"), Some("1.0"));
        assert_eq!(pins.version("tlp"), None);
        assert_eq!(Pins::default().version("tlp"), None);
    }
}
