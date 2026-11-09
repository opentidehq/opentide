//! The environment a run reads, as a snapshot: tests pass their own.

use std::collections::BTreeMap;

/// Environment variables by name. A value that is not UTF-8 is read lossily.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Env {
    vars: BTreeMap<String, String>,
}

impl Env {
    /// This process's environment.
    pub fn from_process() -> Env {
        Env::from_pairs(std::env::vars_os().map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        }))
    }

    /// An environment of exactly these variables.
    pub fn from_pairs<K: Into<String>, V: Into<String>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Env {
        Env {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// The value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// Every variable, by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// `name` read as a boolean literal (`1`, `true`, `yes`, `on`, their
    /// negatives and the empty string); `None` when unset or anything else,
    /// such as `DEBUG='*'` from Node tooling.
    pub fn boolean(&self, name: &str) -> Option<bool> {
        let value = self.get(name)?.trim().to_lowercase();
        match value.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "" | "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    }

    /// Whether the environment asks for `--debug`: `OPENTIDE_DEBUG` when it
    /// is a boolean, otherwise `DEBUG` when it is one.
    pub fn debug_requested(&self) -> bool {
        self.boolean("OPENTIDE_DEBUG")
            .or_else(|| self.boolean("DEBUG"))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framework_debug_reads_opentide_debug_then_a_boolean_debug() {
        let env = |pairs: &[(&str, &str)]| Env::from_pairs(pairs.iter().copied());
        assert!(env(&[("OPENTIDE_DEBUG", "1")]).debug_requested());
        assert!(!env(&[("OPENTIDE_DEBUG", "0"), ("DEBUG", "1")]).debug_requested());
        assert!(env(&[("OPENTIDE_DEBUG", "maybe"), ("DEBUG", "yes")]).debug_requested());
        assert!(!env(&[("DEBUG", "*")]).debug_requested());
        assert!(env(&[("DEBUG", " TRUE ")]).debug_requested());
        assert!(!env(&[]).debug_requested());
        assert_eq!(env(&[("X", "")]).boolean("X"), Some(false));
        assert!(Env::from_process().iter().count() < usize::MAX);
    }
}
