//! The environment a connector reads: a snapshot the caller hands over.
//!
//! Nothing here reads the process environment on its own: the CLI passes the
//! variables it was started with (its `Env`), and a test passes its own, so
//! two tenants in one run, or two runs in one process, never see each
//! other's proxies, CA bundles or credentials.

use std::collections::BTreeMap;

/// Environment variables, by name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Environment {
    vars: BTreeMap<String, String>,
}

impl Environment {
    /// An environment of these variables.
    pub fn from_pairs<K: Into<String>, V: Into<String>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Self {
            vars: pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        }
    }

    /// The process's own environment (a binary's `main`; never a library's default).
    pub fn process() -> Self {
        Self::from_pairs(
            std::env::vars_os().filter_map(|(key, value)| {
                Some((key.into_string().ok()?, value.into_string().ok()?))
            }),
        )
    }

    /// A variable's value, as set; `None` when it is unset.
    pub fn raw(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    /// A variable's value when it is set and not blank.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.raw(name).filter(|value| !value.trim().is_empty())
    }

    /// The first of *names* that is set and not blank.
    pub fn first(&self, names: &[&str]) -> Option<&str> {
        names.iter().find_map(|name| self.get(name))
    }

    /// The same environment with *name* set to *value*.
    #[must_use]
    pub fn with(mut self, name: &str, value: &str) -> Self {
        self.vars.insert(name.to_owned(), value.to_owned());
        self
    }

    /// Every variable, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.vars
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
    }
}
