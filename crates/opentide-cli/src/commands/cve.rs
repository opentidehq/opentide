//! The online CVE lookup of `validate --check cve` (UC-4.4, #834): the host
//! side of `opentide_workspace::validate::CveCheck`, on the connectors'
//! Vulnerability-Lookup client.

use std::time::Duration;

use opentide_compile::generate::docs::cve::{CveLinks, canonical};
use opentide_connectors::Environment;
use opentide_connectors::vulnerability::{
    DEFAULT_BASE_URL, DEFAULT_TIMEOUT, LookupSettings, VulnerabilityLookup,
};
use opentide_schema::node::{Node, Value};
use opentide_workspace::validate::{CveCheck, CveLookup};

use crate::env::Env;

/// The `[cve]` settings of `documentation.toml`: each one that is missing
/// takes its default, and one of the wrong type is refused.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    /// The instance asked, without a trailing `/`.
    pub base_url: String,
    /// `default_db_link`, as written.
    pub default_db_link: String,
    /// How long a request may take.
    pub timeout: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_owned(),
            default_db_link: String::new(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// The string `[cve] key` holds, none when it is missing.
fn string<'n>(cve: &'n Node, key: &str) -> Result<Option<&'n str>, String> {
    match cve.get(key).map(|value| &value.value) {
        None => Ok(None),
        Some(Value::Str(text)) => Ok(Some(text)),
        Some(_) => Err(format!("documentation.toml: [cve] {key} must be a string")),
    }
}

impl Settings {
    /// From the merged configuration's `documentation` tree, `[cve]`.
    ///
    /// # Errors
    ///
    /// `[cve]` is not a table, or one of its settings is of the wrong type
    /// (`base_url = true`), or `timeout` is not a positive number of seconds.
    pub fn from_documentation(documentation: Option<&Node>) -> Result<Self, String> {
        let Some(cve) = documentation.and_then(|docs| docs.get("cve")) else {
            return Ok(Self::default());
        };
        if !matches!(cve.value, Value::Map(_)) {
            return Err("documentation.toml: [cve] must be a table".to_owned());
        }
        let base_url = string(cve, "base_url")?
            .filter(|url| !url.is_empty())
            .unwrap_or(DEFAULT_BASE_URL);
        let default_db_link = string(cve, "default_db_link")?
            .map(str::trim)
            .unwrap_or_default();
        let timeout = match cve.get("timeout").map(|value| &value.value) {
            None => Some(DEFAULT_TIMEOUT),
            Some(Value::Int(seconds)) => u64::try_from(*seconds)
                .ok()
                .filter(|seconds| *seconds > 0)
                .map(Duration::from_secs),
            Some(Value::Float(seconds)) => Duration::try_from_secs_f64(*seconds)
                .ok()
                .filter(|timeout| !timeout.is_zero()),
            Some(_) => None,
        }
        .ok_or("documentation.toml: [cve] timeout must be a positive number of seconds")?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            default_db_link: default_db_link.to_owned(),
            timeout,
        })
    }

    /// Where a record's page is (`page_url_for`).
    pub fn links(&self) -> CveLinks {
        CveLinks::new(Some(&self.base_url), Some(&self.default_db_link))
    }
}

/// `validate --check cve`'s lookups, each logged: a record found at debug, a
/// CVE not found or a lookup that failed as a warning naming the threat.
#[derive(Debug)]
pub struct OnlineCve {
    lookup: VulnerabilityLookup,
    links: CveLinks,
}

impl OnlineCve {
    /// A lookup with `settings`, through the run's proxy and CA bundles.
    pub fn new(settings: &Settings, env: &Env, proxy: Option<&str>, version: &str) -> Self {
        let environment = Environment::from_pairs(env.iter());
        let lookup = VulnerabilityLookup::new(
            LookupSettings {
                base_url: settings.base_url.clone(),
                timeout: settings.timeout,
            },
            &environment,
            proxy,
            version,
        );
        Self {
            lookup,
            links: settings.links(),
        }
    }
}

impl CveCheck for OnlineCve {
    fn canonical(&self, text: &str) -> String {
        canonical(text)
    }

    fn lookup(&self, threat: &str, id: &str) -> CveLookup {
        let page = |key: &str| self.links.page_url(key);
        match self.lookup.get(id, false, &page) {
            Ok(Some(record)) => {
                tracing::debug!(
                    cve = id,
                    url = record.page_url.as_str(),
                    "cve_found_in_vulnerability_lookup"
                );
                CveLookup::Found
            }
            Ok(None) => {
                tracing::warn!(
                    cve = id,
                    threat,
                    url = self.links.page_url(id).as_str(),
                    "cve_not_found_in_vulnerability_lookup"
                );
                CveLookup::NotFound
            }
            Err(error) => {
                tracing::warn!(
                    cve = id,
                    threat,
                    detail = error.0.as_str(),
                    "cve_lookup_unavailable"
                );
                CveLookup::Unavailable(error.0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn documentation(toml: &str) -> Node {
        opentide_schema::configuration::toml::parse(toml).unwrap()
    }

    #[test]
    fn settings_take_their_defaults_when_missing() {
        assert_eq!(Settings::from_documentation(None), Ok(Settings::default()));
        let docs = documentation("[cve]\n");
        assert_eq!(
            Settings::from_documentation(Some(&docs)),
            Ok(Settings::default())
        );
        let docs = documentation(
            "[cve]\nbase_url = \"https://vl.example/\"\ndefault_db_link = \" https://x/?id= \"\ntimeout = 2\n",
        );
        let settings = Settings::from_documentation(Some(&docs)).unwrap();
        assert_eq!(settings.base_url, "https://vl.example");
        assert_eq!(settings.default_db_link, "https://x/?id=");
        assert_eq!(settings.timeout, Duration::from_secs(2));
        assert_eq!(
            settings.links().page_url("cve-2024-1"),
            "https://x/?id=CVE-2024-1"
        );
        let docs = documentation("[cve]\nbase_url = \"\"\ntimeout = 2.5\n");
        let settings = Settings::from_documentation(Some(&docs)).unwrap();
        assert_eq!(settings.base_url, DEFAULT_BASE_URL);
        assert_eq!(settings.timeout, Duration::from_millis(2500));
    }

    /// A setting of the wrong type is refused, naming it, and not read as the
    /// text of its value (`base_url = true` is not the URL `true`).
    #[test]
    fn a_wrong_typed_setting_is_refused() {
        let refused = |toml: &str| Settings::from_documentation(Some(&documentation(toml)));
        assert_eq!(
            refused("[cve]\nbase_url = true\n"),
            Err("documentation.toml: [cve] base_url must be a string".to_owned())
        );
        assert_eq!(
            refused("[cve]\ndefault_db_link = 1\n"),
            Err("documentation.toml: [cve] default_db_link must be a string".to_owned())
        );
        for timeout in [
            "-1", "\"soon\"", "\"2.5\"", "0", "[1]", "true", "nan", "inf",
        ] {
            assert_eq!(
                refused(&format!("[cve]\ntimeout = {timeout}\n")),
                Err(
                    "documentation.toml: [cve] timeout must be a positive number of seconds"
                        .to_owned()
                ),
                "{timeout}"
            );
        }
        assert_eq!(
            refused("cve = 1\n"),
            Err("documentation.toml: [cve] must be a table".to_owned())
        );
    }
}
