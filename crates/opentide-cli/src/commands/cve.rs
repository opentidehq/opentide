//! The online CVE lookup of `validate --check cve` (UC-4.4, #834;
//! `validation/cve_check.py`, `vulnerability_lookup.py`'s settings): the
//! host side of `opentide_workspace::validate::CveCheck`, on the connectors'
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

/// The Python module whose events this port logs.
const LOGGER: &str = "opentide.validation.cve_check";

/// The `[cve]` settings (`load_cve_settings`): read leniently, each value
/// that is missing or of the wrong type taking its default, as the oracle's
/// `dict.get` reads them.
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

/// Python's `str` of a TOML value.
fn text(node: &Node) -> String {
    match &node.value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// An integer number of seconds as Python's `float()` reads it.
#[expect(
    clippy::cast_precision_loss,
    reason = "a timeout of more than 2^52 seconds rounds, as Python's float() rounds it"
)]
fn int_seconds(integer: i64) -> f64 {
    integer as f64
}

/// Python's truth value of a TOML value.
fn truthy(node: &Node) -> bool {
    match &node.value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Int(integer) => *integer != 0,
        Value::Float(float) => *float != 0.0,
        Value::Str(text) | Value::Datetime(text) => !text.is_empty(),
        Value::Seq(items) => !items.is_empty(),
        Value::Map(entries) => !entries.is_empty(),
    }
}

impl Settings {
    /// From the merged configuration's `documentation` tree, `[cve]`.
    pub fn from_documentation(documentation: Option<&Node>) -> Self {
        let cve = documentation
            .and_then(|docs| docs.get("cve"))
            .filter(|cve| matches!(cve.value, Value::Map(_)));
        let Some(cve) = cve else {
            return Self::default();
        };
        let base_url = cve
            .get("base_url")
            .filter(|value| truthy(value))
            .map_or_else(|| DEFAULT_BASE_URL.to_owned(), |value| text(value));
        let default_db_link = cve
            .get("default_db_link")
            .filter(|value| truthy(value))
            .map(|value| text(value).trim().to_owned())
            .unwrap_or_default();
        let seconds = match cve.get("timeout").map(|value| &value.value) {
            None => Some(DEFAULT_TIMEOUT.as_secs_f64()),
            Some(Value::Int(integer)) => Some(int_seconds(*integer)),
            Some(Value::Float(float)) => Some(*float),
            Some(Value::Bool(flag)) => Some(f64::from(u8::from(*flag))),
            Some(Value::Str(text)) => text.trim().parse::<f64>().ok(),
            Some(_) => None,
        }
        .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
        .unwrap_or(DEFAULT_TIMEOUT.as_secs_f64());
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            default_db_link,
            timeout: Duration::try_from_secs_f64(seconds).unwrap_or(DEFAULT_TIMEOUT),
        }
    }

    /// Where a record's page is (`page_url_for`).
    pub fn links(&self) -> CveLinks {
        CveLinks::new(Some(&self.base_url), Some(&self.default_db_link))
    }
}

/// `validate --check cve`'s lookups, each logged as the oracle logs it.
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
                    logger = LOGGER,
                    "cve_found_in_vulnerability_lookup"
                );
                CveLookup::Found
            }
            Ok(None) => {
                tracing::warn!(
                    cve = id,
                    threat,
                    url = self.links.page_url(id).as_str(),
                    logger = LOGGER,
                    "cve_not_found_in_vulnerability_lookup"
                );
                CveLookup::NotFound
            }
            Err(error) => {
                tracing::warn!(
                    cve = id,
                    threat,
                    detail = error.0.as_str(),
                    logger = LOGGER,
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
    fn settings_read_leniently() {
        assert_eq!(Settings::from_documentation(None), Settings::default());
        let docs = documentation(
            "[cve]\nbase_url = \"https://vl.example/\"\ndefault_db_link = \" https://x/?id= \"\ntimeout = 2\n",
        );
        let settings = Settings::from_documentation(Some(&docs));
        assert_eq!(settings.base_url, "https://vl.example");
        assert_eq!(settings.default_db_link, "https://x/?id=");
        assert_eq!(settings.timeout, Duration::from_secs(2));
        assert_eq!(
            settings.links().page_url("cve-2024-1"),
            "https://x/?id=CVE-2024-1"
        );
        for timeout in ["-1", "\"soon\"", "0", "[1]"] {
            let docs = documentation(&format!("[cve]\nbase_url = \"\"\ntimeout = {timeout}\n"));
            let settings = Settings::from_documentation(Some(&docs));
            assert_eq!(settings.timeout, DEFAULT_TIMEOUT, "{timeout}");
            assert_eq!(settings.base_url, DEFAULT_BASE_URL);
        }
        let docs = documentation("[cve]\ntimeout = \"2.5\"\n");
        assert_eq!(
            Settings::from_documentation(Some(&docs)).timeout,
            Duration::from_millis(2500)
        );
        let docs = documentation("cve = 1\n");
        assert_eq!(
            Settings::from_documentation(Some(&docs)),
            Settings::default()
        );
    }

    #[test]
    fn values_print_as_python_strs() {
        let docs = documentation("a = true\nb = false\nc = 1.5\n");
        assert_eq!(text(docs.get("a").unwrap()), "True");
        assert_eq!(text(docs.get("b").unwrap()), "False");
        assert_eq!(text(docs.get("c").unwrap()), "1.5");
        assert!(!truthy(docs.get("b").unwrap()));
        assert!(truthy(docs.get("c").unwrap()));
    }
}
