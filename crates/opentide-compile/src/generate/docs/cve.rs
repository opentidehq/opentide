//! CVE references as links to a Vulnerability-Lookup instance
//! (`vulnerability_lookup.py`: identifiers, `page_url_for`, `[cve]`).
//!
//! Offline: a page lists each identifier as a link to its record page. The
//! oracle also fetched each record's details over HTTP when `[cve]
//! retrieve_details` is on (its default); the engine has no HTTP client until
//! the connectors bring one (UC-4.1), so the details table is not written
//! (`CHANGELOG.md`, the "**`generate docs` runs on the Rust engine**" entry).

use std::sync::LazyLock;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;

/// The public Vulnerability-Lookup instance.
pub const DEFAULT_BASE_URL: &str = "https://vulnerability.circl.lu";

const LEGACY_NVD_PREFIXES: [&str; 2] = [
    "https://nvd.nist.gov/vuln/detail/",
    "https://nvd.nist.gov/view/vuln/detail?vulnId=",
];

#[expect(clippy::unwrap_used, reason = "constant patterns")]
static CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^cve-(\d{4})-(\d+)$").unwrap());
#[expect(clippy::unwrap_used, reason = "constant patterns")]
static GHSA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^ghsa-([0-9a-z]{4})-([0-9a-z]{4})-([0-9a-z]{4})$").unwrap());
#[expect(clippy::unwrap_used, reason = "constant patterns")]
static GCVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)^gcve-(\d+)-(.+)$").unwrap());
#[expect(clippy::unwrap_used, reason = "constant patterns")]
static GCVE0_REST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{4})-(\d+)$").unwrap());

/// What URL quoting keeps as is: letters, digits and `_.-~`.
const KEPT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

/// Where CVE links point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveLinks {
    /// The prefix of a record page.
    pub page_url_prefix: String,
}

impl Default for CveLinks {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl CveLinks {
    /// From `[cve] base_url` and `default_db_link`; an NVD link prefix is
    /// read as the instance's own pages.
    pub fn new(base_url: Option<&str>, default_db_link: Option<&str>) -> Self {
        let base = base_url
            .filter(|base| !base.is_empty())
            .unwrap_or(DEFAULT_BASE_URL)
            .trim_end_matches('/');
        let configured = default_db_link.unwrap_or_default().trim();
        let page_url_prefix = if configured.is_empty()
            || LEGACY_NVD_PREFIXES
                .iter()
                .any(|p| configured.starts_with(p))
        {
            format!("{base}/vuln/")
        } else {
            configured.to_owned()
        };
        Self { page_url_prefix }
    }

    /// The record page of `id`.
    pub fn page_url(&self, id: &str) -> String {
        let ident = utf8_percent_encode(&lookup_identifier(id), KEPT).to_string();
        if self.page_url_prefix.ends_with('=') {
            format!("{}{ident}", self.page_url_prefix)
        } else {
            format!("{}/{ident}", self.page_url_prefix.trim_end_matches('/'))
        }
    }
}

/// An identifier with its prefix and case made canonical (`CVE-2024-3094`).
pub fn canonical(value: &str) -> String {
    let text = value.trim();
    if let Some(cve) = CVE.captures(text) {
        return format!("CVE-{}-{}", &cve[1], &cve[2]);
    }
    if let Some(ghsa) = GHSA.captures(text) {
        return format!(
            "GHSA-{}-{}-{}",
            ghsa[1].to_lowercase(),
            ghsa[2].to_lowercase(),
            ghsa[3].to_lowercase()
        );
    }
    if let Some(gcve) = GCVE.captures(text) {
        return format!("GCVE-{}-{}", &gcve[1], &gcve[2]);
    }
    text.to_owned()
}

/// The key Vulnerability-Lookup stores `id` under: a GNA 0 GCVE identifier
/// is its CVE.
pub fn lookup_identifier(id: &str) -> String {
    let ident = canonical(id);
    if let Some(gcve) = GCVE.captures(&ident)
        && &gcve[1] == "0"
        && let Some(rest) = GCVE0_REST.captures(&gcve[2])
    {
        return format!("CVE-{}-{}", &rest[1], &rest[2]);
    }
    ident
}

/// The identifiers of a `cve` list, canonical, each once by its lookup key.
pub fn identifiers(values: &[String]) -> Vec<String> {
    let mut canonical_ids: Vec<String> = Vec::new();
    for value in values {
        let text = canonical(value);
        if !text.is_empty() && !canonical_ids.contains(&text) {
            canonical_ids.push(text);
        }
    }
    let mut keys: Vec<String> = Vec::new();
    let mut unique = Vec::new();
    for id in canonical_ids {
        let key = lookup_identifier(&id);
        if !keys.contains(&key) {
            keys.push(key);
            unique.push(id);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_canonical_and_unique() {
        let ids = identifiers(&[
            " cve-2024-3094 ".into(),
            "GCVE-0-2024-3094".into(),
            "ghsa-AbCd-1234-zzzz".into(),
            String::new(),
            "CVE-2024-3094".into(),
        ]);
        assert_eq!(ids, ["CVE-2024-3094", "GHSA-abcd-1234-zzzz"]);
    }

    #[test]
    fn links() {
        let links = CveLinks::new(None, Some("https://nvd.nist.gov/vuln/detail/"));
        assert_eq!(
            links.page_url("gcve-0-2024-3094"),
            "https://vulnerability.circl.lu/vuln/CVE-2024-3094"
        );
        let links = CveLinks::new(Some("https://x.example/"), Some("https://db.example/?id="));
        assert_eq!(links.page_url("a b"), "https://db.example/?id=a%20b");
        let links = CveLinks::new(Some("https://x.example/"), None);
        assert_eq!(links.page_url("A"), "https://x.example/vuln/A");
    }
}
