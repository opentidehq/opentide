//! CVE references as links to a Vulnerability-Lookup instance
//! (`vulnerability_lookup.py`: identifiers, `page_url_for`, `[cve]`).
//!
//! With `[cve] retrieve_details` off, a page lists each identifier as a link
//! to its record page. With it on (its default) a page is a table of each
//! record's CVSS score, EPSS score, exploitation (CISA KEV, else SSVC) and
//! weakness (0.26.0), which the host fetches ([`CveSource`]: the connectors'
//! Vulnerability-Lookup client, UC-4.4, #834); this crate does no I/O.

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

/// The most recent CVSS base score a record carries (`CvssScore`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cvss {
    /// `4.0`, `3.1`, `3.0` or `2.0`.
    pub version: String,
    /// The base score.
    pub score: f64,
    /// `CRITICAL`, upper case, or empty.
    pub severity: String,
    /// The vector string, or empty.
    pub vector: String,
}

/// A CWE the record classifies the vulnerability under (`Weakness`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Weakness {
    /// `CWE-119`.
    pub identifier: String,
    /// Its name, without the identifier some CNAs repeat in it.
    pub name: String,
}

impl Weakness {
    /// Its page on cwe.mitre.org, empty when the identifier has no number.
    pub fn url(&self) -> String {
        let upper = self.identifier.to_uppercase();
        let number = upper.strip_prefix("CWE-").unwrap_or(&upper);
        if !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()) {
            format!("https://cwe.mitre.org/data/definitions/{number}.html")
        } else {
            String::new()
        }
    }
}

/// FIRST's Exploit Prediction Scoring System: the chance of exploitation in
/// the next 30 days (`EpssScore`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Epss {
    /// The probability, 0 to 1.
    pub probability: f64,
    /// Its percentile among all scored CVEs, 0 to 1.
    pub percentile: f64,
    /// The score's date (`YYYY-MM-DD`), or empty.
    pub date: String,
}

/// What the instance said about a record's EPSS score.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum EpssDetail {
    /// No score: the record has no CVE identifier, or the instance has none.
    #[default]
    None,
    /// Its score.
    Score(Epss),
    /// The instance could not be asked.
    Unavailable,
}

/// One record's details, as a page's CVE table shows them
/// (`VulnerabilityRecord`, with its EPSS score).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CveRecord {
    /// Its canonical identifier.
    pub identifier: String,
    /// Its title.
    pub title: Option<String>,
    /// Its description.
    pub description: Option<String>,
    /// Its publication date.
    pub published: Option<String>,
    /// The CVE record's state.
    pub state: Option<String>,
    /// Its severity.
    pub severity: Option<String>,
    /// Its aliases.
    pub aliases: Vec<String>,
    /// Its page.
    pub page_url: String,
    /// Its newest CVSS score.
    pub cvss: Option<Cvss>,
    /// Its weaknesses.
    pub weaknesses: Vec<Weakness>,
    /// The products it affects (`vendor product`), each once.
    pub affected: Vec<String>,
    /// CISA's SSVC `Exploitation` decision: `none`, `poc` or `active`.
    pub exploitation: Option<String>,
    /// The date CISA added it to its Known Exploited Vulnerabilities catalog.
    pub kev_added: Option<String>,
    /// Its EPSS score.
    pub epss: EpssDetail,
}

impl CveRecord {
    /// Whether it is known to be exploited: in CISA's KEV catalog, or SSVC
    /// `active` (`CveFindings.exploited`).
    pub fn exploited(&self) -> bool {
        self.kev_added.is_some()
            || self
                .exploitation
                .as_deref()
                .is_some_and(|state| state.eq_ignore_ascii_case("active"))
    }
}

/// Whether `id` is a CVE identifier, in any case.
pub fn is_cve(id: &str) -> bool {
    CVE.is_match(id)
}

/// What the instance answered for one identifier.
#[derive(Debug, Clone, PartialEq)]
pub enum CveDetail {
    /// Its record.
    Found(Box<CveRecord>),
    /// It does not know the identifier.
    NotFound,
    /// It could not be asked.
    Unavailable,
}

/// Where a run's CVE details come from: the host's lookup (the connectors'
/// Vulnerability-Lookup client), each identifier asked with its linked
/// records and its EPSS score. Without one a page that needs details reads
/// every identifier as unavailable.
#[derive(Clone, Default)]
pub struct CveSource(Option<std::sync::Arc<Lookup>>);

/// A host's lookup of one identifier.
type Lookup = dyn Fn(&str) -> CveDetail + Send + Sync;

impl CveSource {
    /// A source that asks `lookup`.
    pub fn new(lookup: impl Fn(&str) -> CveDetail + Send + Sync + 'static) -> Self {
        Self(Some(std::sync::Arc::new(lookup)))
    }

    /// The details of `id`.
    pub fn get(&self, id: &str) -> CveDetail {
        self.0
            .as_ref()
            .map_or(CveDetail::Unavailable, |lookup| lookup(id))
    }
}

impl std::fmt::Debug for CveSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "CveSource(lookup)"
        } else {
            "CveSource(none)"
        })
    }
}

/// Two runs' settings are the same whatever their lookups.
impl PartialEq for CveSource {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for CveSource {}

/// What a threat page knows of its CVEs, asked once per page
/// (`CveFindings`): the identifiers, and with `[cve] retrieve_details` on
/// what the instance answered for each.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CveFindings {
    /// The identifiers, canonical and each once.
    pub identifiers: Vec<String>,
    /// Each identifier's answer, in their order; empty when details are off.
    pub details: Vec<CveDetail>,
}

impl CveFindings {
    /// The findings of `ids`: their details from `source` when `enriched`.
    pub fn lookup(ids: Vec<String>, enriched: bool, source: &CveSource) -> Self {
        let details = if enriched {
            ids.iter().map(|id| source.get(id)).collect()
        } else {
            Vec::new()
        };
        Self {
            identifiers: ids,
            details,
        }
    }

    /// Whether the details were asked for.
    pub fn enriched(&self) -> bool {
        !self.details.is_empty()
    }

    /// The identifiers with a record, and the record.
    pub fn records(&self) -> impl Iterator<Item = (&str, &CveRecord)> {
        self.identifiers
            .iter()
            .zip(&self.details)
            .filter_map(|(id, detail)| match detail {
                CveDetail::Found(record) => Some((id.as_str(), record.as_ref())),
                _ => None,
            })
    }

    /// The identifiers the instance does not know.
    pub fn missing(&self) -> Vec<&str> {
        self.identifiers
            .iter()
            .zip(&self.details)
            .filter(|(_, detail)| matches!(detail, CveDetail::NotFound))
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Whether a record could not be asked.
    pub fn unreachable(&self) -> bool {
        self.details
            .iter()
            .any(|detail| matches!(detail, CveDetail::Unavailable))
    }

    /// Whether an EPSS score could not be asked.
    pub fn epss_unavailable(&self) -> bool {
        self.records()
            .any(|(_, record)| record.epss == EpssDetail::Unavailable)
    }

    /// The records known to be exploited.
    pub fn exploited(&self) -> Vec<(&str, &CveRecord)> {
        self.records()
            .filter(|(_, record)| record.exploited())
            .collect()
    }

    /// `2 CVEs (highest CVSS 10.0, 1 known exploited)` for the overview
    /// table (`cve_overview`); empty without identifiers.
    pub fn overview(&self) -> String {
        if self.identifiers.is_empty() {
            return String::new();
        }
        let text = super::text::plural(self.identifiers.len(), "CVE");
        let mut facts = Vec::new();
        let highest = self
            .records()
            .filter_map(|(_, record)| record.cvss.as_ref().map(|cvss| cvss.score))
            .reduce(f64::max);
        if let Some(highest) = highest {
            facts.push(format!("highest CVSS {highest:.1}"));
        }
        let exploited = self.exploited().len();
        if exploited > 0 {
            facts.push(format!("{exploited} known exploited"));
        }
        if facts.is_empty() {
            text
        } else {
            format!("{text} ({})", facts.join(", "))
        }
    }

    /// The warning naming the CVEs exploited in the wild
    /// (`exploited_banner`), without its callout; `None` when none is.
    pub fn exploited_warning(&self) -> Option<String> {
        let exploited = self.exploited();
        if exploited.is_empty() {
            return None;
        }
        let named: Vec<String> = exploited
            .iter()
            .map(|(id, record)| {
                let source = record.kev_added.as_ref().map_or_else(
                    || "CISA SSVC: active".to_owned(),
                    |added| format!("CISA KEV since {added}"),
                );
                let ident = if record.identifier.is_empty() {
                    id
                } else {
                    record.identifier.as_str()
                };
                format!("{} ({source})", super::text::inline_code(ident))
            })
            .collect();
        let verb = if named.len() == 1 { "is" } else { "are" };
        Some(format!(
            "{} {verb} known to be exploited in the wild.",
            named.join(", ")
        ))
    }
}

/// A probability as a percentage that never rounds to a certainty
/// (`_share`): `>99.9%`, `<0.1%`.
pub fn share(value: f64) -> String {
    let percent = value * 100.0;
    if percent >= 99.95 {
        ">99.9%".to_owned()
    } else if percent < 0.05 {
        "<0.1%".to_owned()
    } else {
        format!("{percent:.1}%")
    }
}

/// The Exploitation cell of a record (`_exploitation`).
pub fn exploitation(record: &CveRecord) -> String {
    if let Some(added) = &record.kev_added {
        return format!("**Known exploited**<br>CISA KEV, {added}");
    }
    let cell = match record
        .exploitation
        .as_deref()
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "active" => "**Active**<br>CISA SSVC",
        "poc" | "public poc" => "Proof of concept<br>CISA SSVC",
        "none" => "None reported<br>CISA SSVC",
        _ => "-",
    };
    cell.to_owned()
}

/// Affected products listed under a CVE; the rest are counted.
pub const AFFECTED_SHOWN: usize = 4;

/// One line per CVE: what it is, what it affects, how it scores
/// (`_cve_detail`).
pub fn detail_line(record: &CveRecord) -> String {
    let source = record
        .title
        .as_deref()
        .filter(|text| !text.is_empty())
        .or(record.description.as_deref())
        .unwrap_or_default();
    let summary = Some(super::text::truncate(source, 280))
        .filter(|summary| !summary.is_empty())
        .unwrap_or_else(|| "no summary".to_owned());
    let mut parts = vec![format!(
        "- **{}**: {}.",
        record.identifier,
        summary.trim_end_matches('.')
    )];
    if !record.affected.is_empty() {
        let shown = record
            .affected
            .iter()
            .take(AFFECTED_SHOWN)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let more = record.affected.len().saturating_sub(AFFECTED_SHOWN);
        let more = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        parts.push(format!("Affects {shown}{more}."));
    }
    if let Some(cvss) = record.cvss.as_ref().filter(|cvss| !cvss.vector.is_empty()) {
        parts.push(format!(
            "Vector {}.",
            super::text::inline_code(&cvss.vector)
        ));
    }
    parts.join(" ")
}

#[cfg(test)]
mod detail_tests {
    use super::*;

    fn citrix_bleed() -> CveRecord {
        CveRecord {
            identifier: "CVE-2023-4966".into(),
            title: Some("Unauthenticated sensitive information disclosure".into()),
            published: Some("2023-10-10".into()),
            severity: Some("CRITICAL (9.4)".into()),
            aliases: vec!["GHSA-2g42-2pwg-93cj".into()],
            page_url: "https://vulnerability.circl.lu/vuln/CVE-2023-4966".into(),
            cvss: Some(Cvss {
                version: "3.1".into(),
                score: 9.4,
                severity: "CRITICAL".into(),
                vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L".into(),
            }),
            weaknesses: vec![Weakness {
                identifier: "CWE-119".into(),
                name: "Improper Restriction of Operations".into(),
            }],
            affected: vec![
                "Citrix NetScaler ADC".into(),
                "Citrix NetScaler Gateway".into(),
            ],
            exploitation: Some("active".into()),
            kev_added: Some("2023-10-18".into()),
            ..CveRecord::default()
        }
    }

    #[test]
    fn epss_never_rounds_to_a_certainty() {
        assert_eq!(share(0.99999), ">99.9%");
        assert_eq!(share(0.0001), "<0.1%");
        assert_eq!(share(0.4567), "45.7%");
        assert_eq!(share(1.0 - 0.99712), "0.3%");
    }

    #[test]
    fn weakness_urls_need_a_number() {
        let weakness = |id: &str| Weakness {
            identifier: id.into(),
            name: String::new(),
        };
        assert_eq!(
            weakness("cwe-119").url(),
            "https://cwe.mitre.org/data/definitions/119.html"
        );
        assert_eq!(weakness("CWE-noinfo").url(), "");
        assert_eq!(weakness("CWE-").url(), "");
    }

    #[test]
    fn the_overview_and_the_warning_name_what_is_exploited() {
        let xz = CveRecord {
            identifier: "CVE-2024-3094".into(),
            cvss: Some(Cvss {
                version: "3.1".into(),
                score: 10.0,
                ..Cvss::default()
            }),
            exploitation: Some("none".into()),
            ..CveRecord::default()
        };
        let findings = CveFindings {
            identifiers: vec!["CVE-2023-4966".into(), "CVE-2024-3094".into()],
            details: vec![
                CveDetail::Found(Box::new(citrix_bleed())),
                CveDetail::Found(Box::new(xz.clone())),
            ],
        };
        assert_eq!(
            findings.overview(),
            "2 CVEs (highest CVSS 10.0, 1 known exploited)"
        );
        assert_eq!(
            findings.exploited_warning().as_deref(),
            Some(
                "`CVE-2023-4966` (CISA KEV since 2023-10-18) is known to be exploited in the wild."
            )
        );
        let ssvc = CveRecord {
            exploitation: Some("Active".into()),
            ..xz
        };
        let two = CveFindings {
            identifiers: vec!["CVE-2023-4966".into(), "CVE-2024-3094".into()],
            details: vec![
                CveDetail::Found(Box::new(citrix_bleed())),
                CveDetail::Found(Box::new(ssvc)),
            ],
        };
        assert_eq!(
            two.exploited_warning().as_deref(),
            Some(
                "`CVE-2023-4966` (CISA KEV since 2023-10-18), `CVE-2024-3094` (CISA SSVC: active) \
                 are known to be exploited in the wild."
            )
        );
        let plain = CveFindings::lookup(vec!["CVE-1-1".into()], false, &CveSource::default());
        assert_eq!(plain.overview(), "1 CVE");
        assert!(!plain.enriched());
        assert_eq!(plain.exploited_warning(), None);
        assert_eq!(CveFindings::default().overview(), "");
        let none = CveFindings::lookup(vec!["CVE-1-1".into()], true, &CveSource::default());
        assert!(none.unreachable());
        assert_eq!(none.overview(), "1 CVE");
    }

    #[test]
    fn exploitation_cells() {
        let mut record = citrix_bleed();
        assert_eq!(
            exploitation(&record),
            "**Known exploited**<br>CISA KEV, 2023-10-18"
        );
        record.kev_added = None;
        assert_eq!(exploitation(&record), "**Active**<br>CISA SSVC");
        for (state, cell) in [
            ("poc", "Proof of concept<br>CISA SSVC"),
            ("public poc", "Proof of concept<br>CISA SSVC"),
            ("NONE", "None reported<br>CISA SSVC"),
            ("other", "-"),
        ] {
            record.exploitation = Some(state.into());
            assert_eq!(exploitation(&record), cell);
        }
    }

    #[test]
    fn detail_lines() {
        assert_eq!(
            detail_line(&citrix_bleed()),
            "- **CVE-2023-4966**: Unauthenticated sensitive information disclosure. Affects \
             Citrix NetScaler ADC, Citrix NetScaler Gateway. Vector \
             `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`."
        );
        let many = CveRecord {
            identifier: "CVE-1-1".into(),
            description: Some("Ends with a dot.".into()),
            affected: (1..=6).map(|n| format!("p{n}")).collect(),
            ..CveRecord::default()
        };
        assert_eq!(
            detail_line(&many),
            "- **CVE-1-1**: Ends with a dot. Affects p1, p2, p3, p4 and 2 more."
        );
        let bare = CveRecord {
            identifier: "CVE-1-2".into(),
            ..CveRecord::default()
        };
        assert_eq!(detail_line(&bare), "- **CVE-1-2**: no summary.");
    }
}
