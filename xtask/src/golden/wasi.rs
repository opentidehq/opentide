//! The cases `golden check --runner wasi` leaves out (ADR 0007's amendment):
//! the WASI build of the command line has no network (`wasm32-wasip1` has no
//! sockets), so a case that needs one cannot pass there, and only such a case
//! may be left out.
//!
//! A case with a cassette (recorded HTTP, UC-4.1) needs the network by its
//! nature and is left out without being listed. Every other case left out is
//! listed in `tests/golden/WASI_EXCLUDED.toml` with its reason, and each
//! entry must name cases that show they need the network: a fixture with
//! tenants, a MISP instance or CVE lookups, a command that sends requests,
//! or a recording in which the oracle's own request was refused
//! ([`needs_network`]). The tests hold the committed list to that.
//!
//! The one other reason a case may be left out is a capability WASI preview 1
//! does not have at all ([`LIMITS`]): an entry that says so (`limit`) names
//! it, and no other limit is accepted.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::case::Case;

/// The fixtures whose cases reach a tenant, a MISP instance or
/// Vulnerability-Lookup (`[fixtures]` in `cases.toml`), by prefix.
pub const NETWORK_FIXTURES: &[&str] = &[
    "tenants",
    "live-tenants",
    "deploy-tenants",
    "deploy-push",
    "share-misp",
    "tide-corpus-cve",
];

/// The commands that send requests whatever their fixture, by prefix.
pub const NETWORK_COMMANDS: &[&str] = &[
    "query",
    "share",
    "generate extract",
    "setup skills",
    "plugin",
];

/// What the oracle prints when the harness refuses one of its requests (every
/// case runs behind a proxy that refuses, unless a cassette serves it): a
/// recording that holds one of these shows its case sent a request.
pub const REFUSED_REQUEST: &[&str] = &["ProxyError", "HTTPSConnectionPool"];

/// The capabilities WASI preview 1 does not have that a case may need, as an
/// entry's `limit` names them: running another program (`git --version`),
/// and file permissions (a hook's executable bit).
pub const LIMITS: &[&str] = &["process", "permissions"];

/// `tests/golden/WASI_EXCLUDED.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exclusions {
    /// The entries, in the file's order.
    #[serde(default, rename = "case")]
    pub cases: Vec<Entry>,
}

/// One entry: the cases it leaves out and why.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// A glob over case ids (`<command>/<mode>/<fixture>/<variant>`), as
    /// `--filter` reads one.
    pub id: String,
    /// Why the case needs the network, or the capability it needs.
    pub reason: String,
    /// The capability of [`LIMITS`] the cases need, which WASI preview 1
    /// does not have; absent for network cases.
    #[serde(default)]
    pub limit: Option<String>,
}

impl Exclusions {
    /// Reads the list from its TOML text.
    ///
    /// # Errors
    ///
    /// The text is not the list's format, or an entry's glob does not parse.
    pub fn parse(text: &str) -> Result<Exclusions> {
        let exclusions: Exclusions = toml::from_str(text).context("WASI_EXCLUDED.toml")?;
        for entry in &exclusions.cases {
            glob::Pattern::new(&entry.id).with_context(|| format!("entry `{}`", entry.id))?;
            if entry.reason.trim().is_empty() {
                bail!("entry `{}` gives no reason", entry.id);
            }
            if let Some(limit) = &entry.limit
                && !LIMITS.contains(&limit.as_str())
            {
                bail!(
                    "entry `{}`: `{limit}` is not a capability WASI preview 1 lacks ({})",
                    entry.id,
                    LIMITS.join(", ")
                );
            }
        }
        Ok(exclusions)
    }

    /// Why `case` is left out of a WASI run, or `None` when it runs.
    pub fn reason(&self, case: &Case) -> Option<String> {
        if let Some(cassette) = &case.cassette {
            return Some(format!(
                "its requests are served from a cassette ({cassette}): it needs the network"
            ));
        }
        self.cases
            .iter()
            .find(|entry| matches(&entry.id, &case.id))
            .map(|entry| entry.reason.clone())
    }

    /// The entries that break the rules: an entry that leaves out no case of
    /// `all`, or one of whose cases shows no need of the network.
    /// `recordings` is the cases' folder (`tests/golden/cases`).
    pub fn problems(&self, all: &[Case], recordings: &std::path::Path) -> Vec<String> {
        let mut problems = Vec::new();
        for entry in &self.cases {
            let named: Vec<&Case> = all
                .iter()
                .filter(|case| matches(&entry.id, &case.id))
                .collect();
            if named.is_empty() {
                problems.push(format!("`{}` names no case", entry.id));
            }
            for case in named {
                if entry.limit.is_some() {
                    continue;
                }
                if case.cassette.is_none() && !needs_network(case, recordings) {
                    problems.push(format!(
                        "`{}` leaves out {}, which shows no need of the network: \
                         only network cases may be left out of the WASI run",
                        entry.id, case.id
                    ));
                }
            }
        }
        problems
    }
}

/// Whether `case` shows it needs the network: its fixture reaches tenants,
/// MISP or CVE lookups, its command sends requests, or its recording under
/// `recordings` shows the oracle's request refused ([`REFUSED_REQUEST`]).
pub fn needs_network(case: &Case, recordings: &std::path::Path) -> bool {
    NETWORK_FIXTURES
        .iter()
        .any(|fixture| case.fixture.starts_with(fixture))
        || NETWORK_COMMANDS.iter().any(|command| {
            case.command == *command || case.command.starts_with(&format!("{command} "))
        })
        || ["stdout", "stderr"].iter().any(|stream| {
            std::fs::read(recordings.join(&case.id).join(stream)).is_ok_and(|bytes| {
                let text = String::from_utf8_lossy(&bytes);
                REFUSED_REQUEST.iter().any(|marker| text.contains(marker))
            })
        })
}

/// Whether the glob `pattern` matches case id `id`, as `--filter` matches.
fn matches(pattern: &str, id: &str) -> bool {
    let options = glob::MatchOptions {
        require_literal_separator: true,
        ..glob::MatchOptions::new()
    };
    glob::Pattern::new(pattern).is_ok_and(|pattern| {
        id.match_indices('/')
            .map(|(end, _)| &id[..end])
            .chain([id])
            .any(|prefix| pattern.matches_with(prefix, options))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::golden::case::Spec;

    fn repository_cases() -> Vec<Case> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join("tests/golden/cases.toml")).unwrap();
        Spec::parse(&text).unwrap().expand().unwrap()
    }

    #[test]
    fn the_committed_list_leaves_out_network_cases_only() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join("tests/golden/WASI_EXCLUDED.toml")).unwrap();
        let exclusions = Exclusions::parse(&text).unwrap();
        assert_eq!(
            exclusions.problems(&repository_cases(), &root.join("tests/golden/cases")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_case_that_needs_no_network_cannot_be_left_out() {
        let cases = repository_cases();
        let exclusions = Exclusions::parse(
            "[[case]]\nid = \"validate/*\"\nreason = \"slow\"\n[[case]]\nid = \"nope/*\"\nreason = \"x\"\n",
        )
        .unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let problems = exclusions.problems(&cases, &root.join("tests/golden/cases"));
        assert!(
            problems.iter().any(|p| p.contains("only network cases")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("`nope/*` names no case")),
            "{problems:?}"
        );
    }

    #[test]
    fn cassette_cases_are_left_out_unlisted() {
        let cases = repository_cases();
        let exclusions = Exclusions::default();
        let with_cassette = cases.iter().find(|case| case.cassette.is_some()).unwrap();
        assert!(
            exclusions
                .reason(with_cassette)
                .unwrap()
                .contains("cassette")
        );
        let validate = cases
            .iter()
            .find(|case| case.command == "validate")
            .unwrap();
        assert_eq!(exclusions.reason(validate), None);
    }

    #[test]
    fn a_recorded_refused_request_is_evidence_of_the_network() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let recordings = root.join("tests/golden/cases");
        let cases = repository_cases();
        let case = |id: &str| cases.iter().find(|case| case.id == id).unwrap();
        // `doctor` asks PyPI for the newest release; `--offline` does not.
        assert!(needs_network(
            case("doctor/json/tide-corpus/default"),
            &recordings
        ));
        assert!(!needs_network(
            case("doctor/json/tide-corpus/offline"),
            &recordings
        ));
        assert!(!needs_network(
            case("validate/json/tide-corpus/default"),
            &recordings
        ));
    }

    #[test]
    fn only_the_capabilities_wasi_lacks_are_limits() {
        let ok = Exclusions::parse(
            "[[case]]\nid = \"setup.hooks/*\"\nreason = \"chmod\"\nlimit = \"permissions\"\n",
        )
        .unwrap();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(
            ok.problems(&repository_cases(), &root.join("tests/golden/cases")),
            Vec::<String>::new()
        );
        assert!(
            Exclusions::parse(
                "[[case]]\nid = \"validate/*\"\nreason = \"slow\"\nlimit = \"speed\"\n"
            )
            .is_err()
        );
    }

    #[test]
    fn an_entry_needs_a_reason() {
        assert!(Exclusions::parse("[[case]]\nid = \"query/*\"\nreason = \" \"\n").is_err());
        assert!(Exclusions::parse("[[case]]\nid = \"query/*\"\n").is_err());
    }
}
