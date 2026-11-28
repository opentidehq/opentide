//! `cargo xtask coverage gate`: line coverage per workspace crate against the
//! gates of `xtask/coverage.toml` (plan §5.4 "Strength", UC-X.2 #844).
//!
//! cargo-llvm-cov measures the whole workspace in one run and exports one
//! summary per source file (`cargo llvm-cov report --json --summary-only`).
//! This module assigns each file to the workspace member whose directory holds
//! it, sums the lines per member and compares each sum with the member's gate:
//! the policy's per-crate gate, or its default. It reads no file and runs no
//! process; `main.rs` does.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The gates, as `xtask/coverage.toml` writes them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The line-coverage gate, in percent, of every member the policy does
    /// not name.
    pub default_lines: u8,
    /// The crates whose gate is higher than the default.
    #[serde(default)]
    pub gate: Vec<Gate>,
}

/// One crate's gate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    /// The package name.
    #[serde(rename = "crate")]
    pub krate: String,
    /// The line-coverage gate, in percent; never below the default.
    pub lines: u8,
    /// The work item that creates the crate, while it is not a workspace
    /// member yet (`"UC-1.1 (#807)"`). The gate applies as soon as the crate
    /// is a member, whether or not this is still set.
    #[serde(default)]
    pub item: Option<String>,
}

impl Policy {
    /// Reads `xtask/coverage.toml`.
    ///
    /// # Errors
    ///
    /// The text is not TOML of that shape.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

/// A mistake in the policy itself: the gate does not run on a policy that
/// has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// A percentage above 100.
    OutOfRange {
        /// The crate, or `default_lines`.
        what: String,
        /// The value written.
        lines: u8,
    },
    /// A per-crate gate below the default: a loosening, which this file
    /// never holds.
    BelowDefault {
        /// The crate.
        krate: String,
        /// Its gate.
        lines: u8,
        /// The default.
        default: u8,
    },
    /// A crate named twice.
    Duplicate {
        /// The crate.
        krate: String,
    },
    /// A crate that is not a workspace member and names no work item: a
    /// typo, or a crate that was removed.
    Stale {
        /// The crate.
        krate: String,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { what, lines } => {
                write!(f, "`{what}` is {lines}%: a gate is a percentage, 0 to 100")
            }
            Self::BelowDefault {
                krate,
                lines,
                default,
            } => write!(
                f,
                "`{krate}` has a gate of {lines}%, below the default of {default}%: \
                 the policy never loosens a crate's gate"
            ),
            Self::Duplicate { krate } => write!(f, "the policy names `{krate}` more than once"),
            Self::Stale { krate } => write!(
                f,
                "the policy names `{krate}`, which is not a workspace member, and no `item` \
                 that creates it: remove the entry, or name the work item"
            ),
        }
    }
}

/// A workspace member: its name and the directory of its manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The package name.
    pub name: String,
    /// The directory that holds its `Cargo.toml`.
    pub dir: PathBuf,
}

/// The part of `cargo metadata --format-version 1 --no-deps` the gate reads.
#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Package {
    id: String,
    name: String,
    manifest_path: PathBuf,
}

/// The workspace members `cargo metadata` lists, by name.
///
/// # Errors
///
/// The text is not that JSON document.
pub fn members(metadata_json: &str) -> Result<Vec<Member>, serde_json::Error> {
    let metadata: Metadata = serde_json::from_str(metadata_json)?;
    let mut members: Vec<Member> = metadata
        .packages
        .into_iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| Member {
            name: package.name,
            dir: package
                .manifest_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default(),
        })
        .collect();
    members.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(members)
}

/// One source file's line counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileLines {
    /// The absolute path llvm-cov reports.
    pub path: PathBuf,
    /// Lines with code.
    pub count: u64,
    /// Lines with code that ran.
    pub covered: u64,
}

#[derive(Debug, Deserialize)]
struct Export {
    data: Vec<ExportData>,
}

#[derive(Debug, Deserialize)]
struct ExportData {
    files: Vec<ExportFile>,
}

#[derive(Debug, Deserialize)]
struct ExportFile {
    filename: PathBuf,
    summary: ExportSummary,
}

#[derive(Debug, Deserialize)]
struct ExportSummary {
    lines: ExportCount,
}

#[derive(Debug, Deserialize)]
struct ExportCount {
    count: u64,
    covered: u64,
}

/// Reads the JSON export `cargo llvm-cov report --json` writes (llvm-cov's
/// `llvm.coverage.json.export`; `--summary-only` is enough).
///
/// # Errors
///
/// The text is not that document.
pub fn files(export_json: &str) -> Result<Vec<FileLines>, serde_json::Error> {
    let export: Export = serde_json::from_str(export_json)?;
    Ok(export
        .data
        .into_iter()
        .flat_map(|data| data.files)
        .map(|file| FileLines {
            path: file.filename,
            count: file.summary.lines.count,
            covered: file.summary.lines.covered,
        })
        .collect())
}

/// One crate's line in the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The package name.
    pub krate: String,
    /// Its gate, in percent.
    pub gate: u8,
    /// What the gate found.
    pub status: Status,
}

/// What the gate found for one crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Measured: lines with code, and those that ran.
    Measured {
        /// Lines with code.
        count: u64,
        /// Lines that ran.
        covered: u64,
    },
    /// A member none of whose lines the run measured: on this target the
    /// tests compile none of its code. It fails, so a crate cannot pass
    /// by having nothing measured.
    Unmeasured,
    /// Not a workspace member yet: the gate waits for the work item that
    /// creates the crate.
    Pending {
        /// That work item.
        item: String,
    },
}

impl Row {
    /// Whether the crate meets its gate. A pending crate does not hold the
    /// gate back.
    pub fn passed(&self) -> bool {
        match self.status {
            // covered / count >= gate / 100, in integers.
            Status::Measured { count, covered } => {
                count > 0 && u128::from(covered) * 100 >= u128::from(count) * u128::from(self.gate)
            }
            Status::Unmeasured => false,
            Status::Pending { .. } => true,
        }
    }
}

/// What the gate found.
#[derive(Debug, Default)]
pub struct Report {
    /// One row per workspace member and per pending crate, by name.
    pub rows: Vec<Row>,
    /// The lines of every member, summed.
    pub total_count: u64,
    /// The lines of every member that ran, summed.
    pub total_covered: u64,
    /// Files of the export under no member's directory (none in a run of
    /// this workspace; reported so that a path mismatch cannot pass quietly).
    pub outside: Vec<PathBuf>,
}

impl Report {
    /// Whether every crate meets its gate and every file was placed.
    pub fn passed(&self) -> bool {
        self.outside.is_empty() && self.rows.iter().all(Row::passed)
    }

    /// The report as Markdown: a table for the job summary, then one line
    /// per failure.
    pub fn markdown(&self) -> String {
        let mut out = String::from(
            "## Rust line coverage per crate\n\n\
             | Crate | Lines covered | Coverage | Gate | Result |\n\
             |-------|--------------:|---------:|-----:|--------|\n",
        );
        for row in &self.rows {
            let (lines, percent) = match row.status {
                Status::Measured { count, covered } => {
                    (format!("{covered} / {count}"), percent(covered, count))
                }
                Status::Unmeasured => ("0 / 0".to_owned(), "n/a".to_owned()),
                Status::Pending { .. } => (String::new(), String::new()),
            };
            let result = match &row.status {
                Status::Pending { item } => format!("pending: {item} creates it"),
                Status::Unmeasured => "**fail**: no line measured".to_owned(),
                Status::Measured { .. } if row.passed() => "pass".to_owned(),
                Status::Measured { .. } => "**fail**".to_owned(),
            };
            let _ = writeln!(
                out,
                "| `{}` | {lines} | {percent} | {}% | {result} |",
                row.krate, row.gate
            );
        }
        let _ = writeln!(
            out,
            "| **workspace** | {} / {} | {} | | |",
            self.total_covered,
            self.total_count,
            percent(self.total_covered, self.total_count)
        );
        for path in &self.outside {
            let _ = writeln!(
                out,
                "\nerror: `{}` is under no workspace member's directory",
                path.display()
            );
        }
        let failed: Vec<&Row> = self.rows.iter().filter(|row| !row.passed()).collect();
        if failed.is_empty() && self.outside.is_empty() {
            out.push_str("\nEvery crate meets its gate.\n");
        } else {
            for row in failed {
                let _ = writeln!(
                    out,
                    "\nerror: `{}` is below its gate of {}% lines",
                    row.krate, row.gate
                );
            }
        }
        out
    }
}

/// A percentage with two decimals, rounded down so that a crate just under
/// its gate never prints as meeting it.
fn percent(covered: u64, count: u64) -> String {
    if count == 0 {
        return "n/a".to_owned();
    }
    let hundredths = u128::from(covered) * 10_000 / u128::from(count);
    format!("{}.{:02}%", hundredths / 100, hundredths % 100)
}

/// Checks the policy against the workspace's members: every error, in order.
pub fn check_policy(policy: &Policy, members: &[Member]) -> Vec<PolicyError> {
    let names: BTreeSet<&str> = members.iter().map(|m| m.name.as_str()).collect();
    let mut errors = Vec::new();
    if policy.default_lines > 100 {
        errors.push(PolicyError::OutOfRange {
            what: "default_lines".to_owned(),
            lines: policy.default_lines,
        });
    }
    let mut seen = BTreeSet::new();
    for gate in &policy.gate {
        if !seen.insert(gate.krate.as_str()) {
            errors.push(PolicyError::Duplicate {
                krate: gate.krate.clone(),
            });
        }
        if gate.lines > 100 {
            errors.push(PolicyError::OutOfRange {
                what: gate.krate.clone(),
                lines: gate.lines,
            });
        }
        if gate.lines < policy.default_lines {
            errors.push(PolicyError::BelowDefault {
                krate: gate.krate.clone(),
                lines: gate.lines,
                default: policy.default_lines,
            });
        }
        if !names.contains(gate.krate.as_str()) && gate.item.is_none() {
            errors.push(PolicyError::Stale {
                krate: gate.krate.clone(),
            });
        }
    }
    errors
}

/// Sums the export's lines per member and compares each with its gate. Run
/// [`check_policy`] first: this trusts the policy.
pub fn gate(policy: &Policy, members: &[Member], files: &[FileLines]) -> Report {
    // Longest directory first, so that a member nested in another's
    // directory takes its own files.
    let mut by_depth: Vec<&Member> = members.iter().collect();
    by_depth.sort_by_key(|member| std::cmp::Reverse(member.dir.components().count()));

    let mut sums: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut report = Report::default();
    for file in files {
        match by_depth.iter().find(|m| file.path.starts_with(&m.dir)) {
            Some(member) => {
                let sum = sums.entry(member.name.as_str()).or_default();
                sum.0 += file.count;
                sum.1 += file.covered;
            }
            None => report.outside.push(file.path.clone()),
        }
    }

    let gates: BTreeMap<&str, &Gate> = policy
        .gate
        .iter()
        .map(|gate| (gate.krate.as_str(), gate))
        .collect();
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    for member in members {
        let gate = gates
            .get(member.name.as_str())
            .map_or(policy.default_lines, |gate| gate.lines);
        let status = match sums.get(member.name.as_str()) {
            Some(&(count, covered)) if count > 0 => {
                report.total_count += count;
                report.total_covered += covered;
                Status::Measured { count, covered }
            }
            _ => Status::Unmeasured,
        };
        rows.insert(
            member.name.clone(),
            Row {
                krate: member.name.clone(),
                gate,
                status,
            },
        );
    }
    for gate in &policy.gate {
        if let (false, Some(item)) = (rows.contains_key(&gate.krate), &gate.item) {
            rows.insert(
                gate.krate.clone(),
                Row {
                    krate: gate.krate.clone(),
                    gate: gate.lines,
                    status: Status::Pending { item: item.clone() },
                },
            );
        }
    }
    report.rows = rows.into_values().collect();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, dir: &str) -> Member {
        Member {
            name: name.to_owned(),
            dir: PathBuf::from(dir),
        }
    }

    fn file(path: &str, count: u64, covered: u64) -> FileLines {
        FileLines {
            path: PathBuf::from(path),
            count,
            covered,
        }
    }

    fn policy(text: &str) -> Policy {
        Policy::parse(text).unwrap()
    }

    const POLICY: &str = r#"
default_lines = 80

[[gate]]
crate = "schema"
lines = 90

[[gate]]
crate = "cli"
lines = 90
item = "UC-3.3 (#825)"
"#;

    fn workspace() -> Vec<Member> {
        vec![
            member("core", "/w/crates/core"),
            member("schema", "/w/crates/schema"),
        ]
    }

    #[test]
    fn sums_files_per_member_and_applies_each_gate() {
        let report = gate(
            &policy(POLICY),
            &workspace(),
            &[
                file("/w/crates/core/src/lib.rs", 60, 50),
                file("/w/crates/core/src/a.rs", 40, 30),
                file("/w/crates/schema/src/lib.rs", 100, 89),
            ],
        );
        assert_eq!(
            report.rows,
            vec![
                Row {
                    krate: "cli".into(),
                    gate: 90,
                    status: Status::Pending {
                        item: "UC-3.3 (#825)".into()
                    }
                },
                Row {
                    krate: "core".into(),
                    gate: 80,
                    status: Status::Measured {
                        count: 100,
                        covered: 80
                    }
                },
                Row {
                    krate: "schema".into(),
                    gate: 90,
                    status: Status::Measured {
                        count: 100,
                        covered: 89
                    }
                },
            ]
        );
        // core meets 80% exactly; schema misses 90% by one line.
        assert!(report.rows[1].passed());
        assert!(!report.rows[2].passed());
        assert!(!report.passed());
        assert_eq!((report.total_count, report.total_covered), (200, 169));
    }

    #[test]
    fn the_gate_compares_exactly_not_after_rounding() {
        let row = |count, covered| Row {
            krate: "x".into(),
            gate: 80,
            status: Status::Measured { count, covered },
        };
        // 79.999...% fails; 80% passes.
        assert!(!row(100_000, 79_999).passed());
        assert!(row(100_000, 80_000).passed());
        assert_eq!(percent(79_999, 100_000), "79.99%");
        assert_eq!(percent(2, 3), "66.66%");
    }

    #[test]
    fn a_member_with_no_measured_line_fails() {
        let report = gate(
            &policy("default_lines = 80"),
            &workspace(),
            &[file("/w/crates/core/src/lib.rs", 10, 10)],
        );
        assert_eq!(report.rows[1].status, Status::Unmeasured);
        assert!(!report.passed());
        // A file whose lines are all zero counts as unmeasured too.
        let report = gate(
            &policy("default_lines = 80"),
            &[member("core", "/w/crates/core")],
            &[file("/w/crates/core/src/lib.rs", 0, 0)],
        );
        assert_eq!(report.rows[0].status, Status::Unmeasured);
    }

    #[test]
    fn a_file_outside_every_member_fails_the_gate() {
        let report = gate(
            &policy("default_lines = 0"),
            &[member("core", "/w/crates/core")],
            &[
                file("/w/crates/core/src/lib.rs", 10, 10),
                file("/elsewhere/lib.rs", 10, 10),
            ],
        );
        assert_eq!(report.outside, vec![PathBuf::from("/elsewhere/lib.rs")]);
        assert!(!report.passed());
        assert!(report.markdown().contains("under no workspace member"));
    }

    #[test]
    fn a_nested_member_takes_its_own_files() {
        let report = gate(
            &policy("default_lines = 50"),
            &[member("outer", "/w/a"), member("inner", "/w/a/inner")],
            &[
                file("/w/a/src/lib.rs", 10, 10),
                file("/w/a/inner/src/lib.rs", 10, 0),
            ],
        );
        let inner = report.rows.iter().find(|r| r.krate == "inner").unwrap();
        assert_eq!(
            inner.status,
            Status::Measured {
                count: 10,
                covered: 0
            }
        );
        // Component-wise prefixes: /w/ab is not inside /w/a.
        let report = gate(
            &policy("default_lines = 50"),
            &[member("a", "/w/a")],
            &[file("/w/ab/src/lib.rs", 1, 1)],
        );
        assert_eq!(report.outside.len(), 1);
    }

    #[test]
    fn the_policy_never_holds_a_loosening_or_a_stale_entry() {
        let errors = check_policy(
            &policy(
                r#"
default_lines = 80
[[gate]]
crate = "core"
lines = 70
[[gate]]
crate = "core"
lines = 101
[[gate]]
crate = "gone"
lines = 90
[[gate]]
crate = "future"
lines = 90
item = "UC-9.9"
"#,
            ),
            &workspace(),
        );
        assert_eq!(
            errors,
            vec![
                PolicyError::BelowDefault {
                    krate: "core".into(),
                    lines: 70,
                    default: 80
                },
                PolicyError::Duplicate {
                    krate: "core".into()
                },
                PolicyError::OutOfRange {
                    what: "core".into(),
                    lines: 101
                },
                PolicyError::Stale {
                    krate: "gone".into()
                },
            ]
        );
        assert!(check_policy(&policy(POLICY), &workspace()).is_empty());
        assert!(Policy::parse("default_lines = 80\nfloor = 1").is_err());
    }

    #[test]
    fn a_pending_gate_applies_once_the_crate_is_a_member() {
        // `cli` still names its work item, but it is a member now: measured.
        let report = gate(
            &policy(POLICY),
            &[member("cli", "/w/crates/cli")],
            &[file("/w/crates/cli/src/main.rs", 10, 8)],
        );
        let cli = report.rows.iter().find(|r| r.krate == "cli").unwrap();
        assert_eq!(cli.gate, 90);
        assert!(!cli.passed());
    }

    #[test]
    fn reads_cargo_metadata_and_the_llvm_cov_export() {
        let members = members(
            r#"{"packages": [
                {"id": "a 0.1", "name": "a", "manifest_path": "/w/a/Cargo.toml"},
                {"id": "dep 1.0", "name": "dep", "manifest_path": "/reg/dep/Cargo.toml"}
            ], "workspace_members": ["a 0.1"]}"#,
        )
        .unwrap();
        assert_eq!(members, vec![member("a", "/w/a")]);
        let files = files(
            r#"{"type": "llvm.coverage.json.export", "version": "2.0.1", "data": [{"files": [
                {"filename": "/w/a/src/lib.rs", "summary": {"lines": {"count": 4, "covered": 3, "percent": 75.0}}}
            ], "totals": {}}]}"#,
        )
        .unwrap();
        assert_eq!(files, vec![file("/w/a/src/lib.rs", 4, 3)]);
    }

    #[test]
    fn the_markdown_lists_every_crate_and_each_failure() {
        let report = gate(
            &policy(POLICY),
            &workspace(),
            &[
                file("/w/crates/core/src/lib.rs", 10, 9),
                file("/w/crates/schema/src/lib.rs", 10, 5),
            ],
        );
        let text = report.markdown();
        assert!(
            text.contains("| `core` | 9 / 10 | 90.00% | 80% | pass |"),
            "{text}"
        );
        assert!(
            text.contains("| `schema` | 5 / 10 | 50.00% | 90% | **fail** |"),
            "{text}"
        );
        assert!(
            text.contains("| `cli` |  |  | 90% | pending: UC-3.3 (#825) creates it |"),
            "{text}"
        );
        assert!(
            text.contains("error: `schema` is below its gate of 90% lines"),
            "{text}"
        );
    }
}
