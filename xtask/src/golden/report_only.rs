//! The catch-up train's report-only goldens (the plan's §4, "Golden oracle
//! move"): while the train carries platforms ported from opentide 0.24–0.28
//! and the oracle is still 0.23.0, every port adds explain pages and codes,
//! which change `explain list` and the SARIF rule catalogues the recordings
//! hold. The differences are expected, and the ledger cannot carry them one
//! port at a time: approving each added code by its index would conflict
//! between the ports and go stale at O2, which re-records every case from
//! the 0.28.x oracle.
//!
//! So the train commits [`MARKER`]: while it is there, the golden-diff
//! gates print every difference as a full report and pass. Nothing else is
//! relaxed — the unit, fixture and cassette tests, and the ledger's own
//! check (`cargo xtask compare --check-ledger`), still gate.
//!
//! The marker belongs to the train alone. [`refuse_on_integration`] is the
//! guard CI runs on every pull request: a pull request into
//! `integration/unified-core` (or the trunk) with the marker present fails,
//! so gating can never be turned off there.

use std::path::{Path, PathBuf};

/// The marker, relative to the repository root.
pub const MARKER: &str = "tests/golden/REPORT_ONLY";

/// The bases that never take the marker: gating is on there.
pub const GATED_BASES: [&str; 2] = ["integration/unified-core", "development"];

/// Where the marker would be in `repo`.
pub fn marker_path(repo: &Path) -> PathBuf {
    repo.join(MARKER)
}

/// Whether `repo` is report-only: the marker is committed there.
pub fn enabled(repo: &Path) -> bool {
    marker_path(repo).is_file()
}

/// What a report-only run prints instead of failing, given how many
/// differences it found and where the report was written.
pub fn verdict(differences: usize, report: Option<&Path>) -> String {
    let mut text = format!(
        "golden: {differences} difference(s) from the oracle; {MARKER} is present, so this run \
         reports them instead of failing (the catch-up train: the oracle moves to 0.28.x at O2, \
         which re-records every case)"
    );
    if let Some(report) = report {
        text.push_str(&format!("\nthe full report is {}", report.display()));
    }
    text
}

/// Why a pull request into `base` must not carry the marker, or `None` when
/// it may (the train's own branches).
pub fn refuse_on_integration(base: &str) -> Option<String> {
    GATED_BASES.contains(&base).then(|| {
        format!(
            "{MARKER} is committed, and this pull request targets {base}, where the goldens \
             gate: the marker belongs to the catch-up train alone. Remove it (O2 removes it for \
             good) before merging there."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_turns_a_repository_report_only() {
        let repo = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir_all(repo.path().join("tests/golden")).expect("tests/golden");
        assert!(!enabled(repo.path()));
        std::fs::write(marker_path(repo.path()), "why\n").expect("the marker");
        assert!(enabled(repo.path()));
        // A directory of that name is not the marker.
        let other = tempfile::tempdir().expect("a temporary directory");
        std::fs::create_dir_all(marker_path(other.path())).expect("a directory");
        assert!(!enabled(other.path()));
    }

    #[test]
    fn the_verdict_names_the_marker_and_the_report() {
        let text = verdict(7, None);
        assert!(
            text.starts_with("golden: 7 difference(s) from the oracle; "),
            "{text}"
        );
        assert!(text.contains(MARKER), "{text}");
        assert!(!text.contains("the full report is"), "{text}");
        let text = verdict(1, Some(Path::new("golden-compare.json")));
        assert!(
            text.ends_with("the full report is golden-compare.json"),
            "{text}"
        );
    }

    #[test]
    fn the_guard_refuses_the_gated_bases_only() {
        for base in GATED_BASES {
            let message = refuse_on_integration(base).unwrap_or_default();
            assert!(message.contains(base), "{message}");
            assert!(message.contains(MARKER), "{message}");
        }
        assert_eq!(refuse_on_integration("train/catchup-0.28"), None);
        assert_eq!(refuse_on_integration("feat/platform-exabeam"), None);
    }
}
