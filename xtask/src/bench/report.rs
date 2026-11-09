//! The result of one `cargo xtask bench` run: the JSON document that
//! `--json` prints, that CI keeps as an artifact and that `--check` reads.
//!
//! Times are seconds (`f64`), memory is bytes (`u64`): the peak resident set
//! size `wait4(2)` reports for the process and the children it waited for.

use serde::{Deserialize, Serialize};

/// The version of this document's shape. A change that a reader of an older
/// artifact would misread bumps it; `--check` refuses a version it does not
/// know rather than compare unlike numbers.
pub const SCHEMA_VERSION: u32 = 1;

/// One run of the benchmarks.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// [`SCHEMA_VERSION`] when it was written.
    pub schema_version: u32,
    /// `python` (the oracle) or `rust`.
    pub engine: String,
    /// The heavy workspace's size: 1 (300 threats, 300 objectives, 500 rules)
    /// or 10.
    pub scale: u32,
    /// The heavy workspace's generator seed; `None` when the run measured a
    /// workspace of its own (`--workspace`), which nothing compares with.
    pub seed: Option<u64>,
    /// Measured runs per command; the median is over these.
    pub runs: u32,
    /// Unmeasured runs per command before them.
    pub warmup: u32,
    /// What ran for the `python` engine: `opentide 0.23.0`, or the path given
    /// with `--opentide`. `None` for `rust`.
    pub oracle: Option<String>,
    /// The machine.
    pub host: Host,
    /// The heavy workspace's digest (`cargo xtask corpus generate --digest`):
    /// the generator's output, which a seed alone does not pin once the
    /// generator changes. `None` for a workspace of one's own.
    #[serde(default)]
    pub workspace_digest: Option<String>,
    /// The commit benchmarked, when git could say.
    pub git_sha: Option<String>,
    /// When the run finished, in seconds since the Unix epoch.
    pub created_unix: u64,
    /// One entry per command, in the order they ran.
    pub results: Vec<CommandResult>,
}

/// The machine a report was measured on, so that a comparison between two
/// runners can be told apart from a regression.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Host {
    /// `std::env::consts::OS`.
    pub os: String,
    /// `std::env::consts::ARCH`.
    pub arch: String,
    /// The CPUs this process may use.
    pub cpus: usize,
    /// `model name` in `/proc/cpuinfo`, when there is one.
    pub cpu_model: Option<String>,
    /// `MemTotal` in `/proc/meminfo`, in bytes.
    pub memory_bytes: Option<u64>,
    /// The GitHub-hosted runner image (`ImageOS` and `ImageVersion`), when
    /// the run was on one.
    pub runner_image: Option<String>,
}

/// What became of one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// It ran `runs` times and every run ended as expected.
    Measured,
    /// The engine has no implementation of it yet ("no Rust yet").
    NotImplemented,
}

/// One command's numbers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommandResult {
    /// The stable id budgets and earlier results are matched on, such as
    /// `validate_clean`.
    pub id: String,
    /// What ran, for a reader: `opentide --json validate`.
    pub command: String,
    /// Whether it was measured.
    pub status: Status,
    /// Why it was not measured, or what to know about the number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The median wall time of the measured runs, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub median_s: Option<f64>,
    /// The median peak RSS of the measured runs, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_rss_bytes: Option<u64>,
    /// Every measured run's wall time, in seconds, in the order they ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub samples_s: Vec<f64>,
    /// Every measured run's peak RSS, in bytes, in the order they ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub samples_rss_bytes: Vec<u64>,
}

impl CommandResult {
    /// A command the engine does not implement yet.
    pub fn not_implemented(id: &str, command: &str, note: &str) -> Self {
        Self {
            id: id.to_owned(),
            command: command.to_owned(),
            status: Status::NotImplemented,
            note: Some(note.to_owned()),
            median_s: None,
            peak_rss_bytes: None,
            samples_s: Vec::new(),
            samples_rss_bytes: Vec::new(),
        }
    }

    /// A measured command, its medians taken from the samples.
    pub fn measured(id: &str, command: &str, samples: &[Sample], note: Option<String>) -> Self {
        let samples_s: Vec<f64> = samples.iter().map(|s| s.wall_s).collect();
        let samples_rss_bytes: Vec<u64> = samples.iter().map(|s| s.peak_rss_bytes).collect();
        Self {
            id: id.to_owned(),
            command: command.to_owned(),
            status: Status::Measured,
            note,
            median_s: median_f64(&samples_s),
            peak_rss_bytes: median_u64(&samples_rss_bytes),
            samples_s,
            samples_rss_bytes,
        }
    }
}

/// One process run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    /// Wall time from before the spawn to after `wait4` returned, in seconds
    /// (for the language server: to its first diagnostics).
    pub wall_s: f64,
    /// Peak RSS of the process and the children it waited for, in bytes.
    pub peak_rss_bytes: u64,
}

/// The median: the middle value of an odd count, the mean of the two middle
/// values of an even one. `None` for no values or a NaN among them.
pub fn median_f64(values: &[f64]) -> Option<f64> {
    if values.is_empty() || values.iter().any(|v| v.is_nan()) {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    Some(if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        f64::midpoint(sorted[mid - 1], sorted[mid])
    })
}

/// [`median_f64`] for whole numbers; an even count's two middle values are
/// averaged, rounding down.
pub fn median_u64(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    Some(if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        sorted[mid - 1].midpoint(sorted[mid])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_median_of_an_odd_count_is_the_middle_value() {
        assert_eq!(median_f64(&[5.0, 1.0, 3.0, 2.0, 100.0]), Some(3.0));
        assert_eq!(median_u64(&[9, 1, 4]), Some(4));
    }

    #[test]
    fn the_median_of_an_even_count_is_the_mean_of_the_middle_two() {
        assert_eq!(median_f64(&[4.0, 1.0, 3.0, 2.0]), Some(2.5));
        assert_eq!(median_u64(&[1, 2, 3, 6]), Some(2));
    }

    #[test]
    fn no_values_or_a_nan_has_no_median() {
        assert_eq!(median_f64(&[]), None);
        assert_eq!(median_f64(&[1.0, f64::NAN, 2.0]), None);
        assert_eq!(median_u64(&[]), None);
    }

    #[test]
    fn one_slow_outlier_does_not_move_the_median() {
        let samples: Vec<Sample> = [1.0, 1.1, 0.9, 9.0, 1.0]
            .iter()
            .map(|&wall_s| Sample {
                wall_s,
                peak_rss_bytes: 100,
            })
            .collect();
        let result = CommandResult::measured("x", "x", &samples, None);
        assert_eq!(result.median_s, Some(1.0));
        assert_eq!(result.samples_s.len(), 5);
    }

    #[test]
    fn a_report_round_trips_through_json() {
        let report = Report {
            schema_version: SCHEMA_VERSION,
            engine: "rust".into(),
            scale: 1,
            seed: Some(20_261_107),
            runs: 5,
            warmup: 1,
            oracle: None,
            host: Host::default(),
            workspace_digest: None,
            git_sha: None,
            created_unix: 0,
            results: vec![CommandResult::not_implemented(
                "info",
                "opentide --json info",
                "no Rust yet",
            )],
        };
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("median_s"), "{text}");
        let back: Report = serde_json::from_str(&text).unwrap();
        assert_eq!(back, report);
    }
}
