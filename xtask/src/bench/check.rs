//! `cargo xtask bench --check BUDGETS BENCH.json [--previous LAST.json]`:
//! a report against its budgets and the last `development` result.
//!
//! A command fails when:
//!
//! - its median or peak RSS is more than `policy.regression` (10%) above the
//!   last `development` result of the same engine, scale and seed
//!   (`--previous`);
//! - for the `python` engine, more than `policy.regression` above the oracle
//!   baseline recorded in the budgets (`baseline_s`, `baseline_rss_mib`), when
//!   the report is of the baseline's scale and seed;
//! - for the `rust` engine, above the plan section 11 target (`target_s`,
//!   `target_rss_mib`), an absolute budget, at scale 1.
//!
//! A relative regression must also exceed the noise floor (`noise_floor_s`,
//! `noise_floor_rss_mib`): a 20 ms difference on a 0.2 s command is the
//! scheduler, not the code. A measured command without a budget entry, a
//! budget entry the report lacks, or a report of another schema fails too, so
//! that a new command cannot slip in unbudgeted. A command the engine does
//! not implement yet ("no Rust yet") is listed, never failed.

use crate::bench::report::{CommandResult, Report, SCHEMA_VERSION, Status};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Bytes in a MiB: budgets are written in MiB, reports hold bytes.
const MIB: f64 = 1024.0 * 1024.0;

/// The seed of the heavy workspace the plan section 11 targets are for.
const SEED_OF_TARGETS: u64 = crate::bench::workspace::SEED;

/// The version of `budgets.toml`'s shape this code reads.
pub const BUDGETS_SCHEMA_VERSION: u32 = 1;

/// `tests/bench/budgets.toml`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    /// [`BUDGETS_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// How a regression is told from noise.
    pub policy: Policy,
    /// Where the oracle baseline came from.
    pub baseline: Baseline,
    /// One entry per command id.
    pub commands: BTreeMap<String, CommandBudget>,
}

/// The regression rule.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The fraction above a reference that fails: 0.10.
    pub regression: f64,
    /// A time difference at or under this many seconds is never a regression.
    pub noise_floor_s: f64,
    /// An RSS difference at or under this many MiB is never a regression.
    pub noise_floor_rss_mib: f64,
}

/// The oracle measurement the `baseline_*` numbers come from.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    /// The engine measured: `python`.
    pub engine: String,
    /// What ran: `opentide 0.23.0`.
    pub oracle: String,
    /// The heavy workspace's scale.
    pub scale: u32,
    /// The heavy workspace's seed.
    pub seed: u64,
    /// The runner class: `ubuntu-24.04, 4 vCPU`.
    pub runner: String,
    /// The CI run the numbers were copied from.
    pub source: String,
}

/// One command's budget.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandBudget {
    /// The label in the summary: `validate, clean`.
    pub label: String,
    /// Plan section 2's measurement (opentide 0.22.0), for the record; never
    /// enforced.
    pub plan_s: Option<f64>,
    /// Plan section 2's peak RSS, in MiB, for the record.
    pub plan_rss_mib: Option<f64>,
    /// The oracle's median on CI's runner class, in seconds.
    pub baseline_s: Option<f64>,
    /// The oracle's peak RSS on CI's runner class, in MiB.
    pub baseline_rss_mib: Option<f64>,
    /// Plan section 11's target for the Rust engine, in seconds.
    pub target_s: Option<f64>,
    /// Plan section 11's peak RSS target for the Rust engine, in MiB.
    pub target_rss_mib: Option<f64>,
}

impl Budgets {
    /// Parses `budgets.toml` and checks its version and its numbers.
    pub fn parse(text: &str) -> Result<Self> {
        let budgets: Self = toml::from_str(text)?;
        if budgets.schema_version != BUDGETS_SCHEMA_VERSION {
            bail!(
                "schema_version {} (this xtask reads {BUDGETS_SCHEMA_VERSION})",
                budgets.schema_version
            );
        }
        let policy = &budgets.policy;
        for (name, value) in [
            ("policy.regression", policy.regression),
            ("policy.noise_floor_s", policy.noise_floor_s),
            ("policy.noise_floor_rss_mib", policy.noise_floor_rss_mib),
        ] {
            if !(value.is_finite() && value >= 0.0) {
                bail!("{name} must be a number >= 0, not {value}");
            }
        }
        for (id, budget) in &budgets.commands {
            for (name, value) in [
                ("baseline_s", budget.baseline_s),
                ("baseline_rss_mib", budget.baseline_rss_mib),
                ("target_s", budget.target_s),
                ("target_rss_mib", budget.target_rss_mib),
            ] {
                if let Some(value) = value
                    && !(value.is_finite() && value > 0.0)
                {
                    bail!("commands.{id}.{name} must be a number > 0, not {value}");
                }
            }
        }
        Ok(budgets)
    }
}

/// Parses a report and refuses a schema this code does not know.
pub fn parse_report(text: &str) -> Result<Report> {
    let report: Report = serde_json::from_str(text)?;
    if report.schema_version != SCHEMA_VERSION {
        bail!(
            "schema_version {} (this xtask reads {SCHEMA_VERSION})",
            report.schema_version
        );
    }
    Ok(report)
}

/// The verdict on one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Within every budget that applies.
    Pass,
    /// Over a budget or a regression.
    Fail,
    /// Not measured: the engine has no implementation yet.
    NotImplemented,
}

/// One row of the summary.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// The command id.
    pub id: String,
    /// Its label from the budgets, or its id.
    pub label: String,
    /// The report's median, in seconds.
    pub median_s: Option<f64>,
    /// The report's peak RSS, in bytes.
    pub peak_rss_bytes: Option<u64>,
    /// The time budget that applies, in seconds.
    pub budget_s: Option<f64>,
    /// The RSS budget that applies, in bytes.
    pub budget_rss_bytes: Option<f64>,
    /// The median against the reference (the oracle baseline for `python`,
    /// the plan target for `rust`), as a fraction: 0.05 is 5% slower.
    pub delta_reference: Option<f64>,
    /// The median against the last `development` result, as a fraction.
    pub delta_previous: Option<f64>,
    /// The verdict.
    pub verdict: Verdict,
    /// Why it failed, or the note it carries.
    pub reasons: Vec<String>,
}

/// The outcome of a check.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    /// One row per command, in the report's order, then budgets the report
    /// lacks.
    pub rows: Vec<Row>,
    /// Problems that are not a command's: a report of another engine or
    /// seed than the previous one, a budget entry the report lacks.
    pub notes: Vec<String>,
    /// Every failure, one line each.
    pub failures: Vec<String>,
    /// What the reference column compares with.
    pub reference: String,
    /// What the previous column compares with, if anything.
    pub previous: Option<String>,
}

impl Outcome {
    /// Whether every command passed.
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Whether `value` exceeds `reference` by more than the fraction `regression`
/// and by more than the absolute `floor`.
pub fn regressed(value: f64, reference: f64, regression: f64, floor: f64) -> bool {
    value - reference > (reference * regression).max(floor)
}

fn fraction(value: f64, reference: f64) -> Option<f64> {
    (reference > 0.0).then(|| value / reference - 1.0)
}

/// Why `previous` cannot be compared with `report`, if it cannot.
fn incomparable(report: &Report, previous: &Report) -> Option<String> {
    if previous.engine != report.engine {
        return Some(format!("engine {} != {}", previous.engine, report.engine));
    }
    if previous.scale != report.scale {
        return Some(format!("scale {} != {}", previous.scale, report.scale));
    }
    if previous.seed != report.seed || report.seed.is_none() {
        return Some(format!(
            "workspace {} != {}",
            workspace_name(previous.seed),
            workspace_name(report.seed)
        ));
    }
    None
}

/// Checks `report` against `budgets` and, when given, the last `development`
/// result.
pub fn check(budgets: &Budgets, report: &Report, previous: Option<&Report>) -> Outcome {
    let policy = &budgets.policy;
    let mut notes = Vec::new();
    let mut failures = Vec::new();

    let baseline_applies = report.engine == budgets.baseline.engine
        && report.scale == budgets.baseline.scale
        && report.seed == Some(budgets.baseline.seed);
    let heavy = report.seed == Some(SEED_OF_TARGETS);
    let reference = match report.engine.as_str() {
        "rust" if report.scale == 1 && heavy => "plan section 11 target".to_owned(),
        "rust" if !heavy => {
            notes.push(
                "the plan section 11 targets are for the heavy workspace; this report \
                 measured a workspace of its own: no absolute budget applies"
                    .to_owned(),
            );
            "none (not the heavy workspace)".to_owned()
        }
        "rust" => {
            notes.push(format!(
                "the plan section 11 targets are for scale 1; this report is scale {}: \
                 no absolute budget applies",
                report.scale
            ));
            "none (targets are for scale 1)".to_owned()
        }
        _ if baseline_applies => format!(
            "oracle baseline ({}, {}; budget = baseline + {:.0}%)",
            budgets.baseline.oracle,
            budgets.baseline.runner,
            policy.regression * 100.0
        ),
        _ => {
            notes.push(format!(
                "the oracle baseline is {} at scale {}, seed {}; this report is {} at \
                 scale {}, {}: no baseline applies",
                budgets.baseline.engine,
                budgets.baseline.scale,
                budgets.baseline.seed,
                report.engine,
                report.scale,
                workspace_name(report.seed)
            ));
            "none (another engine, scale or seed than the baseline)".to_owned()
        }
    };

    let previous = previous.and_then(|previous| match incomparable(report, previous) {
        Some(why) => {
            notes.push(format!(
                "the last development result is not comparable ({why}); \
                 no regression check against it"
            ));
            None
        }
        None => Some(previous),
    });
    let previous_label = previous.map(|previous| {
        let sha = previous.git_sha.as_deref().unwrap_or("unknown commit");
        format!("commit {}", short(sha))
    });

    let mut rows = Vec::new();
    for result in &report.results {
        let budget = budgets.commands.get(&result.id);
        let prior = previous.and_then(|p| p.results.iter().find(|r| r.id == result.id));
        let row = check_one(
            report,
            result,
            budget,
            prior,
            policy,
            baseline_applies,
            &mut failures,
        );
        rows.push(row);
    }
    for (id, budget) in &budgets.commands {
        if !report.results.iter().any(|r| &r.id == id) {
            let why = format!("{id}: has a budget but is not in the report");
            failures.push(why.clone());
            rows.push(Row {
                id: id.clone(),
                label: budget.label.clone(),
                median_s: None,
                peak_rss_bytes: None,
                budget_s: None,
                budget_rss_bytes: None,
                delta_reference: None,
                delta_previous: None,
                verdict: Verdict::Fail,
                reasons: vec![why],
            });
        }
    }

    Outcome {
        rows,
        notes,
        failures,
        reference,
        previous: previous_label,
    }
}

fn check_one(
    report: &Report,
    result: &CommandResult,
    budget: Option<&CommandBudget>,
    prior: Option<&CommandResult>,
    policy: &Policy,
    baseline_applies: bool,
    failures: &mut Vec<String>,
) -> Row {
    let id = &result.id;
    let mut row = Row {
        id: id.clone(),
        label: budget.map_or_else(|| id.clone(), |b| b.label.clone()),
        median_s: result.median_s,
        peak_rss_bytes: result.peak_rss_bytes,
        budget_s: None,
        budget_rss_bytes: None,
        delta_reference: None,
        delta_previous: None,
        verdict: Verdict::Pass,
        reasons: Vec::new(),
    };
    let mut fail = |row: &mut Row, why: String| {
        failures.push(format!("{id}: {why}"));
        row.reasons.push(why);
        row.verdict = Verdict::Fail;
    };

    if result.status == Status::NotImplemented {
        row.verdict = Verdict::NotImplemented;
        row.reasons.push(
            result
                .note
                .clone()
                .unwrap_or_else(|| "not implemented".into()),
        );
        return row;
    }
    let (Some(median), Some(rss)) = (result.median_s, result.peak_rss_bytes) else {
        fail(&mut row, "measured, but the report has no median".into());
        return row;
    };
    #[expect(
        clippy::cast_precision_loss,
        reason = "an RSS in bytes is far below 2^52"
    )]
    let rss = rss as f64;
    let Some(budget) = budget else {
        fail(
            &mut row,
            "no budget: add [commands.<id>] to the budgets file".into(),
        );
        return row;
    };

    let floor_rss = policy.noise_floor_rss_mib * MIB;
    if report.engine == "rust" {
        if report.scale == 1 && report.seed == Some(SEED_OF_TARGETS) {
            row.budget_s = budget.target_s;
            row.budget_rss_bytes = budget.target_rss_mib.map(|mib| mib * MIB);
            if let Some(target) = budget.target_s {
                row.delta_reference = fraction(median, target);
                if median > target {
                    fail(
                        &mut row,
                        format!("median {median:.3} s is over the target {target:.3} s"),
                    );
                }
            }
            if let Some(target) = row.budget_rss_bytes
                && rss > target
            {
                fail(
                    &mut row,
                    format!(
                        "peak RSS {:.1} MiB is over the target {:.1} MiB",
                        rss / MIB,
                        target / MIB
                    ),
                );
            }
        }
    } else if baseline_applies {
        match budget.baseline_s {
            Some(baseline) => {
                row.budget_s =
                    Some(baseline + (baseline * policy.regression).max(policy.noise_floor_s));
                row.delta_reference = fraction(median, baseline);
                if regressed(median, baseline, policy.regression, policy.noise_floor_s) {
                    fail(
                        &mut row,
                        format!(
                            "median {median:.3} s is {:+.1}% against the oracle baseline \
                             {baseline:.3} s (more than {:.0}%)",
                            (median / baseline - 1.0) * 100.0,
                            policy.regression * 100.0
                        ),
                    );
                }
            }
            None => fail(&mut row, "the budgets record no baseline_s".into()),
        }
        match budget.baseline_rss_mib.map(|mib| mib * MIB) {
            Some(baseline) => {
                row.budget_rss_bytes =
                    Some(baseline + (baseline * policy.regression).max(floor_rss));
                if regressed(rss, baseline, policy.regression, floor_rss) {
                    fail(
                        &mut row,
                        format!(
                            "peak RSS {:.1} MiB is {:+.1}% against the oracle baseline \
                             {:.1} MiB (more than {:.0}%)",
                            rss / MIB,
                            (rss / baseline - 1.0) * 100.0,
                            baseline / MIB,
                            policy.regression * 100.0
                        ),
                    );
                }
            }
            None => fail(&mut row, "the budgets record no baseline_rss_mib".into()),
        }
    }

    if let Some(prior) = prior
        && prior.status == Status::Measured
        && let (Some(prior_median), Some(prior_rss)) = (prior.median_s, prior.peak_rss_bytes)
    {
        #[expect(
            clippy::cast_precision_loss,
            reason = "an RSS in bytes is far below 2^52"
        )]
        let prior_rss = prior_rss as f64;
        row.delta_previous = fraction(median, prior_median);
        if regressed(
            median,
            prior_median,
            policy.regression,
            policy.noise_floor_s,
        ) {
            fail(
                &mut row,
                format!(
                    "median {median:.3} s is {:+.1}% against the last development result \
                     {prior_median:.3} s (more than {:.0}%)",
                    (median / prior_median - 1.0) * 100.0,
                    policy.regression * 100.0
                ),
            );
        }
        if regressed(rss, prior_rss, policy.regression, floor_rss) {
            fail(
                &mut row,
                format!(
                    "peak RSS {:.1} MiB is {:+.1}% against the last development result \
                     {:.1} MiB (more than {:.0}%)",
                    rss / MIB,
                    (rss / prior_rss - 1.0) * 100.0,
                    prior_rss / MIB,
                    policy.regression * 100.0
                ),
            );
        }
    }
    row
}

/// How a report names its workspace.
fn workspace_name(seed: Option<u64>) -> String {
    seed.map_or_else(
        || "a workspace of its own".to_owned(),
        |seed| format!("seed {seed}"),
    )
}

fn short(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

fn seconds(value: Option<f64>) -> String {
    value.map_or_else(|| "–".to_owned(), |s| format!("{s:.3} s"))
}

fn mib(value: Option<f64>) -> String {
    value.map_or_else(|| "–".to_owned(), |b| format!("{:.1} MiB", b / MIB))
}

fn percent(value: Option<f64>) -> String {
    value.map_or_else(|| "–".to_owned(), |f| format!("{:+.1}%", f * 100.0))
}

/// The job summary: a table with a row per command (median, RSS, budget and
/// deltas), the failures, and a chart of the medians against their budgets.
pub fn summary_markdown(outcome: &Outcome, report: &Report) -> String {
    let mut out = String::new();
    let verdict = if outcome.passed() { "passed" } else { "FAILED" };
    let _ = writeln!(
        out,
        "### Benchmarks: {} engine, scale {}: {verdict}\n",
        report.engine, report.scale
    );
    let _ = writeln!(
        out,
        "Median of {} cold process runs (after {} warm-up) and the median peak RSS \
         (`wait4`), on {} ({} CPUs{}). Reference: {}. Last `development` result: {}.\n",
        report.runs,
        report.warmup,
        report
            .host
            .runner_image
            .as_deref()
            .unwrap_or(report.host.os.as_str()),
        report.host.cpus,
        report
            .host
            .cpu_model
            .as_deref()
            .map(|m| format!(", {m}"))
            .unwrap_or_default(),
        outcome.reference,
        outcome.previous.as_deref().unwrap_or("none found")
    );
    out.push_str(
        "| Command | Median | Peak RSS | Budget (time) | Budget (RSS) | Δ reference | \
         Δ last `development` | Result |\n",
    );
    out.push_str("|---|---:|---:|---:|---:|---:|---:|---|\n");
    for row in &outcome.rows {
        let result = match row.verdict {
            Verdict::Pass => "✅ pass".to_owned(),
            Verdict::Fail => format!("❌ {}", row.reasons.join("; ")),
            Verdict::NotImplemented => format!("➖ {}", row.reasons.join("; ")),
        };
        #[expect(
            clippy::cast_precision_loss,
            reason = "an RSS in bytes is far below 2^52"
        )]
        let rss = row.peak_rss_bytes.map(|b| b as f64);
        let _ = writeln!(
            out,
            "| {} (`{}`) | {} | {} | {} | {} | {} | {} | {} |",
            row.label.replace('|', "\\|"),
            row.id,
            seconds(row.median_s),
            mib(rss),
            seconds(row.budget_s),
            mib(row.budget_rss_bytes),
            percent(row.delta_reference),
            percent(row.delta_previous),
            result.replace('|', "\\|"),
        );
    }
    if !outcome.notes.is_empty() {
        out.push('\n');
        for note in &outcome.notes {
            let _ = writeln!(out, "- {note}");
        }
    }
    let charted: Vec<&Row> = outcome
        .rows
        .iter()
        .filter(|row| row.median_s.is_some())
        .collect();
    if !charted.is_empty() {
        // Tildes, not backticks: the same Markdown sits inside the
        // backtick-fenced console blocks of tests/cmd/bench.trycmd.
        out.push_str("\n~~~mermaid\nxychart-beta\n");
        let _ = writeln!(
            out,
            "    title \"Median seconds (bars) against the budget (line)\""
        );
        let labels: Vec<String> = charted.iter().map(|r| format!("\"{}\"", r.id)).collect();
        let _ = writeln!(out, "    x-axis [{}]", labels.join(", "));
        let _ = writeln!(out, "    y-axis \"seconds\"");
        let medians: Vec<String> = charted
            .iter()
            .map(|r| format!("{:.3}", r.median_s.unwrap_or_default()))
            .collect();
        let _ = writeln!(out, "    bar [{}]", medians.join(", "));
        if charted.iter().all(|r| r.budget_s.is_some()) {
            let budgets: Vec<String> = charted
                .iter()
                .map(|r| format!("{:.3}", r.budget_s.unwrap_or_default()))
                .collect();
            let _ = writeln!(out, "    line [{}]", budgets.join(", "));
        }
        out.push_str("~~~\n");
    }
    out
}

/// Reads and checks the files of `--check`; the I/O half of [`check`].
pub fn check_files(
    budgets_path: &std::path::Path,
    report_path: &std::path::Path,
    previous_path: Option<&std::path::Path>,
) -> Result<(Outcome, Report)> {
    let read = |path: &std::path::Path| {
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
    };
    let budgets = Budgets::parse(&read(budgets_path)?)
        .with_context(|| format!("parse {}", budgets_path.display()))?;
    let report = parse_report(&read(report_path)?)
        .with_context(|| format!("parse {}", report_path.display()))?;
    let previous = match previous_path {
        Some(path) => {
            Some(parse_report(&read(path)?).with_context(|| format!("parse {}", path.display()))?)
        }
        None => None,
    };
    let outcome = check(&budgets, &report, previous.as_ref());
    Ok((outcome, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bench::report::{Host, Sample};

    const BUDGETS: &str = r#"
schema_version = 1

[policy]
regression = 0.10
noise_floor_s = 0.03
noise_floor_rss_mib = 2.0

[baseline]
engine = "python"
oracle = "opentide 0.23.0"
scale = 1
seed = 20261107
runner = "ubuntu-24.04, 4 vCPU"
source = "test"

[commands.validate_clean]
label = "validate, clean"
baseline_s = 3.0
baseline_rss_mib = 170.0
target_s = 0.7
target_rss_mib = 100.0

[commands.explain]
label = "explain"
baseline_s = 0.2
baseline_rss_mib = 33.0
target_s = 0.03
"#;

    fn budgets() -> Budgets {
        Budgets::parse(BUDGETS).unwrap()
    }

    fn measured(id: &str, seconds: f64, rss_mib: f64) -> CommandResult {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "test values"
        )]
        let rss = (rss_mib * MIB) as u64;
        let samples = vec![
            Sample {
                wall_s: seconds,
                peak_rss_bytes: rss,
            };
            5
        ];
        CommandResult::measured(id, id, &samples, None)
    }

    fn report(engine: &str, results: Vec<CommandResult>) -> Report {
        Report {
            schema_version: SCHEMA_VERSION,
            engine: engine.into(),
            scale: 1,
            seed: Some(20_261_107),
            runs: 5,
            warmup: 1,
            oracle: None,
            host: Host::default(),
            git_sha: Some("0123456789abcdef".into()),
            created_unix: 0,
            results,
        }
    }

    #[test]
    fn the_baseline_itself_passes() {
        let r = report(
            "python",
            vec![
                measured("validate_clean", 3.0, 170.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        let outcome = check(&budgets(), &r, None);
        assert!(outcome.passed(), "{:?}", outcome.failures);
        assert_eq!(outcome.rows[0].delta_reference, Some(0.0));
    }

    #[test]
    fn eleven_percent_over_the_baseline_fails_and_nine_passes() {
        let slow = report(
            "python",
            vec![
                measured("validate_clean", 3.33, 170.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        let outcome = check(&budgets(), &slow, None);
        assert!(!outcome.passed());
        assert!(
            outcome.failures[0].contains("oracle baseline"),
            "{:?}",
            outcome.failures
        );
        assert_eq!(outcome.rows[0].verdict, Verdict::Fail);

        let ok = report(
            "python",
            vec![
                measured("validate_clean", 3.27, 170.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        assert!(check(&budgets(), &ok, None).passed());
    }

    #[test]
    fn the_noise_floor_absorbs_a_small_absolute_difference() {
        // 0.2 s -> 0.225 s is +12.5% but 25 ms, under the 30 ms floor.
        let r = report(
            "python",
            vec![
                measured("validate_clean", 3.0, 170.0),
                measured("explain", 0.225, 33.0),
            ],
        );
        assert!(check(&budgets(), &r, None).passed());
        // 0.2 s -> 0.24 s is 40 ms: over the floor and over 10%.
        let r = report(
            "python",
            vec![
                measured("validate_clean", 3.0, 170.0),
                measured("explain", 0.24, 33.0),
            ],
        );
        assert!(!check(&budgets(), &r, None).passed());
    }

    #[test]
    fn an_rss_regression_fails() {
        let r = report(
            "python",
            vec![
                measured("validate_clean", 3.0, 190.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        let outcome = check(&budgets(), &r, None);
        assert!(!outcome.passed());
        assert!(
            outcome.failures[0].contains("peak RSS"),
            "{:?}",
            outcome.failures
        );
    }

    #[test]
    fn a_regression_against_the_last_development_result_fails() {
        let previous = report(
            "python",
            vec![
                measured("validate_clean", 2.5, 170.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        // Within the baseline budget, but 20% slower than development.
        let current = report(
            "python",
            vec![
                measured("validate_clean", 3.0, 170.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        let outcome = check(&budgets(), &current, Some(&previous));
        assert!(!outcome.passed());
        assert!(
            outcome.failures[0].contains("last development result"),
            "{:?}",
            outcome.failures
        );
        let delta = outcome.rows[0].delta_previous.unwrap();
        assert!((delta - 0.2).abs() < 1e-9, "{delta}");
        assert!(
            outcome
                .previous
                .as_deref()
                .unwrap_or("")
                .contains("0123456789ab")
        );
    }

    #[test]
    fn a_previous_result_of_another_scale_is_not_compared() {
        let mut previous = report(
            "python",
            vec![
                measured("validate_clean", 1.0, 100.0),
                measured("explain", 0.1, 20.0),
            ],
        );
        previous.scale = 10;
        let current = report(
            "python",
            vec![
                measured("validate_clean", 3.0, 170.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        let outcome = check(&budgets(), &current, Some(&previous));
        assert!(outcome.passed(), "{:?}", outcome.failures);
        assert!(
            outcome.notes[0].contains("not comparable"),
            "{:?}",
            outcome.notes
        );
        assert_eq!(outcome.previous, None);
    }

    #[test]
    fn rust_is_held_to_the_plan_target_and_no_rust_yet_is_listed_not_failed() {
        let r = report(
            "rust",
            vec![
                measured("validate_clean", 0.69, 90.0),
                CommandResult::not_implemented("explain", "explain", "no Rust yet"),
            ],
        );
        let outcome = check(&budgets(), &r, None);
        assert!(outcome.passed(), "{:?}", outcome.failures);
        assert_eq!(outcome.rows[1].verdict, Verdict::NotImplemented);

        let r = report(
            "rust",
            vec![
                measured("validate_clean", 0.71, 90.0),
                CommandResult::not_implemented("explain", "explain", "no Rust yet"),
            ],
        );
        let outcome = check(&budgets(), &r, None);
        assert!(!outcome.passed());
        assert!(
            outcome.failures[0].contains("target"),
            "{:?}",
            outcome.failures
        );
    }

    #[test]
    fn an_unbudgeted_command_and_a_missing_one_both_fail() {
        let r = report(
            "python",
            vec![
                measured("validate_clean", 3.0, 170.0),
                measured("brand_new", 1.0, 10.0),
            ],
        );
        let outcome = check(&budgets(), &r, None);
        assert_eq!(outcome.failures.len(), 2, "{:?}", outcome.failures);
        assert!(outcome.failures[0].starts_with("brand_new: no budget"));
        assert!(outcome.failures[1].starts_with("explain: has a budget but is not in the report"));
    }

    #[test]
    fn a_workspace_of_its_own_is_compared_with_nothing() {
        let mut r = report(
            "python",
            vec![
                measured("validate_clean", 30.0, 900.0),
                measured("explain", 9.0, 33.0),
            ],
        );
        r.seed = None;
        let previous = r.clone();
        let outcome = check(&budgets(), &r, Some(&previous));
        assert!(outcome.passed(), "{:?}", outcome.failures);
        assert!(
            outcome
                .notes
                .iter()
                .any(|n| n.contains("a workspace of its own")),
            "{:?}",
            outcome.notes
        );
        r.engine = "rust".into();
        let outcome = check(&budgets(), &r, None);
        assert!(outcome.passed(), "{:?}", outcome.failures);
    }

    #[test]
    fn another_scale_than_the_baseline_has_no_python_budget() {
        let mut r = report(
            "python",
            vec![
                measured("validate_clean", 30.0, 900.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        r.scale = 10;
        let outcome = check(&budgets(), &r, None);
        assert!(outcome.passed(), "{:?}", outcome.failures);
        assert!(outcome.notes[0].contains("no baseline applies"));
    }

    #[test]
    fn the_summary_has_a_row_per_command_with_median_rss_budget_and_delta() {
        let r = report(
            "python",
            vec![
                measured("validate_clean", 3.4, 170.0),
                measured("explain", 0.2, 33.0),
            ],
        );
        let outcome = check(&budgets(), &r, None);
        let text = summary_markdown(&outcome, &r);
        assert!(text.contains("FAILED"), "{text}");
        assert!(
            text.contains(
                "| Command | Median | Peak RSS | Budget (time) | Budget (RSS) | Δ reference"
            ),
            "{text}"
        );
        assert!(text.contains("| validate, clean (`validate_clean`) | 3.400 s | 170.0 MiB | 3.300 s | 187.0 MiB | +13.3% |"), "{text}");
        assert!(text.contains("xychart-beta"), "{text}");
    }

    #[test]
    fn bad_budgets_and_reports_are_refused() {
        assert!(
            Budgets::parse(&BUDGETS.replace("schema_version = 1", "schema_version = 2")).is_err()
        );
        assert!(
            Budgets::parse(&BUDGETS.replace("regression = 0.10", "regression = -1.0")).is_err()
        );
        assert!(Budgets::parse(&BUDGETS.replace("baseline_s = 0.2", "baseline_s = 0.0")).is_err());
        assert!(Budgets::parse(&format!("{BUDGETS}\nunknown = 1\n")).is_err());
        let mut r = report("python", vec![]);
        r.schema_version = 99;
        assert!(parse_report(&serde_json::to_string(&r).unwrap()).is_err());
    }
}
