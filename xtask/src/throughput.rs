//! `cargo xtask throughput`: each language's parse and analysis, counted in
//! instructions with callgrind and held to `tests/bench/instructions.toml`
//! (#1571, ADR 0014).
//!
//! The bench binary `crates/opentide-analysis/benches/throughput.rs` lists
//! the languages (`--list`) and runs one counted pass of a language, mode
//! (`parse`, `analyze`) and input set (`corpus`, `external`) after its
//! warm-up (`--count`); callgrind counts that pass alone
//! (`--toggle-collect=throughput::counted`). Instructions are deterministic
//! for a build and an input, where time is not: the check allows
//! [`TOLERANCE`] for what still varies (hash seeds, the CPU features a
//! routine is chosen by), and a count that falls further asks for the budgets
//! to be recorded again (`--record`), so that the gain is kept.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// How far a count may rise above its budget before the check fails, and fall
/// below it before the check asks for the budgets to be recorded again.
pub const TOLERANCE: f64 = 0.03;

const MODES: [&str; 2] = ["parse", "analyze"];
const SETS: [&str; 2] = ["corpus", "external"];

/// `cargo xtask throughput` arguments.
#[derive(Debug, clap::Args)]
pub struct ThroughputArgs {
    /// Hold the counts to the budgets: exit 1 when one rises more than 3%.
    #[arg(long, conflicts_with = "record")]
    pub check: bool,
    /// Write the counts as the new budgets.
    #[arg(long)]
    pub record: bool,
    /// The budgets file.
    #[arg(long, default_value = "tests/bench/instructions.toml")]
    pub budgets: PathBuf,
    /// Only these languages (names as the bench binary lists them).
    #[arg(long = "language")]
    pub languages: Vec<String>,
}

/// One counted pass.
#[derive(Debug)]
struct Count {
    language: String,
    key: String,
    instructions: u64,
    bytes: u64,
}

/// Runs `cargo xtask throughput`.
pub fn main(args: &ThroughputArgs) -> ExitCode {
    match run(args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("throughput: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &ThroughputArgs) -> Result<bool> {
    let binary = build()?;
    let listed = output(Command::new(&binary).arg("--list"))?;
    let languages: Vec<&str> = listed
        .lines()
        .filter(|l| args.languages.is_empty() || args.languages.iter().any(|w| w == l))
        .collect();
    let cases: Vec<(&str, &str, &str)> = languages
        .iter()
        .flat_map(|l| {
            MODES
                .iter()
                .flat_map(move |m| SETS.iter().map(move |s| (*l, *m, *s)))
        })
        .collect();
    let scratch = tempfile::tempdir()?;
    let counts = crate::parallel::in_order(&cases, |&(language, mode, set)| {
        count(&binary, scratch.path(), language, mode, set)
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    if args.record {
        // Merged into the budgets there are: `--language` records those alone.
        let mut budgets = if args.budgets.exists() {
            read_budgets(&args.budgets)?
        } else {
            BTreeMap::new()
        };
        for c in &counts {
            budgets
                .entry(c.language.clone())
                .or_default()
                .insert(c.key.clone(), c.instructions);
        }
        std::fs::write(&args.budgets, budgets_toml(&budgets))
            .with_context(|| format!("writing {}", args.budgets.display()))?;
        println!(
            "throughput: {} counts recorded in {}",
            counts.len(),
            args.budgets.display()
        );
        return Ok(true);
    }
    let budgets = read_budgets(&args.budgets)?;
    let mut ok = true;
    println!("| language | pass | instructions | per byte | budget | change |");
    println!("|---|---|---:|---:|---:|---:|");
    for c in &counts {
        let budget = budgets
            .get(&c.language)
            .and_then(|b| b.get(&c.key))
            .copied();
        let (shown, verdict) = match budget {
            None => ("—".to_owned(), Verdict::Missing),
            Some(b) => (b.to_string(), verdict(c.instructions, b)),
        };
        #[expect(clippy::cast_precision_loss, reason = "a ratio for the report")]
        let per_byte = c.instructions as f64 / c.bytes.max(1) as f64;
        let change = budget.map_or_else(String::new, |b| change(c.instructions, b));
        println!(
            "| {} | {} | {} | {per_byte:.0} | {shown} | {change} {} |",
            c.language,
            c.key,
            c.instructions,
            verdict.mark()
        );
        if args.check && matches!(verdict, Verdict::Over | Verdict::Missing) {
            ok = false;
        }
    }
    if !ok {
        eprintln!(
            "throughput: a count is over its budget by more than {:.0}%, or has none; \
             fix the regression, or record the budgets again on purpose \
             (`cargo xtask throughput --record`, ADR 0014)",
            TOLERANCE * 100.0
        );
    }
    Ok(ok)
}

/// A count against its budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Within,
    Over,
    Under,
    Missing,
}

impl Verdict {
    fn mark(self) -> &'static str {
        match self {
            Self::Within => "",
            Self::Over => "**over**",
            Self::Under => "(lower: record again)",
            Self::Missing => "**no budget**",
        }
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "instruction counts, far below 2^52"
)]
fn verdict(count: u64, budget: u64) -> Verdict {
    let ratio = count as f64 / budget.max(1) as f64;
    if ratio > 1.0 + TOLERANCE {
        Verdict::Over
    } else if ratio < 1.0 - TOLERANCE {
        Verdict::Under
    } else {
        Verdict::Within
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "instruction counts, far below 2^52"
)]
fn change(count: u64, budget: u64) -> String {
    format!(
        "{:+.1}%",
        (count as f64 / budget.max(1) as f64 - 1.0) * 100.0
    )
}

/// Builds the bench binary, symbols kept (callgrind names `counted` by them),
/// and returns its path.
fn build() -> Result<PathBuf> {
    let text = output(
        Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args([
                "bench",
                "--no-run",
                "--locked",
                "-p",
                "opentide-analysis",
                "--bench",
                "throughput",
                "--message-format=json",
            ])
            .env("CARGO_PROFILE_BENCH_STRIP", "none"),
    )?;
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v["target"]["name"] == "throughput")
        .find_map(|v| v["executable"].as_str().map(PathBuf::from))
        .context("cargo built no `throughput` bench binary")
}

/// One counted pass under callgrind; `None` for an empty input set.
fn count(
    binary: &Path,
    scratch: &Path,
    language: &str,
    mode: &str,
    set: &str,
) -> Result<Option<Count>> {
    let out = scratch.join(format!("{language}.{mode}.{set}.callgrind"));
    let printed = output(
        Command::new("valgrind")
            .arg("--tool=callgrind")
            .arg("--toggle-collect=throughput::counted")
            .arg(format!("--callgrind-out-file={}", out.display()))
            .arg(binary)
            .args(["--count", language, mode, set]),
    )
    .with_context(|| format!("valgrind on {language} {mode} {set} (is valgrind installed?)"))?;
    let mut numbers = printed.split_whitespace().map(str::parse::<u64>);
    let (Some(Ok(calls)), Some(Ok(bytes))) = (numbers.next(), numbers.next()) else {
        bail!("{language} {mode} {set}: the bench printed {printed:?}");
    };
    if calls == 0 {
        return Ok(None);
    }
    let profile =
        std::fs::read_to_string(&out).with_context(|| format!("reading {}", out.display()))?;
    let instructions = profile
        .lines()
        .find_map(|l| {
            l.strip_prefix("summary:")
                .or_else(|| l.strip_prefix("totals:"))
        })
        .and_then(|n| n.trim().parse().ok())
        .with_context(|| format!("no instruction total in {}", out.display()))?;
    if instructions == 0 {
        bail!(
            "{language} {mode} {set}: callgrind counted nothing in `throughput::counted` \
             (were the bench binary's symbols stripped?)"
        );
    }
    Ok(Some(Count {
        language: language.to_owned(),
        key: format!("{mode}_{set}"),
        instructions,
        bytes,
    }))
}

fn output(command: &mut Command) -> Result<String> {
    let out = command
        .output()
        .with_context(|| format!("running {command:?}"))?;
    if !out.status.success() {
        bail!(
            "{command:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

fn read_budgets(path: &Path) -> Result<BTreeMap<String, BTreeMap<String, u64>>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn budgets_toml(budgets: &BTreeMap<String, BTreeMap<String, u64>>) -> String {
    let mut out = String::from(
        "# Instructions each language's counted pass takes (`cargo xtask throughput`,\n\
         # ADR 0014): parse alone and full analysis, over the short corpus and the\n\
         # external public rules. Written by `cargo xtask throughput --record`; the\n\
         # check fails a count more than 3% over. Record again when a change lowers\n\
         # counts on purpose, or raises them on purpose with the reason in its PR.\n",
    );
    for (language, counts) in budgets {
        out.push_str(&format!("\n[{language}]\n"));
        for (key, instructions) in counts {
            out.push_str(&format!("{key} = {instructions}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_is_within_over_or_under_its_budget() {
        assert_eq!(verdict(1_000, 1_000), Verdict::Within);
        assert_eq!(verdict(1_029, 1_000), Verdict::Within);
        assert_eq!(verdict(1_031, 1_000), Verdict::Over);
        assert_eq!(verdict(969, 1_000), Verdict::Under);
    }

    #[test]
    fn recorded_budgets_read_back() {
        let mut written: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        written
            .entry("kql".into())
            .or_default()
            .extend([("parse_corpus".into(), 7), ("analyze_corpus".into(), 9)]);
        written
            .entry("eql".into())
            .or_default()
            .insert("parse_corpus".into(), 3);
        let budgets: BTreeMap<String, BTreeMap<String, u64>> =
            toml::from_str(&budgets_toml(&written)).expect("budgets");
        assert_eq!(budgets, written);
    }
}
