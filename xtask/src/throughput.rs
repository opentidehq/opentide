//! `cargo xtask throughput`: each language's parse and analysis, counted in
//! instructions with callgrind and held to `tests/bench/instructions.toml`
//! (#1571, ADR 0014).
//!
//! The bench binary `crates/opentide-analysis/benches/throughput.rs` lists
//! the languages (`--list`) and runs one counted pass of a language, mode
//! (`parse`, `analyze`) and input set (`corpus`, `external`) after its
//! warm-up (`--count`); callgrind counts that pass alone
//! (`--toggle-collect=throughput::counted`). Instructions are deterministic
//! for a build, an input and an allocation order, where time is not. The
//! allocation order still varies (each process seeds its hash maps, and
//! glibc's malloc does more or less work with the order): one pass can differ
//! from the next by 1.5%. So each pass is counted [`RUNS`] times: the check
//! holds the lowest to its budget within [`TOLERANCE`], and a record writes
//! the highest. A count that falls further asks for the budgets to be recorded
//! again (`--record`), so that the gain is kept. glibc's malloc is counted, so
//! budgets hold for one environment: the file names it ([`environment`]), and
//! a check elsewhere warns.

use anyhow::{Context, Result, bail};
use clap::builder::TypedValueParser as _;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// How far a count may rise above its budget before the check fails, and fall
/// below it before the check asks for the budgets to be recorded again.
pub const TOLERANCE: f64 = 0.03;

/// How many times each pass is counted (the default of `--runs`).
pub const RUNS: usize = 3;

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
    /// How many times each pass is counted: the check takes the lowest, a
    /// record the highest.
    #[arg(long, default_value_t = RUNS, value_parser = clap::value_parser!(u8).range(1..).map(usize::from))]
    pub runs: usize,
}

/// One counted pass.
#[derive(Debug, Clone)]
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
    let counts = counts(args)?;
    let environment = environment();
    if args.record {
        record(args, &counts, &environment)?;
        return Ok(true);
    }
    check(args, &counts, &environment)
}

/// Every pass of the languages asked for, counted `args.runs` times: the
/// lowest for a check, the highest for a record.
fn counts(args: &ThroughputArgs) -> Result<Vec<Count>> {
    let binary = build()?;
    let listed = output(Command::new(&binary).arg("--list"))?;
    let listed: Vec<&str> = listed.lines().collect();
    if let Some(unknown) = args
        .languages
        .iter()
        .find(|l| !listed.contains(&l.as_str()))
    {
        bail!(
            "unknown language {unknown:?}: the bench lists {}",
            listed.join(", ")
        );
    }
    let languages: Vec<&str> = listed
        .into_iter()
        .filter(|l| args.languages.is_empty() || args.languages.iter().any(|w| w == l))
        .collect();
    let cases: Vec<(&str, &str, &str, usize)> = languages
        .iter()
        .flat_map(|l| {
            MODES.iter().flat_map(move |m| {
                SETS.iter()
                    .flat_map(move |s| (0..args.runs).map(move |r| (*l, *m, *s, r)))
            })
        })
        .collect();
    let scratch = tempfile::tempdir()?;
    let runs = crate::parallel::in_order(&cases, |&(language, mode, set, run)| {
        count(&binary, scratch.path(), language, mode, set, run)
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    // Each pass's runs, in order: the lowest for a check, the highest for a record.
    let counts: Vec<Count> = runs
        .chunks(args.runs)
        .map(|chunk| {
            let pick = if args.record {
                chunk.iter().max_by_key(|c| c.instructions)
            } else {
                chunk.iter().min_by_key(|c| c.instructions)
            };
            pick.cloned()
        })
        .collect::<Option<_>>()
        .context("no counts")?;
    if counts.is_empty() {
        bail!("no language to count");
    }
    Ok(counts)
}

/// Writes the budgets.
fn record(args: &ThroughputArgs, counts: &[Count], environment: &str) -> Result<()> {
    // A whole record writes the file anew (a language gone from the bench
    // goes from it); `--language` merges into the budgets there are.
    let mut budgets = if args.languages.is_empty() || !args.budgets.exists() {
        BTreeMap::new()
    } else {
        read_budgets(&args.budgets)?
    };
    for c in counts {
        budgets
            .entry(c.language.clone())
            .or_default()
            .insert(c.key.clone(), c.instructions);
    }
    std::fs::write(&args.budgets, budgets_toml(&budgets, environment))
        .with_context(|| format!("writing {}", args.budgets.display()))?;
    println!(
        "throughput: {} counts recorded in {} ({environment})",
        counts.len(),
        args.budgets.display()
    );
    Ok(())
}

/// Holds the counts to the budgets: false when one is over, has none, or a
/// budget is stale (and `--check` is given).
fn check(args: &ThroughputArgs, counts: &[Count], environment: &str) -> Result<bool> {
    let text = std::fs::read_to_string(&args.budgets)
        .with_context(|| format!("reading {}", args.budgets.display()))?;
    let budgets = parse_budgets(&text, &args.budgets)?;
    let recorded = recorded_environment(&text);
    if recorded.as_deref() != Some(environment) {
        println!(
            "::warning::throughput: the budgets were recorded on {}, this is {environment}: \
             glibc's malloc is counted, so counts can differ",
            recorded.as_deref().unwrap_or("an unnamed environment")
        );
    }
    let mut ok = true;
    let mut report = String::from(
        "| language | pass | instructions | per byte | budget | change |\n|---|---|---:|---:|---:|---:|\n",
    );
    for c in counts {
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
        report.push_str(&format!(
            "| {} | {} | {} | {per_byte:.0} | {shown} | {change} {} |\n",
            c.language,
            c.key,
            c.instructions,
            verdict.mark()
        ));
        match verdict {
            Verdict::Over | Verdict::Missing => ok &= !args.check,
            Verdict::Under => println!(
                "::warning::throughput: {} {} is {change} under its budget: record the budgets again",
                c.language, c.key
            ),
            Verdict::Within => {}
        }
    }
    // A budget no pass counted: a language or a pass gone from the bench.
    if args.languages.is_empty() {
        for (language, keys) in &budgets {
            for key in keys.keys() {
                if !counts
                    .iter()
                    .any(|c| &c.language == language && &c.key == key)
                {
                    report.push_str(&format!("| {language} | {key} | — | | | **stale** |\n"));
                    ok &= !args.check;
                }
            }
        }
    }
    print!("{report}");
    if let Some(summary) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        // The step summary is a convenience: the table is on stdout too.
        let _ = std::fs::OpenOptions::new()
            .append(true)
            .open(summary)
            .and_then(|mut f| std::io::Write::write_all(&mut f, report.as_bytes()));
    }
    if !ok {
        eprintln!(
            "throughput: a count is over its budget by more than {:.0}%, has none, or a budget \
             is stale; fix the regression, or record the budgets again on purpose \
             (`cargo xtask throughput --record`, ADR 0014)",
            TOLERANCE * 100.0
        );
    }
    Ok(ok)
}

/// Where the counts are taken: the valgrind and glibc versions and the
/// architecture, which the counts depend on.
fn environment() -> String {
    let first_line = |program: &str, arg: &str| {
        Command::new(program)
            .arg(arg)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|t| t.lines().next().map(str::to_owned))
            .unwrap_or_else(|| format!("{program}?"))
    };
    format!(
        "{}, {}, {}",
        first_line("valgrind", "--version"),
        first_line("getconf", "GNU_LIBC_VERSION"),
        std::env::consts::ARCH
    )
}

const ENVIRONMENT: &str = "# Recorded on: ";

/// The environment a budgets file names, if it names one.
fn recorded_environment(text: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix(ENVIRONMENT))
        .map(str::to_owned)
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

/// One counted pass under callgrind (the bench stops on an empty input set).
fn count(
    binary: &Path,
    scratch: &Path,
    language: &str,
    mode: &str,
    set: &str,
    run: usize,
) -> Result<Count> {
    let out = scratch.join(format!("{language}.{mode}.{set}.{run}.callgrind"));
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
        bail!("{language} {mode} {set}: no texts");
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
    Ok(Count {
        language: language.to_owned(),
        key: format!("{mode}_{set}"),
        instructions,
        bytes,
    })
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

type Budgets = BTreeMap<String, BTreeMap<String, u64>>;

fn read_budgets(path: &Path) -> Result<Budgets> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_budgets(&text, path)
}

fn parse_budgets(text: &str, path: &Path) -> Result<Budgets> {
    toml::from_str(text).with_context(|| format!("parsing {}", path.display()))
}

fn budgets_toml(budgets: &Budgets, environment: &str) -> String {
    let mut out = String::from(
        "# Instructions each language's counted pass takes (`cargo xtask throughput`,\n\
         # ADR 0014): parse alone and full analysis, over the short corpus and the\n\
         # external public rules. Written by `cargo xtask throughput --record`; the\n\
         # check fails a count more than 3% over. Record again when a change lowers\n\
         # counts on purpose, or raises them on purpose with the reason in its PR.\n\
         # Each is the highest of several runs. glibc's malloc is counted, so record\n\
         # where CI checks (its `throughput` job's runner image).\n",
    );
    out.push_str(&format!("{ENVIRONMENT}{environment}\n"));
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
        let budgets: BTreeMap<String, BTreeMap<String, u64>> = toml::from_str(&budgets_toml(
            &written,
            "valgrind-3.22.0, glibc 2.39, x86_64",
        ))
        .expect("budgets");
        assert_eq!(budgets, written);
        assert_eq!(
            recorded_environment(&budgets_toml(&written, "here")).as_deref(),
            Some("here")
        );
    }
}
