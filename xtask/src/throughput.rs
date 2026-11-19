//! `cargo xtask throughput`: each language's parse and analysis, counted with
//! callgrind in instructions and in allocator calls, and held to
//! `tests/bench/instructions.toml` (#1571, ADR 0014).
//!
//! The bench binary `crates/opentide-analysis/benches/throughput.rs` lists
//! the languages (`--list`) and runs one counted pass of a language, mode
//! (`parse`, `analyze`) and input set (`corpus`, `external`) after its
//! warm-up (`--count`); callgrind counts that pass's instructions alone
//! (`--toggle-collect=throughput::counted`). Instructions are deterministic
//! for a build and an input, where time is not, once the shared libraries are
//! left out: only the bench binary's own code is counted. glibc's malloc and
//! string routines move with the glibc version, the CPU a routine is chosen
//! for and the allocation order (each process seeds its hash maps): with them,
//! one pass differed from the next by 1.5% and from CI's by 3%; without them,
//! by under 0.1%. Each pass is still counted [`RUNS`] times: the check holds
//! the lowest to its budget within [`TOLERANCE`], and a record writes the
//! highest. A count that falls further asks for the budgets to be recorded
//! again (`--record`), so that the gain is kept. The budgets file names the
//! environment it was recorded in (valgrind, glibc, the architecture), and a
//! check elsewhere warns.
//!
//! Leaving glibc out leaves out what malloc and free do, so each pass has a
//! second budget, `<pass>_allocations`: how many times the counted pass
//! enters the allocator ([`ALLOCATORS`]), read as the executions of each
//! allocator's first instruction (`--dump-instr=yes`), whoever called it.
//! Callgrind's call arcs (`calls=`) are not used: whether it records
//! `__rust_alloc`'s tail jump into `malloc` as a call of its own depends on
//! the code's layout: on #1624 the arcs over the warm-up and counted passes
//! of CQL's and Falco's corpus analyses rose by 7,312 and 10,049 while their
//! allocations fell. An instruction's execution count is the same however it
//! was reached, and it counts only the counted pass, as the instructions do.
//! It does not vary from run to run (ten runs of Exabeam's corpus analysis
//! gave one count), so it is held within [`ALLOCATION_SLACK`] calls, with no
//! percentage.

use anyhow::{Context, Result, bail};
use clap::builder::TypedValueParser as _;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// How far a count may rise above its budget before the check fails, and fall
/// below it before the check asks for the budgets to be recorded again.
pub const TOLERANCE: f64 = 0.03;

/// How many allocator calls a count may differ from its budget by. The count
/// does not vary from run to run, but the earlier count of call arcs did by
/// one from machine to machine: on CI's runner Exabeam's corpus analysis made
/// one call more than here,
/// on the same build inputs, valgrind and glibc (a CPU-dependent choice in a
/// dependency; #1581). Below the smallest input set's number of analyses, so
/// one allocation more a call still fails.
pub const ALLOCATION_SLACK: u64 = 2;

/// Where the callgrind profiles of the last run are kept.
pub const PROFILES: &str = "target/throughput";

/// How many times each pass is counted (the default of `--runs`).
pub const RUNS: usize = 3;

const MODES: [&str; 2] = ["parse", "analyze"];
const SETS: [&str; 2] = ["corpus", "external"];

/// `cargo xtask throughput` arguments.
#[derive(Debug, clap::Args)]
pub struct ThroughputArgs {
    /// Hold the counts to the budgets: exit 1 when an instruction count rises
    /// more than 3%, or an allocator-call count rises more than its slack.
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
    // The profiles are kept, to trace a count that moved (CI uploads them
    // when the check fails); each run starts the directory afresh.
    let profiles = Path::new(PROFILES);
    if profiles.exists() {
        std::fs::remove_dir_all(profiles)
            .with_context(|| format!("clearing {}", profiles.display()))?;
    }
    std::fs::create_dir_all(profiles)
        .with_context(|| format!("creating {}", profiles.display()))?;
    let runs = crate::parallel::in_order(&cases, |&(language, mode, set, run)| {
        count(&binary, profiles, language, mode, set, run)
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    // Each pass's runs (its instructions, then its allocations, a run after
    // the other): the lowest for a check, the highest for a record.
    let mut counts: Vec<Count> = Vec::new();
    for run in runs.into_iter().flatten() {
        match counts
            .iter_mut()
            .find(|c| c.language == run.language && c.key == run.key)
        {
            Some(kept) if args.record => {
                kept.instructions = kept.instructions.max(run.instructions);
            }
            Some(kept) => {
                kept.instructions = kept.instructions.min(run.instructions);
            }
            None => counts.push(run),
        }
    }
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
             the bench's own code should count the same, but compare with care",
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
            Some(b) => (b.to_string(), judge(&c.key, c.instructions, b)),
        };
        #[expect(clippy::cast_precision_loss, reason = "a ratio for the report")]
        let per_byte = if c.key.ends_with("_allocations") {
            String::new()
        } else {
            format!("{:.0}", c.instructions as f64 / c.bytes.max(1) as f64)
        };
        let change = budget.map_or_else(String::new, |b| change(&c.key, c.instructions, b));
        report.push_str(&format!(
            "| {} | {} | {} | {per_byte} | {shown} | {change} {} |\n",
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
            "throughput: an instruction count is over its budget by more than {:.0}%, an \
             allocator-call count is over its budget by more than {ALLOCATION_SLACK}, a count has no budget, or a \
             budget is stale; fix the regression, or record the budgets again on purpose \
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
fn verdict(count: u64, budget: u64, tolerance: f64) -> Verdict {
    let ratio = count as f64 / budget.max(1) as f64;
    if ratio > 1.0 + tolerance {
        Verdict::Over
    } else if ratio < 1.0 - tolerance {
        Verdict::Under
    } else {
        Verdict::Within
    }
}

/// A count against its budget: an instruction count within [`TOLERANCE`],
/// an allocator-call count within [`ALLOCATION_SLACK`] calls.
fn judge(key: &str, count: u64, budget: u64) -> Verdict {
    if key.ends_with("_allocations") {
        if count > budget + ALLOCATION_SLACK {
            Verdict::Over
        } else if count + ALLOCATION_SLACK < budget {
            Verdict::Under
        } else {
            Verdict::Within
        }
    } else {
        verdict(count, budget, TOLERANCE)
    }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "instruction counts, far below 2^52"
)]
fn change(key: &str, count: u64, budget: u64) -> String {
    if key.ends_with("_allocations") {
        // Held exactly: the difference itself, which a percentage rounds away.
        let difference = i128::from(count) - i128::from(budget);
        return format!("{difference:+}");
    }
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
) -> Result<[Count; 2]> {
    let out = scratch.join(format!("{language}.{mode}.{set}.{run}.callgrind"));
    let printed = output(
        Command::new("valgrind")
            .arg("--tool=callgrind")
            .arg("--toggle-collect=throughput::counted")
            // Each instruction's own cost line, at its absolute address: the
            // allocations are the runs of each allocator's first instruction.
            .args(["--dump-instr=yes", "--dump-line=no", "--compress-pos=no"])
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
    let Own {
        instructions,
        allocations,
    } = own_cost(&profile, binary);
    if allocations == 0 {
        // Every pass allocates: none counted means the allocator's symbols no
        // longer match ALLOCATORS (another global allocator, another libc).
        bail!(
            "{language} {mode} {set}: callgrind counted no entry into {ALLOCATORS:?} \
             in `throughput::counted`"
        );
    }
    if instructions == 0 {
        bail!(
            "{language} {mode} {set}: callgrind counted nothing of the bench binary in \
             `throughput::counted` (were its symbols stripped?)"
        );
    }
    Ok([
        Count {
            language: language.to_owned(),
            key: format!("{mode}_{set}"),
            instructions,
            bytes,
        },
        Count {
            language: language.to_owned(),
            key: format!("{mode}_{set}_allocations"),
            instructions: allocations,
            bytes,
        },
    ])
}

/// What a pass costs in the bench binary's own code.
#[derive(Debug, PartialEq, Eq)]
struct Own {
    /// Its instructions.
    instructions: u64,
    /// The counted pass's entries into the allocator (`malloc`, `calloc`,
    /// `realloc` and the aligned ones), from any caller, whose own
    /// instructions are left out with glibc's: the number is exact, so an
    /// allocation more a token still shows (the module doc).
    allocations: u64,
}

/// The allocator's entry points a call into counts as an allocation.
pub const ALLOCATORS: [&str; 5] = [
    "malloc",
    "calloc",
    "realloc",
    "posix_memalign",
    "aligned_alloc",
];

/// What a callgrind profile, written with `--dump-instr=yes --dump-line=no
/// --compress-pos=no`, counts of the bench. Its instructions: every cost line
/// under an `ob=` (the object a function is in) that names `binary`, but a
/// call's inclusive cost (the line after `calls=`), which is the callee's.
/// Shared libraries (glibc's malloc and string routines, the loader) are left
/// out of the instructions: their counts move with the glibc version, the CPU
/// it picks a routine for, and the allocation order, where the bench's own
/// code counts the same on any x86-64 Linux. Its allocations: for each
/// [`ALLOCATORS`] function, the cost of its lowest address, the function's
/// first instruction, which runs once each time the function is entered,
/// whether callgrind recorded the way in as a call or as a jump (the module
/// doc). Every line at that address counts (callgrind may write a block in
/// several contexts), and a function is told apart by its object too.
///
/// glibc's own calls between its allocators count as entries too:
/// `posix_memalign` with an alignment of 16 or less, and `realloc` of a null
/// pointer, go through `malloc`. Rust's system allocator calls neither (it
/// calls `posix_memalign` only when an alignment exceeds the size, and never
/// reallocates null), so each Rust allocation is one entry.
fn own_cost(profile: &str, binary: &Path) -> Own {
    let wanted = binary.file_name();
    // Compressed names: objects and functions each have their own ids.
    let mut objects: BTreeMap<&str, &str> = BTreeMap::new();
    let mut functions: BTreeMap<&str, &str> = BTreeMap::new();
    let mut own = false;
    let mut object = "";
    let mut function = "";
    let mut after_call = false;
    // Each allocator's (object, name) lowest address with a cost, and the
    // cost of every line at that address.
    let mut entries: BTreeMap<(&str, &str), (u64, u64)> = BTreeMap::new();
    let mut cost = Own {
        instructions: 0,
        allocations: 0,
    };
    for line in profile.lines() {
        let Some((key, rest)) = line.split_once('=').filter(|(key, _)| {
            matches!(
                *key,
                "ob" | "cob" | "fn" | "cfn" | "fl" | "fi" | "fe" | "cfi" | "cfl"
            )
        }) else {
            if line.starts_with("calls=") {
                after_call = true;
            } else if line.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '+' | '-' | '*'))
                && !std::mem::take(&mut after_call)
            {
                let mut fields = line.split_whitespace();
                let address = fields
                    .next()
                    .and_then(|a| a.strip_prefix("0x"))
                    .and_then(|a| u64::from_str_radix(a, 16).ok());
                let n = fields
                    .next_back()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0);
                if own {
                    cost.instructions += n;
                }
                if let Some(address) = address
                    && ALLOCATORS.contains(&function)
                {
                    let entry = entries.entry((object, function)).or_insert((address, 0));
                    if address < entry.0 {
                        *entry = (address, 0);
                    }
                    if address == entry.0 {
                        entry.1 += n;
                    }
                }
            }
            continue;
        };
        let names = match key {
            "ob" | "cob" => &mut objects,
            "fn" | "cfn" => &mut functions,
            _ => continue,
        };
        // `(id) name` defines a compressed name, `(id)` reuses it.
        let name = match rest.strip_prefix('(').and_then(|r| r.split_once(')')) {
            Some((id, name)) if !name.trim().is_empty() => {
                names.insert(id, name.trim());
                name.trim()
            }
            Some((id, _)) => names.get(id).copied().unwrap_or_default(),
            None => rest.trim(),
        };
        match key {
            "ob" => {
                object = name;
                own = Path::new(name).file_name() == wanted;
            }
            "fn" => function = name,
            _ => {}
        }
    }
    cost.allocations = entries.values().map(|&(_, n)| n).sum();
    cost
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
        "# What each language's passes cost (`cargo xtask throughput`, ADR 0014):\n\
         # parse alone and full analysis, over the short corpus and the external\n\
         # public rules. `<pass>` is the bench binary's own instructions in the\n\
         # counted pass (glibc and the loader left out), held within 3%;\n\
         # `<pass>_allocations` its entries into the allocator in the counted\n\
         # pass, held within a few calls. Written by\n\
         # `cargo xtask throughput --record`, the highest of several runs. Record\n\
         # again when a change lowers counts on purpose, or raises them on purpose\n\
         # with the reason in its PR.\n",
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
    fn only_the_bench_binary_s_own_cost_is_counted() {
        // A call's inclusive cost (after `calls=`) is the callee's, and a
        // compressed object name, `(id)`, is the one its id was given.
        let profile = "\
events: Ir
ob=(1) /usr/lib/x86_64-linux-gnu/libc.so.6
fn=(1) malloc
0xad750 500
ob=(2) /work/target/release/deps/throughput-abc
fn=(2) throughput::counted
0x1000 7
0x1004 3
cob=(1)
cfn=(1)
calls=2 0xad750
0x1008 500
ob=(1)
fn=(1)
0xad760 200
ob=(2)
fn=(3) opentide_kql::analyze
0x2000 11
cob=(1)
cfn=(4) realloc
calls=5 0xae1a0
0x2004 40
totals: 761
";
        let binary = Path::new("/elsewhere/throughput-abc");
        let own = own_cost(profile, binary);
        assert_eq!(own.instructions, 7 + 3 + 11);
        // No cost line of realloc's own: it ran in no counted pass.
        assert_eq!(own.allocations, 500);
    }

    #[test]
    fn an_allocation_is_an_entry_however_callgrind_recorded_the_way_in() {
        // The same pass, twice: malloc entered 6 times, its first instruction
        // (the lowest address, 0xad750) run 6 times, its loop 9. In the
        // second, callgrind recorded two of the entries, which came through
        // `__rust_alloc`'s tail jump, as calls of their own (#1624): the arcs
        // add up to 8, the entries stay 6.
        let entries = "\
ob=(1) /usr/lib/x86_64-linux-gnu/libc.so.6
fn=(1) malloc
0xad760 9
0xad750 6
fn=(2) realloc
0xae1a0 4
0xae1b0 4
ob=(2) /work/throughput-abc
fn=(3) throughput::counted
0x1000 7
cob=(1)
cfn=(1)
calls=6 0xad750
0x1004 30
";
        let jumps = "\
ob=(1) /usr/lib/x86_64-linux-gnu/libc.so.6
fn=(1) malloc
0xad760 9
0xad750 6
fn=(2) realloc
0xae1a0 4
0xae1b0 4
ob=(2) /work/throughput-abc
fn=(3) throughput::counted
0x1000 7
cob=(1)
cfn=(1)
calls=6 0xad750
0x1004 30
fn=(4) __rust_alloc
cob=(1)
cfn=(1)
calls=2 0xad750
0x3000 10
";
        let binary = Path::new("/elsewhere/throughput-abc");
        assert_eq!(own_cost(entries, binary).allocations, 6 + 4);
        assert_eq!(own_cost(jumps, binary).allocations, 6 + 4);
    }

    #[test]
    fn an_entry_is_summed_over_its_blocks_and_kept_to_its_object() {
        // malloc's first instruction written in two blocks (3 + 2 entries),
        // and another object's `malloc` at a lower address, which is not
        // libc's entry and does not replace it.
        let profile = "\
ob=(1) /usr/lib/x86_64-linux-gnu/libc.so.6
fn=(1) malloc
0xad750 3
0xad760 8
ob=(2) /usr/lib/libother.so
fn=(1)
0x100 7
0x104 7
ob=(1)
fn=(1)
0xad750 2
";
        let binary = Path::new("/elsewhere/throughput-abc");
        assert_eq!(own_cost(profile, binary).allocations, 3 + 2 + 7);
    }

    #[test]
    fn a_count_is_within_over_or_under_its_budget() {
        assert_eq!(verdict(1_000, 1_000, TOLERANCE), Verdict::Within);
        assert_eq!(verdict(1_029, 1_000, TOLERANCE), Verdict::Within);
        assert_eq!(verdict(1_031, 1_000, TOLERANCE), Verdict::Over);
        assert_eq!(verdict(969, 1_000, TOLERANCE), Verdict::Under);
        // Allocator calls: within ALLOCATION_SLACK calls, whatever the size.
        let allocations = "parse_corpus_allocations";
        assert_eq!(judge(allocations, 1_002, 1_000), Verdict::Within);
        assert_eq!(judge(allocations, 1_003, 1_000), Verdict::Over);
        assert_eq!(judge(allocations, 998, 1_000), Verdict::Within);
        assert_eq!(judge(allocations, 997, 1_000), Verdict::Under);
        assert_eq!(judge(allocations, 1_000_003, 1_000_000), Verdict::Over);
        // Instructions: within TOLERANCE.
        assert_eq!(judge("parse_corpus", 1_029, 1_000), Verdict::Within);
        assert_eq!(judge("parse_corpus", 1_031, 1_000), Verdict::Over);
        assert_eq!(change("parse_corpus_allocations", 220_053, 219_819), "+234");
        assert_eq!(change("parse_corpus", 1_050, 1_000), "+5.0%");
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
