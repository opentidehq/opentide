//! The `corpus` subcommands: argument parsing, files and processes.

use super::configuration;
use super::coverage;
use super::faults::{self, Catalogue, Kind, Verdict};
use super::generate::{self, Counts, Layout, Options};
use super::structural;
use super::workspace::Workspace;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

/// The usage of `cargo xtask corpus`.
pub const USAGE: &str = "\
usage: cargo xtask corpus <command> [options]

commands:
  generate --seed N [--scale F | --threats N --objectives N --rules N]
           [--layout standard|explicit|custom] --out DIR
                 write the heavy workspace for seed N (default counts
                 300/300/500, --scale multiplies them); DIR must not exist
                 or be empty. --digest prints the digest instead of writing
  faults --check --engine python [--oracle BIN] [--only ID,...] [--jobs N]
         [--keep DIR] [--report FILE] [--catalogue FILE]
                 apply each fault kind of tests/corpora/faults.toml to its own
                 copy of the clean workspace, run the oracle, and check it
                 reports exactly the expected codes and severities
  faults --check --engine rust [--oracle BIN] [--only structural|ID,...]
         [--keep DIR] [--catalogue FILE]
                 the structural fault kinds (UC-1.2): each object file read and
                 converted by opentide-schema, every schema_validation finding
                 compared with the oracle's field for field (code, field path,
                 message, line, columns, yaml_line), and yaml_parse by code
  faults --check --engine rust [--oracle BIN] --only configuration|ID,...
         [--keep DIR] [--catalogue FILE]
                 the configuration fault kinds (UC-1.5): each workspace's
                 configuration resolved by opentide-schema, and what validate
                 reports for it compared with the oracle field for field
                 (code, severity, field path, message), or the failure that
                 stops resolution; without --only, both groups run
  faults --out DIR [--catalogue FILE]
                 write one workspace ([combined] counts) with every fault
                 kind not marked isolated applied once (twice if cross-file)
                 to files of its own, and DIR.faults.json beside it listing
                 each kind's files, command and expected codes
  clean --engine python [--oracle BIN] --repo DIR
                 run the oracle's validate and lint on DIR and fail on any
                 finding (the clean heavy workspace has none); prints timings
  codes --engine python [--oracle BIN] [--write]
                 list the diagnostic codes in scope from the oracle
                 (tests/corpora/codes.toml); --write records them
  coverage [--check | --write] [--dir DIR]
                 map every code in tests/corpora/codes.toml to the fault
                 kinds that produce it; --write records tests/corpora/COVERAGE.md,
                 --check fails when a code has no kind or the file is stale;
                 --dir reads faults.toml, codes.toml and COVERAGE.md from DIR

The oracle is BIN, else $OPENTIDE_ORACLE, else `opentide` on PATH; it must
print the version faults.toml names. `--engine rust` covers the structural
kinds (opentide-schema, UC-1.2) and the configuration kinds (UC-1.5) today;
every kind comes with the Rust engine's validate (UC-2.x).
";

/// Runs `corpus <args>`; the process exit status.
pub fn run(args: &[String]) -> Result<u8> {
    let Some((command, rest)) = args.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };
    match command.as_str() {
        "generate" => generate_command(rest),
        "faults" => faults_command(rest),
        "codes" => codes_command(rest),
        "clean" => clean_command(rest),
        "coverage" => coverage_command(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(0)
        }
        other => bail!("unknown command `{other}`\n\n{USAGE}"),
    }
}

fn value<'a>(args: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<&'a str> {
    args.next()
        .map(String::as_str)
        .with_context(|| format!("{flag} needs a value"))
}

fn number(text: &str, flag: &str) -> Result<usize> {
    text.parse()
        .with_context(|| format!("{flag}: `{text}` is not a whole number"))
}

/// Parses the generator's options.
pub fn parse_options(args: &[String]) -> Result<(Options, Option<String>, bool)> {
    let mut seed = None;
    let mut scale = None;
    let mut counts = [None, None, None];
    let mut layout = Layout::Explicit;
    let mut out = None;
    let mut digest = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                let text = value(&mut args, arg)?;
                seed = Some(
                    text.parse::<u64>()
                        .with_context(|| format!("--seed: `{text}` is not a whole number"))?,
                );
            }
            "--scale" => {
                let text = value(&mut args, arg)?;
                let factor: f64 = text
                    .parse()
                    .with_context(|| format!("--scale: `{text}` is not a number"))?;
                scale = Some(
                    Counts::scaled(factor)
                        .with_context(|| format!("--scale: `{text}` is not in (0, 1000]"))?,
                );
            }
            "--threats" => counts[0] = Some(number(value(&mut args, arg)?, arg)?),
            "--objectives" => counts[1] = Some(number(value(&mut args, arg)?, arg)?),
            "--rules" => counts[2] = Some(number(value(&mut args, arg)?, arg)?),
            "--layout" => {
                let text = value(&mut args, arg)?;
                layout = Layout::parse(text).with_context(|| {
                    format!("--layout: `{text}` is not standard, explicit or custom")
                })?;
            }
            "--out" => out = Some(value(&mut args, arg)?.to_string()),
            "--digest" => digest = true,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let seed = seed.context("--seed is required")?;
    if scale.is_some() && counts.iter().any(Option::is_some) {
        bail!("--scale and --threats/--objectives/--rules exclude each other");
    }
    let base = scale.unwrap_or(generate::DEFAULT_COUNTS);
    let counts = Counts {
        threats: counts[0].unwrap_or(base.threats),
        objectives: counts[1].unwrap_or(base.objectives),
        rules: counts[2].unwrap_or(base.rules),
    };
    Ok((
        Options {
            seed,
            counts,
            layout,
        },
        out,
        digest,
    ))
}

fn generate_command(args: &[String]) -> Result<u8> {
    let (options, out, digest) = parse_options(args)?;
    let started = Instant::now();
    let workspace = generate::generate(&options);
    if digest {
        println!("{}", workspace.digest());
        return Ok(0);
    }
    let out = out.context("--out is required (or --digest)")?;
    write_workspace(&workspace, Path::new(&out))?;
    eprintln!(
        "corpus generate: seed {} ({}) into {out} in {} ms; digest {}",
        options.seed,
        workspace.summary(),
        started.elapsed().as_millis(),
        workspace.digest()
    );
    Ok(0)
}

/// Writes `workspace` under `root`, which must not exist or be empty: the
/// generator never overwrites a file it did not write.
pub fn write_workspace(workspace: &Workspace, root: &Path) -> Result<()> {
    if root.exists() {
        let mut entries =
            std::fs::read_dir(root).with_context(|| format!("cannot read {}", root.display()))?;
        if entries.next().is_some() {
            bail!("{} exists and is not empty", root.display());
        }
    }
    for (path, text) in workspace.rendered() {
        if !super::faults::is_relative_inside(&path) {
            bail!("{path} is not a path inside the workspace");
        }
        let target = root.join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .with_context(|| format!("cannot create {}", target.display()))?;
        std::io::Write::write_all(&mut file, text.as_bytes())
            .with_context(|| format!("cannot write {}", target.display()))?;
    }
    Ok(())
}

/// The repository root: `CARGO_MANIFEST_DIR`'s parent as `cargo run` sets
/// it at run time, else the working directory (never compiled in:
/// xtask/AGENTS.md).
pub fn repo_root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .and_then(|dir| dir.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `tests/corpora/` under the repository root.
pub fn corpora_dir() -> PathBuf {
    repo_root().join("tests").join("corpora")
}

/// The oracle executable: `--oracle`, `$OPENTIDE_ORACLE`, or `opentide`.
pub(crate) fn oracle_bin(flag: Option<&str>) -> PathBuf {
    flag.map(PathBuf::from)
        .or_else(|| std::env::var_os("OPENTIDE_ORACLE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("opentide"))
}

/// Runs the oracle without the variables that would point it elsewhere.
pub(crate) fn oracle_command(bin: &Path, env: &BTreeMap<String, String>) -> Command {
    let mut command = Command::new(bin);
    // A kind that sets a proxy gets only its own: Python's urllib lets an
    // inherited lowercase variable win over an uppercase one. Every spelling
    // the kind does not set itself is removed; on Windows, where `https_proxy`
    // and `HTTPS_PROXY` are one variable, setting it replaces the inherited one.
    if env
        .keys()
        .any(|k| k.to_ascii_lowercase().ends_with("_proxy"))
    {
        for name in ["http_proxy", "https_proxy", "all_proxy", "no_proxy"] {
            for var in [name.to_string(), name.to_ascii_uppercase()] {
                if !env.keys().any(|k| same_variable(k, &var)) {
                    command.env_remove(&var);
                }
            }
        }
    }
    for var in [
        "OPENTIDE_REPO_ROOT",
        "OPENTIDE_TIDE_WORKSPACE",
        "OPENTIDE_DATA_ROOT",
        "OPENTIDE_DEBUG",
        "OPENTIDE_PROXY",
    ] {
        command.env_remove(var);
    }
    command.env("NO_COLOR", "1");
    command.envs(env);
    command
}

/// Whether two environment variable names name one variable: case-blind on
/// Windows, exact elsewhere.
fn same_variable(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// How many objects (validate) or object files (lint) the run checked.
fn checked(document: &serde_json::Value) -> Option<u64> {
    let summary = document.get("summary")?;
    summary
        .get("objects")
        .or_else(|| summary.get("files"))
        .and_then(serde_json::Value::as_u64)
}

/// A run that checked nothing, or stopped, proves nothing: `failure` must
/// be null and the run must have checked `expected` objects (at least one,
/// when `None`).
fn require_checked(
    document: &serde_json::Value,
    expected: Option<usize>,
    what: &str,
) -> Result<()> {
    if let Some(failure) = document.get("failure").filter(|f| !f.is_null()) {
        bail!("{what}: the oracle's run failed: {failure}");
    }
    let count = checked(document).unwrap_or(0);
    let count = usize::try_from(count).unwrap_or(usize::MAX);
    match expected {
        Some(expected) if count != expected => {
            bail!("{what}: the oracle checked {count} objects, not {expected}")
        }
        None if count == 0 => bail!("{what}: the oracle checked no object"),
        _ => Ok(()),
    }
}

/// `require_checked` for a run of `command`: a whole `validate` or `lint`
/// must have checked every object; a run of one check (`--check cve`,
/// `--check sharing-config`), which loads no object, must not have failed.
fn require_run(
    document: &serde_json::Value,
    command: &[String],
    objects: usize,
    what: &str,
) -> Result<()> {
    if command.len() == 1 {
        return require_checked(document, Some(objects), what);
    }
    match document.get("failure").filter(|f| !f.is_null()) {
        Some(failure) => bail!("{what}: the oracle's run failed: {failure}"),
        None => Ok(()),
    }
}

/// The number of object files (threats, objectives, rules) in `workspace`.
fn object_files(workspace: &Workspace) -> usize {
    use super::workspace::Family;
    workspace
        .files
        .iter()
        .filter(|f| matches!(f.family, Family::Threat | Family::Objective | Family::Rule))
        .count()
}

/// Removes the scratch directory however the run ends, unless `--keep`.
pub(crate) struct Scratch {
    pub(crate) path: PathBuf,
    pub(crate) keep: bool,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Checks that `bin` is the oracle version the catalogue names.
pub(crate) fn check_oracle_version(bin: &Path, expected: &str) -> Result<()> {
    let output = oracle_command(bin, &BTreeMap::new())
        .arg("--version")
        .output()
        .with_context(|| format!("cannot run the oracle `{}`", bin.display()))?;
    let version = String::from_utf8_lossy(&output.stdout);
    let version = version.trim();
    if version != format!("opentide {expected}") {
        bail!(
            "the oracle `{}` is `{version}`, not opentide {expected} (install opentide=={expected} \
             in its own venv: tests/corpora/README.md)",
            bin.display()
        );
    }
    Ok(())
}

/// Runs `opentide --json --repo ROOT ARGS...` and parses its document.
fn run_oracle(
    bin: &Path,
    root: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> Result<serde_json::Value> {
    let output = oracle_command(bin, env)
        .arg("--json")
        .arg("--repo")
        .arg(root)
        .args(args)
        .output()
        .with_context(|| format!("cannot run the oracle `{}`", bin.display()))?;
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "the oracle printed no JSON document for {args:?} in {}; stderr: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[derive(Clone)]
struct FaultArgs {
    check: bool,
    engine: Option<String>,
    oracle: Option<String>,
    only: Option<BTreeSet<String>>,
    jobs: usize,
    keep: Option<PathBuf>,
    report: Option<PathBuf>,
    out: Option<PathBuf>,
    catalogue: PathBuf,
}

fn parse_fault_args(args: &[String]) -> Result<FaultArgs> {
    let mut parsed = FaultArgs {
        check: false,
        engine: None,
        oracle: None,
        only: None,
        jobs: std::thread::available_parallelism().map_or(2, |n| n.get()),
        keep: None,
        report: None,
        out: None,
        catalogue: corpora_dir().join("faults.toml"),
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--check" => parsed.check = true,
            "--engine" => parsed.engine = Some(value(&mut args, arg)?.to_string()),
            "--oracle" => parsed.oracle = Some(value(&mut args, arg)?.to_string()),
            "--only" => {
                parsed.only = Some(
                    value(&mut args, arg)?
                        .split(',')
                        .map(str::to_string)
                        .collect(),
                );
            }
            "--jobs" => parsed.jobs = number(value(&mut args, arg)?, arg)?.max(1),
            "--keep" => parsed.keep = Some(PathBuf::from(value(&mut args, arg)?)),
            "--report" => parsed.report = Some(PathBuf::from(value(&mut args, arg)?)),
            "--out" => parsed.out = Some(PathBuf::from(value(&mut args, arg)?)),
            "--catalogue" => parsed.catalogue = PathBuf::from(value(&mut args, arg)?),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    Ok(parsed)
}

pub(crate) fn load_catalogue(path: &Path) -> Result<Catalogue> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Catalogue::parse(&text).with_context(|| format!("in {}", path.display()))
}

/// The engine a check runs against: only the oracle today.
fn require_python(engine: Option<&str>) -> Result<Option<u8>> {
    match engine {
        Some("python") => Ok(None),
        Some("rust") => {
            eprintln!(
                "xtask corpus: --engine rust is not implemented yet; the Rust engine's \
                 validate (UC-2.x, https://github.com/opentidehq/opentide/issues/790) runs it"
            );
            Ok(Some(1))
        }
        Some(other) => bail!("--engine `{other}` is neither python nor rust"),
        None => bail!("--engine python is required (the oracle the expectations name)"),
    }
}

fn faults_command(args: &[String]) -> Result<u8> {
    let parsed = parse_fault_args(args)?;
    let catalogue = load_catalogue(&parsed.catalogue)?;
    if let Some(out) = &parsed.out {
        return materialise(&catalogue, out);
    }
    if !parsed.check {
        bail!("faults needs --check or --out\n\n{USAGE}");
    }
    if parsed.engine.as_deref() == Some("rust") {
        return rust_check(&parsed, &catalogue);
    }
    if let Some(code) = require_python(parsed.engine.as_deref())? {
        return Ok(code);
    }
    let bin = oracle_bin(parsed.oracle.as_deref());
    check_oracle_version(&bin, &catalogue.oracle)?;
    let base = generate::generate(&catalogue.base.options()?);
    let kinds: Vec<&Kind> = catalogue
        .kinds
        .iter()
        .filter(|k| parsed.only.as_ref().is_none_or(|only| only.contains(&k.id)))
        .collect();
    if let Some(only) = &parsed.only {
        for id in only {
            if catalogue.kind(id).is_none() {
                bail!("--only: no fault kind `{id}`");
            }
        }
    }
    let scratch = match &parsed.keep {
        Some(dir) => dir.clone(),
        None => std::env::temp_dir().join(format!("opentide-corpus-faults-{}", std::process::id())),
    };
    // Absolute, so that XDG_STATE_HOME below is one the oracle honours.
    let scratch = std::path::absolute(&scratch)
        .with_context(|| format!("cannot resolve {}", scratch.display()))?;
    if scratch.exists() {
        bail!(
            "{} exists; remove it or name another --keep",
            scratch.display()
        );
    }
    let guard = Scratch {
        path: scratch.clone(),
        keep: parsed.keep.is_some(),
    };
    let started = Instant::now();
    // The clean base must be clean under every command the kinds use.
    let commands: BTreeSet<(Vec<String>, BTreeMap<String, String>)> = kinds
        .iter()
        .filter(|k| k.baseline)
        .map(|k| (k.command.clone(), k.env.clone()))
        .collect();
    let base_dir = scratch.join("_base");
    write_workspace(&base, &base_dir)?;
    for (command, env) in &commands {
        let mut env = env.clone();
        env.entry("XDG_STATE_HOME".to_string())
            .or_insert_with(|| scratch.join("_state").to_string_lossy().into_owned());
        let document = run_oracle(&bin, &base_dir, command, &env)?;
        require_run(
            &document,
            command,
            object_files(&base),
            &format!("the clean base under {command:?}"),
        )?;
        let found = faults::findings(&document, &base_dir.to_string_lossy())?;
        if !found.is_empty() {
            bail!(
                "the clean base workspace has {} finding(s) under {command:?}, first: {:?}",
                found.len(),
                found[0]
            );
        }
    }
    let verdicts: Mutex<Vec<(Verdict, Vec<String>)>> = Mutex::new(Vec::new());
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..parsed.jobs.min(kinds.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(kind) = kinds.get(index) else { break };
                    match run_kind(&bin, &base, kind, &scratch) {
                        Ok(result) => {
                            if let Ok(mut v) = verdicts.lock() {
                                v.push(result);
                            }
                        }
                        Err(error) => {
                            if let Ok(mut e) = errors.lock() {
                                e.push(format!("{}: {error:#}", kind.id));
                            }
                        }
                    }
                }
            });
        }
    });
    let mut verdicts = verdicts.into_inner().unwrap_or_default();
    verdicts.sort_by(|a, b| a.0.id.cmp(&b.0.id));
    let mut errors = errors.into_inner().unwrap_or_default();
    drop(guard);
    if verdicts.len() + errors.len() != kinds.len() {
        errors.push(format!(
            "{} kinds ran, {} reported: a result was lost",
            kinds.len(),
            verdicts.len() + errors.len()
        ));
    }
    let failed: Vec<&(Verdict, Vec<String>)> = verdicts
        .iter()
        .filter(|(v, _)| !v.problems.is_empty())
        .collect();
    for (verdict, _) in &verdicts {
        let status = if verdict.problems.is_empty() {
            "ok  "
        } else {
            "FAIL"
        };
        let reported: Vec<String> = verdict
            .reported
            .iter()
            .map(|(code, n)| format!("{code}x{n}"))
            .collect();
        println!("{status} {:<48} {}", verdict.id, reported.join(" "));
        for problem in &verdict.problems {
            println!("       - {problem}");
        }
    }
    for error in &errors {
        println!("ERR  {error}");
    }
    if let Some(report) = &parsed.report {
        let json: Vec<serde_json::Value> = verdicts
            .iter()
            .map(|(v, targets)| {
                serde_json::json!({
                    "id": v.id,
                    "ok": v.problems.is_empty(),
                    "problems": v.problems,
                    "reported": v.reported,
                    "targets": targets,
                })
            })
            .collect();
        std::fs::write(report, serde_json::to_string_pretty(&json)? + "\n")
            .with_context(|| format!("cannot write {}", report.display()))?;
    }
    println!(
        "corpus faults: {} kinds, {} passed, {} failed, {} could not run, in {:.1} s against {}",
        kinds.len(),
        verdicts.len() - failed.len(),
        failed.len(),
        errors.len(),
        started.elapsed().as_secs_f64(),
        catalogue.oracle
    );
    if !errors.is_empty() {
        return Ok(2);
    }
    Ok(u8::from(!failed.is_empty()))
}

fn run_kind(
    bin: &Path,
    base: &Workspace,
    kind: &Kind,
    scratch: &Path,
) -> Result<(Verdict, Vec<String>)> {
    let mut workspace = base.clone();
    let targets = faults::select(&workspace, kind, &BTreeSet::new())?;
    let target_paths = faults::apply(&mut workspace, kind, &targets)?;
    let dir = scratch.join(&kind.id);
    write_workspace(&workspace, &dir)?;
    // Crash logs of a crashing run stay in the scratch directory.
    let mut env = kind.env.clone();
    env.entry("XDG_STATE_HOME".to_string())
        .or_insert_with(|| scratch.join("_state").to_string_lossy().into_owned());
    let document = run_oracle(bin, &dir, &kind.command, &env)?;
    let found = faults::findings(&document, &dir.to_string_lossy())?;
    // A silence proves something only if the run checked every object.
    if kind.codes.is_empty() {
        require_run(&document, &kind.command, object_files(&workspace), &kind.id)?;
    }
    Ok((faults::judge(kind, &target_paths, &found), target_paths))
}

/// `faults --check --engine rust`: `--only` split between the structural
/// group and the configuration group; without it, both.
fn rust_check(parsed: &FaultArgs, catalogue: &Catalogue) -> Result<u8> {
    let config: BTreeSet<&str> = configuration::CONFIGURATION
        .iter()
        .map(|(id, _)| *id)
        .collect();
    let Some(only) = &parsed.only else {
        let structural = structural_check(parsed, catalogue)?;
        let all: BTreeSet<String> = config.iter().map(|id| (*id).to_string()).collect();
        let configuration = configuration_check(parsed, catalogue, &all)?;
        return Ok(structural.max(configuration));
    };
    let mut config_ids = BTreeSet::new();
    let mut rest = BTreeSet::new();
    for id in only {
        if id == configuration::GROUP {
            config_ids.extend(config.iter().map(|id| (*id).to_string()));
        } else if config.contains(id.as_str()) {
            config_ids.insert(id.clone());
        } else {
            rest.insert(id.clone());
        }
    }
    let mut status = 0;
    if !rest.is_empty() {
        let mut structural = parsed.clone();
        structural.only = Some(rest);
        status = structural_check(&structural, catalogue)?;
    }
    if !config_ids.is_empty() {
        status = status.max(configuration_check(parsed, catalogue, &config_ids)?);
    }
    Ok(status)
}

/// A configuration folder as [`configuration::rust_findings`] reads it:
/// every file directly in it or in a folder directly under it, `path` the
/// name it carries in messages. `None` when it is not a folder.
pub(crate) fn read_folder(
    dir: &Path,
    path: &str,
) -> Result<Option<opentide_schema::configuration::resolve::Folder>> {
    if !dir.is_dir() {
        return Ok(None);
    }
    let mut folder = opentide_schema::configuration::resolve::Folder {
        path: path.to_owned(),
        ..Default::default()
    };
    for entry in std::fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            folder.folders.push(name.clone());
            for nested in std::fs::read_dir(entry.path())? {
                let nested = nested?;
                if nested.file_type()?.is_file() {
                    let text = std::fs::read_to_string(nested.path())
                        .with_context(|| format!("cannot read {}", nested.path().display()))?;
                    folder.files.push((
                        format!("{name}/{}", nested.file_name().to_string_lossy()),
                        text,
                    ));
                }
            }
        } else if kind.is_file() {
            let text = std::fs::read_to_string(entry.path())
                .with_context(|| format!("cannot read {}", entry.path().display()))?;
            folder.files.push((name, text));
        }
    }
    Ok(Some(folder))
}

/// The configuration folders of the workspace at `dir`: its own, its
/// parent instance's, and the `sharing.toml` layers (bundled first) by
/// absolute folder.
type Folders = (
    Option<opentide_schema::configuration::resolve::Folder>,
    Option<opentide_schema::configuration::resolve::Folder>,
    Vec<(String, Option<String>, bool)>,
);

fn workspace_folders(dir: &Path) -> Result<Folders> {
    let dir =
        std::fs::canonicalize(dir).with_context(|| format!("cannot resolve {}", dir.display()))?;
    let own_dir = dir.join(".opentide").join("configurations");
    let own = read_folder(&own_dir, ".opentide/configurations")?;
    let parent_dir = dir
        .parent()
        .map(|parent| parent.join(".opentide").join("configurations"));
    let parent = match &parent_dir {
        Some(parent_dir) if *parent_dir != own_dir => {
            read_folder(parent_dir, "../.opentide/configurations")?
        }
        _ => None,
    };
    let mut sharing = vec![(
        "<bundled>".to_owned(),
        opentide_schema::configuration::bundled::text("sharing.toml").map(str::to_owned),
        false,
    )];
    for (folder, path) in [(&own, Some(&own_dir)), (&parent, parent_dir.as_ref())] {
        if let (Some(folder), Some(path)) = (folder, path) {
            sharing.push((
                path.to_string_lossy().into_owned(),
                folder
                    .files
                    .iter()
                    .find(|(name, _)| name == "sharing.toml")
                    .map(|(_, text)| text.clone()),
                folder.folders.iter().any(|name| name == "sharing"),
            ));
        }
    }
    Ok((own, parent, sharing))
}

/// `faults --check --engine rust --only configuration`: the configuration
/// kinds, the Rust resolution and checks against the oracle
/// ([`configuration`]).
fn configuration_check(
    parsed: &FaultArgs,
    catalogue: &Catalogue,
    ids: &BTreeSet<String>,
) -> Result<u8> {
    for id in ids {
        if catalogue.kind(id).is_none() {
            bail!("--only: no fault kind `{id}`");
        }
    }
    let bin = oracle_bin(parsed.oracle.as_deref());
    check_oracle_version(&bin, &catalogue.oracle)?;
    let base = generate::generate(&catalogue.base.options()?);
    let scratch = match &parsed.keep {
        Some(dir) => dir.join("configuration"),
        None => std::env::temp_dir().join(format!(
            "opentide-corpus-configuration-{}",
            std::process::id()
        )),
    };
    let scratch = std::path::absolute(&scratch)
        .with_context(|| format!("cannot resolve {}", scratch.display()))?;
    if scratch.exists() {
        bail!(
            "{} exists; remove it or name another --keep",
            scratch.display()
        );
    }
    let guard = Scratch {
        path: scratch.clone(),
        keep: parsed.keep.is_some(),
    };
    let changelog = std::fs::read_to_string(repo_root().join("CHANGELOG.md"))
        .context("reading CHANGELOG.md for the approved differences")?;
    let started = Instant::now();
    let mut failed = 0usize;
    for id in ids {
        let kind = catalogue
            .kind(id)
            .with_context(|| format!("no fault kind `{id}` in the catalogue"))?;
        let mut workspace = base.clone();
        let targets = faults::select(&workspace, kind, &BTreeSet::new())?;
        faults::apply(&mut workspace, kind, &targets)?;
        let dir = scratch.join(&kind.id);
        write_workspace(&workspace, &dir)?;
        let mut env = kind.env.clone();
        env.entry("XDG_STATE_HOME".to_string())
            .or_insert_with(|| scratch.join("_state").to_string_lossy().into_owned());
        let document = run_oracle(&bin, &dir, &kind.command, &env)?;
        let sharing = configuration::is_sharing(&kind.command);
        let oracle = configuration::oracle_findings(&document, sharing);
        let (own, parent, layers) = workspace_folders(&dir)?;
        let rust =
            configuration::rust_findings(&kind.command, own.as_ref(), parent.as_ref(), &layers);
        let mut problems = Vec::new();
        let approved = configuration::approved(id);
        let equal = match approved {
            Some(approved) => {
                if rust == oracle {
                    problems.push(format!(
                        "the approved difference is stale: the findings are equal ({})",
                        approved.reason
                    ));
                }
                if !changelog.contains(approved.changelog) {
                    problems.push(format!("CHANGELOG.md has no {:?}", approved.changelog));
                }
                configuration::codes_only(&rust) == configuration::codes_only(&oracle)
            }
            None => rust == oracle,
        };
        if !equal {
            problems.push(format!(
                "findings differ:\n         oracle: {}\n         rust:   {}",
                serde_json::to_string(&oracle)?,
                serde_json::to_string(&rust)?
            ));
        }
        // Not vacuous: a kind that expects codes has findings to compare.
        if !kind.codes.is_empty() && oracle.is_empty() {
            problems.push("the oracle reports no configuration finding".to_owned());
        }
        let status = if problems.is_empty() { "ok  " } else { "FAIL" };
        println!(
            "{status} {id:<48} {} finding(s) compared{}",
            oracle.len(),
            if approved.is_some() {
                ", codes only (approved)"
            } else {
                ""
            }
        );
        for problem in &problems {
            println!("       - {problem}");
        }
        if !problems.is_empty() {
            failed += 1;
        }
    }
    drop(guard);
    println!(
        "corpus faults --engine rust: {} configuration kinds, {} passed, {failed} failed, in \
         {:.1} s against {}",
        ids.len(),
        ids.len() - failed,
        started.elapsed().as_secs_f64(),
        catalogue.oracle
    );
    Ok(u8::from(failed > 0))
}

/// `faults --check --engine rust`: the structural kinds, the Rust conversion
/// against the oracle, finding for finding ([`structural`]).
fn structural_check(parsed: &FaultArgs, catalogue: &Catalogue) -> Result<u8> {
    let structural: BTreeSet<&str> = structural::STRUCTURAL.iter().map(|(id, _)| *id).collect();
    let mut ids: BTreeSet<String> = BTreeSet::new();
    match &parsed.only {
        None => ids.extend(structural.iter().map(|id| (*id).to_string())),
        Some(only) => {
            for id in only {
                if id == structural::GROUP {
                    ids.extend(structural.iter().map(|id| (*id).to_string()));
                } else if structural.contains(id.as_str()) {
                    ids.insert(id.clone());
                } else if catalogue.kind(id).is_none() {
                    bail!("--only: no fault kind `{id}`");
                } else {
                    bail!(
                        "--engine rust checks the structural kinds only (UC-1.2; --only \
                         structural lists them): `{id}` comes with the Rust engine's validate \
                         (UC-2.x)"
                    );
                }
            }
        }
    }
    let bin = oracle_bin(parsed.oracle.as_deref());
    check_oracle_version(&bin, &catalogue.oracle)?;
    let base = generate::generate(&catalogue.base.options()?);
    let scratch = match &parsed.keep {
        Some(dir) => dir.clone(),
        None => {
            std::env::temp_dir().join(format!("opentide-corpus-structural-{}", std::process::id()))
        }
    };
    let scratch = std::path::absolute(&scratch)
        .with_context(|| format!("cannot resolve {}", scratch.display()))?;
    if scratch.exists() {
        bail!(
            "{} exists; remove it or name another --keep",
            scratch.display()
        );
    }
    let guard = Scratch {
        path: scratch.clone(),
        keep: parsed.keep.is_some(),
    };
    let changelog = std::fs::read_to_string(repo_root().join("CHANGELOG.md"))
        .context("reading CHANGELOG.md for the approved differences")?;
    let started = Instant::now();
    let mut failed = 0usize;
    // The clean base: the stand-in models report nothing on any object.
    let mut checked = 0usize;
    for file in &base.files {
        if let Some(found) = structural::check_object(&file.path, file.render().as_bytes()) {
            checked += 1;
            if !found.is_empty() {
                bail!(
                    "the clean base: the Rust conversion reports {} finding(s) on {}, first: {}",
                    found.len(),
                    file.path,
                    found[0]
                );
            }
        }
    }
    println!(
        "ok   {:<48} {checked} rules and threats, no finding",
        "(clean base)"
    );
    for id in &ids {
        let kind = catalogue
            .kind(id)
            .with_context(|| format!("no fault kind `{id}` in the catalogue"))?;
        let mut workspace = base.clone();
        let targets = faults::select(&workspace, kind, &BTreeSet::new())?;
        let target_paths = faults::apply(&mut workspace, kind, &targets)?;
        let dir = scratch.join(&kind.id);
        write_workspace(&workspace, &dir)?;
        let mut env = kind.env.clone();
        env.entry("XDG_STATE_HOME".to_string())
            .or_insert_with(|| scratch.join("_state").to_string_lossy().into_owned());
        let document = run_oracle(&bin, &dir, &kind.command, &env)?;
        let mut problems = Vec::new();
        let mut compared = 0usize;
        let approved = structural::approved(id);
        let mut applied = 0usize;
        for file in &workspace.files {
            let Some(rust) = structural::check_object(&file.path, file.render().as_bytes()) else {
                continue;
            };
            let rust = structural::comparable(&rust);
            let oracle = structural::oracle_findings(&document, &file.path);
            compared += rust.len();
            if rust != oracle
                && let Some(approved) = approved
                && serde_json::from_str::<serde_json::Value>(approved.oracle)?
                    == serde_json::Value::from(oracle.clone())
                && serde_json::from_str::<serde_json::Value>(approved.rust)?
                    == serde_json::Value::from(rust.clone())
            {
                applied += 1;
                continue;
            }
            if rust != oracle {
                problems.push(format!(
                    "{}:\n         oracle: {}\n         rust:   {}",
                    file.path,
                    serde_json::to_string(&oracle)?,
                    serde_json::to_string(&rust)?
                ));
            }
        }
        if let Some(approved) = approved {
            if applied == 0 {
                problems.push(format!(
                    "the approved difference applied to no file: it is stale ({})",
                    approved.reason
                ));
            }
            if !changelog.contains(approved.changelog) {
                problems.push(format!("CHANGELOG.md has no {:?}", approved.changelog));
            }
        }
        // Not vacuous: each target carries a finding the two agree on, or the
        // approved difference.
        for path in target_paths.iter().filter(|_| approved.is_none()) {
            let file = workspace
                .files
                .iter()
                .find(|file| &file.path == path)
                .with_context(|| format!("{id}: no target {path}"))?;
            let rust =
                structural::check_object(&file.path, file.render().as_bytes()).unwrap_or_default();
            if rust.is_empty() {
                problems.push(format!("{path}: no finding on a target"));
            }
        }
        let status = if problems.is_empty() { "ok  " } else { "FAIL" };
        println!(
            "{status} {id:<48} {} target(s), {compared} finding(s) compared{}",
            target_paths.len(),
            if applied > 0 {
                format!(", {applied} file(s) differ as approved")
            } else {
                String::new()
            }
        );
        for problem in &problems {
            println!("       - {problem}");
        }
        if !problems.is_empty() {
            failed += 1;
        }
    }
    drop(guard);
    println!(
        "corpus faults --engine rust: {} structural kinds, {} passed, {failed} failed, in {:.1} s \
         against {}",
        ids.len(),
        ids.len() - failed,
        started.elapsed().as_secs_f64(),
        catalogue.oracle
    );
    Ok(u8::from(failed > 0))
}

/// `DIR.faults.json` beside `DIR` (also for `DIR/`), never inside it.
fn manifest_path(out: &Path) -> Result<PathBuf> {
    let name = out
        .file_name()
        .with_context(|| format!("--out {} names no directory", out.display()))?;
    let mut manifest_name = name.to_os_string();
    manifest_name.push(".faults.json");
    Ok(out.with_file_name(manifest_name))
}

/// Writes the combined fault workspace and its manifest.
pub(crate) fn materialise(catalogue: &Catalogue, out: &Path) -> Result<u8> {
    let options = catalogue.combined_options()?;
    let mut workspace = generate::generate(&options);
    let mut taken = BTreeSet::new();
    let mut manifest = Vec::new();
    for kind in catalogue.kinds.iter().filter(|k| !k.isolated) {
        let mut once = kind.clone();
        once.count = kind.combined_count();
        let kind = &once;
        let targets = faults::select(&workspace, kind, &taken)?;
        taken.extend(targets.iter().copied());
        let before = workspace.files.len();
        faults::apply(&mut workspace, kind, &targets)?;
        if workspace.files.len() < before {
            bail!("fault kind `{}` deletes files; mark it isolated", kind.id);
        }
        // The files the kind changed, and those it added (a state shard, a
        // configuration file), where its findings are.
        let files: Vec<String> = targets
            .iter()
            .copied()
            .chain(before..workspace.files.len())
            .map(|i| workspace.files[i].path.clone())
            .collect();
        // Files a kind adds are its own, never another kind's target.
        taken.extend(before..workspace.files.len());
        let severities: BTreeMap<&str, &str> = kind
            .codes
            .iter()
            .filter_map(|c| kind.severity_of(c).ok().map(|s| (c.as_str(), s)))
            .collect();
        manifest.push(serde_json::json!({
            "id": kind.id,
            "class": kind.class,
            "command": kind.command,
            "env": kind.env,
            "codes": severities,
            "files": files,
        }));
    }
    let manifest_path = manifest_path(out)?;
    if manifest_path.exists() {
        bail!(
            "{} exists; the manifest is never overwritten",
            manifest_path.display()
        );
    }
    write_workspace(&workspace, out)?;
    let document = serde_json::json!({
        "oracle": catalogue.oracle,
        "base": {
            "seed": options.seed,
            "threats": options.counts.threats,
            "objectives": options.counts.objectives,
            "rules": options.counts.rules,
            "layout": options.layout.name(),
        },
        "note": "each kind is applied to files no other kind touches, once (twice for a \
                 cross-file kind); kinds marked isolated are left out. The expectations are \
                 checked per kind in isolation (faults --check), not on this workspace.",
        "digest": workspace.digest(),
        "kinds": manifest,
    });
    let mut manifest_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .with_context(|| format!("cannot create {}", manifest_path.display()))?;
    std::io::Write::write_all(
        &mut manifest_file,
        (serde_json::to_string_pretty(&document)? + "\n").as_bytes(),
    )
    .with_context(|| format!("cannot write {}", manifest_path.display()))?;
    eprintln!(
        "corpus faults: {} kinds into {} (digest {}); manifest {}",
        manifest.len(),
        out.display(),
        workspace.digest(),
        manifest_path.display()
    );
    Ok(0)
}

/// The Python the oracle runs on. The oracle is a venv's console script, so
/// the venv's interpreter sits beside it (`bin/python` on Unix,
/// `Scripts/python.exe` on Windows); failing that, the script's `#!` line
/// names it (Unix only: a Windows console script is an `.exe` launcher).
fn oracle_python(bin: &Path) -> Result<PathBuf> {
    let resolved = if bin.components().count() > 1 {
        bin.to_path_buf()
    } else {
        let mut names = vec![bin.to_path_buf()];
        if cfg!(windows) {
            names.push(bin.with_extension("exe"));
        }
        std::env::var_os("PATH")
            .and_then(|paths| {
                std::env::split_paths(&paths)
                    .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
                    .find(|candidate| candidate.is_file())
            })
            .with_context(|| format!("`{}` is not on PATH", bin.display()))?
    };
    if let Some(dir) = resolved.parent() {
        for name in ["python", "python3", "python.exe"] {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let text =
        std::fs::read(&resolved).with_context(|| format!("cannot read {}", resolved.display()))?;
    let first = text.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(first);
    let python = line
        .strip_prefix("#!")
        .map(str::trim)
        .filter(|p| !p.is_empty() && !p.contains(' '))
        .with_context(|| format!("{} has no interpreter line", resolved.display()))?;
    Ok(PathBuf::from(python))
}

fn codes_command(args: &[String]) -> Result<u8> {
    let mut engine = None;
    let mut oracle = None;
    let mut write = false;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--engine" => engine = Some(value(&mut iter, arg)?.to_string()),
            "--oracle" => oracle = Some(value(&mut iter, arg)?.to_string()),
            "--write" => write = true,
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    if let Some(code) = require_python(engine.as_deref())? {
        return Ok(code);
    }
    let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
    let bin = oracle_bin(oracle.as_deref());
    check_oracle_version(&bin, &catalogue.oracle)?;
    let python = oracle_python(&bin)?;
    let output = Command::new(&python)
        .arg("-I")
        .arg("-c")
        .arg(coverage::INVENTORY_SCRIPT)
        .output()
        .with_context(|| format!("cannot run {}", python.display()))?;
    if !output.status.success() {
        bail!(
            "the inventory script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let inventory: coverage::Inventory = serde_json::from_slice(&output.stdout)
        .context("the inventory script printed no inventory")?;
    let text = coverage::render_codes(&inventory, &catalogue.oracle);
    if write {
        let path = corpora_dir().join("codes.toml");
        std::fs::write(&path, &text).with_context(|| format!("cannot write {}", path.display()))?;
        eprintln!(
            "corpus codes: {} codes into {}",
            inventory.total(),
            path.display()
        );
    } else {
        print!("{text}");
    }
    Ok(0)
}

fn coverage_command(args: &[String]) -> Result<u8> {
    let mut mode = "print";
    let mut dir = corpora_dir();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--check" => mode = "check",
            "--write" => mode = "write",
            "--dir" => dir = PathBuf::from(value(&mut iter, arg)?),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let catalogue = load_catalogue(&dir.join("faults.toml"))?;
    let codes_path = dir.join("codes.toml");
    let codes_text = std::fs::read_to_string(&codes_path)
        .with_context(|| format!("cannot read {}", codes_path.display()))?;
    let codes = coverage::Codes::parse(&codes_text)?;
    let report = coverage::report(&codes, &catalogue);
    let rendered = coverage::render(&report, &catalogue);
    let path = dir.join("COVERAGE.md");
    match mode {
        "write" => {
            std::fs::write(&path, &rendered)
                .with_context(|| format!("cannot write {}", path.display()))?;
            eprintln!("corpus coverage: wrote {}", path.display());
        }
        "check" => {
            let recorded = std::fs::read_to_string(&path).unwrap_or_default();
            if recorded != rendered {
                eprintln!(
                    "corpus coverage: {} is stale; run `cargo xtask corpus coverage --write`",
                    path.display()
                );
                return Ok(1);
            }
        }
        _ => print!("{rendered}"),
    }
    println!("{}", report.summary());
    Ok(u8::from(
        !report.missing.is_empty() || !report.problems.is_empty(),
    ))
}

fn clean_command(args: &[String]) -> Result<u8> {
    let mut engine = None;
    let mut oracle = None;
    let mut repo = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--engine" => engine = Some(value(&mut iter, arg)?.to_string()),
            "--oracle" => oracle = Some(value(&mut iter, arg)?.to_string()),
            "--repo" => repo = Some(PathBuf::from(value(&mut iter, arg)?)),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    if let Some(code) = require_python(engine.as_deref())? {
        return Ok(code);
    }
    let repo = repo.context("--repo is required")?;
    let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
    let bin = oracle_bin(oracle.as_deref());
    check_oracle_version(&bin, &catalogue.oracle)?;
    let mut total = 0;
    for command in ["validate", "lint"] {
        let started = Instant::now();
        let document = run_oracle(&bin, &repo, &[command.to_string()], &BTreeMap::new())?;
        let elapsed = started.elapsed().as_secs_f64();
        let found = faults::findings(&document, &repo.to_string_lossy())?;
        let summary = document.get("summary").cloned().unwrap_or_default();
        if let Err(error) = require_checked(&document, None, command) {
            println!("{error:#}; summary {summary}");
            total += 1;
            continue;
        }
        println!(
            "{command}: {} finding(s) in {elapsed:.1} s; summary {summary}",
            found.len()
        );
        for finding in found.iter().take(20) {
            println!(
                "  {} {} {}",
                finding.severity,
                finding.code,
                finding.path.as_deref().unwrap_or("")
            );
        }
        total += found.len();
    }
    Ok(u8::from(total > 0))
}

#[cfg(test)]
mod tests {
    use super::{Scratch, manifest_path, oracle_command, require_checked, require_run};
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    #[test]
    fn a_kind_that_sets_a_proxy_gets_only_its_own() {
        /// What the child process sees for a variable.
        #[derive(Debug, PartialEq)]
        enum Seen {
            Set(String),
            Removed,
            Inherited,
        }
        // Names compared as the OS does: on Windows `https_proxy` and
        // `HTTPS_PROXY` are one variable.
        fn sees(command: &std::process::Command, name: &str) -> Seen {
            match command
                .get_envs()
                .filter(|(k, _)| super::same_variable(&k.to_string_lossy(), name))
                .last()
            {
                Some((_, Some(value))) => Seen::Set(value.to_string_lossy().into_owned()),
                Some((_, None)) => Seen::Removed,
                None => Seen::Inherited,
            }
        }
        let proxy = "http://127.0.0.1:9";
        let mut env = BTreeMap::new();
        env.insert("HTTPS_PROXY".to_string(), proxy.to_string());
        let command = oracle_command(Path::new("opentide"), &env);
        assert_eq!(sees(&command, "HTTPS_PROXY"), Seen::Set(proxy.to_string()));
        for var in [
            "https_proxy",
            "http_proxy",
            "HTTP_PROXY",
            "no_proxy",
            "NO_PROXY",
            "all_proxy",
        ] {
            // Never inherited: removed or, on Windows where it is the same
            // variable as the kind's, the kind's own value.
            match sees(&command, var) {
                Seen::Removed => {}
                Seen::Set(value) => {
                    assert!(var.eq_ignore_ascii_case("HTTPS_PROXY"), "{var} = {value}");
                    assert_eq!(value, proxy);
                }
                Seen::Inherited => panic!("{var} is inherited"),
            }
        }
        assert_eq!(sees(&command, "OPENTIDE_REPO_ROOT"), Seen::Removed);
        let lowercase = if cfg!(windows) {
            Seen::Set(proxy.to_string())
        } else {
            Seen::Removed
        };
        assert_eq!(sees(&command, "https_proxy"), lowercase);
        // Without a proxy of its own a kind keeps the inherited ones.
        let plain = oracle_command(Path::new("opentide"), &BTreeMap::new());
        assert_eq!(sees(&plain, "https_proxy"), Seen::Inherited);
        assert!(super::same_variable("PATH", "PATH"));
        assert_eq!(super::same_variable("Path", "PATH"), cfg!(windows));
    }

    #[test]
    fn the_oracles_python_is_the_venvs() {
        let dir = std::env::temp_dir().join(format!("xtask-oracle-python-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("opentide");
        std::fs::write(&bin, "#!/opt/elsewhere/python3\n").unwrap();
        // The shebang, when no interpreter sits beside the script.
        assert_eq!(
            super::oracle_python(&bin).unwrap(),
            PathBuf::from("/opt/elsewhere/python3")
        );
        // The venv's own interpreter, beside the script, wins (Windows has
        // no shebang to read).
        std::fs::write(dir.join("python.exe"), "").unwrap();
        assert_eq!(super::oracle_python(&bin).unwrap(), dir.join("python.exe"));
        std::fs::write(&bin, "no interpreter line").unwrap();
        assert_eq!(super::oracle_python(&bin).unwrap(), dir.join("python.exe"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn scratch_is_removed_unless_kept() {
        let base = std::env::temp_dir().join(format!("xtask-scratch-test-{}", std::process::id()));
        for keep in [false, true] {
            std::fs::create_dir_all(base.join("_base")).unwrap();
            drop(Scratch {
                path: base.clone(),
                keep,
            });
            assert_eq!(base.exists(), keep);
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_run_that_checked_nothing_is_no_pass() {
        let validate = |objects: u64, failure: serde_json::Value| serde_json::json!({"summary": {"objects": objects, "files": 0}, "failure": failure});
        let ok = serde_json::Value::Null;
        assert!(require_checked(&validate(10, ok.clone()), Some(10), "x").is_ok());
        assert!(require_checked(&validate(0, ok.clone()), None, "x").is_err());
        assert!(require_checked(&validate(9, ok.clone()), Some(10), "x").is_err());
        let failed = serde_json::json!({"code": "config_parse"});
        assert!(require_checked(&validate(10, failed.clone()), Some(10), "x").is_err());
        let lint = serde_json::json!({"summary": {"files": 0}, "failure": null});
        assert!(require_checked(&lint, None, "lint").is_err());
        let cve = vec![
            "validate".to_string(),
            "--check".to_string(),
            "cve".to_string(),
        ];
        assert!(require_run(&validate(0, ok.clone()), &cve, 10, "x").is_ok());
        assert!(require_run(&validate(0, failed), &cve, 10, "x").is_err());
        assert!(require_run(&validate(0, ok), &["validate".to_string()], 10, "x").is_err());
    }

    #[test]
    fn the_manifest_sits_beside_the_workspace() {
        assert_eq!(
            manifest_path(Path::new("/tmp/x/faults/")).unwrap(),
            Path::new("/tmp/x/faults.faults.json")
        );
        assert_eq!(
            manifest_path(Path::new("ws")).unwrap(),
            Path::new("ws.faults.json")
        );
        assert!(manifest_path(Path::new("/")).is_err());
    }
}
