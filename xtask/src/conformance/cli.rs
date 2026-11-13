//! `cargo xtask conformance`: lays the manifest's corpora out, runs each
//! runner on them, and compares the documents they write ([`super`]).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};

use super::{
    Known, Manifest, Mismatch, RUNNERS, TENANT_CALLS, documents, explained, first_difference,
    parse_known, passed,
};
use crate::corpus::cli::{corpora_dir, load_catalogue, materialise, repo_root, write_workspace};
use crate::corpus::{configuration, faults, generate};
use crate::golden::fixture::copy_tree;

const USAGE: &str = "\
usage: cargo xtask conformance [--runners rust,python,node] [--corpus NAME,...]
                               [--out DIR] [--diverge RUNNER] [--keep]

Lays out the corpora of tests/conformance/manifest.json under DIR (default
<target>/conformance), runs every operation on each through every runner (the
Rust SDK's `cargo test -p opentide --features cli,connectors --test
conformance`, the Python SDK's pytest under `uv run`, the Node SDK's
`node --test`), and requires
their documents byte-identical; a difference is reported by its JSON pointer.
The first runner is the reference. The stand-in tenants of the manifest
(tests/cassettes/<name>/tenant.py, run with $PYTHON, else python3) start once,
on loopback, and every runner talks to them; each is reset before each runner.

  --runners   the runners, at least two (default rust,python,node). The Python
              runner needs `uv sync`; the Node runner the addon `npm run build`
              writes in bindings/node
  --corpus    only these corpora of the manifest
  --diverge   the suite's own test: RUNNER (not the first) diverges on purpose
              (OPENTIDE_CONFORMANCE_DIVERGE), and the run passes only when the
              comparator catches it, in that runner alone
  --keep      keep the corpora and documents of a run that passed (a failed
              run keeps them)

exit status: 0 identical (or, with --diverge, caught), 1 a difference (or a
divergence missed, or a runner failed), 2 a usage error";

/// The variables no runner sees: the CI providers', the coding agents', and
/// opentide's own, which change what a command writes. The runners run as a
/// person's shell would, and all three in the same environment.
const CLEARED: [&str; 8] = [
    "CI",
    "GITHUB_ACTIONS",
    "GITHUB_STEP_SUMMARY",
    "GITHUB_EVENT_NAME",
    "GITLAB_CI",
    "TF_BUILD",
    "CI_PIPELINE_SOURCE",
    "BUILD_REASON",
];

/// The marker of a folder this command made, which it may remove.
const MARKER: &str = ".xtask-conformance";

#[derive(Debug)]
struct Args {
    runners: Vec<String>,
    corpora: Option<Vec<String>>,
    out: Option<PathBuf>,
    diverge: Option<String>,
    keep: bool,
}

fn parse(args: &[String]) -> Result<Args> {
    let mut parsed = Args {
        runners: RUNNERS.iter().map(|r| (*r).to_owned()).collect(),
        corpora: None,
        out: None,
        diverge: None,
        keep: false,
    };
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--runners" => {
                parsed.runners = value()?.split(',').map(str::to_owned).collect();
            }
            "--corpus" => {
                parsed.corpora = Some(value()?.split(',').map(str::to_owned).collect());
            }
            "--out" => parsed.out = Some(PathBuf::from(value()?)),
            "--diverge" => parsed.diverge = Some(value()?),
            "--keep" => parsed.keep = true,
            "-h" | "--help" | "help" => bail!("{USAGE}"),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    let mut seen = BTreeSet::new();
    for runner in &parsed.runners {
        if !RUNNERS.contains(&runner.as_str()) {
            bail!("--runners: unknown runner `{runner}` (rust, python, node)");
        }
        if !seen.insert(runner) {
            bail!("--runners: `{runner}` is named twice");
        }
    }
    if parsed.runners.len() < 2 {
        bail!("--runners: name at least two runners to compare");
    }
    if let Some(runner) = &parsed.diverge {
        if !parsed.runners.contains(runner) {
            bail!("--diverge: `{runner}` is not one of --runners");
        }
        if parsed.runners[0] == *runner {
            bail!("--diverge: `{runner}` is the reference; diverge another runner");
        }
    }
    Ok(parsed)
}

/// Runs the command; the exit status.
///
/// # Errors
///
/// A usage error, or a corpus or runner that could not be set up (status 2).
pub fn run(args: &[String]) -> Result<u8> {
    let args = match parse(args) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("xtask conformance: {error:#}");
            return Ok(2);
        }
    };
    let repo = repo_root();
    let manifest_path = repo.join("tests/conformance/manifest.json");
    let manifest = Manifest::parse(
        &std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("cannot read {}", manifest_path.display()))?,
    )
    .with_context(|| format!("in {}", manifest_path.display()))?;
    if let Some(only) = &args.corpora {
        for name in only {
            if !manifest.corpora.iter().any(|c| &c.name == name) {
                eprintln!("xtask conformance: --corpus: the manifest has no corpus `{name}`");
                return Ok(2);
            }
        }
    }

    let known_path = repo.join("tests/conformance/known_differences.json");
    let known = parse_known(
        &std::fs::read_to_string(&known_path)
            .with_context(|| format!("cannot read {}", known_path.display()))?,
    )
    .with_context(|| format!("in {}", known_path.display()))?;

    let out = match &args.out {
        Some(out) => std::path::absolute(out)?,
        None => target_dir(&repo).join("conformance"),
    };
    fresh(&out)?;
    let started = Instant::now();

    let corpora_root = out.join("corpora");
    let mut laid_out = Vec::new();
    for corpus in &manifest.corpora {
        if args
            .corpora
            .as_ref()
            .is_some_and(|only| !only.contains(&corpus.name))
        {
            continue;
        }
        laid_out.extend(lay_out(&repo, corpus, &corpora_root)?);
    }
    eprintln!(
        "xtask conformance: {} workspaces laid out under {} in {} ms",
        laid_out.len(),
        corpora_root.display(),
        started.elapsed().as_millis()
    );

    // The stand-in tenants, started once: every runner talks to the same ones.
    let families: BTreeSet<&str> = laid_out
        .iter()
        .filter_map(|(name, _)| name.split('/').next())
        .collect();
    let on_tenants = manifest.operations.iter().any(|operation| {
        TENANT_CALLS.contains(&operation.call.as_str())
            && operation
                .corpora
                .as_ref()
                .is_none_or(|only| only.iter().any(|c| families.contains(c.as_str())))
    });
    let stand_ins = if on_tenants {
        start_stand_ins(&repo, &manifest)?
    } else {
        Vec::new()
    };
    let urls: serde_json::Map<String, serde_json::Value> = stand_ins
        .iter()
        .map(|running| (running.name.clone(), running.url.clone().into()))
        .collect();

    let raw: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    let plan = serde_json::json!({
        "corpora": laid_out
            .iter()
            .map(|(name, root)| serde_json::json!({"name": name, "root": root.to_string_lossy()}))
            .collect::<Vec<_>>(),
        "operations": raw["operations"],
        "tenants": raw.get("tenants").cloned().unwrap_or_else(|| serde_json::json!([])),
        "urls": urls,
    });
    let plan_path = out.join("plan.json");
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan)?)?;

    for runner in &args.runners {
        for running in &stand_ins {
            reset(&running.url).with_context(|| {
                format!(
                    "cannot reset the {} stand-in before the {runner} runner",
                    running.name
                )
            })?;
        }
        let documents = out.join("documents").join(runner);
        std::fs::create_dir_all(&documents)?;
        let diverge = args.diverge.as_deref() == Some(runner.as_str());
        let begun = Instant::now();
        let mut command = runner_command(&repo, runner, &out)?;
        command.current_dir(&repo);
        for name in CLEARED {
            command.env_remove(name);
        }
        for name in opentide_cli::mode::AGENT_VARIABLES {
            command.env_remove(name);
        }
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("OPENTIDE_") {
                command.env_remove(&name);
            }
        }
        command
            .env("OPENTIDE_CONFORMANCE_PLAN", &plan_path)
            .env("OPENTIDE_CONFORMANCE_OUT", &documents);
        if diverge {
            command.env("OPENTIDE_CONFORMANCE_DIVERGE", "1");
        }
        eprintln!("xtask conformance: runner {runner}: {command:?}");
        let status = command
            .status()
            .with_context(|| format!("cannot start the {runner} runner"))?;
        if !status.success() {
            eprintln!(
                "xtask conformance: the {runner} runner failed ({status}); {}",
                hint(runner)
            );
            return Ok(1);
        }
        eprintln!(
            "xtask conformance: runner {runner} wrote its documents in {} ms",
            begun.elapsed().as_millis()
        );
    }

    let names: Vec<String> = laid_out.iter().map(|(name, _)| name.clone()).collect();
    let expected = documents(&manifest.operations, &names);
    let reference = &args.runners[0];
    let mut mismatches = Vec::new();
    let mut approved: Vec<(String, String)> = Vec::new();
    let mut used = BTreeSet::new();
    for document in &expected {
        let read =
            |runner: &str| std::fs::read(out.join("documents").join(runner).join(document)).ok();
        let Some(base) = read(reference) else {
            eprintln!("xtask conformance: the reference runner {reference} wrote no {document}");
            return Ok(1);
        };
        for runner in &args.runners[1..] {
            let difference = match read(runner) {
                Some(bytes) => first_difference(&base, &bytes),
                None => {
                    mismatches.push(Mismatch {
                        document: document.clone(),
                        runner: runner.clone(),
                        difference: None,
                    });
                    continue;
                }
            };
            if let Some(difference) = difference {
                let bytes = read(runner).unwrap_or_default();
                if let Some(entries) = explained(&base, &bytes, document, runner, &known) {
                    used.extend(entries);
                    approved.push((document.clone(), runner.clone()));
                    continue;
                }
                mismatches.push(Mismatch {
                    document: document.clone(),
                    runner: runner.clone(),
                    difference: Some(difference),
                });
            }
        }
    }

    // An entry this run could have needed and did not: the difference is gone.
    let stale: Vec<&Known> = known
        .iter()
        .enumerate()
        .filter(|(index, k)| {
            !used.contains(index)
                && expected.contains(&k.document)
                && args.runners[1..].contains(&k.runner)
        })
        .map(|(_, k)| k)
        .collect();
    let ok = passed(&mismatches, args.diverge.as_deref()) && stale.is_empty();
    print_report(
        &args,
        &laid_out,
        &manifest,
        &expected,
        &mismatches,
        &approved,
        started,
    );
    print_known(&known, &approved, &stale);
    write_report(&out.join("report.json"), &args, &expected, &mismatches, ok)?;
    drop(stand_ins);
    if ok && !args.keep {
        remove(&out.join("corpora"))?;
        remove(&out.join("documents"))?;
        remove(&out.join("pytest"))?;
    }
    Ok(u8::from(!ok))
}

fn hint(runner: &str) -> &'static str {
    match runner {
        "python" => "it runs the SDK `uv sync --group dev` built",
        "node" => {
            "it loads the addon `npm ci && npm run build` (or `node build.mjs --profile develop`) \
             writes in bindings/node, built with OPENTIDE_VERSION set to the workspace's version"
        }
        _ => "its output above says why",
    }
}

/// The command that runs `runner` on the plan.
fn runner_command(repo: &Path, runner: &str, out: &Path) -> Result<Command> {
    Ok(match runner {
        "rust" => {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
            let mut command = Command::new(cargo);
            command.args([
                "test",
                "--locked",
                "--package",
                "opentide",
                "--features",
                "cli,connectors",
                // The profile the Python and Node bindings are built with.
                "--profile",
                "develop",
                "--test",
                "conformance",
                "--",
                "--exact",
                "the_rust_runner_writes_every_document",
            ]);
            command
        }
        "python" => {
            let mut command = Command::new("uv");
            command
                .args([
                    "run",
                    "--no-sync",
                    "python",
                    "-m",
                    "pytest",
                    "tests/conformance/test_python_runner.py::test_the_python_runner_writes_every_document",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    // The suite's options (coverage) and its conftest (which
                    // changes the environment) are not the runner's.
                    "-o",
                    "addopts=",
                    "--confcutdir",
                    "tests/conformance",
                ])
                .arg(format!("--basetemp={}", out.join("pytest").display()));
            command
        }
        "node" => {
            let addon = std::fs::read_dir(repo.join("bindings/node"))
                .context("reading bindings/node")?
                .filter_map(Result::ok)
                .any(|entry| entry.file_name().to_string_lossy().ends_with(".node"));
            if !addon {
                bail!(
                    "bindings/node holds no addon (opentide.<target>.node): {}",
                    hint("node")
                );
            }
            let mut command = Command::new("node");
            command.args([
                "--test",
                "--test-name-pattern=writes every document",
                "bindings/node/test/conformance.test.mjs",
            ]);
            command
        }
        other => bail!("unknown runner `{other}`"),
    })
}

/// A stand-in tenant this run started; killed when dropped.
struct Running {
    name: String,
    url: String,
    child: Child,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// The Python that runs the stand-ins (standard library only): `$PYTHON`,
/// else `python3` (`python` on Windows), as the Python and Node suites run
/// them.
fn python() -> OsString {
    std::env::var_os("PYTHON")
        .unwrap_or_else(|| if cfg!(windows) { "python" } else { "python3" }.into())
}

/// Starts each stand-in of the manifest on loopback; its URL is
/// `http://127.0.0.1:<the port it prints first>`.
fn start_stand_ins(repo: &Path, manifest: &Manifest) -> Result<Vec<Running>> {
    let mut running = Vec::new();
    for stand_in in &manifest.stand_ins {
        let script = repo
            .join("tests/cassettes")
            .join(&stand_in.name)
            .join("tenant.py");
        let mut command = Command::new(python());
        command
            .arg(&script)
            .envs(&stand_in.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = command
            .spawn()
            .with_context(|| format!("cannot start the stand-in {}", script.display()))?;
        let stdout = child.stdout.take().context("the stand-in's stdout")?;
        let mut line = String::new();
        let read = BufReader::new(stdout).read_line(&mut line);
        let mut started = Running {
            name: stand_in.name.clone(),
            url: String::new(),
            child,
        };
        read.with_context(|| format!("reading the {} stand-in's port", stand_in.name))?;
        let port: u16 = line
            .trim()
            .parse()
            .with_context(|| format!("the {} stand-in printed no port", stand_in.name))?;
        eprintln!(
            "xtask conformance: stand-in {} on 127.0.0.1:{port}",
            stand_in.name
        );
        started.url = format!("http://127.0.0.1:{port}");
        running.push(started);
    }
    Ok(running)
}

/// Resets the stand-in at `url` (`POST /__stand-in/reset`): it forgets the rules and
/// queries the last runner left, so that every runner sees the same ids.
fn reset(url: &str) -> Result<()> {
    let address = url
        .strip_prefix("http://")
        .context("a stand-in's URL is http://")?;
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    write!(
        stream,
        "POST /__stand-in/reset HTTP/1.1\r\nHost: {address}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    let status = answer.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        bail!("the stand-in answered `{status}`");
    }
    Ok(())
}

/// The Cargo target directory: `CARGO_TARGET_DIR`, else the repository's
/// `target/`.
fn target_dir(repo: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map_or_else(
            || repo.join("target"),
            |dir| {
                if dir.is_absolute() {
                    dir
                } else {
                    repo.join(dir)
                }
            },
        )
}

/// Makes `out` an empty folder of this command's: a folder it made before is
/// emptied, any other existing folder refused.
fn fresh(out: &Path) -> Result<()> {
    if out.exists() {
        if !out.join(MARKER).is_file() {
            bail!(
                "{} exists and is not a conformance run's folder; name another --out",
                out.display()
            );
        }
        std::fs::remove_dir_all(out).with_context(|| format!("cannot empty {}", out.display()))?;
    }
    std::fs::create_dir_all(out).with_context(|| format!("cannot create {}", out.display()))?;
    std::fs::write(out.join(MARKER), "cargo xtask conformance\n")?;
    Ok(())
}

fn remove(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("cannot remove {}", path.display()))?;
    }
    Ok(())
}

/// Lays `corpus` out under `root`: its workspaces, each by its name.
fn lay_out(repo: &Path, corpus: &super::Corpus, root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let dir = root.join(&corpus.name);
    match corpus.kind.as_str() {
        "tide_corpus" => {
            let source = repo.join("tests/fixtures/tide_corpus/current");
            for (legacy, today) in [
                ("Configurations", ".opentide/configurations"),
                ("Objects/Threat Vectors", "objects/threats"),
                ("Objects/Detection Objectives", "objects/objectives"),
                ("Objects/Detection Rules", "objects/rules"),
            ] {
                copy_tree(&source.join(legacy), &dir.join(today))?;
            }
            Ok(vec![(corpus.name.clone(), dir)])
        }
        "heavy" => {
            let seed = corpus.seed.context("a heavy workspace needs a seed")?;
            let workspace = generate::generate(&generate::Options::new(seed));
            write_workspace(&workspace, &dir)?;
            Ok(vec![(corpus.name.clone(), dir)])
        }
        "faults" => {
            let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
            let code = materialise(&catalogue, &dir)?;
            if code != 0 {
                bail!("the combined fault workspace did not lay out");
            }
            Ok(vec![(corpus.name.clone(), dir)])
        }
        "configuration_faults" => {
            let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
            let base = generate::generate(&catalogue.base.options()?);
            let mut out = Vec::new();
            for (id, _) in configuration::CONFIGURATION {
                let kind = catalogue
                    .kind(id)
                    .with_context(|| format!("no fault kind `{id}` in faults.toml"))?;
                let mut workspace = base.clone();
                let targets = faults::select(&workspace, kind, &BTreeSet::new())?;
                faults::apply(&mut workspace, kind, &targets)?;
                let path = dir.join(id);
                write_workspace(&workspace, &path)?;
                out.push((format!("{}/{id}", corpus.name), path));
            }
            Ok(out)
        }
        "compile_faults" => {
            // The compile check's kinds (UC-2.2, #817): isolated, since the
            // check runs only when the run has no other error (KG-10).
            let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
            let base = generate::generate(&catalogue.base.options()?);
            let mut out = Vec::new();
            for kind in catalogue
                .kinds
                .iter()
                .filter(|kind| kind.id.starts_with("compile-"))
            {
                let mut workspace = base.clone();
                let targets = faults::select(&workspace, kind, &BTreeSet::new())?;
                faults::apply(&mut workspace, kind, &targets)?;
                let path = dir.join(&kind.id);
                write_workspace(&workspace, &path)?;
                out.push((format!("{}/{}", corpus.name, kind.id), path));
            }
            ensure!(!out.is_empty(), "faults.toml has no compile-* kind");
            Ok(out)
        }
        other => bail!("unknown corpus kind `{other}`"),
    }
}

fn print_report(
    args: &Args,
    laid_out: &[(String, PathBuf)],
    manifest: &Manifest,
    expected: &[String],
    mismatches: &[Mismatch],
    approved: &[(String, String)],
    started: Instant,
) {
    let runners = args.runners.join(", ");
    println!("## Cross-SDK conformance ({runners})\n");
    println!(
        "| Corpus | Workspaces | Documents | Identical in every runner | Known difference | Different |\n|---|---:|---:|---:|---:|---:|"
    );
    for corpus in &manifest.corpora {
        let workspaces = laid_out
            .iter()
            .filter(|(name, _)| name.split('/').next() == Some(corpus.name.as_str()))
            .count();
        if workspaces == 0 {
            continue;
        }
        let prefix = format!("{}/", corpus.name);
        let mine: Vec<&String> = expected.iter().filter(|d| d.starts_with(&prefix)).collect();
        let differing: BTreeSet<&str> = mismatches
            .iter()
            .filter(|m| m.document.starts_with(&prefix))
            .map(|m| m.document.as_str())
            .collect();
        let known: BTreeSet<&str> = approved
            .iter()
            .filter(|(d, _)| d.starts_with(&prefix) && !differing.contains(d.as_str()))
            .map(|(d, _)| d.as_str())
            .collect();
        println!(
            "| {} | {workspaces} | {} | {} | {} | {} |",
            corpus.name,
            mine.len(),
            mine.len() - differing.len() - known.len(),
            known.len(),
            differing.len()
        );
    }
    let differing: BTreeSet<&str> = mismatches.iter().map(|m| m.document.as_str()).collect();
    let known: BTreeSet<&str> = approved
        .iter()
        .map(|(d, _)| d.as_str())
        .filter(|d| !differing.contains(d))
        .collect();
    println!(
        "\n{} documents per runner, {} operations: {} identical in every runner, {} with a known \
         difference, {} different; {} s.",
        expected.len(),
        manifest.operations.len(),
        expected.len() - differing.len() - known.len(),
        known.len(),
        differing.len(),
        started.elapsed().as_secs()
    );
    if !mismatches.is_empty() {
        println!();
        for mismatch in mismatches.iter().take(50) {
            match &mismatch.difference {
                Some(difference) => println!(
                    "- `{}`: {} differs from {} at `{}`: {}",
                    mismatch.document,
                    mismatch.runner,
                    args.runners[0],
                    if difference.pointer.is_empty() {
                        "(root)"
                    } else {
                        &difference.pointer
                    },
                    difference.detail
                ),
                None => println!(
                    "- `{}`: {} wrote no such document",
                    mismatch.document, mismatch.runner
                ),
            }
        }
        if mismatches.len() > 50 {
            println!("- ... and {} more (report.json)", mismatches.len() - 50);
        }
    }
    match &args.diverge {
        Some(runner) if passed(mismatches, args.diverge.as_deref()) => println!(
            "\nThe deliberate divergence of the {runner} runner was caught ({} documents).",
            mismatches.len()
        ),
        Some(runner) => println!(
            "\nThe deliberate divergence of the {runner} runner was NOT caught as expected."
        ),
        None => {}
    }
}

fn print_known(known: &[Known], approved: &[(String, String)], stale: &[&Known]) {
    if !approved.is_empty() {
        println!("\nKnown differences (tests/conformance/known_differences.json):");
        for (document, runner) in approved {
            for k in known
                .iter()
                .filter(|k| &k.document == document && &k.runner == runner)
            {
                println!(
                    "- `{document}`: {runner} at `{}`: {} for {}. {} ({})",
                    k.pointer, k.candidate, k.reference, k.reason, k.issue
                );
            }
        }
    }
    for k in stale {
        println!(
            "\nStale known difference: `{}` {} at `{}` no longer differs; remove its entry.",
            k.document, k.runner, k.pointer
        );
    }
}

fn write_report(
    path: &Path,
    args: &Args,
    expected: &[String],
    mismatches: &[Mismatch],
    ok: bool,
) -> Result<()> {
    let report = serde_json::json!({
        "runners": args.runners,
        "reference": args.runners[0],
        "diverge": args.diverge,
        "passed": ok,
        "documents": expected.len(),
        "mismatches": mismatches
            .iter()
            .map(|m| serde_json::json!({
                "document": m.document,
                "runner": m.runner,
                "pointer": m.difference.as_ref().map(|d| d.pointer.clone()),
                "detail": m.difference.as_ref().map_or_else(
                    || "no such document".to_owned(),
                    |d| d.detail.clone(),
                ),
            }))
            .collect::<Vec<_>>(),
    });
    std::fs::write(path, serde_json::to_string_pretty(&report)? + "\n")
        .with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &[&str]) -> Result<Args> {
        parse(&text.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn the_options_parse() {
        let parsed = args(&["--runners", "rust,node", "--diverge", "node", "--keep"]).unwrap();
        assert_eq!(parsed.runners, ["rust", "node"]);
        assert_eq!(parsed.diverge.as_deref(), Some("node"));
        assert!(parsed.keep);
        assert_eq!(args(&[]).unwrap().runners, RUNNERS);
    }

    #[test]
    fn bad_options_are_usage_errors() {
        for (text, message) in [
            (&["--runners", "rust"][..], "at least two"),
            (&["--runners", "rust,ruby"][..], "unknown runner"),
            (&["--runners", "rust,rust"][..], "named twice"),
            (&["--diverge", "rust"][..], "is the reference"),
            (
                &["--runners", "rust,python", "--diverge", "node"][..],
                "not one of",
            ),
            (&["--frobnicate"][..], "unknown option"),
            (&["--out"][..], "needs a value"),
        ] {
            let error = args(text).unwrap_err();
            assert!(
                format!("{error:#}").contains(message),
                "{text:?}: {error:#}"
            );
        }
    }

    #[test]
    fn the_stand_ins_start_on_loopback_and_reset() {
        let repo = repo_root();
        let manifest = Manifest::parse(
            &std::fs::read_to_string(repo.join("tests/conformance/manifest.json")).unwrap(),
        )
        .unwrap();
        let running = start_stand_ins(&repo, &manifest).unwrap();
        assert_eq!(running.len(), manifest.stand_ins.len());
        for stand_in in &running {
            assert!(
                stand_in.url.starts_with("http://127.0.0.1:"),
                "{}",
                stand_in.url
            );
            reset(&stand_in.url).unwrap();
            reset(&stand_in.url).unwrap();
        }
        assert!(reset("http://127.0.0.1:9").is_err());
        assert!(reset("https://127.0.0.1:9").is_err());
    }

    #[test]
    fn a_folder_this_command_did_not_make_is_never_emptied() {
        let dir = tempfile::tempdir().unwrap();
        let theirs = dir.path().join("theirs");
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(theirs.join("keep.txt"), "mine").unwrap();
        assert!(fresh(&theirs).is_err());
        assert!(theirs.join("keep.txt").is_file());

        let ours = dir.path().join("ours");
        fresh(&ours).unwrap();
        std::fs::write(ours.join("old.json"), "{}").unwrap();
        fresh(&ours).unwrap();
        assert!(!ours.join("old.json").exists());
        assert!(ours.join(MARKER).is_file());
    }
}
