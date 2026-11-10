//! `cargo xtask payloads`: the deploy compile's request bodies against the
//! oracle (UC-3.1, #823).
//!
//! `diff --against python` materialises each corpus (the fixtures of
//! `tests/golden/cases.toml`), has the oracle compile every rule's Sentinel
//! and Elastic block (`probe.py`: the dry run's body, each configured
//! tenant's, and the dry run's payload entry), compiles the same with
//! `opentide-compile`, and compares them byte for byte. A difference fails,
//! unless `tests/golden/payloads/APPROVED.toml` approves it.

pub mod git;
pub mod plan;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail, ensure};
use opentide_compile::json::Json;
use opentide_compile::preview::{self, Preview};
use opentide_compile::{CompileError, Owned, Rule, elastic, sentinel};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{Options, OsFs, RootOptions, Workspace};
use serde::Deserialize;

/// The probe the oracle runs.
const PROBE: &str = include_str!("probe.py");

/// The approved differences, relative to the repository.
pub const APPROVED: &str = "tests/golden/payloads/APPROVED.toml";

/// Every corpus of `cases.toml` with rules in it.
pub const CORPORA: [&str; 5] = [
    "tide-corpus",
    "vscode",
    "tide-corpus-typo",
    "heavy-small",
    "fault",
];

/// The usage.
pub const USAGE: &str = "\
usage: cargo xtask payloads <command> [options]

commands:
  diff --against python [--corpus NAME|all ...] [--python PATH]
                 compile every Sentinel and Elastic block of every rule of each
                 corpus (the fixtures of tests/golden/cases.toml) with the oracle
                 and with opentide-compile: the dry run's body, each configured
                 tenant's body, and the dry run's payload entry; any difference
                 not in tests/golden/payloads/APPROVED.toml fails
  git --against python [--python PATH]
                 the changed rule files of a scripted git history (first commit,
                 edits, a non-ASCII name, a nested rule, a rename, a delete, a
                 detached HEAD, a merge, a shallow clone, no commit, no checkout),
                 read by the oracle and by opentide-compile's gix baseline
  plan [--filter PREFIX]
                 make deploy --dry-run's plan with opentide-compile for every
                 dry-run case recorded in tests/golden/cases/deploy/json and
                 compare it with the oracle's document
  help           print this message

exit status: 0 passed, 1 a body differs, 2 usage error or the check could not run
";

/// Runs `cargo xtask payloads ARGS`.
pub fn main(args: &[String]) -> ExitCode {
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "diff" => parse(rest).and_then(|options| run(&options)),
        "git" => {
            parse(rest).and_then(|options| git::run(&oracle_python(options.python.as_deref())?))
        }
        "plan" => match rest {
            [] => plan::run(None),
            [flag, filter] if flag == "--filter" => plan::run(Some(filter)),
            _ => Err(anyhow::anyhow!(
                "usage: cargo xtask payloads plan [--filter PREFIX]"
            )),
        },
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        other => {
            eprint!("xtask payloads: unknown command `{other}`\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// The options of `payloads diff`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DiffOptions {
    /// The oracle's Python; installed from `tests/golden/ORACLE` when `None`.
    pub python: Option<PathBuf>,
    /// The corpora; [`CORPORA`] when empty.
    pub corpora: Vec<String>,
}

/// Reads the options.
pub fn parse(args: &[String]) -> Result<DiffOptions> {
    let mut options = DiffOptions::default();
    let mut against = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .cloned()
                .with_context(|| format!("{name} takes a value"))
        };
        match arg.as_str() {
            "--against" => against = Some(value("--against")?),
            "--corpus" => {
                let corpus = value("--corpus")?;
                if corpus == "all" {
                    options
                        .corpora
                        .extend(CORPORA.iter().map(|c| (*c).to_owned()));
                } else {
                    options.corpora.push(corpus);
                }
            }
            "--python" => options.python = Some(PathBuf::from(value("--python")?)),
            other => bail!("unknown option `{other}`"),
        }
    }
    ensure!(
        against.as_deref() == Some("python"),
        "pass --against python: the oracle is the only reference"
    );
    options.corpora.dedup();
    Ok(options)
}

/// One approved difference.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approved {
    /// The corpus.
    pub corpus: String,
    /// The rule's UUID.
    pub uuid: String,
    /// The platform.
    pub platform: String,
    /// What differs: `compile`, `preview` or `tenant:<name>`.
    pub what: String,
    /// The oracle's output, as the report prints it.
    pub oracle: String,
    /// The candidate's output, as the report prints it.
    pub candidate: String,
    /// Why the candidate's is right.
    pub reason: String,
    /// The issue that decided it.
    pub issue: String,
    /// The bold lead of the CHANGELOG.md entry that announces it.
    pub changelog: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedFile {
    #[serde(default)]
    diff: Vec<Approved>,
    #[serde(default, rename = "plan")]
    _plan: Vec<toml::Value>,
}

/// Reads the approved differences, checking each is complete and announced.
pub fn read_approved(text: &str, changelog: &str) -> Result<Vec<Approved>> {
    let file: ApprovedFile = toml::from_str(text).context("parse the approved differences")?;
    for entry in &file.diff {
        ensure!(
            !entry.reason.is_empty() && entry.issue.starts_with("https://github.com/opentidehq/"),
            "{APPROVED}: {} {} needs a reason and an opentidehq issue",
            entry.uuid,
            entry.what
        );
        ensure!(
            changelog.contains(&entry.changelog),
            "{APPROVED}: CHANGELOG.md has no entry `{}`",
            entry.changelog
        );
    }
    Ok(file.diff)
}

/// The oracle's outcome of one compile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Outcome {
    /// The body, compact JSON in the oracle's key order.
    #[serde(default)]
    pub body: Option<String>,
    /// Or the error a dry run reports.
    #[serde(default)]
    pub error: Option<ErrorOutcome>,
}

/// A compile error as a dry run reports it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ErrorOutcome {
    /// `code`.
    pub code: String,
    /// `message`.
    pub message: String,
    /// `help`.
    pub help: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TenantOutcome {
    tenant: String,
    #[serde(flatten)]
    outcome: Outcome,
}

#[derive(Debug, Deserialize)]
struct ProbeRule {
    uuid: String,
    platform: String,
    compile: Outcome,
    preview: String,
    tenants: Vec<TenantOutcome>,
}

#[derive(Debug, Deserialize)]
struct Unloadable {
    uuid: String,
    error: String,
}

#[derive(Debug, Deserialize)]
struct ProbeResult {
    rules: Vec<ProbeRule>,
    unloadable: Vec<Unloadable>,
}

/// An outcome as both sides print it.
fn describe(outcome: &Outcome) -> String {
    match (&outcome.body, &outcome.error) {
        (Some(body), _) => body.clone(),
        (None, Some(error)) => format!(
            "error[{}] {}{}",
            error.code,
            error.message,
            error
                .help
                .as_deref()
                .map(|help| format!(" (help: {help})"))
                .unwrap_or_default()
        ),
        (None, None) => "nothing".to_owned(),
    }
}

/// The candidate's outcome.
fn candidate(result: Result<Json, CompileError>) -> Outcome {
    match result {
        Ok(body) => Outcome {
            body: Some(body.to_compact()),
            error: None,
        },
        Err(error) => Outcome {
            body: None,
            error: Some(ErrorOutcome {
                code: error.code.to_owned(),
                message: error.reason,
                help: error.hint,
            }),
        },
    }
}

/// One comparison that differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// The corpus.
    pub corpus: String,
    /// The rule's UUID.
    pub uuid: String,
    /// The platform.
    pub platform: String,
    /// `compile`, `preview` or `tenant:<name>`.
    pub what: String,
    /// The oracle's output.
    pub oracle: String,
    /// The candidate's output.
    pub candidate: String,
}

/// What one corpus gave.
#[derive(Debug, Default)]
pub struct Tally {
    /// Comparisons made.
    pub compared: usize,
    /// Comparisons not made, by reason.
    pub skipped: Vec<(String, String)>,
    /// Comparisons that differ.
    pub differences: Vec<Difference>,
}

/// The workspace at `ws`, as the CLI opens it there.
pub fn open(ws: &Path) -> Result<Workspace> {
    Workspace::open(
        Arc::new(OsFs),
        Options {
            roots: RootOptions {
                repo: Some(ws.to_path_buf()),
                cwd: ws.to_path_buf(),
                ..RootOptions::default()
            },
        },
    )
    .map_err(|error| anyhow::anyhow!("open {}: {error}", ws.display()))
}

/// The rules the probe reads: each rule of the index with its file.
pub fn request(ws: &Path, workspace: &Workspace) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = workspace
        .index()
        .rules()
        .map(|rule| serde_json::json!({"uuid": rule.uuid, "path": rule.path}))
        .collect();
    serde_json::json!({"repo": ws, "rules": rules})
}

/// Compares the oracle's result on a corpus with opentide-compile's.
pub fn compare(corpus: &str, workspace: &Workspace, text: &str) -> Result<Tally> {
    let result: ProbeResult = serde_json::from_str(text).context("read the probe's result")?;
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let tenants = |platform: &str| -> Vec<Json> {
        let tree = Json::from_node(&workspace.configuration().resolved.tree);
        match tree
            .get("platforms")
            .and_then(|platforms| platforms.get(platform))
            .and_then(|platform| platform.get("tenants"))
        {
            Some(Json::Array(items)) => items.clone(),
            _ => Vec::new(),
        }
    };
    let elastic_tenants = tenants("elastic");
    let mut tally = Tally::default();
    for refused in &result.unloadable {
        tally.skipped.push((
            refused.uuid.clone(),
            format!(
                "the oracle's data model refuses the rule: {}",
                first_line(&refused.error)
            ),
        ));
    }
    for probe in &result.rules {
        let Some(object) = index.get("rule", &probe.uuid) else {
            tally.skipped.push((
                probe.uuid.clone(),
                "the Rust index has no rule with this UUID".to_owned(),
            ));
            continue;
        };
        let Some(root) = object.root() else {
            continue;
        };
        let rule = Rule::new(root, Some(object.path.to_string_lossy().into_owned()));
        let mut check = |what: String, oracle: String, candidate: String| {
            tally.compared += 1;
            if oracle != candidate {
                tally.differences.push(Difference {
                    corpus: corpus.to_owned(),
                    uuid: probe.uuid.clone(),
                    platform: probe.platform.clone(),
                    what,
                    oracle,
                    candidate,
                });
            }
        };
        let Some(compiled) = preview::compile_offline(&cx, &probe.platform, &rule) else {
            continue;
        };
        check(
            "compile".to_owned(),
            describe(&probe.compile),
            describe(&candidate(compiled)),
        );
        for tenant in &probe.tenants {
            let candidate_outcome = match probe.platform.as_str() {
                "sentinel" => candidate(sentinel::compile(&cx, &rule, &tenant.tenant)),
                _ => {
                    let setup = elastic_tenants
                        .iter()
                        .find(|known| {
                            known.get("name").and_then(Json::as_str) == Some(&tenant.tenant)
                        })
                        .map(elastic::Setup::from_tenant)
                        .unwrap_or_else(elastic::Setup::none);
                    candidate(elastic::compile(&cx, &rule, &setup))
                }
            };
            check(
                format!("tenant:{}", tenant.tenant),
                describe(&tenant.outcome),
                describe(&candidate_outcome),
            );
        }
        match preview::preview(&cx, &probe.platform, &rule) {
            Preview::Entry(entry) => {
                // The oracle's entry names the file it read; the Rust side
                // reads the same file from the same materialised corpus.
                check(
                    "preview".to_owned(),
                    probe.preview.clone(),
                    entry.to_compact(),
                );
            }
            Preview::ConfigDump => tally.skipped.push((
                probe.uuid.clone(),
                format!(
                    "{} preview is the block's model dump, which needs the platform models \
                     (UC-1.4, #810)",
                    probe.platform
                ),
            )),
        }
    }
    Ok(tally)
}

/// The first line of a message.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

/// The oracle's Python: `python` when given, else the one
/// `tests/golden/ORACLE` installs.
pub fn oracle_python(python: Option<&Path>) -> Result<PathBuf> {
    if let Some(python) = python {
        return Ok(python.to_path_buf());
    }
    let (repo, target) = crate::vocab::diff::workspace()?;
    let golden = repo.join("tests/golden");
    let oracle = crate::golden::oracle::Oracle::parse(&fs::read_to_string(golden.join("ORACLE"))?)?;
    let engine = oracle.provision(&golden, &crate::golden::oracle::cache_dir(&target))?;
    Ok(engine.install_dir.join("bin").join("python"))
}

/// Runs the comparison. Whether it passed.
pub fn run(options: &DiffOptions) -> Result<bool> {
    let (repo, _target) = crate::vocab::diff::workspace()?;
    let golden = repo.join("tests/golden");
    let python = oracle_python(options.python.as_deref())?;
    let spec = crate::golden::case::Spec::parse(&fs::read_to_string(golden.join("cases.toml"))?)?;
    let changelog = fs::read_to_string(repo.join("CHANGELOG.md"))?;
    let approved = match fs::read_to_string(repo.join(APPROVED)) {
        Ok(text) => read_approved(&text, &changelog)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error).context(APPROVED),
    };
    let corpora: Vec<String> = if options.corpora.is_empty() {
        CORPORA.iter().map(|c| (*c).to_owned()).collect()
    } else {
        options.corpora.clone()
    };
    let scratch = tempfile::tempdir()?;
    fs::write(scratch.path().join("probe.py"), PROBE)?;
    let mut passed = true;
    let mut used = vec![false; approved.len()];
    for corpus in &corpora {
        let fixture = spec
            .fixtures
            .get(corpus)
            .with_context(|| format!("cases.toml has no fixture `{corpus}`"))?;
        let root = scratch.path().join(corpus);
        let ws = root.join("ws");
        fs::create_dir_all(&ws)?;
        fixture
            .materialise(&repo, &ws)
            .with_context(|| format!("materialise {corpus}"))?;
        let ws = ws.canonicalize()?;
        let workspace = open(&ws)?;
        let request = root.join("request.json");
        let response = root.join("result.json");
        fs::write(
            &request,
            serde_json::to_string(&self::request(&ws, &workspace))?,
        )?;
        let home = root.join("home");
        fs::create_dir_all(&home)?;
        let status = Command::new(&python)
            .arg("-I")
            .arg(scratch.path().join("probe.py"))
            .arg(&request)
            .arg(&response)
            .env_clear()
            .env(
                "PATH",
                python.parent().map(Path::as_os_str).unwrap_or_default(),
            )
            .env("HOME", &home)
            .env("NO_COLOR", "1")
            .env("OPENTIDE_NO_UPDATE_CHECK", "1")
            .status()
            .with_context(|| format!("run {}", python.display()))?;
        ensure!(
            status.success(),
            "the oracle's probe failed on {corpus} ({status})"
        );
        let text = fs::read_to_string(&response)
            .with_context(|| format!("the probe wrote no result for {corpus}"))?;
        let tally = compare(corpus, &workspace, &text)?;
        let mut report = format!(
            "{corpus}: {} bodies compared, {} differ, {} not compared\n",
            tally.compared,
            tally.differences.len(),
            tally.skipped.len()
        );
        for (uuid, why) in &tally.skipped {
            let _ = writeln!(report, "  not compared: {uuid}: {why}");
        }
        for difference in &tally.differences {
            let approval = approved.iter().position(|entry| {
                entry.corpus == difference.corpus
                    && entry.uuid == difference.uuid
                    && entry.platform == difference.platform
                    && entry.what == difference.what
                    && entry.oracle == difference.oracle
                    && entry.candidate == difference.candidate
            });
            if let Some(position) = approval {
                used[position] = true;
                let _ = writeln!(
                    report,
                    "  approved: {} {} {}",
                    difference.uuid, difference.platform, difference.what
                );
                continue;
            }
            passed = false;
            let _ = writeln!(
                report,
                "  DIFFERS: {} {} {}\n    oracle:    {}\n    candidate: {}",
                difference.uuid,
                difference.platform,
                difference.what,
                difference.oracle,
                difference.candidate
            );
        }
        print!("{report}");
    }
    for (entry, used) in approved.iter().zip(&used) {
        if !used && corpora.contains(&entry.corpus) {
            passed = false;
            eprintln!(
                "error: {APPROVED}: the approval of {} {} {} matches nothing (stale)",
                entry.uuid, entry.platform, entry.what
            );
        }
    }
    Ok(passed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn options_parse() {
        let options = parse(&args("--against python --corpus all")).unwrap();
        assert_eq!(options.corpora.len(), CORPORA.len());
        let options = parse(&args("--against python --corpus vscode --python /p")).unwrap();
        assert_eq!(options.corpora, ["vscode"]);
        assert_eq!(options.python.as_deref(), Some(Path::new("/p")));
        assert!(parse(&args("--against rust")).is_err());
        assert!(parse(&args("--against python --nope")).is_err());
    }

    #[test]
    fn approvals_need_a_reason_an_issue_and_a_changelog_entry() {
        let entry = "[[diff]]\ncorpus = \"c\"\nuuid = \"u\"\nplatform = \"elastic\"\nwhat = \
                     \"compile\"\noracle = \"a\"\ncandidate = \"b\"\nreason = \"r\"\nissue = \
                     \"https://github.com/opentidehq/opentide/issues/823\"\nchangelog = \"**Lead**\"\n";
        assert!(read_approved(entry, "- **Lead** text").is_ok());
        assert!(read_approved(entry, "nothing").is_err());
        assert!(
            read_approved(
                &entry.replace("https://github.com/opentidehq/", "x"),
                "**Lead**"
            )
            .is_err()
        );
    }

    #[test]
    fn outcomes_are_described_alike() {
        let outcome = Outcome {
            body: None,
            error: Some(ErrorOutcome {
                code: "compile_missing_field".into(),
                message: "m".into(),
                help: Some("h".into()),
            }),
        };
        assert_eq!(
            describe(&outcome),
            "error[compile_missing_field] m (help: h)"
        );
        assert_eq!(
            describe(&candidate(Err(CompileError::new(
                "compile_missing_field",
                "m",
                Some("h")
            )))),
            describe(&outcome)
        );
    }
}
