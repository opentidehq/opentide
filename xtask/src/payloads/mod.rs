//! `cargo xtask payloads`: the deploy compile's request bodies against the
//! oracle (UC-3.1, #823).
//!
//! `diff --against python` materialises each corpus (the fixtures of
//! `tests/golden/cases.toml`), has the oracle compile every platform block of
//! every rule (`probe.py`: the dry run's body of Sentinel, Elastic and
//! Sysdig, each configured tenant's body, or for the other six platforms the
//! writes their deployer sends to it, and the dry run's payload entry),
//! compiles the same with `opentide-compile`, and compares them byte for
//! byte. A difference fails, unless `tests/golden/payloads/APPROVED.toml`
//! approves it: one difference (`[[diff]]`), or a class of differences of
//! the model-dump previews (`[[dump]]`, [`dump_approval`]).

pub mod git;
pub mod plan;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail, ensure};
use opentide_compile::json::Json;
use opentide_compile::preview::{self, Inputs, PROBE_CLOCK, PROBE_TIMESTAMP};
use opentide_compile::{CompileError, Owned, Rule};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, Options, OsFs, RootOptions, Workspace};
use serde::Deserialize;

/// The probe the oracle runs.
const PROBE: &str = include_str!("probe.py");

/// The approved differences, relative to the repository.
pub const APPROVED: &str = "tests/golden/payloads/APPROVED.toml";

/// The compile corpus: rules for every branch of the compilers.
pub const COMPILE_CORPUS: &str = "tests/golden/payloads/corpus";

/// What the oracle compiles from the compile corpus, paths written `<WS>`.
pub const ORACLE_RECORD: &str = "tests/golden/payloads/oracle.json";

/// Every corpus with rules in it: the compile corpus, then the fixtures of
/// `cases.toml`.
pub const CORPORA: [&str; 6] = [
    "payloads",
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
  diff --against python [--corpus NAME|all ...] [--python PATH] [--record]
                 compile every platform block of every rule of each corpus (the
                 fixtures of tests/golden/cases.toml) with the oracle and with
                 opentide-compile: the dry run's body, each configured tenant's
                 body (the writes the deployer sends, for Defender, Splunk,
                 SentinelOne, CrowdStrike, HarfangLab and Carbon Black), and the
                 dry run's payload entry; any difference not in
                 tests/golden/payloads/APPROVED.toml fails. The corpus
                 `payloads` is tests/golden/payloads/corpus; the oracle's result on it
                 must equal tests/golden/payloads/oracle.json (--record writes it)
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
    /// Write [`ORACLE_RECORD`] instead of checking it.
    pub record: bool,
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
            "--record" => options.record = true,
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

/// A class of differences approved in the model-dump previews (`[[dump]]`):
/// the dry run shows a block it builds no body for as the block's model,
/// which opentide-compile serialises with serde from opentide-schema's
/// models, not with Pydantic's `model_dump`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DumpApproval {
    /// `nulls`: the oracle writes an unset optional field `null`, serde
    /// leaves it out. `order`: as `nulls`, and a mapping's keys are in the
    /// model's order (a `BTreeMap`'s), not the file's.
    pub rule: String,
    /// The platforms it applies to.
    pub platforms: Vec<String>,
    /// Why the candidate's is right.
    pub reason: String,
    /// The issue that decided it.
    pub issue: String,
    /// The bold lead of the CHANGELOG.md entry that announces it.
    pub changelog: String,
}

/// A fault of the oracle the probe works around (`[[fault]]`): the oracle's
/// own client fails before it sends anything, so the probe records the
/// failure, gives the client what it lacked, and compares the bodies the
/// deployer builds. The oracle's deploy fails where opentide-compile's
/// sends the bodies: an intended difference, announced like the others.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultApproval {
    /// The platform whose client fails.
    pub platform: String,
    /// The failure, `Type: message`, as the probe records it.
    pub error: String,
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
    #[serde(default)]
    dump: Vec<DumpApproval>,
    #[serde(default)]
    fault: Vec<FaultApproval>,
    #[serde(default, rename = "plan")]
    _plan: Vec<toml::Value>,
}

/// Reads the approved model-dump classes, checking each is complete and
/// announced.
pub fn read_dump_approvals(text: &str, changelog: &str) -> Result<Vec<DumpApproval>> {
    let file: ApprovedFile = toml::from_str(text).context("parse the approved differences")?;
    for entry in &file.dump {
        ensure!(
            matches!(entry.rule.as_str(), "nulls" | "order"),
            "{APPROVED}: a [[dump]] rule is `nulls` or `order`, not `{}`",
            entry.rule
        );
        ensure!(
            !entry.reason.is_empty() && entry.issue.starts_with("https://github.com/opentidehq/"),
            "{APPROVED}: the [[dump]] {} needs a reason and an opentidehq issue",
            entry.rule
        );
        ensure!(
            changelog.contains(&entry.changelog),
            "{APPROVED}: CHANGELOG.md has no entry `{}`",
            entry.changelog
        );
    }
    Ok(file.dump)
}

/// Reads the approved oracle faults, checking each is complete and announced.
pub fn read_fault_approvals(text: &str, changelog: &str) -> Result<Vec<FaultApproval>> {
    let file: ApprovedFile = toml::from_str(text).context("parse the approved differences")?;
    for entry in &file.fault {
        ensure!(
            !entry.error.is_empty()
                && !entry.reason.is_empty()
                && entry.issue.starts_with("https://github.com/opentidehq/"),
            "{APPROVED}: the [[fault]] of {} needs an error, a reason and an opentidehq issue",
            entry.platform
        );
        ensure!(
            changelog.contains(&entry.changelog),
            "{APPROVED}: CHANGELOG.md has no entry `{}`",
            entry.changelog
        );
    }
    Ok(file.fault)
}

/// The `[[fault]]` approval of `fault`: same platform, same failure.
pub fn fault_approval(approvals: &[FaultApproval], fault: &Fault) -> Option<usize> {
    approvals
        .iter()
        .position(|entry| entry.platform == fault.platform && entry.error == fault.error)
}

/// `value` without its `null` members, at every depth, keys in order.
fn without_null_members(value: Json) -> Json {
    match value {
        Json::Object(object) => Json::Object(
            object
                .into_iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key, without_null_members(value)))
                .collect(),
        ),
        Json::Array(items) => Json::Array(items.into_iter().map(without_null_members).collect()),
        other => other,
    }
}

/// The `[[dump]]` approval that accounts for a preview entry of `platform`
/// that differs: the oracle's entry is a model dump (an `api_request` and no
/// `status`), and with its `null` members left out it equals the
/// candidate's text (`nulls`), or the candidate's value with the keys of
/// some object in another order (`order`). Every value is compared; only
/// what serde does not write, and for `order` the order of keys, is
/// approved.
pub fn dump_approval(
    approvals: &[DumpApproval],
    platform: &str,
    oracle: &str,
    candidate: &str,
) -> Option<usize> {
    let oracle_json: Json = serde_json::from_str(oracle).ok()?;
    if oracle_json.get("status").is_some() || oracle_json.get("api_request").is_none() {
        return None;
    }
    let trimmed = without_null_members(oracle_json).to_compact();
    let rule = if trimmed == candidate {
        "nulls"
    } else {
        let unordered = |text: &str| serde_json::from_str::<serde_json::Value>(text).ok();
        if unordered(&trimmed)? != unordered(candidate)? {
            return None;
        }
        "order"
    };
    approvals.iter().position(|approval| {
        approval.rule == rule && approval.platforms.iter().any(|known| known == platform)
    })
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
    /// The failure of the oracle's own client, which the probe worked
    /// around to record the body (`[[fault]]`).
    #[serde(default)]
    fault: Option<String>,
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

/// A failure of the oracle's own client that the probe worked around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// The rule's UUID.
    pub uuid: String,
    /// The platform.
    pub platform: String,
    /// `tenant:<name>`.
    pub what: String,
    /// The failure, `Type: message`.
    pub error: String,
}

/// What one corpus gave.
#[derive(Debug, Default)]
pub struct Tally {
    /// The oracle faults the probe worked around: each must be approved.
    pub faults: Vec<Fault>,
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

/// `text`, a JSON document or a compact value, with the workspace `ws`
/// written `<WS>`, and the path that follows it written with `/`: a Windows
/// run names its files with `\`, which JSON escapes, and the recorded oracle
/// (recorded on Unix) with `/`. The comparison is of what the files are, in
/// one form on every host.
pub fn placeholder(text: &str, ws: &Path) -> String {
    placeholder_for(text, &ws.to_string_lossy(), cfg!(windows))
}

/// [`placeholder`] for a workspace spelled `ws`, with Windows' separator
/// when `windows`.
fn placeholder_for(text: &str, ws: &str, windows: bool) -> String {
    let quoted = serde_json::to_string(ws).unwrap_or_default();
    let escaped = quoted
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(ws);
    if escaped.is_empty() {
        return text.to_owned();
    }
    if !windows {
        return text.replace(escaped, "<WS>");
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(escaped) {
        out.push_str(&rest[..at]);
        out.push_str("<WS>");
        rest = &rest[at + escaped.len()..];
        // The path runs to the end of its JSON string.
        let end = rest.find('"').unwrap_or(rest.len());
        out.push_str(&rest[..end].replace(r"\\", "/"));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
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
        let root = workspace.root();
        let mut check = |what: String, oracle: String, candidate: String| {
            tally.compared += 1;
            let oracle = placeholder(&oracle, root);
            let candidate = placeholder(&candidate, root);
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
        // The dry run's body, for a platform that builds it from the rule.
        if let Some(compiled) = preview::compile_offline(&cx, &probe.platform, &rule) {
            check(
                "compile".to_owned(),
                describe(&probe.compile),
                describe(&candidate(compiled)),
            );
        }
        for tenant in &probe.tenants {
            if let Some(error) = &tenant.fault {
                tally.faults.push(Fault {
                    uuid: probe.uuid.clone(),
                    platform: probe.platform.clone(),
                    what: format!("tenant:{}", tenant.tenant),
                    error: error.clone(),
                });
            }
            let inputs = Inputs {
                known: opentide_compile::plan::state_id(
                    &OsFs as &dyn FileSystem,
                    root,
                    &probe.uuid,
                    &probe.platform,
                    &tenant.tenant,
                ),
                clock: PROBE_CLOCK,
                timestamp: PROBE_TIMESTAMP,
            };
            let Some(compiled) =
                preview::compile_tenant(&cx, &probe.platform, &rule, &tenant.tenant, &inputs)
            else {
                tally.skipped.push((
                    probe.uuid.clone(),
                    format!(
                        "{} is not a platform opentide-compile knows",
                        probe.platform
                    ),
                ));
                continue;
            };
            check(
                format!("tenant:{}", tenant.tenant),
                describe(&tenant.outcome),
                describe(&candidate(compiled)),
            );
        }
        // The oracle's entry names the file it read; the Rust side reads the
        // same file from the same materialised corpus.
        check(
            "preview".to_owned(),
            probe.preview.clone(),
            preview::preview(&cx, &probe.platform, &rule).to_compact(),
        );
    }
    Ok(tally)
}

/// Lays out `corpus` in `ws`: the compile corpus, or a fixture of `cases.toml`.
fn materialise(
    spec: &crate::golden::case::Spec,
    repo: &Path,
    corpus: &str,
    ws: &Path,
) -> Result<()> {
    if corpus == "payloads" {
        return crate::golden::fixture::copy_tree(&repo.join(COMPILE_CORPUS), ws);
    }
    spec.fixtures
        .get(corpus)
        .with_context(|| format!("cases.toml has no fixture `{corpus}`"))?
        .materialise(repo, ws)
        .with_context(|| format!("materialise {corpus}"))
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
    let (approved, dumps, faults) = match fs::read_to_string(repo.join(APPROVED)) {
        Ok(text) => (
            read_approved(&text, &changelog)?,
            read_dump_approvals(&text, &changelog)?,
            read_fault_approvals(&text, &changelog)?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (Vec::new(), Vec::new(), Vec::new())
        }
        Err(error) => return Err(error).context(APPROVED),
    };
    let mut dumps_used = vec![false; dumps.len()];
    let mut faults_used = vec![false; faults.len()];
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
        let root = scratch.path().join(corpus);
        let ws = root.join("ws");
        fs::create_dir_all(&ws)?;
        materialise(&spec, &repo, corpus, &ws)?;
        let ws = dunce::canonicalize(&ws)?;
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
        if corpus == "payloads" {
            let recorded = text.replace(&ws.to_string_lossy().into_owned(), "<WS>");
            let path = repo.join(ORACLE_RECORD);
            if options.record {
                fs::write(&path, &recorded)?;
                println!("wrote {ORACLE_RECORD}");
            } else if fs::read_to_string(&path).ok().as_deref() != Some(recorded.as_str()) {
                passed = false;
                eprintln!(
                    "error: {ORACLE_RECORD} is not what the oracle compiles from {COMPILE_CORPUS}: \
                     run cargo xtask payloads diff --against python --corpus payloads --record"
                );
            }
        }
        // An approval names the workspace `<WS>`, as `compare` writes it:
        // the corpus is laid out in a new directory on every run.
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
        for fault in &tally.faults {
            if let Some(position) = fault_approval(&faults, fault) {
                faults_used[position] = true;
                let _ = writeln!(
                    report,
                    "  approved (the oracle fails: {}): {} {} {}",
                    fault.error, fault.uuid, fault.platform, fault.what
                );
                continue;
            }
            passed = false;
            let _ = writeln!(
                report,
                "  ORACLE FAILS: {} {} {}: {} (worked around by the probe; approve it as a \
                 [[fault]] or fix the probe)",
                fault.uuid, fault.platform, fault.what, fault.error
            );
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
            if difference.what == "preview"
                && let Some(position) = dump_approval(
                    &dumps,
                    &difference.platform,
                    &difference.oracle,
                    &difference.candidate,
                )
            {
                dumps_used[position] = true;
                let _ = writeln!(
                    report,
                    "  approved ({} of the model dump): {} {} preview",
                    dumps[position].rule, difference.uuid, difference.platform
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
    let every_corpus = CORPORA
        .iter()
        .all(|corpus| corpora.iter().any(|run| run == corpus));
    for (entry, used) in dumps.iter().zip(&dumps_used) {
        if !used && every_corpus {
            passed = false;
            eprintln!(
                "error: {APPROVED}: the [[dump]] {} of {} matches nothing (stale)",
                entry.rule,
                entry.platforms.join(", ")
            );
        }
    }
    for (entry, used) in faults.iter().zip(&faults_used) {
        if !used && every_corpus {
            passed = false;
            eprintln!(
                "error: {APPROVED}: the [[fault]] of {} ({}) matches nothing (stale)",
                entry.platform, entry.error
            );
        }
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

    #[test]
    fn a_workspace_path_is_written_the_same_on_every_host() {
        // Unix: the path, as it is.
        assert_eq!(
            placeholder_for(r#"{"file":"/t/ws/objects/rules/a.yaml"}"#, "/t/ws", false),
            r#"{"file":"<WS>/objects/rules/a.yaml"}"#
        );
        // Windows: the path JSON escapes, its separators up to the end of
        // its string written `/`, and nothing after the string touched.
        assert_eq!(
            placeholder_for(
                r#"{"file":"C:\\t\\ws\\objects\\rules\\a.yaml","x":"a\\b"}"#,
                r"C:\t\ws",
                true
            ),
            r#"{"file":"<WS>/objects/rules/a.yaml","x":"a\\b"}"#
        );
        assert_eq!(
            placeholder_for(r#""from C:\\ws. Run inside it.""#, r"C:\ws", true),
            r#""from <WS>. Run inside it.""#
        );
        assert_eq!(placeholder_for("{}", "", true), "{}");
        let here = std::env::current_dir().unwrap();
        let text = serde_json::to_string(&here.join("objects").join("a.yaml")).unwrap();
        assert_eq!(placeholder(&text, &here), "\"<WS>/objects/a.yaml\"");
    }

    #[test]
    fn the_recorded_oracle_agrees_with_the_compile_corpus() {
        let (repo, _) = crate::vocab::diff::workspace().unwrap();
        let scratch = tempfile::tempdir().unwrap();
        let ws = scratch.path().join("ws");
        crate::golden::fixture::copy_tree(&repo.join(COMPILE_CORPUS), &ws).unwrap();
        let ws = dunce::canonicalize(&ws).unwrap();
        let workspace = open(&ws).unwrap();
        let request = request(&ws, &workspace);
        assert!(request["rules"].as_array().unwrap().len() >= 20);
        // The record names the workspace `<WS>`, as `compare` does: no path is
        // put back into it, so the record reads the same on every host.
        let recorded = fs::read_to_string(repo.join(ORACLE_RECORD)).unwrap();
        let tally = compare("payloads", &workspace, &recorded).unwrap();
        assert!(tally.compared >= 150, "{}", tally.compared);
        assert!(tally.skipped.is_empty(), "{:?}", tally.skipped);
        // Every difference is approved: one by one (the oracle names
        // Sentinel in a Sysdig failure, Defender's `odata_type` rewrite,
        // Splunk's risk JSON, HarfangLab's Sigma quotes), or as a class of
        // the model-dump previews.
        let changelog = fs::read_to_string(repo.join("CHANGELOG.md")).unwrap();
        let text = fs::read_to_string(repo.join(APPROVED)).unwrap();
        let approved = read_approved(&text, &changelog).unwrap();
        let dumps = read_dump_approvals(&text, &changelog).unwrap();
        // The oracle's HarfangLab client fails on every tenant; each failure
        // the probe worked around is approved.
        let faults = read_fault_approvals(&text, &changelog).unwrap();
        assert!(
            tally
                .faults
                .iter()
                .filter(|fault| fault.platform == "harfanglab")
                .count()
                >= 5,
            "{:?}",
            tally.faults
        );
        for fault in &tally.faults {
            assert!(fault_approval(&faults, fault).is_some(), "{fault:?}");
        }
        let mut one_by_one: Vec<(&str, &str)> = Vec::new();
        for difference in &tally.differences {
            if approved.iter().any(|entry| {
                entry.corpus == "payloads"
                    && entry.uuid == difference.uuid
                    && entry.what == difference.what
                    && entry.oracle == difference.oracle
                    && entry.candidate == difference.candidate
            }) {
                one_by_one.push((difference.platform.as_str(), difference.what.as_str()));
                continue;
            }
            assert!(
                difference.what == "preview"
                    && dump_approval(
                        &dumps,
                        &difference.platform,
                        &difference.oracle,
                        &difference.candidate
                    )
                    .is_some(),
                "{difference:?}"
            );
        }
        one_by_one.sort_unstable();
        assert_eq!(
            one_by_one,
            [
                ("defender_for_endpoint", "tenant:contoso"),
                ("defender_for_endpoint", "tenant:fabrikam"),
                ("harfanglab", "tenant:sigma"),
                ("splunk", "tenant:es"),
                ("splunk", "tenant:es"),
                ("sysdig", "preview")
            ]
        );
        // A rule the oracle refused, and one the index does not hold.
        let refused = r#"{"rules":[{"uuid":"00000000-0000-4000-8005-ffffffffffff","file":"",
            "platform":"sysdig","compile":{"body":"{}"},"preview":"{}","tenants":[]}],
            "unloadable":[{"uuid":"u","error":"ValidationError: no\nmore"}]}"#;
        let tally = compare("payloads", &workspace, refused).unwrap();
        assert_eq!(tally.compared, 0);
        assert_eq!(tally.skipped.len(), 2, "{:?}", tally.skipped);
        assert!(
            tally.skipped[0]
                .1
                .ends_with("refuses the rule: ValidationError: no")
        );
        assert!(compare("payloads", &workspace, "not json").is_err());
    }

    #[test]
    fn oracle_faults_need_an_approval_of_the_same_failure() {
        let text = "[[fault]]\nplatform = \"harfanglab\"\nerror = \"AttributeError: X\"\n\
                    reason = \"r\"\nissue = \"https://github.com/opentidehq/opentide/issues/895\"\n\
                    changelog = \"**Lead**\"\n";
        let faults = read_fault_approvals(text, "**Lead**").unwrap();
        assert!(read_fault_approvals(text, "nothing").is_err());
        assert!(read_fault_approvals(&text.replace("AttributeError: X", ""), "**Lead**").is_err());
        let fault = Fault {
            uuid: "u".into(),
            platform: "harfanglab".into(),
            what: "tenant:t".into(),
            error: "AttributeError: X".into(),
        };
        assert_eq!(fault_approval(&faults, &fault), Some(0));
        let other = Fault {
            error: "KeyError: X".into(),
            ..fault.clone()
        };
        assert_eq!(fault_approval(&faults, &other), None);
        let elsewhere = Fault {
            platform: "splunk".into(),
            ..fault
        };
        assert_eq!(fault_approval(&faults, &elsewhere), None);
    }

    #[test]
    fn model_dump_classes_approve_only_nulls_and_key_order() {
        let changelog = "**Lead**";
        let text = "[[dump]]\nrule = \"nulls\"\nplatforms = [\"splunk\"]\nreason = \"r\"\nissue = \
                    \"https://github.com/opentidehq/opentide/issues/895\"\nchangelog = \"**Lead**\"\n";
        let dumps = read_dump_approvals(text, changelog).unwrap();
        assert!(read_dump_approvals(&text.replace("nulls", "loose"), changelog).is_err());
        assert!(read_dump_approvals(text, "nothing").is_err());
        let oracle =
            r#"{"uuid":"u","name":"n","api_request":{"a":1,"b":null,"c":{"d":null,"e":[1]}}}"#;
        let candidate = r#"{"uuid":"u","name":"n","api_request":{"a":1,"c":{"e":[1]}}}"#;
        assert_eq!(dump_approval(&dumps, "splunk", oracle, candidate), Some(0));
        // Another platform, another value, another order, a failure entry.
        assert_eq!(
            dump_approval(&dumps, "crowdstrike", oracle, candidate),
            None
        );
        let other = r#"{"uuid":"u","name":"n","api_request":{"a":2,"c":{"e":[1]}}}"#;
        assert_eq!(dump_approval(&dumps, "splunk", oracle, other), None);
        let reordered = r#"{"uuid":"u","name":"n","api_request":{"c":{"e":[1]},"a":1}}"#;
        assert_eq!(dump_approval(&dumps, "splunk", oracle, reordered), None);
        let order = read_dump_approvals(&text.replace("nulls", "order"), changelog).unwrap();
        assert_eq!(dump_approval(&order, "splunk", oracle, reordered), Some(0));
        assert_eq!(dump_approval(&order, "splunk", oracle, candidate), None);
        let failed = r#"{"uuid":"u","status":"failed","api_request":null}"#;
        assert_eq!(dump_approval(&dumps, "splunk", failed, failed), None);
    }

    #[test]
    fn every_platforms_blocks_are_compared() {
        let scratch = tempfile::tempdir().unwrap();
        let ws = scratch.path().join("ws");
        fs::create_dir_all(ws.join(".opentide/configurations/platforms")).unwrap();
        fs::create_dir_all(ws.join("objects/rules")).unwrap();
        fs::write(
            ws.join("objects/rules/r.yaml"),
            "name: Rule\nmetadata:\n  uuid: 00000000-0000-4000-8005-000000000902\n  \
             schema: rule::1.0\ndescription: d\nconfigurations:\n  splunk:\n    \
             status: STAGING\n    query: index=main\n",
        )
        .unwrap();
        let ws = dunce::canonicalize(&ws).unwrap();
        let workspace = open(&ws).unwrap();
        let probe = r#"{"rules":[{"uuid":"00000000-0000-4000-8005-000000000902","platform":"splunk",
            "compile":{},"preview":"{\"uuid\":\"00000000-0000-4000-8005-000000000902\",\"name\":\"Rule\",\"api_request\":{}}",
            "tenants":[]}],"unloadable":[]}"#;
        let tally = compare("c", &workspace, probe).unwrap();
        // The preview alone: no compile for a deployer's platform, no tenant.
        assert_eq!(tally.compared, 1);
        assert!(tally.skipped.is_empty(), "{:?}", tally.skipped);
        assert_eq!(tally.differences.len(), 1);
        assert!(
            tally.differences[0]
                .candidate
                .contains(r#""query":"index=main""#),
            "{:?}",
            tally.differences
        );
    }

    #[test]
    fn the_command_line_answers_usage_and_unknown_commands() {
        assert_eq!(main(&[]), ExitCode::from(2));
        assert_eq!(main(&args("help")), ExitCode::SUCCESS);
        assert_eq!(main(&args("nope")), ExitCode::from(2));
        assert_eq!(main(&args("plan --filter")), ExitCode::from(2));
        assert_eq!(main(&args("diff --against rust")), ExitCode::from(2));
    }
}
