//! `opentide generate exports [navigator|objects|revisions]`, `generate docs`,
//! `generate explorer` and `generate inflight [prune]`
//! (`cli/commands/generate.py`, `cli/services/export.py`,
//! `cli/services/generation.py`) on `opentide-compile`'s `generate` module.
//!
//! A phase runs as a checklist step that counts the files it wrote, compared
//! by modification time and size before and after ([`Snapshot`]); the result
//! is `Generated 3 files in 0.1s · exports`, with the steps behind it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use opentide_compile::generate::docs::catalog::{Catalog, Scope};
use opentide_compile::generate::docs::facts::Environment as DeploymentFacts;
use opentide_compile::generate::docs::render::Pages;
use opentide_compile::generate::docs::vocab::Vocab;
use opentide_compile::generate::docs::{
    Counts, FlavorHints, Settings as DocsSettings, changed, index_pages, inflight as docs_inflight,
    pages, stale_pages,
};
use opentide_compile::generate::exports::{Settings, Target, export};
use opentide_compile::generate::files::{Snapshot, common_dir, remove_all, write_all};
use opentide_compile::generate::visibility::{self, DatasetRead, Inputs};
use opentide_compile::generate::{Output, PhaseError, explorer, inflight};
use opentide_compile::git;
use opentide_compile::strategy::Statuses;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, OsFs, Workspace};

use super::{Report, open, placement};
use crate::env::Env;
use crate::envelope::Failure;
use crate::json::Json;
use crate::render::progress::{Step, StepStatus, plural, seconds_text};

/// Where a generate command runs.
pub struct Context<'a> {
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// `--proxy`: `generate docs` fetches CVE details through it.
    pub proxy: Option<&'a str>,
    /// opentide's version, for the CVE lookups' `User-Agent`.
    pub version: &'a str,
}

/// `failure.code` of a phase that failed (`default_failure_code("failed")`).
const COMMAND_FAILED: &str = super::COMMAND_FAILED;

/// A phase run as one step: the files it wrote, found on disk.
struct Phase {
    step: Step,
    error: Option<String>,
}

/// Runs `work` as the step `name`, watching `roots` for the files it writes.
fn run_phase(
    name: &str,
    roots: &[PathBuf],
    cwd: &Path,
    workspace: &Path,
    work: impl FnOnce() -> Result<(), String>,
) -> Phase {
    let snapshot = Snapshot::take(roots);
    let started = Instant::now();
    let result = work();
    let mut step = Step::new(name);
    step.seconds = started.elapsed().as_secs_f64();
    match result {
        Ok(()) => {
            let (written, removed) = snapshot.changes();
            step.status = StepStatus::Ok;
            if !removed.is_empty() && written.is_empty() {
                step.count = Some(removed.len());
                step.place = common_dir(&removed, cwd, workspace);
                step.detail = "removed".into();
                step.unit = "file removed".into();
            } else {
                step.count = Some(written.len());
                step.place = common_dir(&written, cwd, workspace);
            }
            Phase { step, error: None }
        }
        Err(error) => {
            step.status = StepStatus::Failed;
            Phase {
                step,
                error: Some(error),
            }
        }
    }
}

/// A step as the result's `steps` carry it.
fn step_json(step: &Step) -> Json {
    let status = match step.status {
        StepStatus::Ok => "ok",
        StepStatus::Failed | StepStatus::Running => "failed",
        StepStatus::Skipped => "skipped",
    };
    Json::object([
        ("name", Json::str(&step.name)),
        ("status", Json::str(status)),
        (
            "count",
            step.count.map_or(Json::Null, |count| {
                Json::Int(i64::try_from(count).unwrap_or(i64::MAX))
            }),
        ),
        ("unit", Json::str(&step.unit)),
        ("seconds", Json::Float(rounded(step.seconds))),
        ("where", Json::opt_str(step.place.clone())),
    ])
}

fn rounded(seconds: f64) -> f64 {
    (seconds * 1000.0).round() / 1000.0
}

/// `Generated 3 files in 0.1s · exports`, the steps and the summary
/// (`generation_result`), after the command's own keys.
fn generated(command: &str, leading: Vec<(String, Json)>, steps: Vec<Step>) -> Report {
    let written: usize = steps
        .iter()
        .filter(|step| step.unit == "file")
        .filter_map(|step| step.count)
        .sum();
    let removed: usize = steps
        .iter()
        .filter(|step| step.unit == "file removed")
        .filter_map(|step| step.count)
        .sum();
    let seconds: f64 = steps.iter().map(|step| step.seconds).sum();
    let subject = match steps.as_slice() {
        [one] => one.name.clone(),
        [] => "nothing to run".to_owned(),
        many => plural(many.len(), "phase", None),
    };
    let message = if removed > 0 && written == 0 {
        format!(
            "Removed {} in {} · {subject}",
            plural(removed, "file", None),
            seconds_text(seconds)
        )
    } else {
        format!(
            "Generated {} in {} · {subject}",
            plural(written, "file", None),
            seconds_text(seconds)
        )
    };
    let mut data = leading;
    data.push((
        "steps".into(),
        Json::Array(steps.iter().map(step_json).collect()),
    ));
    let mut report = Report::completed(command, data);
    report.outcome.message = message;
    report.outcome.summary = vec![
        ("files".into(), count_json(written)),
        ("removed".into(), count_json(removed)),
        ("phases".into(), count_json(steps.len())),
        ("seconds".into(), Json::Float(rounded(seconds))),
    ];
    report.steps = steps;
    report
}

fn count_json(count: usize) -> Json {
    Json::Int(i64::try_from(count).unwrap_or(i64::MAX))
}

/// A phase that failed (`phase_failure`): exit 1, the phase named in
/// `phase` and leading the message.
pub(crate) fn phase_failed(
    command: &str,
    phase: &str,
    detail: &str,
    extra: Vec<(String, Json)>,
    steps: Vec<Step>,
) -> Report {
    let message = format!("{phase}: {detail}");
    let mut report = Report::failed(command, 1, Failure::new(COMMAND_FAILED, &message));
    let mut data = vec![("phase".to_owned(), Json::str(phase))];
    data.extend(extra);
    report.outcome.data = data;
    report.steps = steps;
    report
}

/// The workspace a generate command reads, or the report of why it cannot.
fn workspace(command: &str, cx: &Context<'_>) -> Result<Workspace, Box<Report>> {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    open(options).map_err(|message| Box::new(Report::error(command, message)))
}

/// The workspace a generate command reads, opened as the first work of its
/// step `step`: the oracle reads the configuration inside the phase, so a
/// configuration that does not resolve (a paths.toml its model refuses,
/// #936, #946) fails that phase, with `phase`, `extra` and the failed row.
fn workspace_in_step(
    command: &str,
    step: &str,
    phase: &str,
    extra: Vec<(String, Json)>,
    cx: &Context<'_>,
) -> Result<Workspace, Box<Report>> {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    open(options).map_err(|detail| {
        let ran = run_phase(step, &[], cx.cwd, cx.cwd, || Err(detail));
        let detail = ran.error.clone().unwrap_or_default();
        Box::new(phase_failed(command, phase, &detail, extra, vec![ran.step]))
    })
}

/// Writes `outputs`, as one phase's work.
fn write(outputs: &[Output]) -> Result<(), String> {
    write_all(outputs).map_err(|(path, error)| format!("{}: {error}", path.display()))
}

/// `opentide generate exports`, or one export when `target` names it.
pub fn exports(target: Option<Target>, cx: &Context<'_>) -> Report {
    let command = match target {
        Some(target) => format!("generate exports {}", target.name()),
        None => "generate exports".to_owned(),
    };
    let name = target.map_or_else(
        || "exports".to_owned(),
        |one| format!("exports {}", one.name()),
    );
    let target_key =
        |target: Option<Target>| target.map(|one| ("target".to_owned(), Json::str(one.name())));
    let workspace = match workspace_in_step(
        &command,
        &name,
        "exports",
        target_key(target).into_iter().collect(),
        cx,
    ) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let root = workspace.root().to_path_buf();
    let settings = Settings::new(workspace.configuration(), &root);
    let vocabularies = Vocabularies::bundled();
    let targets: Vec<Target> = target.map_or_else(|| Target::ALL.to_vec(), |one| vec![one]);
    let phase = run_phase(&name, std::slice::from_ref(&root), cx.cwd, &root, || {
        let mut outputs = Vec::new();
        for target in &targets {
            match export(*target, workspace.index(), &settings, &vocabularies) {
                Ok(output) => outputs.push(output),
                Err(PhaseError { detail }) => {
                    // The oracle writes the exports one after another: the
                    // ones before a failure are on disk.
                    write(&outputs)?;
                    return Err(detail);
                }
            }
        }
        write(&outputs)
    });
    match phase.error {
        Some(detail) => phase_failed(
            &command,
            "exports",
            &detail,
            target_key(target).into_iter().collect(),
            vec![phase.step],
        ),
        None => {
            let leading = match target {
                Some(_) => target_key(target).into_iter().collect(),
                None => vec![("phase".to_owned(), Json::str("exports"))],
            };
            generated(&command, leading, vec![phase.step])
        }
    }
}

/// The page family a `generate docs` subcommand writes, or the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocsScope {
    /// One family's pages.
    Objects(Scope),
    /// The index pages.
    Index,
}

impl DocsScope {
    /// Its word on the command line.
    pub fn name(self) -> &'static str {
        match self {
            Self::Objects(scope) => scope.folder(),
            Self::Index => "index",
        }
    }
}

/// `opentide generate docs` and its subcommands, parsed.
#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command's flags, one field each"
)]
pub struct DocsArgs {
    /// The subcommand: one family, or the index.
    pub scope: Option<DocsScope>,
    /// `--output`.
    pub output: Option<String>,
    /// `--flavor`.
    pub flavor: Option<String>,
    /// `--rules`.
    pub rules: bool,
    /// `--threats`.
    pub threats: bool,
    /// `--objectives`.
    pub objectives: bool,
    /// `--changed`.
    pub changed: bool,
}

/// What a docs run did, for its result.
#[derive(Default)]
struct DocsRun {
    data: Vec<(String, Json)>,
    message: Option<String>,
    /// `--changed` outside a checkout: the run's own failure.
    failure: Option<String>,
}

/// The CVE details `generate docs` writes with `[cve] retrieve_details` on
/// (UC-4.4, #834; 0.26.0): each identifier asked of Vulnerability-Lookup with
/// its linked records, then the EPSS score of its CVE, each once per run,
/// through the run's proxy (`lookup_cves`).
fn cve_source(
    resolved: &opentide_schema::configuration::resolve::Resolved,
    cx: &Context<'_>,
) -> opentide_compile::generate::docs::cve::CveSource {
    use opentide_compile::generate::docs::cve::{CveDetail, CveSource, EpssDetail};
    let settings = super::cve::Settings::from_documentation(resolved.get("documentation"));
    let links = settings.links();
    let environment = opentide_connectors::Environment::from_pairs(cx.env.iter());
    let lookup = opentide_connectors::vulnerability::VulnerabilityLookup::new(
        opentide_connectors::vulnerability::LookupSettings {
            base_url: settings.base_url.clone(),
            timeout: settings.timeout,
        },
        &environment,
        cx.proxy,
        cx.version,
    );
    CveSource::new(
        move |id: &str| match lookup.get(id, true, &|key: &str| links.page_url(key)) {
            Ok(Some(record)) => {
                let epss = match record.cve_id().map(|cve| lookup.epss(&cve)) {
                    Some(Ok(Some(score))) => EpssDetail::Score(score),
                    Some(Err(_)) => EpssDetail::Unavailable,
                    None | Some(Ok(None)) => EpssDetail::None,
                };
                CveDetail::Found(Box::new(record.into_docs(epss)))
            }
            Ok(None) => CveDetail::NotFound,
            Err(_) => CveDetail::Unavailable,
        },
    )
}

fn counts_json(counts: Counts) -> Json {
    Json::object([
        ("rules", count_json(counts.rules)),
        ("objectives", count_json(counts.objectives)),
        ("threats", count_json(counts.threats)),
    ])
}

fn strings_json<'s>(items: impl IntoIterator<Item = &'s String>) -> Json {
    Json::Array(items.into_iter().map(Json::str).collect())
}

/// Writes `outputs` and removes `stale`.
fn publish(outputs: &[Output], stale: &[PathBuf]) -> Result<(), String> {
    write(outputs)?;
    remove_all(stale).map_err(|(path, error)| format!("{}: {error}", path.display()))
}

/// The nested-file warning (`with_nested_object_warning`): files in
/// subfolders of an object folder are not objects and get no page.
pub(crate) fn nested_warning(workspace: &Workspace) -> Option<String> {
    let index = workspace.index();
    if index.nested.is_empty() {
        return None;
    }
    let root = workspace.root();
    let paths: Vec<String> = index
        .nested
        .iter()
        .map(|nested| {
            let shown = nested.path.strip_prefix(root).unwrap_or(&nested.path);
            shown.to_string_lossy().replace('\\', "/")
        })
        .collect();
    Some(format!(
        "{} object file(s) in subfolders of an object folder are not object instances and are \
         skipped (opentide reads only files directly in each object folder; see \
         https://github.com/opentidehq/opentide/issues/584): {}",
        paths.len(),
        paths.join(", ")
    ))
}

/// `opentide generate docs` (`run_generate_docs`, `run_document`).
pub fn docs(args: &DocsArgs, cx: &Context<'_>) -> Report {
    let command = match args.scope {
        Some(scope) => format!("generate docs {}", scope.name()),
        None => "generate docs".to_owned(),
    };
    if args.changed && (args.scope.is_some() || args.rules || args.threats || args.objectives) {
        let mut failure = Failure::new(
            crate::envelope::code::USAGE_ERROR,
            "--changed cannot be combined with scoped docs generation",
        );
        failure.argument = Some("--changed".into());
        return Report::failed(&command, crate::envelope::USAGE_EXIT_CODE, failure);
    }
    let workspace = match workspace_in_step(&command, "docs", "docs", Vec::new(), cx) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let root = workspace.root().to_path_buf();
    let base = output_base(&workspace);
    let mut roots = vec![root.clone(), base.clone()];
    if let Some(output) = args.output.as_deref().filter(|output| !output.is_empty()) {
        let path = PathBuf::from(output);
        roots.push(if path.is_absolute() {
            path
        } else {
            base.join(path)
        });
    }
    let mut run = DocsRun::default();
    let phase = run_phase("docs", &roots, cx.cwd, &root, || {
        docs_phase(args, &workspace, cx, &mut run)
    });
    let warnings: Vec<String> = nested_warning(&workspace).into_iter().collect();
    if let Some(detail) = phase.error {
        let mut report = phase_failed(&command, "docs", &detail, Vec::new(), vec![phase.step]);
        report.warnings = warnings;
        return report;
    }
    if let Some(message) = run.failure {
        let mut step = phase.step;
        step.status = StepStatus::Failed;
        let mut report = Report::failed(&command, 1, Failure::new(COMMAND_FAILED, &message));
        report.outcome.data = run.data;
        report.steps = vec![step];
        report.warnings = warnings;
        return report;
    }
    let wrote = phase.step.count.is_some_and(|count| count > 0);
    let mut report = generated(&command, run.data, vec![phase.step]);
    if !wrote && let Some(message) = run.message {
        report.outcome.message = message;
    }
    report.warnings = warnings;
    report
}

/// The folder a relative docs output is under: the repository root, as the
/// oracle's `load_settings` joins it onto `get_repo_root()`, not the Tide
/// workspace, which `OPENTIDE_TIDE_WORKSPACE` can place elsewhere (#931).
/// Resolved as the workspace is, so the two compare when they are one folder.
fn output_base(workspace: &Workspace) -> PathBuf {
    OsFs.resolve(&workspace.roots().repo)
}

/// The work of the docs phase: the pages, the stale pages removed, the
/// index; `run` gets the result's keys.
fn docs_phase(
    args: &DocsArgs,
    workspace: &Workspace,
    cx: &Context<'_>,
    run: &mut DocsRun,
) -> Result<(), String> {
    let resolved = &workspace.configuration().resolved;
    let root = workspace.root();
    let env = |name: &str| cx.env.get(name).map(str::to_owned);
    let hints = FlavorHints::new(&env, opentide_compile::git::origin_url(root));
    let mut settings = DocsSettings::resolve(
        resolved,
        &output_base(workspace),
        args.output.as_deref(),
        args.flavor.as_deref(),
        &hints,
    )
    .map_err(|error| error.detail)?;
    if settings.cve_details {
        settings.cve_source = cve_source(resolved, cx);
    }
    // Documentation previews open pull requests: their inflight shards are
    // overlaid on the index for the run (`inflight_preview`).
    let overlaid = docs_inflight::overlay(workspace.index(), &root.join(".opentide/inflight"));
    let index = overlaid
        .as_ref()
        .unwrap_or_else(|| workspace.index().as_ref());
    let catalog =
        Catalog::build(index, Statuses::from_resolved(resolved)).map_err(|error| error.detail)?;
    let vocabularies = Vocabularies::bundled();
    // What deploy would do with each rule: the statuses, the enabled
    // platforms, their tenants (never their credentials) and the state's ids.
    let config = opentide_compile::Json::from_node(&resolved.tree);
    let enabled = opentide_compile::plan::enabled_with(&config, &crate::plugins::plugin_ids());
    let deployment = DeploymentFacts::read(
        &config,
        &enabled,
        &OsFs,
        root,
        catalog.rules.iter().map(|record| record.uuid.as_str()),
    );
    let pages_of = Pages {
        catalog: &catalog,
        settings: &settings,
        vocab: Vocab::new(&vocabularies),
        deployment: &deployment,
    };
    let output_text = Json::str(settings.output.to_string_lossy().as_ref());
    let flagged: Vec<Scope> = [
        (Scope::Rules, args.rules),
        (Scope::Threats, args.threats),
        (Scope::Objectives, args.objectives),
    ]
    .into_iter()
    .filter_map(|(scope, given)| given.then_some(scope))
    .collect();
    let scope = args
        .scope
        .or_else(|| flagged.first().map(|scope| DocsScope::Objects(*scope)));
    if args.changed {
        return changed_phase(workspace, &pages_of, output_text, run);
    }
    match scope {
        Some(DocsScope::Index) => {
            publish(&index_pages(&pages_of).map_err(|error| error.detail)?, &[])?;
            run.data = vec![("output".into(), output_text)];
            run.message = Some("Index pages written".into());
        }
        Some(DocsScope::Objects(_)) if args.scope.is_none() && flagged.len() > 1 => {
            let mut counts = Counts::default();
            for scope in &flagged {
                let (outputs, scoped) =
                    pages(&pages_of, &[*scope], None).map_err(|error| error.detail)?;
                publish(&outputs, &stale_pages(&pages_of, &[*scope]))?;
                counts.rules += scoped.rules;
                counts.objectives += scoped.objectives;
                counts.threats += scoped.threats;
            }
            let names: Vec<String> = flagged
                .iter()
                .map(|scope| scope.folder().to_owned())
                .collect();
            run.message = Some(format!(
                "Documentation scopes {} completed",
                names.join(", ")
            ));
            run.data = vec![
                ("scopes".into(), strings_json(&names)),
                ("counts".into(), counts_json(counts)),
            ];
        }
        Some(DocsScope::Objects(scope)) => {
            let (outputs, counts) =
                pages(&pages_of, &[scope], None).map_err(|error| error.detail)?;
            let stale = stale_pages(&pages_of, &[scope]);
            publish(&outputs, &stale)?;
            run.message = Some(format!("Documentation scope {} completed", scope.folder()));
            run.data = vec![
                ("counts".into(), counts_json(counts)),
                ("removed".into(), count_json(stale.len())),
            ];
        }
        None => {
            let (outputs, counts) =
                pages(&pages_of, &Scope::ALL, None).map_err(|error| error.detail)?;
            let stale = stale_pages(&pages_of, &Scope::ALL);
            publish(&outputs, &stale)?;
            publish(&index_pages(&pages_of).map_err(|error| error.detail)?, &[])?;
            run.message = Some("Full documentation pipeline completed".into());
            run.data = vec![
                ("counts".into(), counts_json(counts)),
                ("removed".into(), count_json(stale.len())),
                ("output".into(), output_text),
            ];
        }
    }
    Ok(())
}

/// `--changed`: the pages of the objects changed against the default branch,
/// their referrers' and the index.
fn changed_phase(
    workspace: &Workspace,
    pages_of: &Pages<'_, '_>,
    output_text: Json,
    run: &mut DocsRun,
) -> Result<(), String> {
    let folders = changed::folders(workspace.configuration());
    let files = match opentide_compile::git::changed_in_folders(
        workspace.root(),
        &folders,
        &changed::is_object_file,
    ) {
        Ok(files) => files,
        Err(error) => {
            let detail = error.message();
            tracing::warn!(detail = detail.as_str(), "docs_changed_requires_git");
            run.failure = Some(format!("--changed requires a git repository: {detail}"));
            run.data = vec![
                ("changed_paths".into(), Json::Array(Vec::new())),
                ("changed_uuids".into(), Json::Array(Vec::new())),
                ("counts".into(), counts_json(Counts::default())),
                ("output".into(), output_text),
            ];
            return Ok(());
        }
    };
    let changes = changed::changes(pages_of.catalog, &files);
    if changes.paths.is_empty() {
        run.message = Some("No changed object documentation detected".into());
        run.data = vec![
            ("changed_paths".into(), Json::Array(Vec::new())),
            ("changed_uuids".into(), Json::Array(Vec::new())),
            ("counts".into(), counts_json(Counts::default())),
            ("output".into(), output_text),
        ];
        return Ok(());
    }
    let (outputs, counts) =
        pages(pages_of, &Scope::ALL, Some(&changes.targets)).map_err(|error| error.detail)?;
    let stale = stale_pages(pages_of, &Scope::ALL);
    publish(&outputs, &stale)?;
    publish(&index_pages(pages_of).map_err(|error| error.detail)?, &[])?;
    let mut scopes: Vec<String> = changes
        .targets
        .iter()
        .filter_map(|uuid| pages_of.catalog.record(uuid))
        .map(|record| match record.scope {
            Scope::Rules => "rule".to_owned(),
            Scope::Objectives => "objective".to_owned(),
            Scope::Threats => "threat".to_owned(),
        })
        .collect();
    scopes.sort();
    scopes.dedup();
    run.message = Some("Changed documentation pipeline completed".into());
    run.data = vec![
        ("counts".into(), counts_json(counts)),
        ("removed".into(), count_json(stale.len())),
        ("changed_paths".into(), strings_json(&changes.paths)),
        ("changed_uuids".into(), strings_json(&changes.uuids)),
        ("targets".into(), strings_json(&changes.targets)),
        ("scopes".into(), strings_json(&scopes)),
        ("output".into(), output_text),
    ];
    Ok(())
}

/// `generate explorer`'s options.
#[derive(Debug, Clone, Default)]
pub struct ExplorerOptions {
    /// `--include-visibility`.
    pub include_visibility: bool,
    /// `--visibility-tlp`, as typed; `None` when not given.
    pub visibility_tlp: Option<String>,
}

/// The visibility probe: one placeholder log source per system whose names
/// declare datasets, so the engines name every dataset a query reads
/// (`dataset_reads`).
const PROBE: &str = "__opentide_visibility_probe__";
/// The systems whose log source names declare datasets to the query checks.
const DATASET_SYSTEMS: [&str; 4] = ["sentinel", "defender_for_endpoint", "splunk", "elastic"];
/// A table outside the engine's catalog: a read only when its message names
/// `visibility.toml`, as the language server's quick fix takes it.
const UNKNOWN_TABLE_CODE: &str = "kql_unknown_table";

/// The datasets each rule's queries read, as the query engines read them
/// (`dataset_reads`): each rule file is analysed with a visibility that
/// declares only the probe for every system, so the engines report every
/// dataset a query reads as undeclared, and the name is the quoted one in the
/// finding. The workspace's own declarations are installed again after.
fn dataset_reads(
    index: &opentide_workspace::Index,
    files: &opentide_workspace::Index,
    root: &Path,
) -> Vec<DatasetRead> {
    let _engine = crate::queries::ENGINE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut probe = String::new();
    for system in DATASET_SYSTEMS {
        let _ = write!(
            probe,
            "[[logsources]]\nname = \"{PROBE}\"\ndescription = \"probe\"\nsystem = \"{system}\"\n\n"
        );
    }
    let _ = opentide_analysis::install_visibility(Some(&probe));
    let host = opentide_analysis::MemoryWorkspace { files: Vec::new() };
    let quoted = regex::Regex::new(r"'([^']+)'|`([^`]+)`").ok();
    let mut reads: Vec<DatasetRead> = Vec::new();
    for rule in index.family("rule") {
        let Some(path) = files.file_paths.get(&rule.uuid) else {
            continue;
        };
        let Some(text) = std::fs::read(path)
            .ok()
            .and_then(|bytes| crate::queries::decode(&bytes).ok())
        else {
            continue;
        };
        for report in opentide_analysis::analyze_queries(&host, &text) {
            let path = &report.field_path;
            let system = match path.as_slice() {
                [first, second, ..] if first == "configurations" => second.clone(),
                _ => String::new(),
            };
            for finding in &report.diagnostics {
                let is_read = crate::queries::DECLARED_DATASET_CODES
                    .contains(&finding.code.as_str())
                    || (finding.code == UNKNOWN_TABLE_CODE
                        && finding.message.contains("visibility.toml"));
                if !is_read {
                    continue;
                }
                let name = quoted
                    .as_ref()
                    .and_then(|quoted| quoted.captures(&finding.message))
                    .and_then(|found| found.get(1).or_else(|| found.get(2)))
                    .map(|found| found.as_str().to_owned())
                    .unwrap_or_default();
                if name.is_empty() || name == PROBE {
                    continue;
                }
                let read = DatasetRead {
                    rule: rule.uuid.clone(),
                    system: system.clone(),
                    name,
                    field_path: path.join("."),
                };
                if !reads.contains(&read) {
                    reads.push(read);
                }
            }
        }
    }
    let own = std::fs::read(root.join(crate::queries::VISIBILITY_CONFIGURATION))
        .ok()
        .and_then(|bytes| crate::queries::decode(&bytes).ok());
    if opentide_analysis::install_visibility(own.as_deref()).is_err() {
        let _ = opentide_analysis::install_visibility(None);
    }
    reads
}

/// The visibility report of the (overlaid) `index` (`load_visibility`):
/// the declared log sources, read through their model, and the datasets the
/// rules' files read.
pub fn visibility_report(
    workspace: &Workspace,
    index: &opentide_workspace::Index,
    root: &Path,
) -> opentide_compile::json::Json {
    let present = root
        .join(crate::queries::VISIBILITY_CONFIGURATION)
        .is_file();
    let mut inputs = Inputs::default();
    if present {
        match workspace
            .configuration()
            .resolved
            .get("visibility")
            .map(visibility::declared)
        {
            Some(Ok(declared)) => inputs.declared = Some(declared),
            Some(Err(problem)) => inputs.problem = Some(problem),
            None => inputs.declared = Some(Vec::new()),
        }
    }
    inputs.reads = dataset_reads(index, workspace.index(), root);
    visibility::report(index, &inputs)
}

/// The UTC time now as Python's `isoformat()` writes an aware datetime.
fn now_iso() -> String {
    jiff::Timestamp::now()
        .to_zoned(jiff::tz::TimeZone::UTC)
        .strftime("%Y-%m-%dT%H:%M:%S%.6f+00:00")
        .to_string()
}

/// `opentide generate explorer`.
pub fn explorer(options: &ExplorerOptions, cx: &Context<'_>) -> Report {
    const COMMAND: &str = "generate explorer";
    let tlp = match &options.visibility_tlp {
        Some(given) if !options.include_visibility => {
            let _ = given;
            let mut failure = Failure::new(
                super::USAGE_MISSING_OPTION,
                "--visibility-tlp needs --include-visibility: it labels explorer.visibility.json, which only --include-visibility writes.",
            );
            failure.argument = Some("--visibility-tlp".into());
            return Report::failed(COMMAND, crate::envelope::USAGE_EXIT_CODE, failure);
        }
        Some(given) => given.trim().to_lowercase(),
        None => explorer::DEFAULT_TLP.to_owned(),
    };
    if !explorer::TLP_CHOICES.contains(&tlp.as_str()) {
        let given = options.visibility_tlp.clone().unwrap_or_default();
        return Report::usage(
            COMMAND,
            format!(
                "Unknown TLP {}. Pass one of: {}.",
                opentide_schema::configuration::repr::quote(&given),
                explorer::TLP_CHOICES.join(", ")
            ),
            super::USAGE_INVALID_CHOICE,
            "--visibility-tlp",
            Some(&given),
            &explorer::TLP_CHOICES,
        );
    }
    let workspace = match workspace_in_step(COMMAND, "explorer", "explorer", Vec::new(), cx) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let root = workspace.root().to_path_buf();
    let dir = Settings::new(workspace.configuration(), &root).dir;
    let phase = run_phase(
        "explorer",
        std::slice::from_ref(&root),
        cx.cwd,
        &root,
        || {
            std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
            // Open pull requests' objects, previewed (`inflight_preview`).
            let shards = inflight::load(&root.join(".opentide").join("inflight"));
            let index = inflight::overlay(workspace.index(), &shards);
            let generated_at = now_iso();
            let outputs = explorer::outputs(&index, &dir, &generated_at)
                .map_err(|PhaseError { detail }| detail)?;
            write(&outputs)?;
            let visibility_path = dir.join(explorer::VISIBILITY);
            if options.include_visibility {
                let report = visibility_report(&workspace, &index, &root);
                let document = explorer::visibility(report, &generated_at, &tlp);
                write(&[Output::text(visibility_path, document.to_compact())])?;
            } else if visibility_path.is_file() {
                // Opt-in per run: an inventory an earlier run wrote is not published again.
                std::fs::remove_file(&visibility_path)
                    .map_err(|error| format!("{}: {error}", visibility_path.display()))?;
            }
            Ok(())
        },
    );
    match phase.error {
        Some(detail) => phase_failed(COMMAND, "explorer", &detail, Vec::new(), vec![phase.step]),
        None => generated(
            COMMAND,
            vec![("phase".to_owned(), Json::str("explorer"))],
            vec![phase.step],
        ),
    }
}

/// The object files the change set touches (`changed_object_yaml_paths`):
/// `INFLIGHT_PATHS` when set, else, outside CI, the work tree against the
/// default branch, and in CI the pull or merge request's diff (the work tree
/// again when that cannot be read).
fn changed_object_files(root: &Path, cx: &Context<'_>) -> Vec<PathBuf> {
    if let Some(raw) = cx
        .env
        .get("INFLIGHT_PATHS")
        .filter(|raw| !raw.trim().is_empty())
    {
        return raw
            .trim()
            .split(',')
            .filter(|path| !path.trim().is_empty())
            .map(|path| cx.cwd.join(path))
            .collect();
    }
    let env = |name: &str| cx.env.get(name).map(str::to_owned);
    if git::ci(&env) == git::Ci::Local {
        let local = work_tree_changes(cx.env, root);
        if local.is_empty() {
            tracing::warn!("inflight_no_local_git_diff_found");
        }
        return local;
    }
    match git::changed_paths(root, cx.cwd, &env, git::DiffSource::ChangeRequest) {
        Ok(scope) => scope
            .iter()
            .filter(|path| inflight::is_object_yaml(path))
            .map(|path| root.join(path))
            .collect(),
        Err(error) => {
            tracing::warn!(detail = error.message().as_str(), "inflight_ci_diff_failed");
            work_tree_changes(cx.env, root)
        }
    }
}

/// The object files changed in the work tree against the default branch,
/// untracked ones included (`_local_git_changed_paths`).
fn work_tree_changes(env: &Env, root: &Path) -> Vec<PathBuf> {
    let baseline = match crate::git_baseline::resolve(env, root) {
        Ok(baseline) => baseline,
        Err(detail) => {
            tracing::warn!(detail = detail.as_str(), "inflight_no_git_baseline");
            return Vec::new();
        }
    };
    let top = crate::git_baseline::toplevel(env, root);
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let prefix = canonical(root)
        .strip_prefix(canonical(&top))
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let prefix_text = prefix.to_string_lossy().replace('\\', "/");
    let pathspec = if prefix_text.is_empty() {
        "objects/".to_owned()
    } else {
        format!("{prefix_text}/objects/")
    };
    crate::git_baseline::changed(env, root, &baseline, &pathspec)
        .into_iter()
        .filter_map(|relative| {
            let within = Path::new(&relative).strip_prefix(&prefix).ok()?;
            let absolute = top.join(&relative);
            (inflight::is_object_yaml(&within.to_string_lossy()) && absolute.is_file())
                .then_some(absolute)
        })
        .collect()
}

/// `path` from the workspace with `/`, or as given when it is outside it
/// (`_normalise_source_path`).
fn source_path(root: &Path, path: &Path) -> String {
    let canonical =
        |path: &Path| std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let shown = canonical(path)
        .strip_prefix(canonical(root))
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf);
    shown.to_string_lossy().replace('\\', "/")
}

/// `opentide generate inflight`: a preview shard for each object file the
/// change set touches, under `.opentide/inflight/`.
pub fn inflight_shards(cx: &Context<'_>) -> Report {
    const COMMAND: &str = "generate inflight";
    let workspace = match workspace_in_step(COMMAND, "inflight", "inflight", Vec::new(), cx) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let root = workspace.root().to_path_buf();
    let dir = root.join(".opentide").join("inflight");
    let phase = run_phase(
        "inflight",
        std::slice::from_ref(&root),
        cx.cwd,
        &root,
        || {
            std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
            let env = |name: &str| cx.env.get(name).map(str::to_owned);
            let ci = git::ci(&env);
            let event = cx
                .env
                .get("GITHUB_EVENT_PATH")
                .filter(|path| !path.is_empty())
                .and_then(|path| std::fs::read_to_string(path).ok());
            let mut shards: indexmap::IndexMap<PathBuf, Output> = indexmap::IndexMap::new();
            for path in changed_object_files(&root, cx) {
                let text = std::fs::read(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))
                    .and_then(|bytes| crate::queries::decode(&bytes))?;
                let document = opentide_schema::node::load(&text)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                let Some(body) = document
                    .root()
                    .filter(|root| matches!(root.value, opentide_schema::node::Value::Map(_)))
                else {
                    tracing::warn!(path = %path.display(), "inflight_skip_non_mapping");
                    continue;
                };
                let Some(uuid) = inflight::object_uuid(body) else {
                    tracing::warn!(path = %path.display(), "inflight_skip_missing_uuid");
                    continue;
                };
                let now = now_iso();
                let change =
                    inflight::change(&env, ci, &source_path(&root, &path), event.as_deref(), &now);
                let shard = inflight::shard(body, &now, change);
                let target = dir.join(format!("{uuid}.json"));
                tracing::info!(uuid = uuid.as_str(), path = %target.display(), "inflight_shard_written");
                shards.insert(
                    target.clone(),
                    Output::text(
                        target,
                        opentide_compile::generate::json_text::pretty(&shard, 2),
                    ),
                );
            }
            write(&shards.into_values().collect::<Vec<_>>())
        },
    );
    match phase.error {
        Some(detail) => phase_failed(COMMAND, "inflight", &detail, Vec::new(), vec![phase.step]),
        None => generated(
            COMMAND,
            vec![("phase".to_owned(), Json::str("inflight"))],
            vec![phase.step],
        ),
    }
}

/// `opentide generate inflight prune`: removes the shards the default
/// branch has caught up with.
pub fn inflight_prune(cx: &Context<'_>) -> Report {
    const COMMAND: &str = "generate inflight prune";
    let workspace =
        match workspace_in_step(COMMAND, "inflight prune", "inflight-prune", Vec::new(), cx) {
            Ok(workspace) => workspace,
            Err(report) => return *report,
        };
    let root = workspace.root().to_path_buf();
    let dir = root.join(".opentide").join("inflight");
    let phase = run_phase(
        "inflight prune",
        std::slice::from_ref(&root),
        cx.cwd,
        &root,
        || {
            for (uuid, path) in inflight::superseded(&dir, workspace.index()) {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(format!("{}: {error}", path.display())),
                }
                tracing::info!(uuid = uuid.as_str(), path = %path.display(), "inflight_shard_pruned");
            }
            Ok(())
        },
    );
    match phase.error {
        Some(detail) => phase_failed(
            COMMAND,
            "inflight-prune",
            &detail,
            Vec::new(),
            vec![phase.step],
        ),
        None => generated(
            COMMAND,
            vec![("phase".to_owned(), Json::str("inflight-prune"))],
            vec![phase.step],
        ),
    }
}

/// The phases `opentide generate` names as words (`generate schemas
/// templates`), sorted as the usage error lists them.
pub const NAMED_PHASES: [&str; 4] = ["schemas", "snippets", "templates", "vocabs"];

/// What a run of named phases did: the steps, and the phase that failed
/// with its detail.
pub struct PhasesRun {
    /// One step per phase that ran, in order.
    pub steps: Vec<Step>,
    /// The phase that failed and why; the phases after it did not run.
    pub failed: Option<(String, String)>,
}

/// The sources of the `schemas` phase: the workspace's resolved
/// configuration, the bundled vocabularies and its object vocabularies.
pub fn schema_sources(workspace: &Workspace) -> opentide_schema::generate::schema::Sources {
    let tree = workspace.configuration().resolved.tree.clone();
    let mut vocabularies = Vocabularies::bundled();
    for vocabulary in
        opentide_workspace::vocabularies::object_vocabularies(workspace.index(), &tree)
    {
        vocabularies.insert(vocabulary);
    }
    opentide_schema::generate::schema::Sources {
        config: std::sync::Arc::new(tree),
        vocabularies: std::sync::Arc::new(vocabularies),
    }
}

/// The files one of the phases this engine runs writes, under `root`.
pub(crate) fn phase_outputs(
    phase: &str,
    workspace: &Workspace,
    root: &Path,
    version: &str,
) -> Result<Vec<Output>, String> {
    use opentide_schema::generate::catalog::{CATALOG_DIR, catalog_texts};
    use opentide_schema::generate::workspace::{
        router_artifact, schema_artifacts, snippets, templates,
    };
    let config = &workspace.configuration().resolved.tree;
    let at = |path: &str| root.join(path);
    match phase {
        "templates" => Ok(templates(config)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|artifact| Output::text(at(&artifact.path), artifact.text))
            .collect()),
        "schemas" => {
            let sources = schema_sources(workspace);
            let mut outputs: Vec<Output> = schema_artifacts(&sources)
                .into_iter()
                .chain(std::iter::once(router_artifact(config)))
                .map(|artifact| Output::text(at(&artifact.path), artifact.text))
                .collect();
            for (name, text) in catalog_texts(version, &sources) {
                outputs.push(Output::text(at(CATALOG_DIR).join(name), text));
            }
            Ok(outputs)
        }
        "snippets" => {
            // The snippets quote the templates as they are on disk.
            let on_disk: Vec<_> = templates(config)
                .map_err(|error| error.to_string())?
                .into_iter()
                .filter_map(|mut artifact| {
                    artifact.text = std::fs::read_to_string(at(&artifact.path)).ok()?;
                    Some(artifact)
                })
                .collect();
            let snippet = snippets(config, &on_disk)?;
            Ok(vec![Output::text(at(&snippet.path), snippet.text)])
        }
        // The object vocabularies are built from the index whenever a
        // schema or a check needs them; the phase writes nothing
        // (`object_vocab.run`).
        "vocabs" => Ok(Vec::new()),
        other => Err(format!("Unknown generation phase: {other}")),
    }
}

/// Runs `phases` (each `schemas`, `templates`, `vocabs` or `snippets`) on `workspace`
/// in order, each as a checklist step, until one fails.
pub fn run_phases(
    phases: &[String],
    workspace: &Workspace,
    cwd: &Path,
    version: &str,
) -> PhasesRun {
    let root = workspace.root().to_path_buf();
    let mut steps = Vec::new();
    for phase in phases {
        // The checklist names `vocabs` by what it builds.
        let name = if phase == "vocabs" {
            "vocabularies"
        } else {
            phase.as_str()
        };
        let ran = run_phase(name, std::slice::from_ref(&root), cwd, &root, || {
            write(&phase_outputs(phase, workspace, &root, version)?)
        });
        steps.push(ran.step);
        if let Some(detail) = ran.error {
            return PhasesRun {
                steps,
                failed: Some((phase.clone(), detail)),
            };
        }
    }
    PhasesRun {
        steps,
        failed: None,
    }
}

/// The full pipeline's phases, in the oracle's order (`_PHASE_ORDER`): what
/// a person reads first (the pages, the exports), then the framework's own
/// files.
pub const PIPELINE: [&str; 6] = [
    "docs",
    "exports",
    "vocabs",
    "templates",
    "schemas",
    "snippets",
];

/// `opentide generate` with no phase (`run_generate_all`): every phase of
/// [`PIPELINE`] as one checklist step each, on the workspace opened once,
/// until one fails; then the nested-file warning (`report_nested_object_files`).
fn pipeline(cx: &Context<'_>, version: &str) -> Report {
    let command = "generate";
    let leading = || {
        vec![(
            "phases".to_owned(),
            Json::Array(PIPELINE.iter().map(|phase| Json::str(*phase)).collect()),
        )]
    };
    // The oracle reads the configuration inside the first phase.
    let workspace = match workspace_in_step(command, "docs", "docs", Vec::new(), cx) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let root = workspace.root().to_path_buf();
    let mut steps = Vec::new();
    let mut run = DocsRun::default();
    let docs = run_phase(
        "docs",
        &[root.clone(), output_base(&workspace)],
        cx.cwd,
        &root,
        || docs_phase(&DocsArgs::default(), &workspace, cx, &mut run),
    );
    steps.push(docs.step);
    if let Some(detail) = docs.error {
        return phase_failed(command, "docs", &detail, Vec::new(), steps);
    }
    let settings = Settings::new(workspace.configuration(), &root);
    let vocabularies = Vocabularies::bundled();
    let exports = run_phase(
        "exports",
        std::slice::from_ref(&root),
        cx.cwd,
        &root,
        || {
            let mut outputs = Vec::new();
            for target in Target::ALL {
                match export(target, workspace.index(), &settings, &vocabularies) {
                    Ok(output) => outputs.push(output),
                    Err(PhaseError { detail }) => {
                        write(&outputs)?;
                        return Err(detail);
                    }
                }
            }
            write(&outputs)
        },
    );
    steps.push(exports.step);
    if let Some(detail) = exports.error {
        return phase_failed(command, "exports", &detail, Vec::new(), steps);
    }
    let named: Vec<String> = PIPELINE[2..]
        .iter()
        .map(|phase| (*phase).to_owned())
        .collect();
    let run = run_phases(&named, &workspace, cx.cwd, version);
    steps.extend(run.steps);
    if let Some((phase, detail)) = run.failed {
        return phase_failed(command, &phase, &detail, Vec::new(), steps);
    }
    let mut report = generated(command, leading(), steps);
    if let Some(detail) = nested_warning(&workspace) {
        let files = workspace
            .index()
            .nested
            .iter()
            .map(|nested| {
                let shown = nested.path.strip_prefix(&root).unwrap_or(&nested.path);
                shown.to_string_lossy().replace('\\', "/")
            })
            .collect();
        report
            .after_steps
            .push(super::AfterSteps::NestedObjectFiles { detail, files });
    }
    report
}

/// `opentide generate <phase>...` (`run_generate` with named phases): the
/// `schemas`, `templates`, `vocabs` and `snippets` phases; with none, the full
/// pipeline (`pipeline`). Each finished phase writes its
/// `OPENTIDE_PROGRESS=json` event, out of the phases the run names.
pub fn phases(names: &[String], cx: &Context<'_>, version: &str) -> Report {
    let mut report = named_phases(names, cx, version);
    report.step_events = Some(if names.is_empty() {
        PIPELINE.len()
    } else {
        names.len()
    });
    report
}

fn named_phases(names: &[String], cx: &Context<'_>, version: &str) -> Report {
    let command = "generate";
    let unknown: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| !NAMED_PHASES.contains(name))
        .collect();
    if let Some(first) = unknown.first() {
        return Report::usage(
            command,
            format!(
                "Unknown generation phase {}. Pass one or more of: {}.",
                unknown.join(", "),
                NAMED_PHASES.join(", ")
            ),
            super::USAGE_INVALID_CHOICE,
            "phase",
            Some(first),
            &NAMED_PHASES,
        );
    }
    if names.is_empty() {
        return pipeline(cx, version);
    }
    let workspace = match workspace(command, cx) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let run = run_phases(names, &workspace, cx.cwd, version);
    if let Some((phase, detail)) = run.failed {
        return phase_failed(command, &phase, &detail, Vec::new(), run.steps);
    }
    generated(
        command,
        vec![("phases".to_owned(), strings_json(names))],
        run.steps,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_counts_its_steps() {
        let mut step = Step::new("exports");
        step.status = StepStatus::Ok;
        step.count = Some(3);
        step.seconds = 0.12345;
        let report = generated("generate exports", vec![], vec![step]);
        assert!(
            report
                .outcome
                .message
                .starts_with("Generated 3 files in 0.1s · exports")
        );
        assert_eq!(report.outcome.summary[0].1, Json::Int(3));
        assert_eq!(report.outcome.summary[3].1, Json::Float(0.123));
        let mut removed = Step::new("docs");
        removed.status = StepStatus::Ok;
        removed.count = Some(2);
        removed.unit = "file removed".into();
        let mut other = Step::new("x");
        other.status = StepStatus::Ok;
        other.count = Some(0);
        let report = generated("generate", vec![], vec![removed, other]);
        assert!(report.outcome.message.starts_with("Removed 2 files in "));
        assert!(report.outcome.message.ends_with(" · 2 phases"));
    }

    #[test]
    fn a_phase_that_only_removes_files_counts_them_as_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let folder = root.join("docs");
        std::fs::create_dir_all(&folder).unwrap();
        for name in ["a.md", "b.md"] {
            std::fs::write(folder.join(name), "x").unwrap();
        }
        let phase = run_phase("docs", std::slice::from_ref(&root), &root, &root, || {
            std::fs::remove_file(folder.join("a.md")).map_err(|error| error.to_string())?;
            std::fs::remove_file(folder.join("b.md")).map_err(|error| error.to_string())
        });
        assert_eq!(phase.error, None);
        assert_eq!(phase.step.status, StepStatus::Ok);
        assert_eq!(phase.step.count, Some(2));
        assert_eq!(phase.step.unit, "file removed");
        assert_eq!(phase.step.detail, "removed");
        assert_eq!(phase.step.place.as_deref(), Some("docs/"));
        let report = generated("generate", vec![], vec![phase.step]);
        assert!(report.outcome.message.starts_with("Removed 2 files in "));

        std::fs::write(folder.join("c.md"), "x").unwrap();
        let phase = run_phase("docs", std::slice::from_ref(&root), &root, &root, || {
            std::fs::write(folder.join("d.md"), "y").map_err(|error| error.to_string())?;
            std::fs::remove_file(folder.join("c.md")).map_err(|error| error.to_string())
        });
        assert_eq!(phase.step.count, Some(1));
        assert_eq!(phase.step.unit, "file");
    }

    #[test]
    fn the_explorer_refuses_a_marking_it_cannot_use() {
        let env = Env::from_pairs(std::iter::empty::<(String, String)>());
        let cwd = std::env::temp_dir();
        let cx = Context {
            repo: None,
            env: &env,
            cwd: &cwd,
            proxy: None,
            version: "0.0.0",
        };
        let alone = explorer(
            &ExplorerOptions {
                include_visibility: false,
                visibility_tlp: Some("red".into()),
            },
            &cx,
        );
        assert_eq!(alone.outcome.exit_code, 2);
        let failure = alone.outcome.failure.unwrap();
        assert_eq!(failure.code, "usage_missing_option");
        assert_eq!(failure.argument.as_deref(), Some("--visibility-tlp"));
        let unknown = explorer(
            &ExplorerOptions {
                include_visibility: true,
                visibility_tlp: Some("redd".into()),
            },
            &cx,
        );
        assert_eq!(unknown.outcome.exit_code, 2);
        assert_eq!(
            unknown.outcome.message,
            "Unknown TLP \"redd\". Pass one of: clear, green, amber, amber+strict, red."
        );
        let failure = unknown.outcome.failure.unwrap();
        assert_eq!(failure.code, "usage_invalid_choice");
        assert_eq!(failure.suggestion.as_deref(), Some("red"));
    }

    #[test]
    fn a_failed_phase_leads_its_message_with_the_phase() {
        let report = phase_failed(
            "generate exports objects",
            "exports",
            "KeyError: 'version' while rendering x",
            vec![("target".into(), Json::str("objects"))],
            vec![],
        );
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(
            report.outcome.message,
            "exports: KeyError: 'version' while rendering x"
        );
        assert_eq!(report.outcome.data[0].0, "phase");
        assert_eq!(report.outcome.data[1].0, "target");
    }

    /// A relative docs output is under the repository root, as the oracle's
    /// `get_repo_root() / output`, not under the Tide workspace that
    /// `OPENTIDE_TIDE_WORKSPACE` places elsewhere (#931).
    #[test]
    fn docs_output_is_under_the_repository_root_not_the_tide_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let outside = OsFs.resolve(dir.path());
        let repo = outside.join("repo");
        let tide = repo.join("detections");
        std::fs::create_dir_all(tide.join("objects")).unwrap();
        let env = Env::from_pairs([("OPENTIDE_TIDE_WORKSPACE", tide.to_string_lossy())]);
        let cx = Context {
            repo: None,
            env: &env,
            cwd: &repo,
            proxy: None,
            version: "0.0.0",
        };
        let report = docs(&DocsArgs::default(), &cx);
        assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome.message);
        assert!(repo.join("docs/README.md").is_file());
        assert!(!tide.join("docs").exists());
        // The step counts the pages it wrote there.
        let written = walk(&repo.join("docs"));
        assert!(written > 1);
        assert_eq!(report.steps[0].count, Some(written));
        let output = DocsArgs {
            output: Some("site".into()),
            ..DocsArgs::default()
        };
        let report = docs(&output, &cx);
        assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome.message);
        assert!(repo.join("site/README.md").is_file());
        assert!(!tide.join("site").exists());
        assert_eq!(report.steps[0].count, Some(walk(&repo.join("site"))));
        // A relative output that leaves both roots is still resolved against
        // the repository root, and the step counts the pages written there.
        let sibling = DocsArgs {
            output: Some("../site".into()),
            ..DocsArgs::default()
        };
        let report = docs(&sibling, &cx);
        assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome.message);
        assert!(outside.join("site/README.md").is_file());
        let written = walk(&outside.join("site"));
        assert!(written > 1);
        assert_eq!(report.steps[0].count, Some(written));
        // An absolute output is used as given.
        let absolute = outside.join("abs");
        let args = DocsArgs {
            output: Some(absolute.to_string_lossy().into_owned()),
            ..DocsArgs::default()
        };
        let report = docs(&args, &cx);
        assert_eq!(report.outcome.exit_code, 0, "{:?}", report.outcome.message);
        assert!(absolute.join("README.md").is_file());
        let written = walk(&absolute);
        assert!(written > 1);
        assert_eq!(report.steps[0].count, Some(written));
    }

    /// The files under `dir`, at any depth.
    fn walk(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                if path.is_dir() { walk(&path) } else { 1 }
            })
            .sum()
    }
}
