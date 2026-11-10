//! `opentide generate exports [navigator|objects|revisions]`
//! (`cli/commands/generate.py`, `cli/services/export.py`,
//! `cli/services/generation.py`) on `opentide-compile`'s `generate` module.
//!
//! A phase runs as a checklist step that counts the files it wrote, compared
//! by modification time and size before and after ([`Snapshot`]); the result
//! is `Generated 3 files in 0.1s · exports`, with the steps behind it.

use std::path::{Path, PathBuf};
use std::time::Instant;

use opentide_compile::generate::docs::catalog::{Catalog, Scope};
use opentide_compile::generate::docs::render::{Pages, Templates};
use opentide_compile::generate::docs::vocab::Vocab;
use opentide_compile::generate::docs::{
    Counts, FlavorHints, Settings as DocsSettings, changed, index_pages, inflight, pages,
    stale_pages,
};
use opentide_compile::generate::exports::{Settings, Target, export};
use opentide_compile::generate::files::{Snapshot, common_dir, remove_all, write_all};
use opentide_compile::generate::{Output, PhaseError};
use opentide_compile::strategy::Statuses;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::Workspace;

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
fn phase_failed(
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
    let workspace = match workspace(&command, cx) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let root = workspace.root().to_path_buf();
    let settings = Settings::new(workspace.configuration(), &root);
    let vocabularies = Vocabularies::bundled();
    let targets: Vec<Target> = target.map_or_else(|| Target::ALL.to_vec(), |one| vec![one]);
    let name = target.map_or_else(
        || "exports".to_owned(),
        |one| format!("exports {}", one.name()),
    );
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
    let target_key =
        |target: Option<Target>| target.map(|one| ("target".to_owned(), Json::str(one.name())));
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
fn nested_warning(workspace: &Workspace) -> Option<String> {
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
    let workspace = match workspace(&command, cx) {
        Ok(workspace) => workspace,
        Err(report) => return *report,
    };
    let root = workspace.root().to_path_buf();
    let mut roots = vec![root.clone()];
    if let Some(output) = args.output.as_deref().filter(|output| !output.is_empty()) {
        let path = PathBuf::from(output);
        roots.push(if path.is_absolute() {
            path
        } else {
            root.join(path)
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
    let settings = DocsSettings::resolve(
        resolved,
        root,
        args.output.as_deref(),
        args.flavor.as_deref(),
        &hints,
    )
    .map_err(|error| error.detail)?;
    // Documentation previews open pull requests: their inflight shards are
    // overlaid on the index for the run (`inflight_preview`).
    let overlaid = inflight::overlay(workspace.index(), &root.join(".opentide/inflight"));
    let index = overlaid
        .as_ref()
        .unwrap_or_else(|| workspace.index().as_ref());
    let catalog =
        Catalog::build(index, Statuses::from_resolved(resolved)).map_err(|error| error.detail)?;
    let vocabularies = Vocabularies::bundled();
    let templates = Templates::new();
    let pages_of = Pages {
        catalog: &catalog,
        settings: &settings,
        vocab: Vocab::new(&vocabularies),
        templates: &templates,
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
}
