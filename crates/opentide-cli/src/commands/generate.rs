//! `opentide generate exports [navigator|objects|revisions]` and `generate
//! explorer` (`cli/commands/generate.py`, `cli/services/export.py`,
//! `cli/services/generation.py`) on `opentide-compile`'s `generate` module.
//!
//! A phase runs as a checklist step that counts the files it wrote, compared
//! by modification time and size before and after ([`Snapshot`]); the result
//! is `Generated 3 files in 0.1s · exports`, with the steps behind it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use opentide_compile::generate::exports::{Settings, Target, export};
use opentide_compile::generate::files::{Snapshot, common_dir, write_all};
use opentide_compile::generate::visibility::{self, DatasetRead, Inputs};
use opentide_compile::generate::{Output, PhaseError, explorer, inflight};
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
fn visibility_report(
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
    let workspace = match workspace(COMMAND, cx) {
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
                write(&[Output::text(
                    visibility_path,
                    opentide_compile::generate::json_text::line(&document),
                )])?;
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
            "Unknown TLP 'redd'. Pass one of: clear, green, amber, amber+strict, red."
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
}
