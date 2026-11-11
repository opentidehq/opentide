//! `opentide migrate vocab-scope` (`cli/commands/migrate.py`,
//! `cli/services/migrate_vocab_scope.py`; UC-3.5c, #928): re-prefix the
//! values of stage-scoped vocabulary fields across `objects/`.
//!
//! The decisions and the span edits are `opentide_schema::migration::vocab_scope`;
//! this module reads the files, writes the ones it may, and reports. Every
//! value is resolved before any file is written, so an ambiguity anywhere is
//! reported first; a value defined under several stages is never guessed and
//! exits 2 (`needs_human_decision`) unless `--force`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_schema::migration::vocab_scope::{
    Outcome, Plan, SCOPED_FIELDS, ScopeIndex, ScopedField, rewrite, scalars, verify,
};
use opentide_schema::node;
use opentide_schema::vocab::bundled;

use super::{ISSUES_FOUND, Report, placement};
use crate::env::Env;
use crate::envelope::Failure;
use crate::json::Json;
use crate::render::outcome::OutcomeKind;

const COMMAND: &str = "migrate vocab-scope";

/// `failure.code` of a run that left values for a person to decide.
pub const NEEDS_HUMAN_DECISION: &str = "needs_human_decision";

/// The parsed options.
#[derive(Debug, Clone, Default)]
pub struct Args {
    /// `--apply`: write the files (default: report only).
    pub apply: bool,
    /// `--field`, repeatable: the scoped fields to migrate (default: all).
    pub fields: Vec<String>,
    /// `--force`: exit 0 even when values need a person.
    pub force: bool,
}

/// What one scoped field needed across the corpus.
#[derive(Debug, Default)]
struct FieldReport {
    /// The values seen, by status, in the order statuses were first seen.
    by_status: IndexMap<&'static str, usize>,
    /// Authored value -> scoped value, in the order first seen.
    rewrites: IndexMap<String, String>,
    /// Values left for a person, by value.
    blocked: BTreeMap<String, Outcome>,
}

/// Runs the command in the workspace `repo`, `env` and `cwd` place.
pub fn run(args: &Args, repo: Option<&str>, env: &Env, cwd: &Path) -> Report {
    let mut fields: Vec<&ScopedField> = SCOPED_FIELDS.iter().collect();
    if !args.fields.is_empty() {
        let mut unknown: Vec<&str> = args
            .fields
            .iter()
            .map(String::as_str)
            .filter(|name| !SCOPED_FIELDS.iter().any(|field| field.name == *name))
            .collect();
        unknown.sort_unstable();
        unknown.dedup();
        if !unknown.is_empty() {
            let known: Vec<&str> = SCOPED_FIELDS.iter().map(|field| field.name).collect();
            return Report::error(
                COMMAND,
                format!(
                    "Unknown scoped field(s) {}. Known scoped fields: {}.",
                    unknown.join(", "),
                    known.join(", ")
                ),
            );
        }
        // In the order given, once each, as the oracle's dict keeps them.
        fields = Vec::new();
        for name in &args.fields {
            if let Some(field) = SCOPED_FIELDS.iter().find(|field| field.name == name)
                && !fields.contains(&field)
            {
                fields.push(field);
            }
        }
    }
    let (shown, _) = placement(repo, env, cwd);
    let root = cwd.join(&shown);
    match migrate(&root, &fields, args.apply) {
        Ok(migration) => report(&migration, args),
        Err(message) => Report::error(COMMAND, message),
    }
}

/// A whole run's outcome.
#[derive(Debug, Default)]
struct Migration {
    applied: bool,
    scanned: usize,
    fields: BTreeMap<&'static str, (&'static str, FieldReport)>,
    changed_files: Vec<String>,
    /// Relative path -> why it was left alone, in the order found.
    failed_files: IndexMap<String, String>,
}

fn migrate(root: &Path, fields: &[&ScopedField], apply: bool) -> Result<Migration, String> {
    let mut indexes: Vec<(&ScopedField, ScopeIndex)> = Vec::new();
    for field in fields {
        let vocabulary = bundled::get(field.vocab)
            .ok_or_else(|| format!("vocabulary '{}' is not loaded", field.vocab))?;
        let index = ScopeIndex::new(&vocabulary);
        if !index.is_staged() {
            return Err(format!(
                "vocabulary '{}' declares no stages, so it cannot be scoped",
                field.vocab
            ));
        }
        indexes.push((field, index));
    }
    let mut migration = Migration {
        applied: apply,
        ..Migration::default()
    };
    for field in fields {
        migration
            .fields
            .insert(field.name, (field.vocab, FieldReport::default()));
    }

    let mut paths = Vec::new();
    collect_yaml(&root.join("objects"), &mut paths);
    paths.sort_by(|a, b| a.components().cmp(b.components()));

    // Pass 1: resolve every value, so an ambiguity anywhere is reported
    // before a file is written.
    let mut documents: Vec<(PathBuf, String, Option<char>, node::Document)> = Vec::new();
    for path in paths {
        let relative = relative(&path, root);
        let bytes = std::fs::read(&path);
        let bom = bytes
            .as_ref()
            .is_ok_and(|bytes| bytes.starts_with("\u{feff}".as_bytes()))
            .then_some('\u{feff}');
        let document = bytes.map_err(|error| error.to_string()).and_then(|bytes| {
            node::load_bytes(&bytes).map_err(|error| match error.mark {
                Some(mark) => format!(
                    "{} (line {}, column {})",
                    error.problem, mark.line, mark.column
                ),
                None => error.problem,
            })
        });
        let document = match document {
            Ok(document) => document,
            Err(reason) => {
                migration
                    .failed_files
                    .insert(relative, format!("unreadable: {reason}"));
                continue;
            }
        };
        migration.scanned += 1;
        for (field, index) in &indexes {
            let mut seen: IndexMap<String, usize> = IndexMap::new();
            for scalar in scalars(&document, field.path) {
                *seen.entry(scalar.value).or_insert(0) += 1;
            }
            let Some((_, report)) = migration.fields.get_mut(field.name) else {
                continue;
            };
            for (value, count) in seen {
                let outcome = index.resolve(&value);
                *report.by_status.entry(outcome.status.as_str()).or_insert(0) += count;
                if outcome.changed()
                    && let Some(resolved) = &outcome.resolved
                {
                    report.rewrites.insert(value, resolved.clone());
                } else if !outcome.is_resolved() {
                    report.blocked.insert(value, outcome);
                }
            }
        }
        documents.push((path, relative, bom, document));
    }

    let rewrites: Vec<(&ScopedField, BTreeMap<String, String>)> = indexes
        .iter()
        .filter_map(|(field, _)| {
            let (_, report) = migration.fields.get(field.name)?;
            (!report.rewrites.is_empty()).then(|| {
                (
                    *field,
                    report
                        .rewrites
                        .iter()
                        .map(|(from, to)| (from.clone(), to.clone()))
                        .collect(),
                )
            })
        })
        .collect();
    if rewrites.is_empty() {
        return Ok(migration);
    }
    let plan: Plan<'_> = rewrites
        .iter()
        .map(|(field, mapping)| (field.path, mapping))
        .collect();

    // Pass 2: rewrite and read back; a file whose values do not land on the
    // plan is left as it is and reported.
    for (path, relative, bom, document) in &documents {
        let (updated, changes) = rewrite(document, &plan);
        if changes == 0 {
            continue;
        }
        if let Some(problem) = verify(document, &updated, &plan) {
            migration.failed_files.insert(relative.clone(), problem);
            continue;
        }
        migration.changed_files.push(relative.clone());
        if apply {
            let mut text = String::new();
            text.extend(bom);
            text.push_str(&updated);
            std::fs::write(path, text.as_bytes())
                .map_err(|error| format!("{}: {error}", path.display()))?;
        }
    }
    if !migration.changed_files.is_empty() {
        let blocked: usize = migration
            .fields
            .values()
            .map(|(_, report)| report.blocked.len())
            .sum();
        tracing::info!(
            applied = apply,
            files = migration.changed_files.len(),
            blocked,
            "vocab_scope_migration"
        );
    }
    Ok(migration)
}

/// Every `*.yaml` file under `dir`, at any depth.
fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect_yaml(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "yaml") && path.is_file() {
            out.push(path);
        }
    }
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

fn int(count: usize) -> Json {
    Json::Int(i64::try_from(count).unwrap_or(i64::MAX))
}

fn report(migration: &Migration, args: &Args) -> Report {
    let mut changed = migration.changed_files.clone();
    changed.sort();
    let fields = Json::Object(
        migration
            .fields
            .iter()
            .map(|(name, (vocab, report))| {
                let values: usize = report.by_status.values().sum();
                (
                    (*name).to_owned(),
                    Json::object([
                        ("vocab", Json::str(*vocab)),
                        ("values", int(values)),
                        (
                            "by_status",
                            Json::Object(
                                report
                                    .by_status
                                    .iter()
                                    .map(|(status, count)| ((*status).to_owned(), int(*count)))
                                    .collect(),
                            ),
                        ),
                        (
                            "rewrites",
                            Json::Object(
                                report
                                    .rewrites
                                    .iter()
                                    .map(|(from, to)| (from.clone(), Json::str(to)))
                                    .collect(),
                            ),
                        ),
                        (
                            "blocked",
                            Json::Object(
                                report
                                    .blocked
                                    .iter()
                                    .map(|(value, outcome)| {
                                        (value.clone(), Json::Str(outcome.detail()))
                                    })
                                    .collect(),
                            ),
                        ),
                    ]),
                )
            })
            .collect(),
    );
    let data = vec![
        ("applied".to_owned(), Json::Bool(migration.applied)),
        ("scanned".to_owned(), int(migration.scanned)),
        (
            "changed_files".to_owned(),
            Json::Array(changed.iter().map(Json::str).collect()),
        ),
        (
            "failed_files".to_owned(),
            Json::Object(
                migration
                    .failed_files
                    .iter()
                    .map(|(path, reason)| (path.clone(), Json::str(reason)))
                    .collect(),
            ),
        ),
        ("fields".to_owned(), fields),
    ];
    let mut report = Report::completed(COMMAND, data);
    let mut warnings: Vec<String> = Vec::new();
    let mut blocked = 0usize;
    for (name, (_, field)) in &migration.fields {
        blocked += field.blocked.len();
        warnings.extend(
            field
                .blocked
                .values()
                .map(|outcome| format!("{name}: {}", outcome.detail())),
        );
    }
    warnings.extend(
        migration
            .failed_files
            .iter()
            .map(|(path, reason)| format!("{path}: {reason}")),
    );
    report.warnings = warnings;
    let verb = if args.apply {
        "Rewrote"
    } else {
        "Would rewrite"
    };
    let files = super::counted(changed.len(), "file");
    report.outcome.message = format!("{verb} {files} · {} scanned", migration.scanned);
    report.outcome.summary = vec![
        ("files".to_owned(), int(changed.len())),
        ("scanned".to_owned(), int(migration.scanned)),
    ];
    if !migration.failed_files.is_empty() {
        let message = format!(
            "{} file(s) could not be migrated safely and were left unchanged.",
            migration.failed_files.len()
        );
        issues(&mut report, message, 1, ISSUES_FOUND);
    } else if blocked > 0 && !args.force {
        let message = format!(
            "{verb} {files}; {blocked} value(s) are defined under several stages and cannot be \
             inferred. Choose a stage for each by hand, then re-run. Pass --force to treat this \
             as success."
        );
        issues(&mut report, message, 2, NEEDS_HUMAN_DECISION);
    } else if !args.apply {
        // A dry run wrote nothing: its line takes no glyph.
        report.outcome_kind = Some(OutcomeKind::Plan);
    }
    report
}

/// The run found what it could not do: `issues`, with its exit code and
/// failure, and the document still `ok`.
fn issues(report: &mut Report, message: String, exit_code: i32, code: &str) {
    "issues".clone_into(&mut report.outcome.status);
    report.outcome.message.clone_from(&message);
    report.outcome.exit_code = exit_code;
    report.outcome.failure = Some(Failure::new(code, message));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    fn run_in(dir: &Path, args: &Args) -> Report {
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        run(args, Some("."), &env, dir)
    }

    fn data<'r>(report: &'r Report, key: &str) -> &'r Json {
        &report
            .outcome
            .data
            .iter()
            .find(|(name, _)| name == key)
            .unwrap()
            .1
    }

    const OBJECTIVE: &str = "\
name: o
objective:
  signals:
    - entities:
        - Process  # implied: Host
        - host::Hostname
";

    #[test]
    fn a_dry_run_reports_and_writes_nothing() {
        let dir = workspace(&[("objects/objectives/o.yaml", OBJECTIVE)]);
        let report = run_in(dir.path(), &Args::default());
        assert_eq!(report.outcome.exit_code, 0);
        assert_eq!(report.outcome.message, "Would rewrite 1 file · 1 scanned");
        assert_eq!(report.outcome_kind, Some(OutcomeKind::Plan));
        assert_eq!(
            data(&report, "changed_files"),
            &Json::Array(vec![Json::str("objects/objectives/o.yaml")])
        );
        let written =
            std::fs::read_to_string(dir.path().join("objects/objectives/o.yaml")).unwrap();
        assert_eq!(written, OBJECTIVE);
    }

    #[test]
    fn apply_rewrites_the_values_in_place() {
        let dir = workspace(&[("objects/objectives/o.yaml", OBJECTIVE)]);
        let args = Args {
            apply: true,
            ..Args::default()
        };
        let report = run_in(dir.path(), &args);
        assert_eq!(report.outcome.exit_code, 0);
        assert_eq!(report.outcome.message, "Rewrote 1 file · 1 scanned");
        let written =
            std::fs::read_to_string(dir.path().join("objects/objectives/o.yaml")).unwrap();
        assert_eq!(
            written,
            OBJECTIVE
                .replace("- Process", "- Host::Process")
                .replace("host::Hostname", "Host::Hostname")
        );
    }

    #[test]
    fn an_ambiguous_value_exits_2_unless_forced() {
        let text = "objective:\n  signals:\n    - entities: [Account, Process]\n";
        let dir = workspace(&[("objects/o.yaml", text)]);
        let args = Args {
            apply: true,
            ..Args::default()
        };
        let report = run_in(dir.path(), &args);
        assert_eq!(report.outcome.exit_code, 2);
        assert_eq!(report.outcome.status, "issues");
        assert!(report.outcome.ok());
        assert_eq!(
            report.outcome.failure.as_ref().unwrap().code,
            NEEDS_HUMAN_DECISION
        );
        assert!(
            report.warnings[0].starts_with("entities: 'Account' is defined under several stages")
        );
        // The mechanical value is still applied.
        let written = std::fs::read_to_string(dir.path().join("objects/o.yaml")).unwrap();
        assert_eq!(written, text.replace(", Process]", ", Host::Process]"));
        let forced = run_in(
            dir.path(),
            &Args {
                force: true,
                ..Args::default()
            },
        );
        assert_eq!(forced.outcome.exit_code, 0);
        assert!(forced.outcome.failure.is_none());
    }

    #[test]
    fn an_unreadable_file_exits_1_and_is_left_alone() {
        let dir = workspace(&[
            ("objects/a.yaml", "threat: [unclosed\n"),
            ("objects/b.yaml", "threat:\n  surface: [Windows]\n"),
        ]);
        let report = run_in(dir.path(), &Args::default());
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(report.outcome.failure.as_ref().unwrap().code, ISSUES_FOUND);
        assert_eq!(
            report.outcome.message,
            "1 file(s) could not be migrated safely and were left unchanged."
        );
        let Json::Object(failed) = data(&report, "failed_files") else {
            panic!("failed_files is an object");
        };
        assert_eq!(failed[0].0, "objects/a.yaml");
        assert_eq!(data(&report, "scanned"), &Json::Int(1));
    }

    #[test]
    fn a_rewrite_that_fails_verification_is_never_written() {
        // The anchored scalar's span takes in `&p `: the rewrite drops the
        // anchor, `*p` no longer resolves, and the read-back refuses it.
        let text = "x: &p Process\nobjective:\n  signals:\n    - entities: [*p]\n";
        let dir = workspace(&[("objects/o.yaml", text)]);
        let report = run_in(
            dir.path(),
            &Args {
                apply: true,
                ..Args::default()
            },
        );
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(report.outcome.status, "issues");
        assert_eq!(report.outcome.failure.as_ref().unwrap().code, ISSUES_FOUND);
        let Json::Object(failed) = data(&report, "failed_files") else {
            panic!("failed_files is an object");
        };
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].0, "objects/o.yaml");
        let Json::Str(reason) = &failed[0].1 else {
            panic!("a reason is a string");
        };
        assert!(
            reason.starts_with("rewrite produced unparseable YAML"),
            "{reason}"
        );
        assert_eq!(data(&report, "changed_files"), &Json::Array(Vec::new()));
        let on_disk = std::fs::read(dir.path().join("objects/o.yaml")).unwrap();
        assert_eq!(on_disk, text.as_bytes());
    }

    #[test]
    fn an_already_scoped_corpus_is_clean() {
        let dir = workspace(&[
            (
                "objects/o.yaml",
                "objective:\n  signals:\n    - entities: [Host::Process, Cloud::Account]\n    - entities: [Host::Process]\n",
            ),
            ("objects/t.yaml", "threat:\n  surface: [OS::Windows]\n"),
        ]);
        let report = run_in(dir.path(), &Args::default());
        assert_eq!(report.outcome.exit_code, 0);
        assert!(report.outcome.failure.is_none());
        assert_eq!(data(&report, "changed_files"), &Json::Array(Vec::new()));
        let Json::Object(fields) = data(&report, "fields") else {
            panic!("fields is an object");
        };
        let field = |name: &str| {
            let Json::Object(field) = &fields.iter().find(|(key, _)| key == name).unwrap().1 else {
                panic!("a field is an object");
            };
            field.clone()
        };
        let member = |field: &[(String, Json)], key: &str| {
            field
                .iter()
                .find(|(name, _)| name == key)
                .unwrap()
                .1
                .clone()
        };
        let entities = field("entities");
        assert_eq!(member(&entities, "blocked"), Json::Object(Vec::new()));
        assert_eq!(member(&entities, "rewrites"), Json::Object(Vec::new()));
        assert_eq!(
            member(&entities, "by_status"),
            Json::Object(vec![("scoped".to_owned(), Json::Int(3))])
        );
        let surface = field("surface");
        assert_eq!(member(&surface, "blocked"), Json::Object(Vec::new()));
        assert_eq!(
            member(&surface, "by_status"),
            Json::Object(vec![("scoped".to_owned(), Json::Int(1))])
        );
    }

    #[test]
    fn a_repeated_key_is_left_alone_and_exits_1() {
        // Intended difference (CHANGELOG): read as YAML 1.2 a repeated key
        // makes the file unreadable, where the oracle's `yaml.compose`
        // accepted it and rewrote the file.
        let text = "objective:\n  signals:\n    - entities: [Process]\nobjective: {}\n";
        let dir = workspace(&[("objects/o.yaml", text)]);
        let report = run_in(
            dir.path(),
            &Args {
                apply: true,
                ..Args::default()
            },
        );
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(report.outcome.failure.as_ref().unwrap().code, ISSUES_FOUND);
        let Json::Object(failed) = data(&report, "failed_files") else {
            panic!("failed_files is an object");
        };
        assert_eq!(failed[0].0, "objects/o.yaml");
        let Json::Str(reason) = &failed[0].1 else {
            panic!("a reason is a string");
        };
        assert!(
            reason.starts_with("unreadable: the key 'objective' is repeated"),
            "{reason}"
        );
        assert_eq!(data(&report, "scanned"), &Json::Int(0));
        let on_disk = std::fs::read(dir.path().join("objects/o.yaml")).unwrap();
        assert_eq!(on_disk, text.as_bytes());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let dir = workspace(&[]);
        let args = Args {
            fields: vec!["nope".into(), "surface".into()],
            ..Args::default()
        };
        let report = run_in(dir.path(), &args);
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(
            report.outcome.message,
            "Unknown scoped field(s) nope. Known scoped fields: entities, surface."
        );
        let only = run_in(
            dir.path(),
            &Args {
                fields: vec!["surface".into()],
                ..Args::default()
            },
        );
        let Json::Object(fields) = data(&only, "fields") else {
            panic!("fields is an object");
        };
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "surface");
    }

    #[test]
    fn a_byte_order_mark_and_crlf_survive_apply() {
        let text = "\u{feff}threat:\r\n  surface:\r\n    - Windows\r\n";
        let dir = workspace(&[("objects/t.yaml", text)]);
        let report = run_in(
            dir.path(),
            &Args {
                apply: true,
                ..Args::default()
            },
        );
        assert_eq!(report.outcome.exit_code, 0);
        let written = std::fs::read_to_string(dir.path().join("objects/t.yaml")).unwrap();
        assert_eq!(written, text.replace("- Windows", "- OS::Windows"));
    }
}
