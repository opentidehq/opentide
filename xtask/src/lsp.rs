//! `cargo xtask lsp parity --corpus faults`: the language server's published
//! diagnostics against `validate`'s findings (UC-2.6, #821).
//!
//! For each fault kind of `tests/corpora/faults.toml` that `opentide
//! validate` reports (its command is `validate` alone), the kind is applied
//! to a copy of the clean workspace, written to a scratch folder and:
//!
//! - validated by `opentide-workspace` (`validate --file` on the files the
//!   editor opens, the queries check off: the editor runs its own query
//!   analysis); a configuration that does not resolve stops `validate`, and
//!   the editor then checks no object either;
//! - served by `opentide-lsp` in this process ([`opentide_lsp::MessageSession`]),
//!   with the folder as its root, every object file that has a finding (and
//!   every target) opened.
//!
//! What the editor shows is `validate`'s findings, and lint's file name and
//! metadata findings on the same files (`lint::lint_file`, run here file by
//! file: KG-03 and KG-05, #926). Per file, the multiset of `(code,
//! severity, range)` must be equal: the range is the 1-based line and
//! code-point columns (end exclusive) converted here to LSP's 0-based lines
//! and UTF-16 columns. What the editor adds of its own is the query
//! analysis of `opentide-analysis` (which `validate`'s queries check covers
//! in UC-2.5): the engine's standalone analysis of the same text, taken out
//! first. The platform blocks are not taken out of either side (UC-2.6,
//! #821): the editor has no check of its own on them, so a server that
//! published them fails the run, as does any other difference.

use crate::corpus::cli::{Scratch, corpora_dir, load_catalogue, write_workspace};
use crate::corpus::faults::{self, Kind};
use crate::corpus::generate;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// The usage of `cargo xtask lsp`.
pub const USAGE: &str = "\
usage: cargo xtask lsp parity --corpus faults [--only ID,...] [--keep DIR]

  For each fault kind `opentide validate` reports, the language server's
  published diagnostics must equal validate's findings, with lint's file
  name and metadata findings, file by file: codes, severities and ranges
  (code points converted to UTF-16).
";

/// One finding as both sides are compared: code, severity, and the range
/// `(line, character)` to `(line, character)` in LSP's coordinates.
type Key = (String, String, (u32, u32), (u32, u32));

/// Runs `lsp <args>`; the process exit status.
pub fn run(args: &[String]) -> Result<u8> {
    let Some((command, rest)) = args.split_first() else {
        bail!("missing command\n\n{USAGE}");
    };
    if command != "parity" {
        if matches!(command.as_str(), "help" | "--help" | "-h") {
            print!("{USAGE}");
            return Ok(0);
        }
        bail!("unknown command `{command}`\n\n{USAGE}");
    }
    let mut corpus = None;
    let mut only: Option<BTreeSet<String>> = None;
    let mut keep = None;
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .with_context(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--corpus" => corpus = Some(value()?),
            "--only" => {
                only = Some(value()?.split(',').map(str::to_owned).collect());
            }
            "--keep" => keep = Some(PathBuf::from(value()?)),
            other => bail!("unknown option `{other}`\n\n{USAGE}"),
        }
    }
    if corpus.as_deref() != Some("faults") {
        bail!("--corpus faults is the one corpus\n\n{USAGE}");
    }
    parity(only.as_ref(), keep)
}

/// Whether `kind` is what `opentide validate` alone reports.
fn compared(kind: &Kind) -> Result<(), String> {
    if kind.command != ["validate"] {
        return Err(format!("its command is `{}`", kind.command.join(" ")));
    }
    if !kind.env.is_empty() {
        return Err("it runs with its own environment".to_owned());
    }
    Ok(())
}

fn parity(only: Option<&BTreeSet<String>>, keep: Option<PathBuf>) -> Result<u8> {
    let catalogue = load_catalogue(&corpora_dir().join("faults.toml"))?;
    if let Some(only) = only {
        for id in only {
            if catalogue.kind(id).is_none() {
                bail!("--only: no fault kind `{id}`");
            }
        }
    }
    let base = generate::generate(&catalogue.base.options()?);
    let scratch = match &keep {
        Some(dir) => dir.clone(),
        None => std::env::temp_dir().join(format!("opentide-lsp-parity-{}", std::process::id())),
    };
    let scratch = std::path::absolute(&scratch)
        .with_context(|| format!("cannot resolve {}", scratch.display()))?;
    if scratch.exists() {
        bail!(
            "{} exists; remove it or name another --keep",
            scratch.display()
        );
    }
    let _guard = Scratch {
        path: scratch.clone(),
        keep: keep.is_some(),
    };
    let started = Instant::now();
    let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
    let mut findings = 0usize;
    let mut selected = Vec::new();
    for kind in &catalogue.kinds {
        if only.is_some_and(|only| !only.contains(&kind.id)) {
            continue;
        }
        if let Err(why) = compared(kind) {
            skipped += 1;
            if only.is_some() {
                println!("skip {:<48} {why}", kind.id);
            }
            continue;
        }
        selected.push(kind);
    }
    // Each kind is its own workspace and its own in-process server: they run
    // on every core, and are reported in the catalogue's order (#841).
    let outcomes = crate::parallel::in_order(&selected, |kind| -> Result<(usize, Vec<String>)> {
        let mut workspace = base.clone();
        let targets = faults::select(&workspace, kind, &BTreeSet::new())?;
        let target_paths = faults::apply(&mut workspace, kind, &targets)?;
        let dir = scratch.join(&kind.id);
        write_workspace(&workspace, &dir)?;
        let dir = dunce::canonicalize(&dir)
            .with_context(|| format!("cannot resolve {}", dir.display()))?;
        compare_kind(&dir, &target_paths)
    });
    for (kind, outcome) in selected.iter().zip(outcomes) {
        let (count, problems) = outcome?;
        findings += count;
        if problems.is_empty() {
            passed += 1;
            println!("ok   {:<48} {count} finding(s)", kind.id);
        } else {
            failed += 1;
            println!("FAIL {:<48} {count} finding(s)", kind.id);
            for problem in &problems {
                println!("       - {problem}");
            }
        }
    }
    println!(
        "lsp parity --corpus faults: {passed} kinds equal, {failed} differ, {skipped} not \
         compared (not `validate` alone), {findings} findings, in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    Ok(u8::from(failed > 0))
}

/// `validate`'s findings on the workspace at `dir`, by file (absolute):
/// every object, or the `files` (`--file`) when some are named, as the
/// editor runs it on its open documents. `None` when the configuration does
/// not resolve (`validate` stops; the editor checks no object).
type ByFile = BTreeMap<PathBuf, Vec<opentide_workspace::Diagnostic>>;

fn validate(dir: &Path, files: &[PathBuf]) -> Option<ByFile> {
    use opentide_workspace::validate::{Options, QueriesMode, Selection};
    use opentide_workspace::{OsFs, RootOptions, Workspace};
    let workspace = Workspace::open(
        Arc::new(OsFs),
        opentide_workspace::Options {
            roots: RootOptions {
                repo: Some(dir.to_path_buf()),
                cwd: dir.to_path_buf(),
                ..RootOptions::default()
            },
        },
    )
    .ok()?;
    let selection = Selection {
        files: files.iter().map(|f| f.display().to_string()).collect(),
        ..Selection::default()
    };
    let run = workspace.validate(&Options {
        selection: (!files.is_empty()).then_some(&selection),
        queries: QueriesMode::Off,
        ..Options::default()
    });
    let mut by_file: ByFile = BTreeMap::new();
    for finding in run.report.issues.into_iter().chain(run.report.warnings) {
        if let Some(file) = finding.file_path.clone() {
            by_file.entry(file).or_default().push(finding);
        }
    }
    // Lint's file name and metadata findings on each file the editor opens,
    // with the workspace's `lint.toml`: one `lint_file` per file.
    if let Ok(config) = opentide_schema::configuration::lint::parse_lint_config(
        workspace.configuration().resolved.get("lint"),
    ) {
        for file in files {
            let found = opentide_workspace::lint::lint_file(
                workspace.fs().as_ref(),
                workspace.root(),
                &config,
                file,
            );
            for finding in found {
                let file = finding.diagnostic.file_path.clone().unwrap_or(file.clone());
                by_file.entry(file).or_default().push(finding.diagnostic);
            }
        }
    }
    Some(by_file)
}

/// The UTF-16 offset of the code-point column `column` (from 1) of `line`,
/// the line's end when it is past it: the line's prefix of that many code
/// points, encoded as UTF-16 by the standard library and counted.
fn utf16(line: &str, column: usize) -> u32 {
    let prefix = line
        .char_indices()
        .nth(column.saturating_sub(1))
        .map_or(line, |(at, _)| &line[..at]);
    u32::try_from(prefix.encode_utf16().count()).unwrap_or(u32::MAX)
}

/// A `validate` finding in LSP's coordinates, computed here, apart from the
/// server's own conversion (`opentide-lsp`'s `checks::finding_range`). The
/// placement of a finding that lacks a line or an end is the contract
/// `docs/engine/EDITORS.md` states ("Tide diagnostics"), which both follow: a
/// finding without a line is at the start of the file; one with a column
/// and no end column on its own line is a point; otherwise a missing end
/// column is the end line's end.
fn expected(text: &str, finding: &opentide_workspace::Diagnostic) -> Key {
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect();
    let at = |line: usize| lines.get(line.saturating_sub(1)).copied().unwrap_or("");
    let severity = match finding.severity {
        opentide_workspace::Severity::Error => "error",
        opentide_workspace::Severity::Warning => "warning",
        _ => "information",
    };
    let range = match finding.line.filter(|line| *line > 0) {
        None => ((0, 0), (0, 0)),
        Some(line) => {
            let end_line = finding.end_line.unwrap_or(line).max(line);
            let start = utf16(at(line), finding.column.unwrap_or(1));
            let end = match (finding.column, finding.end_column) {
                (_, Some(end)) => utf16(at(end_line), end),
                (Some(_), None) if end_line == line => start,
                _ => utf16(at(end_line), usize::MAX),
            };
            let l = |n: usize| u32::try_from(n - 1).unwrap_or(u32::MAX);
            ((l(line), start), (l(end_line), end))
        }
    };
    (finding.code.clone(), severity.to_owned(), range.0, range.1)
}

fn key_of(diagnostic: &Value) -> Key {
    let position = |p: &Value| {
        (
            u32::try_from(p["line"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX),
            u32::try_from(p["character"].as_u64().unwrap_or(0)).unwrap_or(u32::MAX),
        )
    };
    let severity = match diagnostic["severity"].as_u64() {
        Some(1) => "error",
        Some(2) => "warning",
        Some(3) => "information",
        _ => "hint",
    };
    (
        diagnostic["code"].as_str().unwrap_or("").to_owned(),
        severity.to_owned(),
        position(&diagnostic["range"]["start"]),
        position(&diagnostic["range"]["end"]),
    )
}

/// The queries of `text`, analysed by the engine on their own, which the
/// server adds to `validate`'s findings (`validate`'s own queries check
/// covers them in UC-2.5). The object's platform blocks are not among them:
/// the editor has no check of its own on those (UC-2.6, #821), and
/// [`block_own`] holds the server to it.
fn engine_own(path: &Path, text: &str) -> Vec<Key> {
    let host = opentide_analysis::MemoryWorkspace {
        files: vec![(path.display().to_string(), text.to_owned())],
    };
    let response = opentide_analysis::analyze(
        &host,
        opentide_analysis::AnalyzeRequest {
            uri: path.display().to_string(),
            language: opentide_analysis::LanguageId::TideYaml,
            text: text.to_owned(),
        },
    );
    response
        .diagnostics
        .iter()
        .map(|d| key_of(&serde_json::to_value(lsp_shape(d)).unwrap_or(Value::Null)))
        .collect()
}

fn lsp_shape(d: &opentide_core::Diagnostic) -> Value {
    let severity = match d.severity {
        opentide_core::Severity::Error => 1,
        opentide_core::Severity::Warning => 2,
        opentide_core::Severity::Information => 3,
        opentide_core::Severity::Hint => 4,
    };
    json!({
        "code": d.code,
        "severity": severity,
        "range": {
            "start": { "line": d.range.start.line, "character": d.range.start.character },
            "end": { "line": d.range.end.line, "character": d.range.end.character },
        },
    })
}

/// What the engine reports on the platform blocks of `text`
/// (`opentide lint`'s advisories and the Sysdig block's own): nothing the
/// server may publish, since `validate` reports a block's constraints as the
/// object's schema check and the editor would then show one fault twice
/// (UC-2.6, #821). It is subtracted from neither side.
fn block_own(path: &Path, text: &str) -> Vec<Key> {
    let host = opentide_analysis::MemoryWorkspace {
        files: vec![(path.display().to_string(), text.to_owned())],
    };
    opentide_analysis::analyze_blocks(&host, text)
        .iter()
        .map(|d| key_of(&serde_json::to_value(lsp_shape(d)).unwrap_or(Value::Null)))
        .collect()
}

/// Which of [`block_own`]'s findings the server published for the file
/// (`published`): none, for a server that publishes `validate`'s findings.
fn published_blocks(path: &Path, text: &str, published: &[Key]) -> Vec<Key> {
    block_own(path, text)
        .into_iter()
        .filter(|key| published.contains(key))
        .collect()
}

/// One kind's workspace: how many findings were compared, and every
/// difference.
fn compare_kind(dir: &Path, targets: &[String]) -> Result<(usize, Vec<String>)> {
    // The files a full run reports on, and the targets, are opened; what
    // the editor shows for them is `validate --file` on those files.
    let full = validate(dir, &[]).unwrap_or_default();
    let mut files: BTreeSet<PathBuf> = full
        .keys()
        .filter(|file| {
            matches!(
                file.extension().and_then(|e| e.to_str()),
                Some("yaml" | "yml")
            )
        })
        .cloned()
        .collect();
    files.extend(
        targets
            .iter()
            .map(|target| dir.join(target))
            .filter(|file| file.is_file() && file.starts_with(dir.join("objects"))),
    );
    let opened: Vec<PathBuf> = files.iter().cloned().collect();
    let by_file = validate(dir, &opened).unwrap_or_default();
    let mut session = opentide_lsp::MessageSession::new();
    let uri = |path: &Path| opentide_lsp::uri::path_to_uri(&path.display().to_string());
    let mut send = |message: Value| -> Vec<Value> {
        session
            .handle(&message.to_string())
            .iter()
            .filter_map(|text| serde_json::from_str(text).ok())
            .collect()
    };
    // A client that pulls: opening every file publishes nothing, and each
    // file's diagnostics are then asked for in one state of the workspace
    // (one `validate` run serves them all).
    send(json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "processId": null, "rootUri": uri(dir), "capabilities": {
            "textDocument": { "diagnostic": { "dynamicRegistration": false } },
            "workspace": { "diagnostics": { "refreshSupport": true } }
        } } }));
    send(json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }));
    let mut texts: BTreeMap<PathBuf, String> = BTreeMap::new();
    for file in &files {
        let text = std::fs::read_to_string(file)
            .with_context(|| format!("cannot read {}", file.display()))?;
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned();
        send(json!({ "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": { "textDocument": { "uri": uri(file), "languageId": "opentide-yaml",
                "version": 1, "text": text } } }));
        texts.insert(file.clone(), text);
    }
    let mut published: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (id, file) in (2..).zip(&files) {
        for message in send(json!({ "jsonrpc": "2.0", "id": id,
            "method": "textDocument/diagnostic",
            "params": { "textDocument": { "uri": uri(file) } } }))
        {
            if message["id"] == id {
                let items = message["result"]["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                published.insert(uri(file), items);
            }
        }
    }
    let mut problems = Vec::new();
    let mut count = 0usize;
    for (file, text) in &texts {
        let mut want: Vec<Key> = by_file
            .get(file)
            .map(|found| found.iter().map(|f| expected(text, f)).collect())
            .unwrap_or_default();
        let mut got: Vec<Key> = published
            .get(&uri(file))
            .map(|items| items.iter().map(key_of).collect())
            .unwrap_or_default();
        for own in engine_own(file, text) {
            if let Some(at) = got.iter().position(|key| *key == own) {
                got.remove(at);
            }
        }
        // The platform blocks are not taken out: a server that published
        // them shows them here, and as findings validate does not have.
        let blocks = published_blocks(file, text, &got);
        want.sort();
        got.sort();
        count += want.len();
        let shown = || file.strip_prefix(dir).unwrap_or(file).display().to_string();
        if !blocks.is_empty() {
            problems.push(format!(
                "{}: the server published the engine's own platform-block analysis {blocks:?} \
                 (UC-2.6, #821: the editor publishes validate's findings)",
                shown()
            ));
        }
        if want != got {
            let shown = shown();
            let missing: Vec<&Key> = want.iter().filter(|k| !got.contains(k)).collect();
            let extra: Vec<&Key> = got.iter().filter(|k| !want.contains(k)).collect();
            problems.push(format!(
                "{shown}: validate only {missing:?}; the server only {extra:?}"
            ));
        }
    }
    Ok((count, problems))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_finding_is_converted_to_utf16_independently() {
        let mut finding = opentide_workspace::Diagnostic::error("vocab_unknown", "x");
        finding.line = Some(2);
        finding.column = Some(3);
        finding.end_line = Some(2);
        finding.end_column = Some(5);
        let key = expected("a\n𝄞é€x\n", &finding);
        assert_eq!(key.2, (1, 3));
        assert_eq!(key.3, (1, 5));
        assert_eq!(key.1, "error");
        let mut placeless = opentide_workspace::Diagnostic::warning("nested_object_file", "x");
        placeless.line = None;
        assert_eq!(expected("a\n", &placeless).2, (0, 0));
    }

    /// A server that published the engine's platform-block analysis is
    /// reported, whatever `validate` says (UC-2.6, #821).
    #[test]
    fn the_servers_own_platform_block_analysis_is_reported() {
        let rule = "name: Tuning\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  \
                    schema: rule::1.0\nconfigurations:\n  sysdig:\n    status: STAGING\n    \
                    append_to_rule: No Such Falco Rule\n    condition: proc.name = bash\n";
        let file = Path::new("objects/rules/tuning.yaml");
        let own = block_own(file, rule);
        let codes: Vec<&str> = own.iter().map(|(code, _, _, _)| code.as_str()).collect();
        assert_eq!(codes, ["falco_unknown_rule"], "{own:?}");
        assert_eq!(published_blocks(file, rule, &own), own);
        assert!(published_blocks(file, rule, &[]).is_empty());
    }

    #[test]
    fn only_validate_alone_is_compared() {
        let catalogue = load_catalogue(&corpora_dir().join("faults.toml")).unwrap();
        let lint = catalogue
            .kinds
            .iter()
            .find(|kind| kind.command.first().map(String::as_str) == Some("lint"))
            .unwrap();
        assert!(compared(lint).is_err());
        assert!(catalogue.kinds.iter().any(|kind| compared(kind).is_ok()));
    }

    fn args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    #[test]
    fn the_editor_and_validate_agree_on_a_few_fault_kinds_and_the_rest_are_skipped() {
        let scratch = tempfile::tempdir().unwrap();
        let keep = scratch.path().join("kept");
        let only = [
            // An object's finding, a vocabulary's, a file that is not YAML
            // and a configuration that does not resolve.
            "uuid-invalid-rule",
            "vocab-unknown-tlp",
            "yaml-parse-rule",
            "config-schema-validation-platform",
            // Not `validate` alone: its own environment, another command.
            "cve-lookup-unavailable",
            "lint-placeholder",
        ]
        .join(",");
        let status = run(&args(&[
            "parity",
            "--corpus",
            "faults",
            "--only",
            &only,
            "--keep",
            keep.to_str().unwrap(),
        ]))
        .unwrap();
        assert_eq!(status, 0);
        // --keep keeps each compared kind's workspace, and only those.
        assert!(keep.join("uuid-invalid-rule").is_dir());
        assert!(keep.join("config-schema-validation-platform").is_dir());
        assert!(!keep.join("lint-placeholder").exists());
        // A kept folder is never written over.
        let error = run(&args(&[
            "parity",
            "--corpus",
            "faults",
            "--only",
            "uuid-invalid-rule",
            "--keep",
            keep.to_str().unwrap(),
        ]))
        .unwrap_err()
        .to_string();
        assert!(
            error.ends_with("exists; remove it or name another --keep"),
            "{error}"
        );
    }

    #[test]
    fn the_command_line_is_parity_on_the_fault_corpus() {
        assert_eq!(run(&args(&["--help"])).unwrap(), 0);
        let error = |argv: &[&str]| run(&args(argv)).unwrap_err().to_string();
        assert!(error(&[]).starts_with("missing command"));
        assert!(error(&["diff"]).starts_with("unknown command `diff`"));
        assert!(error(&["parity", "--fast"]).starts_with("unknown option `--fast`"));
        assert_eq!(error(&["parity", "--only"]), "--only needs a value");
        assert!(error(&["parity"]).starts_with("--corpus faults is the one corpus"));
        assert!(
            error(&["parity", "--corpus", "fixtures"]).starts_with("--corpus faults is the one")
        );
        assert_eq!(
            error(&["parity", "--corpus", "faults", "--only", "no-such-kind"]),
            "--only: no fault kind `no-such-kind`"
        );
    }
}
