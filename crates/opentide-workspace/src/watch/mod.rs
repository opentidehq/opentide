//! `validate --watch` as a library (UC-2.3, #818; `cli/ui/watch.py`,
//! `docs/internal/cli-experience.md`): which files changed, and whether a
//! pass validates them alone or the whole scope. Drawing a pass (the live
//! view, the plain lines, cropping) is the command line's (UC-3.5).
//!
//! [`Watcher`] keeps a snapshot of the object files ([`Stamp`]s) and the
//! UUIDs each one writes. A pass validates only the changed files when the
//! registry's graph did not move, and everything otherwise, since other
//! objects' findings may then change too ([`select_pass`]). The graph moves
//! when a file is added or removed, a UUID in a file changes, or a file's
//! object enters or leaves the registry: it stops or starts parsing, or
//! loses its UUID ([`UNREGISTERED_CODES`], before or after), or a scoped
//! pass checks another number of objects than files it was given. A command
//! narrowed by `--file`, `--uuid` or `--type` validates that scope again on
//! every pass. The watcher keeps the findings of every file, so each pass
//! reports the whole workspace.
//!
//! Change detection is the `notify` crate's ([`events::Events`], not on
//! WebAssembly): an event wakes the loop, which then compares snapshots, so
//! an editor's save through a temporary file and a rename is one modified
//! file, and a missed event is caught by the next look ([`POLL_INTERVAL`]).

#[cfg(not(target_family = "wasm"))]
pub mod events;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::diagnostic::{Diagnostic, Severity};
use crate::fs::{FileSystem, Stamp};

/// How long the loop waits for an event before it looks at the folders
/// anyway (a network drive may send none).
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Codes of findings whose object stays out of the registry, so other
/// objects' references to it dangle while the finding stands.
pub const UNREGISTERED_CODES: [&str; 2] = ["yaml_parse", "missing_uuid"];

/// Each object file and what it held when it was looked at.
pub type Snapshot = BTreeMap<PathBuf, Stamp>;

/// The object files under `roots`: each folder's catalogue (direct
/// children, debug output left out).
pub fn object_files(fs: &dyn FileSystem, roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut found = BTreeSet::new();
    for root in roots {
        if let Ok(scan) = crate::discover::scan(fs, root) {
            found.extend(scan.files);
        }
    }
    found.into_iter().collect()
}

/// The stamp of every object file under `roots`.
pub fn take_snapshot(fs: &dyn FileSystem, roots: &[PathBuf]) -> Snapshot {
    object_files(fs, roots)
        .into_iter()
        .filter_map(|path| fs.stamp(&path).ok().map(|stamp| (path, stamp)))
        .collect()
}

fn uuid_pattern() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        #[expect(clippy::expect_used, reason = "a literal pattern")]
        regex::Regex::new(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        )
        .expect("the pattern compiles")
    })
}

/// The UUIDs written in `path`, lower case: the object's own and every one
/// it points at. A file that cannot be read writes none.
pub fn references(fs: &dyn FileSystem, path: &Path) -> BTreeSet<String> {
    let Ok(bytes) = fs.read(path) else {
        return BTreeSet::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    uuid_pattern()
        .find_iter(&text)
        .map(|found| found.as_str().to_lowercase())
        .collect()
}

/// What differs between two snapshots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Files that appeared.
    pub added: BTreeSet<PathBuf>,
    /// Files that went.
    pub removed: BTreeSet<PathBuf>,
    /// Files whose stamp changed.
    pub modified: BTreeSet<PathBuf>,
}

impl Changes {
    /// The changes from `old` to `new`.
    pub fn between(old: &Snapshot, new: &Snapshot) -> Self {
        Self {
            added: new
                .keys()
                .filter(|path| !old.contains_key(*path))
                .cloned()
                .collect(),
            removed: old
                .keys()
                .filter(|path| !new.contains_key(*path))
                .cloned()
                .collect(),
            modified: old
                .iter()
                .filter(|(path, stamp)| new.get(*path).is_some_and(|now| now != *stamp))
                .map(|(path, _)| path.clone())
                .collect(),
        }
    }

    /// Whether nothing changed.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    /// Every changed path, sorted.
    pub fn paths(&self) -> Vec<PathBuf> {
        let all: BTreeSet<&PathBuf> = self
            .added
            .iter()
            .chain(&self.removed)
            .chain(&self.modified)
            .collect();
        all.into_iter().cloned().collect()
    }

    /// The changes as [`crate::Change`]s, for [`crate::Workspace::invalidate`].
    pub fn to_invalidation(&self) -> Vec<crate::Change> {
        self.added
            .iter()
            .map(|path| crate::Change::created(path.clone()))
            .chain(
                self.removed
                    .iter()
                    .map(|path| crate::Change::deleted(path.clone())),
            )
            .chain(
                self.modified
                    .iter()
                    .map(|path| crate::Change::changed(path.clone())),
            )
            .collect()
    }
}

/// A pass: the whole scope, or the changed files alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// Everything the command selects.
    Full,
    /// The changed files.
    Scoped,
}

/// What [`select_pass`] reads about one changed file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileChange {
    /// The UUIDs it wrote before (`None`: it was not there).
    pub references_before: Option<BTreeSet<String>>,
    /// The UUIDs it writes now (`None`: it is gone).
    pub references_after: Option<BTreeSet<String>>,
    /// Whether the last pass kept its object out of the registry.
    pub was_unregistered: bool,
}

/// The pass a change needs before validating (`Watcher.poll`): full when a
/// file was added or removed, a UUID in a file changed, a file whose object
/// was out of the registry changed, or the command is narrowed
/// (`scoped_runs` false); scoped otherwise. A scoped pass may still turn
/// full on what it finds ([`scoped_pass_holds`]).
pub fn select_pass(files: &[FileChange], scoped_runs: bool) -> Pass {
    let moved = files.iter().any(|file| {
        file.references_before.is_none()
            || file.references_after.is_none()
            || file.references_before != file.references_after
            || file.was_unregistered
    });
    if moved || !scoped_runs {
        Pass::Full
    } else {
        Pass::Scoped
    }
}

/// Whether a scoped pass's result stands (`Watcher._scoped`): every finding
/// is in a changed file, none keeps its object out of the registry, and it
/// checked one object per changed file. Otherwise only a full pass can say
/// what else changed.
pub fn scoped_pass_holds(found: &[Diagnostic], objects: usize, changed: &[PathBuf]) -> bool {
    found.iter().all(|item| {
        item.file_path
            .as_ref()
            .is_some_and(|file| changed.contains(file))
    }) && !unregistered_in(found)
        && objects == changed.len()
}

fn unregistered_in<'a>(findings: impl IntoIterator<Item = &'a Diagnostic>) -> bool {
    findings
        .into_iter()
        .any(|item| UNREGISTERED_CODES.contains(&item.code.as_str()))
}

/// Validates for the watcher.
pub trait Validate {
    /// Takes the changed files into account (reloads them) before a pass.
    fn reload(&mut self, changes: &Changes);

    /// Validates `files`, or the command's whole scope for `None`: the
    /// findings and how many objects were checked.
    fn validate(&mut self, files: Option<&[PathBuf]>) -> (Vec<Diagnostic>, usize);
}

/// One pass and the state of the whole workspace after it.
#[derive(Debug, Clone, PartialEq)]
pub struct WatchRun {
    /// From 1.
    pub number: usize,
    /// Every finding in the workspace, file by file.
    pub diagnostics: Vec<Diagnostic>,
    /// The findings this pass produced (all of them on a full pass).
    pub found: Vec<Diagnostic>,
    /// Objects checked by the last full pass.
    pub objects: usize,
    /// Errors in the workspace.
    pub errors: usize,
    /// Warnings in the workspace.
    pub warnings: usize,
    /// Files with a finding.
    pub files: usize,
    /// Whether the workspace fails (errors, or warnings under `--strict`).
    pub failed: bool,
    /// Findings `validate --fix` would fix.
    pub fixable: usize,
    /// Whether only the changed files were validated.
    pub scoped: bool,
    /// The files that changed, sorted.
    pub changed: Vec<PathBuf>,
    /// How long the pass took.
    pub elapsed: Duration,
}

/// Re-validates the object folders when their files change.
pub struct Watcher<'fs, V: Validate> {
    fs: &'fs dyn FileSystem,
    roots: Vec<PathBuf>,
    validate: V,
    strict: bool,
    scoped_runs: bool,
    strict_exempt: Vec<String>,
    files: Snapshot,
    references: BTreeMap<PathBuf, BTreeSet<String>>,
    findings: BTreeMap<Option<PathBuf>, Vec<Diagnostic>>,
    objects: usize,
    runs: usize,
}

impl<'fs, V: Validate> Watcher<'fs, V> {
    /// A watcher of the object folders `roots`, read through `fs`.
    /// `scoped_runs` is false when the command is narrowed (`--file`,
    /// `--uuid`, `--type`): every pass validates that scope again.
    /// `strict_exempt` are the warning codes `--strict` does not fail on.
    pub fn new(
        fs: &'fs dyn FileSystem,
        roots: Vec<PathBuf>,
        validate: V,
        strict: bool,
        scoped_runs: bool,
        strict_exempt: &[&str],
    ) -> Self {
        Self {
            fs,
            roots,
            validate,
            strict,
            scoped_runs,
            strict_exempt: strict_exempt
                .iter()
                .map(|code| (*code).to_owned())
                .collect(),
            files: Snapshot::new(),
            references: BTreeMap::new(),
            findings: BTreeMap::new(),
            objects: 0,
            runs: 0,
        }
    }

    /// The validator.
    pub fn validator(&self) -> &V {
        &self.validate
    }

    /// The folders it watches.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Reads the folders and validates the whole scope once.
    pub fn start(&mut self) -> WatchRun {
        self.files = take_snapshot(self.fs, &self.roots);
        self.references = self
            .files
            .keys()
            .map(|path| (path.clone(), references(self.fs, path)))
            .collect();
        self.full(Vec::new())
    }

    /// Validates again if a file changed since the last look; `None`
    /// otherwise.
    pub fn poll(&mut self) -> Option<WatchRun> {
        let current = take_snapshot(self.fs, &self.roots);
        let changes = Changes::between(&self.files, &current);
        self.files = current;
        if changes.is_empty() {
            return None;
        }
        let mut files = Vec::new();
        for path in &changes.removed {
            files.push(FileChange {
                references_before: self.references.remove(path),
                references_after: None,
                was_unregistered: self.unregistered(path),
            });
        }
        for path in changes.added.iter().chain(&changes.modified) {
            let now = references(self.fs, path);
            files.push(FileChange {
                references_before: self.references.get(path).cloned(),
                references_after: Some(now.clone()),
                was_unregistered: self.unregistered(path),
            });
            self.references.insert(path.clone(), now);
        }
        self.validate.reload(&changes);
        let paths = changes.paths();
        match select_pass(&files, self.scoped_runs) {
            Pass::Full => Some(self.full(paths)),
            Pass::Scoped => Some(self.scoped(paths)),
        }
    }

    fn unregistered(&self, path: &Path) -> bool {
        self.findings
            .get(&Some(path.to_path_buf()))
            .is_some_and(unregistered_in)
    }

    fn full(&mut self, changed: Vec<PathBuf>) -> WatchRun {
        let started = Instant::now();
        let (diagnostics, objects) = self.validate.validate(None);
        self.findings = by_file(&diagnostics);
        self.objects = objects;
        self.result(diagnostics, started, false, changed)
    }

    fn scoped(&mut self, changed: Vec<PathBuf>) -> WatchRun {
        let started = Instant::now();
        let (diagnostics, objects) = self.validate.validate(Some(&changed));
        if !scoped_pass_holds(&diagnostics, objects, &changed) {
            return self.full(changed);
        }
        for path in &changed {
            self.findings.remove(&Some(path.clone()));
        }
        for (key, items) in by_file(&diagnostics) {
            self.findings.insert(key, items);
        }
        self.result(diagnostics, started, true, changed)
    }

    fn result(
        &mut self,
        found: Vec<Diagnostic>,
        started: Instant,
        scoped: bool,
        changed: Vec<PathBuf>,
    ) -> WatchRun {
        self.runs += 1;
        let everything: Vec<Diagnostic> = self.findings.values().flatten().cloned().collect();
        let errors = everything
            .iter()
            .filter(|item| item.severity == Severity::Error)
            .count();
        let warnings = everything
            .iter()
            .filter(|item| item.severity == Severity::Warning)
            .count();
        let failing_warnings = everything.iter().any(|item| {
            item.severity == Severity::Warning && !self.strict_exempt.contains(&item.code)
        });
        let files = everything
            .iter()
            .filter_map(|item| item.path.as_deref())
            .collect::<BTreeSet<_>>()
            .len();
        let fixable = crate::fix::plan(self.fs, &everything).changes.len();
        WatchRun {
            number: self.runs,
            failed: errors > 0 || (self.strict && failing_warnings),
            diagnostics: everything,
            found,
            objects: self.objects,
            errors,
            warnings,
            files,
            fixable,
            scoped,
            changed,
            elapsed: started.elapsed(),
        }
    }
}

fn by_file(diagnostics: &[Diagnostic]) -> BTreeMap<Option<PathBuf>, Vec<Diagnostic>> {
    let mut grouped: BTreeMap<Option<PathBuf>, Vec<Diagnostic>> = BTreeMap::new();
    for item in diagnostics {
        grouped
            .entry(item.file_path.clone())
            .or_default()
            .push(item.clone());
    }
    grouped
}

/// [`Validate`] over a [`crate::Workspace`]: each pass reloads the files
/// that changed ([`crate::Workspace::invalidate`]) and runs `validate` with
/// the command's options, narrowed to the changed files for a scoped pass.
pub struct WorkspaceValidate<'q> {
    /// The workspace, kept between passes.
    pub workspace: crate::Workspace,
    /// `--check`.
    pub check: Option<crate::validate::Check>,
    /// `--file`, `--uuid`, `--type`.
    pub selection: crate::validate::Selection,
    /// `--strict`.
    pub strict: bool,
    /// `--queries`.
    pub queries: crate::validate::QueriesMode,
    /// The queries check.
    pub query_check: Option<&'q dyn crate::validate::QueryCheck>,
    /// Why the last reload failed (the configuration no longer resolves);
    /// the workspace is then as it was.
    pub reload_error: Option<crate::OpenError>,
}

impl WorkspaceValidate<'_> {
    /// The command's options over `workspace`.
    pub fn new(workspace: crate::Workspace, selection: crate::validate::Selection) -> Self {
        Self {
            workspace,
            check: None,
            selection,
            strict: false,
            queries: crate::validate::QueriesMode::default(),
            query_check: None,
            reload_error: None,
        }
    }

    /// The object folders the configuration names: what to watch.
    pub fn roots(&self) -> Vec<PathBuf> {
        self.workspace
            .configuration()
            .object_folders
            .iter()
            .filter_map(|folder| folder.path.clone())
            .collect()
    }
}

impl Validate for WorkspaceValidate<'_> {
    fn reload(&mut self, changes: &Changes) {
        self.reload_error = self.workspace.invalidate(&changes.to_invalidation()).err();
    }

    fn validate(&mut self, files: Option<&[PathBuf]>) -> (Vec<Diagnostic>, usize) {
        let scoped = files.map(|files| crate::validate::Selection {
            files: files
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            ..crate::validate::Selection::default()
        });
        let selection = scoped.as_ref().unwrap_or(&self.selection);
        let validation = self.workspace.validate(&crate::validate::Options {
            check: self.check,
            selection: Some(selection),
            strict: self.strict,
            queries: self.queries,
            query_check: self.query_check,
        });
        let objects = validation.summary.objects;
        let mut found = validation.report.issues;
        found.extend(validation.report.warnings);
        (found, objects)
    }
}
