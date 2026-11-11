//! The checks the editor shows are the command line's: a root's Tide
//! objects are validated by `opentide-workspace` (`validate`, as `opentide
//! validate` runs it), and a configuration buffer by `opentide-schema`'s
//! configuration checks (UC-2.6, #821). This module holds a root's
//! [`Workspace`], kept up to date through its invalidation API, over the
//! disk with the editor's buffers in place of their files ([`OverlayFs`]),
//! and turns each finding into a range the editor reads (UTF-16).

use opentide_core::{Diagnostic as EngineDiagnostic, Position, Range, Severity};
use opentide_workspace::fs::{DirEntry, EntryKind};
use opentide_workspace::lint;
use opentide_workspace::validate::{Options as ValidateOptions, QueriesMode, Selection};
use opentide_workspace::{
    Change, Diagnostic, FileSystem, MemoryFs, OpenError, Options, OsFs, RootOptions, Workspace,
};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::session::workspace_path;

/// The disk, with the editor's buffers (and what a host with no filesystem
/// supplied) in place of their files: a buffer is read for its path, and its
/// folders exist, whatever the disk holds.
pub(crate) struct OverlayFs {
    base: OsFs,
    buffers: MemoryFs,
}

impl OverlayFs {
    fn new() -> Self {
        Self {
            base: OsFs,
            buffers: MemoryFs::new(),
        }
    }
}

impl FileSystem for OverlayFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.buffers.read(path).or_else(|_| self.base.read(path))
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        self.buffers.kind(path).or_else(|_| self.base.kind(path))
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntry>> {
        let disk = self.base.read_dir(path);
        let buffers = self.buffers.read_dir(path);
        if disk.is_err() && buffers.is_err() {
            return disk;
        }
        let mut entries: BTreeMap<String, DirEntry> = BTreeMap::new();
        for entry in disk.into_iter().chain(buffers).flatten() {
            entries.insert(entry.name.clone(), entry);
        }
        Ok(entries.into_values().collect())
    }

    fn resolve(&self, path: &Path) -> PathBuf {
        self.base.resolve(path)
    }
}

/// `validate`'s findings by file, resolved, shared between requests.
pub(crate) type Findings = Arc<HashMap<PathBuf, Vec<Diagnostic>>>;

/// An object a host knows by its metadata alone (`opentide-object:<uuid>`):
/// the workspace reads it as a file of its family's folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Stub {
    pub family: String,
    pub uuid: String,
    pub schema: String,
    pub name: String,
}

impl Stub {
    /// The file that stands for it in `folder`, and its text.
    fn file(&self, folder: &Path) -> (PathBuf, String) {
        let text = serde_json::json!({
            "name": self.name,
            "metadata": { "uuid": self.uuid, "schema": self.schema },
        })
        .to_string();
        (
            folder.join(format!("opentide-supplied-{}.yaml", self.uuid)),
            text,
        )
    }
}

/// What the editor and the host hold for a root: files in place of their
/// paths, and objects known by their metadata alone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Buffers {
    pub files: BTreeMap<PathBuf, String>,
    pub stubs: Vec<Stub>,
}

/// How the workspace at `root` is opened: `validate` run there.
fn open_options(root: &Path) -> Options {
    Options {
        roots: RootOptions {
            repo: Some(root.to_path_buf()),
            cwd: root.to_path_buf(),
            ..RootOptions::default()
        },
    }
}

/// A root's workspace, loaded once and kept current: what changed since
/// (an edit, a watcher's event, a file the host supplied) is handed to
/// [`Workspace::invalidate`] before the next check.
pub(crate) struct RootChecks {
    fs: Arc<OverlayFs>,
    /// The buffers in [`OverlayFs`], by path.
    buffers: BTreeMap<PathBuf, String>,
    workspace: Option<Workspace>,
    /// The workspace being loaded on a thread of its own, for its root
    /// ([`prefetch`](Self::prefetch)).
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    opening: Option<(
        PathBuf,
        std::thread::JoinHandle<Result<Workspace, OpenError>>,
    )>,
    /// Paths changed since the workspace last saw them.
    pending: Vec<Change>,
    /// The findings of the last run, by file, for the buffers and generation
    /// they were computed for.
    findings: Option<(u64, Vec<PathBuf>, Findings)>,
    /// The findings of the last run over every object, for the generation
    /// it ran in.
    all: Option<(u64, Findings)>,
    /// Why the configuration does not resolve, when it does not.
    pub failure: Option<String>,
    /// The field catalogs generated for the workspace.
    catalog: crate::models::FieldCatalog,
}

impl Default for RootChecks {
    fn default() -> Self {
        Self {
            fs: Arc::new(OverlayFs::new()),
            buffers: BTreeMap::new(),
            workspace: None,
            #[cfg(not(any(target_family = "wasm", fuzzing)))]
            opening: None,
            pending: Vec::new(),
            findings: None,
            all: None,
            failure: None,
            catalog: crate::models::FieldCatalog::default(),
        }
    }
}

impl RootChecks {
    /// What the workspace read and parsed so far, once loaded.
    #[cfg(all(debug_assertions, not(fuzzing)))]
    pub(crate) fn stats(&self) -> Option<opentide_workspace::Stats> {
        self.workspace.as_ref().map(Workspace::stats)
    }

    /// `path` as the workspace names its files: a path that is not
    /// absolute on this platform (a browser host's, or `/a` on Windows)
    /// under the virtual root ([`workspace_path`]), then resolved as the
    /// workspace resolves what it reads (symbolic links, macOS's `/var` for
    /// `/private/var`, Windows' long form of a short name such as
    /// `RUNNER~1`). A buffer, a change, a root and a finding then name one
    /// file whatever spelling the editor used for it.
    pub(crate) fn resolve(&self, path: &Path) -> PathBuf {
        self.fs.resolve(&workspace_path(&path.to_string_lossy()))
    }

    /// `paths` changed on disk (a watcher's events).
    pub(crate) fn changed(&mut self, paths: impl IntoIterator<Item = PathBuf>) {
        let changes: Vec<Change> = paths
            .into_iter()
            .map(|path| Change::changed(self.resolve(&path)))
            .collect();
        self.pending.extend(changes);
    }

    /// Put `buffers` in place of their files: the ones that changed, came or
    /// went since the last call are changes for the workspace.
    fn set_buffers(&mut self, buffers: BTreeMap<PathBuf, String>) {
        let buffers: BTreeMap<PathBuf, String> = buffers
            .into_iter()
            .map(|(path, text)| (self.resolve(&path), text))
            .collect();
        if buffers == self.buffers {
            return;
        }
        for (path, text) in &self.buffers {
            if buffers.get(path) != Some(text) {
                if !buffers.contains_key(path) {
                    self.fs.buffers.remove(path);
                }
                self.pending.push(Change::changed(path.clone()));
            }
        }
        for (path, text) in &buffers {
            if self.buffers.get(path) != Some(text) {
                self.fs.buffers.write(path, text.as_bytes().to_vec());
                if !self.buffers.contains_key(path) {
                    self.pending.push(Change::changed(path.clone()));
                }
            }
        }
        self.buffers = buffers;
    }

    /// The workspace at `root` with `buffers` in place of their files,
    /// brought up to date. `None` while its configuration does not resolve
    /// ([`failure`](Self::failure) says why).
    pub(crate) fn workspace(&mut self, root: &Path, buffers: Buffers) -> Option<&Workspace> {
        let root = &self.resolve(root);
        let mut files = buffers.files.clone();
        self.set_buffers(buffers.files);
        self.update(root);
        if buffers.stubs.is_empty() {
            return self.workspace.as_ref();
        }
        // The stubs go where the configuration puts their families' files.
        let folders: HashMap<String, PathBuf> = self
            .workspace
            .as_ref()
            .map(|workspace| {
                workspace
                    .configuration()
                    .object_folders
                    .iter()
                    .filter_map(|folder| Some((folder.family.clone(), folder.path.clone()?)))
                    .collect()
            })
            .unwrap_or_default();
        for stub in &buffers.stubs {
            if let Some(folder) = folders.get(&stub.family) {
                let (path, text) = stub.file(folder);
                files.entry(path).or_insert(text);
            }
        }
        self.set_buffers(files);
        self.update(root);
        self.workspace.as_ref()
    }

    /// Start loading the workspace at `root` on a thread of its own, while
    /// the server reads the editor's index and answers the first requests:
    /// [`update`](Self::update) takes it then, with what changed since
    /// handed to [`Workspace::invalidate`]. Nothing to do once loaded or
    /// loading, or where a thread cannot start.
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    pub(crate) fn prefetch(&mut self, root: &Path) {
        if self.workspace.is_some() || self.opening.is_some() {
            return;
        }
        let root = self.resolve(root);
        let fs: Arc<dyn FileSystem> = Arc::clone(&self.fs) as Arc<dyn FileSystem>;
        let options = open_options(&root);
        self.opening = std::thread::Builder::new()
            .name("opentide-lsp-load".to_owned())
            .spawn(move || Workspace::open(fs, options))
            .ok()
            .map(|handle| (root, handle));
    }

    /// The workspace [`prefetch`](Self::prefetch) loaded for `root`, if it
    /// did and the load succeeded; `None` otherwise (the caller loads it).
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    fn prefetched(&mut self, root: &Path) -> Option<Workspace> {
        let (at, handle) = self.opening.take()?;
        let workspace = handle.join().ok()?.ok()?;
        (at == root).then_some(workspace)
    }

    /// Whether `change` names an open buffer whose text is the file's on
    /// disk: a workspace loaded meanwhile read the same bytes either way.
    #[cfg(not(any(target_family = "wasm", fuzzing)))]
    fn is_unchanged_buffer(&self, change: &Change) -> bool {
        self.buffers.get(&change.path).is_some_and(|text| {
            self.fs
                .base
                .read(&change.path)
                .is_ok_and(|bytes| bytes == text.as_bytes())
        })
    }

    /// Hand what changed to the workspace, or load it.
    fn update(&mut self, root: &Path) {
        let current = self.pending.is_empty() && self.workspace.is_some();
        if !current {
            let changes = std::mem::take(&mut self.pending);
            self.findings = None;
            self.all = None;
            let result = match self.workspace.as_mut() {
                Some(workspace) => workspace.invalidate(&changes).map(|_| ()),
                None => self.load(root, changes),
            };
            match result {
                Ok(()) => self.failure = None,
                Err(error) => {
                    // The configuration stops every command: nothing is
                    // checked until it resolves again.
                    self.failure = Some(error.to_string());
                    self.workspace = None;
                }
            }
        }
    }

    /// Load the workspace at `root`: the one [`prefetch`](Self::prefetch)
    /// loaded, with `changes` (what came in meanwhile) handed to it, but
    /// for the buffers that hold what the disk does; else read it now.
    fn load(&mut self, root: &Path, changes: Vec<Change>) -> Result<(), OpenError> {
        #[cfg(not(any(target_family = "wasm", fuzzing)))]
        if let Some(mut workspace) = self.prefetched(root) {
            let changes: Vec<Change> = changes
                .into_iter()
                .filter(|change| !self.is_unchanged_buffer(change))
                .collect();
            workspace.invalidate(&changes)?;
            self.workspace = Some(workspace);
            return Ok(());
        }
        // Read now, the buffers in place: what changed is in what it reads.
        drop(changes);
        let fs: Arc<dyn FileSystem> = Arc::clone(&self.fs) as Arc<dyn FileSystem>;
        self.workspace = Some(Workspace::open(fs, open_options(root))?);
        Ok(())
    }

    /// What `validate` reports for `files` (the open Tide documents of the
    /// root), by file: run once per `generation` and set of files.
    pub(crate) fn findings(
        &mut self,
        root: &Path,
        buffers: Buffers,
        files: Vec<PathBuf>,
        generation: u64,
    ) -> Findings {
        let files: Vec<PathBuf> = files.iter().map(|file| self.resolve(file)).collect();
        let cached = self.findings.as_ref().filter(|(at, wanted, _)| {
            *at == generation && files.iter().all(|file| wanted.contains(file))
        });
        if let Some((_, _, found)) = cached {
            if self.pending.is_empty() {
                return Arc::clone(found);
            }
        }
        let Some(workspace) = self.workspace(root, buffers) else {
            return Arc::default();
        };
        let found = Arc::new(validate_files(workspace, &files));
        self.findings = Some((generation, files, Arc::clone(&found)));
        found
    }
}

/// The family a Tide object names (`rule` of `metadata.schema:
/// rule::1.0`), if it names one.
fn family_of(text: &str) -> Option<String> {
    let value: serde_yaml::Value = serde_yaml::from_str(opentide_core::strip_bom(text)).ok()?;
    let schema = value.get("metadata")?.get("schema")?.as_str()?;
    let family = schema.split("::").next()?.trim();
    (!family.is_empty()).then(|| family.to_string())
}

impl RootChecks {
    /// Where a Tide object outside every workspace (an unsaved buffer, a
    /// file with no `objects/` or `.opentide/` around it) is checked: as a
    /// file of its family's folder in the workspace at `root` (the virtual
    /// root, which holds what a host supplied), named after `id` (its URI),
    /// so `validate` reports on it what it would on that object in a
    /// workspace of its own, a reference to an object it does not hold
    /// included. `None` for a text that names no family, or a family the
    /// configuration gives no folder.
    pub(crate) fn standalone_path(
        &mut self,
        root: &Path,
        buffers: &Buffers,
        id: &str,
        text: &str,
    ) -> Option<PathBuf> {
        use std::hash::{Hash, Hasher};
        let family = family_of(text)?;
        if self.workspace.is_none() {
            self.workspace(root, buffers.clone());
        }
        let folder = self
            .workspace
            .as_ref()?
            .configuration()
            .object_folders
            .iter()
            .find(|folder| folder.family == family)?
            .path
            .clone()?;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        id.hash(&mut hasher);
        Some(folder.join(format!("opentide-standalone-{:016x}.yaml", hasher.finish())))
    }
}

impl RootChecks {
    /// The workspace's parse of each object file it read, by the
    /// [`path_key`](crate::session::path_key) of the file under `root` as
    /// the editor names it (the walk's path): what the editor's index reads
    /// instead of parsing the files again (#926). Empty until the workspace
    /// has loaded. It never loads the workspace or hands it what changed.
    pub(crate) fn parses_under(
        &self,
        root: &Path,
    ) -> HashMap<String, Arc<opentide_schema::node::Document>> {
        let Some(workspace) = self.workspace.as_ref() else {
            return HashMap::new();
        };
        let resolved = self.resolve(root);
        workspace
            .index()
            .sources
            .iter()
            .filter_map(|source| {
                let relative = source.path.strip_prefix(&resolved).ok()?;
                let path = root.join(relative).display().to_string();
                Some((
                    crate::session::path_key(&path),
                    Arc::clone(&source.document),
                ))
            })
            .collect()
    }

    /// The Tide field catalogs the models generate for this root's
    /// configuration, as the workspace last resolved it
    /// ([`crate::models::FieldCatalog`]). `None` until the workspace has
    /// loaded and they are generated, and while its configuration does not
    /// resolve. It never loads the workspace or hands it what changed: the
    /// checks do.
    pub(crate) fn field_catalog(&mut self) -> Option<Arc<opentide_analysis::Catalog>> {
        let workspace = self.workspace.as_ref()?;
        self.catalog.for_workspace(workspace)
    }
}

impl RootChecks {
    /// What `validate` reports on every object of the root, by file: run
    /// once per `generation` (a client that pulls the workspace's
    /// diagnostics).
    pub(crate) fn all_findings(
        &mut self,
        root: &Path,
        buffers: Buffers,
        generation: u64,
    ) -> Findings {
        if let Some((at, found)) = &self.all {
            if *at == generation && self.pending.is_empty() {
                return Arc::clone(found);
            }
        }
        let Some(workspace) = self.workspace(root, buffers) else {
            return Arc::default();
        };
        let found = Arc::new(by_file(
            workspace,
            workspace.validate(&ValidateOptions {
                queries: QueriesMode::Off,
                ..ValidateOptions::default()
            }),
            None,
        ));
        self.all = Some((generation, Arc::clone(&found)));
        found
    }
}

/// A run's findings by file, resolved, and lint's file name and metadata
/// findings on the same files (`files`, or every object file for `None`).
fn by_file(
    workspace: &Workspace,
    run: opentide_workspace::validate::Validation,
    files: Option<&[PathBuf]>,
) -> HashMap<PathBuf, Vec<Diagnostic>> {
    let mut by_file: HashMap<PathBuf, Vec<Diagnostic>> = HashMap::new();
    let fs = workspace.fs();
    // KG-03 and KG-05 (#893): the editor shows lint's `filename_mismatch`
    // and `metadata_recommended` (#926).
    let lint = workspace.editor_lint(files).into_iter().map(|finding| {
        let mut diagnostic = finding.diagnostic;
        if diagnostic.code == lint::codes::FILENAME {
            // The rename quick fix's suggestion: the file name the object
            // should have, beside the file.
            diagnostic.suggestion = finding
                .json
                .get("expected")
                .and_then(serde_json::Value::as_str)
                .and_then(|expected| Path::new(expected).file_name())
                .map(|name| name.to_string_lossy().into_owned());
        }
        diagnostic
    });
    for finding in run
        .report
        .issues
        .into_iter()
        .chain(run.report.warnings)
        .chain(lint)
    {
        let Some(file) = finding.file_path.as_deref() else {
            continue;
        };
        by_file.entry(fs.resolve(file)).or_default().push(finding);
    }
    by_file
}

/// `validate`'s findings on `files`, as `opentide validate --file` reports
/// them (the queries check is the editor's own analysis), and lint's file
/// name and metadata findings on them, by file, resolved.
pub(crate) fn validate_files(
    workspace: &Workspace,
    files: &[PathBuf],
) -> HashMap<PathBuf, Vec<Diagnostic>> {
    if files.is_empty() {
        return HashMap::new();
    }
    let selection = Selection {
        files: files.iter().map(|f| f.display().to_string()).collect(),
        ..Selection::default()
    };
    let run = workspace.validate(&ValidateOptions {
        selection: Some(&selection),
        queries: QueriesMode::Off,
        ..ValidateOptions::default()
    });
    by_file(workspace, run, Some(files))
}

/// The UTF-16 column of the code-point column `column` (from 0) of `line`,
/// clamped to the line's end.
#[expect(
    clippy::cast_possible_truncation,
    reason = "LSP positions are u32: a line of more than 4 GiB of UTF-16 is not a document an editor holds"
)]
fn utf16_column(line: &str, column: usize) -> u32 {
    line.chars()
        .take(column)
        .map(char::len_utf16)
        .sum::<usize>() as u32
}

/// The range of a finding in `text` (its file, without a byte-order mark),
/// from its 1-based line and code-point columns (`end_column` exclusive):
/// LSP's 0-based lines and UTF-16 columns. A finding without a line is at
/// the start of the file; one with a line and no column covers the line.
#[expect(
    clippy::cast_possible_truncation,
    reason = "LSP positions are u32: a document of more than 4 billion lines is not one an editor holds"
)]
pub(crate) fn finding_range(text: &str, finding: &Diagnostic) -> Range {
    let Some(line) = finding.line.filter(|line| *line > 0) else {
        return Range::point(0, 0);
    };
    let lines: Vec<&str> = text.split('\n').collect();
    let line_text = |line: usize| {
        lines
            .get(line - 1)
            .map_or("", |text| text.strip_suffix('\r').unwrap_or(text))
    };
    let start_text = line_text(line);
    let start = utf16_column(start_text, finding.column.unwrap_or(1).saturating_sub(1));
    let end_line = finding.end_line.unwrap_or(line).max(line);
    let end_text = line_text(end_line);
    let end = match finding.end_column {
        Some(column) => utf16_column(end_text, column.saturating_sub(1)),
        None if finding.column.is_some() && end_line == line => start,
        None => utf16_column(end_text, usize::MAX),
    };
    let (start_line, end_line) = ((line - 1) as u32, (end_line - 1) as u32);
    let end = if end_line == start_line {
        end.max(start)
    } else {
        end
    };
    Range {
        start: Position::new(start_line, start),
        end: Position::new(end_line, end),
    }
}

/// A finding as the editor's diagnostic: its code, severity, message and
/// field path, placed in `text`. A fix of one edit (it replaces the value
/// the finding underlines) is the suggestion a quick fix applies; lint's
/// `filename_mismatch` suggests the file name, which the quick fix renames
/// the file to.
pub(crate) fn engine_diagnostic(text: &str, finding: &Diagnostic) -> EngineDiagnostic {
    let severity = match finding.severity {
        opentide_workspace::Severity::Error => Severity::Error,
        opentide_workspace::Severity::Warning => Severity::Warning,
        _ => Severity::Information,
    };
    let suggestion = finding
        .fix
        .as_ref()
        .filter(|fix| fix.edits.len() == 1)
        .and_then(|fix| fix.edits.first())
        .map(|edit| edit.replacement.clone())
        .or_else(|| {
            (finding.code == lint::codes::FILENAME)
                .then(|| finding.suggestion.clone())
                .flatten()
        });
    EngineDiagnostic {
        code: finding.code.clone(),
        severity,
        message: finding.message.clone(),
        range: finding_range(text, finding),
        field_path: (!finding.field_path.is_empty()).then(|| finding.field_path.clone()),
        suggestion,
        object_uuid: (!finding.object_uuid.is_empty()).then(|| finding.object_uuid.clone()),
        object_type: (!finding.object_type.is_empty()).then(|| finding.object_type.clone()),
    }
}

/// The findings `opentide-schema`'s configuration checks report on a buffer
/// under `.opentide/configurations/`, as an editor sees it: the buffer
/// merged onto the bundled file, then the parent instance's file of the
/// same name; for `sharing.toml`, the statuses an open `deployment.toml`
/// buffer (else the file) declares, and whether `configurations/sharing/`
/// exists. `read` reads a file the editor has not open (the disk, or what a
/// host supplied); `is_dir` says whether a folder exists.
pub(crate) fn configuration_issues(
    path: &str,
    text: &str,
    open: &[(String, String)],
    read: &dyn Fn(&Path) -> Option<String>,
    is_dir: &dyn Fn(&Path) -> bool,
) -> Vec<opentide_analysis::ConfigIssue> {
    use opentide_schema::configuration::checks::{
        BufferContext, buffer_issues, configurations_directory,
    };
    let mut context = BufferContext::default();
    if let Some((configurations, relative)) = configurations_directory(path) {
        let configurations = PathBuf::from(configurations);
        // `<workspace>/.opentide/configurations` → `<workspace>/../.opentide/configurations`.
        let parent = configurations
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(|above| above.join(".opentide").join("configurations"));
        if let Some(parent) = parent.filter(|p| *p != configurations && is_dir(p)) {
            context.parent = read(&parent.join(&relative));
        }
        if relative == "sharing.toml" {
            let deployment = configurations.join("deployment.toml");
            let key = crate::session::path_key(&deployment.display().to_string());
            context.deployment = open
                .iter()
                .find(|(open, _)| crate::session::path_key(open) == key)
                .map(|(_, text)| text.clone())
                .or_else(|| read(&deployment));
            context.sharing_directory = is_dir(&configurations.join("sharing"));
        }
    }
    buffer_issues(path, text, &context)
        .into_iter()
        .map(|finding| opentide_analysis::ConfigIssue {
            code: finding.code,
            field_path: finding.field_path,
            severity: finding.severity,
            message: finding.message,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(line: usize, column: usize, end_column: usize) -> Diagnostic {
        let mut finding = Diagnostic::error("vocab_unknown", "unknown");
        finding.line = Some(line);
        finding.column = Some(column);
        finding.end_line = Some(line);
        finding.end_column = Some(end_column);
        finding
    }

    #[test]
    fn code_point_columns_become_utf16_columns() {
        // `é` is one code point and one UTF-16 unit; `𝄞` one code point and two units.
        let text = "name: é𝄞 x\ntlp: clearr\n";
        let range = finding_range(text, &at(1, 9, 10));
        assert_eq!(range.start, Position::new(0, 9));
        assert_eq!(range.end, Position::new(0, 10));
        let range = finding_range(text, &at(1, 8, 9));
        assert_eq!((range.start.character, range.end.character), (7, 9));
        let range = finding_range(text, &at(2, 6, 12));
        assert_eq!(range.start, Position::new(1, 5));
        assert_eq!(range.end, Position::new(1, 11));
    }

    #[test]
    fn a_finding_without_a_place_is_at_the_start_and_a_line_alone_covers_it() {
        let text = "a: 1\nbb: 22\r\n";
        let mut finding = Diagnostic::error("yaml_parse", "broken");
        assert_eq!(finding_range(text, &finding), Range::point(0, 0));
        finding.line = Some(2);
        assert_eq!(
            finding_range(text, &finding),
            Range {
                start: Position::new(1, 0),
                end: Position::new(1, 6),
            }
        );
    }

    #[test]
    fn a_column_without_an_end_column_is_a_point() {
        // `𝄞` is two UTF-16 units: column 4 (from 1) is UTF-16 unit 4.
        let text = "a𝄞 key: value\n";
        let mut finding = Diagnostic::error("schema_validation", "point");
        finding.line = Some(1);
        finding.column = Some(4);
        let point = Range::point(0, 4);
        assert_eq!(finding_range(text, &finding), point);
        // The same with the end line named, on the start's line.
        finding.end_line = Some(1);
        assert_eq!(finding_range(text, &finding), point);
        // An end line further down and no end column: to that line's end.
        let text = "a𝄞 key: value\nnext line\n";
        finding.end_line = Some(2);
        assert_eq!(
            finding_range(text, &finding),
            Range {
                start: Position::new(0, 4),
                end: Position::new(1, 9),
            }
        );
    }

    /// A nested workspace's configuration buffer is merged with the parent
    /// instance's file of the same name before it is checked, as `validate`
    /// resolves it: a key only the parent supplies is not a finding.
    #[test]
    fn a_configuration_buffer_takes_the_parent_instance_s_file() {
        let child = "/w/child/.opentide/configurations/deployment.toml";
        let text = "[promotion]\npromotion_target = \"NOPE\"\n";
        let parent_folder = PathBuf::from("/w/.opentide/configurations");
        let parent_file = parent_folder.join("deployment.toml");
        let read = |path: &Path| {
            (path == parent_file).then(|| "[promotion]\npromotion_target = \"DESIGN\"\n".to_owned())
        };
        let codes = |is_dir: &dyn Fn(&Path) -> bool| {
            configuration_issues(child, text, &[], &read, is_dir)
                .into_iter()
                .map(|issue| issue.code)
                .collect::<Vec<_>>()
        };
        // No parent instance: the child's own value is checked.
        assert_eq!(codes(&|_| false), ["promotion_target_unknown"]);
        // The parent instance's file is the later layer.
        assert_eq!(codes(&|path| path == parent_folder), Vec::<String>::new());
    }

    #[test]
    fn a_one_edit_fix_is_the_suggestion_and_the_severity_is_kept() {
        let mut finding = at(1, 6, 12);
        finding.fix = Some(opentide_workspace::Fix {
            safe: true,
            edits: vec![opentide_workspace::TextEdit {
                line: 1,
                column: 6,
                end_line: 1,
                end_column: 12,
                replacement: "clear".into(),
            }],
        });
        finding.field_path = vec!["metadata".into(), "tlp".into()];
        let diagnostic = engine_diagnostic("tlp: clearr\n", &finding);
        assert_eq!(diagnostic.suggestion.as_deref(), Some("clear"));
        assert_eq!(diagnostic.severity, Severity::Error);
        assert_eq!(
            diagnostic.field_path,
            Some(vec!["metadata".to_string(), "tlp".to_string()])
        );
        let warning = engine_diagnostic(
            "",
            &Diagnostic::warning("nested_object_file", "not indexed"),
        );
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.suggestion, None);
        assert_eq!(warning.field_path, None);
    }

    #[test]
    fn a_buffer_stands_in_for_its_file_and_its_folders() {
        let fs = OverlayFs::new();
        let base =
            std::env::temp_dir().join(format!("opentide-lsp-overlay-{}", std::process::id()));
        let file = base.join("objects/rules/new.yaml");
        fs.buffers.write(&file, b"name: x\n".to_vec());
        assert_eq!(fs.read(&file).unwrap(), b"name: x\n");
        assert_eq!(fs.kind(&base.join("objects")).unwrap(), EntryKind::Dir);
        let listed: Vec<String> = fs
            .read_dir(&base.join("objects/rules"))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        assert_eq!(listed, ["new.yaml"]);
        assert!(fs.read(&base.join("objects/rules/other.yaml")).is_err());
    }
}
