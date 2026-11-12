//! A Tide workspace, opened once: validate, lint, info, the catalogue and
//! coverage on it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_workspace::lint::LintCheck;
use opentide_workspace::validate::{Check, QueriesMode, Selection, Validation};
use opentide_workspace::{FileSystem, MemoryFs, OsFs, RootOptions};
use serde::Serialize;

use crate::catalog::{Catalogue, Coverage, PlatformInfo};
use crate::lint::LintReport;
use crate::{Error, queries};

/// How [`Workspace::open`] opens a workspace.
///
/// ```
/// let options = opentide::Options::default().cwd("/repo");
/// assert_eq!(options.cwd.as_deref(), Some(std::path::Path::new("/repo")));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The folder paths in findings are shown from, as the command line
    /// shows them from its working directory. Default: the workspace's own
    /// folder.
    pub cwd: Option<PathBuf>,
}

impl Options {
    /// Shows paths from `cwd`.
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
}

/// A Tide workspace: its configuration, resolved once, and every object file,
/// read and parsed once (in parallel) into one index.
///
/// Opening is the expensive step; each operation then reads the index, so
/// one `Workspace` serves many of them. It is `Clone` (the index is shared)
/// and `Send + Sync`.
///
/// ```
/// let ws = opentide::Workspace::from_files(
///     "/ws",
///     [(
///         "objects/rules/example.yaml",
///         "name: Example\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.1\n",
///     )],
/// )?;
/// assert_eq!(ws.info().counts.rules, 1);
/// # Ok::<(), opentide::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Workspace {
    inner: opentide_workspace::Workspace,
}

impl Workspace {
    /// Opens the workspace at `path` on disk: a repository holding
    /// `.opentide/` or `objects/`, or a folder inside one.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when `path` cannot be made absolute;
    /// [`Error::Configuration`] when the configuration does not resolve.
    pub fn open(path: impl AsRef<Path>, options: &Options) -> Result<Self, Error> {
        let path = path.as_ref();
        let absolute = std::path::absolute(path).map_err(|error| Error::Io {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        let cwd = match &options.cwd {
            Some(cwd) => std::path::absolute(cwd).map_err(|error| Error::Io {
                path: cwd.clone(),
                message: error.to_string(),
            })?,
            None => absolute.clone(),
        };
        Self::open_on(Arc::new(OsFs), absolute, cwd)
    }

    /// Opens a workspace held in memory, rooted at `root`: each of `files` is
    /// a path (relative to `root`, or absolute) and its bytes. Nothing is read
    /// from or written to the disk: an editor's buffers, a browser, a test.
    ///
    /// # Errors
    ///
    /// [`Error::Configuration`] when the configuration among `files` does not
    /// resolve.
    pub fn from_files<P, B>(
        root: impl AsRef<Path>,
        files: impl IntoIterator<Item = (P, B)>,
    ) -> Result<Self, Error>
    where
        P: AsRef<Path>,
        B: Into<Vec<u8>>,
    {
        let root = root.as_ref().to_path_buf();
        let fs = MemoryFs::new();
        fs.create_dir(&root);
        for (path, bytes) in files {
            fs.write(root.join(path), bytes);
        }
        Self::open_on(Arc::new(fs), root.clone(), root)
    }

    fn open_on(fs: Arc<dyn FileSystem>, repo: PathBuf, cwd: PathBuf) -> Result<Self, Error> {
        let inner = opentide_workspace::Workspace::open(
            fs,
            opentide_workspace::Options {
                roots: RootOptions {
                    repo: Some(repo),
                    cwd,
                    ..RootOptions::default()
                },
            },
        )?;
        Ok(Self { inner })
    }

    /// The workspace folder: the one that holds `.opentide/` and `objects/`.
    pub fn root(&self) -> &Path {
        self.inner.root()
    }

    /// Runs every check of `opentide validate` (`validate --json`'s `checks`,
    /// `report` and `summary`): each finding a [`crate::Diagnostic`] with its
    /// place.
    ///
    /// The queries check runs on the query engines with the `queries`
    /// feature; without it, it reports one `engine_unavailable` error unless
    /// [`ValidateOptions::queries`] turns it off.
    ///
    /// ```
    /// use opentide::validate::QueriesMode;
    ///
    /// let ws = opentide::Workspace::from_files(
    ///     "/ws",
    ///     [("objects/rules/a.yaml", "name: A\nmetadata:\n  uuid: not-a-uuid\n")],
    /// )?;
    /// let options = opentide::ValidateOptions::default().queries(QueriesMode::Off);
    /// let validation = ws.validate(&options);
    /// assert!(validation.failed);
    /// assert!(validation.report.issues.iter().any(|d| d.code == "invalid_uuid"));
    /// # Ok::<(), opentide::Error>(())
    /// ```
    pub fn validate(&self, options: &ValidateOptions) -> Validation {
        let selection = Selection {
            files: options.files.clone(),
            uuids: options.uuids.clone(),
            types: options.types.clone(),
        };
        self.inner.validate(&opentide_workspace::validate::Options {
            check: options.check,
            selection: Some(&selection),
            strict: options.strict,
            queries: options.queries,
            query_check: Some(queries::validate_check()),
            cve_check: None,
        })
    }

    /// Runs `opentide lint` (its `lint.toml`, or the checks `options` names)
    /// without fixing anything: lint's `--fix` renames files, which is the
    /// command line's to do.
    ///
    /// The queries check runs on the query engines with the `queries`
    /// feature; without it a lint that runs it fails with `engine_unavailable`
    /// (its [`LintReport::failure_code`]).
    pub fn lint(&self, options: &LintOptions) -> LintReport {
        queries::with_lint_check(&self.inner, |check| {
            self.inner.lint(
                None,
                &opentide_workspace::lint::LintOptions {
                    checks: options.checks.clone(),
                    fix: false,
                    strict: options.strict,
                    files: options.files.clone(),
                    changed: None,
                    cwd: self.inner.cwd().to_path_buf(),
                    query_check: Some(check),
                },
            )
        })
    }

    /// What `opentide info` reports: the object counts, the files that did
    /// not load and each platform with its tenants. A tenant names the
    /// environment variables it reads and whether each is set in this
    /// process, never their values.
    pub fn info(&self) -> Info {
        let index = self.inner.index();
        let count = |family: &str| index.objects.get(family).map_or(0, |objects| objects.len());
        let is_set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
        Info {
            root: self.root().to_path_buf(),
            counts: Counts {
                rules: count("rule"),
                threats: count("threat"),
                objectives: count("objective"),
            },
            load_errors: index.load_errors.len() + index.duplicates.len(),
            platforms: opentide_workspace::info::platforms(
                self.inner.configuration().resolved.get("systems"),
                None,
                &is_set,
            ),
        }
    }

    /// The catalogue (`opentide info catalog`): every object with its
    /// techniques and platforms, every edge between objects, the signals and
    /// the ATT&CK matrix.
    pub fn catalog(&self) -> Catalogue {
        opentide_workspace::catalogue::build(&self.inner)
    }

    /// The rules that cover the ATT&CK `technique` (`opentide info coverage
    /// --technique`), their own techniques or ones they inherit from their
    /// objective and its threats. A technique covers its sub-techniques.
    pub fn coverage(&self, technique: &str) -> Coverage {
        opentide_workspace::coverage::match_technique(
            technique,
            &opentide_workspace::coverage::rule_technique_index(self.inner.index()),
        )
    }

    /// The workspace the domain crates load, for the facade's other modules.
    #[cfg_attr(
        all(not(feature = "compile"), not(test)),
        expect(dead_code, reason = "deploy_plan's")
    )]
    pub(crate) fn inner(&self) -> &opentide_workspace::Workspace {
        &self.inner
    }
}

/// What [`Workspace::validate`] runs: `opentide validate`'s options.
///
/// ```
/// use opentide::validate::{Check, QueriesMode};
///
/// let options = opentide::ValidateOptions::default()
///     .check(Check::Schema)
///     .file("objects/rules/a.yaml")
///     .strict(true)
///     .queries(QueriesMode::Warn);
/// assert_eq!(options.files, ["objects/rules/a.yaml"]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidateOptions {
    /// `--check`: one check, else the default ones.
    pub check: Option<Check>,
    /// `--file`: object files, by path or by name.
    pub files: Vec<String>,
    /// `--uuid`: objects by UUID.
    pub uuids: Vec<String>,
    /// `--type`: object families (`rule`, `threat`, `objective`).
    pub types: Vec<String>,
    /// `--strict`: a warning fails the run too.
    pub strict: bool,
    /// `--queries`: a query the engine rejects as an error (the default), a
    /// warning, or not checked.
    pub queries: QueriesMode,
}

impl ValidateOptions {
    /// Runs `check` alone.
    pub fn check(mut self, check: Check) -> Self {
        self.check = Some(check);
        self
    }

    /// Narrows the run to the object file `file` (repeatable).
    pub fn file(mut self, file: impl Into<String>) -> Self {
        self.files.push(file.into());
        self
    }

    /// Narrows the run to the object `uuid` (repeatable).
    pub fn uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuids.push(uuid.into());
        self
    }

    /// Narrows the run to the family `family` (repeatable).
    pub fn object_type(mut self, family: impl Into<String>) -> Self {
        self.types.push(family.into());
        self
    }

    /// Whether a warning fails the run.
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// How the queries check reports a query the engine rejects.
    pub fn queries(mut self, queries: QueriesMode) -> Self {
        self.queries = queries;
        self
    }
}

/// What [`Workspace::lint`] runs: `opentide lint`'s options, without `--fix`
/// and `--changed` (the command line's).
///
/// ```
/// use opentide::lint::LintCheck;
///
/// let options = opentide::LintOptions::default().check(LintCheck::Metadata).strict(true);
/// assert_eq!(options.checks, [LintCheck::Metadata]);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LintOptions {
    /// `--check`; empty runs the checks `lint.toml` enables.
    pub checks: Vec<LintCheck>,
    /// `--strict`: any finding fails the run.
    pub strict: bool,
    /// `--file`: object files, by path or by name.
    pub files: Vec<String>,
}

impl LintOptions {
    /// Runs `check` (repeatable).
    pub fn check(mut self, check: LintCheck) -> Self {
        self.checks.push(check);
        self
    }

    /// Whether any finding fails the run.
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Narrows the run to the object file `file` (repeatable).
    pub fn file(mut self, file: impl Into<String>) -> Self {
        self.files.push(file.into());
        self
    }
}

/// What [`Workspace::info`] reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Info {
    /// The workspace folder.
    pub root: PathBuf,
    /// Objects by family.
    pub counts: Counts,
    /// Files that did not load, and duplicated UUIDs.
    pub load_errors: usize,
    /// Every platform, with its tenants.
    pub platforms: Vec<PlatformInfo>,
}

/// Objects by family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Counts {
    /// Detection rules.
    pub rules: usize,
    /// Threat vectors.
    pub threats: usize,
    /// Detection objectives.
    pub objectives: usize,
}
