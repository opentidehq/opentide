//! `opentide doctor` (UC-3.5c, #928; its network checks UC-4.4, #834): one
//! checklist for the
//! installation, the workspace and its integrations.
//!
//! Every check has a stable `code` (`docs/cli/doctor.md`), a status (`pass`,
//! `warn`, `fail` or `skip`), a one-line message and, when something needs
//! doing, a `fix`. A check never prints a secret: credentials are reported
//! set or unset by variable name, a proxy URL without its user and password.
//!
//! The network checks (the newest release on PyPI, the proxy's reachability)
//! are [`super::doctor_network`]'s; `--offline` skips them.
//!
//! What the Rust command line reports differently, and why:
//!
//! - It has no `python_version` and no `platform_sdk` check (UC-6.0d, #841,
//!   #977): it does not run on Python, and the platforms are its own
//!   connectors, which import no Python SDK.
//! - `analysis_engine` passes: the engine is compiled into this program.
//! - `lsp_catalog` warns about a committed catalog from another opentide;
//!   no program reads it (the language server generates its own, #926).

use std::path::{Component, Path, PathBuf};
use std::process::Command;

use opentide_compile::Json as CJson;
use opentide_compile::generate::Output;
use opentide_connectors::connector::{CREDENTIALS_UNAVAILABLE, DeployError, TenantContext};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{ConnectorError, HttpClient, Tenant};
use opentide_schema::configuration::lint::parse_lint_config;
use opentide_schema::generate::catalog::CATALOG_DIR;
use opentide_schema::generate::router::{schema_artifact_name, template_artifact_name};
use opentide_schema::generate::template::Options;
use opentide_schema::generate::workspace::{
    CORE_OBJECT_TYPES, identifiers_for_families, object_template,
};
use opentide_schema::node::{Node, Value};
use opentide_schema::platforms::PlatformId;
use opentide_workspace::info::env_reference;
use opentide_workspace::root::{self, RootOptions};
use opentide_workspace::{OsFs, config};
use serde_json::Value as JsonValue;
use tokio_util::sync::CancellationToken;

use super::doctor_network as network;
use super::generate::phase_outputs;
use super::interrupt::watched;
use super::result::{ExitCode, Status};
use super::{Block, Report, placement};
use crate::env::Env;
use crate::envelope::Failure;
use crate::json::{Json, Object};
use crate::render::glyphs;
use crate::render::text::Text;
use anstyle::{AnsiColor, Style};

const COMMAND: &str = "doctor";

/// `failure.code` when at least one check failed.
pub const CHECKS_FAILED: &str = "doctor_checks_failed";

/// The files `opentide setup mcp` writes, with the host each is for.
const MCP_OUTPUT_PATHS: [(&str, &str); 4] = [
    ("VS Code", ".vscode/mcp.json"),
    ("Cursor", ".cursor/mcp.json"),
    ("Claude Code", ".mcp.json"),
    ("generic", "opentide.mcp.json"),
];

/// What `vscode_settings` suggests when the repository does not recommend the
/// extension: install it (the recommended path), or have the repository
/// recommend it to the team with `setup vscode`.
const INSTALL_EXTENSION_FIX: &str = "code --install-extension opentidehq.opentide (or opentide setup vscode, to recommend it to the team)";

/// The opentide VS Code extension.
const EXTENSION_ID: &str = "opentidehq.opentide";

const OPENTIDE_DIR: &str = ".opentide";

/// One line of the checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// The stable code.
    pub code: &'static str,
    /// `pass`, `warn`, `fail` or `skip`.
    pub status: &'static str,
    /// What was found.
    pub message: String,
    /// What fixes it.
    pub fix: Option<String>,
    /// What it is about when it repeats: a platform, a tenant.
    pub subject: Option<String>,
}

impl Check {
    fn new(code: &'static str, status: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
            fix: None,
            subject: None,
        }
    }

    fn fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }

    fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    fn to_json(&self) -> Json {
        Json::object([
            ("code", Json::str(self.code)),
            ("status", Json::str(self.status)),
            ("message", Json::str(&self.message)),
            ("fix", Json::opt_str(self.fix.clone())),
            ("subject", Json::opt_str(self.subject.clone())),
        ])
    }
}

/// What the checks read.
pub struct Context<'a> {
    /// `--repo`, as typed.
    pub repo: Option<&'a str>,
    /// The process environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// opentide's version.
    pub version: &'a str,
    /// Whether the run prints text (the checklist), not JSON.
    pub text: bool,
    /// `--proxy`, from the command line or `OPENTIDE_PROXY`.
    pub proxy: Option<&'a str>,
    /// Whether Ctrl-C was pressed: `--live`'s requests stop at once.
    pub interrupted: &'a (dyn Fn() -> bool + Sync),
}

/// What the checks share: the workspace and its configuration.
struct Doctor<'a> {
    cx: &'a Context<'a>,
    workspace: PathBuf,
    explicit: bool,
    cwd: PathBuf,
    /// The Tide workspace `placement` resolves, against the working
    /// directory: `OPENTIDE_TIDE_WORKSPACE` when it is set, else the
    /// repository path.
    tide_workspace: Option<PathBuf>,
    /// The merged configuration, when it loads.
    config: Option<Node>,
    /// What `generate schemas` would write now, when the workspace opens
    /// with the generator's own configuration: `Err` says why not.
    expected: Option<Result<Expected, String>>,
}

/// The files `generate schemas` writes for this version, in memory.
struct Expected {
    /// Their folder's root: the workspace's.
    root: PathBuf,
    outputs: Vec<Output>,
}

/// What [`Expected::compare`] found.
struct Comparison {
    /// The files compared, each path once.
    checked: usize,
    /// The ones not on disk (`NotFound`), by file name.
    missing: Vec<String>,
    /// The ones whose text differs, or that cannot be read, by file name.
    differing: Vec<String>,
}

impl Expected {
    /// The files of the schemas (`catalog` false) or of the language-server
    /// catalog (`catalog` true) against the disk. Line endings and a byte
    /// order mark do not count, as for the templates: an editor or git's
    /// `autocrlf` rewrites them.
    fn compare(&self, catalog: bool) -> Comparison {
        let catalog_dir = self.root.join(CATALOG_DIR);
        let mut seen: Vec<&Path> = Vec::new();
        let mut found = Comparison {
            checked: 0,
            missing: Vec::new(),
            differing: Vec::new(),
        };
        for output in &self.outputs {
            if output.path.starts_with(&catalog_dir) != catalog
                || seen.contains(&output.path.as_path())
            {
                continue;
            }
            seen.push(&output.path);
            found.checked += 1;
            let name = output
                .path
                .file_name()
                .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
            match std::fs::read(&output.path) {
                Ok(bytes) if same_text(&bytes, &output.bytes) => {}
                Ok(_) => found.differing.push(name),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    found.missing.push(name);
                }
                Err(_) => found.differing.push(format!("{name} (unreadable)")),
            }
        }
        found
    }
}

/// Whether a file on disk holds `expected`, ignoring a leading byte order
/// mark and the difference between CRLF and LF.
fn same_text(disk: &[u8], expected: &[u8]) -> bool {
    let disk = disk.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(disk);
    if disk == expected {
        return true;
    }
    let mut unix = Vec::with_capacity(disk.len());
    let mut bytes = disk.iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        if byte == b'\r' && bytes.peek() == Some(&b'\n') {
            continue;
        }
        unix.push(byte);
    }
    unix == expected
}

/// One configured tenant: the environment variables its setup names.
struct TenantEnv {
    /// `platform/name`.
    subject: String,
    /// The tenant's name (`tenant 2` when the table has none).
    name: String,
    /// Every variable the setup refers to, once each.
    variables: Vec<String>,
    /// The ones that are unset or empty.
    unset: Vec<String>,
    /// A Google SecOps tenant that names no `credentials` on a machine with
    /// no Application Default Credentials file and no variable naming one:
    /// it holds no credentials locally (only a Google Cloud host's metadata
    /// server could supply them).
    adc_missing: bool,
    /// The tenant's table, for its setup.
    node: Node,
}

/// An enabled platform and its configured tenants.
struct PlatformTenants {
    platform: &'static str,
    tenants: Vec<TenantEnv>,
}

/// Which network checks `opentide doctor` makes: `--offline` and `--live`
/// conflict, so a run is in one of three modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoctorMode {
    /// Neither flag: the PyPI release and the proxy are checked, the tenants
    /// are not reached.
    Default,
    /// `--offline`: no network check.
    Offline,
    /// `--live`: each tenant whose credentials are set is reached too.
    Live,
}

impl From<&crate::tree::DoctorArgs> for DoctorMode {
    fn from(args: &crate::tree::DoctorArgs) -> Self {
        // clap refuses `--offline --live` together.
        if args.live {
            Self::Live
        } else if args.offline {
            Self::Offline
        } else {
            Self::Default
        }
    }
}

/// Runs `opentide doctor`.
pub fn run(mode: DoctorMode, cx: &Context<'_>) -> Report {
    let offline = mode == DoctorMode::Offline;
    let live = mode == DoctorMode::Live;
    let (shown, options) = placement(cx.repo, cx.env, cx.cwd);
    let cwd = resolve(cx.cwd);
    let workspace = resolve(&cx.cwd.join(&shown));
    let discovered = resolve(&root::find_workspace_root(&OsFs, cx.cwd));
    let explicit = cx.repo.is_some() || workspace != discovered;
    let tide_workspace = options
        .tide_workspace_env
        .as_deref()
        .map(|path| resolve(&cx.cwd.join(path)));
    let mut doctor = Doctor {
        cx,
        workspace,
        explicit,
        cwd,
        tide_workspace,
        config: None,
        expected: None,
    };
    let roots = root::resolve(&OsFs, &options_for(&options));
    let loaded = config::load(&OsFs, &roots);
    let mut checks: Vec<Check> = Vec::new();
    checks.push(Check::new(
        "opentide_version",
        "pass",
        format!("opentide {}", cx.version),
    ));
    checks.push(latest_version(offline, cx));
    checks.push(doctor.workspace_check());
    checks.extend(doctor.git());
    let configuration = doctor.configuration(loaded.as_ref().map(|_| ()).map_err(|_| ()));
    let configuration_failed = configuration.status == "fail";
    checks.push(configuration);
    if let Ok(configuration) = loaded {
        doctor.config = Some(configuration.resolved.tree);
    }
    let skipped = |code: &'static str| {
        Check::new(code, "skip", "Not checked: the configuration does not load")
    };
    // Opening the workspace and rendering the schemas takes a while, so it
    // runs beside the checks that wait on the network and is joined after
    // them: until then `schemas_fresh` and `lsp_catalog` hold the checks
    // that need no comparison.
    let comparing = (!configuration_failed).then(|| {
        let options = options_for(&options);
        let version = cx.version.to_owned();
        std::thread::Builder::new()
            .name("doctor-schemas".to_owned())
            .stack_size(8 << 20)
            .spawn(move || expected_schemas(&options, &version))
    });
    let schemas_at = checks.len() + 1;
    if configuration_failed {
        checks.push(skipped("templates_fresh"));
        checks.push(skipped("schemas_fresh"));
    } else {
        checks.push(doctor.templates());
        checks.push(doctor.schemas());
    }
    let catalog_at = checks.len();
    checks.push(doctor.lsp_catalog());
    if configuration_failed {
        checks.push(skipped("platforms_enabled"));
    } else {
        checks.push(doctor.platforms());
    }
    checks.push(Check::new(
        "analysis_engine",
        "pass",
        format!(
            "The analysis engine (language server {}) loads",
            opentide_analysis::VERSION
        ),
    ));
    if configuration_failed {
        checks.push(skipped("credentials"));
        checks.push(skipped("connectivity"));
    } else {
        let tenants = doctor.tenants();
        checks.extend(doctor.credentials(&tenants));
        checks.extend(doctor.connectivity(live, &tenants));
    }
    // A run that was interrupted does not wait for the comparison.
    if let Some(started) = comparing
        && !(cx.interrupted)()
    {
        doctor.expected = Some(match started.map(std::thread::JoinHandle::join) {
            Ok(Ok(expected)) => expected,
            Ok(Err(_)) => Err("the comparison stopped unexpectedly".to_owned()),
            Err(error) => Err(error.to_string()),
        });
        checks[schemas_at] = doctor.schemas();
        checks[catalog_at] = doctor.lsp_catalog();
    }
    checks.push(doctor.proxy(offline));
    if configuration_failed {
        checks.push(skipped("vscode_settings"));
        checks.push(skipped("vscode_snippets"));
    } else {
        checks.extend(doctor.vscode());
    }
    checks.push(doctor.mcp());
    report(&checks, cx.text)
}

/// What `generate schemas` would write: the workspace opened as the
/// generator opens it (its visibility, statuses and enabled platforms shape
/// the schemas), the phase's outputs in memory.
fn expected_schemas(options: &RootOptions, version: &str) -> Result<Expected, String> {
    let workspace = super::open_for("doctor", options_for(options))
        .map_err(|report| report.outcome.message.clone())?;
    let root = workspace.root().to_path_buf();
    let outputs = phase_outputs("schemas", &workspace, &root, version)?;
    Ok(Expected { root, outputs })
}

/// `check_latest_version`: whether PyPI has a newer opentide.
fn latest_version(offline: bool, cx: &Context<'_>) -> Check {
    if offline {
        return Check::new("opentide_latest", "skip", "Not checked: --offline");
    }
    let environment = opentide_connectors::Environment::from_pairs(cx.env.iter());
    latest_check(network::fetch_latest(&environment, cx.proxy), cx.version)
}

/// The `opentide_latest` check for what asking PyPI gave.
fn latest_check(found: Result<String, network::Failed>, version: &str) -> Check {
    match found {
        Err(network::Failed::NoNetwork) => Check::new(
            "opentide_latest",
            "skip",
            "Not checked: this build of opentide has no network",
        ),
        Err(network::Failed::Problem(problem)) => Check::new(
            "opentide_latest",
            "warn",
            format!("Could not ask PyPI for the latest release ({problem})"),
        )
        .fix("check the network or --proxy, or pass --offline to skip network checks"),
        Ok(latest) if network::newer(&latest, version) => Check::new(
            "opentide_latest",
            "warn",
            format!("opentide {latest} is available; {version} is installed"),
        )
        .fix(network::UPGRADE_COMMAND),
        Ok(_) => Check::new(
            "opentide_latest",
            "pass",
            format!("No newer release on PyPI than {version}"),
        ),
    }
}

fn options_for(options: &RootOptions) -> RootOptions {
    RootOptions {
        repo: options.repo.clone(),
        repo_root_env: options.repo_root_env.clone(),
        tide_workspace_env: options.tide_workspace_env.clone(),
        cwd: options.cwd.clone(),
    }
}

/// `path` made absolute and resolved, as far as it exists.
fn resolve(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn posix(path: &Path) -> String {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
        .replacen("//", "/", 1)
}

impl Doctor<'_> {
    /// `path` as every path opentide prints it: relative to the current
    /// directory (`./` for it, `../..` above it), else relative to `base`
    /// when inside it, else absolute.
    fn shown(&self, path: &Path, base: Option<&Path>) -> String {
        let resolved = resolve(path);
        if resolved == self.cwd {
            return "./".to_owned();
        }
        if let Ok(inside) = resolved.strip_prefix(&self.cwd) {
            return posix(inside);
        }
        if let Ok(below) = self.cwd.strip_prefix(&resolved) {
            return vec![".."; below.components().count()].join("/");
        }
        if let Some(base) = base
            && let Ok(inside) = resolved.strip_prefix(resolve(base))
        {
            return posix(inside);
        }
        resolved.to_string_lossy().into_owned()
    }

    fn workspace_check(&self) -> Check {
        let shown = self.shown(&self.workspace, None);
        let how = if self.explicit {
            "set by --repo or OPENTIDE_REPO_ROOT"
        } else {
            "found from the current directory"
        };
        if !self.workspace.is_dir() {
            let problem = if self.workspace.exists() {
                "is not a directory"
            } else {
                "does not exist"
            };
            return Check::new(
                "workspace",
                "fail",
                format!("Workspace {shown} {problem} ({how})"),
            )
            .fix("set --repo or OPENTIDE_REPO_ROOT to your detection repository".to_owned());
        }
        // The command line refuses an `OPENTIDE_TIDE_WORKSPACE` that names no
        // folder; `doctor` runs anyway and reports it here (#1659).
        if let Some(tide) = self.tide_workspace.as_ref().filter(|tide| !tide.is_dir()) {
            let shown = self.shown(tide, None);
            let problem = if tide.exists() {
                "is not a directory"
            } else {
                "does not exist"
            };
            return Check::new(
                "workspace",
                "fail",
                format!("OPENTIDE_TIDE_WORKSPACE={shown} {problem}"),
            )
            .fix(
                "set OPENTIDE_TIDE_WORKSPACE to the folder whose objects are read, or unset it"
                    .to_owned(),
            );
        }
        if self.workspace.join(OPENTIDE_DIR).is_dir() {
            return Check::new(
                "workspace",
                "pass",
                format!("Workspace {shown} has {OPENTIDE_DIR}/ ({how})"),
            );
        }
        if self.workspace.join("objects").is_dir() {
            return Check::new(
                "workspace",
                "warn",
                format!("Workspace {shown} has objects/ but no {OPENTIDE_DIR}/ ({how})"),
            )
            .fix(format!("opentide setup repo --path {shown}"));
        }
        Check::new(
            "workspace",
            "fail",
            format!("No workspace at {shown}: no {OPENTIDE_DIR}/ or objects/ there or above it"),
        )
        .fix(format!(
            "opentide setup --path {shown}, or run from inside a workspace"
        ))
    }

    /// `git <args>` in the workspace: its trimmed output when it exits 0.
    fn git_output(&self, git: &Path, args: &[&str]) -> Option<String> {
        let output = Command::new(git)
            .args(args)
            .current_dir(&self.workspace)
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn git(&self) -> Vec<Check> {
        let path = self.cx.env.search_path().unwrap_or_default().to_owned();
        let Some(git) = on_path("git", &path, &self.cwd) else {
            return vec![
                Check::new(
                    "git",
                    "warn",
                    "git is not on PATH; changed-object detection and hooks need it",
                )
                .fix("install git"),
            ];
        };
        // WASI runs no program: git's version stays unknown, and the
        // repository is read with gix (`git_checkout`).
        if cfg!(target_os = "wasi") {
            let _ = git;
            return self.git_checkout();
        }
        let version = self
            .git_output(&git, &["--version"])
            .unwrap_or_else(|| "git".to_owned());
        let version = version
            .strip_prefix("git version ")
            .unwrap_or(&version)
            .to_owned();
        let found = self.git_output(&git, &["rev-parse", "--show-toplevel"]);
        let mut checks = vec![Check::new("git", "pass", format!("git {version}"))];
        let Some(found) = found else {
            let workspace = self.shown(&self.workspace, None);
            checks.push(
                Check::new(
                    "git_repository",
                    "warn",
                    format!("{workspace} is not in a git repository"),
                )
                .fix(format!("git init {workspace}")),
            );
            return checks;
        };
        let top = self.shown(Path::new(&found), None);
        if let Some(head) = self
            .git_output(
                &git,
                &["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"],
            )
            .filter(|head| !head.is_empty())
        {
            let branch = head.strip_prefix("refs/remotes/origin/").unwrap_or(&head);
            checks.push(Check::new(
                "git_repository",
                "pass",
                format!("Repository {top}, default branch {branch}"),
            ));
            return checks;
        }
        if self
            .git_output(&git, &["remote", "get-url", "origin"])
            .is_some()
        {
            checks.push(
                Check::new(
                    "git_repository",
                    "warn",
                    format!("Repository {top}: default branch unknown, origin/HEAD is not set"),
                )
                .fix("git remote set-head origin --auto"),
            );
        } else {
            let current = self
                .git_output(&git, &["branch", "--show-current"])
                .filter(|branch| !branch.is_empty())
                .unwrap_or_else(|| "detached HEAD".to_owned());
            checks.push(Check::new(
                "git_repository",
                "pass",
                format!("Repository {top} has no origin remote; on {current}"),
            ));
        }
        checks
    }

    /// `git` and `git_repository` without running git (the WASI build, which
    /// has no subprocesses): git was found on PATH, and the repository is
    /// read with gix, saying what `git` itself would.
    fn git_checkout(&self) -> Vec<Check> {
        let mut checks = vec![Check::new("git", "pass", GIT_VERSION_NOT_CHECKED)];
        let Some(checkout) = opentide_compile::git::checkout(&self.workspace) else {
            let workspace = self.shown(&self.workspace, None);
            checks.push(
                Check::new(
                    "git_repository",
                    "warn",
                    format!("{workspace} is not in a git repository"),
                )
                .fix(format!("git init {workspace}")),
            );
            return checks;
        };
        let top = self.shown(&checkout.top, None);
        checks.push(match (checkout.default_branch, checkout.has_origin) {
            (Some(branch), _) => Check::new(
                "git_repository",
                "pass",
                format!("Repository {top}, default branch {branch}"),
            ),
            (None, true) => Check::new(
                "git_repository",
                "warn",
                format!("Repository {top}: default branch unknown, origin/HEAD is not set"),
            )
            .fix("git remote set-head origin --auto"),
            (None, false) => Check::new(
                "git_repository",
                "pass",
                format!(
                    "Repository {top} has no origin remote; on {}",
                    checkout
                        .current_branch
                        .as_deref()
                        .unwrap_or("detached HEAD")
                ),
            ),
        });
        checks
    }

    /// The workspace's configuration TOMLs and its parent instance's, in
    /// load order: every `*.toml` under each folder, none in a hidden or
    /// private folder.
    fn configuration_files(&self) -> Vec<PathBuf> {
        let mut folders = vec![self.workspace.join(OPENTIDE_DIR).join("configurations")];
        if let Some(parent) = self.workspace.parent() {
            let theirs = parent.join(OPENTIDE_DIR).join("configurations");
            if !folders.contains(&theirs) {
                folders.push(theirs);
            }
        }
        let mut files = Vec::new();
        for folder in folders.iter().filter(|folder| folder.is_dir()) {
            let mut found = Vec::new();
            collect_toml(folder, &mut found);
            found.sort_by(|a, b| a.components().cmp(b.components()));
            files.extend(found);
        }
        files
    }

    fn configuration(&self, loaded: Result<(), ()>) -> Check {
        let files = self.configuration_files();
        if loaded.is_err() {
            for path in &files {
                let Some((line, reason)) = toml_problem(path) else {
                    continue;
                };
                let shown = self.shown(path, Some(&self.workspace));
                let at = match line {
                    Some(line) => format!("{shown} line {line}"),
                    None => shown,
                };
                return Check::new(
                    "configuration",
                    "fail",
                    format!("{at} is not valid TOML: {reason}"),
                )
                .fix(format!(
                    "fix {at}; the checks that read the configuration are skipped until then"
                ));
            }
            return Check::new(
                "configuration",
                "fail",
                "The configuration does not load (ConfigurationError)",
            )
            .fix("re-run with --debug for the traceback");
        }
        match files.len() {
            0 => Check::new(
                "configuration",
                "pass",
                "No workspace configuration: the defaults apply",
            ),
            1 => Check::new("configuration", "pass", "1 configuration file loads"),
            count => Check::new(
                "configuration",
                "pass",
                format!("{count} configuration files load"),
            ),
        }
    }

    fn node(&self, path: &[&str]) -> Option<&Node> {
        let mut current = self.config.as_ref()?;
        for key in path {
            current = current.get(key)?;
        }
        Some(current)
    }

    fn string(&self, path: &[&str]) -> Option<&str> {
        self.node(path)
            .and_then(|node| node.value.as_str())
            .filter(|value| !value.is_empty())
    }

    /// A configured folder or file, relative to the workspace.
    fn configured(&self, path: &[&str], default: &str) -> PathBuf {
        self.workspace.join(self.string(path).unwrap_or(default))
    }

    fn templates(&self) -> Check {
        let lint = match parse_lint_config(self.node(&["lint"])) {
            Ok(lint) => lint,
            Err(error) => {
                return Check::new(
                    "templates_fresh",
                    "warn",
                    format!("Templates not compared: {error}"),
                )
                .fix("fix the key lint.toml names, then run opentide doctor again");
            }
        };
        let options = Options {
            required_metadata: lint.required_metadata,
            indent: 0,
        };
        let folder = self.configured(
            &["paths", "paths", "opentide", "templates"],
            ".opentide/templates/",
        );
        let mut missing = Vec::new();
        let mut stale = Vec::new();
        for id in identifiers_for_families(&CORE_OBJECT_TYPES) {
            let name = template_artifact_name(&id);
            let target = folder.join(&name);
            if !target.is_file() {
                missing.push(name);
                continue;
            }
            let expected = object_template(&id.to_string(), &options).ok().flatten();
            let written = std::fs::read(&target).ok();
            let same = match (&expected, &written) {
                (Some(expected), Some(written)) => same_text(written, expected.as_bytes()),
                _ => false,
            };
            if !same {
                stale.push(name);
            }
        }
        let fix = "opentide generate templates schemas snippets";
        if !missing.is_empty() {
            return Check::new(
                "templates_fresh",
                "warn",
                format!(
                    "{} template(s) missing: {}",
                    missing.len(),
                    missing.join(", ")
                ),
            )
            .fix(fix);
        }
        if !stale.is_empty() {
            return Check::new(
                "templates_fresh",
                "warn",
                format!(
                    "{} template(s) differ from what this version generates: {}",
                    stale.len(),
                    stale.join(", ")
                ),
            )
            .fix(fix);
        }
        Check::new(
            "templates_fresh",
            "pass",
            "Templates match the installed version",
        )
    }

    fn schemas(&self) -> Check {
        let folder = self.configured(
            &["paths", "paths", "opentide", "schemas"],
            ".opentide/schemas/",
        );
        let mut names: Vec<String> = identifiers_for_families(&CORE_OBJECT_TYPES)
            .iter()
            .map(schema_artifact_name)
            .collect();
        for key in ["router", "visibility"] {
            if let Some(name) = self.string(&["paths", "artifacts", "schemas", key]) {
                names.push(name.to_owned());
            }
        }
        let mut unique: Vec<String> = Vec::new();
        for name in names {
            if !unique.contains(&name) {
                unique.push(name);
            }
        }
        let fix = "opentide generate schemas";
        let mut note = String::new();
        match &self.expected {
            Some(Ok(expected)) => {
                let Comparison {
                    checked,
                    missing,
                    differing,
                } = expected.compare(false);
                if !missing.is_empty() {
                    return Check::new(
                        "schemas_fresh",
                        "warn",
                        format!(
                            "{} schema(s) this version generates are missing: {}",
                            missing.len(),
                            missing.join(", ")
                        ),
                    )
                    .fix(fix);
                }
                if !differing.is_empty() {
                    return Check::new(
                        "schemas_fresh",
                        "warn",
                        format!(
                            "{} schema(s) differ from what `generate schemas` writes now \
                             (objects or configuration changed, or another version wrote \
                             them): {}",
                            differing.len(),
                            differing.join(", ")
                        ),
                    )
                    .fix(fix);
                }
                return Check::new(
                    "schemas_fresh",
                    "pass",
                    format!("Schemas match what `generate schemas` writes now ({checked})"),
                );
            }
            Some(Err(reason)) => {
                note = format!("; contents not compared, the workspace did not open: {reason}");
            }
            None => {}
        }
        let missing: Vec<&String> = unique
            .iter()
            .filter(|name| !folder.join(name.as_str()).is_file())
            .collect();
        if !missing.is_empty() {
            return Check::new(
                "schemas_fresh",
                "warn",
                format!(
                    "{} schema(s) this version generates are missing: {}",
                    missing.len(),
                    missing
                        .iter()
                        .map(|name| name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .fix("opentide generate schemas");
        }
        Check::new(
            "schemas_fresh",
            "pass",
            format!(
                "Every schema this version generates is present ({}){note}",
                unique.len()
            ),
        )
    }

    fn lsp_catalog(&self) -> Check {
        if !self.workspace.join(OPENTIDE_DIR).is_dir() {
            return Check::new("lsp_catalog", "skip", "Not checked: no workspace");
        }
        let folder = self
            .workspace
            .join(OPENTIDE_DIR)
            .join("lsp")
            .join("catalogs")
            .join("generated");
        let path = folder.join("fields.json");
        let version = self.cx.version;
        if path.is_file() {
            let shown = self.shown(&folder, Some(&self.workspace));
            let fix = "opentide generate schemas";
            let generated = std::fs::read_to_string(&path)
                .map_err(|error| error.to_string())
                .and_then(|text| {
                    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
                    serde_json::from_str::<JsonValue>(text).map_err(|error| error.to_string())
                });
            let generated = match generated {
                Ok(JsonValue::Object(map)) => match map.get("opentide") {
                    Some(JsonValue::String(text)) => text.clone(),
                    Some(JsonValue::Null | JsonValue::Bool(false)) | None => String::new(),
                    Some(other) => other.to_string(),
                },
                Ok(_) => {
                    return Check::new(
                        "lsp_catalog",
                        "warn",
                        format!("{shown}/fields.json does not parse: it is not an object"),
                    )
                    .fix(fix);
                }
                Err(error) => {
                    return Check::new(
                        "lsp_catalog",
                        "warn",
                        format!("{shown}/fields.json does not parse: {error}"),
                    )
                    .fix(fix);
                }
            };
            if !network::same(&generated, version) {
                let from = if generated.is_empty() {
                    "?"
                } else {
                    generated.as_str()
                };
                return Check::new(
                    "lsp_catalog",
                    "warn",
                    format!(
                        "The language-server catalog committed in {shown} is from opentide \
                         {from}, not {version}"
                    ),
                )
                .fix(fix);
            }
            if let Some(Ok(expected)) = &self.expected {
                let Comparison {
                    missing, differing, ..
                } = expected.compare(true);
                let mut problems = Vec::new();
                if !missing.is_empty() {
                    problems.push(format!("missing {}", missing.join(", ")));
                }
                if !differing.is_empty() {
                    problems.push(format!("differs: {}", differing.join(", ")));
                }
                if !problems.is_empty() {
                    return Check::new(
                        "lsp_catalog",
                        "warn",
                        format!(
                            "The language-server catalog committed in {shown} does not match \
                             what `generate schemas` writes now ({})",
                            problems.join("; ")
                        ),
                    )
                    .fix(fix);
                }
            }
        }
        Check::new(
            "lsp_catalog",
            "pass",
            format!("Language-server catalog compiled into opentide {version}"),
        )
    }

    /// The built-in platforms whose merged `[platform] enabled` is `true`
    /// ([`opentide_schema::configuration::resolve::enabled_platforms`]).
    fn enabled_platforms(&self) -> Vec<&'static str> {
        opentide_schema::configuration::resolve::enabled_platforms(self.node(&["platforms"]))
            .into_iter()
            .map(PlatformId::as_str)
            .collect()
    }

    fn platforms(&self) -> Check {
        let enabled = self.enabled_platforms();
        if enabled.is_empty() {
            return Check::new(
                "platforms_enabled",
                "warn",
                "No platform is enabled; rules validate but nothing deploys",
            )
            .fix("opentide setup platforms --sentinel (or another platform)");
        }
        Check::new(
            "platforms_enabled",
            "pass",
            format!("Enabled: {}", enabled.join(", ")),
        )
    }

    /// Each enabled platform's configured tenants, with the environment
    /// variables their `setup` names and which of them are unset: what
    /// `credentials` reports and `connectivity` reads, so the second runs on
    /// exactly the tenants the first found ready.
    fn tenants(&self) -> Vec<PlatformTenants> {
        let mut found = Vec::new();
        for platform in self.enabled_platforms() {
            let tenants: Vec<&Node> = match self
                .node(&["platforms", platform, "tenants"])
                .map(|node| &node.value)
            {
                Some(Value::Seq(items)) => items
                    .iter()
                    .map(AsRef::as_ref)
                    .filter(|tenant| matches!(tenant.value, Value::Map(_)))
                    .collect(),
                _ => Vec::new(),
            };
            let mut listed = Vec::new();
            for (index, tenant) in tenants.iter().enumerate() {
                let name = match tenant.get("name").map(|node| &node.value) {
                    Some(Value::Str(name)) if !name.is_empty() => name.to_string(),
                    Some(Value::Null | Value::Bool(false)) | None => {
                        format!("tenant {}", index + 1)
                    }
                    Some(Value::Str(_)) => format!("tenant {}", index + 1),
                    Some(other) => other.to_string(),
                };
                let mut variables: Vec<String> = Vec::new();
                if let Some(Value::Map(entries)) = tenant.get("setup").map(|node| &node.value) {
                    for entry in entries {
                        if let Some(name) = entry.value.value.as_str().and_then(env_reference)
                            && !variables.iter().any(|known| known == name)
                        {
                            variables.push(name.to_owned());
                        }
                    }
                }
                let unset = variables
                    .iter()
                    .filter(|variable| {
                        self.cx
                            .env
                            .get(variable)
                            .is_none_or(|value| value.is_empty())
                    })
                    .cloned()
                    .collect();
                let names_credentials = tenant
                    .get("setup")
                    .and_then(|setup| setup.get("credentials"))
                    .is_some_and(|node| !matches!(node.value, Value::Null));
                let adc_missing = platform == "google_secops"
                    && !names_credentials
                    && !opentide_connectors::google_secops::auth::has_local_default_credentials(
                        &opentide_connectors::Environment::from_pairs(self.cx.env.iter()),
                    );
                listed.push(TenantEnv {
                    subject: format!("{platform}/{name}"),
                    name,
                    variables,
                    unset,
                    adc_missing,
                    node: (*tenant).clone(),
                });
            }
            found.push(PlatformTenants {
                platform,
                tenants: listed,
            });
        }
        found
    }

    /// `credentials`: per configured tenant of an enabled platform, whether
    /// every variable its setup names is set. A variable that is not is
    /// reported, never a failure: most users hold no tenant secret locally
    /// (the CI runner does), so `doctor` does not fail on it.
    fn credentials(&self, platforms: &[PlatformTenants]) -> Vec<Check> {
        let mut checks = Vec::new();
        for PlatformTenants { platform, tenants } in platforms {
            if tenants.is_empty() {
                checks.push(
                    Check::new(
                        "credentials",
                        "skip",
                        format!("{platform}: no tenant configured"),
                    )
                    .fix(format!(
                        "add a [[tenants]] entry in \
                         {OPENTIDE_DIR}/configurations/platforms/{platform}.toml"
                    ))
                    .subject(*platform),
                );
                continue;
            }
            for tenant in tenants {
                let TenantEnv {
                    subject,
                    variables,
                    unset,
                    adc_missing,
                    ..
                } = tenant;
                let check = if *adc_missing && unset.is_empty() {
                    Check::new(
                        "credentials",
                        "warn",
                        format!(
                            "{subject}: no credentials: the tenant names none, \
                             {} is unset and there is no gcloud \
                             credentials file (a Google Cloud host's metadata server may still \
                             supply them)",
                            // Assembled where the connector assembles it (#1743).
                            opentide_connectors::google_secops::auth::credentials_variable()
                        ),
                    )
                    .fix(
                        "set `credentials` in the tenant's setup, or run \
                         gcloud auth application-default login",
                    )
                } else if !unset.is_empty() {
                    Check::new(
                        "credentials",
                        "warn",
                        format!(
                            "{subject}: {} of {} variables unset: {}",
                            unset.len(),
                            variables.len(),
                            unset.join(", ")
                        ),
                    )
                    .fix(format!(
                        "set {} in the environment (or a .env file you load)",
                        unset.join(", ")
                    ))
                } else if variables.is_empty() {
                    Check::new(
                        "credentials",
                        "pass",
                        format!("{subject}: setup names no environment variable"),
                    )
                } else {
                    Check::new(
                        "credentials",
                        "pass",
                        format!("{subject}: all {} variables set", variables.len()),
                    )
                };
                checks.push(check.subject(subject.clone()));
            }
        }
        checks
    }

    /// `connectivity` (`doctor --live`, #1658): for each tenant whose
    /// credentials are all set, opens it as `opentide deploy` does (its
    /// credentials resolved, its sign-in made) and makes the platform's one
    /// read-only request. A tenant without its credentials is skipped, not
    /// failed; one with them that cannot be reached, or whose credentials
    /// the tenant refuses, fails, naming the error's code. Nothing is
    /// written to a tenant.
    fn connectivity(&self, live: bool, platforms: &[PlatformTenants]) -> Vec<Check> {
        if !live {
            return vec![
                Check::new("connectivity", "skip", "Not checked: --live not set")
                    .fix("opentide doctor --live reaches each tenant whose credentials are set"),
            ];
        }
        if platforms.is_empty() {
            return vec![Check::new(
                "connectivity",
                "skip",
                "No platform is enabled: no tenant to reach",
            )];
        }
        let environment = opentide_connectors::Environment::from_pairs(self.cx.env.iter());
        let registry = opentide_connectors::builtin_with(&environment);
        let mut checks = Vec::new();
        for PlatformTenants { platform, tenants } in platforms {
            if tenants.is_empty() {
                checks.push(
                    Check::new(
                        "connectivity",
                        "skip",
                        format!("{platform}: no tenant configured"),
                    )
                    .subject(*platform),
                );
                continue;
            }
            for tenant in tenants {
                // After Ctrl-C no further tenant is contacted.
                let check = if (self.cx.interrupted)() {
                    Check::new(
                        "connectivity",
                        "skip",
                        format!("{}: not reached, interrupted", tenant.subject),
                    )
                } else {
                    self.reach(platform, tenant, &registry, &environment)
                };
                checks.push(check.subject(tenant.subject.clone()));
            }
        }
        checks
    }

    /// Opens `tenant` as a deploy does and runs its platform's read-only
    /// request, through the tenant's own client (its `ssl`, CA bundle,
    /// timeouts and the run's `--proxy`).
    fn probe(
        &self,
        platform: &str,
        tenant: &TenantEnv,
        prober: &dyn opentide_connectors::connector::Prober,
        environment: &opentide_connectors::Environment,
    ) -> Result<(), DeployError> {
        let setup = CJson::from_node(&tenant.node)
            .get("setup")
            .and_then(CJson::as_object)
            .cloned()
            .unwrap_or_default();
        let settings = opentide_connectors::deploy_http_settings(platform);
        Tenant::from_setup(
            platform,
            &tenant.name,
            &setup,
            environment,
            Resolve::Required,
            &settings,
        )
        .and_then(|connected| {
            HttpClient::new(
                &connected.label,
                &connected.http,
                environment,
                self.cx.proxy,
            )
            .map(|http| (connected, http))
        })
        .map_err(DeployError::from)
        .and_then(|(connected, http)| {
            let cancel = CancellationToken::new();
            let context = TenantContext {
                tenant: &connected,
                http: &http,
                cancel: &cancel,
            };
            opentide_connectors::runtime::sync_call(|| {
                opentide_connectors::runtime::block_on(watched(
                    async { Ok(prober.probe(context).await) },
                    &cancel,
                    self.cx.interrupted,
                ))
                .map(|watched| watched.map_err(DeployError::from).and_then(|probed| probed))
            })
            .unwrap_or_else(|_| Err("the check stopped unexpectedly".to_owned()))
            .unwrap_or_else(|message| {
                Err(DeployError::from(ConnectorError::Crashed {
                    platform: platform.to_owned(),
                    tenant: tenant.name.clone(),
                    message,
                }))
            })
        })
    }

    /// One tenant's `connectivity` check.
    fn reach(
        &self,
        platform: &str,
        tenant: &TenantEnv,
        registry: &opentide_connectors::Registry,
        environment: &opentide_connectors::Environment,
    ) -> Check {
        let subject = &tenant.subject;
        // What the platform can check comes first: a tenant of a platform
        // with no read-only request is never told to set variables, since
        // setting them would not make `--live` check it.
        let prober = opentide_schema::platforms::get(platform)
            .filter(|row| row.deploys)
            .and_then(|_| registry.get(platform))
            .and_then(|connector| connector.prober());
        let Some(prober) = prober else {
            return Check::new(
                "connectivity",
                "skip",
                format!(
                    "{subject}: not supported by doctor --live: {platform} has no read-only request to make"
                ),
            );
        };
        if !tenant.unset.is_empty() {
            return Check::new(
                "connectivity",
                "skip",
                format!(
                    "{subject}: not reached, credentials not set: {}",
                    tenant.unset.join(", ")
                ),
            )
            .fix(format!(
                "set {} in the environment, then run opentide doctor --live",
                tenant.unset.join(", ")
            ));
        }
        let outcome = self.probe(platform, tenant, prober, environment);
        match outcome {
            Ok(()) => Check::new(
                "connectivity",
                "pass",
                format!("{subject}: reached with its credentials"),
            ),
            // A setup key the tenant lacks is a credential that is not there
            // (a literal value was never written, or the key is absent):
            // skipped, as an unset variable is.
            Err(failed)
                if matches!(
                    failed.failure.code,
                    "credential_unset" | CREDENTIALS_UNAVAILABLE
                ) =>
            {
                Check::new(
                    "connectivity",
                    "skip",
                    format!("{subject}: not reached, {}", failed.failure.message),
                )
            }
            // Ctrl-C: the run ends interrupted, whatever this line says.
            Err(failed) if failed.failure.code == "interrupted" => Check::new(
                "connectivity",
                "skip",
                format!("{subject}: not reached, interrupted"),
            ),
            Err(failed) if failed.failure.code == "network_unavailable" => Check::new(
                "connectivity",
                "skip",
                format!("{subject}: not reached, this build of opentide has no network"),
            ),
            Err(failed) => Check::new(
                "connectivity",
                "fail",
                format!(
                    "{subject}: could not be reached ({}): {}",
                    failed.failure.code, failed.failure.message
                ),
            )
            .fix(format!(
                "check the tenant's address, the credentials of {} and the network or --proxy",
                tenant.name
            )),
        }
    }

    /// `check_proxy`: whether the proxy the connectors' requests go through
    /// accepts a TCP connection.
    fn proxy(&self, offline: bool) -> Check {
        let environment = opentide_connectors::Environment::from_pairs(self.cx.env.iter());
        let Some((url, http_only)) = network::proxy_to_test(&environment, self.cx.proxy) else {
            return Check::new(
                "proxy",
                "skip",
                "No proxy set (--proxy, OPENTIDE_PROXY, https_proxy, http_proxy, all_proxy)",
            );
        };
        let shown = redact_url(&url);
        if offline {
            return Check::new(
                "proxy",
                "skip",
                format!("Proxy {shown} not checked: --offline"),
            );
        }
        let note = if http_only {
            "; only http:// requests go through it"
        } else if network::bypasses_proxy(&environment, self.cx.proxy, network::PYPI_URL) {
            "; pypi.org bypasses it (NO_PROXY)"
        } else {
            ""
        };
        let parsed = match opentide_connectors::proxy::parse(&url) {
            Ok(parsed) => parsed,
            Err(reason) => {
                return Check::new(
                    "proxy",
                    "fail",
                    format!("The proxy URL cannot be parsed: {reason}"),
                )
                .fix("pass --proxy http://host:port");
            }
        };
        let host = match parsed.host() {
            Some(url::Host::Ipv6(address)) => address.to_string(),
            Some(host) => host.to_string(),
            None => String::new(),
        };
        if host.is_empty() {
            return Check::new("proxy", "fail", format!("Proxy {shown} has no host"))
                .fix("pass --proxy http://host:port");
        }
        let port = parsed.port_or_known_default().unwrap_or(80);
        // WASI has no sockets: the check would fail as if the name did not
        // resolve. The requests through the proxy are the client's to make.
        if cfg!(target_os = "wasi") {
            return Check::new(
                "proxy",
                "skip",
                format!(
                    "Proxy {shown} not checked: this build of opentide cannot open a connection"
                ),
            );
        }
        match network::connect(&host, port, network::NETWORK_TIMEOUT) {
            Ok(()) => Check::new(
                "proxy",
                "pass",
                format!("Proxy {shown} accepts connections{note}"),
            ),
            Err(name) => Check::new(
                "proxy",
                "fail",
                format!("Cannot connect to proxy {shown} ({name})"),
            )
            .fix(
                "check --proxy, OPENTIDE_PROXY, https_proxy or all_proxy, and that the proxy is up",
            ),
        }
    }

    fn snippet_file(&self) -> String {
        let configured = self
            .string(&["paths", "paths", "objects", "snippet_file"])
            .unwrap_or(".vscode/model-templates.code-snippets");
        let path = resolve(&self.workspace.join(configured));
        match path.strip_prefix(&self.workspace) {
            Ok(inside) => posix(inside),
            Err(_) => path.to_string_lossy().into_owned(),
        }
    }

    /// Object folders, workspace-relative, without a trailing `/`.
    fn object_folders(&self) -> Vec<String> {
        let families: Vec<String> = match self.node(&["paths", "objects"]).map(|node| &node.value) {
            Some(Value::Seq(items)) if !items.is_empty() => items
                .iter()
                .filter_map(|item| item.value.as_str().map(str::to_owned))
                .collect(),
            _ => CORE_OBJECT_TYPES
                .iter()
                .map(|&family| family.to_owned())
                .collect(),
        };
        families
            .iter()
            .map(|family| {
                self.string(&["paths", "paths", "objects", family])
                    .map_or_else(|| format!("objects/{family}s/"), str::to_owned)
                    .trim_end_matches('/')
                    .to_owned()
            })
            .collect()
    }

    fn router_schema_uri(&self) -> String {
        let name = self
            .string(&["paths", "artifacts", "schemas", "router"])
            .unwrap_or("opentide.schema.json");
        format!("{OPENTIDE_DIR}/schemas/{name}")
    }

    /// Whether a `yaml.schemas` entry is one an earlier `setup vscode` wrote.
    fn is_opentide_schema_mapping(&self, schema: &str, globs: &JsonValue) -> bool {
        let folders = self.object_folders();
        let schema = schema.strip_prefix("./").unwrap_or(schema);
        let values: Vec<&JsonValue> = match globs {
            JsonValue::String(_) => vec![globs],
            JsonValue::Array(items) => items.iter().collect(),
            _ => {
                return schema == self.router_schema_uri();
            }
        };
        let per_folder: Vec<String> = folders
            .iter()
            .flat_map(|folder| [format!("{folder}/**/*.yaml"), format!("{folder}/*.yaml")])
            .collect();
        if schema == self.router_schema_uri() {
            let mut generated = per_folder;
            generated.extend(object_glob(&folders));
            let ours = values.iter().any(|value| {
                value.as_str().is_some_and(|value| {
                    generated
                        .iter()
                        .any(|glob| glob == value.strip_prefix("./").unwrap_or(value))
                })
            });
            return values.is_empty() || ours;
        }
        let Some(rest) = schema.strip_prefix(&format!("{OPENTIDE_DIR}/schemas/")) else {
            return false;
        };
        let families: Vec<String> = match self.node(&["paths", "objects"]).map(|node| &node.value) {
            Some(Value::Seq(items)) if !items.is_empty() => items
                .iter()
                .filter_map(|item| item.value.as_str().map(str::to_owned))
                .collect(),
            _ => CORE_OBJECT_TYPES
                .iter()
                .map(|&family| family.to_owned())
                .collect(),
        };
        let revision = families.iter().any(|family| {
            rest.strip_prefix(family.as_str())
                .and_then(|rest| rest.strip_suffix(".schema.json"))
                .and_then(|rest| rest.strip_prefix('.'))
                .and_then(|rest| rest.split_once('.'))
                .is_some_and(|(major, minor)| {
                    [major, minor]
                        .iter()
                        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
                })
        });
        revision
            && !values.is_empty()
            && values.iter().all(|value| {
                value
                    .as_str()
                    .is_some_and(|value| per_folder.iter().any(|glob| glob == value))
            })
    }

    #[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
    fn vscode(&self) -> Vec<Check> {
        let mut checks = Vec::new();
        let settings = self.workspace.join(".vscode").join("settings.json");
        let extensions = self.workspace.join(".vscode").join("extensions.json");
        let data = if settings.is_file() {
            read_jsonc(&settings)
        } else {
            Some(JsonValue::Object(serde_json::Map::new()))
        };
        let mut mapped: Vec<String> = match data.as_ref().and_then(|data| data.get("yaml.schemas"))
        {
            Some(JsonValue::Object(schemas)) => schemas
                .iter()
                .filter(|(schema, globs)| self.is_opentide_schema_mapping(schema, globs))
                .map(|(schema, _)| schema.clone())
                .collect(),
            _ => Vec::new(),
        };
        mapped.sort();
        let recommended = if extensions.is_file() {
            read_jsonc(&extensions)
        } else {
            None
        };
        let listed = |key: &str| {
            recommended
                .as_ref()
                .and_then(|value| value.get(key))
                .and_then(JsonValue::as_array)
                .is_some_and(|items| items.iter().any(|item| item == EXTENSION_ID))
        };
        let check = if data.is_none() {
            Check::new(
                "vscode_settings",
                "warn",
                ".vscode/settings.json is not valid JSON",
            )
            .fix("fix the file, then opentide setup vscode")
        } else if !mapped.is_empty() {
            Check::new(
                "vscode_settings",
                "warn",
                format!(
                    ".vscode/settings.json maps objects to {} in yaml.schemas: a YAML extension \
                     would report what the opentide extension already does",
                    mapped.join(", ")
                ),
            )
            .fix("opentide setup vscode")
        } else if !extensions.is_file() {
            Check::new(
                "vscode_settings",
                "skip",
                format!("No .vscode/extensions.json: VS Code does not suggest {EXTENSION_ID}"),
            )
            .fix(INSTALL_EXTENSION_FIX)
        } else if recommended.is_none() {
            Check::new(
                "vscode_settings",
                "warn",
                ".vscode/extensions.json is not valid JSON",
            )
            .fix("fix the file, then opentide setup vscode")
        } else if listed("recommendations") {
            Check::new(
                "vscode_settings",
                "pass",
                format!(".vscode/extensions.json recommends {EXTENSION_ID}"),
            )
        } else if listed("unwantedRecommendations") {
            Check::new(
                "vscode_settings",
                "skip",
                format!(
                    ".vscode/extensions.json lists {EXTENSION_ID} under unwantedRecommendations"
                ),
            )
        } else {
            Check::new(
                "vscode_settings",
                "warn",
                format!(".vscode/extensions.json does not recommend {EXTENSION_ID}"),
            )
            .fix(INSTALL_EXTENSION_FIX)
        };
        checks.push(check);
        let snippets = self.snippet_file();
        if self.workspace.join(&snippets).is_file() {
            checks.push(Check::new(
                "vscode_snippets",
                "pass",
                format!("Snippets in {snippets}"),
            ));
        } else {
            checks.push(
                Check::new(
                    "vscode_snippets",
                    "skip",
                    format!("No snippets at {snippets}"),
                )
                .fix("opentide generate snippets"),
            );
        }
        checks
    }

    fn recommends_extension(&self) -> bool {
        let path = self.workspace.join(".vscode").join("extensions.json");
        path.is_file()
            && read_jsonc(&path)
                .as_ref()
                .and_then(|value| value.get("recommendations"))
                .and_then(JsonValue::as_array)
                .is_some_and(|items| items.iter().any(|item| item == EXTENSION_ID))
    }

    /// The server of Claude Desktop's configuration that runs `opentide mcp
    /// start` for this workspace (its `env.OPENTIDE_REPO_ROOT`). The file is
    /// the user's, not the repository's: a server for another workspace is
    /// none of this one's.
    fn claude_desktop_server(&self) -> Option<serde_json::Map<String, JsonValue>> {
        use crate::commands::setup::desktop::{Os, config_path, home};
        let os = Os::current();
        let path = config_path(os, self.cx.env, home(os, self.cx.env).as_deref())?;
        let data = read_jsonc(&path)?;
        let here = crate::commands::setup::real(&self.cwd.join(&self.workspace));
        let JsonValue::Object(servers) = data.get("mcpServers")? else {
            return None;
        };
        servers.values().find_map(|server| {
            let JsonValue::Object(server) = server else {
                return None;
            };
            let root = server
                .get("env")
                .and_then(|env| env.get("OPENTIDE_REPO_ROOT"))
                .and_then(JsonValue::as_str)
                .filter(|root| Path::new(root).is_absolute())?;
            (runs_mcp_start(server) && crate::commands::setup::real(Path::new(root)) == here)
                .then(|| server.clone())
        })
    }

    fn mcp(&self) -> Check {
        let mut hosts: Vec<&str> = Vec::new();
        let mut without: Vec<&str> = Vec::new();
        let mut commands: Vec<String> = Vec::new();
        for (host, relative) in MCP_OUTPUT_PATHS {
            let path = self.workspace.join(relative);
            if !path.is_file() {
                continue;
            }
            let Some(server) = read_jsonc(&path).and_then(|data| opentide_server(&data)) else {
                without.push(relative);
                continue;
            };
            hosts.push(host);
            let command = match server.get("command") {
                Some(JsonValue::String(text)) => text.clone(),
                Some(JsonValue::Null | JsonValue::Bool(false)) | None => String::new(),
                Some(other) => other.to_string(),
            };
            if !commands.contains(&command) {
                commands.push(command);
            }
        }
        if let Some(server) = self.claude_desktop_server() {
            hosts.push(crate::commands::setup::desktop::LABEL);
            let command = match server.get("command") {
                Some(JsonValue::String(text)) => text.clone(),
                _ => String::new(),
            };
            if !commands.contains(&command) {
                commands.push(command);
            }
        }
        let setup =
            "opentide setup mcp --vscode (or --cursor, --claude-code, --claude-desktop, --generic)";
        let extension = self.recommends_extension();
        if hosts.is_empty() && extension {
            return Check::new(
                "mcp_config",
                "pass",
                format!(
                    "VS Code: the opentide extension ({EXTENSION_ID}), which \
                     .vscode/extensions.json recommends, provides the opentide MCP server"
                ),
            );
        }
        if hosts.is_empty() {
            if !without.is_empty() {
                return Check::new(
                    "mcp_config",
                    "warn",
                    format!(
                        "{} has no opentide server running 'mcp start'",
                        without.join(", ")
                    ),
                )
                .fix(setup);
            }
            return Check::new(
                "mcp_config",
                "skip",
                "No MCP configuration: agents in editors cannot call opentide tools",
            )
            .fix(setup);
        }
        let mut configured = format!("MCP configured for {}", hosts.join(", "));
        if !without.is_empty() {
            configured.push_str(&format!(" ({} has no opentide server)", without.join(", ")));
        }
        if extension {
            configured.push_str(&format!(
                "; the opentide extension ({EXTENSION_ID}) also provides the server to VS Code"
            ));
        }
        let path = self.cx.env.search_path().unwrap_or_default().to_owned();
        let mut unresolved: Vec<String> = commands
            .into_iter()
            .filter(|command| !command.is_empty() && on_path(command, &path, &self.cwd).is_none())
            .collect();
        unresolved.sort();
        if !unresolved.is_empty() {
            return Check::new(
                "mcp_config",
                "warn",
                format!(
                    "{configured}, but {} is not on PATH for the editor to start",
                    unresolved.join(", ")
                ),
            )
            .fix("put opentide on PATH, or set the full path as the server command");
        }
        Check::new("mcp_config", "pass", configured)
    }
}

/// Every `*.toml` file under `dir`, at any depth, none in a folder whose
/// name starts with `.` or `__`. A link to a folder is entered, once: a link
/// that points back up ends. `.toml` is matched case-sensitively, on every
/// system: `CONFIG.TOML` is not read.
fn collect_toml(dir: &Path, out: &mut Vec<PathBuf>) {
    let hidden = |entry: &walkdir::DirEntry| {
        let name = entry.file_name().to_string_lossy();
        entry.depth() > 0
            && entry.file_type().is_dir()
            && (name.starts_with('.') || name.starts_with("__"))
    };
    out.extend(
        walkdir::WalkDir::new(dir)
            .min_depth(1)
            .follow_links(true)
            .into_iter()
            .filter_entry(|entry| !hidden(entry))
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().is_file()
                    && entry.file_name().to_string_lossy().ends_with(".toml")
            })
            .map(walkdir::DirEntry::into_path),
    );
}

/// The line and reason `path` does not parse as TOML, or `None` when it
/// does. The reason is the parser's description only, never the text
/// around it, which may hold a credential.
fn toml_problem(path: &Path) -> Option<(Option<usize>, String)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return Some((None, format!("it cannot be read ({:?})", error.kind()))),
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return Some((None, "it is not UTF-8".to_owned()));
    };
    match text.parse::<toml::Table>() {
        Ok(_) => None,
        Err(error) => {
            let line = error
                .span()
                // Newlines are single bytes: a span starting inside a
                // character counts the newlines before that character.
                .map(|span| {
                    text.bytes()
                        .take(span.start)
                        .filter(|byte| *byte == b'\n')
                        .count()
                        + 1
                });
            let reason = error
                .message()
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            Some((line, reason))
        }
    }
}

/// `url` without its user and password: `http://proxy:8080`; a URL that
/// cannot be read safely ([`opentide_connectors::proxy::parse`]) is not
/// shown at all.
fn redact_url(url: &str) -> String {
    opentide_connectors::proxy::redact(url).unwrap_or_else(|| "<unparseable proxy URL>".to_owned())
}

/// A JSON file as VS Code reads it (comments, trailing commas, a byte order
/// mark); `None` when it cannot be read.
fn read_jsonc(path: &Path) -> Option<JsonValue> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    jsonc_parser::parse_to_serde_value(text, &jsonc_parser::ParseOptions::default())
        .ok()
        .flatten()
}

/// The server of an MCP configuration that runs `opentide mcp start`.
fn opentide_server(data: &JsonValue) -> Option<serde_json::Map<String, JsonValue>> {
    for key in ["servers", "mcpServers"] {
        let Some(JsonValue::Object(servers)) = data.get(key) else {
            continue;
        };
        for server in servers.values() {
            let JsonValue::Object(server) = server else {
                continue;
            };
            if runs_mcp_start(server) {
                return Some(server.clone());
            }
        }
    }
    None
}

/// Whether an MCP server entry's `args` end in `mcp start`.
fn runs_mcp_start(server: &serde_json::Map<String, JsonValue>) -> bool {
    matches!(
        server.get("args"),
        Some(JsonValue::Array(args)) if args.len() >= 2
            && args[args.len() - 2] == "mcp"
            && args[args.len() - 1] == "start"
    )
}

/// One recursive glob over the object folders' common parent, or one per
/// folder when they share none.
fn object_glob(folders: &[String]) -> Vec<String> {
    let parent = |folder: &str| match folder.rsplit_once('/') {
        Some((parent, _)) => parent.to_owned(),
        None => ".".to_owned(),
    };
    let mut parents: Vec<String> = folders.iter().map(|folder| parent(folder)).collect();
    parents.sort();
    parents.dedup();
    if let [parent] = parents.as_slice()
        && !parent.is_empty()
        && parent != "."
    {
        return vec![format!("{parent}/**/*.yaml")];
    }
    folders
        .iter()
        .map(|folder| format!("{folder}/**/*.yaml"))
        .collect()
}

fn int(count: usize) -> Json {
    Json::Int(i64::try_from(count).unwrap_or(i64::MAX))
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else {
        format!("{count} {word}s")
    }
}

fn report(checks: &[Check], text: bool) -> Report {
    let count = |status: &str| checks.iter().filter(|check| check.status == status).count();
    let (passed, warned, failed, skipped) =
        (count("pass"), count("warn"), count("fail"), count("skip"));
    let mut rest = vec![format!("{passed} passed")];
    let (headline, status) = if failed > 0 {
        if warned > 0 {
            rest.push(plural(warned, "warning"));
        }
        (
            format!("{} failed", plural(failed, "check")),
            Status::Failed,
        )
    } else if warned > 0 {
        (plural(warned, "warning"), Status::Issues)
    } else {
        rest.clear();
        (
            format!("{} passed", plural(passed, "check")),
            Status::Completed,
        )
    };
    if skipped > 0 {
        rest.push(format!("{skipped} skipped"));
    }
    let message = if rest.is_empty() {
        headline
    } else {
        format!("{headline} {} {}", glyphs::SEPARATOR, rest.join(", "))
    };
    let data = vec![(
        "checks".to_owned(),
        Json::Array(checks.iter().map(Check::to_json).collect()),
    )];
    let mut report = Report::completed(COMMAND, data);
    report.outcome.status = status;
    report.outcome.message.clone_from(&message);
    report.outcome.summary = Object::from([
        ("checks".to_owned(), int(checks.len())),
        ("passed".to_owned(), int(passed)),
        ("warnings".to_owned(), int(warned)),
        ("failed".to_owned(), int(failed)),
        ("skipped".to_owned(), int(skipped)),
    ]);
    if failed > 0 {
        report.outcome.exit_code = ExitCode::Failure;
        report.outcome.failure = Some(Failure::new(CHECKS_FAILED, message));
    }
    if text {
        report.body = vec![Block::Hanging(checks.iter().flat_map(lines).collect())];
    }
    report
}

/// A check's line, and its fix underneath when there is something to do,
/// each with the indent its wrapped rows take.
fn lines(check: &Check) -> Vec<(Text, usize)> {
    let (glyph, style) = match check.status {
        "pass" => (glyphs::OK, AnsiColor::Green.on_default().bold()),
        "fail" => (glyphs::FAILED, AnsiColor::Red.on_default().bold()),
        "skip" => (glyphs::SKIP, Style::new().bold().dimmed()),
        _ => (glyphs::WARNING, AnsiColor::Yellow.on_default().bold()),
    };
    let mut line = Text::default();
    line.append(glyph, &style);
    line.push_str(" ");
    line.push_str(&check.message);
    line.append(
        &format!(" {} {}", glyphs::SEPARATOR, check.code),
        &Style::new().dimmed(),
    );
    let mut out = vec![(line, 2)];
    if let Some(fix) = &check.fix
        && matches!(check.status, "warn" | "fail" | "skip")
    {
        let mut hint = Text::plain("  ");
        hint.append(
            &format!("{} ", glyphs::NEXT),
            &AnsiColor::Cyan.on_default().bold(),
        );
        if check.status == "skip" {
            hint.append(fix, &Style::new().dimmed());
        } else {
            hint.push_str(fix);
        }
        out.push((hint, 4));
    }
    out
}

/// The `git` check's message where git cannot be run (WASI).
pub const GIT_VERSION_NOT_CHECKED: &str =
    "git found; version not checked (no subprocesses under WASI)";

/// The program `name` resolves to on `path` (a `PATH` value), relative to
/// `cwd`, as a shell finds it.
#[cfg(not(target_os = "wasi"))]
pub(crate) fn on_path(name: &str, path: &str, cwd: &std::path::Path) -> Option<std::path::PathBuf> {
    which::which_in(name, Some(path), cwd).ok()
}

/// WASI: `std::env::split_paths`, which `which` reads `PATH` with, is not
/// implemented there (it panics), so the search is done here: `:`-separated
/// folders, the first that holds a file of that name (WASI has no execute
/// bit to check).
#[cfg(target_os = "wasi")]
pub(crate) fn on_path(name: &str, path: &str, cwd: &std::path::Path) -> Option<std::path::PathBuf> {
    let candidate = std::path::Path::new(name);
    if candidate.components().count() > 1 {
        let found = cwd.join(candidate);
        return found.is_file().then_some(found);
    }
    path.split(':')
        .filter(|folder| !folder.is_empty())
        .map(|folder| cwd.join(folder).join(name))
        .find(|found| found.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_toml_problem_after_multi_byte_text_is_on_its_line() {
        // #1946: the line counts newlines up to the error, wherever the
        // multi-byte characters before it are.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.toml");
        std::fs::write(&path, "# é😀\nnom = \"é😀\"\n😀 = 1\n").unwrap();
        let (line, reason) = toml_problem(&path).expect("invalid TOML");
        assert_eq!(line, Some(3), "{reason}");
        std::fs::write(&path, "nom = \"é😀\"\nclé = \"é😀").unwrap();
        assert_eq!(toml_problem(&path).expect("invalid TOML").0, Some(2));
        std::fs::write(&path, "nom = \"é😀\"\n").unwrap();
        assert_eq!(toml_problem(&path), None);
    }

    fn context<'a>(env: &'a Env, cwd: &'a Path) -> Context<'a> {
        Context {
            repo: None,
            env,
            cwd,
            version: "9.9.9",
            text: false,
            proxy: None,
            interrupted: &|| false,
        }
    }

    /// The checklist reads the platforms every other command reads: the
    /// resolved `platforms` table, which the 0.x `systems.toml` merges into
    /// (#1935).
    #[test]
    fn enabled_platforms_and_their_tenants_come_from_the_platforms_table() {
        use opentide_schema::configuration::resolve::{Folder, Instance, resolve};
        let env = Env::default();
        let dir = tempfile::tempdir().unwrap();
        let cx = context(&env, dir.path());
        for (file, text) in [
            (
                "systems.toml",
                "[splunk.platform]\nenabled = true\n[[splunk.tenants]]\nname = 'é😀'\n",
            ),
            (
                "platforms/splunk.toml",
                "[platform]\nenabled = true\n[[tenants]]\nname = 'é😀'\n",
            ),
        ] {
            let folder = Folder {
                path: "/w/.opentide/configurations".to_owned(),
                files: vec![(file.to_owned(), text.to_owned())],
                folders: vec!["platforms".to_owned()],
            };
            let tree = resolve(&Instance {
                workspace: Some(&folder),
                ..Instance::default()
            })
            .unwrap()
            .tree;
            // `systems` merges into `platforms`, the only table the tree holds.
            assert!(tree.get("systems").is_none(), "{file}");
            let doctor = Doctor {
                cx: &cx,
                workspace: dir.path().to_path_buf(),
                explicit: false,
                cwd: dir.path().to_path_buf(),
                tide_workspace: None,
                config: Some(tree),
                expected: None,
            };
            assert_eq!(doctor.enabled_platforms(), ["splunk"], "{file}");
            let tenants = doctor.tenants();
            assert_eq!(tenants.len(), 1, "{file}");
            assert_eq!(tenants[0].tenants.len(), 1, "{file}");
        }
    }

    fn checks(report: &Report) -> Vec<(String, String, String)> {
        let Some(Json::Array(items)) = report.outcome.data.get("checks") else {
            panic!("no checks");
        };
        items
            .iter()
            .map(|item| {
                let Json::Object(members) = item else {
                    panic!("a check is an object")
                };
                let get = |key: &str| match &members[key] {
                    Json::Str(text) => text.clone(),
                    _ => String::new(),
                };
                (get("code"), get("status"), get("message"))
            })
            .collect()
    }

    #[test]
    fn the_flags_pick_one_mode() {
        let mode = |offline, live| DoctorMode::from(&crate::tree::DoctorArgs { offline, live });
        assert_eq!(mode(false, false), DoctorMode::Default);
        assert_eq!(mode(true, false), DoctorMode::Offline);
        assert_eq!(mode(false, true), DoctorMode::Live);
    }

    #[test]
    fn a_build_without_a_network_skips_the_pypi_check() {
        // The WASI build outside a serve whose client makes its requests.
        let check = latest_check(Err(network::Failed::NoNetwork), "1.0.0");
        assert_eq!(
            (check.status, check.message.as_str()),
            ("skip", "Not checked: this build of opentide has no network")
        );
        assert!(check.fix.is_none());
        // Any other failure is still a warning that names it.
        let check = latest_check(
            Err(network::Failed::Problem("PyPI answered HTTP 503".into())),
            "1.0.0",
        );
        assert_eq!(check.status, "warn");
        assert_eq!(
            check.message,
            "Could not ask PyPI for the latest release (PyPI answered HTTP 503)"
        );
    }

    #[test]
    fn without_offline_it_asks_pypi_and_the_proxy() {
        // A port nothing listens on: the proxy refuses, so nothing leaves
        // this machine.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);
        let env = Env::from_pairs([("HTTPS_PROXY".to_owned(), proxy.clone())]);
        let dir = tempfile::tempdir().unwrap();
        let report = run(DoctorMode::Default, &context(&env, dir.path()));
        let found = checks(&report);
        let latest = found
            .iter()
            .find(|(code, ..)| code == "opentide_latest")
            .unwrap();
        assert_eq!(latest.1, "warn");
        // The HTTP client's words: the tenant it could not reach, and why.
        assert!(
            latest
                .2
                .starts_with("Could not ask PyPI for the latest release (Cannot reach pypi"),
            "{}",
            latest.2
        );
        let checked = found.iter().find(|(code, ..)| code == "proxy").unwrap();
        assert_eq!(checked.1, "fail");
        // The operating system's words for the refused connection.
        assert!(
            checked
                .2
                .starts_with(&format!("Cannot connect to proxy {proxy} (")),
            "{}",
            checked.2
        );
        assert!(
            checked.2.to_lowercase().contains("refused"),
            "{}",
            checked.2
        );
    }

    /// A committed catalog from another opentide warns, naming both versions
    /// and nothing that reads it (#1684); one from this opentide, or none,
    /// passes.
    #[test]
    fn a_committed_catalog_from_another_opentide_warns() {
        let env = Env::default();
        let dir = tempfile::tempdir().unwrap();
        let generated = dir.path().join(".opentide/lsp/catalogs/generated");
        std::fs::create_dir_all(&generated).unwrap();
        let cx = context(&env, dir.path());
        let doctor = Doctor {
            cx: &cx,
            workspace: dir.path().to_path_buf(),
            explicit: false,
            cwd: dir.path().to_path_buf(),
            tide_workspace: None,
            config: None,
            expected: None,
        };
        assert_eq!(doctor.lsp_catalog().status, "pass");
        std::fs::write(generated.join("fields.json"), r#"{"opentide": "0.18.0"}"#).unwrap();
        let check = doctor.lsp_catalog();
        assert_eq!(check.status, "warn");
        assert_eq!(
            check.message,
            "The language-server catalog committed in .opentide/lsp/catalogs/generated is from \
             opentide 0.18.0, not 9.9.9"
        );
        std::fs::write(generated.join("fields.json"), r#"{"opentide": "9.9.9"}"#).unwrap();
        assert_eq!(doctor.lsp_catalog().status, "pass");
    }

    /// The Python package spells a candidate `1.0.0rc1`, the crates and the
    /// binaries `1.0.0-rc.1`: one release, so a catalog one of them committed
    /// passes in the other (RC1-3); another release warns whatever its spelling.
    #[test]
    fn a_catalog_from_the_same_release_in_the_other_spelling_passes() {
        let env = Env::default();
        let dir = tempfile::tempdir().unwrap();
        let generated = dir.path().join(".opentide/lsp/catalogs/generated");
        std::fs::create_dir_all(&generated).unwrap();
        for (running, committed, status) in [
            ("1.0.0-rc.1", "1.0.0rc1", "pass"),
            ("1.0.0rc1", "1.0.0-rc.1", "pass"),
            ("1.0.0-rc.1", "1.0.0-rc.1", "pass"),
            ("1.0.0-rc.1", "1.0.0rc2", "warn"),
            ("1.0.0-rc.1", "1.0.0", "warn"),
        ] {
            let cx = Context {
                version: running,
                ..context(&env, dir.path())
            };
            let doctor = Doctor {
                cx: &cx,
                workspace: dir.path().to_path_buf(),
                explicit: false,
                cwd: dir.path().to_path_buf(),
                tide_workspace: None,
                config: None,
                expected: None,
            };
            std::fs::write(
                generated.join("fields.json"),
                format!(r#"{{"opentide": "{committed}"}}"#),
            )
            .unwrap();
            let check = doctor.lsp_catalog();
            assert_eq!(check.status, status, "{committed} under {running}");
        }
    }

    #[test]
    fn a_proxy_that_accepts_passes_and_names_a_no_proxy_bypass() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let env = Env::from_pairs([("NO_PROXY".to_owned(), "pypi.org".to_owned())]);
        let dir = tempfile::tempdir().unwrap();
        let cx = Context {
            proxy: Some(&proxy),
            ..context(&env, dir.path())
        };
        let doctor = Doctor {
            cx: &cx,
            workspace: dir.path().to_path_buf(),
            explicit: false,
            cwd: dir.path().to_path_buf(),
            tide_workspace: None,
            config: None,
            expected: None,
        };
        let check = doctor.proxy(false);
        assert_eq!(check.status, "pass");
        assert_eq!(
            check.message,
            format!("Proxy {proxy} accepts connections; pypi.org bypasses it (NO_PROXY)")
        );
        let unparsed = Context {
            proxy: Some("ht tp://x"),
            ..context(&env, dir.path())
        };
        let doctor = Doctor {
            cx: &unparsed,
            ..doctor
        };
        let check = doctor.proxy(false);
        assert_eq!(
            (check.status, check.message.as_str()),
            (
                "fail",
                "The proxy URL cannot be parsed: relative URL without a base"
            )
        );
        let hostless = Context {
            proxy: Some("http://:8080"),
            ..context(&env, dir.path())
        };
        let doctor = Doctor {
            cx: &hostless,
            ..doctor
        };
        let check = doctor.proxy(false);
        assert_eq!(
            (check.status, check.message.as_str()),
            ("fail", "The proxy URL cannot be parsed: empty host")
        );
    }

    #[test]
    fn an_empty_folder_fails_the_workspace_check() {
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let dir = tempfile::tempdir().unwrap();
        let report = run(DoctorMode::Offline, &context(&env, dir.path()));
        let found = checks(&report);
        let workspace = found.iter().find(|(code, ..)| code == "workspace").unwrap();
        assert_eq!(workspace.1, "fail");
        assert!(
            workspace.2.starts_with("No workspace at ./"),
            "{workspace:?}"
        );
        assert_eq!(report.outcome.exit_code, ExitCode::Failure);
        assert_eq!(report.outcome.status, Status::Failed);
        assert_eq!(report.outcome.failure.unwrap().code, CHECKS_FAILED);
        let codes: Vec<&str> = found.iter().map(|(code, ..)| code.as_str()).collect();
        assert_eq!(
            codes[..3],
            ["opentide_version", "opentide_latest", "workspace"]
        );
        assert!(codes.contains(&"mcp_config"));
        // Neither Python check is run (UC-6.0d, #841).
        assert!(!codes.contains(&"python_version"));
        assert!(!codes.contains(&"platform_sdk"));
    }

    #[test]
    fn a_workspace_reports_templates_schemas_and_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("elastic.toml"),
            "[platform]\nenabled = true\n\n[[tenants]]\nname = \"prod\"\n[tenants.setup]\napi_key = \"$ELASTIC_KEY\"\nurl = \"https://example\"\n",
        )
        .unwrap();
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let report = run(DoctorMode::Offline, &context(&env, dir.path()));
        let found = checks(&report);
        let get = |code: &str| {
            found
                .iter()
                .filter(|(c, ..)| c == code)
                .map(|(_, status, message)| (status.as_str(), message.as_str()))
                .collect::<Vec<_>>()
        };
        assert_eq!(get("workspace")[0].0, "pass");
        assert_eq!(
            get("configuration"),
            [("pass", "1 configuration file loads")]
        );
        assert_eq!(get("platforms_enabled"), [("pass", "Enabled: elastic")]);
        assert!(get("platform_sdk").is_empty());
        assert_eq!(
            get("credentials"),
            [("warn", "elastic/prod: 1 of 1 variables unset: ELASTIC_KEY")]
        );
        assert_eq!(get("templates_fresh")[0].0, "warn");
        assert!(
            get("templates_fresh")[0]
                .1
                .starts_with("4 template(s) missing")
        );
        assert_eq!(get("schemas_fresh")[0].0, "warn");
        assert_eq!(report.outcome.status, Status::Issues);
        assert_eq!(report.outcome.exit_code, ExitCode::Success);
    }

    #[test]
    fn templates_this_version_writes_are_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let templates = dir.path().join(".opentide/templates");
        std::fs::create_dir_all(&templates).unwrap();
        let options = Options {
            required_metadata: parse_lint_config(None).unwrap().required_metadata,
            indent: 0,
        };
        for id in identifiers_for_families(&CORE_OBJECT_TYPES) {
            let text = object_template(&id.to_string(), &options).unwrap().unwrap();
            std::fs::write(templates.join(template_artifact_name(&id)), text).unwrap();
        }
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let found = checks(&run(DoctorMode::Offline, &context(&env, dir.path())));
        let fresh = found
            .iter()
            .find(|(code, ..)| code == "templates_fresh")
            .unwrap();
        assert_eq!(fresh.1, "pass", "{fresh:?}");
        // One byte off is stale.
        let first = identifiers_for_families(&CORE_OBJECT_TYPES)[0].clone();
        let path = templates.join(template_artifact_name(&first));
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        let found = checks(&run(DoctorMode::Offline, &context(&env, dir.path())));
        let stale = found
            .iter()
            .find(|(code, ..)| code == "templates_fresh")
            .unwrap();
        assert_eq!(stale.1, "warn");
        assert!(stale.2.starts_with("1 template(s) differ"), "{stale:?}");
    }

    const OBJECTIVE: &str = "name: Shared Objective\n\nmetadata:\n  uuid: \
        00000000-0000-4000-8048-000000000002\n  schema: objective::1.0\n  version: 3\n  \
        created: 2026-01-01\n  modified: 2026-01-02\n  tlp: green\n  pap: green\n\n\
        objective:\n  priority: High\n  type: Threat\n  description: An objective.\n";

    /// A workspace with a non-default configuration (two responder teams) and
    /// an objective, on which the real `generate schemas` has run.
    fn generated_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let configurations = dir.path().join(".opentide/configurations");
        std::fs::create_dir_all(&configurations).unwrap();
        std::fs::write(
            configurations.join("deployment.toml"),
            "[[responders]]\nname = \"Blue Team\"\ndescription = \"Triage\"\n\n\
             [[responders]]\nname = \"Red Team\"\ndescription = \"Hunt\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("objects/objectives")).unwrap();
        std::fs::write(dir.path().join("objects/objectives/shared.yaml"), OBJECTIVE).unwrap();
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let cx = super::super::generate::Context {
            repo: None,
            env: &env,
            cwd: dir.path(),
            proxy: None,
            version: "9.9.9",
        };
        let report = super::super::generate::phases(&["schemas".to_owned()], &cx, "9.9.9");
        assert_eq!(
            report.outcome.exit_code,
            ExitCode::Success,
            "{}",
            report.outcome.message
        );
        dir
    }

    fn find_check(dir: &Path, code: &str) -> (String, String, String) {
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        checks(&run(DoctorMode::Offline, &context(&env, dir)))
            .into_iter()
            .find(|(found, ..)| found == code)
            .unwrap()
    }

    #[test]
    fn schemas_the_generator_just_wrote_are_fresh_until_an_object_changes() {
        let dir = generated_workspace();
        let schemas = find_check(dir.path(), "schemas_fresh");
        assert_eq!(schemas.1, "pass", "{schemas:?}");
        assert_eq!(
            find_check(dir.path(), "lsp_catalog").1,
            "pass",
            "{:?}",
            find_check(dir.path(), "lsp_catalog")
        );
        // The objective's name is in the rule schema's `detection_model`
        // values: renaming it makes the schemas on disk stale.
        let object = dir.path().join("objects/objectives/shared.yaml");
        std::fs::write(&object, OBJECTIVE.replace("Shared Objective", "Renamed")).unwrap();
        let stale = find_check(dir.path(), "schemas_fresh");
        assert_eq!(stale.1, "warn", "{stale:?}");
        assert!(
            stale
                .2
                .contains("differ from what `generate schemas` writes now")
        );
        assert!(stale.2.contains("rule."), "{stale:?}");
    }

    #[test]
    fn schemas_with_crlf_line_endings_and_a_byte_order_mark_are_still_fresh() {
        let dir = generated_workspace();
        for folder in [".opentide/schemas", ".opentide/lsp/catalogs/generated"] {
            for entry in std::fs::read_dir(dir.path().join(folder)).unwrap() {
                let path = entry.unwrap().path();
                if !path.is_file() {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let mut bytes = b"\xEF\xBB\xBF".to_vec();
                bytes.extend(text.replace('\n', "\r\n").into_bytes());
                std::fs::write(&path, bytes).unwrap();
            }
        }
        assert_eq!(find_check(dir.path(), "schemas_fresh").1, "pass");
        assert_eq!(find_check(dir.path(), "lsp_catalog").1, "pass");
    }

    #[test]
    fn a_committed_catalog_with_a_file_missing_warns() {
        let dir = generated_workspace();
        let generated = dir.path().join(".opentide/lsp/catalogs/generated");
        std::fs::remove_file(generated.join("deprecations.json")).unwrap();
        let check = find_check(dir.path(), "lsp_catalog");
        assert_eq!(check.1, "warn", "{check:?}");
        assert!(check.2.contains("missing deprecations.json"), "{check:?}");
    }

    #[test]
    fn same_text_ignores_a_byte_order_mark_and_crlf_only() {
        assert!(same_text(b"a\r\nb\n", b"a\nb\n"));
        assert!(same_text(b"\xEF\xBB\xBFa\n", b"a\n"));
        assert!(!same_text(b"a\rb\n", b"a\nb\n"));
        assert!(!same_text(b"a\nb ", b"a\nb"));
    }

    #[test]
    fn a_broken_configuration_names_the_file_and_line_and_skips_its_readers() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".opentide/configurations");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("lint.toml"), "[metadata]\nrequired = [\n").unwrap();
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let found = checks(&run(DoctorMode::Offline, &context(&env, dir.path())));
        let configuration = found
            .iter()
            .find(|(code, ..)| code == "configuration")
            .unwrap();
        assert_eq!(configuration.1, "fail");
        assert!(
            configuration
                .2
                .starts_with(".opentide/configurations/lint.toml line "),
            "{configuration:?}"
        );
        for code in [
            "templates_fresh",
            "schemas_fresh",
            "platforms_enabled",
            "vscode_settings",
        ] {
            let check = found.iter().find(|(c, ..)| c == code).unwrap();
            assert_eq!(check.1, "skip", "{code}");
            assert_eq!(check.2, "Not checked: the configuration does not load");
        }
    }

    #[test]
    fn proxies_are_shown_without_credentials() {
        assert_eq!(
            redact_url("http://user:p%40ss%2Fw%23rd@proxy:8080"),
            "http://proxy:8080"
        );
        assert_eq!(redact_url("proxy.example"), "http://proxy.example");
        assert_eq!(redact_url("ht tp://x"), "<unparseable proxy URL>");
        // An unencoded `@` in the password: the last `@` ends the user info.
        assert_eq!(
            redact_url("http://user:p@ss@proxy:8080"),
            "http://proxy:8080"
        );
        // An unencoded `/`, `#` or `?` ends the host early, where the url
        // crate would read a piece of the password as the host: not shown.
        for unsafe_url in [
            "http://user:p@ss/w#rd@proxy:8080",
            "http://user:pa/ss@proxy:8080",
            "http://user:pa#ss@proxy:8080",
            "http://user:pa?ss@proxy:8080",
            "user:pa/ss@proxy:8080",
        ] {
            assert_eq!(
                redact_url(unsafe_url),
                "<unparseable proxy URL>",
                "{unsafe_url}"
            );
        }
    }

    /// The `proxy` check of a run with *env* and `--proxy` *flag*.
    fn proxy_check(env: &[(&str, &str)], flag: Option<&str>) -> Check {
        let env = Env::from_pairs(
            env.iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        );
        let dir = tempfile::tempdir().unwrap();
        let cx = Context {
            proxy: flag,
            ..context(&env, dir.path())
        };
        let doctor = Doctor {
            cx: &cx,
            workspace: dir.path().to_path_buf(),
            explicit: false,
            cwd: dir.path().to_path_buf(),
            tide_workspace: None,
            config: None,
            expected: None,
        };
        doctor.proxy(false)
    }

    #[test]
    fn the_proxy_checked_is_the_one_the_connectors_use() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let up = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let down = format!("http://127.0.0.1:{}", closed.local_addr().unwrap().port());
        drop(closed);
        let passes = |env: &[(&str, &str)], flag: Option<&str>| {
            let check = proxy_check(env, flag);
            assert_eq!(
                (check.status, check.message.as_str()),
                ("pass", format!("Proxy {up} accepts connections").as_str()),
                "{env:?} {flag:?}"
            );
        };
        // `OPENTIDE_PROXY` wins over the scheme variables, as `--proxy` does.
        passes(&[("OPENTIDE_PROXY", &up), ("HTTPS_PROXY", &down)], None);
        passes(&[("OPENTIDE_PROXY", &down)], Some(&up));
        // `all_proxy` (else `ALL_PROXY`) when no scheme variable is set.
        passes(&[("all_proxy", &up)], None);
        passes(&[("ALL_PROXY", &up)], None);
        passes(&[("all_proxy", &down), ("HTTPS_PROXY", &up)], None);
        // The lower-case spelling first, as curl and the connectors read them.
        passes(&[("https_proxy", &up), ("HTTPS_PROXY", &down)], None);
        // `https_proxy` before `http_proxy`: PyPI and the tenants are https.
        passes(&[("http_proxy", &down), ("HTTPS_PROXY", &up)], None);
        // Only `http_proxy`: an https request goes direct, so it says so.
        let check = proxy_check(&[("http_proxy", &up)], None);
        assert_eq!(
            (check.status, check.message),
            (
                "pass",
                format!("Proxy {up} accepts connections; only http:// requests go through it")
            )
        );
        let check = proxy_check(&[("HTTP_PROXY", ""), ("NO_PROXY", "*")], None);
        assert_eq!(
            (check.status, check.message.as_str()),
            (
                "skip",
                "No proxy set (--proxy, OPENTIDE_PROXY, https_proxy, http_proxy, all_proxy)"
            )
        );
    }

    #[test]
    fn a_proxy_whose_password_hides_its_host_is_never_echoed() {
        let check = proxy_check(
            &[("HTTPS_PROXY", "http://al1ce:Qz7k/Wm4r@proxy:8080")],
            None,
        );
        assert_eq!(check.status, "fail");
        assert!(
            check
                .message
                .starts_with("The proxy URL cannot be parsed: an `@` follows a `/`"),
            "{}",
            check.message
        );
        for fragment in ["al1ce", "Qz7k", "Wm4r", "proxy:8080"] {
            assert!(!check.message.contains(fragment), "{}", check.message);
        }
    }

    #[test]
    fn mcp_and_vscode_files_are_read_as_jsonc() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".opentide")).unwrap();
        std::fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        std::fs::write(
            dir.path().join(".vscode/extensions.json"),
            "{\n  // ours\n  \"recommendations\": [\"opentidehq.opentide\",],\n}\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".mcp.json"),
            "{\"mcpServers\": {\"x\": {\"command\": \"no-such-opentide\", \"args\": [\"mcp\", \"start\"]}}}",
        )
        .unwrap();
        let env = Env::from_pairs([("PATH", "/nonexistent")]);
        let found = checks(&run(DoctorMode::Offline, &context(&env, dir.path())));
        let settings = found.iter().find(|(c, ..)| c == "vscode_settings").unwrap();
        assert_eq!(settings.1, "pass");
        let mcp = found.iter().find(|(c, ..)| c == "mcp_config").unwrap();
        assert_eq!(mcp.1, "warn");
        assert!(mcp.2.contains("MCP configured for Claude Code"), "{mcp:?}");
        assert!(mcp.2.contains("no-such-opentide is not on PATH"), "{mcp:?}");
        let git = found.iter().find(|(c, ..)| c == "git").unwrap();
        assert_eq!(git.1, "warn");
    }

    #[test]
    fn claude_desktop_counts_only_for_this_workspace() {
        use crate::commands::setup::desktop::{Os, config_path};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let workspace = root.join("é😀 ws");
        std::fs::create_dir_all(workspace.join(".opentide")).unwrap();
        let home = root.join("home");
        let home_text = home.to_string_lossy().into_owned();
        let env = Env::from_pairs([
            ("HOME", home_text.clone()),
            ("USERPROFILE", home_text.clone()),
            ("APPDATA", format!("{home_text}/AppData/Roaming")),
            ("XDG_CONFIG_HOME", format!("{home_text}/.config")),
            ("PATH", "/nonexistent".to_owned()),
        ]);
        let config = config_path(Os::current(), &env, Some(&home)).unwrap();
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let mcp = |for_root: &Path| {
            let entry = serde_json::json!({"mcpServers": {"opentide": {
                "command": "/bin/sh",
                "args": ["mcp", "start"],
                "env": {"OPENTIDE_REPO_ROOT": for_root},
            }}});
            std::fs::write(&config, entry.to_string()).unwrap();
            let found = checks(&run(DoctorMode::Offline, &context(&env, &workspace)));
            found.into_iter().find(|(c, ..)| c == "mcp_config").unwrap()
        };
        let here = mcp(&workspace);
        assert_eq!(here.1, "pass", "{here:?}");
        assert!(
            here.2.contains("MCP configured for Claude Desktop"),
            "{here:?}"
        );
        let elsewhere = mcp(&root.join("another"));
        assert_eq!(elsewhere.1, "skip", "{elsewhere:?}");
        assert!(!elsewhere.2.contains("Claude Desktop"), "{elsewhere:?}");
    }

    #[test]
    fn a_router_mapping_of_the_object_folders_is_opentides() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        std::fs::create_dir_all(dir.path().join(".opentide")).unwrap();
        std::fs::write(
            dir.path().join(".vscode/settings.json"),
            "{\"yaml.schemas\": {\".opentide/schemas/opentide.schema.json\": \"objects/**/*.yaml\", \"mine.json\": [\"x/*.yaml\"]}}",
        )
        .unwrap();
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let found = checks(&run(DoctorMode::Offline, &context(&env, dir.path())));
        let settings = found.iter().find(|(c, ..)| c == "vscode_settings").unwrap();
        assert_eq!(settings.1, "warn");
        assert!(
            settings
                .2
                .starts_with(".vscode/settings.json maps objects to .opentide/schemas/opentide.schema.json in yaml.schemas"),
            "{settings:?}"
        );
    }
}
