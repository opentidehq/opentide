//! `opentide doctor --offline` (`cli/commands/doctor.py`,
//! `cli/services/doctor.py`; UC-3.5c, #928): one checklist for the
//! installation, the workspace and its integrations.
//!
//! Every check has a stable `code` (`docs/cli/doctor.md`), a status (`pass`,
//! `warn`, `fail` or `skip`), a one-line message and, when something needs
//! doing, a `fix`. A check never prints a secret: credentials are reported
//! set or unset by variable name, a proxy URL without its user and password.
//!
//! The network checks (the newest release on PyPI, the proxy's reachability)
//! are UC-4.1's: this engine runs `doctor --offline` only, and refuses a run
//! without it with `engine_not_ported` (`OPENTIDE_ENGINE=compare` then runs
//! Python alone).
//!
//! What the Rust command line reports differently, and why:
//!
//! - `python_version` is skipped: this command line does not run on Python.
//! - `platform_sdk` reads which Python modules import from the launcher that
//!   started it ([`PYTHON_MODULES_ENV`]); without one, it is skipped.
//! - `analysis_engine` passes: the engine is compiled into this program.
//! - `lsp_catalog` reports the catalog compiled in (the field catalog is not
//!   generated from Rust yet, UC-2.6), and still warns about a committed one
//!   from another opentide.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use opentide_schema::configuration::lint::parse_lint_config;
use opentide_schema::generate::router::{schema_artifact_name, template_artifact_name};
use opentide_schema::generate::template::Options;
use opentide_schema::generate::workspace::{
    CORE_OBJECT_TYPES, identifiers_for_families, object_template,
};
use opentide_schema::node::{Node, Value};
use opentide_workspace::info::env_reference;
use opentide_workspace::root::{self, RootOptions};
use opentide_workspace::{OsFs, config};
use serde_json::Value as JsonValue;

use super::{Block, Report, placement};
use crate::env::Env;
use crate::envelope::{Failure, USAGE_EXIT_CODE, code};
use crate::json::Json;
use crate::render::glyphs;
use crate::render::text::{Style, Text};

const COMMAND: &str = "doctor";

/// `failure.code` when at least one check failed.
pub const CHECKS_FAILED: &str = "doctor_checks_failed";

/// The variable a launcher sets to tell `platform_sdk` which Python modules
/// import in its environment: a JSON object mapping each platform to the
/// modules its live calls import, in order, each a `[module, status]` pair
/// whose status is `null` when it imports, else why not
/// (`ModuleNotFoundError: No module named 'cbc_sdk'`). A platform it does not
/// name needs no module. The Python launcher (`opentide.cli.rust`) sets it
/// for `doctor`: the modules are the Python package's to name, so this
/// program lists none of its own.
pub const PYTHON_MODULES_ENV: &str = "OPENTIDE_PYTHON_MODULES";

/// [`PYTHON_MODULES_ENV`] read: each platform's `(module, why it does not
/// import)` pairs, in the order the launcher checked them.
type PlatformModules = BTreeMap<String, Vec<(String, Option<String>)>>;

const REINSTALL_COMMAND: &str = "pip install --force-reinstall opentide";

/// The platforms, in the order the checklist names them (`SYSTEM_KEYS`).
const SYSTEM_KEYS: [&str; 9] = [
    "sentinel",
    "defender_for_endpoint",
    "splunk",
    "sentinel_one",
    "crowdstrike",
    "harfanglab",
    "carbon_black_cloud",
    "elastic",
    "sysdig",
];

/// The files `opentide setup mcp` writes, with the host each is for.
const MCP_OUTPUT_PATHS: [(&str, &str); 4] = [
    ("VS Code", ".vscode/mcp.json"),
    ("Cursor", ".cursor/mcp.json"),
    ("Claude Code", ".mcp.json"),
    ("generic", "opentide.mcp.json"),
];

/// The opentide VS Code extension.
const EXTENSION_ID: &str = "opentidehq.opentide";

const OPENTIDE_DIR: &str = ".opentide";

const PROXY_VARIABLES: [&str; 4] = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"];

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
}

/// What the checks share: the workspace and its configuration.
struct Doctor<'a> {
    cx: &'a Context<'a>,
    workspace: PathBuf,
    explicit: bool,
    cwd: PathBuf,
    /// The merged configuration, when it loads.
    config: Option<Node>,
}

/// Runs `opentide doctor`.
pub fn run(offline: bool, cx: &Context<'_>) -> Report {
    if !offline {
        let message = "opentide doctor without --offline has no Rust implementation yet: unset \
                       OPENTIDE_ENGINE, or set it to python or compare.";
        let mut failure = Failure::new(code::ENGINE_NOT_PORTED, message);
        failure.argument = Some("OPENTIDE_ENGINE".into());
        return Report::failed(COMMAND, USAGE_EXIT_CODE, failure);
    }
    let (shown, options) = placement(cx.repo, cx.env, cx.cwd);
    let cwd = resolve(cx.cwd);
    let workspace = resolve(&cx.cwd.join(&shown));
    let discovered = resolve(&root::find_workspace_root(&OsFs, cx.cwd));
    let explicit = cx.repo.is_some() || workspace != discovered;
    let mut doctor = Doctor {
        cx,
        workspace,
        explicit,
        cwd,
        config: None,
    };
    let roots = root::resolve(&OsFs, &options_for(&options));
    let loaded = config::load(&OsFs, &roots);
    let mut checks: Vec<Check> = Vec::new();
    checks.push(Check::new(
        "python_version",
        "skip",
        "Not checked: opentide's Rust command line does not run on Python",
    ));
    checks.push(Check::new(
        "opentide_version",
        "pass",
        format!("opentide {}", cx.version),
    ));
    checks.push(Check::new(
        "opentide_latest",
        "skip",
        "Not checked: --offline",
    ));
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
    if configuration_failed {
        checks.push(skipped("templates_fresh"));
        checks.push(skipped("schemas_fresh"));
    } else {
        checks.push(doctor.templates());
        checks.push(doctor.schemas());
    }
    checks.push(doctor.lsp_catalog());
    if configuration_failed {
        checks.push(skipped("platforms_enabled"));
        checks.push(skipped("platform_sdk"));
    } else {
        checks.push(doctor.platforms());
        checks.extend(doctor.platform_sdks());
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
    } else {
        checks.extend(doctor.credentials());
    }
    checks.push(doctor.proxy());
    if configuration_failed {
        checks.push(skipped("vscode_settings"));
        checks.push(skipped("vscode_snippets"));
    } else {
        checks.extend(doctor.vscode());
    }
    checks.push(doctor.mcp());
    report(&checks, cx.text)
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
        let path = self.cx.env.get("PATH").unwrap_or_default().to_owned();
        let Ok(git) = which::which_in("git", Some(path), &self.cwd) else {
            return vec![
                Check::new(
                    "git",
                    "warn",
                    "git is not on PATH; changed-object detection and hooks need it",
                )
                .fix("install git"),
            ];
        };
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
            if expected.as_deref().map(str::as_bytes) != written.as_deref() {
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
                "Every schema this version generates is present ({})",
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
                    serde_json::from_str::<JsonValue>(&text).map_err(|error| error.to_string())
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
            if generated != version {
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
                         {from}, not {version}: editors that run opentide-lsp on their own use it"
                    ),
                )
                .fix(fix);
            }
        }
        Check::new(
            "lsp_catalog",
            "pass",
            format!("Language-server catalog compiled into opentide {version}"),
        )
    }

    /// The platforms whose merged `[platform] enabled` is `true`.
    fn enabled_platforms(&self) -> Vec<&'static str> {
        SYSTEM_KEYS
            .iter()
            .copied()
            .filter(|system| {
                matches!(
                    self.node(&["systems", system, "platform", "enabled"])
                        .map(|node| &node.value),
                    Some(Value::Bool(true))
                )
            })
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

    fn platform_sdks(&self) -> Vec<Check> {
        let platforms: Option<PlatformModules> = self
            .cx
            .env
            .get(PYTHON_MODULES_ENV)
            .and_then(|text| serde_json::from_str(text).ok());
        let mut checks = Vec::new();
        for platform in self.enabled_platforms() {
            let Some(platforms) = &platforms else {
                checks.push(
                    Check::new(
                        "platform_sdk",
                        "skip",
                        format!("{platform}: not checked: no Python environment started opentide"),
                    )
                    .subject(platform),
                );
                continue;
            };
            let needed = platforms.get(platform).map_or(&[][..], Vec::as_slice);
            let failure = needed
                .iter()
                .find_map(|(module, reason)| Some((module, reason.as_ref()?)));
            if let Some((module, reason)) = failure {
                checks.push(
                    Check::new(
                        "platform_sdk",
                        "fail",
                        format!("{platform}: cannot import {module} ({reason})"),
                    )
                    .fix(REINSTALL_COMMAND)
                    .subject(platform),
                );
            } else {
                let names = if needed.is_empty() {
                    "no SDK needed".to_owned()
                } else {
                    needed
                        .iter()
                        .map(|(module, _)| module.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                checks.push(
                    Check::new(
                        "platform_sdk",
                        "pass",
                        format!("{platform}: {names} import"),
                    )
                    .subject(platform),
                );
            }
        }
        checks
    }

    fn credentials(&self) -> Vec<Check> {
        let mut checks = Vec::new();
        for platform in self.enabled_platforms() {
            let tenants: Vec<&Node> = match self
                .node(&["systems", platform, "tenants"])
                .map(|node| &node.value)
            {
                Some(Value::Seq(items)) => items
                    .iter()
                    .map(AsRef::as_ref)
                    .filter(|tenant| matches!(tenant.value, Value::Map(_)))
                    .collect(),
                _ => Vec::new(),
            };
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
                    .subject(platform),
                );
                continue;
            }
            for (index, tenant) in tenants.iter().enumerate() {
                let name = match tenant.get("name").map(|node| &node.value) {
                    Some(Value::Str(name)) if !name.is_empty() => name.clone(),
                    Some(Value::Null | Value::Bool(false)) | None => {
                        format!("tenant {}", index + 1)
                    }
                    Some(Value::Str(_)) => format!("tenant {}", index + 1),
                    Some(other) => other.to_string(),
                };
                let subject = format!("{platform}/{name}");
                let mut variables: Vec<&str> = Vec::new();
                if let Some(Value::Map(entries)) = tenant.get("setup").map(|node| &node.value) {
                    for entry in entries {
                        if let Some(name) = entry.value.value.as_str().and_then(env_reference)
                            && !variables.contains(&name)
                        {
                            variables.push(name);
                        }
                    }
                }
                let unset: Vec<&str> = variables
                    .iter()
                    .copied()
                    .filter(|variable| {
                        self.cx
                            .env
                            .get(variable)
                            .is_none_or(|value| value.is_empty())
                    })
                    .collect();
                let check = if !unset.is_empty() {
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
                checks.push(check.subject(subject));
            }
        }
        checks
    }

    fn proxy(&self) -> Check {
        let url = PROXY_VARIABLES
            .iter()
            .find_map(|name| self.cx.env.get(name).filter(|value| !value.is_empty()));
        let Some(url) = url else {
            return Check::new("proxy", "skip", "No proxy set (--proxy, HTTPS_PROXY)");
        };
        Check::new(
            "proxy",
            "skip",
            format!("Proxy {} not checked: --offline", redact_url(url)),
        )
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
            .fix("opentide setup vscode")
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
            .fix("opentide setup vscode")
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
        let setup = "opentide setup mcp --vscode (or --cursor, --claude-code, --generic)";
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
        let path = self.cx.env.get("PATH").unwrap_or_default().to_owned();
        let mut unresolved: Vec<String> = commands
            .into_iter()
            .filter(|command| {
                !command.is_empty() && which::which_in(command, Some(&path), &self.cwd).is_err()
            })
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
/// name starts with `.` or `__`.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "the oracle's `rglob(\"*.toml\")` matches `.toml` case-sensitively on Linux"
)]
fn collect_toml(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !(name.starts_with('.') || name.starts_with("__")) {
                collect_toml(&path, out);
            }
        } else if name.ends_with(".toml") && path.is_file() {
            out.push(path);
        }
    }
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
                .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
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

/// `url` without its user and password: `http://proxy:8080`.
fn redact_url(url: &str) -> String {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("http", url),
    };
    if scheme.is_empty() || !scheme.chars().all(char::is_alphanumeric) {
        return "<unparseable proxy URL>".to_owned();
    }
    let host_port = rest.rsplit_once('@').map_or(rest, |(_, after)| after);
    let host_port = host_port.split(['/', '?', '#']).next().unwrap_or_default();
    match url::Url::parse(&format!("{scheme}://{host_port}")) {
        Ok(parsed) => {
            let host = parsed.host_str().unwrap_or_default();
            match parsed.port() {
                Some(port) => format!("{scheme}://{host}:{port}"),
                None => format!("{scheme}://{host}"),
            }
        }
        Err(_) => "<unparseable proxy URL>".to_owned(),
    }
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
            if let Some(JsonValue::Array(args)) = server.get("args")
                && args.len() >= 2
                && args[args.len() - 2] == "mcp"
                && args[args.len() - 1] == "start"
            {
                return Some(server.clone());
            }
        }
    }
    None
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
        (format!("{} failed", plural(failed, "check")), "failed")
    } else if warned > 0 {
        (plural(warned, "warning"), "issues")
    } else {
        rest.clear();
        (format!("{} passed", plural(passed, "check")), "completed")
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
    status.clone_into(&mut report.outcome.status);
    report.outcome.message.clone_from(&message);
    report.outcome.summary = vec![
        ("checks".to_owned(), int(checks.len())),
        ("passed".to_owned(), int(passed)),
        ("warnings".to_owned(), int(warned)),
        ("failed".to_owned(), int(failed)),
        ("skipped".to_owned(), int(skipped)),
    ];
    if failed > 0 {
        report.outcome.exit_code = 1;
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
        "pass" => (glyphs::OK, "bold green"),
        "fail" => (glyphs::FAILED, "bold red"),
        "skip" => (glyphs::SKIP, "bold dim"),
        _ => (glyphs::WARNING, "bold yellow"),
    };
    let mut line = Text::default();
    line.append(glyph, &Style::new(style));
    line.push_str(" ");
    line.push_str(&check.message);
    line.append(
        &format!(" {} {}", glyphs::SEPARATOR, check.code),
        &Style::new("dim"),
    );
    let mut out = vec![(line, 2)];
    if let Some(fix) = &check.fix
        && matches!(check.status, "warn" | "fail" | "skip")
    {
        let mut hint = Text::plain("  ");
        hint.append(&format!("{} ", glyphs::NEXT), &Style::new("bold cyan"));
        if check.status == "skip" {
            hint.append(fix, &Style::new("dim"));
        } else {
            hint.push_str(fix);
        }
        out.push((hint, 4));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>(env: &'a Env, cwd: &'a Path) -> Context<'a> {
        Context {
            repo: None,
            env,
            cwd,
            version: "9.9.9",
            text: false,
        }
    }

    fn checks(report: &Report) -> Vec<(String, String, String)> {
        let Some((_, Json::Array(items))) =
            report.outcome.data.iter().find(|(key, _)| key == "checks")
        else {
            panic!("no checks");
        };
        items
            .iter()
            .map(|item| {
                let Json::Object(members) = item else {
                    panic!("a check is an object")
                };
                let get = |key: &str| match &members.iter().find(|(k, _)| k == key).unwrap().1 {
                    Json::Str(text) => text.clone(),
                    _ => String::new(),
                };
                (get("code"), get("status"), get("message"))
            })
            .collect()
    }

    #[test]
    fn without_offline_it_is_refused() {
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let dir = tempfile::tempdir().unwrap();
        let report = run(false, &context(&env, dir.path()));
        assert_eq!(report.outcome.exit_code, 2);
        let failure = report.outcome.failure.unwrap();
        assert_eq!(failure.code, code::ENGINE_NOT_PORTED);
        assert!(
            failure
                .message
                .starts_with("opentide doctor without --offline")
        );
    }

    #[test]
    fn an_empty_folder_fails_the_workspace_check() {
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let dir = tempfile::tempdir().unwrap();
        let report = run(true, &context(&env, dir.path()));
        let found = checks(&report);
        let workspace = found.iter().find(|(code, ..)| code == "workspace").unwrap();
        assert_eq!(workspace.1, "fail");
        assert!(
            workspace.2.starts_with("No workspace at ./"),
            "{workspace:?}"
        );
        assert_eq!(report.outcome.exit_code, 1);
        assert_eq!(report.outcome.status, "failed");
        assert_eq!(report.outcome.failure.unwrap().code, CHECKS_FAILED);
        let codes: Vec<&str> = found.iter().map(|(code, ..)| code.as_str()).collect();
        assert_eq!(
            codes[..4],
            [
                "python_version",
                "opentide_version",
                "opentide_latest",
                "workspace"
            ]
        );
        assert!(codes.contains(&"mcp_config"));
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
        let env = Env::from_pairs([(PYTHON_MODULES_ENV, r#"{"elastic": [["requests", null]]}"#)]);
        let report = run(true, &context(&env, dir.path()));
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
        assert_eq!(get("platform_sdk"), [("pass", "elastic: requests import")]);
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
        assert_eq!(report.outcome.status, "issues");
        assert_eq!(report.outcome.exit_code, 0);
    }

    /// `platform_sdk` reports what the launcher found for each enabled
    /// platform: the first module that does not import fails it, the modules
    /// that do are named, a platform the launcher names no module for needs
    /// none, and without a launcher every platform is skipped.
    #[test]
    fn platform_sdk_reports_the_launchers_modules() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".opentide/configurations/platforms");
        std::fs::create_dir_all(&config).unwrap();
        for platform in ["elastic", "sentinel", "splunk"] {
            std::fs::write(
                config.join(format!("{platform}.toml")),
                "[platform]\nenabled = true\n",
            )
            .unwrap();
        }
        let sdk = |env: &Env| {
            checks(&run(true, &context(env, dir.path())))
                .into_iter()
                .filter(|(code, ..)| code == "platform_sdk")
                .map(|(_, status, message)| (status, message))
                .collect::<Vec<_>>()
        };
        let modules = r#"{
            "sentinel": [["a.b", null], ["c", "ImportError: no c"], ["d", "ImportError: no d"]],
            "splunk": [["s.client", null], ["t", null]]
        }"#;
        let pairs = |rows: &[(&str, &str)]| {
            rows.iter()
                .map(|(status, message)| ((*status).to_owned(), (*message).to_owned()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            sdk(&Env::from_pairs([(PYTHON_MODULES_ENV, modules)])),
            pairs(&[
                ("fail", "sentinel: cannot import c (ImportError: no c)"),
                ("pass", "splunk: s.client, t import"),
                ("pass", "elastic: no SDK needed import"),
            ])
        );
        assert_eq!(
            sdk(&Env::from_pairs(Vec::<(String, String)>::new())),
            pairs(&[
                (
                    "skip",
                    "sentinel: not checked: no Python environment started opentide"
                ),
                (
                    "skip",
                    "splunk: not checked: no Python environment started opentide"
                ),
                (
                    "skip",
                    "elastic: not checked: no Python environment started opentide"
                ),
            ])
        );
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
        let found = checks(&run(true, &context(&env, dir.path())));
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
        let found = checks(&run(true, &context(&env, dir.path())));
        let stale = found
            .iter()
            .find(|(code, ..)| code == "templates_fresh")
            .unwrap();
        assert_eq!(stale.1, "warn");
        assert!(stale.2.starts_with("1 template(s) differ"), "{stale:?}");
    }

    #[test]
    fn a_broken_configuration_names_the_file_and_line_and_skips_its_readers() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(".opentide/configurations");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("lint.toml"), "[metadata]\nrequired = [\n").unwrap();
        let env = Env::from_pairs(Vec::<(String, String)>::new());
        let found = checks(&run(true, &context(&env, dir.path())));
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
            redact_url("http://user:p@ss/w#rd@proxy:8080"),
            "http://proxy:8080"
        );
        assert_eq!(redact_url("proxy.example"), "http://proxy.example");
        assert_eq!(redact_url("ht tp://x"), "<unparseable proxy URL>");
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
        let found = checks(&run(true, &context(&env, dir.path())));
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
        let found = checks(&run(true, &context(&env, dir.path())));
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
