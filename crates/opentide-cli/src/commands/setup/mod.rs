//! `opentide setup ci <provider>` (`cli/setup_app.py`,
//! `cli/services/setup/ci.py`, `cli/services/setup/promotion.py`): writes
//! the CI pipeline `opentide-compile`'s `ci` templates render for the
//! platforms the repository enables, and the `[promotion]` override
//! `deploy` reads when `--promotion` or `--promotion-target` asks for one.
//!
//! `--plan` lists the files the step would write (`create` or `merge`)
//! and writes nothing; without `--yes` a person confirms the write at a
//! terminal, and anything that cannot answer (`--json`, an agent, no
//! terminal) is refused with `usage_needs_input`.

pub mod files;
pub mod hooks;
pub mod jsonc;
pub mod run;
pub mod skills;
pub mod stage;
pub mod vscode;
pub mod wizard;

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_compile::ci::{self, Provider};
use opentide_schema::configuration::resolve::Resolved;
use opentide_schema::node::Value;

use super::{Block, Report, USAGE_INVALID_VALUE};
use crate::env::Env;
use crate::envelope::{Failure, USAGE_EXIT_CODE};
use crate::json::Json;
use crate::mode::Mode;
use crate::render::outcome::OutcomeKind;
use crate::render::table::columns;
use crate::render::text::{Style, Text};

const COMMAND: &str = "setup ci";

/// `path` relative to `base` (`os.path.relpath`), through `..` when it is
/// outside it, with `/` between parts; `.` for `base` itself.
pub(crate) fn shown_relative(path: &Path, base: &Path) -> String {
    match pathdiff::diff_paths(path, base) {
        Some(relative) if relative.as_os_str().is_empty() => ".".to_owned(),
        Some(relative) => relative.to_string_lossy().replace('\\', "/"),
        None => path.to_string_lossy().replace('\\', "/"),
    }
}

/// `failure.code` of a prompt nobody can answer.
pub const USAGE_NEEDS_INPUT: &str = "usage_needs_input";

/// `setup ci`'s arguments, the `setup` group's handed down.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the command's switches, one field each"
)]
pub struct CiArgs {
    /// The provider.
    pub provider: Provider,
    /// `--path`, when given to the command.
    pub path: Option<String>,
    /// `--path` of the `setup` group, when given there.
    pub group_path: Option<String>,
    /// `--staging/--no-staging`.
    pub staging: bool,
    /// `--inflight/--no-inflight`.
    pub inflight: bool,
    /// `--sharing/--no-sharing`.
    pub sharing: bool,
    /// `--lint-changed/--lint-all`.
    pub lint_changed: bool,
    /// `--promotion/--no-promotion`; `None` keeps the repository's setting.
    pub promotion: Option<bool>,
    /// `--promotion-target`; `None` keeps the repository's setting.
    pub promotion_target: Option<String>,
    /// `--python-version`.
    pub python_version: String,
    /// `--explorer-pages/--no-explorer-pages`.
    pub explorer_pages: bool,
    /// `--default-branch`; `None` detects it.
    pub default_branch: Option<String>,
    /// `--plan`, here or on the group.
    pub plan: bool,
    /// `--yes`, here or on the group.
    pub yes: bool,
    /// The `setup` group's own options given on the command line, which
    /// `setup ci` would ignore.
    pub group_only: Vec<String>,
}

/// Where the run is.
pub struct Context<'a> {
    /// `--repo`, as typed on the command line.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// The output mode.
    pub mode: Mode,
    /// opentide's version, which the pipeline pins.
    pub version: &'a str,
    /// `--quiet`: no summary of the files written.
    pub quiet: bool,
    /// The streams' styles and widths: what a step prints as it runs (the
    /// wizard's screens, `setup vscode`'s deprecation).
    pub terminal: crate::commands::Terminal,
    /// Ctrl-C for this run: a wizard question answered with Ctrl-C stops the
    /// run as Ctrl-C does elsewhere (`error: interrupted`, exit 130).
    pub interrupt: crate::app::Interrupt,
    /// stderr, shared with the log lines: what a step prints there as it
    /// runs comes before the log lines it writes after (`setup vscode`'s
    /// deprecation).
    pub stderr: crate::logging::Sink,
    /// `--proxy`: how `setup skills` reaches the skills repository.
    pub proxy: Option<&'a str>,
}

/// An app-level usage error, as Click words a `BadParameter`.
pub(crate) fn bad_parameter(message: &str, hint: &[&str], argument: Option<&str>) -> Box<Report> {
    let shown = if hint.is_empty() {
        format!("Invalid value: {message}")
    } else {
        let names: Vec<String> = hint.iter().map(|name| format!("'{name}'")).collect();
        format!("Invalid value for {}: {message}", names.join(" / "))
    };
    let mut failure = Failure::new(USAGE_INVALID_VALUE, shown);
    failure.argument = argument.map(str::to_owned);
    Box::new(Report::failed(COMMAND, USAGE_EXIT_CODE, failure))
}

/// A prompt nobody can answer: exit 2 naming the flag that answers it.
/// A prompt nobody can answer in `command`: exit 2 naming the flag that answers it.
pub(crate) fn needs_input_for(command: &str, message: String) -> Box<Report> {
    Box::new(Report::failed(
        command,
        USAGE_EXIT_CODE,
        Failure::new(USAGE_NEEDS_INPUT, message),
    ))
}

/// Python's `repr()` of a string, for the messages that quote one.
pub(crate) fn repr(text: &str) -> String {
    opentide_schema::configuration::repr::quote(text)
}

/// Whether a branch name can be written into the pipelines
/// (`is_valid_branch_name`): letters, digits, `.`, `_`, `/` and `-`,
/// starting with a letter or digit, and read by YAML as that string.
pub fn is_valid_branch_name(name: &str) -> bool {
    let mut chars = name.chars();
    let shaped = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
    shaped
        && opentide_schema::node::load(&format!("k: {name}\n"))
            .ok()
            .and_then(|document| {
                document
                    .root()
                    .and_then(|root| root.get("k"))
                    .and_then(|value| value.value.as_str().map(str::to_owned))
            })
            .is_some_and(|read| read == name)
}

/// `path` made absolute against `cwd` as `Path.resolve()` gives it: the
/// links of its existing part resolved (before the `..` that follow them),
/// `.` and `..` folded, the part that does not exist yet kept.
pub(crate) fn resolved(cwd: &Path, path: &Path) -> PathBuf {
    real(&cwd.join(path))
}

/// An absolute `path` resolved as [`resolved`] does (soft_canonicalize:
/// it need not exist); kept as given when resolving fails.
pub(crate) fn real(path: &Path) -> PathBuf {
    soft_canonicalize::soft_canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The repository `setup ci` writes to (`_option_path`): the one path the
/// command and its group name, `.` by default, which an explicit `--repo`
/// replaces.
fn target(args: &CiArgs, cx: &Context<'_>) -> Result<PathBuf, Box<Report>> {
    let setup_path = |given: &str| -> PathBuf {
        let path = Path::new(given);
        match cx.repo {
            Some(repo)
                if path == Path::new(".")
                    && resolved(cx.cwd, Path::new(repo)) != resolved(cx.cwd, cx.cwd) =>
            {
                cx.cwd.join(repo)
            }
            _ => path.to_path_buf(),
        }
    };
    let named: Vec<&str> = [args.group_path.as_deref(), args.path.as_deref()]
        .into_iter()
        .flatten()
        .collect();
    let mut targets: Vec<PathBuf> = named
        .iter()
        .map(|path| resolved(cx.cwd, &setup_path(path)))
        .collect();
    targets.dedup();
    if targets.len() > 1 {
        return Err(bad_parameter(
            &format!(
                "Pass the repository path once: {} name different targets.",
                named.join(" and ")
            ),
            &[],
            None,
        ));
    }
    Ok(setup_path(named.last().copied().unwrap_or(".")))
}

/// Asks a person to confirm the write, at the terminal (`_confirm_write`).
/// `Ok(false)` when they decline.
fn confirm(shown: &Path, absolute: &Path, cx: &Context<'_>) -> Result<bool, Box<Report>> {
    confirm_write(
        COMMAND,
        shown,
        absolute,
        cx,
        "Write this CI/CD configuration?",
    )
}

/// Asks a person to confirm a write to `absolute` with `question`
/// (`_confirm_write`); refuses where nobody can answer.
pub(crate) fn confirm_write(
    command: &str,
    shown: &Path,
    absolute: &Path,
    cx: &Context<'_>,
    question: &str,
) -> Result<bool, Box<Report>> {
    if cx.mode == Mode::Json {
        return Err(needs_input_for(
            command,
            format!(
                "--json cannot prompt for confirmation. Add --yes to write to '{}'.",
                shown.to_string_lossy().replace('\\', "/")
            ),
        ));
    }
    if cx.mode == Mode::Agent {
        let reader = crate::mode::detect_agent(cx.env).map_or_else(
            || "agent output mode".to_owned(),
            |agent| format!("a coding agent ({agent})"),
        );
        return Err(needs_input_for(
            command,
            format!(
                "Interactive setup does not prompt in {reader}. Add --yes to confirm this write."
            ),
        ));
    }
    if !std::io::stdin().is_terminal() {
        return Err(needs_input_for(
            command,
            "Interactive setup requires a terminal. Add --yes to confirm this write.".to_owned(),
        ));
    }
    let mut stdout = std::io::stdout();
    let _ = write!(
        stdout,
        "Target: {}\n? {question} (Y/n) ",
        absolute.display()
    );
    let _ = stdout.flush();
    let mut answer = String::new();
    if std::io::stdin().lock().read_line(&mut answer).is_err() {
        return Ok(false);
    }
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

/// The bundled `[promotion]` table `deploy` uses when a repository sets none.
pub(crate) fn promotion_defaults() -> toml::Table {
    opentide_schema::configuration::bundled::FILES
        .iter()
        .find(|(path, _)| *path == "deployment.toml")
        .and_then(|(_, text)| text.parse::<toml::Table>().ok())
        .and_then(|table| {
            table
                .get("promotion")
                .and_then(toml::Value::as_table)
                .cloned()
        })
        .unwrap_or_default()
}

/// The `deployment.toml` a promotion flag writes, with its new text.
#[derive(Debug)]
pub(crate) struct PromotionOverride {
    pub(crate) path: PathBuf,
    /// `None` when the file already says what was asked.
    pub(crate) content: Option<String>,
}

/// The flags' names, as the refusals name them.
const PROMOTION_FLAG: &str = "--promotion/--no-promotion";
const PROMOTION_TARGET_FLAG: &str = "--promotion-target";

/// What `.opentide/configurations/deployment.toml` needs so `deploy`
/// promotes as asked (`plan_promotion_override`).
pub(crate) fn promotion_override(
    root: &Path,
    promotion: Option<bool>,
    promotion_target: Option<&str>,
    statuses: impl FnOnce() -> Result<Vec<String>, String>,
) -> Result<Option<PromotionOverride>, Box<Report>> {
    let defaults = promotion_defaults();
    let mut requested = toml::Table::new();
    let mut hint = Vec::new();
    if let Some(enabled) = promotion {
        requested.insert("enabled".into(), toml::Value::Boolean(enabled));
        hint.push(PROMOTION_FLAG);
    }
    if let Some(status) = promotion_target {
        requested.insert(
            "promotion_target".into(),
            toml::Value::String(status.to_owned()),
        );
        hint.push(PROMOTION_TARGET_FLAG);
    }
    if requested.is_empty() {
        return Ok(None);
    }
    let relative = ".opentide/configurations/deployment.toml";
    let path = root.join(relative);
    // A file that cannot be read is refused: read as empty, the override
    // would replace everything in it.
    let existing = if path.is_file() {
        std::fs::read_to_string(&path).map_err(|error| {
            bad_parameter(
                &format!("{relative} cannot be read ({error}); fix it, then re-run setup."),
                &hint,
                None,
            )
        })?
    } else {
        String::new()
    };
    let parsed = match existing.parse::<toml::Table>() {
        Ok(parsed) => parsed,
        Err(error) => {
            let reason = error.message().to_owned();
            return Err(bad_parameter(
                &format!("{relative} is not valid TOML ({reason}); fix it, then re-run setup."),
                &hint,
                None,
            ));
        }
    };
    if let Some(status) = promotion_target {
        let known = statuses().map_err(|problem| {
            bad_parameter(
                &format!("cannot read the statuses of {}: {problem}", root.display()),
                &[PROMOTION_TARGET_FLAG],
                None,
            )
        })?;
        if !known.iter().any(|known| known == status) {
            return Err(bad_parameter(
                &format!(
                    "{} is not a status in this repository's deployment.toml; use one of: {}",
                    repr(status),
                    known.join(", ")
                ),
                &[PROMOTION_TARGET_FLAG],
                None,
            ));
        }
    }
    match parsed.get("promotion") {
        None => {
            let table: toml::Table = requested
                .into_iter()
                .filter(|(key, value)| defaults.get(key) != Some(value))
                .collect();
            if table.is_empty() {
                return Ok(None);
            }
            let mut document = toml::Table::new();
            document.insert("promotion".into(), toml::Value::Table(table));
            let block = toml::to_string(&document).unwrap_or_default();
            let content = if existing.is_empty() || existing.ends_with("\n\n") {
                format!("{existing}{block}")
            } else if existing.ends_with('\n') {
                format!("{existing}\n{block}")
            } else {
                format!("{existing}\n\n{block}")
            };
            Ok(Some(PromotionOverride {
                path,
                content: Some(content),
            }))
        }
        Some(toml::Value::Table(current))
            if requested.iter().all(|(key, value)| {
                current.get(key).or_else(|| defaults.get(key)) == Some(value)
            }) =>
        {
            Ok(Some(PromotionOverride {
                path,
                content: None,
            }))
        }
        Some(_) => {
            let assignments: Vec<String> = requested
                .iter()
                .map(|(key, value)| format!("{key} = {value}"))
                .collect();
            Err(bad_parameter(
                &format!(
                    "{relative} already has a [promotion] table, which setup does not rewrite. Set {} in it, or delete it and re-run setup.",
                    assignments.join(", ")
                ),
                &hint,
                None,
            ))
        }
    }
}

/// The platforms whose file under `.opentide/configurations/platforms/`
/// enables them, by file name (`discover_enabled_platforms`).
fn enabled_platforms(stage: &stage::Stage, root: &Path) -> Vec<String> {
    let dir = root.join(".opentide/configurations/platforms");
    stage
        .entries(&dir)
        .into_iter()
        .filter(|name| Path::new(name).extension().is_some_and(|ext| ext == "toml"))
        .filter(|name| {
            files::read_text(stage, &dir.join(name))
                .ok()
                .flatten()
                .is_some_and(|text| ci::enables(&text))
        })
        .filter_map(|name| {
            Path::new(&name)
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
        })
        .collect()
}

const NO_PLATFORMS_WARNING: &str = "No enabled platforms found under .opentide/configurations/platforms/. Run `opentide setup platforms` (e.g. `--sentinel`) before `setup ci` so validate query jobs are included in the generated pipeline.";
const GITLAB_DEFAULT_BRANCH: &str = "$CI_DEFAULT_BRANCH";
const FALLBACK_DEFAULT_BRANCH: &str = "main";

/// The first folder of `path` and its parents that exists.
fn repository_dir(path: &Path) -> PathBuf {
    path.ancestors()
        .find(|candidate| candidate.is_dir())
        .map_or_else(|| path.to_path_buf(), Path::to_path_buf)
}

/// The branch GitHub and Azure jobs deploy from, and which setting named it
/// (`_detect_default_branch`): `origin/HEAD`, the checked-out branch, then
/// `init.defaultBranch`, else `main`.
fn detect_default_branch(env: &Env, path: &Path) -> (String, &'static str) {
    use crate::git_baseline::stdout;
    let dir = repository_dir(path);
    let short = |args: &[&str]| stdout(env, &dir, args).unwrap_or_default();
    let remote_head = short(&[
        "symbolic-ref",
        "--quiet",
        "--short",
        "refs/remotes/origin/HEAD",
    ]);
    let remote = remote_head
        .strip_prefix("origin/")
        .unwrap_or_default()
        .to_owned();
    for (source, branch) in [
        ("origin/HEAD", remote),
        (
            "HEAD",
            short(&["symbolic-ref", "--quiet", "--short", "HEAD"]),
        ),
        (
            "init.defaultBranch",
            short(&["config", "--get", "init.defaultBranch"]),
        ),
    ] {
        if is_valid_branch_name(&branch) {
            return (branch, source);
        }
    }
    (FALLBACK_DEFAULT_BRANCH.to_owned(), "fallback")
}

/// A detected branch that is likely not the one that deploys
/// (`_default_branch_warnings`).
fn default_branch_warnings(env: &Env, path: &Path, branch: &str, source: &str) -> Vec<String> {
    use crate::git_baseline::stdout;
    let dir = repository_dir(path);
    let local: Vec<String> = stdout(
        env,
        &dir,
        &["for-each-ref", "--format=%(refname)", "refs/heads/"],
    )
    .unwrap_or_default()
    .lines()
    .map(|line| line.strip_prefix("refs/heads/").unwrap_or(line).to_owned())
    .collect();
    let quoted = repr(branch);
    if source == "fallback"
        && stdout(env, &dir, &["rev-parse", "--git-dir"])
            .unwrap_or_default()
            .is_empty()
    {
        return vec![format!(
            "This folder is not a git repository yet, so the pipeline targets {quoted}; create it on that branch with 'git init -b {branch}', or write the pipeline for another one with 'opentide setup ci <provider> --default-branch <branch>'."
        )];
    }
    if source == "fallback" && !local.iter().any(|name| name == branch) {
        return vec![format!(
            "Found no origin/HEAD, checked-out branch or init.defaultBranch; the pipeline targets {quoted}, which is not a branch of this repository. Re-run with --default-branch <branch>."
        )];
    }
    if source == "HEAD" && local.iter().any(|name| name != branch) {
        return vec![format!(
            "origin/HEAD is not set, so the pipeline targets the checked-out branch {quoted}. Re-run with --default-branch <branch> if another branch deploys."
        )];
    }
    Vec::new()
}

/// Where `setup ci` finds the workspace at `root`.
pub(crate) fn root_options(root: &Path, cx: &Context<'_>) -> opentide_workspace::RootOptions {
    opentide_workspace::RootOptions {
        repo: Some(root.to_path_buf()),
        repo_root_env: Some(root.to_path_buf()),
        tide_workspace_env: Some(root.to_path_buf()),
        cwd: cx.cwd.to_path_buf(),
    }
}

/// The rules folder of the workspace at `root`, from the repository root,
/// links resolved.
fn rules_folder(root: &Path, cx: &Context<'_>) -> String {
    super::open(root_options(root, cx))
        .ok()
        .and_then(|workspace| {
            workspace
                .configuration()
                .folder("rule")
                .map(Path::to_path_buf)
        })
        .and_then(|folder| {
            let folder = std::fs::canonicalize(folder).ok()?;
            let base = std::fs::canonicalize(root).ok()?;
            let relative = folder.strip_prefix(base).ok()?;
            let text = relative
                .to_string_lossy()
                .replace('\\', "/")
                .trim_matches('/')
                .to_owned();
            (!text.is_empty() && text != ".").then_some(text)
        })
        .unwrap_or_else(|| ci::DEFAULT_RULES_FOLDER.to_owned())
}

/// The statuses `deployment.toml` defines in the workspace at `root`, read
/// from the merged files without checking them, as the oracle's
/// `resolve_configurations` reads them: a `paths.toml` its model refuses
/// does not hide them (#957).
pub(crate) fn statuses(root: &Path, cx: &Context<'_>) -> Result<Vec<String>, String> {
    let fs = opentide_workspace::OsFs;
    let roots = opentide_workspace::root::resolve(&fs, &root_options(root, cx));
    opentide_workspace::config::resolve_only(&fs, &roots)
        .map(|resolved| deployment_statuses(&resolved))
        .map_err(|error| error.to_string())
}

/// The names of the statuses `deployment.toml` defines, in order (`str(entry.get("name"))`).
fn deployment_statuses(resolved: &Resolved) -> Vec<String> {
    let Some(Value::Seq(entries)) = resolved
        .get("deployment")
        .and_then(|deployment| deployment.get("statuses"))
        .map(|statuses| &statuses.value)
    else {
        return Vec::new();
    };
    entries
        .iter()
        .map(|entry| {
            entry.get("name").map_or_else(
                || "None".to_owned(),
                |name| match &name.value {
                    Value::Str(text) => text.clone(),
                    _ => opentide_schema::configuration::repr::node(name),
                },
            )
        })
        .collect()
}

/// What a run did, or would do.
pub(crate) struct Run {
    /// The files written, relative to the repository, in order.
    pub(crate) files: Vec<(String, Option<Vec<u8>>, bool)>,
    pub(crate) warnings: Vec<String>,
    pub(crate) platforms: Vec<String>,
    pub(crate) branch: String,
}

/// `run_ci_setup`: everything but the writing.
pub(crate) fn prepare(
    stage: &stage::Stage,
    args: &CiArgs,
    root: &Path,
    cx: &Context<'_>,
) -> Result<Run, Box<Report>> {
    let promotion = promotion_override(
        root,
        args.promotion,
        args.promotion_target.as_deref(),
        || statuses(root, cx),
    )?;
    let platforms = enabled_platforms(stage, root);
    let mut warnings = Vec::new();
    if platforms.is_empty() {
        warnings.push(NO_PLATFORMS_WARNING.to_owned());
    }
    if args.explorer_pages && args.provider != Provider::GitHub {
        warnings.push(format!(
            "Explorer pages were not written for {}",
            args.provider.name()
        ));
    }
    let branch = match (&args.provider, &args.default_branch) {
        (Provider::GitLab, given) => {
            if given.is_some() {
                warnings.push(format!(
                    "GitLab pipelines publish to {GITLAB_DEFAULT_BRANCH}; --default-branch is ignored."
                ));
            }
            GITLAB_DEFAULT_BRANCH.to_owned()
        }
        (_, Some(given)) => given.clone(),
        (_, None) => {
            let (branch, source) = detect_default_branch(cx.env, root);
            warnings.extend(default_branch_warnings(cx.env, root, &branch, source));
            branch
        }
    };
    let mut credentials = IndexMap::new();
    for platform in &platforms {
        if ci::QUERY_VALIDATION_PLATFORMS.contains(&platform.as_str()) {
            let file = root
                .join(".opentide/configurations/platforms")
                .join(format!("{platform}.toml"));
            let names = files::read_text(stage, &file)
                .ok()
                .flatten()
                .map(|text| ci::tenant_variables(&text))
                .unwrap_or_default();
            credentials.insert(platform.clone(), names);
        }
    }
    let options = ci::Options {
        provider: args.provider,
        platforms: platforms.clone(),
        staging: args.staging,
        inflight: args.inflight,
        sharing: args.sharing,
        lint_changed: args.lint_changed,
        explorer_pages: args.explorer_pages,
        python_version: args.python_version.clone(),
        opentide_version: cx.version.to_owned(),
        default_branch: branch.clone(),
        docs_output: "docs".to_owned(),
        rules_folder: rules_folder(root, cx),
        credentials,
    };
    let text = ci::render(&options)
        .map_err(|error| Box::new(Report::error(COMMAND, error.to_string())))?;
    let pipeline = args.provider.path();
    let mut files = vec![(
        pipeline.to_owned(),
        Some(text.into_bytes()),
        root.join(pipeline).exists(),
    )];
    if let Some(promotion) = promotion
        && let Some(content) = promotion.content
    {
        let relative = promotion
            .path
            .strip_prefix(root)
            .map_or_else(|_| promotion.path.clone(), Path::to_path_buf)
            .to_string_lossy()
            .replace('\\', "/");
        files.push((
            relative,
            Some(content.into_bytes()),
            promotion.path.exists(),
        ));
    }
    Ok(Run {
        files,
        warnings,
        platforms,
        branch,
    })
}

fn strings(items: &[String]) -> Json {
    Json::Array(items.iter().map(Json::str).collect())
}

/// `opentide setup ci <provider>`.
pub fn ci(args: &CiArgs, cx: &Context<'_>) -> Report {
    if let Some(branch) = &args.default_branch
        && !is_valid_branch_name(branch)
    {
        return *bad_parameter(
            &format!(
                "{} cannot be written into a pipeline; use letters, digits, '.', '_', '/' and '-'",
                repr(branch)
            ),
            &["--default-branch"],
            Some("--default-branch"),
        );
    }
    if !args.group_only.is_empty() {
        let verb = if args.group_only.len() == 1 {
            "configures"
        } else {
            "configure"
        };
        return *bad_parameter(
            &format!(
                "{} {verb} `opentide setup` itself and would be ignored by `opentide setup ci`.",
                args.group_only.join(", ")
            ),
            &[],
            None,
        );
    }
    let shown = match target(args, cx) {
        Ok(shown) => shown,
        Err(report) => return *report,
    };
    let root = resolved(cx.cwd, &shown);
    if !args.plan && !args.yes {
        match confirm(&shown, &root, cx) {
            Ok(true) => {}
            Ok(false) => {
                let mut report = Report::completed(COMMAND, Vec::new());
                report.outcome.status = "skipped".into();
                report.outcome.message = "CI/CD setup cancelled".into();
                return report;
            }
            Err(report) => return *report,
        }
    }
    let run = match prepare(&stage::Stage::new(), args, &root, cx) {
        Ok(run) => run,
        Err(report) => return *report,
    };
    if args.plan {
        return plan(&root, &run);
    }
    for (relative, bytes, _) in &run.files {
        let Some(bytes) = bytes else { continue };
        let path = root.join(relative);
        let written = path
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(&path, bytes));
        if let Err(error) = written {
            return Report::error(COMMAND, format!("{}: {error}", path.display()));
        }
    }
    let files: Vec<String> = run.files.iter().map(|(path, _, _)| path.clone()).collect();
    let mut report = Report::completed(
        COMMAND,
        vec![
            (
                "path".into(),
                Json::str(root.to_string_lossy().into_owned()),
            ),
            ("ci".into(), Json::str(args.provider.name())),
            ("platforms".into(), strings(&run.platforms)),
            ("default_branch".into(), Json::str(&run.branch)),
            ("files".into(), strings(&files)),
        ],
    );
    report.outcome.message = match files.as_slice() {
        [one] => format!("Wrote {one}"),
        many => format!("Wrote {} files", many.len()),
    };
    report.warnings = unique(run.warnings);
    if cx.mode != Mode::Json {
        let rows: Vec<Vec<Text>> = files
            .iter()
            .map(|path| {
                vec![
                    Text::styled(path, &Style::new("bold")),
                    Text::styled(purpose(path), &Style::new("dim")),
                ]
            })
            .collect();
        let mut lines: Vec<Text> = columns(&rows, 3, &[])
            .into_iter()
            .map(|row| {
                let mut line = Text::plain("  ");
                line.append_text(&row);
                line
            })
            .collect();
        lines.push(Text::default());
        report.body = vec![Block::Lines(lines)];
    }
    report
}

fn unique(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

/// What a written file is for, as the summary lists it.
fn purpose(path: &str) -> &'static str {
    const PURPOSES: [(&str, &str); 3] = [
        (".github/workflows/", "GitHub Actions pipeline"),
        (".gitlab-ci.yml", "GitLab CI pipeline"),
        ("azure-pipelines", "Azure Pipelines pipeline"),
    ];
    PURPOSES
        .iter()
        .find(|(prefix, _)| path.starts_with(prefix) || path == prefix.trim_end_matches('/'))
        .map_or("", |(_, purpose)| purpose)
}

/// The `--plan` document: the step's files, the counts and the outcome line
/// (`plan_payload`).
fn plan(root: &Path, run: &Run) -> Report {
    let mut created = 0;
    let mut merged = 0;
    let files: Vec<Json> = run
        .files
        .iter()
        .map(|(path, _, existed)| {
            let action = if *existed { "merge" } else { "create" };
            if *existed {
                merged += 1;
            } else {
                created += 1;
            }
            Json::object([("path", Json::str(path)), ("action", Json::str(action))])
        })
        .collect();
    let warnings = unique(run.warnings.clone());
    let writes = created + merged;
    let noun = if writes == 1 { "file" } else { "files" };
    let step = Json::object([
        ("step", Json::str("ci")),
        ("files", Json::Array(files)),
        ("warnings", strings(&warnings)),
    ]);
    let mut report = Report::completed(
        COMMAND,
        vec![
            ("plan".into(), Json::Bool(true)),
            (
                "path".into(),
                Json::str(root.to_string_lossy().into_owned()),
            ),
            ("steps".into(), Json::Array(vec![step])),
        ],
    );
    report.outcome.message = format!(
        "Plan: {writes} {noun} to write ({created} new, {merged} changed) · nothing written"
    );
    report.outcome.summary = vec![
        ("create".into(), Json::Int(created)),
        ("merge".into(), Json::Int(merged)),
        ("skip".into(), Json::Int(0)),
        ("delete".into(), Json::Int(0)),
        ("steps".into(), Json::Int(1)),
    ];
    report.outcome_kind = Some(OutcomeKind::Plan);
    report.warnings = warnings;
    let bold = Style::new("bold");
    let mut lines = vec![Text::styled("ci", &bold)];
    if run.files.is_empty() {
        lines.push(Text::styled("  nothing to write", &Style::new("dim")));
    } else {
        let rows: Vec<Vec<Text>> = run
            .files
            .iter()
            .map(|(path, _, existed)| {
                vec![
                    Text::plain(if *existed { "merge" } else { "create" }),
                    Text::styled(path, &bold),
                ]
            })
            .collect();
        lines.extend(columns(&rows, 2, &[]).into_iter().map(|row| {
            let mut line = Text::plain("  ");
            line.append_text(&row);
            line
        }));
    }
    lines.push(Text::default());
    report.body = vec![Block::Lines(lines)];
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_joins_folds_and_keeps_the_missing_tail() {
        let dir = tempfile::tempdir().unwrap();
        let root = soft_canonicalize::soft_canonicalize(dir.path()).unwrap();
        std::fs::create_dir(root.join("a")).unwrap();
        assert_eq!(
            resolved(&root, Path::new("a/./b/../new/file")),
            root.join("a").join("new").join("file")
        );
        assert_eq!(resolved(&root, Path::new(".")), root);
        assert_eq!(resolved(&root, &root.join("a")), root.join("a"));
    }

    /// `..` after a link climbs from where the link points, as
    /// `Path.resolve()` does, not from the link's own folder.
    #[cfg(unix)]
    #[test]
    fn resolved_follows_a_link_before_its_parent_step() {
        let dir = tempfile::tempdir().unwrap();
        let root = soft_canonicalize::soft_canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("real").join("deep")).unwrap();
        std::os::unix::fs::symlink(root.join("real").join("deep"), root.join("link")).unwrap();
        assert_eq!(
            resolved(&root, Path::new("link/../ws")),
            root.join("real").join("ws")
        );
    }

    fn po(
        root: &Path,
        args: &CiArgs,
        statuses: impl FnOnce() -> Result<Vec<String>, String>,
    ) -> Result<Option<PromotionOverride>, Box<Report>> {
        promotion_override(
            root,
            args.promotion,
            args.promotion_target.as_deref(),
            statuses,
        )
    }

    #[test]
    fn branch_names_are_checked_as_the_pipelines_need() {
        for good in ["main", "release/v1.2", "feature_x-1", "on", "yes"] {
            assert!(is_valid_branch_name(good), "{good}");
        }
        for bad in [
            "", "a b", "-x", "$x", "2024", "1.0", "true", "null", "ma'in",
        ] {
            assert!(!is_valid_branch_name(bad), "{bad}");
        }
    }

    #[test]
    fn a_promotion_flag_appends_the_table_deploy_reads() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let args = |promotion: Option<bool>, target: Option<&str>| CiArgs {
            provider: Provider::GitHub,
            path: None,
            group_path: None,
            staging: true,
            inflight: true,
            sharing: false,
            lint_changed: false,
            promotion,
            promotion_target: target.map(str::to_owned),
            python_version: "3.12".into(),
            explorer_pages: false,
            default_branch: None,
            plan: false,
            yes: true,
            group_only: Vec::new(),
        };
        let statuses = || Ok(vec!["STAGING".to_owned(), "PRODUCTION".to_owned()]);
        // The defaults already say so: nothing to write.
        assert!(
            po(root, &args(Some(true), None), statuses)
                .unwrap()
                .is_none()
        );
        let written = po(root, &args(Some(false), Some("STAGING")), statuses)
            .unwrap()
            .unwrap();
        assert_eq!(
            written.content.as_deref(),
            Some("[promotion]\nenabled = false\npromotion_target = \"STAGING\"\n")
        );
        let config = root.join(".opentide/configurations");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("deployment.toml"), "[x]\na = 1\n").unwrap();
        let appended = po(root, &args(Some(false), None), statuses)
            .unwrap()
            .unwrap();
        assert_eq!(
            appended.content.as_deref(),
            Some("[x]\na = 1\n\n[promotion]\nenabled = false\n")
        );
        std::fs::write(
            config.join("deployment.toml"),
            "[promotion]\nenabled = false\n",
        )
        .unwrap();
        let same = po(root, &args(Some(false), None), statuses)
            .unwrap()
            .unwrap();
        assert!(same.content.is_none());
        let refused = po(root, &args(Some(true), None), statuses).unwrap_err();
        assert_eq!(
            refused.outcome.message,
            "Invalid value for '--promotion/--no-promotion': .opentide/configurations/deployment.toml already has a [promotion] table, which setup does not rewrite. Set enabled = true in it, or delete it and re-run setup."
        );
        let unknown = po(root, &args(None, Some("NOPE")), statuses).unwrap_err();
        assert_eq!(
            unknown.outcome.message,
            "Invalid value for '--promotion-target': 'NOPE' is not a status in this repository's deployment.toml; use one of: STAGING, PRODUCTION"
        );
        assert_eq!(unknown.outcome.exit_code, 2);
    }

    /// A `deployment.toml` that cannot be read is refused and left as it
    /// is: read as empty, the override would replace the whole file.
    #[test]
    fn an_unreadable_deployment_file_is_refused_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let config = root.join(".opentide/configurations");
        std::fs::create_dir_all(&config).unwrap();
        let path = config.join("deployment.toml");
        let bytes = b"# caf\xe9\n[x]\na = 1\n".to_vec();
        std::fs::write(&path, &bytes).unwrap();
        let args = CiArgs {
            provider: Provider::GitHub,
            path: None,
            group_path: None,
            staging: true,
            inflight: true,
            sharing: false,
            lint_changed: false,
            promotion: Some(false),
            promotion_target: None,
            python_version: "3.12".into(),
            explorer_pages: false,
            default_branch: None,
            plan: false,
            yes: true,
            group_only: Vec::new(),
        };
        let refused = po(root, &args, || Ok(Vec::new())).unwrap_err();
        assert_eq!(refused.outcome.exit_code, 2);
        assert!(
            refused.outcome.message.starts_with(
                "Invalid value for '--promotion/--no-promotion': .opentide/configurations/deployment.toml cannot be read ("
            ),
            "{}",
            refused.outcome.message
        );
        assert!(
            refused
                .outcome
                .message
                .ends_with("); fix it, then re-run setup."),
            "{}",
            refused.outcome.message
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}
