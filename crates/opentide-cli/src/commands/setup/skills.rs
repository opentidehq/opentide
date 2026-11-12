//! Installing agent skills (UC-4.4d, #834): `opentide setup skills`,
//! `setup --skills` and `--plugin` (`services/setup/skills.py`,
//! `services/setup/plugin.py`).
//!
//! A run downloads each skill tree from the opentidehq/skills repository
//! (the four authoring skills come from the package), puts it under
//! `.agents/skills/<slug>/`, copies it for each harness that reads skills
//! from its own folder, writes each harness's entrypoint file when the
//! repository has none, and with `--plugin` registers the opentidehq/skills
//! Agent Plugin in `.claude/settings.json`. Everything goes through a
//! [`Stage`]: every byte of every skill is read before anything is written,
//! so a failed download leaves the previous tree as it was.
//!
//! What the user already has stays theirs: an entrypoint file that exists is
//! left alone (with a warning when it is not opentide's), a harness copy
//! keeps the files the skill does not ship, nothing is written through a
//! link, and `.claude/settings.json` is edited in place on its syntax tree,
//! so its comments, layout, line endings and byte-order mark stay.

use std::cell::OnceCell;
use std::path::{Component, Path, PathBuf};

use super::files::{StepResult, strings};
use super::jsonc;
use super::stage::Stage;
use crate::commands::skills::{self as catalogue, Manifest, Network};
use crate::json::Json;

/// The skills installed when none is named (`_STARTER_SKILLS`).
pub const STARTER_SKILLS: [&str; 2] = ["opentide-detection-rule", "detection-engineering"];

/// A skill's files: each one's path in the skill and its bytes.
type Files = Vec<(String, Vec<u8>)>;

/// A bundled skill: its slug and its files.
type Bundled = (&'static str, &'static [(&'static str, &'static [u8])]);

/// The authoring skills' files, shipped with opentide
/// (`data/setup/skills/authoring/<slug>/`).
const BUNDLED: [Bundled; 4] = [
    (
        "detection-engineering",
        &[(
            "SKILL.md",
            include_bytes!(
                "../../../../../src/opentide/data/setup/skills/authoring/detection-engineering/SKILL.md"
            ),
        )],
    ),
    (
        "opentide-detection-objective",
        &[(
            "SKILL.md",
            include_bytes!(
                "../../../../../src/opentide/data/setup/skills/authoring/opentide-detection-objective/SKILL.md"
            ),
        )],
    ),
    (
        "opentide-detection-rule",
        &[(
            "SKILL.md",
            include_bytes!(
                "../../../../../src/opentide/data/setup/skills/authoring/opentide-detection-rule/SKILL.md"
            ),
        )],
    ),
    (
        "opentide-threat-vector",
        &[(
            "SKILL.md",
            include_bytes!(
                "../../../../../src/opentide/data/setup/skills/authoring/opentide-threat-vector/SKILL.md"
            ),
        )],
    ),
];

/// The entrypoint templates (`data/setup/skills/`).
const CLAUDE_TEMPLATE: &str =
    include_str!("../../../../../src/opentide/data/setup/skills/CLAUDE.md.template");
const AGENTS_TEMPLATE: &str =
    include_str!("../../../../../src/opentide/data/setup/skills/AGENTS.md.template");
const COPILOT_TEMPLATE: &str =
    include_str!("../../../../../src/opentide/data/setup/skills/copilot-instructions.md");

/// The preview deploy the templates name (`render_agent_entrypoint`).
const DEPLOY: &str = "opentide deploy --dry-run --strategy PREVIEW --all";

/// The marketplace and plugin name in opentidehq/skills' `.claude-plugin/`.
pub const MARKETPLACE: &str = "opentide";
/// The plugin's id: `opentide@opentide`.
pub const PLUGIN_ID: &str = "opentide@opentide";
/// Where Claude Code reads a project's plugins.
pub const CLAUDE_SETTINGS: &str = ".claude/settings.json";

/// How each other host installs the plugin (opentidehq/skills README).
const OTHER_HOSTS: [(&str, &str); 3] = [
    ("cursor", "/add-plugin opentidehq/skills"),
    (
        "vscode",
        "Chat: Install Plugin From Source → opentidehq/skills (needs chat.plugins.enabled)",
    ),
    (
        "copilot-cli",
        "copilot plugin marketplace add opentidehq/skills && copilot plugin install opentide@opentide",
    ),
];

/// A harness skills install for (`SkillTarget`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// `.cursor/skills/`.
    Cursor,
    /// `CLAUDE.md` and `.claude/skills/`.
    ClaudeCode,
    /// `AGENTS.md`.
    Generic,
    /// `.github/copilot-instructions.md`, and `AGENTS.md`.
    GithubCopilot,
}

impl Target {
    /// The target a flag or wizard key names: `claude-code`.
    pub fn parse(key: &str) -> Option<Target> {
        match key {
            "cursor" => Some(Target::Cursor),
            "claude-code" => Some(Target::ClaudeCode),
            "generic" => Some(Target::Generic),
            "github-copilot" => Some(Target::GithubCopilot),
            _ => None,
        }
    }
}

/// What to install (`SkillsSetupOptions`).
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// The harnesses, in the order given.
    pub targets: Vec<Target>,
    /// `--install`, in the order given; empty for the starter skills.
    pub slugs: Vec<String>,
    /// `--all`: every skill of the catalogue.
    pub all: bool,
    /// The entrypoints' heading; the folder's name by default.
    pub name: Option<String>,
    /// The organisation the entrypoints name.
    pub org: Option<String>,
    /// The paragraph under their heading.
    pub description: Option<String>,
    /// `--plugin`.
    pub plugin: bool,
}

/// Why an install stopped. What it wrote before stopping stays staged: the
/// oracle wrote it before it failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A usage error (`typer.BadParameter`): an unknown `--install` slug.
    Usage(String),
    /// The catalogue or a skill could not be read (`SkillsManifestError`,
    /// `SkillsDownloadError`).
    Failed(String),
}

impl Error {
    /// The message.
    pub fn message(&self) -> &str {
        match self {
            Error::Usage(message) | Error::Failed(message) => message,
        }
    }
}

/// The opentidehq/skills repository as one run reads it: the catalogue and
/// the repository's file list, each fetched once, on first use (the
/// oracle's in-process manifest cache and `GithubTree`).
pub struct Catalogue<'a> {
    network: Network<'a>,
    manifest: OnceCell<Result<Manifest, String>>,
    tree: OnceCell<Option<Vec<String>>>,
}

impl std::fmt::Debug for Catalogue<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Catalogue")
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl<'a> Catalogue<'a> {
    /// The repository, read through `network` when first needed.
    pub fn new(network: Network<'a>) -> Self {
        Self {
            network,
            manifest: OnceCell::new(),
            tree: OnceCell::new(),
        }
    }

    /// The live catalogue (`load_manifest`).
    ///
    /// # Errors
    ///
    /// It cannot be read: the message users read.
    pub fn manifest(&self) -> Result<&Manifest, String> {
        self.manifest
            .get_or_init(|| catalogue::load(false, self.network))
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Every file of the repository at the catalogue's ref.
    fn tree(&self, git_ref: &str) -> Option<&[String]> {
        self.tree
            .get_or_init(|| catalogue::fetch_tree(git_ref, self.network))
            .as_deref()
    }

    /// The files under `folder/`, sorted, or `None` when the list cannot be
    /// read or names a path that would leave the folder (`list_github_paths`).
    fn files_under(&self, folder: &str, git_ref: &str) -> Option<Vec<String>> {
        let blobs = self.tree(git_ref)?;
        let prefix = format!("{folder}/");
        let mut paths = Vec::new();
        for path in blobs {
            let Some(rest) = path.strip_prefix(&prefix) else {
                continue;
            };
            if catalogue::repo_file_path(rest).is_none() {
                tracing::warn!(path = path.as_str(), "skills_tree_path_rejected");
                return None;
            }
            paths.push(path.clone());
        }
        paths.sort();
        Some(paths)
    }

    /// The bytes of the repository's file at `path`.
    fn file(&self, path: &str, git_ref: &str) -> Option<Vec<u8>> {
        catalogue::fetch_file(path, git_ref, self.network)
    }
}

/// Whether `slug` ships with opentide.
fn is_bundled(slug: &str) -> bool {
    BUNDLED.iter().any(|(name, _)| *name == slug)
}

/// The message of a skill that could not be downloaded (`_download_error`).
fn download_error(slug: &str, git_ref: &str) -> Error {
    Error::Failed(format!(
        "Could not download skill '{slug}' from {}@{git_ref}. Check network access and that the skills repository is publicly reachable.",
        catalogue::DEFAULT_SOURCE
    ))
}

/// The slugs a run installs (`_resolve_skill_slugs`).
fn resolve_slugs(options: &Options, catalogue: &Catalogue<'_>) -> Result<Vec<String>, Error> {
    let manifest = catalogue.manifest().map_err(Error::Failed)?;
    if options.all {
        return Ok(manifest
            .entries
            .iter()
            .map(|entry| entry.slug.clone())
            .collect());
    }
    if options.slugs.is_empty() {
        return Ok(STARTER_SKILLS
            .iter()
            .map(|slug| (*slug).to_owned())
            .collect());
    }
    let unknown: Vec<&str> = options
        .slugs
        .iter()
        .filter(|slug| !manifest.entries.iter().any(|entry| entry.slug == **slug))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return Err(Error::Usage(format!(
            "Unknown skill slug(s): {}. Run 'opentide setup skills discover' to list available skills.",
            unknown.join(", ")
        )));
    }
    Ok(options.slugs.clone())
}

/// The skills of `options` that cannot be fetched, checked before anything
/// is written (`unavailable_skills`): the wizards' preflight.
///
/// # Errors
///
/// The catalogue cannot be read, or a slug is unknown.
pub fn unavailable(options: &Options, catalogue: &Catalogue<'_>) -> Result<Vec<String>, Error> {
    let slugs = resolve_slugs(options, catalogue)?;
    let git_ref = catalogue.manifest().map_err(Error::Failed)?.git_ref.clone();
    Ok(slugs
        .into_iter()
        .filter(|slug| {
            !is_bundled(slug)
                && catalogue
                    .file(&format!("skills/{slug}/SKILL.md"), &git_ref)
                    .is_none()
        })
        .collect())
}

/// One skill's files, by their path in the skill, sorted
/// (`_install_bundled_skill`, `_download_skill`).
fn skill_files(slug: &str, git_ref: &str, catalogue: &Catalogue<'_>) -> Result<Files, Error> {
    if !catalogue::slug_is_contained(slug) {
        return Err(Error::Failed(format!(
            "Refusing skill slug {}",
            super::repr(slug)
        )));
    }
    if let Some((_, files)) = BUNDLED.iter().find(|(name, _)| *name == slug) {
        return Ok(files
            .iter()
            .map(|(name, bytes)| ((*name).to_owned(), bytes.to_vec()))
            .collect());
    }
    let folder = format!("skills/{slug}");
    let paths = catalogue
        .files_under(&folder, git_ref)
        .filter(|paths| !paths.is_empty())
        .ok_or_else(|| download_error(slug, git_ref))?;
    let prefix = format!("{folder}/");
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let (Some(bytes), Some(relative)) =
            (catalogue.file(&path, git_ref), path.strip_prefix(&prefix))
        else {
            return Err(download_error(slug, git_ref));
        };
        files.push((relative.to_owned(), bytes));
    }
    if !files.iter().any(|(name, _)| name == "SKILL.md") {
        return Err(download_error(slug, git_ref));
    }
    Ok(files)
}

/// `relative` under `root`, refused when it would leave it (`_contained_file`).
fn contained(root: &Path, relative: &str) -> Result<PathBuf, Error> {
    let refused = || Error::Failed(format!("Refusing skill path {}", super::repr(relative)));
    if relative.is_empty() || relative.starts_with(['/', '\\']) || relative.contains('\\') {
        return Err(refused());
    }
    let mut out = root.to_path_buf();
    for part in relative.split('/') {
        if matches!(part, "" | "." | "..") {
            return Err(refused());
        }
        out.push(part);
    }
    if Path::new(relative)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(refused());
    }
    Ok(out)
}

/// Every file under `dir`, relative to it with `/`, sorted; links to
/// folders are not followed (`Path.rglob`).
fn files_below(stage: &Stage, dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = vec![(dir.to_path_buf(), String::new())];
    while let Some((folder, prefix)) = pending.pop() {
        for name in stage.entries(&folder) {
            let path = folder.join(&name);
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if stage.is_file(&path) {
                out.push(relative);
            } else if stage.is_dir(&path) && !path.is_symlink() {
                pending.push((path, relative));
            }
        }
    }
    out.sort();
    out
}

/// Puts `files` at `dest`, the skill's own folder: what it held before goes,
/// the files an older version shipped included (`_replace_tree`). Links in
/// it are removed, never written through.
fn replace_tree(stage: &mut Stage, dest: &Path, files: &[(String, Vec<u8>)]) -> Result<(), Error> {
    let mut paths = Vec::with_capacity(files.len());
    for (relative, _) in files {
        paths.push(contained(dest, relative)?);
    }
    if dest.is_symlink() {
        stage.unlink(dest);
    } else if stage.is_dir(dest) {
        unlink_below(stage, dest);
        for old in files_below(stage, dest) {
            if !files.iter().any(|(relative, _)| *relative == old) {
                stage.remove(&dest.join(&old));
            }
        }
        for folder in folders_below(dest) {
            let kept = files
                .iter()
                .any(|(relative, _)| dest.join(relative).starts_with(&folder));
            if !kept {
                stage.remove_dir(&folder);
            }
        }
    }
    stage.mkdir(dest);
    for (path, (_, bytes)) in paths.iter().zip(files) {
        stage.write_mode(path, bytes.clone(), false);
    }
    Ok(())
}

/// Every folder under `dir` on disk, links to folders not followed.
fn folders_below(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(folder) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && !path.is_symlink() {
                out.push(path.clone());
                pending.push(path);
            }
        }
    }
    out
}

/// Removes every link under `dir`, links to folders included, unfollowed.
fn unlink_below(stage: &mut Stage, dir: &Path) {
    let mut pending = vec![dir.to_path_buf()];
    while let Some(folder) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_symlink() {
                stage.unlink(&path);
            } else if path.is_dir() {
                pending.push(path);
            }
        }
    }
}

/// `path` as `Path.resolve()` gives it.
fn resolved(path: &Path) -> PathBuf {
    super::real(path)
}

/// The warning for the files a copy kept (`_kept_warning`).
fn kept_warning(place: &str, kept: &[String]) -> String {
    format!(
        "Kept {} file(s) in {place} that the skill does not ship ({}); delete them by hand if they are left over from an older version.",
        kept.len(),
        shown_some(kept)
    )
}

/// The first five of `items`, then how many more.
fn shown_some(items: &[String]) -> String {
    let mut shown = items.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > 5 {
        shown.push_str(&format!(" and {} more", items.len() - 5));
    }
    shown
}

/// Copies the skill at `src` (its `files`) over `dest`, keeping the files
/// in `dest` it does not ship (`_copy_skill`). A link at a path the skill
/// ships is replaced by the skill's own file, with a warning; a `dest` that
/// resolves outside `root` is left alone, with a warning.
fn copy_skill(
    stage: &mut Stage,
    root: &Path,
    src: &Path,
    dest: &Path,
    files: &[(String, Vec<u8>)],
    place: &str,
    warnings: &mut Vec<String>,
) {
    let real_dest = resolved(dest);
    if real_dest == resolved(src) {
        // `.claude/skills` links to `.agents/skills` (or this skill's folder
        // does): the skill is already there.
        return;
    }
    if !real_dest.starts_with(resolved(root)) {
        warnings.push(format!(
            "Left {place} as it is: it links outside this repository, to {}. Copy the skill there by hand if that folder should have it.",
            real_dest.display()
        ));
        return;
    }
    let mut shipped: Vec<&String> = files.iter().map(|(relative, _)| relative).collect();
    shipped.sort();
    let kept: Vec<String> = if dest.is_symlink() || !stage.is_dir(dest) {
        Vec::new()
    } else {
        files_below(stage, dest)
            .into_iter()
            .filter(|relative| !shipped.contains(&relative))
            .collect()
    };
    stage.mkdir(&real_dest);
    let mut replaced: Vec<String> = Vec::new();
    for relative in &shipped {
        let parts: Vec<&str> = relative.split('/').collect();
        let mut out = dest.to_path_buf();
        for (depth, part) in parts.iter().enumerate() {
            out.push(part);
            if out.is_symlink() && !stage.unlinked(&out) {
                stage.unlink(&out);
                replaced.push(parts[..=depth].join("/"));
            }
            if depth + 1 < parts.len() {
                stage.mkdir(&out);
            }
        }
        if let Some((_, bytes)) = files.iter().find(|(name, _)| name == *relative) {
            stage.write_mode(&out, bytes.clone(), false);
        }
    }
    if !replaced.is_empty() {
        warnings.push(format!(
            "Replaced {} link(s) in {place} with the skill's own files ({}), rather than write through them.",
            replaced.len(),
            shown_some(&replaced)
        ));
    }
    if !kept.is_empty() {
        warnings.push(kept_warning(place, &kept));
    }
}

/// The entrypoint files a run left alone, and why (`_Entrypoints`).
#[derive(Default)]
struct Entrypoints {
    skipped: Vec<String>,
    warnings: Vec<String>,
}

impl Entrypoints {
    /// Writes `content` to `relative` unless the file exists: it is the
    /// repository's own agent instructions.
    fn write(
        &mut self,
        stage: &mut Stage,
        root: &Path,
        relative: &str,
        content: &str,
    ) -> Vec<String> {
        let dest = root.join(relative);
        if stage.exists(&dest) {
            self.skipped.push(relative.to_owned());
            let same = stage
                .read(&dest)
                .ok()
                .flatten()
                .is_some_and(|bytes| bytes == content.as_bytes());
            if !same {
                self.warnings.push(format!(
                    "Left {relative} unchanged because the file already exists; point it at .agents/skills/ by hand, or delete it and re-run to write opentide's template."
                ));
            }
            return Vec::new();
        }
        stage.write(&dest, content.as_bytes().to_vec());
        vec![relative.to_owned()]
    }
}

/// A template with the run's values (`render_agent_entrypoint`): each
/// `{key}` replaced in turn, `deploy` first.
fn render(template: &str, context: &[(&str, String)]) -> String {
    let mut text = template.to_owned();
    for (key, value) in std::iter::once(("deploy", DEPLOY.to_owned()))
        .chain(context.iter().map(|(key, value)| (*key, value.clone())))
    {
        text = text.replace(&format!("{{{key}}}"), &value);
    }
    text
}

/// The plugin's settings, as the template merged into `.claude/settings.json`.
fn plugin_settings() -> Json {
    Json::object([
        (
            "extraKnownMarketplaces",
            Json::object([(
                MARKETPLACE,
                Json::object([(
                    "source",
                    Json::object([
                        ("source", Json::str("github")),
                        ("repo", Json::str(catalogue::DEFAULT_SOURCE)),
                    ]),
                )]),
            )]),
        ),
        (
            "enabledPlugins",
            Json::object([(PLUGIN_ID, Json::Bool(true))]),
        ),
    ])
}

/// Adds the opentide marketplace and plugin to `root`'s Claude Code settings
/// (`register_claude_code_plugin`), every other setting kept, on the file's
/// syntax tree: its comments, layout, line endings and byte-order mark stay.
///
/// # Errors
///
/// The file is not JSON with comments, not an object, or holds either key
/// as something other than an object: why, and the file is left as it is.
fn register_plugin(stage: &mut Stage, root: &Path) -> Result<String, String> {
    let dest = root.join(CLAUDE_SETTINGS);
    let template = plugin_settings();
    let text = if stage.is_file(&dest) {
        let existing = match stage.read(&dest) {
            Ok(Some(bytes)) => String::from_utf8(bytes)
                .map_err(|_| "is not valid JSON (the file is not UTF-8)".to_owned())?,
            Ok(None) => String::new(),
            Err(error) => return Err(format!("is not valid JSON ({error})")),
        };
        // `null` is not an object to the oracle, as any other non-object.
        if let Ok(serde_json::Value::Object(members)) = jsonc::parse(&existing) {
            for key in ["extraKnownMarketplaces", "enabledPlugins"] {
                if members.get(key).is_some_and(serde_json::Value::is_null) {
                    return Err(jsonc::MergeError::MemberNotAnObject(key.to_owned()).to_string());
                }
            }
        }
        jsonc::merge(&existing, &template).map_err(|error| error.to_string())?
    } else {
        jsonc::dumps(&template, "\n")
    };
    stage.write(&dest, text);
    Ok(CLAUDE_SETTINGS.to_owned())
}

/// Installs the skills of `options` into `root` through `stage`
/// (`run_skills_setup`): the step's result.
///
/// # Errors
///
/// No target, an unknown slug, or a catalogue or skill that cannot be
/// read. What was staged before the error stays staged.
pub fn install(
    stage: &mut Stage,
    root: &Path,
    options: &Options,
    catalogue: &Catalogue<'_>,
) -> Result<StepResult, Error> {
    if options.targets.is_empty() && !options.plugin {
        return Err(Error::Usage(
            "Choose at least one skills target (--cursor, --claude-code, --generic, --github-copilot, --plugin)"
                .to_owned(),
        ));
    }
    let mut written: Vec<String> = Vec::new();
    let mut plugin_warnings: Vec<String> = Vec::new();
    if options.plugin {
        match register_plugin(stage, root) {
            Ok(relative) => written.push(relative),
            Err(problem) => plugin_warnings.push(format!(
                "{CLAUDE_SETTINGS} {problem}; left unchanged. Install the plugin in Claude Code with /plugin marketplace add opentidehq/skills."
            )),
        }
    }
    // With the plugin, Claude Code takes the skills from it: copying them
    // into .claude/skills/ as well would load every skill twice.
    let copies = options
        .targets
        .iter()
        .any(|target| !(options.plugin && *target == Target::ClaudeCode));
    let slugs = if copies {
        resolve_slugs(options, catalogue)?
    } else {
        Vec::new()
    };
    let context = [
        (
            "name",
            options
                .name
                .clone()
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| super::files::folder_name(root)),
        ),
        ("org", options.org.clone().unwrap_or_default()),
        (
            "description",
            options.description.clone().unwrap_or_default(),
        ),
    ];
    let mut entrypoints = Entrypoints::default();
    let mut trees: Vec<(String, Files)> = Vec::new();
    if !slugs.is_empty() {
        let git_ref = catalogue.manifest().map_err(Error::Failed)?.git_ref.clone();
        for slug in &slugs {
            let files = skill_files(slug, &git_ref, catalogue)?;
            replace_tree(
                stage,
                &root.join(".agents").join("skills").join(slug),
                &files,
            )?;
            written.extend(
                files
                    .iter()
                    .map(|(relative, _)| format!(".agents/skills/{slug}/{relative}")),
            );
            trees.push((slug.clone(), files));
        }
    }
    let mut also_applied: Vec<String> = Vec::new();
    let copy_into = |stage: &mut Stage, folder: &str, warnings: &mut Vec<String>| {
        let mut out = Vec::new();
        for (slug, files) in &trees {
            let src = root.join(".agents").join("skills").join(slug);
            let dest = root.join(folder).join("skills").join(slug);
            let place = format!("{folder}/skills/{slug}");
            copy_skill(stage, root, &src, &dest, files, &place, warnings);
            out.push(format!("{place}/SKILL.md"));
        }
        out
    };
    for target in &options.targets {
        match target {
            Target::Cursor => {
                written.extend(copy_into(stage, ".cursor", &mut entrypoints.warnings));
            }
            Target::ClaudeCode => {
                let claude = render(CLAUDE_TEMPLATE, &context);
                written.extend(entrypoints.write(stage, root, "CLAUDE.md", &claude));
                if !options.plugin {
                    written.extend(copy_into(stage, ".claude", &mut entrypoints.warnings));
                }
            }
            Target::Generic => {
                let agents = render(AGENTS_TEMPLATE, &context);
                written.extend(entrypoints.write(stage, root, "AGENTS.md", &agents));
            }
            Target::GithubCopilot => {
                if !options.targets.contains(&Target::Generic) {
                    let agents = render(AGENTS_TEMPLATE, &context);
                    written.extend(entrypoints.write(stage, root, "AGENTS.md", &agents));
                    also_applied.push("generic".to_owned());
                }
                let copilot = render(COPILOT_TEMPLATE, &context);
                written.extend(entrypoints.write(
                    stage,
                    root,
                    ".github/copilot-instructions.md",
                    &copilot,
                ));
            }
        }
    }
    tracing::debug!(
        detail = %root.display(),
        files = ?written,
        skills = ?slugs,
        "agent_skills_created"
    );
    let mut result = StepResult::new([
        ("message", Json::str("Agent skills installed")),
        ("path", Json::str(super::files::shown(root))),
        ("skills", strings(&slugs)),
        ("files", strings(&written)),
    ]);
    if !also_applied.is_empty() {
        result.set("also_applied", strings(&also_applied));
    }
    if !entrypoints.skipped.is_empty() {
        result.set("skipped", strings(&entrypoints.skipped));
    }
    if options.plugin {
        result.set("plugin", Json::str(PLUGIN_ID));
        let hosts: Vec<String> = OTHER_HOSTS
            .iter()
            .map(|(host, how)| format!("{host}: {how}"))
            .collect();
        result.set(
            "advice",
            Json::str(format!(
                "Claude Code offers the opentide plugin to whoever opens this project. The plugin starts opentide mcp start itself: other agents install it with {}.",
                hosts.join("; ")
            )),
        );
    }
    let mut warnings = plugin_warnings;
    warnings.append(&mut entrypoints.warnings);
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_env() -> crate::env::Env {
        crate::env::Env::from_pairs([
            ("HTTPS_PROXY".to_owned(), "http://127.0.0.1:9".to_owned()),
            ("HTTP_PROXY".to_owned(), "http://127.0.0.1:9".to_owned()),
        ])
    }

    fn never() -> bool {
        false
    }

    /// A catalogue whose manifest is already loaded: no request is sent.
    fn loaded(network: Network<'_>, manifest: Result<Manifest, String>) -> Catalogue<'_> {
        let catalogue = Catalogue::new(network);
        let _ = catalogue.manifest.set(manifest);
        catalogue
    }

    fn manifest() -> Manifest {
        catalogue::parse_manifest(&serde_json::Map::new(), false)
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap()
    }

    #[test]
    fn templates_take_each_value_in_turn_deploy_first() {
        let context = [
            ("name", "{org}".to_owned()),
            ("org", "Acme".to_owned()),
            ("description", String::new()),
        ];
        assert_eq!(
            render("# {name} / {description} / {deploy}", &context),
            "# Acme /  / opentide deploy --dry-run --strategy PREVIEW --all"
        );
    }

    #[test]
    fn the_plugin_is_merged_into_existing_settings_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        let existing = "\u{feff}{\r\n  // the team's\r\n  \"permissions\": {\"allow\": [\"Bash(ls)\"]},\r\n  \"enabledPlugins\": {\"other@x\": false}\r\n}\r\n";
        std::fs::write(root.join(CLAUDE_SETTINGS), existing).unwrap();
        let mut stage = Stage::new();
        assert_eq!(register_plugin(&mut stage, root).unwrap(), CLAUDE_SETTINGS);
        stage.commit().unwrap();
        let text = read(&root.join(CLAUDE_SETTINGS));
        assert!(text.starts_with("\u{feff}{\r\n  // the team's\r\n  \"permissions\": {\"allow\": [\"Bash(ls)\"]},\r\n"), "{text:?}");
        assert!(text.contains("\"other@x\": false"), "{text:?}");
        assert!(text.contains("\"opentide@opentide\": true"), "{text:?}");
        assert!(!text.replace("\r\n", "").contains('\n'), "{text:?}");
        let value = jsonc::parse(&text).unwrap();
        assert_eq!(
            value["extraKnownMarketplaces"]["opentide"]["source"]["repo"],
            "opentidehq/skills"
        );
        // Again: the same document.
        let mut again = Stage::new();
        register_plugin(&mut again, root).unwrap();
        again.commit().unwrap();
        assert_eq!(
            jsonc::parse(&read(&root.join(CLAUDE_SETTINGS))).unwrap(),
            value
        );
    }

    #[test]
    fn settings_the_plugin_cannot_join_are_left_alone() {
        for (text, problem) in [
            ("[1]", "is not a JSON object"),
            (
                "{\"enabledPlugins\": null}",
                "has a 'enabledPlugins' that is not a JSON object",
            ),
            (
                "{\"extraKnownMarketplaces\": []}",
                "has a 'extraKnownMarketplaces' that is not a JSON object",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
            std::fs::write(dir.path().join(CLAUDE_SETTINGS), text).unwrap();
            let mut stage = Stage::new();
            assert_eq!(
                register_plugin(&mut stage, dir.path()).unwrap_err(),
                problem
            );
            stage.commit().unwrap();
            assert_eq!(read(&dir.path().join(CLAUDE_SETTINGS)), text);
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
        std::fs::write(dir.path().join(CLAUDE_SETTINGS), "{,").unwrap();
        let mut stage = Stage::new();
        assert!(
            register_plugin(&mut stage, dir.path())
                .unwrap_err()
                .starts_with("is not valid JSON (")
        );
    }

    #[test]
    fn a_fresh_install_writes_the_starter_skills_and_entrypoints() {
        let env = offline_env();
        let network = Network {
            env: &env,
            proxy: None,
            interrupted: &never,
        };
        let catalogue = loaded(network, Ok(manifest()));
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let mut stage = Stage::new();
        let options = Options {
            targets: vec![Target::Cursor, Target::ClaudeCode, Target::GithubCopilot],
            name: Some("Detections".into()),
            ..Options::default()
        };
        let result = install(&mut stage, &root, &options, &catalogue).unwrap();
        stage.commit().unwrap();
        assert_eq!(
            result.strings("skills"),
            ["opentide-detection-rule", "detection-engineering"]
        );
        assert_eq!(
            result.strings("files"),
            [
                ".agents/skills/opentide-detection-rule/SKILL.md",
                ".agents/skills/detection-engineering/SKILL.md",
                ".cursor/skills/opentide-detection-rule/SKILL.md",
                ".cursor/skills/detection-engineering/SKILL.md",
                "CLAUDE.md",
                ".claude/skills/opentide-detection-rule/SKILL.md",
                ".claude/skills/detection-engineering/SKILL.md",
                "AGENTS.md",
                ".github/copilot-instructions.md",
            ]
        );
        assert_eq!(result.strings("also_applied"), ["generic"]);
        assert!(result.get("warnings").is_none());
        assert!(read(&root.join("CLAUDE.md")).starts_with("# Detections\n"));
        assert_eq!(
            std::fs::read(root.join(".claude/skills/detection-engineering/SKILL.md")).unwrap(),
            BUNDLED[0].1[0].1
        );
    }

    #[test]
    fn an_install_over_the_users_files_keeps_them() {
        let env = offline_env();
        let network = Network {
            env: &env,
            proxy: None,
            interrupted: &never,
        };
        let catalogue = loaded(network, Ok(manifest()));
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("CLAUDE.md"), "\u{feff}# Ours\r\n").unwrap();
        let ours = root.join(".claude/skills/detection-engineering");
        std::fs::create_dir_all(&ours).unwrap();
        std::fs::write(ours.join("NOTES.md"), "team notes").unwrap();
        let agents = root.join(".agents/skills/detection-engineering");
        std::fs::create_dir_all(agents.join("old")).unwrap();
        std::fs::write(agents.join("old/gone.md"), "an older version's").unwrap();
        let mut stage = Stage::new();
        let options = Options {
            targets: vec![Target::ClaudeCode],
            slugs: vec!["detection-engineering".into()],
            ..Options::default()
        };
        let result = install(&mut stage, &root, &options, &catalogue).unwrap();
        let changes = stage.step();
        assert!(
            changes
                .iter()
                .any(|change| change.action == "delete" && change.path.ends_with("old/gone.md")),
            "{changes:?}"
        );
        stage.commit().unwrap();
        assert_eq!(read(&root.join("CLAUDE.md")), "\u{feff}# Ours\r\n");
        assert_eq!(read(&ours.join("NOTES.md")), "team notes");
        assert!(!agents.join("old/gone.md").exists());
        assert!(!agents.join("old").exists());
        assert_eq!(result.strings("skipped"), ["CLAUDE.md"]);
        assert_eq!(
            result.strings("warnings"),
            [
                "Left CLAUDE.md unchanged because the file already exists; point it at .agents/skills/ by hand, or delete it and re-run to write opentide's template.",
                "Kept 1 file(s) in .claude/skills/detection-engineering that the skill does not ship (NOTES.md); delete them by hand if they are left over from an older version.",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn nothing_is_written_through_a_link() {
        let env = offline_env();
        let network = Network {
            env: &env,
            proxy: None,
            interrupted: &never,
        };
        let catalogue = loaded(network, Ok(manifest()));
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap().join("repo");
        let outside = std::fs::canonicalize(dir.path()).unwrap().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("SKILL.md"), "theirs").unwrap();
        let cursor = root.join(".cursor/skills/detection-engineering");
        std::fs::create_dir_all(&cursor).unwrap();
        std::os::unix::fs::symlink(outside.join("SKILL.md"), cursor.join("SKILL.md")).unwrap();
        std::fs::create_dir_all(root.join(".claude")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".claude/skills")).unwrap();
        let mut stage = Stage::new();
        let options = Options {
            targets: vec![Target::Cursor, Target::ClaudeCode],
            slugs: vec!["detection-engineering".into()],
            ..Options::default()
        };
        let result = install(&mut stage, &root, &options, &catalogue).unwrap();
        stage.commit().unwrap();
        assert_eq!(read(&outside.join("SKILL.md")), "theirs");
        assert!(!cursor.join("SKILL.md").is_symlink());
        assert_eq!(
            std::fs::read(cursor.join("SKILL.md")).unwrap(),
            BUNDLED[0].1[0].1
        );
        let warnings = result.strings("warnings");
        assert_eq!(
            warnings[0],
            "Replaced 1 link(s) in .cursor/skills/detection-engineering with the skill's own files (SKILL.md), rather than write through them."
        );
        assert!(
            warnings[1].starts_with(
                "Left .claude/skills/detection-engineering as it is: it links outside this repository, to "
            ),
            "{warnings:?}"
        );
    }

    #[test]
    fn unknown_slugs_and_an_unreadable_catalogue_stop_the_run() {
        let env = offline_env();
        let network = Network {
            env: &env,
            proxy: None,
            interrupted: &never,
        };
        let dir = tempfile::tempdir().unwrap();
        let catalogue = loaded(network, Ok(manifest()));
        let options = Options {
            targets: vec![Target::Generic],
            slugs: vec!["nope".into(), "detection-engineering".into(), "gone".into()],
            plugin: true,
            ..Options::default()
        };
        let mut stage = Stage::new();
        assert_eq!(
            install(&mut stage, dir.path(), &options, &catalogue),
            Err(Error::Usage(
                "Unknown skill slug(s): nope, gone. Run 'opentide setup skills discover' to list available skills."
                    .into()
            ))
        );
        // The plugin was registered first, as the oracle registers it.
        assert!(stage.is_file(&dir.path().join(CLAUDE_SETTINGS)));
        let failing = loaded(network, Err(catalogue::unavailable()));
        let mut stage = Stage::new();
        assert_eq!(
            install(
                &mut stage,
                dir.path(),
                &Options {
                    targets: vec![Target::Generic],
                    ..Options::default()
                },
                &failing
            ),
            Err(Error::Failed(catalogue::unavailable()))
        );
        assert_eq!(
            install(&mut stage, dir.path(), &Options::default(), &failing)
                .unwrap_err()
                .message(),
            "Choose at least one skills target (--cursor, --claude-code, --generic, --github-copilot, --plugin)"
        );
        // A plugin alone, or with Claude Code, reads no catalogue.
        let result = install(
            &mut Stage::new(),
            dir.path(),
            &Options {
                targets: vec![Target::ClaudeCode],
                plugin: true,
                ..Options::default()
            },
            &failing,
        )
        .unwrap();
        assert_eq!(result.strings("files"), [CLAUDE_SETTINGS, "CLAUDE.md"]);
        assert_eq!(result.text("plugin"), Some(PLUGIN_ID));
    }

    #[test]
    fn a_remote_skill_that_cannot_be_read_is_a_download_error() {
        let env = offline_env();
        let network = Network {
            env: &env,
            proxy: None,
            interrupted: &never,
        };
        let mut known = manifest();
        known.entries.push(catalogue::Entry {
            name: "Remote".into(),
            slug: "remote".into(),
            description: String::new(),
        });
        let catalogue = loaded(network, Ok(known));
        let _ = catalogue.tree.set(Some(vec![
            "skills/remote/SKILL.md".into(),
            "skills/remote/../escape".into(),
        ]));
        let dir = tempfile::tempdir().unwrap();
        let options = Options {
            targets: vec![Target::Generic],
            slugs: vec!["remote".into()],
            ..Options::default()
        };
        let error = install(&mut Stage::new(), dir.path(), &options, &catalogue).unwrap_err();
        assert_eq!(
            error.message(),
            "Could not download skill 'remote' from opentidehq/skills@main. Check network access and that the skills repository is publicly reachable."
        );
        // The preflight names it: its SKILL.md cannot be fetched here.
        assert_eq!(unavailable(&options, &catalogue).unwrap(), ["remote"]);
    }

    #[test]
    fn skill_paths_stay_in_the_skill() {
        let root = Path::new("/r");
        assert!(contained(root, "SKILL.md").is_ok());
        assert!(contained(root, "a/b.md").is_ok());
        for bad in ["", "/etc", "\\x", "a\\b", "a/../b", "./a", "a//b"] {
            assert!(contained(root, bad).is_err(), "{bad}");
        }
        assert_eq!(
            shown_some(&(1..=7).map(|n| n.to_string()).collect::<Vec<_>>()),
            "1, 2, 3, 4, 5 and 2 more"
        );
    }
}
