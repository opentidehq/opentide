//! The setup steps that write files from what opentide bundles: `setup env`
//! (`services/setup/env.py`), `setup platforms` (`platforms.py`), `setup
//! repo` (`repo.py`) and `setup mcp` (`mcp.py`). Each reads and writes
//! through the [`Stage`] and returns its result's members in the oracle's
//! order.

use std::path::{Path, PathBuf};

use super::jsonc;
use super::stage::Stage;
use crate::json::Json;

/// A step's result: its members, in order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StepResult {
    /// The members.
    pub fields: Vec<(String, Json)>,
}

impl StepResult {
    /// A result from `(key, value)` pairs.
    pub fn new<K: Into<String>>(fields: impl IntoIterator<Item = (K, Json)>) -> StepResult {
        StepResult {
            fields: fields.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// The strings of the list `key` (empty when there is none).
    pub fn strings(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Json::Array(items)) => items
                .iter()
                .filter_map(|item| match item {
                    Json::Str(text) => Some(text.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// The string `key`.
    pub fn text(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Json::Str(text)) => Some(text),
            _ => None,
        }
    }

    /// Sets `key`, in its place when it is there, else last.
    pub fn set(&mut self, key: &str, value: Json) {
        match self.fields.iter_mut().find(|(k, _)| k == key) {
            Some((_, slot)) => *slot = value,
            None => self.fields.push((key.to_owned(), value)),
        }
    }

    /// Removes `key`, returning its value.
    pub fn take(&mut self, key: &str) -> Option<Json> {
        let at = self.fields.iter().position(|(k, _)| k == key)?;
        Some(self.fields.remove(at).1)
    }
}

/// A list of strings as JSON.
pub fn strings(items: &[String]) -> Json {
    Json::Array(items.iter().map(Json::str).collect())
}

/// `path` as the results print it.
pub fn shown(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// What `.opentide/` is called in a workspace.
pub const OPENTIDE_DIR: &str = ".opentide";

// ---------------------------------------------------------------- env

const ENV_EXAMPLE_PATH: &str = ".env.example";
const GITIGNORE_PATH: &str = ".gitignore";
const ENV_EXAMPLE_CONTENT: &str = "# opentide environment template. Copy to .env and adjust as needed.\n# The CLI, MCP server, and SDK honour OPENTIDE_REPO_ROOT (same as --repo).\nOPENTIDE_REPO_ROOT=.\n";

/// A file setup must read as UTF-8 text that is not.
fn not_utf8(path: &Path) -> String {
    format!("{}: the file is not UTF-8", path.display())
}

/// The text of the file at `path`, if any.
///
/// # Errors
///
/// It cannot be read, or is not UTF-8.
pub fn read_text(stage: &Stage, path: &Path) -> Result<Option<String>, String> {
    match stage.read(path) {
        Ok(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| not_utf8(path)),
        Ok(None) => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// A `.gitignore` pattern as compared: `/opentide-reports/` is `opentide-reports`.
fn ignore_key(line: &str) -> &str {
    let line = line.trim().trim_start_matches('\u{feff}');
    let line = line.strip_prefix('/').unwrap_or(line);
    line.trim_end_matches('/')
}

/// Why `.gitignore` was not changed.
#[derive(Debug)]
pub enum GitignoreError {
    /// It is not UTF-8.
    NotUtf8,
    /// It cannot be read.
    Unreadable(String),
}

/// Adds each of `lines` that `target/.gitignore` lacks; the ones added
/// (`append_gitignore_lines`).
///
/// The file is made when missing. An existing one keeps its content, its
/// byte-order mark and its line endings; a line counts as present with or
/// without a leading or trailing `/`.
///
/// # Errors
///
/// The file is not UTF-8, or cannot be read.
pub fn append_gitignore_lines(
    stage: &mut Stage,
    target: &Path,
    lines: &[&str],
) -> Result<Vec<String>, GitignoreError> {
    let dest = target.join(GITIGNORE_PATH);
    if !stage.is_file(&dest) {
        let text: String = lines.iter().flat_map(|line| [*line, "\n"]).collect();
        stage.write(&dest, text);
        return Ok(lines.iter().map(|line| (*line).to_owned()).collect());
    }
    let bytes = stage
        .read(&dest)
        .map_err(|error| GitignoreError::Unreadable(error.to_string()))?
        .unwrap_or_default();
    let existing = String::from_utf8(bytes).map_err(|_| GitignoreError::NotUtf8)?;
    let present: Vec<&str> = existing.split(['\n', '\r']).map(ignore_key).collect();
    let missing: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| !present.contains(&ignore_key(line)))
        .collect();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    let newline = if existing.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let lead = if existing.is_empty() || existing.ends_with(['\n', '\r']) {
        ""
    } else {
        newline
    };
    let added: String = missing.iter().flat_map(|line| [*line, newline]).collect();
    stage.write(&dest, format!("{existing}{lead}{added}"));
    Ok(missing.iter().map(|line| (*line).to_owned()).collect())
}

/// `setup env`: `.env.example` with `OPENTIDE_REPO_ROOT`, and `.env` ignored.
///
/// # Errors
///
/// A file cannot be read, or is not UTF-8.
pub fn env(stage: &mut Stage, target: &Path) -> Result<StepResult, String> {
    stage.mkdir(target);
    let mut written = Vec::new();
    let mut skipped = Vec::new();
    let example = target.join(ENV_EXAMPLE_PATH);
    let changed = match read_text(stage, &example)? {
        Some(existing) if existing.contains("OPENTIDE_REPO_ROOT") => false,
        Some(existing) => {
            let suffix = if existing.ends_with('\n') { "" } else { "\n" };
            stage.write(
                &example,
                format!("{existing}{suffix}OPENTIDE_REPO_ROOT=.\n"),
            );
            true
        }
        None => {
            stage.write(&example, ENV_EXAMPLE_CONTENT);
            true
        }
    };
    if changed {
        written.push(ENV_EXAMPLE_PATH.to_owned());
    } else {
        skipped.push(ENV_EXAMPLE_PATH.to_owned());
    }
    match append_gitignore_lines(stage, target, &[".env"]) {
        Ok(added) if !added.is_empty() => written.push(GITIGNORE_PATH.to_owned()),
        Ok(_) => skipped.push(GITIGNORE_PATH.to_owned()),
        Err(GitignoreError::NotUtf8) => return Err(not_utf8(&target.join(GITIGNORE_PATH))),
        Err(GitignoreError::Unreadable(error)) => {
            return Err(format!(
                "{}: {error}",
                target.join(GITIGNORE_PATH).display()
            ));
        }
    }
    let message = if written.iter().any(|path| path == ENV_EXAMPLE_PATH) {
        "Environment example written"
    } else {
        "Environment example already present"
    };
    Ok(StepResult::new([
        ("message", Json::str(message)),
        ("path", Json::str(shown(target))),
        ("files", strings(&written)),
        ("skipped", strings(&skipped)),
    ]))
}

// ---------------------------------------------------------------- platforms

/// A platform's configuration file, `<id>.toml`, when it is built in.
pub fn platform_file(platform: &str) -> Option<String> {
    opentide_schema::platforms::is_builtin(platform).then(|| format!("{platform}.toml"))
}

/// `content` with `enabled = true` in its `[platform]` table
/// (`_enable_platform_toml`), its line endings kept.
pub fn enable_platform_toml(content: &str) -> String {
    #[expect(clippy::expect_used, reason = "regex literals")]
    let (present, value) = (
        regex::Regex::new(r"(?m)^enabled\s*=").expect("regex"),
        regex::Regex::new(r"(?m)^enabled\s*=\s*\w+[ \t]*(\r?)$").expect("regex"),
    );
    if present.is_match(content) {
        return value
            .replacen(content, 1, "enabled = true${1}")
            .into_owned();
    }
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    content.replacen(
        "[platform]",
        &format!("[platform]{newline}enabled = true"),
        1,
    )
}

/// `setup platforms`: each platform's bundled configuration, enabled.
///
/// # Errors
///
/// A file cannot be read, or is not UTF-8.
pub fn platforms(
    stage: &mut Stage,
    target: &Path,
    chosen: &[String],
) -> Result<StepResult, String> {
    let dest = target.join(OPENTIDE_DIR).join("configurations/platforms");
    stage.mkdir(&dest);
    let (mut written, mut updated, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    for platform in chosen {
        let Some(file) = platform_file(platform) else {
            continue;
        };
        let Some(template) =
            opentide_schema::configuration::bundled::text(&format!("platforms/{file}"))
        else {
            tracing::warn!(platform = %platform, "platform_template_missing");
            continue;
        };
        let out = dest.join(&file);
        let relative = format!("{OPENTIDE_DIR}/configurations/platforms/{file}");
        if let Some(current) = read_text(stage, &out)? {
            let enabled = enable_platform_toml(&current);
            if enabled == current {
                skipped.push(relative);
            } else {
                stage.write(&out, enabled);
                updated.push(relative);
            }
            continue;
        }
        stage.write(&out, enable_platform_toml(template));
        written.push(relative);
    }
    let message = if !written.is_empty() {
        "Platform configuration files created"
    } else if !updated.is_empty() {
        "Platform enabled flags updated"
    } else {
        "Platform configuration files already present"
    };
    let mut result = StepResult::new([
        ("message", Json::str(message)),
        ("path", Json::str(shown(target))),
        ("platforms", strings(chosen)),
        ("files", strings(&written)),
    ]);
    if !updated.is_empty() {
        result.set("updated", strings(&updated));
    }
    if !skipped.is_empty() {
        result.set("skipped", strings(&skipped));
    }
    Ok(result)
}

// ---------------------------------------------------------------- repo

const SCAFFOLD_DIRS: [&str; 11] = [
    "objects/threats",
    "objects/objectives",
    "objects/rules",
    ".opentide/configurations/platforms",
    ".opentide/schemas",
    ".opentide/templates",
    ".opentide/exports",
    ".opentide/inflight",
    "docs/rules",
    "docs/threats",
    "docs/objectives",
];

/// What a new repository's `.gitignore` holds besides [`OPENTIDE_IGNORES`].
const PYTHON_IGNORES: [&str; 7] = [
    "__pycache__/",
    "*.pyc",
    ".venv/",
    "dist/",
    "build/",
    "*.egg-info/",
    ".pytest_cache/",
];

/// The files opentide writes that a repository must not commit.
const OPENTIDE_IGNORES: [&str; 3] = [
    ".opentide/exports/*.export.json",
    ".opentide/states/sharing.jsonl",
    "opentide-reports/",
];

/// `setup repo`'s README and scaffold choices.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepoOptions {
    /// `--name`.
    pub name: Option<String>,
    /// `--org`.
    pub org: Option<String>,
    /// `--description`.
    pub description: Option<String>,
    /// `--platform`, in order.
    pub platforms: Vec<String>,
}

/// The folder name of `target`, the repository's default name.
pub fn folder_name(target: &Path) -> String {
    target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn readme(target: &Path, options: &RepoOptions) -> String {
    let name = options
        .name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| folder_name(target));
    let platforms = if options.platforms.is_empty() {
        format!("- (configure platforms in {OPENTIDE_DIR}/configurations/)")
    } else {
        options
            .platforms
            .iter()
            .map(|platform| format!("- {platform}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mut metadata = String::new();
    if let Some(description) = options
        .description
        .as_deref()
        .filter(|text| !text.is_empty())
    {
        metadata.push_str(&format!("\n{description}\n"));
    }
    if let Some(org) = options.org.as_deref().filter(|text| !text.is_empty()) {
        metadata.push_str(&format!("\n**Organisation:** {org}\n"));
    }
    let deploy = if options.platforms.is_empty() {
        "opentide deploy --dry-run".to_owned()
    } else {
        options
            .platforms
            .iter()
            .map(|platform| format!("opentide deploy --platform {platform} --dry-run"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "# {name}\n{metadata}\n## Quick start\n\n```bash\nopentide setup\nopentide validate\nopentide generate\n{deploy}\n```\n\n## Platforms\n\n{platforms}\n"
    )
}

/// `setup repo`: the scaffold, the README, `.gitignore`, and the platforms.
///
/// # Errors
///
/// A file cannot be read, or is not UTF-8.
pub fn repo(stage: &mut Stage, target: &Path, options: &RepoOptions) -> Result<StepResult, String> {
    stage.mkdir(target);
    for relative in SCAFFOLD_DIRS {
        let dir = target.join(relative);
        stage.mkdir(&dir);
        if stage.entries(&dir).is_empty() {
            stage.write(&dir.join(".gitkeep"), "");
        }
    }
    let (mut files, mut skipped, mut warnings) = (Vec::new(), Vec::new(), Vec::new());
    let readme_path = target.join("README.md");
    if stage.is_file(&readme_path) {
        skipped.push("README.md".to_owned());
        let ignored: Vec<&str> = [
            ("--name", &options.name),
            ("--org", &options.org),
            ("--description", &options.description),
        ]
        .into_iter()
        .filter(|(_, value)| value.as_deref().is_some_and(|text| !text.is_empty()))
        .map(|(flag, _)| flag)
        .collect();
        if !ignored.is_empty() {
            warnings.push(format!(
                "Left README.md unchanged; ignored {} because the file already exists",
                ignored.join(", ")
            ));
        }
    } else {
        stage.write(&readme_path, readme(target, options));
        files.push("README.md".to_owned());
    }
    let gitignore = target.join(GITIGNORE_PATH);
    let added = if stage.is_file(&gitignore) {
        match append_gitignore_lines(stage, target, &OPENTIDE_IGNORES) {
            Ok(added) => added,
            Err(GitignoreError::NotUtf8) => {
                warnings.push(format!(
                    "Left .gitignore unchanged: it is not UTF-8. Add these lines to it: {}",
                    OPENTIDE_IGNORES.join(", ")
                ));
                Vec::new()
            }
            Err(GitignoreError::Unreadable(error)) => {
                return Err(format!("{}: {error}", gitignore.display()));
            }
        }
    } else {
        let all: Vec<&str> = PYTHON_IGNORES
            .iter()
            .chain(OPENTIDE_IGNORES.iter())
            .copied()
            .collect();
        append_gitignore_lines(stage, target, &all).map_err(|_| not_utf8(&gitignore))?
    };
    if added.is_empty() {
        skipped.push(GITIGNORE_PATH.to_owned());
    } else {
        files.push(GITIGNORE_PATH.to_owned());
    }
    let name = options
        .name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| folder_name(target));
    let mut result = StepResult::new([
        ("message", Json::str("Repository scaffold created")),
        ("path", Json::str(shown(target))),
        ("platforms", strings(&options.platforms)),
        ("name", Json::str(name)),
        ("scaffolded", Json::Bool(true)),
        ("files", strings(&files)),
        ("gitignore_added", strings(&added)),
    ]);
    if !skipped.is_empty() {
        result.set("skipped", strings(&skipped));
    }
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    if !options.platforms.is_empty() {
        let platforms = platforms(stage, target, &options.platforms)?;
        result.set(
            "platform_files",
            Json::Array(platforms.strings("files").iter().map(Json::str).collect()),
        );
    }
    Ok(result)
}

// ---------------------------------------------------------------- mcp

/// An MCP host: its command-line value, the file it reads, its template.
pub const MCP_HOSTS: [(&str, &str, &str); 4] = [
    (
        "vscode",
        ".vscode/mcp.json",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/setup/mcp/vscode.json"
        )),
    ),
    (
        "cursor",
        ".cursor/mcp.json",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/setup/mcp/cursor.json"
        )),
    ),
    (
        "claude-code",
        ".mcp.json",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/setup/mcp/claude-code.json"
        )),
    ),
    (
        "generic",
        "opentide.mcp.json",
        include_str!(concat!(
            env!("OPENTIDE_ASSETS"),
            "/src/opentide/data/setup/mcp/generic.json"
        )),
    ),
];

/// The opentide VS Code extension.
pub const EXTENSION_ID: &str = "opentidehq.opentide";

/// What `setup mcp --vscode` says when the workspace recommends the extension.
pub const EXTENSION_MCP_NOTE: &str = "The opentide VS Code extension (opentidehq.opentide), which .vscode/extensions.json recommends, provides the opentide MCP server to VS Code; .vscode/mcp.json is for teammates without it";

/// Whether `.vscode/extensions.json` recommends the opentide extension.
pub fn recommends_extension(stage: &Stage, target: &Path) -> bool {
    let path = target.join(".vscode/extensions.json");
    let Ok(Some(text)) = read_text(stage, &path) else {
        return false;
    };
    jsonc::parse(&text).is_ok_and(|value| {
        value
            .get("recommendations")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.iter().any(|item| item == EXTENSION_ID))
    })
}

/// Writes or merges `host`'s configuration; its path relative to `target`.
///
/// # Errors
///
/// The existing file cannot be merged: the reason, for the warning.
pub fn write_mcp_config(stage: &mut Stage, target: &Path, host: &str) -> Result<String, String> {
    let Some((_, relative, template)) = MCP_HOSTS.iter().find(|(name, _, _)| *name == host) else {
        return Err(format!("unknown MCP host {host}"));
    };
    let template = Json::parse(template).unwrap_or(Json::Null);
    let dest = target.join(relative);
    let text = if stage.is_file(&dest) {
        let existing = match stage.read(&dest) {
            Ok(Some(bytes)) => String::from_utf8(bytes)
                .map_err(|_| "is not valid JSON (the file is not UTF-8)".to_owned())?,
            Ok(None) => String::new(),
            Err(error) => return Err(format!("is not valid JSON ({error})")),
        };
        jsonc::merge(&existing, &template).map_err(|error| error.to_string())?
    } else {
        crate::json::document_text(&template, true)
    };
    stage.write(&dest, text);
    Ok((*relative).to_owned())
}

/// The warning for an MCP configuration left unchanged.
pub fn mcp_config_warning(relative: &str, problem: &str) -> String {
    format!("{relative} {problem}; left unchanged. Add the opentide server to it by hand.")
}

/// Why `opentide mcp start`, which every configuration launches, cannot
/// start here: what [`McpServer::probe`] finds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McpServer {
    /// What the server needs that this installation cannot satisfy.
    pub missing: Vec<String>,
    /// The command that repairs the installation.
    pub hint: String,
}

impl McpServer {
    /// The server `opentide mcp start` runs: this program's own
    /// ([`crate::mcp`]), compiled in with everything it serves, so it starts
    /// wherever this program does and needs nothing installed beside it
    /// (UC-6.0d, #841). The oracle's server was a Python module whose
    /// imports the environment could lack.
    pub fn probe() -> McpServer {
        McpServer::default()
    }
}

/// `setup mcp`: each host's configuration; `server` is what
/// [`McpServer::probe`] found about `opentide mcp start`.
pub fn mcp(
    stage: &mut Stage,
    target: &Path,
    hosts: &[String],
    server: Option<&McpServer>,
) -> StepResult {
    let (mut written, mut skipped, mut warnings) = (Vec::new(), Vec::new(), Vec::new());
    for host in hosts {
        match write_mcp_config(stage, target, host) {
            Ok(relative) => written.push(relative),
            Err(problem) => {
                let relative = MCP_HOSTS
                    .iter()
                    .find(|(name, _, _)| name == host)
                    .map_or(host.as_str(), |(_, relative, _)| relative);
                skipped.push(relative.to_owned());
                warnings.push(mcp_config_warning(relative, &problem));
            }
        }
    }
    let mut result = StepResult::new([
        ("message", Json::str("MCP configuration generated")),
        ("path", Json::str(shown(target))),
        ("files", strings(&written)),
    ]);
    if !skipped.is_empty() {
        result.set("skipped", strings(&skipped));
    }
    if hosts.iter().any(|host| host == "vscode") && recommends_extension(stage, target) {
        result.set("extension_mcp", Json::Bool(true));
        result.set("detail", Json::str(EXTENSION_MCP_NOTE));
    }
    if hosts.iter().any(|host| host == "generic") {
        result.set(
            "advice",
            Json::str("Copy opentide.mcp.json into your editor MCP settings or run opentide setup mcp with a specific host flag."),
        );
    }
    // Every configuration runs `opentide mcp start`. Say so now rather than
    // leaving the user to debug a server their editor silently fails to start.
    match server.filter(|server| !server.missing.is_empty()) {
        Some(server) => {
            result.set("mcp_available", Json::Bool(false));
            warnings.push(format!(
                "These configs launch opentide mcp start, which cannot import {} in this environment. Repair it with: {}",
                server.missing.join(", "),
                server.hint
            ));
        }
        None => result.set("mcp_available", Json::Bool(true)),
    }
    if !warnings.is_empty() {
        result.set("warnings", strings(&warnings));
    }
    result
}

/// `path` relative to `base` when it is below it.
pub fn relative_to(path: &Path, base: &Path) -> PathBuf {
    path.strip_prefix(base)
        .map_or_else(|_| path.to_path_buf(), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabling_a_platform_keeps_crlf_and_the_rest_of_the_line_endings() {
        assert_eq!(
            enable_platform_toml("[platform]\r\nenabled = false\r\nx = 1\r\n"),
            "[platform]\r\nenabled = true\r\nx = 1\r\n"
        );
        assert_eq!(
            enable_platform_toml("[platform]\r\nx = 1\r\n"),
            "[platform]\r\nenabled = true\r\nx = 1\r\n"
        );
        assert_eq!(
            enable_platform_toml("[platform]\nenabled=false\n"),
            "[platform]\nenabled = true\n"
        );
        // Already enabled: no change, so the step skips the file.
        let enabled = "[platform]\nenabled = true\n";
        assert_eq!(enable_platform_toml(enabled), enabled);
    }

    #[test]
    fn gitignore_lines_are_appended_once_in_the_files_line_endings() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".gitignore"), "\u{feff}/build\r\nnode_modules").unwrap();
        let mut stage = Stage::new();
        let added = append_gitignore_lines(&mut stage, root, &["build/", ".env"]).unwrap();
        assert_eq!(added, [".env"]);
        assert_eq!(
            stage.read(&root.join(".gitignore")).unwrap().unwrap(),
            "\u{feff}/build\r\nnode_modules\r\n.env\r\n".as_bytes()
        );
        assert!(
            append_gitignore_lines(&mut stage, root, &[".env"])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_repo_scaffold_keeps_a_folder_with_content_and_an_existing_readme() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("objects/rules")).unwrap();
        std::fs::write(root.join("objects/rules/a.yaml"), "x").unwrap();
        std::fs::write(root.join("README.md"), "mine").unwrap();
        let mut stage = Stage::new();
        let options = RepoOptions {
            name: Some("X".into()),
            platforms: vec!["sentinel".into()],
            ..RepoOptions::default()
        };
        let result = repo(&mut stage, root, &options).unwrap();
        assert!(!stage.is_file(&root.join("objects/rules/.gitkeep")));
        assert!(stage.is_file(&root.join("objects/threats/.gitkeep")));
        assert_eq!(result.strings("skipped"), ["README.md"]);
        assert_eq!(
            result.strings("warnings"),
            ["Left README.md unchanged; ignored --name because the file already exists"]
        );
        assert_eq!(
            result.strings("platform_files"),
            [".opentide/configurations/platforms/sentinel.toml"]
        );
        let toml = String::from_utf8(
            stage
                .read(&root.join(".opentide/configurations/platforms/sentinel.toml"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(toml.contains("enabled = true"), "{toml}");
    }

    #[test]
    fn the_readme_names_the_platforms_and_the_metadata() {
        let options = RepoOptions {
            name: Some("Detections".into()),
            org: Some("Blue".into()),
            description: Some("Ours".into()),
            platforms: vec!["sentinel".into(), "splunk".into()],
        };
        let text = readme(Path::new("/x/ws"), &options);
        assert!(
            text.starts_with("# Detections\n\nOurs\n\n**Organisation:** Blue\n\n## Quick start")
        );
        assert!(text.contains("opentide deploy --platform splunk --dry-run\n```"));
        assert!(text.ends_with("- sentinel\n- splunk\n"));
    }

    #[test]
    fn an_mcp_file_with_comments_is_merged_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        let before = "{\r\n  // ours\r\n  \"servers\": {\"x\": {}}\r\n}\r\n";
        std::fs::write(root.join(".vscode/mcp.json"), before).unwrap();
        let mut stage = Stage::new();
        let result = mcp(&mut stage, root, &["vscode".into()], None);
        assert_eq!(result.strings("files"), [".vscode/mcp.json"]);
        let after = String::from_utf8(stage.read(&root.join(".vscode/mcp.json")).unwrap().unwrap())
            .unwrap();
        assert!(after.starts_with("{\r\n  // ours\r\n"), "{after}");
        assert!(after.contains("\"opentide\""));
        std::fs::write(root.join(".cursor.json"), "").unwrap();
        std::fs::create_dir_all(root.join(".cursor")).unwrap();
        std::fs::write(root.join(".cursor/mcp.json"), "[]").unwrap();
        let refused = mcp(&mut Stage::new(), root, &["cursor".into()], None);
        assert_eq!(refused.strings("skipped"), [".cursor/mcp.json"]);
        assert_eq!(
            refused.strings("warnings"),
            [
                ".cursor/mcp.json is not a JSON object; left unchanged. Add the opentide server to it by hand."
            ]
        );
    }

    #[test]
    fn an_env_example_without_a_final_newline_gets_one_before_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join(".env.example"), "A=1").unwrap();
        let mut stage = Stage::new();
        let result = env(&mut stage, root).unwrap();
        assert_eq!(result.strings("files"), [".env.example", ".gitignore"]);
        assert_eq!(
            stage.read(&root.join(".env.example")).unwrap().unwrap(),
            b"A=1\nOPENTIDE_REPO_ROOT=.\n"
        );
        // A file that ends its last line is not given a blank one.
        std::fs::write(root.join(".env.example"), "A=1\n").unwrap();
        let mut stage = Stage::new();
        env(&mut stage, root).unwrap();
        assert_eq!(
            stage.read(&root.join(".env.example")).unwrap().unwrap(),
            b"A=1\nOPENTIDE_REPO_ROOT=.\n"
        );
        // One that names the root already is left alone.
        let mut stage = Stage::new();
        std::fs::write(root.join(".env.example"), "OPENTIDE_REPO_ROOT=x").unwrap();
        let kept = env(&mut stage, root).unwrap();
        assert_eq!(kept.strings("skipped")[0], ".env.example");
        assert_eq!(
            kept.text("message"),
            Some("Environment example already present")
        );
    }

    #[test]
    fn only_the_vscode_host_reports_the_extension_server() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(
            root.join(".vscode/extensions.json"),
            r#"{"recommendations": ["opentidehq.opentide"]}"#,
        )
        .unwrap();
        let cursor = mcp(&mut Stage::new(), root, &["cursor".into()], None);
        assert_eq!(cursor.get("extension_mcp"), None);
        assert_eq!(cursor.get("detail"), None);
        let vscode = mcp(&mut Stage::new(), root, &["vscode".into()], None);
        assert_eq!(vscode.get("extension_mcp"), Some(&Json::Bool(true)));
        assert_eq!(vscode.text("detail"), Some(EXTENSION_MCP_NOTE));
    }

    #[test]
    fn a_server_that_cannot_start_is_reported_unavailable_with_its_repair() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let broken = McpServer {
            missing: vec!["mcp.server.mcpserver".into()],
            hint: "pip install 'mcp>=2.3,<3'".into(),
        };
        let result = mcp(&mut Stage::new(), root, &["cursor".into()], Some(&broken));
        assert_eq!(result.get("mcp_available"), Some(&Json::Bool(false)));
        assert_eq!(
            result.strings("warnings"),
            [
                "These configs launch opentide mcp start, which cannot import mcp.server.mcpserver in this environment. Repair it with: pip install 'mcp>=2.3,<3'"
            ]
        );
        let fine = McpServer::default();
        for server in [Some(&fine), None] {
            let result = mcp(&mut Stage::new(), root, &["cursor".into()], server);
            assert_eq!(result.get("mcp_available"), Some(&Json::Bool(true)));
            assert_eq!(result.get("warnings"), None);
        }
        // The server is this program's: nothing is ever missing.
        assert_eq!(McpServer::probe(), McpServer::default());
    }
}
