//! The workspace's values a Tab press completes (#841): object UUIDs and
//! files, object types, ATT&CK techniques, platforms, strategies, tenants and
//! diagnostic codes, as the Python CLI's Typer callbacks completed them
//! (`cli/completion.py`, 0.28.0).
//!
//! [`attach`] gives each option of the command tree its
//! [`ArgValueCompleter`], by option name, so `--uuid` completes the same way
//! on `validate`, `share` and every `share` subcommand. A completer reads the
//! workspace through `opentide-workspace` (the root, the configuration's
//! object folders, the discovery scan, `catalogue::text_fields` on the first
//! lines of each object file) and never parses an object or opens the
//! catalogue the way a command does. A source that cannot be read completes
//! nothing; nothing here prints.
//!
//! clap_complete hands a completer only the word being completed, so the
//! words already on the command line that change the answer (`--repo`,
//! `--data`, `--type`, `--platform`) are read once, before completing, into
//! the [`Context`] every completer shares.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use clap::Command;
use clap_complete::engine::{ArgValueCompleter, CompletionCandidate};
use opentide_workspace::fs::{FileSystem, OsFs};
use opentide_workspace::root::{self, Roots};
use opentide_workspace::{Configuration, RootOptions};

use crate::env::Env;

/// The object families, in the order completion lists them, with their
/// default folders.
pub const FAMILIES: [(&str, &str); 3] = [
    ("rule", "objects/rules/"),
    ("threat", "objects/threats/"),
    ("objective", "objects/objectives/"),
];

/// Every family.
const ALL_KINDS: [&str; 3] = ["rule", "threat", "objective"];

/// Rules only: what `validate query`, `deploy` and `query` read.
const RULES: [&str; 1] = ["rule"];

/// How far into an object file its `name` and `metadata.uuid` are looked for.
pub const HEADER_LINES: usize = 200;

/// The strategies a run deploys, and what each one deploys.
pub const STRATEGIES: [(&str, &str); 2] = [
    ("PREVIEW", "Deployment from Pull/Merge Requests"),
    (
        "RELEASE",
        "Deployment from the default branch (also called trunk, or main branch)",
    ),
];

/// The ATT&CK vocabulary's field, and its file under a data root's
/// `vocabulary/` folder.
const ATTACK: &str = "att&ck";

/// `query --tenant`'s value that selects every tenant.
const ALL_TENANTS: &str = "all";

/// What every completer of one Tab press reads: the words on the command
/// line that change the answer, the working directory, the environment, and
/// the workspace, read once on first use.
#[derive(Debug)]
pub struct Context {
    /// `--repo`, as typed.
    repo: Option<PathBuf>,
    /// `--data`, as typed.
    data: Option<PathBuf>,
    /// The `--type` values typed.
    types: Vec<String>,
    /// The `--platform` values typed.
    platforms: Vec<String>,
    /// Whether the shell is bash, whose script inserts a candidate as it is:
    /// a space or shell character in it is escaped here.
    bash: bool,
    /// The working directory.
    cwd: PathBuf,
    /// `OPENTIDE_REPO_ROOT`.
    repo_root_env: Option<PathBuf>,
    /// `OPENTIDE_TIDE_WORKSPACE`.
    tide_workspace_env: Option<PathBuf>,
    /// `OPENTIDE_DATA_ROOT`.
    data_root_env: Option<PathBuf>,
    /// The workspace, read on first use.
    workspace: OnceLock<Workspace>,
}

/// The workspace as completion sees it.
#[derive(Debug)]
struct Workspace {
    /// Where it is.
    roots: Roots,
    /// Its configuration, when it resolves.
    config: Option<Configuration>,
}

/// One object file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectFile {
    /// Its family.
    pub kind: &'static str,
    /// The file.
    pub path: PathBuf,
}

fn env_path(env: &Env, name: &str) -> Option<PathBuf> {
    env.get(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

impl Context {
    /// The context of the command line `words` (the program's name first,
    /// the word being completed last, as the shell passes them), completed
    /// for `shell` in `cwd`.
    pub fn new(words: &[String], shell: &str, cwd: PathBuf, env: &Env) -> Self {
        let mut repo = None;
        let mut data = None;
        let mut types = Vec::new();
        let mut platforms = Vec::new();
        // The last word is the one being completed: it is not typed yet.
        let before = words.get(1..words.len().saturating_sub(1)).unwrap_or(&[]);
        let mut index = 0;
        while index < before.len() {
            let word = before[index].as_str();
            index += 1;
            if word == "--" {
                break;
            }
            let (name, inline) = match word.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (word, None),
            };
            if !matches!(name, "--repo" | "--data" | "--type" | "--platform") {
                continue;
            }
            let value = inline.or_else(|| {
                // bash splits `--repo=x` into `--repo`, `=` and `x`.
                if before.get(index).is_some_and(|next| next == "=") {
                    index += 1;
                }
                let value = before.get(index).cloned();
                index += 1;
                value
            });
            let Some(value) = value.filter(|value| !value.is_empty()) else {
                continue;
            };
            match name {
                "--repo" => repo = Some(PathBuf::from(value)),
                "--data" => data = Some(PathBuf::from(value)),
                "--type" => types.push(value),
                _ => platforms.push(value),
            }
        }
        Self {
            repo,
            data,
            types,
            platforms,
            bash: shell == "bash",
            cwd,
            repo_root_env: env_path(env, "OPENTIDE_REPO_ROOT"),
            tide_workspace_env: env_path(env, "OPENTIDE_TIDE_WORKSPACE"),
            data_root_env: env_path(env, "OPENTIDE_DATA_ROOT"),
            workspace: OnceLock::new(),
        }
    }

    fn workspace(&self) -> &Workspace {
        self.workspace.get_or_init(|| {
            let options = RootOptions {
                repo: self.repo.clone(),
                repo_root_env: self.repo_root_env.clone(),
                tide_workspace_env: self.tide_workspace_env.clone(),
                cwd: self.cwd.clone(),
            };
            let roots = root::resolve(&OsFs, &options);
            let config = opentide_workspace::config::load(&OsFs, &roots).ok();
            Workspace { roots, config }
        })
    }

    /// The families of `kinds`, narrowed to the `--type` values typed.
    fn selected(&self, kinds: &[&'static str]) -> Vec<&'static str> {
        let narrowed: Vec<&'static str> = kinds
            .iter()
            .copied()
            .filter(|kind| self.types.iter().any(|typed| typed == kind))
            .collect();
        if narrowed.is_empty() {
            kinds.to_vec()
        } else {
            narrowed
        }
    }

    /// The folder of `kind`: the configuration's, else the default under the
    /// workspace.
    fn folder(&self, kind: &str) -> PathBuf {
        let workspace = self.workspace();
        if let Some(folder) = workspace
            .config
            .as_ref()
            .and_then(|config| config.folder(kind))
        {
            return folder.to_path_buf();
        }
        let default = FAMILIES
            .iter()
            .find(|(family, _)| *family == kind)
            .map_or("objects", |(_, folder)| folder);
        workspace.roots.workspace.join(default)
    }

    /// Every object file of `kinds`, family by family, each family's sorted:
    /// the files directly in its folder, as the registry lists them.
    pub fn object_files(&self, kinds: &[&'static str]) -> Vec<ObjectFile> {
        let mut files = Vec::new();
        for (kind, _) in FAMILIES {
            if !kinds.contains(&kind) {
                continue;
            }
            let Ok(scan) = opentide_workspace::discover::scan(&OsFs, &self.folder(kind)) else {
                continue;
            };
            files.extend(scan.files.into_iter().map(|path| ObjectFile { kind, path }));
        }
        files
    }

    /// `--uuid`: the UUIDs of the objects of `kinds` that start with
    /// `current` (in any case), each with the object's name and family.
    pub fn uuids(&self, kinds: &[&'static str], current: &str) -> Vec<CompletionCandidate> {
        let prefix = current.to_lowercase();
        let mut seen = HashSet::new();
        let mut found = Vec::new();
        for file in self.object_files(&self.selected(kinds)) {
            let (uuid, name) = header(&file.path);
            let Some(uuid) = uuid.filter(|uuid| is_uuid(uuid)) else {
                continue;
            };
            if !uuid.to_lowercase().starts_with(&prefix) || !seen.insert(uuid.clone()) {
                continue;
            }
            let name = name.unwrap_or_else(|| file_name(&file.path));
            found.push(candidate(uuid, format!("{name} ({})", file.kind)));
        }
        found
    }

    /// `--file`: the object files of `kinds` whose path starts with
    /// `current`, from the working directory when inside it, else from the
    /// workspace; when nothing matches and `current` names no folder, the
    /// files whose name starts with it. Each with the object's name.
    pub fn files(&self, kinds: &[&'static str], current: &str) -> Vec<CompletionCandidate> {
        let current = if self.bash {
            bash_unescape(current)
        } else {
            current.to_owned()
        };
        let workspace = self.workspace();
        let root = OsFs.resolve(&workspace.roots.repo);
        let cwd = OsFs.resolve(&self.cwd);
        let files = self.object_files(&self.selected(kinds));
        let mut found: Vec<(String, &Path)> = files
            .iter()
            .map(|file| (shown_path(&OsFs.resolve(&file.path), &cwd, &root), file))
            .filter(|(shown, _)| shown.starts_with(&current))
            .map(|(shown, file)| (shown, file.path.as_path()))
            .collect();
        if found.is_empty() && !current.contains(['/', std::path::MAIN_SEPARATOR]) {
            found = files
                .iter()
                .map(|file| (file_name(&file.path), file.path.as_path()))
                .filter(|(name, _)| name.starts_with(&current))
                .collect();
        }
        found
            .into_iter()
            // A line break cannot be escaped: bash would split the candidate.
            .filter(|(shown, _)| !(self.bash && shown.contains('\n')))
            .map(|(shown, path)| {
                let value = if self.bash { bash_word(&shown) } else { shown };
                candidate(value, header(path).1.unwrap_or_default())
            })
            .collect()
    }

    /// `--type`: the families that start with `current`, each with its
    /// folder.
    pub fn types(&self, current: &str) -> Vec<CompletionCandidate> {
        FAMILIES
            .iter()
            .filter(|(kind, _)| kind.starts_with(current))
            .map(|(kind, folder)| candidate((*kind).to_owned(), (*folder).to_owned()))
            .collect()
    }

    /// `--technique`: the ATT&CK ids that start with `current` (in any
    /// case), with their titles, from `--data`'s or `OPENTIDE_DATA_ROOT`'s
    /// vocabulary, else the bundled one.
    pub fn techniques(&self, current: &str) -> Vec<CompletionCandidate> {
        let prefix = current.to_uppercase();
        let data = self.data.as_ref().or(self.data_root_env.as_ref());
        let vocabulary = match data {
            Some(data) => {
                let file = format!("{ATTACK}{}", opentide_schema::vocab::SUFFIX);
                let path = self.absolute(data).join("vocabulary").join(&file);
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|text| {
                        opentide_schema::vocab::Vocabulary::from_file(&file, &text).ok()
                    })
                    .map(Arc::new)
            }
            None => opentide_schema::vocab::bundled::get(ATTACK),
        };
        let Some(vocabulary) = vocabulary else {
            return Vec::new();
        };
        let mut found: Vec<(&str, &str)> = vocabulary
            .entries
            .values()
            .filter_map(|entry| {
                let id = entry
                    .extra
                    .get("id")
                    .and_then(toml::Value::as_str)
                    .unwrap_or(entry.key.as_str());
                is_technique(id).then_some((id, entry.name.as_str()))
            })
            .filter(|(id, _)| id.starts_with(&prefix))
            .collect();
        found.sort_by_key(|(id, _)| technique_order(id));
        found.dedup_by_key(|(id, _)| *id);
        found
            .into_iter()
            .map(|(id, name)| candidate(id.to_owned(), name.to_owned()))
            .collect()
    }

    /// `--platform`: of `choices`, the platforms the workspace enables first,
    /// marked `enabled`, then the others; those that start with `current`
    /// (in any case).
    pub fn platforms(&self, choices: &[String], current: &str) -> Vec<CompletionCandidate> {
        let enabled = self.enabled_platforms();
        let prefix = current.to_lowercase();
        let mut ordered: Vec<(&str, bool)> = enabled
            .iter()
            .filter(|name| choices.contains(name))
            .map(|name| (name.as_str(), true))
            .collect();
        ordered.extend(
            choices
                .iter()
                .filter(|name| !enabled.contains(name))
                .map(|name| (name.as_str(), false)),
        );
        ordered
            .into_iter()
            .filter(|(name, _)| name.to_lowercase().starts_with(&prefix))
            .map(|(name, on)| {
                CompletionCandidate::new(name).help(on.then(|| "enabled".to_owned().into()))
            })
            .collect()
    }

    /// The platforms the workspace's configuration enables.
    fn enabled_platforms(&self) -> Vec<String> {
        self.workspace()
            .config
            .as_ref()
            .map(|config| {
                let tree = opentide_compile::Json::from_node(&config.resolved.tree);
                opentide_compile::plan::enabled(&tree)
            })
            .unwrap_or_default()
    }

    /// `--strategy`: `PREVIEW` and `RELEASE`, those that start with
    /// `current` (in any case), with what each deploys.
    pub fn strategies(&self, current: &str) -> Vec<CompletionCandidate> {
        let prefix = current.to_uppercase();
        STRATEGIES
            .iter()
            .filter(|(name, _)| name.starts_with(&prefix))
            .map(|(name, meaning)| candidate((*name).to_owned(), (*meaning).to_owned()))
            .collect()
    }

    /// `--tenant`: the tenants of the `--platform` typed, else of every
    /// enabled platform, that start with `current`, each with its
    /// description or platform; then `all`.
    pub fn tenants(&self, current: &str) -> Vec<CompletionCandidate> {
        let Some(config) = self.workspace().config.as_ref() else {
            return Vec::new();
        };
        let tree = opentide_compile::Json::from_node(&config.resolved.tree);
        let platforms = if self.platforms.is_empty() {
            opentide_compile::plan::enabled(&tree)
        } else {
            self.platforms.clone()
        };
        let mut seen = HashSet::new();
        let mut found = Vec::new();
        for platform in &platforms {
            for tenant in opentide_compile::plan::tenants(&tree, platform) {
                let name = opentide_compile::deploy::tenant_name(tenant);
                if name.is_empty() || !name.starts_with(current) || !seen.insert(name) {
                    continue;
                }
                let help = tenant
                    .get("description")
                    .and_then(opentide_compile::Json::as_str)
                    .filter(|text| !text.is_empty())
                    .map_or_else(|| platform.clone(), str::to_owned);
                let value = if self.bash {
                    bash_word(name)
                } else {
                    name.to_owned()
                };
                found.push(candidate(value, help));
            }
        }
        if !found.is_empty() && ALL_TENANTS.starts_with(current) {
            found.push(candidate(
                ALL_TENANTS.to_owned(),
                "Every tenant configured".to_owned(),
            ));
        }
        found
    }

    /// `explain <code>`: the codes with a page that start with `current`
    /// (in any case), each with what it means.
    pub fn codes(&self, current: &str) -> Vec<CompletionCandidate> {
        let prefix = current.to_lowercase();
        crate::explain::codes()
            .into_iter()
            .filter(|code| code.starts_with(&prefix))
            .map(|code| {
                let summary = crate::explain::page(code)
                    .map(|page| page.summary)
                    .unwrap_or_default();
                candidate(code.to_owned(), summary)
            })
            .collect()
    }

    fn absolute(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.cwd.join(path)
        }
    }
}

/// A candidate with its help, none when `help` is empty.
fn candidate(value: String, help: String) -> CompletionCandidate {
    let help = (!help.is_empty()).then(|| help.into());
    CompletionCandidate::new(value).help(help)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `(uuid, name)` from the first [`HEADER_LINES`] lines of an object file,
/// read as `catalogue::text_fields` reads a file that did not load.
pub fn header(path: &Path) -> (Option<String>, Option<String>) {
    let Ok(bytes) = OsFs.read(path) else {
        return (None, None);
    };
    let text = String::from_utf8_lossy(&bytes);
    let end = text
        .match_indices('\n')
        .nth(HEADER_LINES - 1)
        .map_or(text.len(), |(at, _)| at);
    let mut fields = opentide_workspace::catalogue::text_fields(&text[..end]);
    (fields.remove("uuid"), fields.remove("name"))
}

/// Whether `text` is a UUID, hyphens in place: a hand-mangled header is never
/// offered.
fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, len)| group.len() == len && group.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Whether `id` is an ATT&CK technique id: `T1059` or `T1059.001`.
fn is_technique(id: &str) -> bool {
    let Some(rest) = id.strip_prefix('T') else {
        return false;
    };
    let (main, sub) = rest.split_once('.').unwrap_or((rest, "000"));
    main.len() == 4 && sub.len() == 3 && main.chars().chain(sub.chars()).all(|c| c.is_ascii_digit())
}

/// Techniques in number order, each technique before its sub-techniques.
fn technique_order(id: &str) -> (u32, i64) {
    let rest = id.trim_start_matches('T');
    let (main, sub) = rest.split_once('.').unwrap_or((rest, ""));
    (
        main.parse().unwrap_or(u32::MAX),
        sub.parse::<i64>().unwrap_or(-1),
    )
}

/// `path` as `--file` takes it: from `cwd` when inside it, else from `root`,
/// else whole; `/`-separated.
fn shown_path(path: &Path, cwd: &Path, root: &Path) -> String {
    for base in [cwd, root] {
        if let Ok(relative) = path.strip_prefix(base)
            && !relative.as_os_str().is_empty()
        {
            return opentide_workspace::index::posix(relative);
        }
    }
    path.to_string_lossy().replace('\\', "/")
}

/// `value` with a backslash before each space and shell character: bash's
/// script inserts a candidate as it is, so `my rule.yaml` would reach the
/// command as two arguments.
pub fn bash_word(value: &str) -> String {
    let mut word = String::with_capacity(value.len());
    for ch in value.chars() {
        if !(ch.is_alphanumeric() || ch == '_' || "./:@%+,=-".contains(ch)) {
            word.push('\\');
        }
        word.push(ch);
    }
    word
}

/// The word bash passes as it was typed, its backslashes taken out.
fn bash_unescape(word: &str) -> String {
    let mut text = String::with_capacity(word.len());
    let mut chars = word.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next) = chars.next() {
                text.push(next);
            }
        } else {
            text.push(ch);
        }
    }
    text
}

/// The command tree `root` with a completer on each option whose value the
/// workspace or the bundled data holds, reading `context`.
pub fn attach(root: Command, context: &Arc<Context>) -> Command {
    attach_at(root, &[], context)
}

fn attach_at(mut command: Command, path: &[String], context: &Arc<Context>) -> Command {
    let kinds: &'static [&'static str] = match path {
        [validate, query] if validate == "validate" && query == "query" => &RULES,
        [deploy] if deploy == "deploy" => &RULES,
        [query] if query == "query" => &RULES,
        _ => &ALL_KINDS,
    };
    let options: Vec<(String, String, Vec<String>)> = command
        .get_arguments()
        .filter_map(|arg| {
            let choices = arg
                .get_possible_values()
                .iter()
                .filter(|value| !value.is_hide_set())
                .map(|value| value.get_name().to_owned())
                .collect();
            arg.get_long()
                .map(|long| (arg.get_id().to_string(), long.to_owned(), choices))
        })
        .collect();
    for (id, long, choices) in options {
        let cx = Arc::clone(context);
        let completer = match long.as_str() {
            "uuid" => ArgValueCompleter::new(move |current: &OsStr| {
                cx.uuids(kinds, &current.to_string_lossy())
            }),
            "file" => ArgValueCompleter::new(move |current: &OsStr| {
                cx.files(kinds, &current.to_string_lossy())
            }),
            "type" => {
                ArgValueCompleter::new(move |current: &OsStr| cx.types(&current.to_string_lossy()))
            }
            "technique" => ArgValueCompleter::new(move |current: &OsStr| {
                cx.techniques(&current.to_string_lossy())
            }),
            "platform" => {
                let choices = if choices.is_empty() {
                    platform_names()
                } else {
                    choices
                };
                ArgValueCompleter::new(move |current: &OsStr| {
                    cx.platforms(&choices, &current.to_string_lossy())
                })
            }
            "strategy" => ArgValueCompleter::new(move |current: &OsStr| {
                cx.strategies(&current.to_string_lossy())
            }),
            "tenant" => ArgValueCompleter::new(move |current: &OsStr| {
                cx.tenants(&current.to_string_lossy())
            }),
            _ => continue,
        };
        command = command.mut_arg(id, |arg| arg.add(completer));
    }
    if matches!(path, [explain] if explain == "explain") {
        let cx = Arc::clone(context);
        command = command.mut_arg("code", |arg| {
            arg.add(ArgValueCompleter::new(move |current: &OsStr| {
                cx.codes(&current.to_string_lossy())
            }))
        });
    }
    let names: Vec<String> = command
        .get_subcommands()
        .map(|sub| sub.get_name().to_owned())
        .collect();
    for name in names {
        let mut below = path.to_vec();
        below.push(name.clone());
        command = command.mut_subcommand(name, |sub| attach_at(sub, &below, context));
    }
    command
}

/// The platforms `--platform` takes where the tree lists none.
fn platform_names() -> Vec<String> {
    use clap::ValueEnum as _;
    crate::tree::Platform::value_variants()
        .iter()
        .filter_map(|platform| platform.to_possible_value())
        .map(|value| value.get_name().to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Copies `from` into `to`.
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let target = to.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    /// The CLI end-to-end corpus (`tests/fixtures/tide_corpus/current`) in
    /// the `.opentide/` layout, its objects in the default folders.
    fn corpus(root: &Path) -> PathBuf {
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tide_corpus/current");
        let ws = root.join("ws");
        copy_tree(
            &source.join("Configurations"),
            &ws.join(".opentide/configurations"),
        );
        for (family, folder) in [
            ("threats", "Threat Vectors"),
            ("objectives", "Detection Objectives"),
            ("rules", "Detection Rules"),
        ] {
            copy_tree(
                &source.join("Objects").join(folder),
                &ws.join("objects").join(family),
            );
        }
        ws
    }

    fn words(line: &str) -> Vec<String> {
        let mut words: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        if line.ends_with(' ') {
            words.push(String::new());
        }
        words
    }

    /// A context for `line` run in `cwd`, no environment.
    fn context(line: &str, shell: &str, cwd: &Path) -> Context {
        Context::new(&words(line), shell, cwd.to_path_buf(), &Env::default())
    }

    fn values(found: &[CompletionCandidate]) -> Vec<String> {
        found
            .iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect()
    }

    fn helps(found: &[CompletionCandidate]) -> Vec<String> {
        found
            .iter()
            .map(|c| c.get_help().map(ToString::to_string).unwrap_or_default())
            .collect()
    }

    #[test]
    fn the_typed_words_that_change_the_answer_are_read() {
        let cx = Context::new(
            &words("opentide --repo=/r --data /d validate --type rule --type = threat --uuid "),
            "zsh",
            PathBuf::from("/"),
            &Env::from_pairs([("OPENTIDE_REPO_ROOT", "/env")]),
        );
        assert_eq!(cx.repo, Some(PathBuf::from("/r")));
        assert_eq!(cx.data, Some(PathBuf::from("/d")));
        assert_eq!(cx.types, ["rule", "threat"]);
        assert_eq!(cx.repo_root_env, Some(PathBuf::from("/env")));
        assert!(!cx.bash);
        // The word being completed is not typed yet.
        let cx = context("opentide query --platform", "bash", Path::new("/"));
        assert!(cx.platforms.is_empty());
        assert!(cx.bash);
    }

    #[test]
    fn uuids_come_with_the_objects_name_and_kind() {
        let dir = tempfile::tempdir().unwrap();
        let ws = corpus(dir.path());
        let cx = context("opentide validate --uuid ", "zsh", &ws);
        let found = cx.uuids(&ALL_KINDS, "");
        let shown = values(&found);
        assert_eq!(shown.len(), 12, "{shown:?}");
        // Rules first, then threats and objectives.
        assert_eq!(shown[0], "00000000-0000-4000-8003-000000000001");
        assert_eq!(helps(&found)[0], "Sentinel KQL Rule (rule)");
        assert!(helps(&found).contains(&"Simulated Actor (threat)".to_owned()));
        // A prefix in any case narrows them.
        let threats = cx.uuids(&ALL_KINDS, "00000000-0000-4000-8001");
        assert_eq!(values(&threats), ["00000000-0000-4000-8001-000000000001"]);
        // Rules only, as validate query reads them.
        assert!(
            helps(&cx.uuids(&RULES, ""))
                .iter()
                .all(|help| help.ends_with("(rule)"))
        );
        // A typed --type narrows them.
        let typed = context("opentide validate --type threat --uuid ", "zsh", &ws);
        assert_eq!(typed.uuids(&ALL_KINDS, "").len(), 1);
        // `--repo` places the workspace from anywhere.
        let elsewhere = Context::new(
            &words(&format!(
                "opentide --repo {} validate --uuid ",
                ws.display()
            )),
            "zsh",
            dir.path().to_path_buf(),
            &Env::default(),
        );
        assert_eq!(elsewhere.uuids(&ALL_KINDS, "").len(), 12);
    }

    #[test]
    fn files_are_shown_from_where_the_person_is() {
        let dir = tempfile::tempdir().unwrap();
        let ws = corpus(dir.path());
        let cx = context("opentide validate --file ", "zsh", &ws);
        let found = cx.files(&ALL_KINDS, "objects/rules/rule-0001");
        assert_eq!(
            values(&found),
            ["objects/rules/rule-0001-sentinel-kql.yaml"]
        );
        assert_eq!(helps(&found), ["Sentinel KQL Rule"]);
        // Inside the rules folder, the path is from there.
        let inside = context(
            "opentide validate --file ",
            "zsh",
            &ws.join("objects/rules"),
        );
        assert_eq!(
            values(&inside.files(&ALL_KINDS, "rule-0003")),
            ["rule-0003-splunk-spl.yaml"]
        );
        // From a folder outside the workspace's objects, the path is from the
        // workspace; with no match, a bare file name matches.
        let other = ws.join(".opentide");
        let outside = context("opentide validate --file ", "zsh", &other);
        assert_eq!(
            values(&outside.files(&ALL_KINDS, "objects/threats/")),
            ["objects/threats/threat-0001-simulated-actor.yaml"]
        );
        assert_eq!(
            values(&outside.files(&ALL_KINDS, "objective-")),
            ["objective-0001-credential-access.yaml"]
        );
        // Nothing matches: the shell completes file names itself.
        assert!(outside.files(&ALL_KINDS, "nothing/").is_empty());
        // Rules only.
        assert!(cx.files(&RULES, "objects/threats/").is_empty());
    }

    #[test]
    fn bash_gets_paths_escaped() {
        let dir = tempfile::tempdir().unwrap();
        let ws = corpus(dir.path());
        std::fs::rename(
            ws.join("objects/threats/threat-0001-simulated-actor.yaml"),
            ws.join("objects/threats/my threat.yaml"),
        )
        .unwrap();
        let bash = context("opentide validate --file ", "bash", &ws);
        assert_eq!(
            values(&bash.files(&ALL_KINDS, "objects/threats/my\\ t")),
            ["objects/threats/my\\ threat.yaml"]
        );
        let zsh = context("opentide validate --file ", "zsh", &ws);
        assert_eq!(
            values(&zsh.files(&ALL_KINDS, "objects/threats/my t")),
            ["objects/threats/my threat.yaml"]
        );
        assert_eq!(bash_word("a b'c$"), "a\\ b\\'c\\$");
        assert_eq!(bash_unescape("a\\ b\\'c"), "a b'c");
    }

    #[test]
    fn object_folders_follow_paths_toml() {
        let dir = tempfile::tempdir().unwrap();
        let ws = corpus(dir.path());
        std::fs::rename(ws.join("objects/rules"), ws.join("detections")).unwrap();
        std::fs::write(
            ws.join(".opentide/configurations/paths.toml"),
            "[paths.objects]\nrule = \"detections/\"\n",
        )
        .unwrap();
        let cx = context("opentide validate --file ", "zsh", &ws);
        assert_eq!(
            values(&cx.files(&RULES, "detections/rule-0001")),
            ["detections/rule-0001-sentinel-kql.yaml"]
        );
        assert_eq!(cx.uuids(&RULES, "").len(), 10);
    }

    #[test]
    fn types_strategies_and_techniques() {
        let cx = context("opentide x ", "zsh", Path::new("/"));
        assert_eq!(values(&cx.types("")), ["rule", "threat", "objective"]);
        assert_eq!(helps(&cx.types("o")), ["objects/objectives/"]);
        assert_eq!(values(&cx.strategies("p")), ["PREVIEW"]);
        let found = cx.techniques("t1059.00");
        assert!(values(&found).starts_with(&["T1059.001".to_owned()]));
        assert_eq!(
            helps(&found)[0],
            "Command and Scripting Interpreter: PowerShell"
        );
        // A technique comes before its sub-techniques.
        let main = values(&cx.techniques("T1059"));
        assert_eq!(main[0], "T1059");
        assert!(main[1..].iter().all(|id| id.starts_with("T1059.")));
        // `--data` names another vocabulary; a missing one completes nothing.
        let dir = tempfile::tempdir().unwrap();
        let data = Context::new(
            &words(&format!(
                "opentide --data {} info --technique ",
                dir.path().display()
            )),
            "zsh",
            PathBuf::from("/"),
            &Env::default(),
        );
        assert!(data.techniques("T").is_empty());
    }

    #[test]
    fn enabled_platforms_come_first_then_tenants() {
        let dir = tempfile::tempdir().unwrap();
        let ws = corpus(dir.path());
        for platform in ["splunk", "crowdstrike"] {
            let path = ws.join(format!(
                ".opentide/configurations/platforms/{platform}.toml"
            ));
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, text.replacen("enabled = true", "enabled = false", 1)).unwrap();
        }
        let cx = context("opentide query --platform ", "zsh", &ws);
        let choices = platform_names();
        let found = cx.platforms(&choices, "");
        let shown = values(&found);
        assert_eq!(shown.len(), choices.len());
        // The disabled platforms come last, in the choices' order: the two
        // disabled here, then those the corpus does not configure (the
        // platforms the 0.23.0 fixture predates, SINCE_ORACLE).
        let mut disabled = vec!["splunk".to_owned(), "crowdstrike".to_owned()];
        disabled.extend(
            choices
                .iter()
                .filter(|id| opentide_schema::platforms::after_oracle(id))
                .cloned(),
        );
        assert_eq!(&shown[shown.len() - disabled.len()..], disabled.as_slice());
        assert_eq!(helps(&found)[0], "enabled");
        assert_eq!(helps(&found)[shown.len() - 1], "");
        assert_eq!(values(&cx.platforms(&choices, "SPL")), ["splunk"]);
        // Tenants of the platform typed, then `all`.
        let elastic = context("opentide query --platform elastic --tenant ", "zsh", &ws);
        let tenants = values(&elastic.tenants(""));
        assert!(tenants.contains(&"staging".to_owned()), "{tenants:?}");
        assert_eq!(tenants.last().map(String::as_str), Some("all"));
        assert_eq!(values(&elastic.tenants("stag")), ["staging"]);
        // A platform with no tenants completes none.
        let splunk = context("opentide query --platform splunk --tenant ", "zsh", &ws);
        assert!(splunk.tenants("").is_empty());
    }

    #[test]
    fn diagnostic_codes_come_with_their_meaning() {
        let cx = context("opentide explain ", "zsh", Path::new("/"));
        let found = cx.codes("vocab_unk");
        assert_eq!(values(&found), ["vocab_unknown"]);
        assert!(!helps(&found)[0].is_empty());
        assert!(cx.codes("").len() > 100);
    }

    #[test]
    fn a_workspace_that_cannot_be_read_completes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cx = context("opentide validate --uuid ", "zsh", dir.path());
        assert!(cx.uuids(&ALL_KINDS, "").is_empty());
        assert!(cx.files(&ALL_KINDS, "").is_empty());
        assert!(cx.tenants("").is_empty());
        let platforms = cx.platforms(&platform_names(), "");
        assert!(helps(&platforms).iter().all(String::is_empty));
        assert_eq!(header(&dir.path().join("missing.yaml")), (None, None));
    }

    #[test]
    fn headers_and_identifiers() {
        assert!(is_uuid("00000000-0000-4000-8003-000000000001"));
        assert!(!is_uuid("00000000-0000-4000-8003-00000000000"));
        assert!(!is_uuid("not-a-uuid"));
        assert!(is_technique("T1059") && is_technique("T1059.001"));
        assert!(!is_technique("TA0001") && !is_technique("T1059.1"));
        let cwd = Path::new("/w");
        let root = Path::new("/r");
        assert_eq!(shown_path(Path::new("/w/a/b.yaml"), cwd, root), "a/b.yaml");
        assert_eq!(shown_path(Path::new("/r/a/b.yaml"), cwd, root), "a/b.yaml");
        assert_eq!(shown_path(Path::new("/o/b.yaml"), cwd, root), "/o/b.yaml");
    }

    #[test]
    fn every_completed_option_has_its_completer() {
        let cx = Arc::new(context("opentide ", "zsh", Path::new("/")));
        let root = attach(crate::catalog::root(), &cx);
        // The argument named `name` (`--name`, or the positional `name`).
        let has = |path: &[&str], name: &str| {
            let mut command = &root;
            for word in path {
                command = command.find_subcommand(word).unwrap();
            }
            command
                .get_arguments()
                .find(|arg| arg.get_long() == Some(name) || arg.get_id() == name)
                .and_then(|arg| arg.get::<ArgValueCompleter>())
                .is_some()
        };
        for (path, name) in [
            (&["validate"][..], "uuid"),
            (&["validate"], "file"),
            (&["validate"], "type"),
            (&["validate", "query"], "uuid"),
            (&["validate", "query"], "strategy"),
            (&["share", "push"], "file"),
            (&["deploy"], "platform"),
            (&["info"], "technique"),
            (&["query"], "tenant"),
            (&["setup"], "platform"),
            (&["explain"], "code"),
        ] {
            assert!(has(path, name), "{path:?} {name}");
        }
        // An option whose value is not the workspace's keeps clap's own.
        assert!(!has(&["validate"], "format"));
    }
}
