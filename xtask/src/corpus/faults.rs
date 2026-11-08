//! The fault catalogue (`tests/corpora/faults.toml`): what each fault kind
//! targets, how it mutates the clean workspace, and what the oracle must
//! report. This module parses the catalogue, applies a kind to a
//! [`Workspace`] in memory and compares findings with the expectation; the
//! runner in [`super::cli`] writes the workspaces and runs the oracle.

use super::generate::{Counts, Layout, Options};
use super::workspace::{Body, Family, File, Workspace};
use super::yaml::Yaml;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// The parsed catalogue.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalogue {
    /// The oracle version the expectations were adjusted to (`0.23.0`).
    pub oracle: String,
    /// The clean workspace every kind mutates a copy of.
    pub base: Base,
    /// The larger base of the combined fault workspace (`faults --out`);
    /// `[base]`'s counts when absent.
    pub combined: Option<Combined>,
    /// The fault kinds.
    #[serde(rename = "kind", default)]
    pub kinds: Vec<Kind>,
    /// Codes no fault can produce through the CLI, each with its evidence.
    #[serde(rename = "unreachable", default)]
    pub unreachable: Vec<Unreachable>,
}

/// `[base]`: the generator options of the clean workspace.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    /// Seed.
    pub seed: u64,
    /// Threats.
    pub threats: usize,
    /// Objectives.
    pub objectives: usize,
    /// Rules.
    pub rules: usize,
    /// `paths.toml` layout.
    pub layout: String,
}

impl Base {
    /// The generator options.
    pub fn options(&self) -> Result<Options> {
        Ok(Options {
            seed: self.seed,
            counts: Counts {
                threats: self.threats,
                objectives: self.objectives,
                rules: self.rules,
            },
            layout: Layout::parse(&self.layout)
                .with_context(|| format!("[base] layout `{}` is unknown", self.layout))?,
        })
    }
}

/// `[combined]`: the base of the combined fault workspace, where every kind
/// is applied once (twice for a cross-file kind) to files of its own.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Combined {
    /// Threats.
    pub threats: usize,
    /// Objectives.
    pub objectives: usize,
    /// Rules.
    pub rules: usize,
}

impl Combined {
    /// The generator options: `[base]`'s seed and layout, these counts.
    pub fn options(&self, base: &Base) -> Result<Options> {
        let mut options = base.options()?;
        options.counts = Counts {
            threats: self.threats,
            objectives: self.objectives,
            rules: self.rules,
        };
        Ok(options)
    }
}

impl Kind {
    /// How many files the kind takes in the combined workspace: one, two
    /// for a cross-file kind, never more than its own count.
    pub fn combined_count(&self) -> usize {
        let wanted = if self.class == "cross-file" { 2 } else { 1 };
        wanted.min(self.count)
    }
}

/// A code the CLI cannot report from a workspace, and why.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unreachable {
    /// The code.
    pub code: String,
    /// Why no workspace mutation produces it through `validate` or `lint`.
    pub reason: String,
}

/// The severity of each expected code: one for all, or one per code.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Severity {
    /// Every expected code has this severity.
    All(String),
    /// A severity per code.
    PerCode(BTreeMap<String, String>),
}

/// One fault kind.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Kind {
    /// A unique id, `kebab-case`.
    pub id: String,
    /// `single`, `combination` (two faults in one file) or `cross-file`.
    #[serde(default = "single")]
    pub class: String,
    /// The codes the oracle must report: exactly these, no other.
    pub codes: Vec<String>,
    /// Their severity.
    pub severity: Severity,
    /// The command after `opentide --json --repo DIR`: `["validate"]` by
    /// default, `["lint"]`, `["validate", "--check", "cve"]`, ...
    #[serde(default = "validate")]
    pub command: Vec<String>,
    /// Which files the kind mutates.
    pub target: Target,
    /// How many targets (at least 5 unless the target is one file).
    #[serde(default = "five")]
    pub count: usize,
    /// The mutation, applied to each target in order.
    pub ops: Vec<Op>,
    /// Whether every target file must carry a finding (false when the
    /// finding is reported on another file).
    #[serde(default = "yes")]
    pub per_target: bool,
    /// Left out of the materialised fault workspace, because it changes how
    /// the whole workspace loads (a broken `paths.toml`), or its codes only
    /// appear when nothing else in the workspace is wrong.
    #[serde(default)]
    pub isolated: bool,
    /// Whether the clean base is checked under this kind's command too
    /// (false for a command that fails on any workspace, `--file nope`).
    #[serde(default = "yes")]
    pub baseline: bool,
    /// Environment variables for the oracle (a dead proxy, so that an online
    /// lookup fails the same way everywhere).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The `KNOWN_GAPS.md` entry this kind documents.
    pub gap: Option<String>,
    /// Why the kind exists or what it shows.
    pub note: Option<String>,
}

fn single() -> String {
    "single".to_string()
}
fn validate() -> Vec<String> {
    vec!["validate".to_string()]
}
fn five() -> usize {
    5
}
fn yes() -> bool {
    true
}

/// A target selector: every condition must hold.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// `threat`, `objective`, `rule` or `config`.
    pub family: String,
    /// The rule configures this platform, or the configuration file is
    /// this platform's.
    pub platform: Option<String>,
    /// The file carries every one of these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// The file carries none of these tags.
    #[serde(default)]
    pub without: Vec<String>,
    /// The file's path is exactly this.
    pub path: Option<String>,
    /// Skip this many matching files first (to keep kinds on distinct files).
    #[serde(default)]
    pub skip: usize,
}

/// One mutation step.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    /// Set the value at a dotted path (YAML objects, or TOML configuration).
    Set {
        /// Dotted path; `{platform}` is the target's first platform.
        path: String,
        /// The value (a TOML value).
        value: Option<toml::Value>,
        /// A YAML scalar written verbatim instead of `value`.
        raw: Option<String>,
    },
    /// Remove the key or item at a dotted path.
    Delete {
        /// Dotted path.
        path: String,
    },
    /// Append a value to the sequence at a dotted path.
    Append {
        /// Dotted path.
        path: String,
        /// The value.
        value: toml::Value,
    },
    /// Pairs the targets (first with second, third with fourth, ...) and
    /// sets `path` of the first of each pair to the value the second holds
    /// at `from_path`: duplicates across files. Needs an even count.
    CopyFromPartner {
        /// Dotted path to set.
        path: String,
        /// Dotted path to read on the partner.
        from_path: String,
    },
    /// Replace text in the rendered file.
    Replace {
        /// The text to find (it must occur).
        find: String,
        /// The replacement.
        with: String,
        /// Every occurrence, not only the first.
        #[serde(default)]
        all: bool,
    },
    /// Append text to the rendered file.
    AppendText {
        /// The text.
        text: String,
    },
    /// Replace the whole file.
    Write {
        /// The new content.
        text: String,
    },
    /// Move the file: `{dir}` is its folder (with a trailing slash), `{stem}`
    /// its name without `.yaml`/`.toml`, `{name}` its file name. Every
    /// string of every op also expands `{n}` (the target's position, from 1),
    /// `{uuid}` (its `metadata.uuid`) and `{platform}` (its first platform).
    Rename {
        /// The new path template.
        to: String,
    },
    /// Add a copy of the file (as it is at this step) at a new path.
    Copy {
        /// The copy's path template, as `rename`.
        to: String,
    },
    /// Delete the file.
    DeleteFile,
    /// Set a path to the value the same file holds at `from_path`.
    CopyPath {
        /// Dotted path to set.
        path: String,
        /// Dotted path to read.
        from_path: String,
    },
    /// Add a file; its path and text expand the target's placeholders, and
    /// a path two targets expand alike is added once.
    AddFile {
        /// Path relative to the root.
        path: String,
        /// Content.
        text: String,
    },
}

impl Catalogue {
    /// Parses and checks a catalogue.
    pub fn parse(text: &str) -> Result<Self> {
        let catalogue: Self = toml::from_str(text).context("faults.toml does not parse")?;
        let mut ids = BTreeSet::new();
        for kind in &catalogue.kinds {
            if !ids.insert(kind.id.as_str()) {
                bail!("fault kind `{}` is defined twice", kind.id);
            }
            if kind.codes.is_empty() && kind.gap.is_none() {
                bail!(
                    "fault kind `{}` expects no code; only a known gap (`gap`) may",
                    kind.id
                );
            }
            if !matches!(kind.class.as_str(), "single" | "combination" | "cross-file") {
                bail!(
                    "fault kind `{}`: class `{}` is unknown",
                    kind.id,
                    kind.class
                );
            }
            if Family::parse(&kind.target.family).is_none() {
                bail!(
                    "fault kind `{}`: family `{}` is unknown",
                    kind.id,
                    kind.target.family
                );
            }
            for code in &kind.codes {
                kind.severity_of(code)?;
            }
            if kind.count < 5 && kind.target.path.is_none() {
                bail!(
                    "fault kind `{}`: {} targets; at least 5, unless the target is one file (`path`)",
                    kind.id,
                    kind.count
                );
            }
            if let Severity::PerCode(map) = &kind.severity {
                for code in map.keys() {
                    if !kind.codes.contains(code) {
                        bail!(
                            "fault kind `{}`: severity for `{code}`, which it does not expect",
                            kind.id
                        );
                    }
                }
            }
        }
        Ok(catalogue)
    }

    /// The kind with `id`.
    pub fn kind(&self, id: &str) -> Option<&Kind> {
        self.kinds.iter().find(|k| k.id == id)
    }
}

impl Kind {
    /// The expected severity of `code`.
    pub fn severity_of(&self, code: &str) -> Result<&str> {
        match &self.severity {
            Severity::All(severity) => Ok(severity),
            Severity::PerCode(map) => map
                .get(code)
                .map(String::as_str)
                .with_context(|| format!("fault kind `{}`: no severity for `{code}`", self.id)),
        }
    }
}

impl Catalogue {
    /// The generator options of the combined fault workspace.
    pub fn combined_options(&self) -> Result<Options> {
        match &self.combined {
            Some(combined) => combined.options(&self.base),
            None => self.base.options(),
        }
    }
}

/// Whether `file` matches `target`.
pub fn matches(file: &File, target: &Target) -> bool {
    Family::parse(&target.family) == Some(file.family)
        && target
            .platform
            .as_ref()
            .is_none_or(|p| file.platforms.iter().any(|fp| fp == p))
        && target.tags.iter().all(|t| file.has_tag(t))
        && !target.without.iter().any(|t| file.has_tag(t))
        && target.path.as_ref().is_none_or(|p| &file.path == p)
}

/// The indexes of the files a kind targets, skipping `taken` files; an
/// error when fewer than `count` match.
pub fn select(workspace: &Workspace, kind: &Kind, taken: &BTreeSet<usize>) -> Result<Vec<usize>> {
    let chosen: Vec<usize> = workspace
        .files
        .iter()
        .enumerate()
        // A kind aimed at one named file shares it with other kinds.
        .filter(|(index, file)| {
            (kind.target.path.is_some() || !taken.contains(index)) && matches(file, &kind.target)
        })
        .map(|(index, _)| index)
        .skip(kind.target.skip)
        .take(kind.count)
        .collect();
    if chosen.len() < kind.count {
        bail!(
            "fault kind `{}`: {} of {} targets match {:?}",
            kind.id,
            chosen.len(),
            kind.count,
            kind.target
        );
    }
    Ok(chosen)
}

/// Converts a TOML value into a YAML node.
pub fn to_yaml(value: &toml::Value) -> Yaml {
    match value {
        toml::Value::String(text) => Yaml::Str(text.clone()),
        toml::Value::Integer(n) => Yaml::raw(n),
        toml::Value::Float(n) => Yaml::raw(n),
        toml::Value::Boolean(b) => Yaml::raw(b),
        toml::Value::Datetime(d) => Yaml::raw(d),
        toml::Value::Array(items) => Yaml::Seq(items.iter().map(to_yaml).collect()),
        toml::Value::Table(table) => {
            Yaml::Map(table.iter().map(|(k, v)| (k.clone(), to_yaml(v))).collect())
        }
    }
}

fn expand(template: &str, file: &File, position: usize) -> String {
    let (dir, name) = match file.path.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name.to_string()),
        None => (String::new(), file.path.clone()),
    };
    let stem = name
        .strip_suffix(".yaml")
        .or_else(|| name.strip_suffix(".toml"))
        .unwrap_or(&name)
        .to_string();
    template
        .replace("{dir}", &dir)
        .replace("{stem}", &stem)
        .replace("{name}", &name)
        .replace(
            "{platform}",
            file.platforms.first().map_or("", String::as_str),
        )
        .replace("{uuid}", file.uuid().unwrap_or(""))
        .replace("{n}", &(position + 1).to_string())
}

/// Expands the placeholders in every string of a TOML value.
fn expand_value(value: &toml::Value, file: &File, position: usize) -> toml::Value {
    match value {
        toml::Value::String(text) => toml::Value::String(expand(text, file, position)),
        toml::Value::Array(items) => toml::Value::Array(
            items
                .iter()
                .map(|v| expand_value(v, file, position))
                .collect(),
        ),
        toml::Value::Table(table) => toml::Value::Table(
            table
                .iter()
                .map(|(k, v)| (k.clone(), expand_value(v, file, position)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Reads the value at a dotted path of a file, as YAML.
fn read_path(file: &File, path: &str) -> Option<Yaml> {
    match &file.body {
        Body::Yaml(doc) => doc.at(path).cloned(),
        Body::Text(text) if file.family == Family::Config => {
            let table: toml::Table = toml::from_str(text).ok()?;
            let mut node = toml::Value::Table(table);
            for segment in path.split('.') {
                node = match node {
                    toml::Value::Table(mut t) => t.remove(segment)?,
                    toml::Value::Array(mut a) => {
                        let index = segment.parse::<usize>().ok()?;
                        if index >= a.len() {
                            return None;
                        }
                        a.swap_remove(index)
                    }
                    _ => return None,
                };
            }
            Some(to_yaml(&node))
        }
        Body::Text(_) => None,
    }
}

fn yaml_to_toml(node: &Yaml) -> toml::Value {
    match node {
        Yaml::Str(text) => toml::Value::String(text.clone()),
        Yaml::Raw(text) => text
            .parse::<i64>()
            .map(toml::Value::Integer)
            .or_else(|_| text.parse::<bool>().map(toml::Value::Boolean))
            .unwrap_or_else(|_| toml::Value::String(text.clone())),
        Yaml::Seq(items) => toml::Value::Array(items.iter().map(yaml_to_toml).collect()),
        Yaml::Map(pairs) => toml::Value::Table(
            pairs
                .iter()
                .map(|(k, v)| (k.clone(), yaml_to_toml(v)))
                .collect(),
        ),
    }
}

/// Edits a TOML file's table: `edit` gets the parent table and last key.
fn edit_toml(
    file: &mut File,
    path: &str,
    edit: impl FnOnce(&mut toml::Value, &str) -> bool,
) -> Result<()> {
    let Body::Text(text) = &file.body else {
        bail!("{} is not TOML", file.path);
    };
    let table: toml::Table =
        toml::from_str(text).with_context(|| format!("{} does not parse as TOML", file.path))?;
    let mut root = toml::Value::Table(table);
    let (parent_path, last) = path.rsplit_once('.').unwrap_or(("", path));
    let mut node = &mut root;
    if !parent_path.is_empty() {
        for segment in parent_path.split('.') {
            node = match node {
                toml::Value::Table(t) => t
                    .entry(segment.to_string())
                    .or_insert_with(|| toml::Value::Table(toml::Table::new())),
                toml::Value::Array(a) => {
                    let index: usize = segment
                        .parse()
                        .with_context(|| format!("{path}: `{segment}` is not an index"))?;
                    a.get_mut(index)
                        .with_context(|| format!("{path}: no item {index}"))?
                }
                _ => bail!("{path}: `{segment}` is not a table"),
            };
        }
    }
    if !edit(node, last) {
        bail!("{}: cannot edit `{path}`", file.path);
    }
    let toml::Value::Table(table) = root else {
        bail!("{} lost its root table", file.path);
    };
    file.body = Body::Text(toml::to_string(&table).context("TOML does not serialise")?);
    Ok(())
}

fn set_value(file: &mut File, path: &str, node: Yaml) -> Result<()> {
    match &mut file.body {
        Body::Yaml(doc) => {
            if !doc.set(path, node) {
                bail!("{}: cannot set `{path}`", file.path);
            }
            Ok(())
        }
        Body::Text(_) => {
            let value = yaml_to_toml(&node);
            edit_toml(file, path, |parent, last| match parent {
                toml::Value::Table(t) => {
                    t.insert(last.to_string(), value);
                    true
                }
                _ => false,
            })
        }
    }
}

/// Applies `kind` to the files at `targets` (indexes into `workspace`).
pub fn apply(workspace: &mut Workspace, kind: &Kind, targets: &[usize]) -> Result<()> {
    // `copy_from_partner` reads the targets as they were before the kind.
    let before: Vec<File> = targets
        .iter()
        .map(|&i| workspace.files[i].clone())
        .collect();
    let mut added = Vec::new();
    let mut deleted = BTreeSet::new();
    for (position, &index) in targets.iter().enumerate() {
        for op in &kind.ops {
            let file = &mut workspace.files[index];
            match op {
                Op::Set { path, value, raw } => {
                    let path = expand(path, file, position);
                    let node = match (value, raw) {
                        (Some(value), None) => to_yaml(&expand_value(value, file, position)),
                        (None, Some(raw)) => Yaml::Raw(expand(raw, file, position)),
                        _ => bail!("fault kind `{}`: set needs value or raw", kind.id),
                    };
                    set_value(file, &path, node)?;
                }
                Op::Delete { path } => {
                    let path = expand(path, file, position);
                    match &mut file.body {
                        Body::Yaml(doc) => {
                            if !doc.remove(&path) {
                                bail!("fault kind `{}`: {} has no `{path}`", kind.id, file.path);
                            }
                        }
                        Body::Text(_) => edit_toml(file, &path, |parent, last| match parent {
                            toml::Value::Table(t) => t.remove(last).is_some(),
                            _ => false,
                        })?,
                    }
                }
                Op::Append { path, value } => {
                    let path = expand(path, file, position);
                    let item = to_yaml(&expand_value(value, file, position));
                    let name = file.path.clone();
                    let Body::Yaml(doc) = &mut file.body else {
                        bail!("fault kind `{}`: append needs a YAML file", kind.id);
                    };
                    match doc.at_mut(&path, false) {
                        Some(Yaml::Seq(items)) => items.push(item),
                        _ => bail!("fault kind `{}`: {name} has no list `{path}`", kind.id),
                    }
                }
                Op::CopyFromPartner { path, from_path } => {
                    if before.len() % 2 != 0 {
                        bail!(
                            "fault kind `{}`: copy_from_partner needs an even count",
                            kind.id
                        );
                    }
                    if position % 2 == 1 {
                        continue;
                    }
                    let partner = &before[position + 1];
                    let node = read_path(partner, from_path).with_context(|| {
                        format!(
                            "fault kind `{}`: {} has no `{from_path}`",
                            kind.id, partner.path
                        )
                    })?;
                    let path = expand(path, file, position);
                    set_value(file, &path, node)?;
                }
                Op::Replace { find, with, all } => {
                    let text = file.render();
                    let find = expand(find, file, position);
                    if !text.contains(&find) {
                        bail!("fault kind `{}`: `{find}` is not in {}", kind.id, file.path);
                    }
                    let with = expand(with, file, position);
                    let replaced = if *all {
                        text.replace(&find, &with)
                    } else {
                        text.replacen(&find, &with, 1)
                    };
                    file.body = Body::Text(replaced);
                }
                Op::AppendText { text } => {
                    let mut rendered = file.render();
                    rendered.push_str(&expand(text, file, position));
                    file.body = Body::Text(rendered);
                }
                Op::Write { text } => file.body = Body::Text(expand(text, file, position)),
                Op::Rename { to } => file.path = expand(to, file, position),
                Op::Copy { to } => {
                    let mut copy = file.clone();
                    copy.path = expand(to, file, position);
                    added.push(copy);
                }
                Op::DeleteFile => {
                    deleted.insert(index);
                }
                Op::CopyPath { path, from_path } => {
                    let node = read_path(file, from_path).with_context(|| {
                        format!(
                            "fault kind `{}`: {} has no `{from_path}`",
                            kind.id, file.path
                        )
                    })?;
                    let path = expand(path, file, position);
                    set_value(file, &path, node)?;
                }
                Op::AddFile { path, text } => {
                    let path = expand(path, file, position);
                    if !added.iter().any(|f: &File| f.path == path) {
                        added.push(File {
                            path,
                            family: Family::Other,
                            platforms: Vec::new(),
                            tags: vec![format!("fault:{}", kind.id)],
                            body: Body::Text(expand(text, file, position)),
                        });
                    }
                }
            }
        }
    }
    let mut index = 0;
    workspace.files.retain(|_| {
        let keep = !deleted.contains(&index);
        index += 1;
        keep
    });
    workspace.files.extend(added);
    let mut paths = BTreeSet::new();
    for file in &workspace.files {
        if !paths.insert(file.path.as_str()) {
            bail!("fault kind `{}` writes {} twice", kind.id, file.path);
        }
    }
    Ok(())
}

/// One finding the oracle reported, reduced to what the check compares.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// The code.
    pub code: String,
    /// `error`, `warning` or `info`.
    pub severity: String,
    /// The file, relative to the workspace root, when the finding names one.
    pub path: Option<String>,
}

/// Reads the findings of `opentide --json ... validate` or `lint` output.
pub fn findings(document: &serde_json::Value, root: &str) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let mut push = |item: &serde_json::Value, default: &str| {
        let code = item
            .get("code")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        let severity = item
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or(default)
            .to_string();
        let path = item
            .get("path")
            .or_else(|| item.get("file"))
            .and_then(|p| p.as_str())
            .map(|p| relative(p, root));
        out.push(Finding {
            code,
            severity,
            path,
        });
    };
    if let Some(report) = document.get("report") {
        for (key, default) in [("issues", "error"), ("warnings", "warning")] {
            for item in report
                .get(key)
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
            {
                push(item, default);
            }
        }
    } else if let Some(items) = document.get("findings").and_then(|v| v.as_array()) {
        for item in items {
            push(item, "warning");
        }
    } else {
        bail!(
            "the oracle's output has neither report nor findings: {}",
            document
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("no message")
        );
    }
    out.sort();
    Ok(out)
}

fn relative(path: &str, root: &str) -> String {
    let path = path.replace('\\', "/");
    let root = root.replace('\\', "/");
    path.strip_prefix(&format!("{}/", root.trim_end_matches('/')))
        .unwrap_or(&path)
        .trim_start_matches("./")
        .to_string()
}

/// How one kind's run compares with its expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The kind.
    pub id: String,
    /// What is wrong; empty when the run matches.
    pub problems: Vec<String>,
    /// Every code reported, with its count.
    pub reported: BTreeMap<String, usize>,
}

/// Compares `found` with `kind`'s expectation for `target_paths`.
pub fn judge(kind: &Kind, target_paths: &[String], found: &[Finding]) -> Verdict {
    let mut problems = Vec::new();
    let mut reported: BTreeMap<String, usize> = BTreeMap::new();
    for finding in found {
        *reported.entry(finding.code.clone()).or_default() += 1;
    }
    let expected: BTreeSet<&str> = kind.codes.iter().map(String::as_str).collect();
    let got: BTreeSet<&str> = reported.keys().map(String::as_str).collect();
    for code in expected.difference(&got) {
        problems.push(format!("expected `{code}`, not reported"));
    }
    for code in got.difference(&expected) {
        problems.push(format!("unexpected `{code}` ({}x)", reported[*code]));
    }
    for finding in found {
        if let Ok(severity) = kind.severity_of(&finding.code)
            && expected.contains(finding.code.as_str())
            && severity != finding.severity
        {
            problems.push(format!(
                "`{}` is {}, expected {severity} ({})",
                finding.code,
                finding.severity,
                finding.path.as_deref().unwrap_or("no file")
            ));
        }
    }
    // A known gap the oracle is silent on expects no finding at all.
    if kind.per_target && !kind.codes.is_empty() {
        for path in target_paths {
            if !found
                .iter()
                .any(|f| f.path.as_deref() == Some(path.as_str()))
            {
                problems.push(format!("no finding on target {path}"));
            }
        }
    }
    problems.sort();
    problems.dedup();
    Verdict {
        id: kind.id.clone(),
        problems,
        reported,
    }
}

#[cfg(test)]
mod tests {
    use super::{Catalogue, Finding, apply, judge, select};
    use crate::corpus::generate::{Counts, Layout, Options, generate};
    use crate::corpus::workspace::Body;
    use std::collections::BTreeSet;

    const CATALOGUE: &str = r#"
oracle = "0.23.0"
[base]
seed = 1
threats = 6
objectives = 6
rules = 36
layout = "explicit"

[combined]
threats = 6
objectives = 6
rules = 36

[[kind]]
id = "bad-uuid"
codes = ["invalid_uuid"]
severity = "error"
target = { family = "rule", platform = "sentinel" }
ops = [{ op = "set", path = "metadata.uuid", value = "not-a-uuid-{n}" }]

[[kind]]
id = "duplicate"
class = "cross-file"
codes = ["duplicate_id"]
severity = { duplicate_id = "error" }
target = { family = "threat" }
count = 6
ops = [{ op = "copy_from_partner", path = "metadata.uuid", from_path = "metadata.uuid" }]

[[kind]]
id = "toml"
codes = ["unknown_key"]
severity = "error"
target = { family = "config", path = ".opentide/configurations/platforms/splunk.toml" }
count = 1
ops = [{ op = "set", path = "platform.colour", value = "blue" }, { op = "rename", to = "{dir}{stem}.old.toml" }]
"#;

    fn workspace() -> crate::corpus::workspace::Workspace {
        generate(&Options {
            seed: 1,
            counts: Counts {
                threats: 6,
                objectives: 6,
                rules: 36,
            },
            layout: Layout::Explicit,
        })
    }

    #[test]
    fn parses_selects_and_applies() {
        let catalogue = Catalogue::parse(CATALOGUE).unwrap();
        let mut ws = workspace();
        let kind = catalogue.kind("bad-uuid").unwrap();
        let targets = select(&ws, kind, &BTreeSet::new()).unwrap();
        assert_eq!(targets.len(), 5);
        apply(&mut ws, kind, &targets).unwrap();
        for &t in &targets {
            assert!(ws.files[t].uuid().unwrap().starts_with("not-a-uuid-"));
            assert!(ws.files[t].platforms.iter().any(|p| p == "sentinel"));
        }
    }

    #[test]
    fn copy_from_partner_makes_duplicates() {
        let catalogue = Catalogue::parse(CATALOGUE).unwrap();
        let mut ws = workspace();
        let kind = catalogue.kind("duplicate").unwrap();
        let targets = select(&ws, kind, &BTreeSet::new()).unwrap();
        let (a, b) = (
            ws.files[targets[0]].uuid().unwrap().to_string(),
            ws.files[targets[1]].uuid().unwrap().to_string(),
        );
        apply(&mut ws, kind, &targets).unwrap();
        assert_ne!(a, b);
        assert_eq!(ws.files[targets[0]].uuid(), Some(b.as_str()));
        assert_eq!(ws.files[targets[1]].uuid(), Some(b.as_str()));
    }

    #[test]
    fn toml_edits_and_renames() {
        let catalogue = Catalogue::parse(CATALOGUE).unwrap();
        let mut ws = workspace();
        let kind = catalogue.kind("toml").unwrap();
        let targets = select(&ws, kind, &BTreeSet::new()).unwrap();
        apply(&mut ws, kind, &targets).unwrap();
        let file = &ws.files[targets[0]];
        assert_eq!(
            file.path,
            ".opentide/configurations/platforms/splunk.old.toml"
        );
        let Body::Text(text) = &file.body else {
            panic!()
        };
        let table: toml::Table = toml::from_str(text).unwrap();
        assert_eq!(table["platform"]["colour"].as_str(), Some("blue"));
        assert_eq!(table["tenants"][0]["name"].as_str(), Some("splunk-es"));
    }

    #[test]
    fn too_few_targets_is_an_error() {
        let mut catalogue = Catalogue::parse(CATALOGUE).unwrap();
        catalogue.kinds[0].count = 500;
        let few = CATALOGUE.replace("count = 6", "count = 2");
        assert!(Catalogue::parse(&few).is_err());
        assert!(select(&workspace(), &catalogue.kinds[0], &BTreeSet::new()).is_err());
    }

    #[test]
    fn rejects_bad_catalogues() {
        let twice = format!(
            "{CATALOGUE}\n[[kind]]\nid = \"toml\"\ncodes = [\"x\"]\nseverity = \"error\"\ntarget = {{ family = \"rule\" }}\nops = []\n"
        );
        assert!(Catalogue::parse(&twice).is_err());
        let missing = CATALOGUE.replace(
            "severity = { duplicate_id = \"error\" }",
            "severity = { other = \"error\" }",
        );
        assert!(Catalogue::parse(&missing).is_err());
        let family = CATALOGUE.replace("family = \"threat\"", "family = \"thread\"");
        assert!(Catalogue::parse(&family).is_err());
    }

    #[test]
    fn judge_compares_codes_severities_and_targets() {
        let catalogue = Catalogue::parse(CATALOGUE).unwrap();
        let kind = catalogue.kind("bad-uuid").unwrap();
        let f = |code: &str, severity: &str, path: &str| Finding {
            code: code.into(),
            severity: severity.into(),
            path: Some(path.into()),
        };
        let targets = vec!["a.yaml".to_string(), "b.yaml".to_string()];
        let ok = judge(
            kind,
            &targets,
            &[
                f("invalid_uuid", "error", "a.yaml"),
                f("invalid_uuid", "error", "b.yaml"),
            ],
        );
        assert!(ok.problems.is_empty(), "{:?}", ok.problems);
        let bad = judge(
            kind,
            &targets,
            &[
                f("invalid_uuid", "warning", "a.yaml"),
                f("schema_validation", "error", "a.yaml"),
            ],
        );
        assert_eq!(
            bad.problems,
            vec![
                "`invalid_uuid` is warning, expected error (a.yaml)".to_string(),
                "no finding on target b.yaml".to_string(),
                "unexpected `schema_validation` (1x)".to_string(),
            ]
        );
        let mut silent = kind.clone();
        silent.codes.clear();
        silent.gap = Some("KG-00".into());
        assert!(judge(&silent, &targets, &[]).problems.is_empty());
        assert_eq!(
            judge(&silent, &targets, &[f("invalid_uuid", "error", "a.yaml")]).problems,
            vec!["unexpected `invalid_uuid` (1x)".to_string()]
        );
        let none = judge(kind, &targets, &[]);
        assert!(
            none.problems
                .contains(&"expected `invalid_uuid`, not reported".to_string())
        );
    }

    #[test]
    fn reads_validate_and_lint_documents() {
        let validate = serde_json::json!({
            "report": {
                "issues": [{"code": "invalid_uuid", "severity": "error", "path": "/w/objects/rules/a.yaml"}],
                "warnings": [{"code": "deprecated_field", "path": "objects/rules/b.yaml"}]
            }
        });
        let found = super::findings(&validate, "/w").unwrap();
        assert_eq!(found[0].path.as_deref(), Some("objects/rules/b.yaml"));
        assert_eq!(found[0].severity, "warning");
        assert_eq!(found[1].path.as_deref(), Some("objects/rules/a.yaml"));
        let lint = serde_json::json!({"findings": [{"code": "filename_mismatch", "severity": "warning", "path": "x.yaml"}]});
        assert_eq!(super::findings(&lint, "/w").unwrap().len(), 1);
        assert!(super::findings(&serde_json::json!({"message": "boom"}), "/w").is_err());
    }
}
