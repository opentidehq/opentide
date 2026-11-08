//! The workspaces the benchmark runs in: the heavy workspace (UC-0.6's
//! generator, seed 20261107), and a copy of it with every platform disabled,
//! where `validate` reports a warning per query instead of checking it.

use crate::bench::measure::copy_tree;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// The heavy workspace's seed (plan section 2, 2026-11-07).
pub const SEED: u64 = 20_261_107;

/// Where the platform configurations of a workspace live.
pub const PLATFORMS_DIR: &str = ".opentide/configurations/platforms";

/// Where the rules of a workspace live.
pub const RULES_DIR: &str = "objects/rules";

/// The prepared workspaces, each a pristine copy that every run copies again.
#[derive(Clone, Debug)]
pub struct Workspaces {
    /// The heavy workspace as generated.
    pub clean: PathBuf,
    /// The same with every platform's `enabled = false`.
    pub warnings: PathBuf,
    /// The rule `validate --file`, `lint --file` and the language server
    /// open, relative to the workspace: the first rule file by name.
    pub rule: PathBuf,
    /// How many rule files the workspace holds.
    pub rules: usize,
    /// How many platforms the warnings copy disabled.
    pub disabled_platforms: usize,
    /// The fewest warnings `validate` must report on the warnings copy for
    /// the run to count.
    pub min_warnings: usize,
}

/// Prepares the workspaces under `work` from `source`, a workspace on disk.
pub fn prepare(source: &Path, work: &Path) -> Result<Workspaces> {
    let clean = work.join("clean");
    let warnings = work.join("warnings");
    for dir in [&clean, &warnings] {
        if dir.exists() {
            std::fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
        }
    }
    copy_tree(source, &clean)?;
    copy_tree(source, &warnings)?;
    let disabled_platforms = disable_platforms(&warnings)?;
    let rule_files = rule_files(&clean)?;
    let Some(rule) = rule_files.first().cloned() else {
        bail!("{} holds no rule file under {RULES_DIR}/", source.display());
    };
    Ok(Workspaces {
        clean,
        warnings,
        rule,
        rules: rule_files.len(),
        disabled_platforms,
        min_warnings: rule_files.len(),
    })
}

/// The rule files of a workspace (`objects/rules/*.yaml|yml`), relative to
/// it, sorted by name.
pub fn rule_files(workspace: &Path) -> Result<Vec<PathBuf>> {
    let dir = workspace.join(RULES_DIR);
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        let is_yaml = path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("yaml") || e.eq_ignore_ascii_case("yml"));
        if is_yaml && path.is_file() {
            files.push(Path::new(RULES_DIR).join(path.file_name().unwrap_or_default()));
        }
    }
    files.sort();
    Ok(files)
}

/// Sets `enabled = false` in the `[platform]` table of every platform
/// configuration that enables one, and returns how many it changed. The
/// edit is a splice of that one line, so comments and layout stay; the
/// result is parsed again to prove the platform is disabled.
pub fn disable_platforms(workspace: &Path) -> Result<usize> {
    let dir = workspace.join(PLATFORMS_DIR);
    let mut changed = 0;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("read {}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.extension().is_some_and(|e| e == "toml"))
        .collect();
    entries.sort();
    for path in entries {
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let Some(disabled) = disable_platform(&text) else {
            continue;
        };
        let parsed: toml::Table =
            toml::from_str(&disabled).with_context(|| format!("parse {}", path.display()))?;
        let enabled = parsed
            .get("platform")
            .and_then(|p| p.get("enabled"))
            .and_then(toml::Value::as_bool);
        if enabled != Some(false) {
            bail!(
                "{}: platform.enabled is {enabled:?} after the edit",
                path.display()
            );
        }
        std::fs::write(&path, disabled).with_context(|| format!("write {}", path.display()))?;
        changed += 1;
    }
    if changed == 0 {
        bail!(
            "no platform to disable under {}: the warnings workspace would equal the clean one",
            dir.display()
        );
    }
    Ok(changed)
}

/// The text with the `[platform]` table's `enabled = true` set to `false`;
/// `None` when the table does not enable the platform.
pub fn disable_platform(text: &str) -> Option<String> {
    let mut in_platform = false;
    let mut out = String::with_capacity(text.len());
    let mut found = false;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_platform = trimmed == "[platform]";
        } else if in_platform && !found {
            let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
            if compact == "enabled=true" || compact.starts_with("enabled=true#") {
                let indent = &line[..line.len() - line.trim_start().len()];
                let ending = if line.ends_with("\r\n") {
                    "\r\n"
                } else if line.ends_with('\n') {
                    "\n"
                } else {
                    ""
                };
                out.push_str(indent);
                out.push_str("enabled = false");
                out.push_str(ending);
                found = true;
                continue;
            }
        }
        out.push_str(line);
    }
    found.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_table_is_disabled_and_nothing_else_changes() {
        let text =
            "# Sentinel\n[platform]\nenabled = true\nname = \"S\"\n\n[[tenants]]\nenabled = true\n";
        assert_eq!(
            disable_platform(text).unwrap(),
            "# Sentinel\n[platform]\nenabled = false\nname = \"S\"\n\n[[tenants]]\nenabled = true\n"
        );
    }

    #[test]
    fn crlf_and_a_trailing_comment_are_kept() {
        let text = "[platform]\r\n  enabled=true # on\r\n";
        assert_eq!(
            disable_platform(text).unwrap(),
            "[platform]\r\n  enabled = false\r\n"
        );
    }

    #[test]
    fn a_disabled_or_commented_platform_is_left_alone() {
        assert_eq!(disable_platform("[platform]\nenabled = false\n"), None);
        assert_eq!(disable_platform("[platform]\n#enabled = true\n"), None);
        assert_eq!(disable_platform("[other]\nenabled = true\n"), None);
    }

    #[test]
    fn a_workspace_without_an_enabled_platform_is_refused() {
        let root = std::env::temp_dir().join(format!("xtask-bench-ws-{}", std::process::id()));
        let platforms = root.join(PLATFORMS_DIR);
        std::fs::create_dir_all(&platforms).unwrap();
        std::fs::write(
            platforms.join("splunk.toml"),
            "[platform]\nenabled = false\n",
        )
        .unwrap();
        assert!(disable_platforms(&root).is_err());
        std::fs::write(
            platforms.join("sentinel.toml"),
            "[platform]\nenabled = true\n",
        )
        .unwrap();
        assert_eq!(disable_platforms(&root).unwrap(), 1);
        assert_eq!(
            std::fs::read_to_string(platforms.join("sentinel.toml")).unwrap(),
            "[platform]\nenabled = false\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
