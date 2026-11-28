//! A rule's query, as `opentide query --rule` and `--file` run it
//! (UC-4.4c, #834): the rule is read, then the queries a deploy of it sends
//! to the platform are
//! taken from its block ([`rule_queries`], opentide-compile's).

use std::path::{Path, PathBuf};

use opentide_compile::rule::Rule;
pub use opentide_compile::rule_query::{RuleQuery, rule_queries};

use super::{open, placement};
use crate::env::Env;

/// Why the rule cannot be read: the message, the flag at fault and the
/// closest UUID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The message.
    pub message: String,
    /// `--rule` or `--file`.
    pub argument: &'static str,
    /// The closest rule UUID, for a `--rule` that names none.
    pub suggestion: Option<String>,
}

impl Refusal {
    fn file(message: String) -> Self {
        Self {
            message,
            argument: "--file",
            suggestion: None,
        }
    }
}

/// The rule `--rule` (by UUID, in the workspace) or `--file` (a path from
/// the working directory, else from the repository) names.
///
/// # Errors
///
/// The rule cannot be read: the refusal.
pub fn load(
    uuid: Option<&str>,
    file: Option<&str>,
    repo: Option<&str>,
    env: &Env,
    cwd: &Path,
) -> Result<Rule, Refusal> {
    if let Some(file) = file {
        let (shown, _) = placement(repo, env, cwd);
        return load_file(file, &cwd.join(shown), cwd);
    }
    load_uuid(uuid.unwrap_or_default(), repo, env, cwd)
}

/// The rule with UUID `wanted` in the workspace; UUIDs compare without case
/// (RFC 9562), so one pasted from a console finds its rule.
fn load_uuid(wanted: &str, repo: Option<&str>, env: &Env, cwd: &Path) -> Result<Rule, Refusal> {
    let (_, options) = placement(repo, env, cwd);
    let folded = wanted.trim().to_lowercase();
    let mut known: Vec<String> = Vec::new();
    let mut found: Option<Rule> = None;
    if let Ok(workspace) = open(options) {
        for object in workspace.index().rules() {
            known.push(object.uuid.clone());
            if found.is_none()
                && object.uuid.to_lowercase() == folded
                && let Some(root) = object.root()
            {
                found = Some(Rule::new(
                    root,
                    Some(object.path.to_string_lossy().into_owned()),
                ));
            }
        }
        crate::app::release(workspace);
    }
    found.ok_or_else(|| Refusal {
        message: format!("no rule with UUID {wanted}"),
        argument: "--rule",
        suggestion: crate::suggest::did_you_mean(wanted, known.iter().map(String::as_str)),
    })
}

/// The rule in `file`: from the working directory, else from the
/// repository root `repo`.
fn load_file(file: &str, repo: &Path, cwd: &Path) -> Result<Rule, Refusal> {
    let given = PathBuf::from(file);
    let mut path = cwd.join(&given);
    if !path.is_file() && !given.is_absolute() && repo.join(&given).is_file() {
        path = repo.join(&given);
    }
    if !path.is_file() {
        return Err(Refusal::file(format!("no rule file at {file}")));
    }
    let unreadable =
        |problem: String| Refusal::file(format!("cannot read the rule in {file}: {problem}"));
    let bytes = std::fs::read(&path).map_err(|error| unreadable(error.to_string()))?;
    let document =
        opentide_schema::node::load_bytes(&bytes).map_err(|error| unreadable(error.to_string()))?;
    let root = match document.root() {
        Some(root) if matches!(root.value, opentide_schema::node::Value::Map(_)) => {
            (**root).clone()
        }
        _ => return Err(unreadable("the file does not hold one rule mapping".into())),
    };
    let read = opentide_schema::revisions::read(&document, "rule")
        .map_err(|rejection| unreadable(rejection.to_string()))?;
    if let Err(errors) = read.result {
        return Err(unreadable(validation_message(&errors)));
    }
    Ok(Rule::new(&root, Some(path.to_string_lossy().into_owned())))
}

/// A rule's schema errors, one line each: the dotted location and the
/// message (the message alone at the root).
fn validation_message(errors: &[opentide_schema::SchemaError]) -> String {
    errors
        .iter()
        .map(|error| {
            if error.path.is_empty() {
                error.message.clone()
            } else {
                format!("{}: {}", error.field_path().join("."), error.message)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_file_is_read_from_the_working_directory_else_the_repository() {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(repo.join("rules")).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let missing = load_file("rules/r.yaml", &repo, &elsewhere).unwrap_err();
        assert_eq!(missing.message, "no rule file at rules/r.yaml");
        assert_eq!(missing.argument, "--file");
        std::fs::write(repo.join("rules/list.yaml"), "- a\n").unwrap();
        assert_eq!(
            load_file("rules/list.yaml", &repo, &elsewhere)
                .unwrap_err()
                .message,
            "cannot read the rule in rules/list.yaml: the file does not hold one rule mapping"
        );
        std::fs::write(
            repo.join("rules/bad.yaml"),
            "name: R\nmetadata:\n  schema: rule::1.0\n",
        )
        .unwrap();
        let invalid = load_file("rules/bad.yaml", &repo, &elsewhere).unwrap_err();
        assert!(
            invalid
                .message
                .starts_with("cannot read the rule in rules/bad.yaml: "),
            "{}",
            invalid.message
        );
        assert!(
            invalid
                .message
                .lines()
                .any(|line| line == "metadata.version: Field required"),
            "{}",
            invalid.message
        );
    }
}
