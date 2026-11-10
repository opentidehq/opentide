//! CI sinks: inline annotations and a job summary for the CI provider running opentide.
//!
//! - GitHub Actions (`GITHUB_ACTIONS`): `::error file=,line=,col=,title=<code>::<message>`
//!   per diagnostic on stdout, at most 10 of each level and then one notice
//!   counting the rest; the summary is appended to `$GITHUB_STEP_SUMMARY`.
//! - GitLab CI (`GITLAB_CI`): nothing inline (`--format codequality` is the
//!   report GitLab shows); the summary is appended to `opentide-reports/summary.md`
//!   in the checkout.
//! - Azure Pipelines (`TF_BUILD`): `##vso[task.logissue type=…;…]<message>` per
//!   diagnostic; the summary is a file of its own in `AGENT_TEMPDIRECTORY`,
//!   attached with `##vso[task.uploadsummary]<file>`.
//!
//! The sinks add to the `human`, `plain` and `agent` modes and are off in
//! `json` and `mcp`: GitHub and Azure read their commands from stdout, which
//! belongs to the JSON document or to JSON-RPC there. A command is never
//! wrapped. See "CI" in `docs/internal/cli-experience.md`.

use super::diagnostic::{Diagnostic, Severity, relative_path};
use crate::env::Env;
use crate::mode::{Mode, detect_ci};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// A provider with sinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    /// GitHub Actions.
    Github,
    /// GitLab CI.
    Gitlab,
    /// Azure Pipelines.
    Azure,
}

impl Provider {
    /// The variable that names where the provider checked the repository out.
    pub fn checkout_variable(self) -> &'static str {
        match self {
            Provider::Github => "GITHUB_WORKSPACE",
            Provider::Gitlab => "CI_PROJECT_DIR",
            Provider::Azure => "BUILD_SOURCESDIRECTORY",
        }
    }
}

/// The directory generated pipelines keep reports in, relative to the checkout.
pub const REPORTS_DIR: &str = "opentide-reports";

/// The GitLab summary file, relative to the checkout; `setup ci` uploads it.
pub const GITLAB_SUMMARY: &str = "opentide-reports/summary.md";

/// GitHub shows at most this many annotations of each level per step (and 50
/// per job; three levels of 10 stay under it); later ones stay log lines.
pub const GITHUB_ANNOTATIONS_PER_LEVEL: usize = 10;

/// The CI provider whose sinks apply to this run.
pub fn ci_provider(env: &Env) -> Option<Provider> {
    match detect_ci(env)? {
        "github" => Some(Provider::Github),
        "gitlab" => Some(Provider::Gitlab),
        "azure" => Some(Provider::Azure),
        _ => None,
    }
}

/// [`ci_provider`], or none in the `json` and `mcp` modes.
pub fn active_provider(mode: Mode, env: &Env) -> Option<Provider> {
    if matches!(mode, Mode::Json | Mode::Mcp) {
        return None;
    }
    ci_provider(env)
}

/// The directory the provider checked the repository out to, when it says.
pub fn checkout_root(provider: Option<Provider>, env: &Env) -> Option<PathBuf> {
    let value = env.get(provider?.checkout_variable())?.trim();
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// The diagnostic's file relative to `root` (the checkout), else its workspace path.
pub fn repository_path(diagnostic: &Diagnostic, root: Option<&Path>) -> Option<String> {
    if let (Some(root), Some(file_path)) = (root, &diagnostic.file_path) {
        let shown = relative_path(file_path, Some(root));
        if !Path::new(&shown).is_absolute() {
            return Some(shown);
        }
    }
    diagnostic.path.clone()
}

/// The message, then `help: …` on its own line when there is help.
pub fn annotation_text(diagnostic: &Diagnostic) -> String {
    match diagnostic.help.as_ref().filter(|help| !help.is_empty()) {
        Some(help) => format!("{}\nhelp: {help}", diagnostic.message),
        None => diagnostic.message.clone(),
    }
}

/// Escapes a workflow command's message, as `@actions/core` does.
pub fn github_escape_data(text: &str) -> String {
    text.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escapes a workflow command property: the message escapes, plus `:` and `,`.
pub fn github_escape_property(text: &str) -> String {
    github_escape_data(text)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

/// `::<level> k=v,…::<message>`, properties without a value left out.
pub fn github_command(level: &str, message: &str, properties: &[(&str, Option<String>)]) -> String {
    let rendered: Vec<String> = properties
        .iter()
        .filter_map(|(name, value)| {
            value
                .as_ref()
                .map(|value| format!("{name}={}", github_escape_property(value)))
        })
        .collect();
    let head = if rendered.is_empty() {
        level.to_owned()
    } else {
        format!("{level} {}", rendered.join(","))
    };
    format!("::{head}::{}", github_escape_data(message))
}

fn github_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Note => "notice",
    }
}

/// One diagnostic as a GitHub `::error`, `::warning` or `::notice` command.
///
/// GitHub's `endColumn` is the last column of the span, one before ours
/// (inclusive), and applies only on a single line: a one-line span's
/// `endLine` repeats `line`, and a longer one has `endLine` and no `endColumn`.
pub fn github_annotation(diagnostic: &Diagnostic, root: Option<&Path>) -> String {
    let path = repository_path(diagnostic, root);
    let line = diagnostic.line.filter(|_| path.is_some());
    let column = diagnostic.column.filter(|_| line.is_some());
    let multiline = line.is_some() && diagnostic.multiline();
    let end_column = match (column, diagnostic.end_column) {
        (Some(column), Some(end)) if !multiline => Some(column.max(end.saturating_sub(1))),
        _ => None,
    };
    let end_line = if multiline {
        diagnostic.last_line()
    } else if end_column.is_some() {
        line
    } else {
        None
    };
    github_command(
        github_level(diagnostic.severity),
        &annotation_text(diagnostic),
        &[
            ("file", path),
            ("line", line.map(|value| value.to_string())),
            ("endLine", end_line.map(|value| value.to_string())),
            ("col", column.map(|value| value.to_string())),
            ("endColumn", end_column.map(|value| value.to_string())),
            ("title", Some(diagnostic.code.clone())),
        ],
    )
}

/// Escapes a logging command's message, as `azure-pipelines-task-lib` does.
pub fn azure_escape_data(text: &str) -> String {
    text.replace('%', "%AZP25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escapes a logging command property: the message escapes, plus `;` and `]`.
pub fn azure_escape_property(text: &str) -> String {
    azure_escape_data(text)
        .replace(';', "%3B")
        .replace(']', "%5D")
}

/// `##vso[<area> k=v;…]<message>`, properties without a value left out.
pub fn azure_command(area: &str, message: &str, properties: &[(&str, Option<String>)]) -> String {
    let rendered: String = properties
        .iter()
        .filter_map(|(name, value)| {
            value
                .as_ref()
                .map(|value| format!("{name}={};", azure_escape_property(value)))
        })
        .collect();
    let head = if rendered.is_empty() {
        area.to_owned()
    } else {
        format!("{area} {rendered}")
    };
    format!("##vso[{head}]{}", azure_escape_data(message))
}

/// One diagnostic as `##vso[task.logissue …]`; none for a note (Azure has no notice level).
pub fn azure_annotation(diagnostic: &Diagnostic, root: Option<&Path>) -> Option<String> {
    let kind = match diagnostic.severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Note => return None,
    };
    let path = repository_path(diagnostic, root);
    let line = diagnostic.line.filter(|_| path.is_some());
    let column = diagnostic.column.filter(|_| line.is_some());
    Some(azure_command(
        "task.logissue",
        &annotation_text(diagnostic),
        &[
            ("type", Some(kind.to_owned())),
            ("sourcepath", path),
            ("linenumber", line.map(|value| value.to_string())),
            ("columnnumber", column.map(|value| value.to_string())),
            ("code", Some(diagnostic.code.clone())),
        ],
    ))
}

/// The notice that says how many findings had no annotation of their own.
pub fn github_overflow_notice(count: usize) -> String {
    let noun = if count == 1 { "finding" } else { "findings" };
    github_command(
        "notice",
        &format!("{count} more {noun}: see the job summary or code scanning"),
        &[("title", Some("opentide".to_owned()))],
    )
}

/// Errors, then warnings, then notes, each cut to what GitHub shows; and how many
/// were cut. When anything is cut, one notice slot is kept for the overflow notice.
fn github_capped(diagnostics: &[Diagnostic]) -> (Vec<&Diagnostic>, usize) {
    let mut ordered: Vec<&Diagnostic> = diagnostics.iter().collect();
    ordered.sort_by_key(|item| item.severity);
    let mut levels: Vec<(Severity, Vec<&Diagnostic>)> = Vec::new();
    for item in &ordered {
        match levels.iter_mut().find(|(level, _)| *level == item.severity) {
            Some((_, items)) => items.push(item),
            None => levels.push((item.severity, vec![item])),
        }
    }
    let limit = GITHUB_ANNOTATIONS_PER_LEVEL;
    let overflow = levels.iter().any(|(_, items)| items.len() > limit);
    let mut shown = Vec::new();
    for (level, items) in levels {
        let keep = if overflow && level == Severity::Note {
            limit - 1
        } else {
            limit
        };
        shown.extend(items.into_iter().take(keep));
    }
    let hidden = ordered.len() - shown.len();
    (shown, hidden)
}

/// The inline commands for `provider`; none on GitLab, which reads a report file.
pub fn annotation_lines(
    diagnostics: &[Diagnostic],
    provider: Option<Provider>,
    root: Option<&Path>,
) -> Vec<String> {
    match provider {
        Some(Provider::Github) => {
            let (shown, hidden) = github_capped(diagnostics);
            let mut lines: Vec<String> = shown
                .into_iter()
                .map(|item| github_annotation(item, root))
                .collect();
            if hidden > 0 {
                lines.push(github_overflow_notice(hidden));
            }
            lines
        }
        Some(Provider::Azure) => diagnostics
            .iter()
            .filter_map(|item| azure_annotation(item, root))
            .collect(),
        Some(Provider::Gitlab) | None => Vec::new(),
    }
}

/// A warning about the whole run, not about a file, for this run's CI.
pub fn warning_line(
    provider: Option<Provider>,
    message: &str,
    title: Option<&str>,
) -> Option<String> {
    let title = title.map(str::to_owned);
    match provider? {
        Provider::Github => Some(github_command("warning", message, &[("title", title)])),
        Provider::Azure => Some(azure_command(
            "task.logissue",
            message,
            &[("type", Some("warning".to_owned())), ("code", title)],
        )),
        Provider::Gitlab => None,
    }
}

/// `opentide-validate-query.md` for `validate query`.
pub fn summary_file_name(command: &str) -> String {
    let slug = command.split_whitespace().collect::<Vec<_>>().join("-");
    format!(
        "opentide-{}.md",
        if slug.is_empty() { "run" } else { &slug }
    )
}

fn append(path: &Path, markdown: &str) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(markdown.trim_end_matches('\n').as_bytes())?;
    file.write_all(b"\n\n")
}

/// A new file in the agent's temporary directory, one per command run.
fn azure_summary_path(command: &str, env: &Env) -> std::io::Result<PathBuf> {
    let directory = env
        .get("AGENT_TEMPDIRECTORY")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map_or_else(std::env::temp_dir, PathBuf::from);
    fs::create_dir_all(&directory)?;
    let name = summary_file_name(command);
    let stem = name.trim_end_matches(".md");
    let mut path = directory.join(format!("{stem}.md"));
    let mut counter = 2;
    while path.exists() {
        path = directory.join(format!("{stem}-{counter}.md"));
        counter += 1;
    }
    Ok(path)
}

/// What [`append_summary`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SummaryWritten {
    /// The file written.
    pub path: Option<PathBuf>,
    /// Lines for stdout: Azure's `##vso[task.uploadsummary]`.
    pub stdout: Vec<String>,
}

/// Adds `markdown` to this run's CI summary.
///
/// GitHub: appended to `$GITHUB_STEP_SUMMARY`. GitLab: appended to
/// [`GITLAB_SUMMARY`] in the checkout (`cwd` without one). Azure: a file of its
/// own, attached with `##vso[task.uploadsummary]`. A summary that cannot be
/// written is skipped: it never fails the command.
pub fn append_summary(
    markdown: &str,
    command: &str,
    mode: Mode,
    env: &Env,
    cwd: &Path,
) -> SummaryWritten {
    let provider = active_provider(mode, env);
    let written = match provider {
        Some(Provider::Github) => {
            let target = env.get("GITHUB_STEP_SUMMARY").unwrap_or_default().trim();
            if target.is_empty() {
                return SummaryWritten::default();
            }
            let path = PathBuf::from(target);
            append(&path, markdown).map(|()| (path, Vec::new()))
        }
        Some(Provider::Gitlab) => {
            let path = checkout_root(provider, env)
                .unwrap_or_else(|| cwd.to_path_buf())
                .join(GITLAB_SUMMARY);
            append(&path, markdown).map(|()| (path, Vec::new()))
        }
        Some(Provider::Azure) => azure_summary_path(command, env).and_then(|path| {
            append(&path, markdown)?;
            let line = azure_command("task.uploadsummary", &path.to_string_lossy(), &[]);
            Ok((path, vec![line]))
        }),
        None => return SummaryWritten::default(),
    };
    match written {
        Ok((path, stdout)) => SummaryWritten {
            path: Some(path),
            stdout,
        },
        Err(_) => SummaryWritten::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Env {
        Env::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn providers_and_modes() {
        assert_eq!(
            ci_provider(&env(&[("GITHUB_ACTIONS", "true")])),
            Some(Provider::Github)
        );
        assert_eq!(ci_provider(&env(&[("CI", "true")])), None);
        assert_eq!(
            active_provider(Mode::Json, &env(&[("TF_BUILD", "True")])),
            None
        );
        assert_eq!(
            active_provider(Mode::Plain, &env(&[("TF_BUILD", "True")])),
            Some(Provider::Azure)
        );
        assert_eq!(
            checkout_root(Some(Provider::Gitlab), &env(&[("CI_PROJECT_DIR", " /w ")])),
            Some(PathBuf::from("/w"))
        );
        assert_eq!(checkout_root(None, &env(&[])), None);
        assert_eq!(
            summary_file_name("validate query"),
            "opentide-validate-query.md"
        );
        assert_eq!(summary_file_name(""), "opentide-run.md");
    }

    #[test]
    fn summaries_are_written_where_each_provider_reads_them() {
        let dir = std::env::temp_dir().join(format!("opentide-ci-sink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let github = dir.join("step.md");
        let written = append_summary(
            "# x\n\n\n",
            "validate",
            Mode::Plain,
            &env(&[
                ("GITHUB_ACTIONS", "1"),
                ("GITHUB_STEP_SUMMARY", &github.to_string_lossy()),
            ]),
            &dir,
        );
        assert_eq!(written.path, Some(github.clone()));
        append_summary(
            "y",
            "validate",
            Mode::Agent,
            &env(&[
                ("GITHUB_ACTIONS", "1"),
                ("GITHUB_STEP_SUMMARY", &github.to_string_lossy()),
            ]),
            &dir,
        );
        assert_eq!(fs::read_to_string(&github).unwrap(), "# x\n\ny\n\n");
        let gitlab = append_summary(
            "g",
            "lint",
            Mode::Plain,
            &env(&[("GITLAB_CI", "true")]),
            &dir,
        );
        assert_eq!(gitlab.path, Some(dir.join(GITLAB_SUMMARY)));
        let agent = dir.join("agent");
        let azure_env = env(&[
            ("TF_BUILD", "True"),
            ("AGENT_TEMPDIRECTORY", &agent.to_string_lossy()),
        ]);
        let first = append_summary("a", "validate query", Mode::Plain, &azure_env, &dir);
        let second = append_summary("b", "validate query", Mode::Plain, &azure_env, &dir);
        assert_eq!(first.path, Some(agent.join("opentide-validate-query.md")));
        assert_eq!(
            second.path,
            Some(agent.join("opentide-validate-query-2.md"))
        );
        assert_eq!(
            second.stdout,
            [format!(
                "##vso[task.uploadsummary]{}",
                agent.join("opentide-validate-query-2.md").display()
            )]
        );
        assert_eq!(
            append_summary("x", "v", Mode::Json, &azure_env, &dir),
            SummaryWritten::default()
        );
        assert_eq!(
            append_summary(
                "x",
                "v",
                Mode::Plain,
                &env(&[("GITHUB_ACTIONS", "1")]),
                &dir
            ),
            SummaryWritten::default()
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
