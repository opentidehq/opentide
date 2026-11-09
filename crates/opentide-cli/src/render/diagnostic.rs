//! The shape every finding takes for its renderers: a code, a severity, a message and a place.
//!
//! Positions are 1-based; columns count Unicode code points (`🔥` is one
//! column); a span runs from (`line`, `column`) up to (`end_line`,
//! `end_column`), `end_column` exclusive and on `end_line`, which is `None`
//! for a span on `line` alone (`docs/cli/diagnostics.md`, plan §3 invariant 3).
//! A validation issue, a lint finding or an engine finding becomes one of
//! these in its command (UC-3.5); the code frames ([`super::codeframe`]), the
//! report files ([`super::report`]) and the CI sinks ([`super::ci`]) read it.

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// How much a finding matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Fails the command.
    Error,
    /// Fails it under `--strict`.
    Warning,
    /// Never fails it.
    Note,
}

impl Severity {
    /// `error`, `warning` or `note`.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Note => "note",
        }
    }
}

/// Replace the text from (`line`, `column`) up to (`end_line`, `end_column`).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct TextEdit {
    /// 1-based.
    pub line: usize,
    /// 1-based, code points.
    pub column: usize,
    /// Exclusive, on `end_line`.
    pub end_column: usize,
    /// The new text.
    pub replacement: String,
    /// The line `end_column` is on; `None` for an edit within `line`.
    #[serde(default)]
    pub end_line: Option<usize>,
}

impl TextEdit {
    /// The line the edit ends on.
    pub fn last_line(&self) -> usize {
        self.end_line.unwrap_or(self.line)
    }
}

/// Edits that resolve a diagnostic; `safe` ones may be applied without review.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Fix {
    /// Whether `validate --fix` applies it.
    pub safe: bool,
    /// The edits, in order.
    pub edits: Vec<TextEdit>,
}

/// One finding, as every renderer reads it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Diagnostic {
    /// The stable code (`vocab_unknown`), with its `opentide explain` page.
    pub code: String,
    /// Its severity.
    pub severity: Severity,
    /// One sentence.
    pub message: String,
    /// Workspace-relative, `/`-separated; `None` when no file is at fault.
    #[serde(default)]
    pub path: Option<String>,
    /// The file on disk, absolute; the frame reads its source lines from it.
    #[serde(default)]
    pub file_path: Option<PathBuf>,
    /// 1-based.
    #[serde(default)]
    pub line: Option<usize>,
    /// 1-based, code points.
    #[serde(default)]
    pub column: Option<usize>,
    /// Exclusive, on `end_line`.
    #[serde(default)]
    pub end_column: Option<usize>,
    /// The line `end_column` is on; `None` for a span on `line` alone.
    #[serde(default)]
    pub end_line: Option<usize>,
    /// The field at fault in the object.
    #[serde(default)]
    pub field_path: Vec<String>,
    /// The step to take: `╰─ help:`.
    #[serde(default)]
    pub help: Option<String>,
    /// Edits that resolve it.
    #[serde(default)]
    pub fix: Option<Fix>,
    /// A few words under the underline (`not in tlp::1.0`).
    #[serde(default)]
    pub label: Option<String>,
    /// Further `(label, text)` lines, such as `("expected", "…")`.
    #[serde(default)]
    pub notes: Vec<(String, String)>,
    /// The object the finding is about.
    #[serde(default)]
    pub object_uuid: Option<String>,
}

impl Diagnostic {
    /// A finding with no place.
    pub fn new(code: &str, severity: Severity, message: &str) -> Diagnostic {
        Diagnostic {
            code: code.to_owned(),
            severity,
            message: message.to_owned(),
            path: None,
            file_path: None,
            line: None,
            column: None,
            end_column: None,
            end_line: None,
            field_path: Vec::new(),
            help: None,
            fix: None,
            label: None,
            notes: Vec::new(),
            object_uuid: None,
        }
    }

    /// The line the span ends on: `end_line`, or `line` for a one-line span.
    pub fn last_line(&self) -> Option<usize> {
        self.end_line.or(self.line)
    }

    /// Whether the span runs over more than one line.
    pub fn multiline(&self) -> bool {
        self.line.is_some() && self.last_line() != self.line
    }

    /// `end_column` on `line`: a frame underlines one line, so a longer span is
    /// its first character there.
    pub fn single_line_end(&self) -> Option<usize> {
        if self.multiline() {
            self.column.map(|column| column + 1)
        } else {
            self.end_column
        }
    }

    /// `opentide explain <code>`.
    pub fn explain(&self) -> String {
        format!("opentide explain {}", self.code)
    }
}

/// Grouped by file (findings with a file first, in path order), then by line and column.
pub fn sort_diagnostics<'a>(
    diagnostics: impl IntoIterator<Item = &'a Diagnostic>,
) -> Vec<&'a Diagnostic> {
    let mut sorted: Vec<&Diagnostic> = diagnostics.into_iter().collect();
    sorted.sort_by(|a, b| {
        (
            a.path.is_none(),
            a.path.as_deref().unwrap_or(""),
            a.line.unwrap_or(0),
            a.column.unwrap_or(0),
        )
            .cmp(&(
                b.path.is_none(),
                b.path.as_deref().unwrap_or(""),
                b.line.unwrap_or(0),
                b.column.unwrap_or(0),
            ))
    });
    sorted
}

/// `path` relative to `base` with `/` separators, or `path` itself, `/`-separated,
/// when it is outside. Compares the paths as written, then resolved (a symlinked
/// temporary directory).
pub fn relative_path(path: &Path, base: Option<&Path>) -> String {
    if let Some(base) = base {
        let resolved = (fs::canonicalize(path).ok(), fs::canonicalize(base).ok());
        let pairs = [
            (Some(path.to_path_buf()), Some(base.to_path_buf())),
            resolved,
        ];
        for (candidate, root) in pairs {
            if let (Some(candidate), Some(root)) = (candidate, root)
                && let Ok(rest) = candidate.strip_prefix(&root)
            {
                let joined = posix(rest);
                return if joined.is_empty() {
                    ".".to_owned()
                } else {
                    joined
                };
            }
        }
    }
    posix(path)
}

/// A path with `/` separators.
fn posix(path: &Path) -> String {
    let mut out = String::new();
    for (index, component) in path.components().enumerate() {
        match component {
            Component::RootDir => out.push('/'),
            other => {
                if index > 0 && !out.ends_with('/') {
                    out.push('/');
                }
                out.push_str(&other.as_os_str().to_string_lossy());
            }
        }
    }
    out
}

/// Where a frame reads its source lines: the files on disk, or (in tests) texts in memory.
pub trait Sources {
    /// The text of `path`, a BOM dropped; `None` when it cannot be read as UTF-8.
    fn text(&mut self, path: &Path) -> Option<&str>;

    /// Line `number` (1-based) of `path`, without its line break, as YAML numbers lines.
    fn line(&mut self, path: &Path, number: usize) -> Option<String> {
        let text = self.text(path)?;
        if number == 0 {
            return None;
        }
        split_yaml_lines(text)
            .into_iter()
            .nth(number - 1)
            .map(str::to_owned)
    }
}

/// `text` split at the line breaks YAML counts (`\r\n`, `\r`, `\n`), a last empty line dropped.
pub fn split_yaml_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                lines.push(&text[start..index]);
                index += if bytes.get(index + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = index;
            }
            b'\n' => {
                lines.push(&text[start..index]);
                index += 1;
                start = index;
            }
            _ => index += 1,
        }
    }
    lines.push(&text[start..]);
    if lines.last() == Some(&"") {
        lines.pop();
    }
    lines
}

/// The files on disk, each read once.
#[derive(Debug, Default)]
pub struct SourceFiles {
    texts: HashMap<PathBuf, Option<String>>,
}

impl Sources for SourceFiles {
    fn text(&mut self, path: &Path) -> Option<&str> {
        self.texts
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let bytes = fs::read(path).ok()?;
                let text = String::from_utf8(bytes).ok()?;
                Some(
                    text.strip_prefix('\u{feff}')
                        .map(str::to_owned)
                        .unwrap_or(text),
                )
            })
            .as_deref()
    }
}

/// Texts in memory, by path.
#[derive(Debug, Default)]
pub struct MemorySources {
    /// Each file's text.
    pub texts: HashMap<PathBuf, String>,
}

impl Sources for MemorySources {
    fn text(&mut self, path: &Path) -> Option<&str> {
        self.texts.get(path).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_lines_and_spans() {
        assert_eq!(split_yaml_lines("a\r\nb\rc\n"), ["a", "b", "c"]);
        assert_eq!(split_yaml_lines("a\u{2028}b"), ["a\u{2028}b"]);
        assert_eq!(split_yaml_lines(""), Vec::<&str>::new());
        let mut item = Diagnostic::new("x", Severity::Error, "m");
        item.line = Some(3);
        item.column = Some(2);
        item.end_column = Some(5);
        assert_eq!(item.single_line_end(), Some(5));
        item.end_line = Some(4);
        assert!(item.multiline());
        assert_eq!(item.single_line_end(), Some(3));
        assert_eq!(item.explain(), "opentide explain x");
    }

    #[test]
    fn relative_paths() {
        assert_eq!(
            relative_path(Path::new("/a/b/c.yaml"), Some(Path::new("/a"))),
            "b/c.yaml"
        );
        assert_eq!(
            relative_path(Path::new("/x/c.yaml"), Some(Path::new("/a"))),
            "/x/c.yaml"
        );
        assert_eq!(relative_path(Path::new("/x/c.yaml"), None), "/x/c.yaml");
    }

    #[test]
    fn sort_puts_files_first() {
        let mut a = Diagnostic::new("a", Severity::Error, "m");
        a.path = Some("b.yaml".into());
        let mut b = a.clone();
        b.path = Some("a.yaml".into());
        b.line = Some(9);
        let c = Diagnostic::new("c", Severity::Note, "m");
        let items = [c.clone(), a.clone(), b.clone()];
        let sorted: Vec<&str> = sort_diagnostics(&items)
            .iter()
            .map(|d| d.code.as_str())
            .collect();
        assert_eq!(sorted, ["a", "a", "c"]);
        assert_eq!(sort_diagnostics(&items)[0].path.as_deref(), Some("a.yaml"));
    }
}
