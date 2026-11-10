//! `validate --fix`: the safe edits of the findings, applied as text splices
//! (`cli/ui/fixes.py`, UC-2.3 #818).
//!
//! An edit replaces the text from (`line`, `column`) up to (`end_line`,
//! `end_column`) and keeps every other byte of the file: comments, quoting,
//! key order, indentation and line endings survive. The YAML is never
//! written back from a parsed tree.
//!
//! Each edit is checked before it is kept. The text it replaces, read again
//! now, must still be a safe replacement for the fix's value
//! ([`is_safe_replacement`]), so a value saved over the typo since the
//! finding was made is never overwritten. The file must still parse, and the
//! parsed document must differ from the one before in exactly that value. An
//! edit that fails a check is left out, and its finding stays reported.
//!
//! [`FixPlan::write`] writes each file through [`WriteFs::replace`]: to a
//! temporary file beside it, renamed into place, and only while the file
//! still holds the text the plan was made from.
//!
//! `--fix --dry-run` prints [`FixPlan::diff`]: a unified diff from the
//! `similar` crate, `a/<path>` against `b/<path>` with three lines of context,
//! the lines split where YAML breaks them (`\r\n`, `\r`, `\n`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use opentide_schema::node::{self, Node, Value};
use serde::Serialize;
use similar::{Algorithm, TextDiff};

use crate::diagnostic::{Diagnostic, TextEdit};
use crate::fs::{FileSystem, WriteFs};
use crate::validate::annotate::is_safe_replacement;

/// One value a fix replaces: where, which finding, and the text before and
/// after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixChange {
    /// The file, relative to the workspace (the finding's `path`).
    pub path: String,
    /// The file, as the finding names it.
    pub file_path: PathBuf,
    /// 1-based.
    pub line: usize,
    /// 1-based, code points.
    pub column: usize,
    /// The finding's code.
    pub code: String,
    /// The text replaced.
    pub before: String,
    /// The text written.
    pub after: String,
}

impl Serialize for FixChange {
    /// An entry of `fixed` (`would_fix` under `--dry-run`): `path`, `line`,
    /// `code`, `before`, `after`.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        let mut out = serializer.serialize_struct("FixChange", 5)?;
        out.serialize_field("path", &self.path)?;
        out.serialize_field("line", &self.line)?;
        out.serialize_field("code", &self.code)?;
        out.serialize_field("before", &self.before)?;
        out.serialize_field("after", &self.after)?;
        out.end()
    }
}

/// One file a plan changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    /// The file, relative to the workspace.
    pub path: String,
    /// Its text as read (a byte order mark included).
    pub before: String,
    /// Its text with the edits applied.
    pub after: String,
}

/// The edits that apply, file by file, with each file's text before and
/// after.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixPlan {
    /// Every value replaced, sorted by path, line and column.
    pub changes: Vec<FixChange>,
    /// The files, in the order their first finding came.
    pub files: IndexMap<PathBuf, PlannedFile>,
}

impl FixPlan {
    /// How many files change.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Whether nothing changes.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// A unified diff of every file, `a/<path>` against `b/<path>`; empty when
    /// nothing changes.
    pub fn diff(&self) -> String {
        let mut out = String::new();
        for file in self.files.values() {
            out.push_str(&unified_diff(&file.path, &file.before, &file.after));
        }
        out
    }

    /// Writes each changed file through `fs`; every byte outside the edits is
    /// written back unchanged. A file that no longer holds the text the plan
    /// was made from, or that cannot be written, is left alone.
    ///
    /// Returns the plan of the files written, and one line per file that was
    /// not (`objects/rules/x.yaml: it changed since it was read; ...`).
    pub fn write(&self, fs: &dyn WriteFs) -> (Self, Vec<String>) {
        let mut written = IndexMap::new();
        let mut failed = Vec::new();
        for (file_path, file) in &self.files {
            match fs.replace(file_path, file.before.as_bytes(), file.after.as_bytes()) {
                Ok(()) => {
                    written.insert(file_path.clone(), file.clone());
                }
                Err(error) => failed.push(format!("{}: {error}", file.path)),
            }
        }
        let changes = self
            .changes
            .iter()
            .filter(|change| written.contains_key(&change.file_path))
            .cloned()
            .collect();
        (
            Self {
                changes,
                files: written,
            },
            failed,
        )
    }
}

/// `before` against `after` as a unified diff with `a/<path>` and `b/<path>`
/// headers and three lines of context (`similar`'s patience diff and unified
/// format); empty when they are the same.
pub fn unified_diff(path: &str, before: &str, after: &str) -> String {
    let old = split_keeping_breaks(before);
    let new = split_keeping_breaks(after);
    let diff = TextDiff::configure()
        .algorithm(Algorithm::Patience)
        .newline_terminated(true)
        .diff_slices(&old, &new);
    diff.unified_diff()
        .context_radius(3)
        .missing_newline_hint(true)
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string()
}

/// `text` split where YAML breaks a line (`\r\n`, a lone `\r`, `\n`), each
/// line with its break.
pub fn split_keeping_breaks(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        let end = match bytes[index] {
            b'\n' => index + 1,
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => index + 2,
            b'\r' => index + 1,
            _ => {
                index += 1;
                continue;
            }
        };
        lines.push(&text[start..end]);
        start = end;
        index = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// The byte range of each line's content (without its break), numbered as
/// YAML numbers lines: a text ending in a break has no empty last line.
fn line_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for line in split_keeping_breaks(text) {
        let content = line.trim_end_matches(['\r', '\n']).len();
        spans.push((start, start + content));
        start += line.len();
    }
    if text.is_empty() {
        spans.push((0, 0));
    }
    spans
}

/// The byte offset of 1-based `line` and `column` (in code points); the
/// column may be one past the line's last character.
fn offset(text: &str, spans: &[(usize, usize)], line: usize, column: usize) -> Option<usize> {
    let (start, end) = *spans.get(line.checked_sub(1)?)?;
    let content = &text[start..end];
    let column = column.checked_sub(1)?;
    if column == content.chars().count() {
        return Some(end);
    }
    content
        .char_indices()
        .nth(column)
        .map(|(position, _)| start + position)
}

/// `text` with `edit` applied, and the text it replaced; `None` when the
/// edit does not fit the text. The edit may span lines; line breaks outside
/// it are left as they are, so a CRLF file keeps its endings.
pub fn apply(text: &str, edit: &TextEdit) -> Option<(String, String)> {
    let spans = line_spans(text);
    let start = offset(text, &spans, edit.line, edit.column)?;
    let end = offset(text, &spans, edit.end_line, edit.end_column)?;
    if end <= start {
        return None;
    }
    let mut updated = String::with_capacity(text.len() + edit.replacement.len());
    updated.push_str(&text[..start]);
    updated.push_str(&edit.replacement);
    updated.push_str(&text[end..]);
    Some((updated, text[start..end].to_owned()))
}

/// The edits `--fix` may apply for `diagnostic`: none unless its fix is safe
/// and it names a file.
pub fn safe_edits(diagnostic: &Diagnostic) -> &[TextEdit] {
    match (&diagnostic.fix, &diagnostic.file_path) {
        (Some(fix), Some(_)) if fix.safe => &fix.edits,
        _ => &[],
    }
}

/// Reads each file with a safe fix once (through `fs`) and works out which
/// edits apply. Nothing is written: [`FixPlan::write`] does that. Two
/// findings with the same edit apply it once; an edit that overlaps one
/// already kept is left out.
pub fn plan<'a>(
    fs: &dyn FileSystem,
    diagnostics: impl IntoIterator<Item = &'a Diagnostic>,
) -> FixPlan {
    let mut by_file: IndexMap<PathBuf, Vec<(&TextEdit, &Diagnostic)>> = IndexMap::new();
    for diagnostic in diagnostics {
        let Some(file) = &diagnostic.file_path else {
            continue;
        };
        for edit in safe_edits(diagnostic) {
            by_file
                .entry(file.clone())
                .or_default()
                .push((edit, diagnostic));
        }
    }
    let mut plan = FixPlan::default();
    for (file_path, edits) in by_file {
        if let Some((file, kept)) = plan_file(fs, &file_path, &edits) {
            plan.files.insert(file_path, file);
            plan.changes.extend(kept);
        }
    }
    plan.changes.sort_by(|a, b| {
        (a.path.as_str(), a.line, a.column).cmp(&(b.path.as_str(), b.line, b.column))
    });
    plan
}

fn plan_file(
    fs: &dyn FileSystem,
    file_path: &Path,
    edits: &[(&TextEdit, &Diagnostic)],
) -> Option<(PlannedFile, Vec<FixChange>)> {
    let original = String::from_utf8(fs.read(file_path).ok()?).ok()?;
    // Positions count from after a byte order mark, as the parser counts them.
    let (bom, body) = match original.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", original.as_str()),
    };
    let mut document = node::load(body).ok()?;
    let mut seen: HashSet<&TextEdit> = HashSet::new();
    let mut ordered: Vec<(&TextEdit, &Diagnostic)> = edits
        .iter()
        .filter(|(edit, _)| seen.insert(edit))
        .copied()
        .collect();
    // Right to left, so an edit never moves the columns of one still to apply.
    ordered.sort_by_key(|(edit, _)| std::cmp::Reverse((edit.line, edit.column)));
    let mut text = body.to_owned();
    let mut taken: Vec<&TextEdit> = Vec::new();
    let mut kept = Vec::new();
    for (edit, diagnostic) in ordered {
        if taken.iter().any(|other| overlaps(edit, other)) {
            continue;
        }
        let Some((updated, before)) = apply(&text, edit) else {
            continue;
        };
        // The file may have been saved since the finding was made: replace
        // only a value this fix is still a safe replacement for.
        if !is_safe_replacement(&diagnostic.code, &before, &edit.replacement) {
            continue;
        }
        let Ok(new_document) = node::load(&updated) else {
            continue;
        };
        if !only_change(
            document.root().map(AsRef::as_ref),
            new_document.root().map(AsRef::as_ref),
            &before,
            &edit.replacement,
        ) {
            continue;
        }
        text = updated;
        document = new_document;
        taken.push(edit);
        kept.push(FixChange {
            path: diagnostic
                .path
                .clone()
                .unwrap_or_else(|| file_path.to_string_lossy().replace('\\', "/")),
            file_path: file_path.to_path_buf(),
            line: edit.line,
            column: edit.column,
            code: diagnostic.code.clone(),
            before,
            after: edit.replacement.clone(),
        });
    }
    let first = kept.first()?;
    let file = PlannedFile {
        path: first.path.clone(),
        after: format!("{bom}{text}"),
        before: original,
    };
    Some((file, kept))
}

fn overlaps(edit: &TextEdit, other: &TextEdit) -> bool {
    (edit.line, edit.column) < (other.end_line, other.end_column)
        && (other.line, other.column) < (edit.end_line, edit.end_column)
}

/// Whether `after` is `before` with exactly one string `old` replaced by
/// `new`. `old` and `new` are the text as written: a plain scalar written over
/// several lines reads back with its line breaks folded into spaces.
fn only_change(before: Option<&Node>, after: Option<&Node>, old: &str, new: &str) -> bool {
    let old = [old.to_owned(), folded(old)];
    let new = [new.to_owned(), folded(new)];
    changed_scalars(before, after, &old, &new) == Some(1)
}

fn folded(text: &str) -> String {
    text.split('\n')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

/// How many strings changed from `old` to `new`; `None` on any other
/// difference.
fn changed_scalars(
    before: Option<&Node>,
    after: Option<&Node>,
    old: &[String; 2],
    new: &[String; 2],
) -> Option<usize> {
    let (before, after) = match (before, after) {
        (None, None) => return Some(0),
        (Some(before), Some(after)) => (before, after),
        _ => return None,
    };
    match (&before.value, &after.value) {
        (Value::Map(a), Value::Map(b)) => {
            if a.len() != b.len() || a.iter().zip(b).any(|(x, y)| x.key.value != y.key.value) {
                return None;
            }
            a.iter().zip(b).try_fold(0, |total, (x, y)| {
                Some(total + changed_scalars(Some(&x.value), Some(&y.value), old, new)?)
            })
        }
        (Value::Seq(a), Value::Seq(b)) => {
            if a.len() != b.len() {
                return None;
            }
            a.iter().zip(b).try_fold(0, |total, (x, y)| {
                Some(total + changed_scalars(Some(x), Some(y), old, new)?)
            })
        }
        (a, b) if a == b => Some(0),
        (Value::Str(a), Value::Str(b)) if old.contains(a) && new.contains(b) => Some(1),
        _ => None,
    }
}

/// `Fixed 3 values in 2 files`, `Would fix 1 value in 1 file`, `No safe fix
/// to apply`; `unwritten` counts the fixes whose file could not be written
/// (`validation.py` `fix_phrase`).
pub fn fix_phrase(count: usize, files: usize, dry_run: bool, unwritten: usize) -> String {
    let failed = if unwritten == 1 {
        format!("could not write {unwritten} fix")
    } else {
        format!("could not write {unwritten} fixes")
    };
    if count == 0 {
        if unwritten > 0 {
            let mut chars = failed.chars();
            return chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + chars.as_str()
            });
        }
        return "No safe fix to apply".to_owned();
    }
    let verb = if dry_run { "Would fix" } else { "Fixed" };
    let done = format!(
        "{verb} {} in {}",
        plural(count, "value"),
        plural(files, "file")
    );
    if unwritten > 0 {
        format!("{done} · {failed}")
    } else {
        done
    }
}

/// `1 value`, `2 values`.
pub fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Fix;
    use crate::fs::MemoryFs;

    fn edit(line: usize, column: usize, end_column: usize, replacement: &str) -> TextEdit {
        TextEdit {
            line,
            column,
            end_line: line,
            end_column,
            replacement: replacement.to_owned(),
        }
    }

    fn finding(file: &str, safe: bool, edits: Vec<TextEdit>) -> Diagnostic {
        let mut diagnostic = Diagnostic::error("vocab_unknown", "m").file(file);
        diagnostic.path = Some(file.trim_start_matches("/w/").to_owned());
        diagnostic.fix = Some(Fix { safe, edits });
        diagnostic
    }

    #[test]
    fn lines_split_where_yaml_breaks_them() {
        assert_eq!(
            split_keeping_breaks("a\r\nb\rc\nd"),
            ["a\r\n", "b\r", "c\n", "d"]
        );
        assert!(split_keeping_breaks("").is_empty());
        // U+2028 and U+0085 stay inside a line, as YAML keeps them.
        assert_eq!(
            split_keeping_breaks("a\u{2028}b\u{85}\n"),
            ["a\u{2028}b\u{85}\n"]
        );
    }

    #[test]
    fn an_edit_replaces_its_span_by_code_points_and_keeps_crlf() {
        let text = "é: high\r\nb: x\r\n";
        let (updated, before) = apply(text, &edit(1, 4, 8, "High")).unwrap();
        assert_eq!(before, "high");
        assert_eq!(updated, "é: High\r\nb: x\r\n");
        // At the end of a line, and past it.
        assert_eq!(apply("a: b", &edit(1, 4, 5, "c")).unwrap().0, "a: c");
        assert!(apply("a: b", &edit(1, 4, 7, "c")).is_none());
        assert!(apply("a: b", &edit(2, 1, 2, "c")).is_none());
        assert!(apply("a: b", &edit(1, 3, 3, "c")).is_none());
        assert!(apply("a: b", &edit(1, 0, 2, "c")).is_none());
        // Across lines.
        let across = TextEdit {
            line: 1,
            column: 4,
            end_line: 2,
            end_column: 3,
            replacement: "z".to_owned(),
        };
        assert_eq!(
            apply("a: b\nc d\n", &across).unwrap(),
            ("a: zd\n".to_owned(), "b\nc ".to_owned())
        );
    }

    #[test]
    fn a_safe_fix_is_planned_and_an_unsafe_one_is_not() {
        let fs = MemoryFs::new();
        fs.write("/w/r.yaml", "tlp: AMBER\nseverity: high # keep\n");
        let findings = [
            finding("/w/r.yaml", true, vec![edit(2, 11, 15, "High")]),
            finding("/w/r.yaml", false, vec![edit(1, 6, 11, "amber")]),
        ];
        let plan = plan(&fs, &findings);
        assert_eq!(plan.changes.len(), 1);
        assert_eq!(plan.changes[0].before, "high");
        assert_eq!(plan.changes[0].after, "High");
        assert_eq!(
            plan.files[Path::new("/w/r.yaml")].after,
            "tlp: AMBER\nseverity: High # keep\n"
        );
        assert_eq!(
            serde_json::to_string(&plan.changes[0]).unwrap(),
            r#"{"path":"r.yaml","line":2,"code":"vocab_unknown","before":"high","after":"High"}"#
        );
    }

    #[test]
    fn edits_apply_right_to_left_once_and_never_overlap() {
        let fs = MemoryFs::new();
        fs.write("/w/r.yaml", "a: [high, low]\n");
        let high = edit(1, 5, 9, "High");
        let findings = [
            finding("/w/r.yaml", true, vec![high.clone()]),
            finding("/w/r.yaml", true, vec![high]),
            finding("/w/r.yaml", true, vec![edit(1, 11, 14, "Low")]),
            // Overlaps the `low` edit, which applies first (right to left).
            finding("/w/r.yaml", true, vec![edit(1, 12, 14, "OW")]),
        ];
        let plan = plan(&fs, &findings);
        assert_eq!(plan.files[Path::new("/w/r.yaml")].after, "a: [High, Low]\n");
        assert_eq!(plan.changes.len(), 2);
        assert_eq!(plan.changes[0].column, 5);
    }

    #[test]
    fn a_value_saved_since_the_finding_is_not_overwritten() {
        let fs = MemoryFs::new();
        // The finding was made on `high`; the file now holds `medium`.
        fs.write("/w/r.yaml", "severity: medium\n");
        let plan = plan(
            &fs,
            &[finding("/w/r.yaml", true, vec![edit(1, 11, 15, "High")])],
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn an_edit_that_breaks_the_yaml_or_changes_more_is_left_out() {
        let fs = MemoryFs::new();
        fs.write("/w/a.yaml", "a: x_y\n");
        // `x_y` and `x: y` fold the same, but the result is a mapping.
        let plan_a = plan(
            &fs,
            &[finding("/w/a.yaml", true, vec![edit(1, 4, 7, "x: y")])],
        );
        assert!(plan_a.is_empty());
        fs.write("/w/b.yaml", "a: x-y\n");
        let plan_b = plan(
            &fs,
            &[finding("/w/b.yaml", true, vec![edit(1, 4, 7, "[x y")])],
        );
        assert!(plan_b.is_empty());
    }

    #[test]
    fn the_diff_is_unified_with_three_lines_of_context() {
        let before = "a\nb\nc\nd\nseverity: high\ne\nf\ng\nh\n";
        let after = before.replace("high", "High");
        assert_eq!(
            unified_diff("r.yaml", before, &after),
            "--- a/r.yaml\n+++ b/r.yaml\n@@ -2,7 +2,7 @@\n b\n c\n d\n-severity: high\n+severity: High\n e\n f\n g\n"
        );
        assert_eq!(unified_diff("r.yaml", before, before), "");
    }

    #[test]
    fn the_diff_marks_a_missing_last_line_break() {
        assert_eq!(
            unified_diff("r.yaml", "a: high", "a: High"),
            "--- a/r.yaml\n+++ b/r.yaml\n@@ -1 +1 @@\n-a: high\n\\ No newline at end of file\n+a: High\n\\ No newline at end of file\n"
        );
        // An unchanged last line without its break is context.
        assert_eq!(
            unified_diff("r.yaml", "a: high\nb: c", "a: High\nb: c"),
            "--- a/r.yaml\n+++ b/r.yaml\n@@ -1,2 +1,2 @@\n-a: high\n+a: High\n b: c\n\\ No newline at end of file\n"
        );
        // A lone CR ends a line.
        assert_eq!(
            unified_diff("r.yaml", "a: high\rb: c\r", "a: High\rb: c\r"),
            "--- a/r.yaml\n+++ b/r.yaml\n@@ -1,2 +1,2 @@\n-a: high\r+a: High\r b: c\r"
        );
    }

    #[test]
    fn a_byte_order_mark_is_kept_and_not_counted() {
        let fs = MemoryFs::new();
        fs.write("/w/r.yaml", "\u{feff}severity: high\n");
        let plan = plan(
            &fs,
            &[finding("/w/r.yaml", true, vec![edit(1, 11, 15, "High")])],
        );
        assert_eq!(
            plan.files[Path::new("/w/r.yaml")].after,
            "\u{feff}severity: High\n"
        );
    }

    #[test]
    fn a_file_that_changed_after_it_was_read_is_not_written() {
        let fs = MemoryFs::new();
        fs.write("/w/a.yaml", "severity: high\n");
        fs.write("/w/b.yaml", "severity: low\n");
        let findings = [
            finding("/w/a.yaml", true, vec![edit(1, 11, 15, "High")]),
            finding("/w/b.yaml", true, vec![edit(1, 11, 14, "Low")]),
        ];
        let plan = plan(&fs, &findings);
        assert_eq!(plan.file_count(), 2);
        // Saved by someone else between the plan and the write.
        fs.write("/w/b.yaml", "severity: lowest\n");
        let (written, failed) = plan.write(&fs);
        assert_eq!(written.changes.len(), 1);
        assert_eq!(written.changes[0].path, "a.yaml");
        assert_eq!(
            failed,
            ["b.yaml: it changed since it was read; run opentide validate --fix again"]
        );
        assert_eq!(
            fs.read(Path::new("/w/a.yaml")).unwrap(),
            b"severity: High\n"
        );
        assert_eq!(
            fs.read(Path::new("/w/b.yaml")).unwrap(),
            b"severity: lowest\n"
        );
        assert_eq!(
            fix_phrase(written.changes.len(), written.file_count(), false, 1),
            "Fixed 1 value in 1 file · could not write 1 fix"
        );
    }

    #[test]
    fn the_phrase_counts_values_files_and_failures() {
        assert_eq!(fix_phrase(0, 0, false, 0), "No safe fix to apply");
        assert_eq!(fix_phrase(0, 0, false, 2), "Could not write 2 fixes");
        assert_eq!(fix_phrase(3, 2, false, 0), "Fixed 3 values in 2 files");
        assert_eq!(fix_phrase(1, 1, true, 0), "Would fix 1 value in 1 file");
    }
}
