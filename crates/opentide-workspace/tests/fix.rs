//! `validate --fix` (UC-2.3, #818): applying any set of fixes never changes
//! a byte outside the fix spans, and the result parses; a file that changed
//! after it was read is not written; the fixes run through `validate`.

use std::path::Path;

use opentide_schema::node;
use opentide_workspace::fix::{self, FixPlan};
use opentide_workspace::validate::annotate::is_safe_replacement;
use opentide_workspace::{Diagnostic, FileSystem as _, Fix, MemoryFs, TextEdit};
use proptest::prelude::*;

const WORDS: [&str; 8] = [
    "amber", "Amber", "AMBER", "red-team", "red_team", "Red Team", "T1059", "t1059",
];

/// One `key: value` line: the key, the value, how it is quoted, the comment
/// after it, the line break.
#[derive(Debug, Clone)]
struct Line {
    value: usize,
    quote: usize,
    comment: bool,
    crlf: bool,
    indent: bool,
}

fn line() -> impl Strategy<Value = Line> {
    (
        0..WORDS.len(),
        0..3usize,
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(value, quote, comment, crlf, indent)| Line {
            value,
            quote,
            comment,
            crlf,
            indent,
        })
}

/// The proposed fixes: the line, the word it replaces the value with, and
/// how its span is placed (on the value, or shifted off it).
fn proposals() -> impl Strategy<Value = Vec<(usize, usize, i8, bool)>> {
    prop::collection::vec((0..40usize, 0..WORDS.len(), -2i8..3, any::<bool>()), 0..30)
}

/// The file, and where each line's value starts and ends (1-based columns).
fn render(lines: &[Line]) -> (String, Vec<(usize, usize, usize)>) {
    let mut text = String::from("name: x\nlist:\n");
    let mut places = vec![(0, 0, 0); lines.len()];
    // The list's items first, then the keys, so the file is one mapping.
    let mut order: Vec<usize> = (0..lines.len()).collect();
    order.sort_by_key(|&index| !lines[index].indent);
    for (row, index) in order.into_iter().enumerate() {
        let line = &lines[index];
        let lead = if line.indent { "  - " } else { "" };
        let key = if line.indent {
            String::new()
        } else {
            format!("k{index}: ")
        };
        let word = WORDS[line.value];
        let (open, close) = [("", ""), ("'", "'"), ("\"", "\"")][line.quote];
        let before = format!("{lead}{key}{open}");
        let column = before.chars().count() + 1;
        places[index] = (row + 3, column, column + word.chars().count());
        text.push_str(&before);
        text.push_str(word);
        text.push_str(close);
        if line.comment {
            text.push_str("  # keep: me");
        } else if line.value.is_multiple_of(2) {
            // Trailing blanks, which the parser ignores: only a byte
            // comparison sees them go.
            text.push_str(" \t ");
        }
        text.push_str(if line.crlf { "\r\n" } else { "\n" });
    }
    (text, places)
}

/// `text` with the byte ranges of `spans` cut out.
fn outside(text: &str, spans: &[(usize, usize)]) -> String {
    let mut spans = spans.to_vec();
    spans.sort_unstable();
    let mut out = String::new();
    let mut at = 0;
    for (start, end) in spans {
        out.push_str(&text[at..start]);
        out.push('\u{0}');
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

/// The byte offset of 1-based `line`, `column` in `text` (lines broken at
/// `\n`; the generated files hold no lone `\r`).
fn byte_at(text: &str, line: usize, column: usize) -> usize {
    let start: usize = text
        .split_inclusive('\n')
        .take(line - 1)
        .map(str::len)
        .sum();
    text[start..]
        .char_indices()
        .nth(column - 1)
        .map_or(text.len(), |(offset, _)| start + offset)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn fixes_change_no_byte_outside_their_spans_and_the_result_parses(
        lines in prop::collection::vec(line(), 1..30),
        proposals in proposals(),
    ) {
        let (text, places) = render(&lines);
        prop_assert!(node::load(&text).is_ok(), "{}", text);
        let fs = MemoryFs::new();
        fs.write("/w/objects/rules/r.yaml", text.clone());
        let diagnostics: Vec<Diagnostic> = proposals
            .iter()
            .map(|&(target, word, shift, safe)| {
                let (line, column, end_column) = places[target % places.len()];
                let column = column.checked_add_signed(isize::from(shift)).unwrap_or(1).max(1);
                let end_column = end_column.checked_add_signed(isize::from(shift)).unwrap_or(1).max(1);
                let mut diagnostic = Diagnostic::error("vocab_unknown", "m").file("/w/objects/rules/r.yaml");
                diagnostic.path = Some("objects/rules/r.yaml".to_owned());
                diagnostic.fix = Some(Fix {
                    safe,
                    edits: vec![TextEdit {
                        line,
                        column,
                        end_line: line,
                        end_column,
                        replacement: WORDS[word].to_owned(),
                    }],
                });
                diagnostic
            })
            .collect();
        let plan = fix::plan(&fs, &diagnostics);
        let (written, failed) = plan.write(&fs);
        prop_assert!(failed.is_empty());
        let after = String::from_utf8(fs.read(Path::new("/w/objects/rules/r.yaml")).unwrap()).unwrap();
        // It parses.
        prop_assert!(node::load(&after).is_ok());
        // Each kept change is a safe replacement of the value it found.
        for change in &written.changes {
            prop_assert!(is_safe_replacement(&change.code, &change.before, &change.after));
        }
        // Every byte outside the spans is the same: cut each kept span out of
        // the text before and after, and what is left is equal.
        let mut before_spans = Vec::new();
        let mut after_spans = Vec::new();
        let (mut added, mut removed) = (0usize, 0usize);
        let mut changes = written.changes.clone();
        changes.sort_by_key(|change| (change.line, change.column));
        for change in &changes {
            let start = byte_at(&text, change.line, change.column);
            before_spans.push((start, start + change.before.len()));
            prop_assert_eq!(&text[start..start + change.before.len()], change.before.as_str());
            let new_start = start + added - removed;
            after_spans.push((new_start, new_start + change.after.len()));
            prop_assert_eq!(&after[new_start..new_start + change.after.len()], change.after.as_str());
            added += change.after.len();
            removed += change.before.len();
        }
        prop_assert_eq!(outside(&text, &before_spans), outside(&after, &after_spans));
        // Nothing changed means the file was not written.
        if written.changes.is_empty() {
            prop_assert_eq!(&after, &text);
            prop_assert!(plan.files.is_empty());
        }
    }
}

#[test]
fn a_fix_is_not_written_when_the_file_changed_after_it_was_read() {
    let fs = MemoryFs::new();
    fs.write("/w/r.yaml", "severity: high\n");
    let mut diagnostic = Diagnostic::error("vocab_unknown", "m").file("/w/r.yaml");
    diagnostic.path = Some("r.yaml".to_owned());
    diagnostic.fix = Some(Fix {
        safe: true,
        edits: vec![TextEdit {
            line: 1,
            column: 11,
            end_line: 1,
            end_column: 15,
            replacement: "High".to_owned(),
        }],
    });
    let plan: FixPlan = fix::plan(&fs, [&diagnostic]);
    assert_eq!(plan.changes.len(), 1);
    // Saved again, with the same typo and a comment, after the plan read it.
    fs.write("/w/r.yaml", "severity: high # mine\n");
    let (written, failed) = plan.write(&fs);
    assert!(written.is_empty());
    assert_eq!(
        failed,
        ["r.yaml: it changed since it was read; run opentide validate --fix again"]
    );
    assert_eq!(
        fs.read(Path::new("/w/r.yaml")).unwrap(),
        b"severity: high # mine\n"
    );
}
