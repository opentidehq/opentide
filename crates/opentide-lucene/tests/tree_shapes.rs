//! The pure-Rust parser's trees against tree-sitter's, on
//! `opentide_parse::differential`, over every Lucene query in the
//! repository's corpora, every prefix, seeded token mutations and random
//! sentences.
//!
//! The surface is the outline of the named nodes (kind and the range from
//! the first to the last token, trivia excluded). Gates: a query
//! tree-sitter parses without an error gives the identical outline and the
//! new parser reports no error; a broken one stays broken. A temporary
//! check: the analysis differential takes its place when production
//! switches. `OPENTIDE_LUCENE_SEED=<n>` picks another seed (default 1).

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod support;

use opentide_core::LanguageId;
use opentide_parse::differential::{Config, Engine, Surfaces, assert_gates, run};
use std::fmt::Write as _;
use support::{SAMPLES, sources, token_ranges};

/// Kinds that are not named nodes of the tree-sitter grammar.
const ANONYMOUS: &[&str] = &[
    "Whitespace",
    "ErrorToken",
    "Eof",
    "AndKw",
    "OrKw",
    "NotKw",
    "AmpAmp",
    "PipePipe",
    "Bang",
    "Plus",
    "Minus",
    "Colon",
    "LParen",
    "RParen",
    "LBracket",
    "RBracket",
    "LBrace",
    "RBrace",
    "ToKw",
    "Error",
];

fn snake(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// tree-sitter's named nodes in pre-order, and whether the tree is clean.
struct Old;

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        let tree = opentide_syntax::parse(LanguageId::Lucene, input).expect("a tree");
        let mut cursor = tree.walk();
        let mut out = String::new();
        'walk: loop {
            let node = cursor.node();
            if node.is_named() && !node.is_error() {
                let _ = writeln!(
                    out,
                    "{}@{}..{}",
                    node.kind(),
                    node.start_byte(),
                    node.end_byte()
                );
            }
            if cursor.goto_first_child() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    break 'walk;
                }
            }
        }
        vec![
            ("outline".to_owned(), out),
            (
                "clean".to_owned(),
                (!tree.root_node().has_error()).to_string(),
            ),
        ]
    }
}

/// The new tree's named nodes, from its debug rendering: `Kind@start..end`
/// lines, a token's text after; a node's range is trimmed to its first and
/// last token that is not whitespace.
struct New;

fn outline(debug: &str) -> (String, bool) {
    struct Open {
        indent: usize,
        slot: usize,
        first: Option<usize>,
        last: usize,
        root: bool,
    }
    let mut lines: Vec<(String, Option<(usize, usize)>)> = Vec::new();
    let mut stack: Vec<Open> = Vec::new();
    let mut clean = true;
    let close =
        |stack: &mut Vec<Open>, lines: &mut Vec<(String, Option<(usize, usize)>)>, to: usize| {
            while stack.last().is_some_and(|o| o.indent >= to) {
                let o = stack.pop().expect("an open node");
                let span = o.first.map(|f| (f, o.last));
                if o.root {
                    // tree-sitter's root starts at the first token and runs to
                    // the end of the text, trailing trivia included.
                    lines[o.slot].1 = Some((
                        span.map_or(lines[o.slot].1.map_or(0, |r| r.1), |s| s.0),
                        lines[o.slot].1.map_or(0, |r| r.1),
                    ));
                } else {
                    lines[o.slot].1 = span;
                }
                if let (Some(parent), Some((f, l))) = (stack.last_mut(), span) {
                    parent.first = Some(parent.first.map_or(f, |p| p.min(f)));
                    parent.last = parent.last.max(l);
                }
            }
        };
    for line in debug.lines() {
        let Some((head, rest)) = line.trim_start().split_once('@') else {
            // An error line: the tree is not clean.
            clean = false;
            continue;
        };
        let indent = line.len() - line.trim_start().len();
        close(&mut stack, &mut lines, indent);
        let (range, text) = rest
            .split_once(' ')
            .map_or((rest, None), |(r, t)| (r, Some(t)));
        let (s, e) = range.split_once("..").expect("a range");
        let (s, e): (usize, usize) = (s.parse().expect("start"), e.parse().expect("end"));
        if head == "Error" {
            clean = false;
        }
        if head == "SourceFile" {
            // tree-sitter's root spans the whole text, trivia included.
            lines.push((snake(head), Some((s, e))));
            stack.push(Open {
                indent,
                slot: lines.len() - 1,
                first: None,
                last: 0,
                root: true,
            });
            continue;
        }
        let named = !ANONYMOUS.contains(&head);
        let slot = lines.len();
        lines.push((if named { snake(head) } else { String::new() }, None));
        if text.is_some() {
            // A token: it trims its parents unless it is whitespace.
            if head != "Whitespace" {
                if named {
                    lines[slot].1 = Some((s, e));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.first = Some(parent.first.map_or(s, |p| p.min(s)));
                    parent.last = parent.last.max(e);
                }
            }
        } else {
            stack.push(Open {
                indent,
                slot,
                first: None,
                last: 0,
                root: false,
            });
        }
    }
    close(&mut stack, &mut lines, 0);
    let mut out = String::new();
    for (name, span) in &lines {
        if let (false, Some((s, e))) = (name.is_empty(), span) {
            let _ = writeln!(out, "{name}@{s}..{e}");
        }
    }
    (out, clean)
}

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        let (outline, clean) = outline(&opentide_lucene::debug_parse(input));
        vec![
            ("outline".to_owned(), outline),
            ("clean".to_owned(), clean.to_string()),
        ]
    }
}

fn verdict(surfaces: &Surfaces) -> bool {
    surfaces.iter().any(|(n, v)| n == "clean" && v == "true")
}

#[test]
fn trees_match_tree_sitter() {
    let files = sources();
    let mut config = Config::new(&verdict, &token_ranges, SAMPLES);
    config.sentences = 3_000;
    config.mutations_per_input = 20;
    config.max_prefixes = 40;
    if let Some(seed) = std::env::var("OPENTIDE_LUCENE_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        config.seed = seed;
    }
    let report = run(&Old, &New, &files, &config);
    eprintln!(
        "lucene tree differential: {} inputs, {} valid; valid differences {}, verdict changes {}, broken-input differences {}",
        report.inputs,
        report.valid,
        report.total(opentide_parse::differential::Class::Valid),
        report.total(opentide_parse::differential::Class::Verdict),
        report.total(opentide_parse::differential::Class::Broken),
    );
    if let Ok(path) = std::env::var("OPENTIDE_LUCENE_DIFF") {
        std::fs::write(path, report.to_json_string()).expect("the report file");
    }
    assert_gates(&report);
}
