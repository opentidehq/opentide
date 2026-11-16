//! The pure-Rust engine against the tree-sitter implementation it replaces
//! (`tests/legacy`, verbatim), on `opentide_parse::differential`, over every
//! Lucene query in the repository's corpora, generated valid queries, every
//! prefix, seeded token mutations and random sentences.
//!
//! Surfaces: the tree's outline (named nodes, kind and the range from the
//! first to the last token), the diagnostics and highlight tokens in each
//! dialect (Elastic, Carbon Black, Graylog), the ECS diagnostics, the
//! fields, and hover and completions in each dialect at sampled offsets.
//! Gates: a query tree-sitter parses without an error gives identical
//! surfaces; a broken one stays broken. `OPENTIDE_LUCENE_SEED=<n>` picks
//! another seed (default 1), `OPENTIDE_LUCENE_DIFF=<file>` writes the JSON
//! report.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

#[allow(
    dead_code,
    unused_imports,
    reason = "a verbatim copy of the old crate; not every item is compared"
)]
mod legacy;
mod support;

use opentide_core::{CompletionItem, Diagnostic, LanguageId};
use opentide_highlight::HighlightToken;
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

fn show(d: &[Diagnostic]) -> String {
    d.iter().fold(String::new(), |mut out, d| {
        let _ = writeln!(
            out,
            "{}|{:?}|{}:{}-{}:{}|{}|{:?}",
            d.code,
            d.severity,
            d.range.start.line,
            d.range.start.character,
            d.range.end.line,
            d.range.end.character,
            d.message,
            d.suggestion
        );
        out
    })
}

fn tokens(t: &[HighlightToken]) -> String {
    t.iter().fold(String::new(), |mut out, t| {
        let _ = write!(out, "{}..{}={} ", t.span.start, t.span.end, t.capture);
        out
    })
}

fn completions(c: &[CompletionItem]) -> String {
    format!("{c:?}")
}

const DIALECTS: [(&str, opentide_lucene::Dialect, legacy::Dialect); 3] = [
    (
        "elastic",
        opentide_lucene::Dialect::Elastic,
        legacy::Dialect::Elastic,
    ),
    (
        "carbon_black",
        opentide_lucene::Dialect::CarbonBlack,
        legacy::Dialect::CarbonBlack,
    ),
    (
        "graylog",
        opentide_lucene::Dialect::Graylog,
        legacy::Dialect::Graylog,
    ),
];

/// tree-sitter's named nodes in pre-order, and whether the tree is clean.
fn old_outline(input: &str) -> (String, bool) {
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
    (out, !tree.root_node().has_error())
}

/// The tree-sitter engine.
struct Old;

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        let (outline, clean) = old_outline(input);
        let mut out = vec![
            ("outline".to_owned(), outline),
            ("clean".to_owned(), clean.to_string()),
            // Carbon Black deploy joins the lines: a query clean as written
            // can break once joined, and is then broken input there.
            (
                "clean/carbon_black".to_owned(),
                old_outline(&joined(input)).1.to_string(),
            ),
            ("ecs".to_owned(), show(&legacy::ecs_diagnostics(input))),
            ("fields".to_owned(), format!("{:?}", legacy::fields(input))),
        ];
        for (name, _, dialect) in DIALECTS {
            let r = legacy::analyze_dialect(input, dialect);
            out.push((format!("diagnostics/{name}"), show(&r.diagnostics)));
            out.push((format!("highlight/{name}"), tokens(&r.tokens)));
        }
        out
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        let mut out = Vec::new();
        for (name, _, dialect) in DIALECTS {
            out.push((
                format!("hover/{name}"),
                format!("{:?}", legacy::hover_dialect(input, offset, dialect)),
            ));
            out.push((
                format!("completions/{name}"),
                completions(&legacy::completions_dialect(input, offset, dialect)),
            ));
        }
        out
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
        let mut out = vec![
            ("outline".to_owned(), outline),
            ("clean".to_owned(), clean.to_string()),
            (
                "clean/carbon_black".to_owned(),
                self::outline(&opentide_lucene::debug_parse(&joined(input)))
                    .1
                    .to_string(),
            ),
            (
                "ecs".to_owned(),
                show(&opentide_lucene::ecs_diagnostics(input)),
            ),
            (
                "fields".to_owned(),
                format!("{:?}", opentide_lucene::fields(input)),
            ),
        ];
        for (name, dialect, _) in DIALECTS {
            let r = opentide_lucene::analyze_dialect(input, dialect);
            out.push((format!("diagnostics/{name}"), show(&r.diagnostics)));
            out.push((format!("highlight/{name}"), tokens(&r.tokens)));
        }
        out
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        let mut out = Vec::new();
        for (name, dialect, _) in DIALECTS {
            out.push((
                format!("hover/{name}"),
                format!(
                    "{:?}",
                    opentide_lucene::hover_dialect(input, offset, dialect)
                ),
            ));
            out.push((
                format!("completions/{name}"),
                completions(&opentide_lucene::completions_dialect(
                    input, offset, dialect,
                )),
            ));
        }
        out
    }
}

/// The text Carbon Black deploys: the lines joined with spaces.
fn joined(input: &str) -> String {
    input.replace(['\n', '\r'], " ")
}

/// Valid: tree-sitter parses the query cleanly as written and as Carbon
/// Black joins it.
fn verdict(surfaces: &Surfaces) -> bool {
    ["clean", "clean/carbon_black"]
        .iter()
        .all(|name| surfaces.iter().any(|(n, v)| n == name && v == "true"))
}

#[test]
fn pure_rust_engine_matches_tree_sitter() {
    let files = sources();
    // `OPENTIDE_DIFF_SCALE=full`: 40 mutations a file, 3,000 sentences, 40
    // prefixes and 32 offsets, run before every push. The default is a sample
    // that keeps CI well under its 300 s test limit. `OPENTIDE_DIFF_SEEDS=1,2,3`
    // runs several seeds (default 1).
    let full = std::env::var("OPENTIDE_DIFF_SCALE").is_ok_and(|s| s == "full");
    let seeds: Vec<u64> = std::env::var("OPENTIDE_DIFF_SEEDS")
        .or_else(|_| std::env::var("OPENTIDE_LUCENE_SEED"))
        .map_or_else(
            |_| vec![1],
            |s| s.split(',').filter_map(|n| n.trim().parse().ok()).collect(),
        );
    for seed in seeds {
        let mut config = Config::new(&verdict, &token_ranges, SAMPLES);
        config.seed = seed;
        if full {
            config.sentences = 3_000;
            config.mutations_per_input = 40;
            config.max_prefixes = 40;
            config.max_offsets = 32;
        } else {
            config.sentences = 200;
            config.mutations_per_input = 2;
            config.max_prefixes = 4;
            config.max_offsets = 4;
        }
        let report = run(&Old, &New, &files, &config);
        eprintln!(
            "seed {seed}, scale {}",
            if full { "full" } else { "sample" }
        );
        eprintln!(
            "lucene differential: {} inputs, {} valid; valid differences {}, verdict changes {}, broken-input differences {}",
            report.inputs,
            report.valid,
            report.total(opentide_parse::differential::Class::Valid),
            report.total(opentide_parse::differential::Class::Verdict),
            report.total(opentide_parse::differential::Class::Broken),
        );
        if let Ok(path) = std::env::var("OPENTIDE_LUCENE_DIFF") {
            std::fs::write(format!("{path}.{seed}"), report.to_json_string())
                .expect("the report file");
        }
        assert_gates(&report);
    }
}
