//! The pure-Rust engine against the tree-sitter implementation it replaces
//! (`tests/legacy`, verbatim), on `opentide_parse::differential`: every CQL
//! file of `crates/testdata`, the string literals of the old tests, valid
//! queries made by joining valid corpus queries with a pipe, every prefix,
//! seeded word mutations and random sentences.
//!
//! Gates: a query tree-sitter parses without an error gives identical
//! diagnostics (as a hunt and as a correlation rule), highlight tokens, hover
//! and completions (at sampled offsets); a broken one keeps its verdict.
//! The default is a sample sized for CI (seed 1). `OPENTIDE_DIFF_SCALE=full`
//! runs 40 mutations a file, 2,000 sentences, 24 prefixes and 12 offsets (about
//! 6 minutes a seed in a debug build), before a push that changes the engine;
//! `OPENTIDE_DIFF_SEEDS=1,2,3` (or `OPENTIDE_CQL_SEEDS`) picks the seeds.
//! `OPENTIDE_CQL_DIFF=<file>` writes the JSON report of each seed to `<file>.<seed>`.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

#[allow(
    dead_code,
    unused_imports,
    clippy::trivially_copy_pass_by_ref,
    clippy::too_many_lines,
    reason = "a verbatim copy of the old crate (its public items were not linted so); not every item is compared"
)]
mod legacy;

use opentide_core::{Diagnostic, codes};
use opentide_parse::differential::{Class, Config, Engine, Source, Surfaces, assert_gates, run};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// Valid inputs the sample must reach: the corpus, the old tests' literals and the joined
/// pairs are valid at any scale.
const VALID_SAMPLE_FLOOR: usize = 1_000;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.cql` file under `dir`, sorted.
fn cql_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "cql") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The query of a corpus file: the `# prod:<rule>` tag on its first line is not part of it.
fn query(file: &str) -> &str {
    match file.split_once('\n') {
        Some((tag, rest)) if tag.starts_with("# prod:") => rest,
        _ => file,
    }
}

/// Rust string literals (`"..."`) of a source file, with `\"`, `\\`, `\n`, `\t`
/// and `\u{...}` read.
fn rust_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut s = String::new();
        while let Some(c) = chars.next() {
            match c {
                '"' => break,
                '\\' => match chars.next() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('u') => {
                        let hex: String =
                            chars.by_ref().skip(1).take_while(|&c| c != '}').collect();
                        if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                        {
                            s.push(c);
                        }
                    }
                    // A line continuation: the newline and the indent after it.
                    Some('\n') => {
                        while chars.peek().is_some_and(|c| c.is_whitespace()) {
                            chars.next();
                        }
                    }
                    Some(other) => s.push(other),
                    None => {}
                },
                c => s.push(c),
            }
        }
        if !s.is_empty() && s.len() < 400 {
            out.push(s);
        }
    }
    out
}

/// Every input the run starts from.
fn sources() -> Vec<Source> {
    let root = repo();
    let mut texts: BTreeSet<(String, String)> = BTreeSet::new();
    let testdata = root.join("crates/testdata");
    let mut valid = Vec::new();
    for path in cql_files(&testdata) {
        let file = std::fs::read_to_string(&path).expect("a CQL file");
        let name = path
            .strip_prefix(&testdata)
            .map_or_else(|_| String::new(), |p| p.to_string_lossy().into_owned());
        let q = query(&file).to_owned();
        if !legacy_fails(&q) {
            valid.push(q.clone());
        }
        texts.insert((name, q));
    }
    // Generated valid queries: two valid queries joined by a pipe, each with the next.
    for pair in valid.windows(2) {
        texts.insert((
            "generated/pipe".to_owned(),
            format!("{} | {}", pair[0].trim_end(), pair[1]),
        ));
    }
    // String literals of the old crate's tests (verbatim) and the analysis tests.
    for file in [
        "crates/opentide-cql/src/tests.rs",
        "crates/opentide-cql/tests/parser_trees.rs",
        "crates/opentide-analysis/tests/external_cql.rs",
        "crates/opentide-analysis/tests/goldens.rs",
    ] {
        let text = std::fs::read_to_string(root.join(file)).expect("a source file");
        for s in rust_strings(&text) {
            texts.insert((file.to_owned(), s));
        }
    }
    texts
        .into_iter()
        .map(|(name, text)| Source { name, text })
        .collect()
}

fn legacy_fails(source: &str) -> bool {
    legacy::analyze(source)
        .diagnostics
        .iter()
        .any(|d| d.code == codes::CQL_PARSE_ERROR)
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

fn tokens(t: &[opentide_highlight::HighlightToken]) -> String {
    t.iter().fold(String::new(), |mut out, t| {
        let _ = write!(out, "{}..{}={} ", t.span.start, t.span.end, t.capture);
        out
    })
}

/// The tree-sitter engine.
struct Old;

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        let r = legacy::analyze(input);
        let rule = legacy::analyze_with(input, &legacy::Context::CORRELATION_RULE);
        vec![
            ("diagnostics".to_owned(), show(&r.diagnostics)),
            ("rule".to_owned(), show(&rule.diagnostics)),
            ("highlight".to_owned(), tokens(&r.tokens)),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![
            (
                "hover".to_owned(),
                format!("{:?}", legacy::assist::hover(input, offset)),
            ),
            (
                "completions".to_owned(),
                format!("{:?}", legacy::assist::completions(input, offset)),
            ),
            (
                "signature".to_owned(),
                format!("{:?}", legacy::assist::signature_help(input, offset)),
            ),
        ]
    }
}

/// The pure-Rust engine, through the crate's public functions.
struct New;

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        let r = opentide_cql::analyze(input);
        let rule = opentide_cql::analyze_with(input, &opentide_cql::Context::CORRELATION_RULE);
        vec![
            ("diagnostics".to_owned(), show(&r.diagnostics)),
            ("rule".to_owned(), show(&rule.diagnostics)),
            ("highlight".to_owned(), tokens(&r.tokens)),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![
            (
                "hover".to_owned(),
                format!("{:?}", opentide_cql::hover(input, offset)),
            ),
            (
                "completions".to_owned(),
                format!("{:?}", opentide_cql::completions(input, offset)),
            ),
            (
                "signature".to_owned(),
                format!("{:?}", opentide_cql::signature_help(input, offset)),
            ),
        ]
    }
}

/// Valid: tree-sitter found no syntax error.
fn verdict(surfaces: &Surfaces) -> bool {
    let parse = format!("{}|", codes::CQL_PARSE_ERROR);
    surfaces
        .iter()
        .find(|(name, _)| name == "diagnostics")
        .is_none_or(|(_, text)| !text.lines().any(|l| l.starts_with(&parse)))
}

/// Word ranges: runs of characters that are not whitespace or CQL punctuation, or
/// one punctuation character (what a reader sees as a unit; the mutations delete,
/// swap and duplicate them).
fn token_ranges(text: &str) -> Vec<Range<usize>> {
    const PUNCT: &str = "()[]{}|,;=!<>:\"/?$+-*%~";
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        let word = !c.is_whitespace() && !PUNCT.contains(c);
        match (word, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push(s..i);
                start = None;
            }
            _ => {}
        }
        if !word && !c.is_whitespace() {
            out.push(i..i + c.len_utf8());
        }
    }
    if let Some(s) = start {
        out.push(s..text.len());
    }
    out
}

const SAMPLES: &[&str] = &[
    "a",
    " ",
    "\n",
    "|",
    " | ",
    "=",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "==",
    "<=>",
    ":=",
    "=~",
    "=>",
    "!",
    "+",
    "-",
    "*",
    "/",
    "%",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ";",
    ":",
    "$",
    "?",
    "?{",
    "\"",
    "\"s\"",
    "\\",
    "//",
    "/*",
    "*/",
    "/x/i",
    "and",
    " and ",
    "or",
    " or ",
    "not ",
    "OR",
    "case",
    "case {",
    "match",
    " match {",
    "like",
    " like ",
    "true",
    "false",
    "1",
    "-1",
    "1.5e+3",
    "5min",
    "#event_simpleName",
    "event_simpleName",
    "ProcessRollup2",
    "#t[0]",
    "a[0]",
    "x.y",
    "count()",
    "groupBy(",
    "f(",
    "!in(x)",
    "not test(",
    "correlate(",
    "regex(",
    "field=",
    "function=",
    "limit=max",
    "as=",
    "aggregation=",
    "within=",
    "include:",
    "a: {",
    "$q()",
    "?p",
    "?{p=1}",
    "https://x/*",
    "\u{a0}",
    "é",
    "\t",
    "eventSize()",
    "wildcard(",
    "readFile(",
    "/(?<g>x)/",
    "\"\\d\"",
    "[a := 1, b]",
    "{ a | b }",
];

/// Seed 1, or `OPENTIDE_DIFF_SEEDS` / `OPENTIDE_CQL_SEEDS` (comma-separated).
fn seeds() -> Vec<u64> {
    std::env::var("OPENTIDE_DIFF_SEEDS")
        .or_else(|_| std::env::var("OPENTIDE_CQL_SEEDS"))
        .map_or_else(
            |_| vec![1],
            |s| s.split(',').filter_map(|n| n.trim().parse().ok()).collect(),
        )
}

#[test]
fn pure_rust_engine_matches_tree_sitter() {
    let files = sources();
    assert!(files.len() > 300, "{} sources", files.len());
    let full = std::env::var("OPENTIDE_DIFF_SCALE").is_ok_and(|s| s == "full");
    for seed in seeds() {
        let mut config = Config::new(&verdict, &token_ranges, SAMPLES);
        config.seed = seed;
        if full {
            config.sentences = 2_000;
            config.mutations_per_input = 40;
            config.max_prefixes = 24;
            config.max_offsets = 12;
        } else {
            config.sentences = 200;
            config.mutations_per_input = 2;
            config.max_prefixes = 4;
            config.max_offsets = 4;
        }
        let report = run(&Old, &New, &files, &config);
        eprintln!(
            "cql differential, seed {seed}, scale {}: {} inputs, {} valid, {} broken; valid differences {}, verdict changes {}, broken-input changes {}",
            if full { "full" } else { "sample" },
            report.inputs,
            report.valid,
            report.inputs - report.valid,
            report.total(Class::Valid),
            report.total(Class::Verdict),
            report.total(Class::Broken),
        );
        if let Ok(path) = std::env::var("OPENTIDE_CQL_DIFF") {
            std::fs::write(format!("{path}.{seed}"), report.to_json_string())
                .expect("the report file");
        }
        let floor = if full { 2_000 } else { VALID_SAMPLE_FLOOR };
        assert!(report.valid > floor, "seed {seed}: {} valid", report.valid);
        assert_gates(&report);
    }
}
