//! The pure-Rust parser against the tree-sitter engine it replaces, over every
//! `.kql` file of `crates/testdata`, its prefixes, seeded token mutations and
//! random sentences (`opentide_parse::differential`, #1230).
//!
//! The old engine is the production one, reached through its public API; the
//! new one is `opentide_kql::testing::analyze_new`. They are compared as far
//! as the new parser goes: the diagnostics that read the tree, and the
//! highlight tokens. The column pass, the performance checks, the HIR and
//! hover on a column are still on tree-sitter on both sides.
//!
//! Gates: valid input, zero differences; broken input, the same verdict.
//! `OPENTIDE_KQL_DIFF=<file>` writes the JSON report of every seed.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod common;

use common::corpus;
use opentide_core::codes;
use opentide_kql::testing::{NEW_CODES, analyze_new, lex_spans};
use opentide_kql::{Catalog, Profile, analyze_with_catalog};
use opentide_parse::differential::{Config, Engine, Source, Surfaces, assert_gates, run};

/// What a diagnostic says, on one line.
fn line(d: &opentide_core::Diagnostic) -> String {
    format!(
        "{} {:?} {}:{}-{}:{} {} [{}]",
        d.code,
        d.severity,
        d.range.start.line,
        d.range.start.character,
        d.range.end.line,
        d.range.end.character,
        d.message,
        d.suggestion.as_deref().unwrap_or("")
    )
}

fn tokens_text(tokens: &[opentide_highlight::HighlightToken]) -> String {
    tokens
        .iter()
        .map(|t| format!("{}..{} {}", t.span.start, t.span.end, t.capture))
        .collect::<Vec<_>>()
        .join("\n")
}

const PROFILES: [(&str, Profile); 2] = [
    ("sentinel", Profile::Sentinel),
    ("defender", Profile::Defender),
];

struct Old;
struct New;

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        let mut out = Vec::new();
        for (name, profile) in PROFILES {
            let catalog = Catalog::for_workspace(profile, input);
            let analysis = analyze_with_catalog(input, &catalog);
            let diagnostics: Vec<String> = analysis
                .diagnostics
                .iter()
                .filter(|d| NEW_CODES.contains(&d.code.as_str()))
                .map(line)
                .collect();
            out.push((format!("diagnostics.{name}"), diagnostics.join("\n")));
            if name == "sentinel" {
                out.push(("tokens".to_owned(), tokens_text(&analysis.tokens)));
            }
        }
        out
    }
}

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        let mut out = Vec::new();
        for (name, profile) in PROFILES {
            let catalog = Catalog::for_workspace(profile, input);
            let analysis = analyze_new(input, &catalog);
            let diagnostics: Vec<String> = analysis.diagnostics.iter().map(line).collect();
            out.push((format!("diagnostics.{name}"), diagnostics.join("\n")));
            if name == "sentinel" {
                out.push(("tokens".to_owned(), tokens_text(&analysis.tokens)));
            }
        }
        out
    }
}

/// Valid unless the diagnostics hold a syntax error.
fn verdict(surfaces: &Surfaces) -> bool {
    !surfaces.iter().any(|(name, text)| {
        name.starts_with("diagnostics")
            && text.lines().any(|l| l.starts_with(codes::KQL_PARSE_ERROR))
    })
}

fn tokens(text: &str) -> Vec<std::ops::Range<usize>> {
    lex_spans(text)
        .into_iter()
        .filter(|(_, _, trivia)| !trivia)
        .map(|(start, end, _)| start..end)
        .collect()
}

const SAMPLES: &[&str] = &[
    "T",
    "SecurityEvent",
    "|",
    "where",
    "project",
    "extend",
    "summarize",
    "by",
    "count()",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ";",
    "=",
    "==",
    "!=",
    "and",
    "or",
    "not",
    "has",
    "in",
    "!in",
    "between",
    "..",
    "1",
    "5m",
    "\"x\"",
    "'y'",
    "@\"z\"",
    "let",
    "x",
    "join",
    "kind",
    "inner",
    "on",
    "$left",
    "$right",
    "union",
    "take",
    "top",
    "sort",
    "asc",
    "desc",
    "mv-expand",
    "parse",
    "with",
    "*",
    "project-away",
    "datatable",
    "dynamic",
    "range",
    "from",
    "to",
    "step",
    "render",
    "evaluate",
    "dcount(a)",
    "ago(1d)",
    ".",
    ":",
    "+",
    "-",
    "/",
    "%",
    "//c\n",
    "```a```",
    "datetime(2024-01-01)",
];

fn sources() -> Vec<Source> {
    corpus()
        .into_iter()
        .map(|path| Source {
            name: path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(&path)
                .display()
                .to_string(),
            text: std::fs::read_to_string(&path).expect("corpus file"),
        })
        .collect()
}

fn differential(seed: u64) {
    let files = sources();
    assert!(files.len() > 150, "{} files", files.len());
    let mut config = Config::new(&verdict, &tokens, SAMPLES);
    config.seed = seed;
    config.max_prefixes = 15;
    config.mutations_per_input = 3;
    config.sentences = 150;
    config.max_offsets = 64;
    let report = run(&Old, &New, &files, &config);
    eprintln!(
        "seed {seed}: {} inputs, {} valid; valid {}, broken {}, verdict {}",
        report.inputs,
        report.valid,
        report.total(opentide_parse::differential::Class::Valid),
        report.total(opentide_parse::differential::Class::Broken),
        report.total(opentide_parse::differential::Class::Verdict),
    );
    if let Ok(path) = std::env::var("OPENTIDE_KQL_DIFF") {
        let path = format!("{path}.{seed}.json");
        std::fs::write(path, report.to_json_string()).expect("write the report");
    }
    assert_gates(&report);
}

#[test]
fn seed_1() {
    differential(1);
}

#[test]
fn seed_2() {
    differential(2);
}
