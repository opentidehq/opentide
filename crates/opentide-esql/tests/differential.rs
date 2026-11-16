//! The differential of the ES|QL port (epic #1219, #1228): the tree-sitter
//! engine (`tests/legacy`, `src/lib.rs` copied verbatim) against the
//! pure-Rust one (`src/engine`, on `src/parser`), over every ES|QL file of the
//! corpora, its prefixes, token mutations and random sentences, on every
//! surface the engine has: diagnostics (for no target and for each stack),
//! highlight tokens, output columns, indices and ECS findings, and hover,
//! completions and signature help at offsets.
//!
//! Valid input must have zero differences; broken input the same verdict.
//! `OPENTIDE_DIFF_SEEDS` (comma separated, default `1`) picks the seeds,
//! `OPENTIDE_DIFF_SCALE` (default 1) multiplies the sampling, and
//! `OPENTIDE_DIFF_REPORT` names a file the JSON reports are written to.
//! The generated-query pass (`generated_queries_match_tree_sitter`) has its own
//! `OPENTIDE_GEN_SEEDS` (default `11,12`), `OPENTIDE_GEN_SCALE` and `OPENTIDE_GEN_REPORT`.
//! `word_level_mutants_match_tree_sitter` is the reviewer's scheme (40 word-level
//! mutants per file: `OPENTIDE_MUT_SEEDS` default `21`, `OPENTIDE_MUT_PER_FILE`, `OPENTIDE_MUT_REPORT`).
//!
//! The defaults are the CI scale (one seed, a sample: well under 120 s in a debug
//! build; nextest kills a test at 300 s). The full gate before a push is
//! `OPENTIDE_DIFF_SEEDS=1,2,3 OPENTIDE_DIFF_SCALE=4 OPENTIDE_MUT_SEEDS=21,22,23
//! OPENTIDE_MUT_PER_FILE=40`, and its numbers are in the PR body and NOTES.md.
//!
//! The new engine is private to the crate (production still runs
//! tree-sitter), so this test includes its source.

#![expect(
    dead_code,
    unused_imports,
    reason = "the included modules are used in part"
)]
#![expect(
    clippy::too_many_lines,
    reason = "the engine dispatchers match every node kind in one function, as src/lib.rs does"
)]

#[path = "../src/engine/mod.rs"]
mod engine;
mod legacy;
#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser/mod.rs"]
mod parser;
#[path = "support/rng.rs"]
mod rng;
#[path = "../src/syntax.rs"]
mod syntax;

// The paths the engine's source uses for the crate's public modules.
pub use opentide_esql::{catalog, version};

use opentide_parse::differential::{Config, Engine, Source, Surfaces, assert_gates, run};
use std::fmt::Debug;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// Every `.esql` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "esql") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut out,
    );
    out.sort();
    out
}

/// The stacks the diagnostics are observed for (`None` is every stack).
const TARGETS: [Option<&str>; 4] = [None, Some("8.19"), Some("9.1"), Some("9.6")];

fn target(name: Option<&str>) -> Option<version::StackTarget> {
    name.and_then(version::StackTarget::parse)
}

fn lines<T: Debug>(items: impl IntoIterator<Item = T>) -> String {
    items.into_iter().fold(String::new(), |mut out, i| {
        out.push_str(&format!("{i:?}\n"));
        out
    })
}

type Analyzed = (
    Vec<opentide_core::Diagnostic>,
    Vec<opentide_highlight::HighlightToken>,
);

/// One side of the differential.
struct Side {
    analyze: fn(&str, Option<version::StackTarget>) -> Analyzed,
    columns: fn(&str) -> Option<Vec<String>>,
    indices: fn(&str) -> Option<Vec<String>>,
    ecs: fn(&str) -> Vec<opentide_core::Diagnostic>,
    hover: fn(&str, usize) -> Option<String>,
    completions: fn(&str, usize) -> Vec<opentide_core::CompletionItem>,
    signature: fn(&str, usize) -> Option<opentide_core::SignatureHelp>,
}

/// The words Elasticsearch's lexer reserves in an expression: never the unit
/// of an interval (`@elastic/esql` 4.33.0 rejects `5 on`, `LIMIT 1 LIKE`).
const RESERVED: [&str; 19] = [
    "and", "asc", "by", "desc", "false", "first", "in", "is", "last", "like", "not", "null",
    "nulls", "on", "or", "rlike", "true", "where", "with",
];

static EXCLUDED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Whether tree-sitter reads a reserved word as the unit of a number in
/// `input`: an old-engine quirk on a query Elasticsearch rejects (class b of
/// NOTES.md: kept out of the comparison, and counted). The new parser errors
/// there (`pinned_regressions` holds it).
fn old_quirk(input: &str) -> bool {
    let Some(tree) = opentide_syntax::parse(opentide_core::LanguageId::Esql, input) else {
        return false;
    };
    let mut found = false;
    opentide_syntax::walk(tree.root_node(), |node| {
        if node.kind() == "qualified_interval"
            && let Some(unit) = node.child_by_field_name("unit")
            && let Some(text) = input.get(unit.start_byte()..unit.end_byte())
        {
            found |= RESERVED.iter().any(|w| text.eq_ignore_ascii_case(w));
        }
    });
    found
}

fn excluded(input: &str) -> Option<Surfaces> {
    old_quirk(input).then(|| {
        EXCLUDED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        vec![("excluded".to_string(), String::new())]
    })
}

impl Engine for Side {
    fn observe(&self, input: &str) -> Surfaces {
        if let Some(skip) = excluded(input) {
            return skip;
        }
        let mut out = Vec::new();
        let mut tokens = String::new();
        for name in TARGETS {
            let (diagnostics, highlight) = (self.analyze)(input, target(name));
            out.push((
                format!("diagnostics {}", name.unwrap_or("all")),
                lines(&diagnostics),
            ));
            if name.is_none() {
                tokens = lines(highlight.iter().map(|t| (t.span, &t.capture)));
            }
        }
        out.push(("highlight".into(), tokens));
        out.push(("columns".into(), format!("{:?}", (self.columns)(input))));
        out.push(("indices".into(), format!("{:?}", (self.indices)(input))));
        out.push(("ecs".into(), lines((self.ecs)(input))));
        out
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        if old_quirk(input) {
            return Vec::new();
        }
        let completions = (self.completions)(input, offset);
        vec![
            ("hover".into(), format!("{:?}", (self.hover)(input, offset))),
            (
                "completions".into(),
                lines(completions.iter().map(|c| (&c.label, &c.kind, &c.detail))),
            ),
            (
                "signature".into(),
                format!("{:?}", (self.signature)(input, offset)),
            ),
        ]
    }
}

fn old() -> Side {
    Side {
        analyze: |s, t| {
            let r = legacy::analyze_for(s, t);
            (r.diagnostics, r.tokens)
        },
        columns: legacy::output_columns,
        indices: legacy::source_indices,
        ecs: legacy::ecs_diagnostics,
        hover: legacy::hover,
        completions: legacy::completions,
        signature: legacy::signature_help,
    }
}

fn new() -> Side {
    Side {
        analyze: |s, t| {
            let r = engine::analyze_for(s, t);
            (r.diagnostics, r.tokens)
        },
        columns: engine::output_columns,
        indices: engine::source_indices,
        ecs: engine::ecs_diagnostics,
        hover: engine::hover,
        completions: engine::completions,
        signature: engine::signature_help,
    }
}

/// Token texts for inserted tokens and random sentences.
const SAMPLES: &[&str] = &[
    "FROM",
    "TS",
    "ROW",
    "SHOW",
    "INFO",
    "EXPLAIN",
    "PROMQL",
    "SET",
    "METADATA",
    "|",
    "WHERE",
    "EVAL",
    "KEEP",
    "DROP",
    "RENAME",
    "AS",
    "SORT",
    "ASC",
    "DESC",
    "NULLS",
    "FIRST",
    "LAST",
    "LIMIT",
    "STATS",
    "INLINE",
    "INLINESTATS",
    "BY",
    "DISSECT",
    "GROK",
    "ENRICH",
    "ON",
    "WITH",
    "MV_EXPAND",
    "LOOKUP",
    "JOIN",
    "CHANGE_POINT",
    "COMPLETION",
    "FORK",
    "FUSE",
    "DEDUP",
    "AND",
    "OR",
    "NOT",
    "IN",
    "IS",
    "NULL",
    "LIKE",
    "RLIKE",
    "TRUE",
    "FALSE",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ".",
    ":",
    "::",
    ";",
    "=",
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "+",
    "-",
    "*",
    "/",
    "%",
    "a",
    "b.c",
    "x*",
    "logs-*",
    "`q`",
    "?p",
    "??p",
    "1",
    "2.5",
    "10 minutes",
    "\"s\"",
    "\"\"\"t\"\"\"",
    "COUNT(*)",
    "TO_STRING(a)",
    "// c\n",
    "/* c */",
    "\n",
];

fn tokens(text: &str) -> Vec<Range<usize>> {
    lexer::lex(text)
        .iter()
        .filter(|l| l.kind != syntax::SyntaxKind::WHITESPACE.raw())
        .map(|l| usize::from(l.range.start())..usize::from(l.range.end()))
        .collect()
}

/// Valid: the observation holds no syntax error.
fn valid(surfaces: &Surfaces) -> bool {
    !surfaces
        .iter()
        .any(|(_, v)| v.contains("ES|QL syntax error"))
}

fn env_list(name: &str, default: &str) -> Vec<u64> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

#[test]
fn the_pure_rust_engine_matches_tree_sitter() {
    let scale: usize = std::env::var("OPENTIDE_DIFF_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let files: Vec<Source> = corpus()
        .into_iter()
        .map(|path| Source {
            name: path
                .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"))
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            text: std::fs::read_to_string(&path).unwrap_or_default(),
        })
        .collect();
    assert!(files.len() > 150, "found {} corpus files", files.len());
    let (old, new) = (old(), new());
    let mut reports = Vec::new();
    for seed in env_list("OPENTIDE_DIFF_SEEDS", "1") {
        let mut config = Config::new(&valid, &tokens, SAMPLES);
        config.seed = seed;
        config.mutations_per_input = scale;
        config.sentences = 40 * scale;
        config.max_prefixes = 4 * scale;
        config.max_offsets = 6 * scale;
        let report = run(&old, &new, &files, &config);
        eprintln!(
            "seed {seed}: {} inputs, {} valid; valid {}, broken {}, verdict {}",
            report.inputs,
            report.valid,
            report.total(opentide_parse::differential::Class::Valid),
            report.total(opentide_parse::differential::Class::Broken),
            report.total(opentide_parse::differential::Class::Verdict),
        );
        reports.push(report.to_json_string());
        if let Ok(path) = std::env::var("OPENTIDE_DIFF_REPORT") {
            std::fs::write(path, reports.join("\n")).unwrap_or_default();
        }
        assert_gates(&report);
    }
}

/// What the differential found, pinned: each of these differed once.
#[test]
fn pinned_regressions() {
    let (old, new) = (old(), new());
    // Class (a): the differential found these, and they are fixed.
    for query in [
        // `not` is a keyword where a boolean expression may start.
        "FROM a | WHERE x IS NOT NULL AND y IS NULL\n",
        "FROM a | WHERE a / NOT IN (\"a*\")\n",
        "FROM a | EVAL x = -not\n",
        // A tuple is the left of an `in`.
        "FROM a | WHERE (a, b) NOT IN (FROM c | KEEP a, b)\n",
        // A parameter names an assignment.
        "ROW ?p = 1\n",
        "FROM a | EVAL ??p = 1 | STATS ?q = COUNT(*)\n",
    ] {
        assert_eq!(old.observe(query), new.observe(query), "{query}");
        for offset in 0..=query.len() {
            assert_eq!(
                old.observe_at(query, offset),
                new.observe_at(query, offset),
                "{query} @ {offset}"
            );
        }
    }
    // The verdict of a broken query is the old engine's: a tuple is the left of an `in`, and nothing else.
    for query in [
        "FROM a | WHERE x* (host.name, user.name) IN (\"a\", \"b\")\n",
        "FROM a | WHERE (a, b) + 1 IN (FROM c)\n",
    ] {
        let errors = |side: &Side| {
            (side.analyze)(query, None)
                .0
                .iter()
                .any(|d| d.message.contains("ES|QL syntax error"))
        };
        assert!(errors(&old) && errors(&new), "{query}");
    }
    // Class (b): tree-sitter reads a reserved word as the unit of a number;
    // Elasticsearch (`@elastic/esql` 4.33.0) and the new parser reject it.
    for query in [
        "FROM a | LIMIT 1 LIKE /* c */\n",
        "FROM a | FORK (WHERE a == 1) (WHERE b == 2 | LIMIT 5WITH )\n",
        "FROM a | LIMIT 10 not BY x\n",
        "FROM a | WHERE x > 1 on\n",
        "FROM a | EVAL x = 5 where\n",
        "FROM a | LIMIT 10 or BY x\n",
    ] {
        assert!(old_quirk(query), "{query}");
        assert!(
            (new.analyze)(query, None)
                .0
                .iter()
                .any(|d| d.message.contains("ES|QL syntax error")),
            "{query}"
        );
    }
}

/// The reviewer's mutation scheme (it found what the corpus-heavy run missed):
/// 40 mutants of every corpus file, each by one word-level edit: delete,
/// duplicate, insert (a word from the corpus) or replace a word, or truncate
/// at a word boundary. A word is a run of non-whitespace characters.
fn word_mutants(text: &str, pool: &[String], seed: u64, n: usize) -> Vec<String> {
    let mut rng = rng::Rng::new(seed);
    let mut words: Vec<(usize, usize)> = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(i),
            (true, Some(s)) => {
                words.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        words.push((s, text.len()));
    }
    if words.is_empty() {
        return Vec::new();
    }
    (0..n)
        .map(|_| {
            let (s, e) = words[rng.below(words.len())];
            let word = &text[s..e];
            let other = &pool[rng.below(pool.len())];
            match rng.below(5) {
                0 => format!("{}{}", &text[..s], &text[e..]),
                1 => format!("{}{word} {}", &text[..s], &text[s..]),
                2 => format!("{}{other} {}", &text[..s], &text[s..]),
                3 => format!("{}{other}{}", &text[..s], &text[e..]),
                _ => text[..e].to_string(),
            }
        })
        .collect()
}

#[test]
fn word_level_mutants_match_tree_sitter() {
    let files: Vec<(String, String)> = corpus()
        .into_iter()
        .map(|path| {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            (path.display().to_string(), text)
        })
        .collect();
    let mut pool: Vec<String> = files
        .iter()
        .flat_map(|(_, t)| t.split_whitespace().map(str::to_string))
        .filter(|w| w.len() < 40)
        .collect();
    pool.sort();
    pool.dedup();
    pool.extend(SAMPLES.iter().map(|s| (*s).to_string()));
    let per_file: usize = std::env::var("OPENTIDE_MUT_PER_FILE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let (old, new) = (old(), new());
    for seed in env_list("OPENTIDE_MUT_SEEDS", "21") {
        let mutants: Vec<Source> = files
            .iter()
            .enumerate()
            .flat_map(|(i, (name, text))| {
                word_mutants(text, &pool, seed * 1_000 + i as u64, per_file)
                    .into_iter()
                    .enumerate()
                    .map(move |(j, text)| Source {
                        name: format!("mutant/{seed}/{name}/{j}"),
                        text,
                    })
            })
            .collect();
        let mut config = Config::new(&valid, &tokens, SAMPLES);
        config.seed = seed;
        config.mutations_per_input = 0;
        config.sentences = 0;
        config.max_prefixes = 0;
        config.max_offsets = 8;
        let report = run(&old, &new, &mutants, &config);
        eprintln!(
            "mutants seed {seed}: {} inputs, {} valid; valid {}, broken {}, verdict {}; {} excluded as old quirks",
            report.inputs,
            report.valid,
            report.total(opentide_parse::differential::Class::Valid),
            report.total(opentide_parse::differential::Class::Broken),
            report.total(opentide_parse::differential::Class::Verdict),
            EXCLUDED.load(std::sync::atomic::Ordering::Relaxed),
        );
        if let Ok(path) = std::env::var("OPENTIDE_MUT_REPORT") {
            std::fs::write(path, report.to_json_string()).unwrap_or_default();
        }
        assert_gates(&report);
    }
}

/// A seeded generator of queries the grammar accepts: a source command, then
/// processing commands, over expressions of every operator, call, constant
/// and name form. It stands beside the corpus (which the differential feeds
/// first) so that the valid side of the gate is not the corpus alone.
mod generated {
    use super::rng::Rng;

    const FIELDS: &[&str] = &[
        "host.name",
        "user.name",
        "source.ip",
        "destination.port",
        "event.code",
        "process.name",
        "@timestamp",
        "message",
        "a",
        "b.c",
        "`odd name`",
        "_id",
        "x",
        "event.outcome",
        "process.command_line",
        "file.path",
        "url.full",
    ];
    const INDICES: &[&str] = &[
        "logs-*",
        "logs-endpoint.events.*",
        "winlogbeat-*",
        "a",
        "b,c",
        "remote:logs-*",
        "logs-*::data",
        "my-index-000001",
        "traces-apm*",
        "\"quoted-index\"",
    ];
    const CALLS: &[&str] = &[
        "TO_LOWER",
        "TO_STRING",
        "LENGTH",
        "ABS",
        "ROUND",
        "COALESCE",
        "CONCAT",
        "MV_COUNT",
        "TO_IP",
        "DATE_TRUNC",
        "NOW",
        "CASE",
        "SUBSTRING",
        "STARTS_WITH",
        "MV_CONTAINS",
    ];
    const AGGS: &[&str] = &[
        "COUNT",
        "SUM",
        "MAX",
        "MIN",
        "AVG",
        "COUNT_DISTINCT",
        "VALUES",
        "TOP",
    ];
    const TYPES: &[&str] = &[
        "long", "keyword", "ip", "datetime", "double", "boolean", "string",
    ];
    const UNITS: &[&str] = &[
        "minute", "minutes", "hour", "hours", "day", "days", "seconds", "m", "ms",
    ];
    const CMP: &[&str] = &["==", "!=", "<", "<=", ">", ">="];
    const ARITH: &[&str] = &["+", "-", "*", "/", "%"];
    const STRINGS: &[&str] = &[
        "\"abc\"",
        "\"a*\"",
        "\"C:\\\\Windows\"",
        "\"tab\\t\"",
        "\"\"\"raw \\ text\"\"\"",
        "\"\"",
        "\"it\\\"s\"",
        "\"*.exe\"",
    ];

    pub struct Gen<'r>(pub &'r mut Rng);

    impl Gen<'_> {
        fn field(&mut self) -> String {
            self.0.pick(FIELDS).to_string()
        }

        fn constant(&mut self) -> String {
            match self.0.below(9) {
                0 => self.0.below(1000).to_string(),
                1 => format!("{}.{}", self.0.below(50), self.0.below(99)),
                2 => self.0.pick(STRINGS).to_string(),
                3 => self
                    .0
                    .pick(&["true", "false", "NULL", "TRUE", "False"])
                    .to_string(),
                4 => format!("{} {}", self.0.below(30) + 1, self.0.pick(UNITS)),
                5 => self.0.pick(&["?p", "?1", "??id", "?"]).to_string(),
                6 => format!("{}e{}", self.0.below(9), self.0.below(5)),
                7 => format!("[{}, {}]", self.0.below(9), self.0.below(9)),
                _ => format!(".{}", self.0.below(99)),
            }
        }

        fn atom(&mut self, depth: usize) -> String {
            match self.0.below(if depth == 0 { 4 } else { 9 }) {
                0 | 1 => self.field(),
                2 | 3 => self.constant(),
                4 | 5 => {
                    let call = self.0.pick(CALLS);
                    let n = self.0.below(3);
                    let args: Vec<String> = (0..n).map(|_| self.expr(depth - 1)).collect();
                    format!("{call}({})", args.join(", "))
                }
                6 => format!("({})", self.expr(depth - 1)),
                7 => format!("{}::{}", self.atom(depth - 1), self.0.pick(TYPES)),
                _ => format!(
                    "{}({}, {{\"k\": {}}})",
                    self.0.pick(CALLS),
                    self.expr(depth - 1),
                    self.constant()
                ),
            }
        }

        fn value(&mut self, depth: usize) -> String {
            match self.0.below(6) {
                0 if depth > 0 => format!("-{}", self.value(depth - 1)),
                1 | 2 if depth > 0 => {
                    let n = self.0.below(3) + 1;
                    let mut s = self.atom(depth - 1);
                    for _ in 0..n {
                        s = format!("{s} {} {}", self.0.pick(ARITH), self.atom(depth - 1));
                    }
                    s
                }
                _ => self.atom(depth),
            }
        }

        fn predicate(&mut self, depth: usize) -> String {
            let v = self.value(depth);
            match self.0.below(10) {
                0..=2 => format!("{v} {} {}", self.0.pick(CMP), self.value(depth)),
                3 => format!("{v} IN ({}, {})", self.constant(), self.constant()),
                4 => format!("{v} NOT IN ({})", self.constant()),
                5 => format!("{v} IS NULL"),
                6 => format!("{v} IS NOT NULL"),
                7 => format!(
                    "{v} {}LIKE {}",
                    self.0.pick(&["", "NOT ", "R"]),
                    self.0.pick(STRINGS)
                ),
                8 => format!("{} : {}", self.field(), self.0.pick(STRINGS)),
                _ => v,
            }
        }

        pub fn expr(&mut self, depth: usize) -> String {
            let mut s = self.predicate(depth);
            for _ in 0..self.0.below(4) {
                let op = self.0.pick(&["AND", "OR", "and", "or"]);
                let p = self.predicate(depth.saturating_sub(1));
                let p = if self.0.chance(15) {
                    format!("NOT {p}")
                } else {
                    p
                };
                s = format!("{s} {op} {p}");
            }
            if self.0.chance(10) {
                format!("NOT ({s})")
            } else {
                s
            }
        }

        fn names(&mut self) -> String {
            let n = self.0.below(3) + 1;
            (0..n)
                .map(|_| {
                    self.0.pick(&[
                        "host.*",
                        "user.name",
                        "a*b",
                        "`q`",
                        "*",
                        "x",
                        "@timestamp",
                        "?p",
                        "process.*",
                    ])
                })
                .collect::<Vec<_>>()
                .join(", ")
        }

        fn agg(&mut self) -> String {
            let call = if self.0.chance(40) {
                "COUNT(*)".to_string()
            } else {
                format!("{}({})", self.0.pick(AGGS), self.field())
            };
            let named = if self.0.chance(60) {
                format!(
                    "{} = {call}",
                    self.0.pick(&["n", "total", "c1", "`my agg`"])
                )
            } else {
                call
            };
            if self.0.chance(25) {
                format!("{named} WHERE {}", self.expr(1))
            } else {
                named
            }
        }

        fn command(&mut self, allow_fork: bool) -> String {
            let e = self.0.below(26);
            match e {
                0..=2 => format!("WHERE {}", self.expr(2)),
                3 | 4 => format!(
                    "EVAL {} = {}",
                    self.0.pick(&["n", "x2", "`y z`", "a.b"]),
                    self.expr(2)
                ),
                5 => format!(
                    "EVAL {}, {} = {}",
                    self.expr(1),
                    self.0.pick(&["p", "q"]),
                    self.expr(1)
                ),
                6 => format!("KEEP {}", self.names()),
                7 => format!("DROP {}", self.names()),
                8 => format!(
                    "RENAME {} AS {}",
                    self.0.pick(&["a", "host.name", "`q`"]),
                    self.0.pick(&["b", "h"])
                ),
                9 => format!(
                    "RENAME {} = {}",
                    self.0.pick(&["b", "h"]),
                    self.0.pick(&["a", "host.name"])
                ),
                10 => format!(
                    "SORT {} {}",
                    self.field(),
                    self.0
                        .pick(&["", "ASC", "DESC", "DESC NULLS FIRST", "ASC NULLS LAST"])
                ),
                11 => format!("LIMIT {}", self.0.below(500)),
                12 => format!("LIMIT {} BY {}", self.0.below(9) + 1, self.field()),
                13 | 14 => {
                    let n = self.0.below(2) + 1;
                    let aggs: Vec<String> = (0..n).map(|_| self.agg()).collect();
                    let by = if self.0.chance(70) {
                        format!(
                            " BY {}",
                            self.0.pick(&[
                                "host.name",
                                "b = BUCKET(@timestamp, 1 hour)",
                                "user.name, host.name"
                            ])
                        )
                    } else {
                        String::new()
                    };
                    format!(
                        "{} {}{by}",
                        self.0.pick(&["STATS", "INLINE STATS", "INLINESTATS"]),
                        aggs.join(", ")
                    )
                }
                15 => format!("DISSECT {} \"%{{a}} %{{b}}\"", self.field()),
                16 => format!("GROK {} \"%{{IP:ip}}\"", self.field()),
                17 => format!(
                    "ENRICH {} ON {} WITH {}",
                    self.0.pick(&["policy", "ctx:policy", "\"p\""]),
                    self.field(),
                    self.0.pick(&["x", "n = x", "x, y"])
                ),
                18 => format!("MV_EXPAND {}", self.field()),
                19 => format!(
                    "{} JOIN {} ON {}",
                    self.0.pick(&["LOOKUP", "LEFT", "RIGHT"]),
                    self.0.pick(&["idx", "lookup-*", "remote:idx"]),
                    self.expr(1)
                ),
                20 => format!("CHANGE_POINT {} ON {} AS t, p", self.field(), self.field()),
                21 => format!("SAMPLE 0.{}", self.0.below(99) + 1),
                22 if allow_fork => format!(
                    "FORK (WHERE {}) (LIMIT {} | KEEP {})",
                    self.expr(1),
                    self.0.below(9) + 1,
                    self.names()
                ),
                23 => format!("FILLNULL {} ON {}", self.constant(), self.names()),
                24 => format!(
                    "COMPLETION {} WITH {{\"inference_id\": \"m\"}}",
                    self.field()
                ),
                _ => self
                    .0
                    .pick(&[
                        "DEDUP",
                        "METRICS_INFO",
                        "TS_INFO",
                        "FUSE",
                        "FUSE RRF",
                        "MV_EXPAND a",
                    ])
                    .to_string(),
            }
        }

        fn source(&mut self) -> String {
            match self.0.below(10) {
                0 => format!(
                    "ROW {} = {}, b = {}",
                    self.0.pick(&["a", "x"]),
                    self.constant(),
                    self.expr(1)
                ),
                1 => "SHOW INFO".to_string(),
                2 => format!("TS {}", self.0.pick(INDICES)),
                3 => format!(
                    "FROM {}, (FROM {} | WHERE {})",
                    self.0.pick(INDICES),
                    self.0.pick(INDICES),
                    self.expr(1)
                ),
                _ => {
                    let n = self.0.below(2) + 1;
                    let idx: Vec<&str> = (0..n).map(|_| self.0.pick(INDICES)).collect();
                    let meta = match self.0.below(4) {
                        0 => " METADATA _id",
                        1 => " METADATA _id, _index, _version",
                        _ => "",
                    };
                    format!("FROM {}{meta}", idx.join(", "))
                }
            }
        }

        pub fn query(&mut self) -> String {
            let mut q = String::new();
            if self.0.chance(8) {
                q.push_str("SET a = 1;\n");
            }
            if self.0.chance(10) {
                q.push_str("// a comment\n");
            }
            q.push_str(&self.source());
            for _ in 0..self.0.below(6) {
                q.push_str(if self.0.chance(70) { "\n| " } else { " | " });
                q.push_str(&self.command(true));
                if self.0.chance(5) {
                    q.push_str(" /* c /* n */ */");
                }
            }
            if self.0.chance(50) {
                q.push('\n');
            }
            q
        }
    }
}

/// Queries composed by the generator: the valid side of the gate beyond the
/// corpus. The queries the old engine rejects count on the broken side.
#[test]
fn generated_queries_match_tree_sitter() {
    let scale: usize = std::env::var("OPENTIDE_GEN_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let (old, new) = (old(), new());
    for seed in env_list("OPENTIDE_GEN_SEEDS", "11,12") {
        let mut rng = rng::Rng::new(seed);
        let mut generator = generated::Gen(&mut rng);
        let files: Vec<Source> = (0..400 * scale)
            .map(|i| Source {
                name: format!("generated/{seed}/{i}"),
                text: generator.query(),
            })
            .collect();
        let originals = files
            .iter()
            .filter(|f| valid(&old.observe(&f.text)))
            .count();
        eprintln!(
            "generated seed {seed}: {originals} of {} queries are valid",
            files.len()
        );
        assert!(
            originals * 10 > files.len() * 7,
            "the generator makes too few valid queries: {originals} of {}",
            files.len()
        );
        let mut config = Config::new(&valid, &tokens, SAMPLES);
        config.seed = seed;
        config.mutations_per_input = 1;
        config.sentences = 0;
        config.max_prefixes = 2;
        config.max_offsets = 16;
        let report = run(&old, &new, &files, &config);
        eprintln!(
            "generated seed {seed}: {} inputs, {} valid; valid {}, broken {}, verdict {}",
            report.inputs,
            report.valid,
            report.total(opentide_parse::differential::Class::Valid),
            report.total(opentide_parse::differential::Class::Broken),
            report.total(opentide_parse::differential::Class::Verdict),
        );
        if let Ok(path) = std::env::var("OPENTIDE_GEN_REPORT") {
            std::fs::write(path, report.to_json_string()).unwrap_or_default();
        }
        assert!(
            report.valid * 10 > files.len() * 6,
            "the generator makes too few valid queries: {} of {}",
            report.valid,
            files.len()
        );
        assert_gates(&report);
    }
}
