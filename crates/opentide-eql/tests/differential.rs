//! The differential of the EQL port (epic #1219, #1224): the tree-sitter engine
//! (`tests/legacy`, the crate's `src` before the switch, verbatim) against the pure-Rust one
//! (the crate's public functions), over every EQL file of the corpora, its lines, its prefixes,
//! token mutations and random sentences, and over the literals of the old tests and the
//! fixtures, on every surface the engine has: diagnostics, highlight tokens, ECS findings and
//! sequences, and hover, completions and signature help at offsets.
//!
//! Valid input must have zero differences; broken input the same verdict. `OPENTIDE_DIFF_SEEDS`
//! (comma separated, default `1`) picks the seeds, `OPENTIDE_DIFF_SCALE` (default 1) multiplies
//! the sampling, and `OPENTIDE_DIFF_REPORT` names a file the JSON reports are written to.
//! `word_level_mutants_match_tree_sitter` is the reviewers' scheme (word-level mutants of every
//! file: `OPENTIDE_MUT_SEEDS`, default `21`, and `OPENTIDE_MUT_PER_FILE`, default 6).
//!
//! The defaults are the CI scale. The full gate before a push is
//! `OPENTIDE_DIFF_SEEDS=1,2,3 OPENTIDE_DIFF_SCALE=4 OPENTIDE_MUT_SEEDS=21,22,23
//! OPENTIDE_MUT_PER_FILE=40 OPENTIDE_GEN_SEEDS=1,2,3 OPENTIDE_GEN_SCALE=4`; its numbers are in the
//! PR body. `generated_queries_match_tree_sitter` feeds queries the generator composes.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

#[allow(
    dead_code,
    reason = "a verbatim copy of the old crate; not every item is compared"
)]
mod legacy;
#[path = "support/rng.rs"]
mod rng;

use opentide_core::{CompletionItem, Diagnostic};
use opentide_highlight::HighlightToken;
use opentide_parse::differential::{Class, Config, Engine, Source, Surfaces, assert_gates, run};
use std::fmt::Debug;
use std::ops::Range;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `.eql` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "eql") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo().join("crates/testdata"), &mut out);
    out.sort();
    out
}

/// Rust string literals (`"..."` and `r#"..."#`) in a source file, unescaped roughly.
fn rust_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let raw = regex::Regex::new(r##"r#"((?s:.)*?)"#"##).expect("regex");
    out.extend(raw.captures_iter(text).map(|c| c[1].to_owned()));
    let plain = regex::Regex::new(r#""((?:[^"\\\n]|\\.)*)""#).expect("regex");
    for c in plain.captures_iter(text) {
        let mut s = String::new();
        let mut chars = c[1].chars();
        while let Some(ch) = chars.next() {
            if ch != '\\' {
                s.push(ch);
                continue;
            }
            match chars.next() {
                Some('n') => s.push('\n'),
                Some('t') => s.push('\t'),
                Some('r') => s.push('\r'),
                Some(other) => s.push(other),
                None => {}
            }
        }
        out.push(s);
    }
    out.retain(|s| !s.is_empty() && s.len() < 2_000);
    out
}

/// Every input the run starts from: the corpus files and their lines, the old tests'
/// literals, and the EQL queries of the fixtures.
fn sources() -> Vec<Source> {
    let mut texts = std::collections::BTreeSet::new();
    for path in corpus() {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let name = path.display().to_string();
        for line in text.lines() {
            texts.insert((format!("{name}#line"), line.to_owned()));
        }
        texts.insert((name, text));
    }
    for file in [
        "crates/opentide-eql/tests/legacy/mod.rs",
        "crates/opentide-eql/tests/legacy/ecs.rs",
        "crates/opentide-eql/tests/legacy/semantics.rs",
        "crates/opentide-eql/tests/legacy/regex.rs",
        "crates/opentide-eql/tests/legacy/lexical.rs",
        "crates/opentide-analysis/tests/deep_queries.rs",
        "crates/opentide-analysis/tests/suggestions.rs",
        "crates/opentide-analysis/src/ecs.rs",
    ] {
        let text = std::fs::read_to_string(repo().join(file)).unwrap_or_default();
        for s in rust_strings(&text) {
            texts.insert((file.to_owned(), s));
        }
    }
    texts
        .into_iter()
        .map(|(name, text)| Source { name, text })
        .collect()
}

fn lines<T: Debug>(items: impl IntoIterator<Item = T>) -> String {
    items.into_iter().fold(String::new(), |mut out, i| {
        out.push_str(&format!("{i:?}\n"));
        out
    })
}

/// One side of the differential.
struct Side {
    analyze: fn(&str) -> (Vec<Diagnostic>, Vec<HighlightToken>),
    ecs: fn(&str) -> Vec<Diagnostic>,
    sequences: fn(&str) -> String,
    hover: fn(&str, usize) -> Option<String>,
    completions: fn(&str, usize) -> Vec<CompletionItem>,
    signature: fn(&str, usize) -> Option<opentide_core::SignatureHelp>,
}

impl Engine for Side {
    fn observe(&self, input: &str) -> Surfaces {
        let (diagnostics, tokens) = (self.analyze)(input);
        vec![
            ("diagnostics".into(), lines(&diagnostics)),
            (
                "highlight".into(),
                lines(tokens.iter().map(|t| (t.span, &t.capture))),
            ),
            ("ecs".into(), lines((self.ecs)(input))),
            ("sequences".into(), (self.sequences)(input)),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![
            ("hover".into(), format!("{:?}", (self.hover)(input, offset))),
            (
                "completions".into(),
                lines((self.completions)(input, offset)),
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
        analyze: |s| {
            let r = legacy::analyze(s);
            (r.diagnostics, r.tokens)
        },
        ecs: legacy::ecs_diagnostics,
        sequences: |s| format!("{:?}", legacy::sequences(s)),
        hover: legacy::hover,
        completions: legacy::completions,
        signature: legacy::signature_help,
    }
}

fn new() -> Side {
    Side {
        analyze: |s| {
            let r = opentide_eql::analyze(s);
            (r.diagnostics, r.tokens)
        },
        ecs: opentide_eql::ecs_diagnostics,
        sequences: |s| format!("{:?}", opentide_eql::sequences(s)),
        hover: opentide_eql::hover,
        completions: opentide_eql::completions,
        signature: opentide_eql::signature_help,
    }
}

/// Token texts for inserted tokens and random sentences.
const SAMPLES: &[&str] = &[
    "sequence",
    "sample",
    "join",
    "by",
    "with",
    "maxspan",
    "=",
    "5m",
    "until",
    "where",
    "any",
    "process",
    "\"network\"",
    "[",
    "![",
    "]",
    "|",
    "head",
    "tail",
    "unique",
    "1",
    "2.5",
    "and",
    "or",
    "not",
    "in",
    "in~",
    "like",
    "like~",
    "regex",
    "regex~",
    ":",
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
    "(",
    ")",
    ",",
    ".",
    "?",
    "a",
    "b.c",
    "`q r`",
    "x[0]",
    "\"s\"",
    "\"*.exe\"",
    "'t'",
    "?\"r\"",
    "\"\"\"t\"\"\"",
    "null",
    "true",
    "false",
    "startsWith~",
    "cidrMatch",
    "length",
    "descendant",
    "of",
    "runs",
    "TRUE",
    "AND",
    "// c\n",
    "/* c */",
    "/* a /* b */ c */",
    "\n",
];

fn tokens(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        let word = c.is_alphanumeric() || "_.@~?`\"'".contains(c);
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

/// Valid: the observation holds no syntax error.
fn valid(surfaces: &Surfaces) -> bool {
    !surfaces
        .iter()
        .any(|(name, v)| name == "diagnostics" && v.contains("EQL syntax error"))
}

fn env_list(name: &str, default: &str) -> Vec<u64> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

fn report_line(label: &str, report: &opentide_parse::differential::Report) {
    eprintln!(
        "{label}: {} inputs, {} valid; valid differences {}, broken-input changes {}, verdict changes {}",
        report.inputs,
        report.valid,
        report.total(Class::Valid),
        report.total(Class::Broken),
        report.total(Class::Verdict),
    );
}

#[test]
fn the_pure_rust_engine_matches_tree_sitter() {
    let scale: usize = std::env::var("OPENTIDE_DIFF_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let files = sources();
    assert!(files.len() > 500, "found {} inputs", files.len());
    let (old, new) = (old(), new());
    let mut reports = Vec::new();
    for seed in env_list("OPENTIDE_DIFF_SEEDS", "1") {
        let mut config = Config::new(&valid, &tokens, SAMPLES);
        config.seed = seed;
        config.mutations_per_input = 2 * scale;
        config.sentences = 300 * scale;
        config.max_prefixes = 6 * scale;
        config.max_offsets = 8 * scale;
        let report = run(&old, &new, &files, &config);
        report_line(&format!("seed {seed}"), &report);
        reports.push(report.to_json_string());
        if let Ok(path) = std::env::var("OPENTIDE_DIFF_REPORT") {
            std::fs::write(path, reports.join("\n")).unwrap_or_default();
        }
        assert_gates(&report);
    }
}

/// The reviewers' mutation scheme: mutants of every corpus file, each by one word-level edit
/// (delete, duplicate, insert or replace a word, or truncate at a word's end). A word is a run
/// of non-whitespace characters.
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
                let salt = seed * 1_000 + u64::try_from(i).unwrap_or(0);
                word_mutants(text, &pool, salt, per_file)
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
        report_line(&format!("mutants seed {seed}"), &report);
        assert_gates(&report);
    }
}

/// A seeded generator of queries the grammar accepts: an event query, a `sequence`, a `sample`
/// or a `join`, then pipes, over expressions of every operator, predicate, call, constant and
/// field form. It stands beside the corpus so that the valid side of the gate is not the corpus
/// alone.
mod generated {
    use super::rng::Rng;

    const CATEGORIES: &[&str] = &[
        "process",
        "file",
        "network",
        "registry",
        "any",
        "\"dns\"",
        "library",
        "authentication",
    ];
    const FIELDS: &[&str] = &[
        "process.name",
        "process.args",
        "user.name",
        "host.os.type",
        "event.type",
        "file.path",
        "a",
        "b.c",
        "`odd name`",
        "process.parent.name",
        "?process.pe.original_file_name",
        "process.args[0]",
        "dll.code_signature.trusted",
        "`a`.b",
        "x.`y z`[1]",
        "source.port",
        "@timestamp",
        "_x",
    ];
    const STRINGS: &[&str] = &[
        "\"cmd.exe\"",
        "\"*\\\\temp\\\\*\"",
        "\"a\"",
        "'b'",
        "?\"C:\\path\"",
        "\"\"\"raw \"x\" \"\"\"",
        "\"\"",
        "\"10.0.0.0/8\"",
        "\"é\"",
    ];
    const NUMBERS: &[&str] = &["0", "1", "42", "2.5", "1e3", "0.5", "100"];
    const CALLS: &[&str] = &[
        "length",
        "startsWith",
        "startsWith~",
        "endsWith~",
        "stringContains",
        "cidrMatch",
        "add",
        "concat",
        "indexOf",
        "number",
        "between",
        "substring",
        "f",
        "wildcard",
    ];
    const RELATIONS: &[&str] = &["descendant", "child", "event"];
    const PIPES: &[&str] = &["head", "tail", "unique", "filter", "unique_count", "count"];
    const UNITS: &[&str] = &["", "s", "m", "h", "d", "ms"];

    pub struct Gen<'a>(pub &'a mut Rng);

    impl Gen<'_> {
        fn pick(&mut self, items: &[&'static str]) -> &'static str {
            self.0.pick(items)
        }

        fn chance(&mut self, percent: usize) -> bool {
            self.0.chance(percent)
        }

        fn constant(&mut self) -> String {
            match self.0.below(6) {
                0 => "null".into(),
                1 => self.pick(&["true", "false"]).into(),
                2 | 3 => self.pick(NUMBERS).into(),
                _ => self.pick(STRINGS).into(),
            }
        }

        fn list(&mut self, mut item: impl FnMut(&mut Self) -> String) -> String {
            let n = 1 + self.0.below(3);
            (0..n).map(|_| item(self)).collect::<Vec<_>>().join(", ")
        }

        /// A primary: a constant, a call, a field or a parenthesized expression.
        fn primary(&mut self, depth: usize) -> String {
            match if depth == 0 {
                self.0.below(2)
            } else {
                self.0.below(5)
            } {
                0 => self.constant(),
                1 => self.pick(FIELDS).into(),
                2 => {
                    let name = self.pick(CALLS);
                    let args = if self.chance(15) {
                        String::new()
                    } else {
                        self.list(|g| g.expr(depth - 1))
                    };
                    format!("{name}({args})")
                }
                3 => format!("({})", self.expr(depth - 1)),
                _ => self.pick(FIELDS).into(),
            }
        }

        /// An operator expression: a predicate, a sign, arithmetic or a primary.
        fn operand(&mut self, depth: usize) -> String {
            match if depth == 0 { 3 } else { self.0.below(6) } {
                0 => {
                    let subject = self.primary(depth - 1);
                    if self.chance(40) {
                        let not = if self.chance(30) { "not " } else { "" };
                        let op = self.pick(&["in", "in~"]);
                        let values = self.list(|g| g.expr(depth - 1));
                        format!("{subject} {not}{op} ({values})")
                    } else {
                        let op = self.pick(&[":", "like", "like~", "regex", "regex~"]);
                        let values = if self.chance(40) {
                            format!("({})", self.list(Self::constant))
                        } else {
                            self.constant()
                        };
                        format!("{subject} {op} {values}")
                    }
                }
                1 => {
                    let sign = self.pick(&["-", "+", "- "]);
                    format!("{sign}{}", self.operand(depth - 1))
                }
                2 => {
                    let n = 2 + self.0.below(3);
                    let mut out = self.operand(depth - 1);
                    for _ in 1..n {
                        let op = self.pick(&["+", "-", "*", "/", "%"]);
                        out = format!("{out} {op} {}", self.operand(depth - 1));
                    }
                    out
                }
                _ => self.primary(depth.saturating_sub(1)),
            }
        }

        /// An expression: `or`, `and`, `not`, lineage, a comparison or an operand.
        pub fn expr(&mut self, depth: usize) -> String {
            if depth == 0 {
                return self.operand(0);
            }
            match self.0.below(8) {
                0 | 1 => {
                    let n = 2 + self.0.below(3);
                    let op = self.pick(&["or", "and"]);
                    (0..n)
                        .map(|_| self.expr(depth - 1))
                        .collect::<Vec<_>>()
                        .join(&format!(" {op} "))
                }
                2 => format!("not {}", self.expr(depth - 1)),
                3 if self.chance(30) => {
                    let relation = self.pick(RELATIONS);
                    format!("{relation} of {}", self.subquery(depth - 1))
                }
                3..=5 => {
                    let op = self.pick(&["==", "!=", "<", "<=", ">", ">=", ":"]);
                    if op == ":" {
                        format!("{} : {}", self.pick(FIELDS), self.constant())
                    } else {
                        let left = self.operand(depth - 1);
                        format!("{left} {op} {}", self.operand(depth - 1))
                    }
                }
                _ => self.operand(depth - 1),
            }
        }

        fn filter(&mut self, depth: usize) -> String {
            let category = self.pick(CATEGORIES);
            format!("{category} where {}", self.expr(depth))
        }

        fn subquery(&mut self, depth: usize) -> String {
            let open = if self.chance(10) { "![" } else { "[" };
            format!("{open}{}]", self.filter(depth))
        }

        fn keys(&mut self) -> String {
            format!("by {}", self.list(|g| g.pick(FIELDS).to_string()))
        }

        fn term(&mut self, sequence: bool) -> String {
            let mut out = self.subquery(2);
            if self.chance(30) {
                out = format!("{out} {}", self.keys());
            }
            if sequence && self.chance(15) {
                out = format!("{out} with runs={}", 1 + self.0.below(5));
            }
            out
        }

        fn terms(&mut self, sequence: bool, least: usize) -> String {
            let n = least + self.0.below(3);
            (0..n)
                .map(|_| self.term(sequence))
                .collect::<Vec<_>>()
                .join("\n  ")
        }

        fn maxspan(&mut self) -> String {
            format!("with maxspan={}{}", 1 + self.0.below(30), self.pick(UNITS))
        }

        fn pipe(&mut self) -> String {
            let name = self.pick(PIPES);
            match name {
                "head" | "tail" => format!("| {name} {}", 1 + self.0.below(10)),
                "filter" => format!("| filter {}", self.expr(2)),
                "count" if self.chance(50) => "| count".into(),
                _ => format!("| {name} {}", self.list(|g| g.pick(FIELDS).to_string())),
            }
        }

        /// One query, its pipes, and now and then a comment.
        pub fn query(&mut self) -> String {
            let mut q = match self.0.below(6) {
                0 => {
                    let mut head = "sequence".to_string();
                    match self.0.below(4) {
                        0 => head = format!("{head} {}", self.keys()),
                        1 => head = format!("{head} {}", self.maxspan()),
                        2 => head = format!("{head} {} {}", self.keys(), self.maxspan()),
                        _ => head = format!("{head} {} {}", self.maxspan(), self.keys()),
                    }
                    let mut q = format!("{head}\n  {}", self.terms(true, 2));
                    if self.chance(20) {
                        q = format!("{q}\nuntil {}", self.term(true));
                    }
                    q
                }
                1 => {
                    let by = if self.chance(70) {
                        self.keys()
                    } else {
                        String::new()
                    };
                    format!("sample {by}\n  {}", self.terms(false, 2))
                }
                2 if self.chance(40) => {
                    let by = if self.chance(50) {
                        self.keys()
                    } else {
                        String::new()
                    };
                    let mut q = format!("join {by}\n  {}", self.terms(false, 2));
                    if self.chance(20) {
                        q = format!("{q}\nuntil {}", self.term(false));
                    }
                    q
                }
                _ => self.filter(3),
            };
            for _ in 0..self.0.below(3) {
                q = format!("{q} {}", self.pipe());
            }
            if self.chance(10) {
                q = format!("/* lead */ {q} // tail");
            }
            q
        }
    }
}

/// Queries composed by the generator: the valid side of the gate beyond the corpus. The queries
/// the old engine rejects count on the broken side. `OPENTIDE_GEN_SEEDS` (default `11`) and
/// `OPENTIDE_GEN_SCALE` (default 1) pick the seeds and the number.
#[test]
fn generated_queries_match_tree_sitter() {
    let scale: usize = std::env::var("OPENTIDE_GEN_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let (old, new) = (old(), new());
    for seed in env_list("OPENTIDE_GEN_SEEDS", "11") {
        let mut rng = rng::Rng::new(seed);
        let mut generator = generated::Gen(&mut rng);
        let files: Vec<Source> = (0..150 * scale)
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
        report_line(&format!("generated seed {seed}"), &report);
        assert_gates(&report);
    }
}
