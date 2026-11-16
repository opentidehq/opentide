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
//! OPENTIDE_MUT_PER_FILE=40`; its numbers are in the PR body.

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
    "sequence", "sample", "join", "by", "with", "maxspan", "=", "5m", "until", "where", "any",
    "process", "\"network\"", "[", "![", "]", "|", "head", "tail", "unique", "1", "2.5", "and",
    "or", "not", "in", "in~", "like", "like~", "regex", "regex~", ":", "==", "!=", "<", "<=", ">",
    ">=", "+", "-", "*", "/", "%", "(", ")", ",", ".", "?", "a", "b.c", "`q r`", "x[0]",
    "\"s\"", "\"*.exe\"", "'t'", "?\"r\"", "\"\"\"t\"\"\"", "null", "true", "false",
    "startsWith~", "cidrMatch", "length", "descendant", "of", "runs", "TRUE", "AND",
    "// c\n", "/* c */", "/* a /* b */ c */", "\n",
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
