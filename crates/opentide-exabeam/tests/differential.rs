//! The pure-Rust tree against the tree-sitter grammar it replaces
//! (`tests/legacy`, verbatim), on `opentide_parse::differential`, over every
//! Exabeam query in the repository's corpora, every prefix, seeded token
//! mutations and generated queries.
//!
//! What tree-sitter did here is highlight (the spans of `highlights.scm`).
//! Diagnostics, hover and completions read the verdict parser
//! (`src/check.rs`), not a tree, so they are the same code on both sides and
//! not compared.
//!
//! Gates: a query whose tree-sitter parse has no error gives identical
//! highlight spans, and a clean tree from the new parser; a broken one keeps
//! its verdict: the new parser reports an error exactly when tree-sitter does.
//! `OPENTIDE_EXABEAM_DIFF=<file>` writes the JSON report;
//! `OPENTIDE_EXABEAM_SEED=<n>` picks the first seed (default 1) and
//! `OPENTIDE_DIFF_SEEDS=<k>` how many run from it.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

#[allow(
    dead_code,
    reason = "a verbatim copy of the old crate; not every item is compared"
)]
mod legacy;

use opentide_parse::differential::{Class, Config, Engine, Source, Surfaces, assert_gates, run};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ops::Range;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// A JSON string literal's value, or a YAML single-quoted scalar's.
fn unquote(s: &str) -> String {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return inner.replace("''", "'");
    }
    let Some(inner) = s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) else {
        return s.to_owned();
    };
    serde_json::from_str::<String>(&format!("\"{inner}\"")).unwrap_or_else(|_| inner.to_owned())
}

/// Rust string literals in a source file, roughly unescaped.
fn rust_strings(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r#""((?:[^"\\\n]|\\.)*)""#).expect("regex");
    re.captures_iter(text)
        .map(|c| unquote(&format!("\"{}\"", &c[1])))
        .filter(|s| !s.is_empty() && s.len() < 400)
        .collect()
}

fn files(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .extension()
                .is_some_and(|e| extensions.iter().any(|x| e == *x))
            {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Broken queries of the quality comparison.
const BROKEN: &[&str] = &[
    "a:(b, c",
    "a:\"b",
    "(a AND b",
    "a AND",
    "a:[1 TO ",
    "a IN \"T\".",
    "SELECT a, FROM t",
    "FOREACH a [b",
    "a | ",
    "| a",
    "a:b)",
    "GROUP-BY",
    "LIMIT x",
    "rgx(\"a\"",
];

/// Every file the run starts from.
fn sources() -> Vec<Source> {
    let mut texts: BTreeSet<(String, String)> = BTreeSet::new();
    let mut add = |origin: &str, text: String| {
        texts.insert((origin.to_owned(), text));
    };
    // Corpus fixtures: the body (the first line is the `prod:` tag), and each line.
    for path in files(&repo().join("crates/testdata/corpus/exabeam"), &["exabeam"]) {
        let text = std::fs::read_to_string(&path).expect("a fixture");
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let body: Vec<&str> = text.lines().skip(1).collect();
        add(&format!("corpus/{name}"), body.join("\n"));
        for line in body {
            add(&format!("corpus/{name}#line"), line.to_owned());
        }
    }
    // The specification's conformance queries and probes.
    let conformance = repo().join("crates/testdata/conformance/exabeam");
    for path in files(&conformance, &["exabeam"]) {
        let text = std::fs::read_to_string(&path).expect("a query");
        add("conformance", text.clone());
        for line in text.lines() {
            add("conformance#line", line.to_owned());
        }
    }
    let reference: serde_json::Value =
        serde_json::from_str(&read("crates/testdata/conformance/exabeam/reference.json"))
            .expect("json");
    for q in reference["queries"].as_array().expect("queries") {
        if let Some(text) = q["text"].as_str() {
            add("reference", text.to_owned());
        }
    }
    for line in read("crates/testdata/conformance/exabeam/probes.tsv").lines() {
        if let Some((_, query)) = line.split_once('\t') {
            add("probes", query.replace('⏎', "\n").replace('⇥', "\t"));
        }
    }
    // The Exabeam fixtures of the CLI: `query:` lines.
    for path in files(&repo().join("tests/fixtures/exabeam"), &["yaml", "yml"]) {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for line in text.lines() {
            let line = line.trim().trim_start_matches("- ");
            if let Some(q) = line.strip_prefix("query:") {
                add("yaml", unquote(q));
            }
        }
    }
    // String literals of the crate's own tests.
    for file in [
        "crates/opentide-exabeam/src/tests.rs",
        "crates/opentide-exabeam/src/check.rs",
        "crates/opentide-exabeam/src/assist.rs",
        "crates/opentide-exabeam/tests/captures.rs",
        "crates/opentide-exabeam/tests/trees.rs",
        "crates/opentide-analysis/tests/goldens.rs",
        "crates/opentide-analysis/tests/deep_queries.rs",
    ] {
        for s in rust_strings(&read(file)) {
            add(file, s);
        }
    }
    for q in BROKEN {
        add("broken", (*q).to_owned());
    }
    for q in generated() {
        add("generated", q);
    }
    texts
        .into_iter()
        .map(|(name, text)| Source { name, text })
        .collect()
}

/// Terms of every construct, valid each on its own.
const TERMS: &[&str] = &[
    "user:\"alice\"",
    "user:alice",
    "user=alice",
    "user==alice",
    "user!=alice",
    "a.b-c:@d",
    "port:>1024",
    "port>=1024",
    "port=<5",
    "port<5",
    "n:-1.5",
    "ip:10.0.0.1",
    "ip:fe80::1",
    "ip:[10.0.0.0/8]",
    "time:[2026-01-01 TO 2026-02-01}",
    "time:{\"a\" TO *]",
    "flag:true",
    "flag:NULL",
    "x:(a, \"b\", 1, @c)",
    "cmd:rgx(\"a.*\")",
    "cmd:WLDi(\"*x*\", 1)",
    "nope(\"a\", b)",
    "user IN \"T\"",
    "user in 'T'.'C'",
    "free",
    "\"a phrase\"",
    "web*",
    "*",
    "10.1.2.3",
    "-x",
    "NOT a:b",
    "not not a",
    "(a OR b)",
    "(a and b c)",
];

/// Clause tails of the advanced form.
const CLAUSES: &[&str] = &[
    "",
    " SELECT a, b AS c",
    " select distinct *",
    " SELECT count(*) AS n, max(a), rgx_extract(a, \"x\") FROM t",
    " FROM t",
    " FROM t a:b",
    " WHERE a:b",
    " AS t",
    " GROUP-BY a, b",
    " order-by a ASC, b desc",
    " LIMIT 10",
];

/// Valid queries composed from [`TERMS`] and [`CLAUSES`], so the
/// differential reaches past the corpus.
fn generated() -> Vec<String> {
    let ops = [" AND ", " OR ", " ", "\tand\n", " AND NOT "];
    let mut out = Vec::new();
    for (i, a) in TERMS.iter().enumerate() {
        out.push(format!("FOREACH f [{a}] LIMIT 3"));
        for (j, b) in TERMS.iter().enumerate() {
            let op = ops[(i + j) % ops.len()];
            out.push(format!("{a}{op}{b}"));
            let c = TERMS[(i * 7 + j * 3) % TERMS.len()];
            let op2 = ops[(i * 5 + j) % ops.len()];
            out.push(format!("({a}{op}{b}){op2}{c}"));
            let tail = CLAUSES[(i + j * 5) % CLAUSES.len()];
            out.push(format!("{a}{op}{b}{tail}"));
            out.push(format!("{a}{tail} | {b}"));
        }
    }
    out
}

fn spans<'a>(spans: impl IntoIterator<Item = (usize, usize, &'a str)>) -> String {
    spans
        .into_iter()
        .fold(String::new(), |mut out, (start, end, capture)| {
            let _ = write!(out, "{start}..{end}={capture} ");
            out
        })
}

/// The tree-sitter engine.
struct Old;

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        vec![
            (
                "syntax_error".to_owned(),
                legacy::has_error(input).to_string(),
            ),
            (
                "highlight".to_owned(),
                spans(
                    legacy::captures(input)
                        .iter()
                        .map(|(s, c)| (s.start, s.end, c.as_str())),
                ),
            ),
        ]
    }
}

/// The pure-Rust engine, through the crate's public functions.
struct New;

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        vec![
            (
                "syntax_error".to_owned(),
                opentide_exabeam::tree_has_error(input).to_string(),
            ),
            (
                "highlight".to_owned(),
                spans(
                    opentide_exabeam::highlight_captures(input)
                        .iter()
                        .map(|(s, c)| (s.start, s.end, *c)),
                ),
            ),
        ]
    }
}

/// Valid: the engine's tree has no syntax error (tree-sitter's for the old
/// engine, the parser's for the new one).
fn verdict(surfaces: &Surfaces) -> bool {
    surfaces
        .iter()
        .find(|(name, _)| name == "syntax_error")
        .is_none_or(|(_, error)| error == "false")
}

/// Token byte ranges: runs of word characters, or one punctuation character.
fn token_ranges(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        let word = c.is_alphanumeric() || matches!(c, '_' | '.');
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
    "a", "b.c", "user", "vendor", " ", "(", ")", "[", "]", "{", "}", ",", ":", "=", "==", "!=",
    "<", "<=", ">", ">=", "\"", "'", "\\", "|", ".", "*", "@", "-", "/", " AND ", " OR ", "NOT ",
    "AND", "or", "not", "IN", "TO", "AS", "ASC", "SELECT", "FROM", "WHERE", "GROUP-BY", "ORDER-BY",
    "LIMIT", "FOREACH", "DISTINCT", "rgx(", "WLDi(", "count(", "1", "-2.5", "10.0.0.1", "true",
    "null", "\t", "\u{a0}", "é", "\n",
];

/// One seed and a sample by default (well under CI's limit); the full run
/// is `OPENTIDE_DIFF_SCALE=full OPENTIDE_DIFF_SEEDS=3`.
fn config_for<'a>(seed: u64, full: bool) -> Config<'a> {
    let mut config = Config::new(&verdict, &token_ranges, SAMPLES);
    config.seed = seed;
    config.max_examples = 40;
    config.max_offsets = 32;
    if full {
        config.sentences = 1_000;
        config.mutations_per_input = 40;
        config.max_prefixes = 12;
    } else {
        config.sentences = 300;
        config.mutations_per_input = 3;
        config.max_prefixes = 3;
    }
    config
}

#[test]
fn pure_rust_tree_matches_tree_sitter() {
    let full = std::env::var("OPENTIDE_DIFF_SCALE").is_ok_and(|s| s == "full");
    let seeds: u64 = std::env::var("OPENTIDE_DIFF_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let first: u64 = std::env::var("OPENTIDE_EXABEAM_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let mut files = sources();
    if !full {
        // Every fourth generated query: the pairs cover the same constructs.
        let mut n = 0usize;
        files.retain(|f| {
            n += 1;
            f.name != "generated" || n.is_multiple_of(4)
        });
    }
    for seed in first..first + seeds {
        let config = config_for(seed, full);
        let report = run(&Old, &New, &files, &config);
        eprintln!(
            "exabeam differential (seed {seed}, {}): {} inputs, {} valid, {} broken; valid differences {}, verdict changes {}, broken-input changes {}",
            if full { "full" } else { "ci" },
            report.inputs,
            report.valid,
            report.inputs - report.valid,
            report.total(Class::Valid),
            report.total(Class::Verdict),
            report.total(Class::Broken),
        );
        if let Ok(path) = std::env::var("OPENTIDE_EXABEAM_DIFF") {
            std::fs::write(format!("{path}.seed{seed}.json"), report.to_json_string())
                .expect("the report file");
        }
        assert_gates(&report);
    }
}
