//! The pure-Rust parser against the tree-sitter implementation it replaces
//! (`tests/legacy`, verbatim), on `opentide_parse::differential`, over every
//! Kibana KQL query in the repository's corpora, every prefix, seeded token
//! mutations and random sentences.
//!
//! Gates: a query tree-sitter parses without an error gives identical
//! diagnostics, highlight tokens, ECS diagnostics, fields, hover and
//! completions (at sampled offsets); a broken one keeps its verdict.
//! `OPENTIDE_KUERY_DIFF=<file>` writes the JSON report; `OPENTIDE_KUERY_SEED=<n>`
//! picks another seed (default 1).

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

#[allow(
    dead_code,
    reason = "a verbatim copy of the old crate; not every item is compared"
)]
mod legacy;

use opentide_core::{Diagnostic, codes};
use opentide_parse::differential::{Config, Engine, Source, Surfaces, assert_gates, run};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A JSON string literal's value (`"..."` with `\"`, `\\`, `\n`, `\t`, `\uXXXX`).
fn json_string(s: &str) -> String {
    let s = s.trim();
    let inner = s.get(1..s.len().saturating_sub(1)).unwrap_or("");
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(c);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Rust string literals (`"..."`) in a source file, unescaped roughly.
fn rust_strings(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r#""((?:[^"\\\n]|\\.)*)""#).expect("regex");
    re.captures_iter(text)
        .map(|c| json_string(&format!("\"{}\"", &c[1])))
        .filter(|s| !s.is_empty() && s.len() < 400)
        .collect()
}

/// Broken queries of the diagnostic-quality comparison.
const BROKEN: &[&str] = &[
    "(a:1 or b:2",
    "message:\"failed login",
    "process.name:",
    "a:1 and",
    "a:1 or ",
    "user:{ name:x",
    "bytes >",
    "a:1)",
    "a:1 b:2",
    "not",
    "f:(a or b",
    "a:(b or )",
    "a:{}",
    "a and (b:",
    "f:()",
    ":x",
    "a:1 and or b:2",
    "C:\\Windows",
];

/// Every file the run starts from.
fn sources() -> Vec<Source> {
    let root = repo();
    let mut texts: BTreeSet<(String, String)> = BTreeSet::new();
    let mut add = |origin: &str, text: String| {
        texts.insert((origin.to_owned(), text));
    };
    // Corpus fixtures: the body, and each line.
    let dir = root.join("crates/testdata/corpus/kuery");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("the corpus")
        .map(|e| e.expect("an entry").path())
        .collect();
    entries.sort();
    for path in entries {
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
    // OpenSearch Dashboards' cases and their fault twins.
    let tsv = std::fs::read_to_string(
        root.join("crates/testdata/conformance/external/kuery-opensearch-dashboards/cases.tsv"),
    )
    .expect("the cases");
    for line in tsv.lines().filter(|l| !l.starts_with('#')) {
        if let Some(q) = line.split('\t').nth(1) {
            let q = json_string(q);
            if let Some(i) = q.find(':') {
                add("osd/twin", format!("{}:){}", &q[..i], &q[i + 1..]));
            }
            add("osd", q);
        }
    }
    // String literals of the old crate's tests (verbatim) and the LSP's.
    for file in [
        "crates/opentide-kuery/tests/legacy/mod.rs",
        "crates/opentide-kuery/tests/legacy/ecs.rs",
        "crates/opentide-kuery/tests/opensearch_dashboards_cases.rs",
        "crates/opentide-analysis/tests/goldens.rs",
        "crates/opentide-analysis/tests/deep_queries.rs",
        "crates/opentide-analysis/src/ecs.rs",
    ] {
        let text = std::fs::read_to_string(root.join(file)).expect("a source file");
        for s in rust_strings(&text) {
            add(file, s);
        }
    }
    // `query:` lines of the Elastic fixtures.
    for dir in ["tests/fixtures/elastic", "tests/fixtures/tide_corpus"] {
        for path in yaml_files(&root.join(dir)) {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for line in text.lines() {
                if let Some(q) = line.trim().strip_prefix("query: ") {
                    let q = q.trim();
                    add(
                        "fixtures",
                        if q.starts_with('"') {
                            json_string(q)
                        } else {
                            q.trim_matches('\'').to_owned()
                        },
                    );
                }
            }
        }
    }
    // Kibana's own verdict file, when present (tests/kibana_oracle.rs).
    if let Ok(path) = std::env::var("OPENTIDE_KUERY_VERDICTS")
        && let Ok(text) = std::fs::read_to_string(path)
    {
        for line in text.lines() {
            if let Some(q) = line.split('\t').nth(1) {
                add("kibana", json_string(q));
            }
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

/// Clauses of every construct the corpus uses, valid each on its own.
const CLAUSES: &[&str] = &[
    "a:1",
    "process.name:\"cmd.exe\"",
    "source.port >= 1024",
    "bytes < 10",
    "x:(a or b)",
    "x:(a and not b)",
    "user:{ name:x and id:1 }",
    "f:*",
    "not g:2",
    "(h:1 and i:2)",
    "msg:foo bar",
    "t:true",
    "n:null",
    "w:a*b",
    "free",
    "\"quoted text\"",
    "e:a\\:b",
    "e:\\u00e9",
    "p:/a/b",
    "k:or",
];

/// Valid queries composed from [`CLAUSES`]: every pair joined by each
/// operator, and triples with the first two grouped, in both cases of the
/// operator and with odd spacing, so the differential reaches past the corpus.
fn generated() -> Vec<String> {
    let ops = [" and ", " or ", " AND ", " Or ", " and not ", "\tor\n"];
    let mut out = Vec::new();
    for (i, a) in CLAUSES.iter().enumerate() {
        for (j, b) in CLAUSES.iter().enumerate() {
            let op = ops[(i + j) % ops.len()];
            out.push(format!("{a}{op}{b}"));
            let c = CLAUSES[(i * 7 + j * 3) % CLAUSES.len()];
            let op2 = ops[(i * 5 + j) % ops.len()];
            out.push(format!("({a}{op}{b}){op2}{c}"));
            out.push(format!("not ({a}{op2}{c})"));
        }
    }
    out
}

fn yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                out.push(p);
            }
        }
    }
    out.sort();
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

fn tokens(t: &[opentide_highlight::HighlightToken]) -> String {
    t.iter().fold(String::new(), |mut out, t| {
        let _ = write!(out, "{}..{}={} ", t.span.start, t.span.end, t.capture);
        out
    })
}

fn completions(c: &[opentide_core::CompletionItem]) -> String {
    format!("{c:?}")
}

/// The tree-sitter engine. It reports a keyword's missing whitespace twice
/// (its walk visits both a node and its anonymous child of the same kind);
/// the pure-Rust engine reports it once, which is the correct behaviour.
/// The duplicates are collapsed here, and counted by the test, so the gate
/// compares what a user sees once.
struct Old;

/// Duplicate diagnostics the old engine reported, collapsed by [`Old`].
static COLLAPSED: AtomicUsize = AtomicUsize::new(0);

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        let r = legacy::analyze(input);
        let mut diagnostics = r.diagnostics;
        let before = diagnostics.len();
        diagnostics.dedup_by(|a, b| a == b && a.message.starts_with("Kibana needs whitespace"));
        COLLAPSED.fetch_add(before - diagnostics.len(), Ordering::Relaxed);
        vec![
            ("diagnostics".to_owned(), show(&diagnostics)),
            ("highlight".to_owned(), tokens(&r.tokens)),
            ("ecs".to_owned(), show(&legacy::ecs_diagnostics(input))),
            ("fields".to_owned(), format!("{:?}", legacy::fields(input))),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![
            (
                "hover".to_owned(),
                format!("{:?}", legacy::hover(input, offset)),
            ),
            (
                "completions".to_owned(),
                completions(&legacy::completions(input, offset)),
            ),
        ]
    }
}

/// The pure-Rust engine, through the crate's public functions.
struct New;

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        let r = opentide_kuery::analyze(input);
        vec![
            ("diagnostics".to_owned(), show(&r.diagnostics)),
            ("highlight".to_owned(), tokens(&r.tokens)),
            (
                "ecs".to_owned(),
                show(&opentide_kuery::ecs_diagnostics(input)),
            ),
            (
                "fields".to_owned(),
                format!("{:?}", opentide_kuery::fields(input)),
            ),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![
            (
                "hover".to_owned(),
                format!("{:?}", opentide_kuery::hover(input, offset)),
            ),
            (
                "completions".to_owned(),
                completions(&opentide_kuery::completions(input, offset)),
            ),
        ]
    }
}

/// Valid: tree-sitter found no syntax error, which is exactly when the
/// analysis reports no "KQL ..." parse error.
fn verdict(surfaces: &Surfaces) -> bool {
    let parse = format!("{}|", codes::KUERY_PARSE_ERROR);
    surfaces
        .iter()
        .find(|(name, _)| name == "diagnostics")
        .is_none_or(|(_, text)| {
            !text.lines().any(|l| {
                l.starts_with(&parse) && l.split('|').nth(3).is_some_and(|m| m.starts_with("KQL"))
            })
        })
}

/// Token byte ranges: runs of word characters, or one punctuation character
/// (what a reader sees as a unit; the mutations delete, swap and duplicate
/// them).
fn token_ranges(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        let word = !c.is_whitespace() && !"():<>{}\"".contains(c);
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
    "b",
    ":",
    " ",
    "(",
    ")",
    "{",
    "}",
    "<",
    "<=",
    ">",
    ">=",
    "\"",
    "\\",
    "*",
    " and ",
    " or ",
    "not ",
    "and",
    "or",
    "not",
    "x.y",
    "1",
    "\\:",
    "\t",
    "\u{a0}",
    "é",
    "?",
    "~",
    "[",
    "]",
    "TO",
    "event.category",
    "process.name",
    "source.port",
    "true",
    "null",
];

#[test]
fn pure_rust_parser_matches_tree_sitter() {
    let files = sources();
    // `OPENTIDE_DIFF_SCALE=full`: 40 mutations a file, 3,000 sentences, 40
    // prefixes and 32 offsets, run before every push. The default, CI's, takes
    // 5 mutations a file and 10 prefixes, well under CI's 300 s test limit.
    // `OPENTIDE_DIFF_SEEDS=1,2,3` runs several seeds (default 1).
    let full = std::env::var("OPENTIDE_DIFF_SCALE").is_ok_and(|s| s == "full");
    let seeds: Vec<u64> = std::env::var("OPENTIDE_DIFF_SEEDS")
        .or_else(|_| std::env::var("OPENTIDE_KUERY_SEED"))
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
            // No fewer inputs than CI ran before the full scale existed
            // (12,823 a seed).
            config.sentences = 3_000;
            config.mutations_per_input = 5;
            config.max_prefixes = 10;
            config.max_offsets = 32;
        }
        let report = run(&Old, &New, &files, &config);
        eprintln!(
            "seed {seed}, scale {}",
            if full { "full" } else { "sample" }
        );
        eprintln!(
            "kuery differential: {} inputs, {} valid, {} broken; valid differences {}, verdict changes {}, broken-input changes {}",
            report.inputs,
            report.valid,
            report.inputs - report.valid,
            report.total(opentide_parse::differential::Class::Valid),
            report.total(opentide_parse::differential::Class::Verdict),
            report.total(opentide_parse::differential::Class::Broken),
        );
        eprintln!(
            "old duplicate keyword-spacing diagnostics collapsed: {}",
            COLLAPSED.load(Ordering::Relaxed)
        );
        if let Ok(path) = std::env::var("OPENTIDE_KUERY_DIFF") {
            std::fs::write(format!("{path}.{seed}"), report.to_json_string())
                .expect("the report file");
        }
        assert_gates(&report);
    }
}

/// The highlight golden (`crates/testdata/highlight/kuery/query.json`, the
/// query of `goldens.rs`' `kuery_golden`): both engines give its tokens,
/// span and capture, and the query is among the differential's sources.
#[test]
fn the_highlight_golden_is_covered() {
    let root = repo();
    let goldens = std::fs::read_to_string(root.join("crates/opentide-analysis/tests/goldens.rs"))
        .expect("goldens.rs");
    let block = &goldens[goldens.find("fn kuery_golden").expect("kuery_golden")..];
    let query = rust_strings(&block[..block.find("\n}").expect("its end")])
        .into_iter()
        .last()
        .expect("the golden query");
    let golden = std::fs::read_to_string(root.join("crates/testdata/highlight/kuery/query.json"))
        .expect("the golden");
    // `"start": n, "end": m` of each span, then its capture, in order.
    let numbers = regex::Regex::new(
        r#""span":\s*\{\s*"start":\s*(\d+),\s*"end":\s*(\d+)[\s\S]*?"capture":\s*"([^"]+)""#,
    )
    .expect("regex");
    let expected = numbers
        .captures_iter(&golden)
        .fold(String::new(), |mut out, c| {
            let _ = write!(out, "{}..{}={} ", &c[1], &c[2], &c[3]);
            out
        });
    assert!(!expected.is_empty());
    assert_eq!(
        tokens(&legacy::analyze(&query).tokens),
        expected,
        "old engine"
    );
    assert_eq!(
        tokens(&opentide_kuery::analyze(&query).tokens),
        expected,
        "new engine"
    );
    assert!(
        sources().iter().any(|s| s.text == query),
        "the golden query is a source"
    );
}
