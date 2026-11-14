//! EXPERIMENT (exp/pure-rust-parser-kuery): the pure-Rust parser against the
//! tree-sitter implementation it replaces (`tests/legacy`, verbatim), over
//! every Kibana KQL query in the repository's corpora, every prefix of each
//! (broken queries), and seeded random mutations.
//!
//! Queries tree-sitter parses without an error must give identical
//! diagnostics, highlight tokens, ECS diagnostics, fields, hover (at every
//! offset) and completions. Broken queries are counted by what differs;
//! `OPENTIDE_KUERY_DIFF=<file>` writes each difference there.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]
#![expect(clippy::format_collect, reason = "test output, not a hot path")]

#[allow(
    dead_code,
    reason = "a verbatim copy of the old crate; not every item is compared"
)]
mod legacy;

use opentide_core::{Diagnostic, codes};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A JSON string literal's value (`"..."` with `\"`, `\\`, `\n`, `\t`, `\uXXXX`).
fn json_string(s: &str) -> String {
    let s = s.trim();
    let inner = &s[1..s.len() - 1];
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
    let re = regex::Regex::new(r#""((?:[^"\\\n]|\\.)*)""#).unwrap();
    re.captures_iter(text)
        .map(|c| json_string(&format!("\"{}\"", &c[1])))
        .filter(|s| !s.is_empty() && s.len() < 400)
        .collect()
}

/// A difference where the new engine is right: the old reported a
/// keyword's missing whitespace twice.
const ACCEPTED_DUPLICATE: &str = "old duplicate keyword_spacing (fixed)";

/// The query's verdict (any error) differs: what Kibana would say.
const VERDICT: &str = "VERDICT (error or not) differs";

/// The broken queries of the diagnostic-quality comparison.
pub const BROKEN: &[&str] = &[
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

fn base_inputs() -> BTreeSet<String> {
    let root = repo();
    let mut out = BTreeSet::new();
    // Corpus fixtures: the body, and each line.
    let dir = root.join("crates/testdata/corpus/kuery");
    for entry in std::fs::read_dir(&dir).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        let body: Vec<&str> = text.lines().skip(1).collect();
        out.insert(body.join("\n"));
        out.extend(body.iter().map(|l| (*l).to_string()));
    }
    // OpenSearch Dashboards' cases and their fault twins.
    let tsv = std::fs::read_to_string(
        root.join("crates/testdata/conformance/external/kuery-opensearch-dashboards/cases.tsv"),
    )
    .unwrap();
    for line in tsv.lines().filter(|l| !l.starts_with('#')) {
        if let Some(q) = line.split('\t').nth(1) {
            let q = json_string(q);
            if let Some(i) = q.find(':') {
                out.insert(format!("{}:){}", &q[..i], &q[i + 1..]));
            }
            out.insert(q);
        }
    }
    // String literals of the crate's tests, the old ones and the LSP's.
    for file in [
        "crates/opentide-kuery/src/lib.rs",
        "crates/opentide-kuery/src/ecs.rs",
        "crates/opentide-kuery/tests/opensearch_dashboards_cases.rs",
        "crates/opentide-analysis/tests/goldens.rs",
        "crates/opentide-analysis/tests/deep_queries.rs",
        "crates/opentide-analysis/src/ecs.rs",
    ] {
        out.extend(rust_strings(
            &std::fs::read_to_string(root.join(file)).unwrap(),
        ));
    }
    // `query:` lines of the Elastic fixtures.
    for dir in ["tests/fixtures/elastic", "tests/fixtures/tide_corpus"] {
        for path in walk(&root.join(dir)) {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for line in text.lines() {
                if let Some(q) = line.trim().strip_prefix("query: ") {
                    let q = q.trim();
                    out.insert(if q.starts_with('"') {
                        json_string(q)
                    } else {
                        q.trim_matches('\'').to_string()
                    });
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
                out.insert(json_string(q));
            }
        }
    }
    out.extend(BROKEN.iter().map(|s| (*s).to_string()));
    out
}

fn walk(dir: &Path) -> Vec<PathBuf> {
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
    out
}

/// A small deterministic generator (xorshift).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

const PIECES: &[&str] = &[
    "a", "b", ":", " ", "(", ")", "{", "}", "<", "<=", ">", ">=", "\"", "\\", "*", " and ", " or ",
    "not ", "and", "or", "not", "x.y", "1", "\\:", "\t", "\u{a0}", "é", "?", "~", "[", "]", "TO",
];

fn derived(base: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for q in base {
        // Every prefix.
        for (i, _) in q.char_indices().skip(1) {
            out.insert(q[..i].to_string());
        }
        // Three mutations: insert or delete a piece.
        for _ in 0..3 {
            let cuts: Vec<usize> = q.char_indices().map(|(i, _)| i).chain([q.len()]).collect();
            let at = cuts[rng.below(cuts.len())];
            let piece = PIECES[rng.below(PIECES.len())];
            out.insert(format!("{}{piece}{}", &q[..at], &q[at..]));
            if cuts.len() > 1 {
                let k = rng.below(cuts.len() - 1);
                out.insert(format!("{}{}", &q[..cuts[k]], &q[cuts[k + 1]..]));
            }
        }
    }
    // Random sentences of pieces.
    for _ in 0..3000 {
        let n = 1 + rng.below(8);
        out.insert((0..n).map(|_| PIECES[rng.below(PIECES.len())]).collect());
    }
    out.retain(|q| !base.contains(q));
    out
}

fn show(d: &[Diagnostic]) -> String {
    d.iter()
        .map(|d| {
            format!(
                "  {} {:?} {}:{}-{}:{} {:?}{}\n",
                d.code,
                d.severity,
                d.range.start.line,
                d.range.start.character,
                d.range.end.line,
                d.range.end.character,
                d.message,
                d.suggestion
                    .as_ref()
                    .map_or(String::new(), |s| format!(" -> {s:?}"))
            )
        })
        .collect()
}

/// What differs between the two implementations for `q`.
fn differences(q: &str, every_offset: bool) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let old = legacy::analyze(q);
    let new = opentide_kuery::analyze(q);
    let rejects = |d: &[Diagnostic]| {
        d.iter()
            .any(|d| d.severity == opentide_core::Severity::Error)
    };
    if rejects(&old.diagnostics) != rejects(&new.diagnostics) {
        out.push((
            VERDICT,
            format!("old rejects: {}", rejects(&old.diagnostics)),
        ));
    }
    if old.diagnostics != new.diagnostics {
        let parse = |d: &[Diagnostic]| -> Vec<Diagnostic> {
            d.iter()
                .filter(|d| d.code != codes::KUERY_PARSE_ERROR || !d.message.starts_with("KQL"))
                .cloned()
                .collect()
        };
        let first = |d: &[Diagnostic]| -> Option<Diagnostic> {
            d.iter()
                .find(|d| d.code == codes::KUERY_PARSE_ERROR && d.message.starts_with("KQL"))
                .cloned()
        };
        let (fo, fn_) = (first(&old.diagnostics), first(&new.diagnostics));
        // tree-sitter's walk visits the `(and)` node and its anonymous `and`
        // child, both of kind "and": the old engine reports a keyword's
        // spacing twice.
        let mut deduped = old.diagnostics.clone();
        deduped.dedup_by(|a, b| a == b && a.message.starts_with("Kibana needs whitespace"));
        let detail = format!(
            "old:\n{}new:\n{}",
            show(&old.diagnostics),
            show(&new.diagnostics)
        );
        if deduped == new.diagnostics {
            out.push((ACCEPTED_DUPLICATE, detail));
        } else {
            match (&fo, &fn_) {
                // The new message names what was expected (an addition).
                (Some(o), Some(n))
                    if o.message != n.message.split("; expected").next().unwrap_or("") =>
                {
                    out.push(("first syntax error: message", detail.clone()));
                }
                (Some(o), Some(n)) if o.range != n.range => {
                    out.push(("first syntax error: range only", detail.clone()));
                }
                (Some(_), None) | (None, Some(_)) => {
                    out.push(("first syntax error: one side only", detail.clone()));
                }
                _ => {}
            }
            let mut rest_old = parse(&old.diagnostics);
            rest_old.dedup_by(|a, b| a == b && a.message.starts_with("Kibana needs whitespace"));
            if rest_old != parse(&new.diagnostics) {
                out.push(("secondary diagnostics", detail));
            }
        }
    }
    if old.tokens != new.tokens {
        let t = |v: &[opentide_highlight::HighlightToken]| -> String {
            v.iter()
                .map(|t| format!("{}..{}={} ", t.span.start, t.span.end, t.capture))
                .collect()
        };
        out.push((
            "highlight tokens",
            format!("old: {}\nnew: {}", t(&old.tokens), t(&new.tokens)),
        ));
    }
    if legacy::ecs_diagnostics(q) != opentide_kuery::ecs_diagnostics(q) {
        out.push((
            "ecs diagnostics",
            format!(
                "old:\n{}new:\n{}",
                show(&legacy::ecs_diagnostics(q)),
                show(&opentide_kuery::ecs_diagnostics(q))
            ),
        ));
    }
    if legacy::fields(q) != opentide_kuery::fields(q) {
        out.push((
            "fields",
            format!("{:?} vs {:?}", legacy::fields(q), opentide_kuery::fields(q)),
        ));
    }
    let offsets: Vec<usize> = if every_offset {
        (0..=q.len()).collect()
    } else {
        vec![q.len() / 2, q.len()]
    };
    for at in offsets {
        let (o, n) = (legacy::hover(q, at), opentide_kuery::hover(q, at));
        if o != n {
            out.push(("hover", format!("at {at}: {o:?} vs {n:?}")));
            break;
        }
        if legacy::completions(q, at) != opentide_kuery::completions(q, at) {
            out.push(("completions", format!("at {at}")));
            break;
        }
    }
    out
}

#[test]
fn pure_rust_parser_matches_tree_sitter() {
    let base = base_inputs();
    let derived = derived(&base);
    let mut log = String::new();
    let mut tally: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let (mut valid, mut broken) = (0, 0);
    let mut valid_mismatches = Vec::new();
    for (set, inputs, every_offset) in [("base", &base, true), ("derived", &derived, false)] {
        for q in inputs {
            let ok = !legacy::tree_has_error(q);
            if ok {
                valid += 1;
            } else {
                broken += 1;
            }
            let class = if ok { "valid" } else { "broken" };
            let found = differences(q, every_offset);
            for (kind, detail) in &found {
                *tally.entry((class, kind)).or_default() += 1;
                let _ = writeln!(log, "=== [{set} {class} {kind}] {q:?}\n{detail}");
            }
            if ok && found.iter().any(|(k, _)| *k != ACCEPTED_DUPLICATE) {
                valid_mismatches.push(q.clone());
            }
        }
    }
    let mismatched: usize = tally.values().sum();
    eprintln!(
        "differential: {} inputs ({} base, {} derived), {valid} valid, {broken} broken; differences: {tally:?} ({mismatched})",
        base.len() + derived.len(),
        base.len(),
        derived.len()
    );
    if let Ok(path) = std::env::var("OPENTIDE_KUERY_DIFF") {
        std::fs::write(path, &log).unwrap();
    }
    assert!(
        !tally.keys().any(|(_, k)| *k == VERDICT),
        "a query's verdict differs: {tally:?}"
    );
    assert!(
        valid_mismatches.is_empty(),
        "{} valid queries differ: {:?}",
        valid_mismatches.len(),
        &valid_mismatches[..valid_mismatches.len().min(20)]
    );
}

/// Median of per-query mean times, in µs, of `f` over `inputs`.
fn median_us(inputs: &[String], rounds: u32, mut f: impl FnMut(&str)) -> (f64, f64) {
    let mut per_query: Vec<f64> = inputs
        .iter()
        .map(|q| {
            f(q);
            let started = std::time::Instant::now();
            for _ in 0..rounds {
                f(q);
            }
            started.elapsed().as_secs_f64() * 1e6 / f64::from(rounds)
        })
        .collect();
    per_query.sort_by(f64::total_cmp);
    let total: f64 = per_query.iter().sum();
    (per_query[per_query.len() / 2], total)
}

/// Measurement: `cargo test --release -p opentide-kuery --test differential
/// -- --ignored --nocapture timing`.
#[test]
#[ignore = "a measurement, run by hand in release"]
fn timing() {
    let all: Vec<String> = base_inputs().into_iter().collect();
    let valid: Vec<String> = all
        .iter()
        .filter(|q| !legacy::tree_has_error(q))
        .cloned()
        .collect();
    let chain = vec!["source.port:1"; 2000].join(" or ");
    for (name, set) in [("valid corpus", &valid), ("whole corpus", &all)] {
        let rounds = 200;
        let (old_parse, old_parse_total) = median_us(set, rounds, |q| {
            let masked = legacy::mask_trailing_keywords(q);
            std::hint::black_box(opentide_syntax::parse(
                opentide_core::LanguageId::Kuery,
                &masked,
            ));
        });
        let (new_parse, new_parse_total) = median_us(set, rounds, |q| {
            std::hint::black_box(opentide_kuery::parser::parse(q, true));
        });
        let (old_an, old_an_total) = median_us(set, rounds, |q| {
            std::hint::black_box(legacy::analyze(q));
        });
        let (new_an, new_an_total) = median_us(set, rounds, |q| {
            std::hint::black_box(opentide_kuery::analyze(q));
        });
        eprintln!(
            "{name} ({} queries): parse median old {old_parse:.2} µs / new {new_parse:.2} µs (sum {old_parse_total:.0} / {new_parse_total:.0}); analyze median old {old_an:.2} µs / new {new_an:.2} µs (sum {old_an_total:.0} / {new_an_total:.0})",
            set.len()
        );
    }
    let one = [chain];
    let (o, _) = median_us(&one, 20, |q| {
        std::hint::black_box(legacy::analyze(q));
    });
    let (n, _) = median_us(&one, 20, |q| {
        std::hint::black_box(opentide_kuery::analyze(q));
    });
    eprintln!("2000-term or chain: analyze old {o:.0} µs / new {n:.0} µs");
}

/// Measurement: the first syntax error of each broken query, old and new.
#[test]
#[ignore = "a measurement, run by hand"]
fn diagnostic_quality() {
    let first = |d: Vec<Diagnostic>| {
        d.into_iter()
            .find(|d| d.code == codes::KUERY_PARSE_ERROR)
            .map_or_else(
                || "(none)".to_string(),
                |d| {
                    format!(
                        "{} [{}..{}]",
                        d.message, d.range.start.character, d.range.end.character
                    )
                },
            )
    };
    for q in BROKEN {
        eprintln!(
            "| `{q}` | {} | {} |",
            first(legacy::analyze(q).diagnostics),
            first(opentide_kuery::analyze(q).diagnostics)
        );
    }
}
