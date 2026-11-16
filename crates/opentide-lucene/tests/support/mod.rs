//! What the differentials of this crate run on: every Lucene query of the
//! repository's corpora, the fault twins, the strings of the crate's tests,
//! and the token vocabulary of the mutations.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]
#![allow(dead_code, reason = "each test uses part of it")]

use opentide_parse::differential::Source;
use std::collections::BTreeSet;
use std::ops::Range;
use std::path::{Path, PathBuf};

pub fn repo() -> PathBuf {
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

fn files(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == extension) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Broken queries of the diagnostic-quality comparison.
const BROKEN: &[&str] = &[
    "(a:1 OR b:2",
    "message:\"failed login",
    "a:",
    "a AND",
    "AND a",
    "a:[1 TO",
    "a:[1 2]",
    "a:AND",
    "a)",
    "a:b:c",
    "a/b",
    "/unclosed",
    "a^",
    "a OR AND b",
    "NOT",
    "a:+b",
    "\\",
];

/// Every file the run starts from.
pub fn sources() -> Vec<Source> {
    let root = repo();
    let mut texts: BTreeSet<(String, String)> = BTreeSet::new();
    let mut add = |origin: &str, text: String| {
        texts.insert((origin.to_owned(), text));
    };
    // Corpus fixtures: the body, and each line (the first line is the tag).
    for path in files(&root.join("crates/testdata/corpus/lucene"), "lucene") {
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
    // Conformance, Carbon Black and oracle probes, and their fault twins.
    for dir in ["conformance/external", "oracles"] {
        for path in files(&root.join("crates/testdata").join(dir), "lucene") {
            let text = std::fs::read_to_string(&path).expect("a query file");
            let name = path
                .strip_prefix(&root)
                .map_or_else(|_| String::new(), |p| p.to_string_lossy().into_owned());
            add(&name, text.trim_end_matches('\n').to_owned());
        }
    }
    // Lucene's own cases.
    let tsv = std::fs::read_to_string(
        root.join("crates/testdata/conformance/external/lucene-queryparser/cases.tsv"),
    )
    .expect("the cases");
    for line in tsv.lines().filter(|l| !l.starts_with('#')) {
        if let Some(q) = line.split('\t').nth(1) {
            let mut out = String::new();
            let mut chars = q.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some('t') => out.push('\t'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some(o) => out.push(o),
                        None => out.push('\\'),
                    }
                } else {
                    out.push(c);
                }
            }
            add("queryparser", out);
        }
    }
    // String literals of the crate's own tests and sources, and the LSP's.
    let mut rust: Vec<PathBuf> = files(&root.join("crates/opentide-lucene/tests"), "rs");
    rust.extend(files(&root.join("crates/opentide-lucene/src"), "rs"));
    for file in [
        "crates/opentide-analysis/tests/goldens.rs",
        "crates/opentide-analysis/tests/deep_queries.rs",
        "crates/opentide-analysis/src/ecs.rs",
    ] {
        rust.push(root.join(file));
    }
    for path in rust {
        let text = std::fs::read_to_string(&path).expect("a source file");
        for s in rust_strings(&text) {
            add("rust", s);
        }
    }
    // `query:` lines of the Elastic fixtures.
    for dir in ["tests/fixtures/elastic", "tests/fixtures/tide_corpus"] {
        for ext in ["yaml", "yml"] {
            for path in files(&root.join(dir), ext) {
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
    "bytes:[100 TO 200}",
    "n:{* TO 5]",
    "x:(a OR b)",
    "x:(a AND NOT b)",
    "+a:1",
    "-b:2",
    "!c",
    "NOT d:e",
    "f:*",
    "w:a*b?",
    "r:/a.*b/",
    "/x[0-9]+/",
    "t:term~1",
    "p:\"a b\"~2",
    "b:x^2",
    "(g:1 h:2)^3",
    "e:a\\:b",
    "_exists_:host",
    "free",
    "\"quoted text\"",
    "u:\\u00e9",
    "&&",
    "path:C\\:\\Windows",
    "message:and",
];

/// Valid queries composed from [`CLAUSES`]: every pair joined by each
/// operator (or none), and triples with the first two grouped, so the
/// differential reaches past the corpus.
fn generated() -> Vec<String> {
    let ops = [
        " AND ",
        " OR ",
        " ",
        " && ",
        " || ",
        " AND NOT ",
        "\t",
        "\n",
    ];
    let mut out = Vec::new();
    for (i, a) in CLAUSES.iter().enumerate() {
        for (j, b) in CLAUSES.iter().enumerate() {
            let op = ops[(i + j) % ops.len()];
            out.push(format!("{a}{op}{b}"));
            let c = CLAUSES[(i * 7 + j * 3) % CLAUSES.len()];
            let op2 = ops[(i * 5 + j) % ops.len()];
            out.push(format!("({a}{op}{b}){op2}{c}"));
            out.push(format!("f:({a}{op2}{c})"));
        }
    }
    out
}

/// Token byte ranges: runs of word characters, or one punctuation character
/// (what a reader sees as a unit; the mutations delete, swap and duplicate
/// them).
pub fn token_ranges(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in text.char_indices() {
        let word = !c.is_whitespace() && !"():[]{}\"^~/".contains(c);
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

pub const SAMPLES: &[&str] = &[
    "a",
    "a:b",
    "a:",
    ":",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    "\"",
    "\"a b\"",
    "/",
    "/re/",
    "^",
    "^2",
    "~",
    "~1",
    "+",
    "-",
    "!",
    "+a",
    "-a",
    "!a",
    "&&",
    "||",
    "AND",
    "OR",
    "NOT",
    "and",
    "or",
    "TO",
    "[1 TO 2]",
    "{a TO b}",
    "*",
    "?",
    "a*",
    "a?b",
    "\\",
    "\\:",
    "\\ ",
    " ",
    "\t",
    "\u{a0}",
    "\u{3000}",
    "é",
    "event.category",
    "process.name",
    "\\/",
    "foo.*",
];
