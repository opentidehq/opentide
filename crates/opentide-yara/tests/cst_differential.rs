//! The CST's highlighting, folding and parenthesis pairs against the
//! tree-sitter engine they replace (#1225).
//!
//! The inputs are every YARA file of the repository, YARA-X's parser suite and
//! the conformance cases, each whole and mutated (a word deleted, doubled,
//! replaced or inserted, or the text cut), over several seeds. Where both
//! parsers accept the text, the two engines must agree on every token's
//! capture, every fold and every parenthesis pair, except for the inputs the
//! two grammars read differently by design: a `true` or `false` in an `of`
//! set, which tree-sitter's libyara grammar reads as a rule name (colour
//! `type`) and YARA-X as the boolean it is (`boolean`; YARA-X's `of-1.in`).
//! Where either refuses, the numbers are printed: a broken text has no verdict
//! to keep.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod legacy;

use opentide_yara::{editor, highlight, paren_pairs};
use std::path::{Path, PathBuf};
use yara_x_parser::Parser;
use yara_x_parser::ast::AST;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = read.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            files(&path, out);
        } else if path
            .extension()
            .is_some_and(|e| e == "yar" || e == "yara" || e == "in")
        {
            out.push(path);
        }
    }
}

fn corpus() -> Vec<String> {
    let mut paths = Vec::new();
    files(&root().join("crates/testdata"), &mut paths);
    let mut texts: Vec<String> = paths
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect();
    let cases = std::fs::read_to_string(root().join("crates/testdata/conformance/yara/cases.json"))
        .expect("cases.json");
    let json: serde_json::Value = serde_json::from_str(&cases).expect("json");
    for case in json["cases"].as_array().expect("cases") {
        if let Some(s) = case["source"].as_str() {
            texts.push(s.to_string());
        }
    }
    texts.sort();
    texts.dedup();
    texts
}

fn yara_x_accepts(source: &str) -> bool {
    AST::from(Parser::new(source.as_bytes()))
        .errors()
        .is_empty()
}

/// A tiny xorshift: the mutations are the same on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 >> 11).unwrap_or(0)
    }
}

/// Word boundaries of `s`: the starts and ends of runs of non-space characters.
fn words(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in s.char_indices() {
        match (c.is_whitespace(), start) {
            (false, None) => start = Some(i),
            (true, Some(b)) => {
                out.push((b, i));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(b) = start {
        out.push((b, s.len()));
    }
    out
}

const INSERTS: [&str; 12] = [
    "and", "(", ")", "$a", "{", "}", "of them", "1..2", "\"s\"", "/r/", "pe.x", "private",
];

fn mutate(s: &str, rng: &mut Rng) -> String {
    let w = words(s);
    if w.is_empty() {
        return s.to_string();
    }
    let (b, e) = w[rng.next() % w.len()];
    match rng.next() % 5 {
        0 => format!("{}{}", &s[..b], &s[e..]),
        1 => format!("{} {}", &s[..e], &s[b..]),
        2 => format!(
            "{}{}{}",
            &s[..b],
            INSERTS[rng.next() % INSERTS.len()],
            &s[e..]
        ),
        3 => format!(
            "{}{} {}",
            &s[..b],
            INSERTS[rng.next() % INSERTS.len()],
            &s[b..]
        ),
        _ => s[..b].to_string(),
    }
}

/// The old tokens, with a `true` or `false` that tree-sitter coloured as a
/// rule name read as the boolean YARA-X reads. The count is how many.
fn old_tokens(source: &str, by_design: &mut usize) -> Vec<(usize, usize, String)> {
    legacy::highlight(source)
        .iter()
        .map(|t| {
            let word = &source[t.span.start..t.span.end];
            let is_bool = word == "true" || word == "false";
            if t.capture == "type" && is_bool {
                *by_design += 1;
                (t.span.start, t.span.end, "boolean".to_string())
            } else {
                (t.span.start, t.span.end, t.capture.clone())
            }
        })
        .collect()
}

fn compare(source: &str, by_design: &mut usize, report: &mut Vec<String>) {
    let new_tokens: Vec<_> = highlight(source)
        .iter()
        .map(|t| (t.span.start, t.span.end, t.capture.clone()))
        .collect();
    let old_tokens = old_tokens(source, by_design);
    if new_tokens != old_tokens {
        let n: Vec<_> = new_tokens
            .iter()
            .filter(|t| !old_tokens.contains(t))
            .collect();
        let o: Vec<_> = old_tokens
            .iter()
            .filter(|t| !new_tokens.contains(t))
            .collect();
        report.push(format!("highlight: new only {n:?}, old only {o:?}"));
    }
    let (nf, of) = (editor::folding(source), legacy::folding(source));
    if nf != of {
        report.push(format!("folding: new {nf:?}, old {of:?}"));
    }
    let (np, op) = (paren_pairs(source), legacy::paren_pairs(source));
    if np != op {
        report.push(format!("parens: new {np:?}, old {op:?}"));
    }
}

const SEEDS: [u64; 4] = [
    0x9E37_79B9_7F4A_7C15,
    0xD1B5_4A32_D192_ED03,
    0x2545_F491_4F6C_DD1D,
    0x8BB8_4B93_962E_ACC9,
];

/// An environment variable as a number, or `default`.
fn env_number(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// CI runs one seed and 10 mutations per input (about 10 s in a debug build);
/// the full gate is `OPENTIDE_DIFF_SEEDS=4 OPENTIDE_DIFF_SCALE=40`.
#[test]
fn cst_agrees_with_tree_sitter_where_both_accept() {
    let seeds = env_number("OPENTIDE_DIFF_SEEDS", 1).clamp(1, SEEDS.len());
    let mutations = env_number("OPENTIDE_DIFF_SCALE", 10);
    let texts = corpus();
    assert!(texts.len() > 1_500, "{} inputs", texts.len());
    let (mut both, mut broken, mut skipped, mut by_design) = (0usize, 0usize, 0usize, 0usize);
    let mut failures = Vec::new();
    let mut run = |source: &str, label: &str| {
        let valid_new = yara_x_accepts(source);
        let valid_old = !legacy::has_error(source);
        if !(valid_new && valid_old) {
            if valid_new == valid_old {
                broken += 1;
            } else {
                skipped += 1;
            }
            return;
        }
        both += 1;
        let mut report = Vec::new();
        compare(source, &mut by_design, &mut report);
        if !report.is_empty() {
            failures.push(format!("{label}\n{source}\n  {}", report.join("\n  ")));
        }
    };
    for (i, text) in texts.iter().enumerate() {
        run(text, &format!("input {i}"));
        for seed in SEEDS.iter().take(seeds) {
            let mut rng = Rng(seed ^ (i as u64 + 1).wrapping_mul(0x1000_0000_01B3));
            for _ in 0..mutations {
                let m = mutate(text, &mut rng);
                run(&m, &format!("mutant of input {i}"));
            }
        }
    }
    eprintln!(
        "{} inputs; both accept {both}; both refuse {broken}; one refuses {skipped}; {by_design} booleans in `of` sets read as YARA-X reads them; {} differences",
        texts.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} differences, first ones:\n{}",
        failures.len(),
        failures
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n---\n")
    );
}
