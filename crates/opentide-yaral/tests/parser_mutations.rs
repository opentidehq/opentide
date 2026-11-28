//! The parser on seeded word mutations of every corpus file: it does not panic
//! and its tree is lossless. A mutation deletes, duplicates, swaps or replaces
//! a token, inserts a sample, drops or adds a bracket, or drops a quote.
//!
//! Forty mutations per file and three seeds with `OPENTIDE_DIFF_SCALE=full`
//! (`OPENTIDE_DIFF_SEEDS` picks the seeds); a sample of one seed by default,
//! well under CI's limit.

#![expect(
    clippy::string_slice,
    reason = "a test: a slice off a char boundary panics, and a panic is a failed test"
)]

use opentide_yaral::parse_facts::{lex_spans, parse_is_lossless};
use std::path::{Path, PathBuf};

const SAMPLES: &[&str] = &[
    "$e",
    "$e.a",
    "$e.principal.hostname",
    "%l",
    "%t.c",
    "#e",
    "and",
    "or",
    "not",
    "in",
    "regex",
    "nocase",
    "any",
    "all",
    "of",
    "if",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ":",
    ".",
    "=",
    "!=",
    "<",
    "+",
    "-",
    "*",
    "/",
    "%",
    "!",
    "1",
    "1.5",
    "5m",
    "\"s\"",
    "`r`",
    "/x/",
    "rule",
    "events:",
    "match:",
    "condition:",
    "over",
    "by",
    "before",
    "every",
    "cross join",
    "f(1)",
    "a.b",
    "\n",
    "//c\n",
    "/*c*/",
    " ",
];

fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "yaral") {
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

/// splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n.max(1) as u64)).unwrap_or(0)
    }
}

/// One mutation of `text` at the boundaries of its tokens.
fn mutate(text: &str, rng: &mut Rng) -> String {
    let tokens: Vec<(usize, usize)> = lex_spans(text)
        .into_iter()
        .filter(|(_, _, trivia)| !trivia)
        .map(|(s, e, _)| (s, e))
        .collect();
    if tokens.is_empty() {
        return format!("{text}{}", SAMPLES[rng.below(SAMPLES.len())]);
    }
    let (start, end) = tokens[rng.below(tokens.len())];
    let sample = SAMPLES[rng.below(SAMPLES.len())];
    let mut out = String::with_capacity(text.len() + 8);
    match rng.below(7) {
        0 => {
            out.push_str(&text[..start]);
            out.push_str(&text[end..]);
        }
        1 => {
            out.push_str(&text[..end]);
            out.push(' ');
            out.push_str(&text[start..]);
        }
        2 => {
            let (s2, e2) = tokens[rng.below(tokens.len())];
            let (a, b) = if start <= s2 {
                ((start, end), (s2, e2))
            } else {
                ((s2, e2), (start, end))
            };
            if a.1 > b.0 {
                return text.to_owned();
            }
            out.push_str(&text[..a.0]);
            out.push_str(&text[b.0..b.1]);
            out.push_str(&text[a.1..b.0]);
            out.push_str(&text[a.0..a.1]);
            out.push_str(&text[b.1..]);
        }
        3 => {
            out.push_str(&text[..start]);
            out.push_str(sample);
            out.push_str(&text[end..]);
        }
        4 => {
            out.push_str(&text[..start]);
            out.push_str(sample);
            out.push(' ');
            out.push_str(&text[start..]);
        }
        5 => {
            out.push_str(&text[..end]);
            out.push_str(sample);
            out.push_str(&text[end..]);
        }
        _ => {
            // Drop a quote or a bracket character, or add a stray one.
            let at = text[start..end]
                .find(['"', '`', '(', ')', '[', ']', '{', '}'])
                .map(|i| start + i);
            match at {
                Some(i) => {
                    out.push_str(&text[..i]);
                    out.push_str(&text[i + 1..]);
                }
                None => {
                    out.push_str(&text[..end]);
                    out.push_str([")", "(", "]", "\"", "`"][rng.below(5)]);
                    out.push_str(&text[end..]);
                }
            }
        }
    }
    out
}

#[test]
fn mutations_of_the_corpus_parse_losslessly() {
    let full = std::env::var("OPENTIDE_DIFF_SCALE").is_ok_and(|v| v == "full");
    let seeds = std::env::var("OPENTIDE_DIFF_SEEDS").unwrap_or_else(|_| "1".to_owned());
    let (stride, per_file) = if full { (1, 40) } else { (3, 8) };
    let mut checked = 0usize;
    for seed in seeds
        .split(',')
        .filter_map(|s| s.trim().parse::<u64>().ok())
    {
        for (n, path) in corpus().into_iter().enumerate().step_by(stride) {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let mut rng = Rng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ n as u64);
            for _ in 0..per_file {
                let mutated = mutate(&text, &mut rng);
                assert!(
                    parse_is_lossless(&mutated),
                    "{}: not lossless",
                    path.display()
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 100, "{checked} mutations");
}
