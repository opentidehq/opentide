//! The lexer over every CQL file of the corpora: it tiles them, and reads the tokens
//! tree-sitter's context-aware lexer and its C scanner read.
//!
//! The lexer is private to the crate (production still runs tree-sitter), so this test
//! includes its source.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/syntax.rs"]
mod syntax;

use std::path::{Path, PathBuf};
use syntax::SyntaxKind as K;

/// Every `.cql` file under `crates/testdata`.
fn corpus() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "cql") {
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

fn text<'s>(source: &'s str, l: &opentide_parse::Lexeme) -> &'s str {
    &source[std::ops::Range::<usize>::from(l.range)]
}

/// The query of a corpus file: the `# prod:<rule>` tag on its first line is not part of it.
fn query(file: &str) -> &str {
    match file.split_once('\n') {
        Some((tag, rest)) if tag.starts_with("# prod:") => rest,
        _ => file,
    }
}

/// The leaves of the tree-sitter tree, as byte ranges, and whether it has no error.
fn leaves(source: &str) -> Option<Vec<(usize, usize)>> {
    let tree = opentide_syntax::parse(opentide_core::LanguageId::Cql, source)?;
    if opentide_syntax::first_error(tree.root_node()).is_some() {
        return None;
    }
    let mut leaves = Vec::new();
    opentide_syntax::walk(tree.root_node(), |node| {
        if node.child_count() == 0 && node.end_byte() > node.start_byte() {
            leaves.push((node.start_byte(), node.end_byte()));
        }
    });
    Some(leaves)
}

/// The significant lexemes of `source` as byte ranges (whitespace is not a leaf).
fn ours(source: &str) -> Vec<(usize, usize)> {
    lexer::lex(source)
        .iter()
        .filter(|l| l.kind != K::WHITESPACE.raw())
        .map(|l| (usize::from(l.range.start()), usize::from(l.range.end())))
        .collect()
}

/// The first place two token lists differ, with the text around it.
fn first_difference(source: &str, ours: &[(usize, usize)], theirs: &[(usize, usize)]) -> String {
    let at = ours.iter().zip(theirs).position(|(a, b)| a != b);
    let i = at.unwrap_or_else(|| ours.len().min(theirs.len()));
    let show = |tokens: &[(usize, usize)]| {
        tokens.get(i).map_or_else(
            || "(none)".to_owned(),
            |&(s, e)| format!("{s}..{e} {:?}", &source[s..e]),
        )
    };
    format!(
        "token {i}: ours {}, tree-sitter {}",
        show(ours),
        show(theirs)
    )
}

#[test]
fn lexemes_tile_every_corpus_file_and_valid_ones_have_no_error_token() {
    let files = corpus();
    assert!(files.len() > 150, "found {} corpus files", files.len());
    for path in files {
        let source = std::fs::read_to_string(&path).unwrap_or_default();
        let lexemes = lexer::lex(&source);
        let joined: String = lexemes.iter().map(|l| text(&source, l)).collect();
        assert_eq!(joined, source, "{} is not tiled", path.display());
        let name = path.to_string_lossy();
        let broken = name.contains("__invalid") || name.contains(".broken.");
        let errors = lexemes
            .iter()
            .filter(|l| l.kind == K::ERROR_TOKEN.raw() || l.kind == K::PATTERN_ERROR.raw())
            .count();
        assert!(broken || errors == 0, "{name}: {errors} error tokens");
    }
}

/// The modes reproduce what tree-sitter's lexer read, token for token, on every corpus file it
/// parses without an error.
#[test]
fn tokens_are_the_leaves_tree_sitter_read() {
    let mut compared = 0;
    let mut failures = Vec::new();
    for path in corpus() {
        let file = std::fs::read_to_string(&path).unwrap_or_default();
        let source = query(&file);
        let Some(theirs) = leaves(source) else {
            continue;
        };
        let ours = ours(source);
        if ours != theirs {
            failures.push(format!(
                "{}: {}",
                path.display(),
                first_difference(source, &ours, &theirs)
            ));
        }
        compared += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(compared > 100, "compared {compared} files");
}

/// splitmix64: a small deterministic generator, so a failure replays.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).unwrap_or(1)).unwrap_or(0)
    }
}

/// Tokens a mutation inserts: every shape the modes tell apart.
const SAMPLES: &[&str] = &[
    "*",
    "-",
    "+",
    "/",
    "//",
    "/*",
    "*/",
    "/x/i",
    "a=",
    "a =",
    "a !=",
    "a <",
    "a like",
    " like ",
    "$q()",
    "$\"q\"(",
    "?p",
    "?{p=1}",
    "?\"p\"",
    "f(",
    "f(x)",
    "in(x)",
    "!in(x)",
    "not f(",
    "a:",
    "a:b(",
    "x :=",
    ":=",
    "=~",
    "<=>",
    "=>",
    "==",
    "!",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    ",",
    ";",
    "|",
    "\"s\"",
    "\"s",
    "#t",
    "#t[0]",
    "a[0]",
    "a[",
    "1",
    "-1",
    "1.5e+3",
    "5min",
    "ERROR",
    "and",
    "OR",
    "not",
    "true",
    "case {",
    "match {",
    " match ",
    "https://x/*",
    "a/b",
    "a*b",
    "a:b",
    "x.y",
    "\\",
    "~",
    "\u{a0}",
    "é",
    "😀",
];

/// A source and, for each token, where it starts and ends.
fn token_ranges(source: &str) -> Vec<(usize, usize)> {
    lexer::lex(source)
        .iter()
        .map(|l| (usize::from(l.range.start()), usize::from(l.range.end())))
        .collect()
}

/// Inputs made from the corpus: prefixes, token deletions, duplications, swaps, insertions of
/// a sample, and two lines of two files joined.
fn mutants(seed: u64, per_file: usize) -> Vec<String> {
    let mut rng = Rng(seed);
    let files: Vec<String> = corpus()
        .iter()
        .map(|p| query(&std::fs::read_to_string(p).unwrap_or_default()).to_owned())
        .collect();
    let lines: Vec<&str> = files
        .iter()
        .flat_map(|f| f.lines())
        .filter(|l| !l.trim().is_empty())
        .collect();
    let mut out = Vec::new();
    for source in &files {
        let tokens = token_ranges(source);
        if tokens.is_empty() {
            continue;
        }
        for _ in 0..per_file {
            let i = rng.below(tokens.len());
            let (start, end) = tokens[i];
            let text = &source[start..end];
            let mutant = match rng.below(6) {
                0 => source[..end].to_owned(),
                1 => format!("{}{}", &source[..start], &source[end..]),
                2 => format!("{}{text}{}", &source[..end], &source[end..]),
                3 => {
                    let (s2, e2) = tokens[rng.below(tokens.len())];
                    let (a, b) = if start <= s2 {
                        ((start, end), (s2, e2))
                    } else {
                        ((s2, e2), (start, end))
                    };
                    if a.1 > b.0 {
                        continue;
                    }
                    format!(
                        "{}{}{}{}{}",
                        &source[..a.0],
                        &source[b.0..b.1],
                        &source[a.1..b.0],
                        &source[a.0..a.1],
                        &source[b.1..]
                    )
                }
                4 => {
                    let sample = SAMPLES[rng.below(SAMPLES.len())];
                    format!("{}{sample}{}", &source[..start], &source[start..])
                }
                _ => {
                    let sample = SAMPLES[rng.below(SAMPLES.len())];
                    format!("{}{sample}{}", &source[..end], &source[end..])
                }
            };
            out.push(mutant);
        }
    }
    // Random sentences of corpus tokens and samples, glued or spaced.
    let pool: Vec<&str> = files
        .iter()
        .flat_map(|f| token_ranges(f).into_iter().map(move |(s, e)| &f[s..e]))
        .filter(|t| !t.trim().is_empty() && t.len() < 40 && !t.contains('\n'))
        .chain(SAMPLES.iter().copied())
        .collect();
    for _ in 0..per_file * 100 {
        let mut sentence = String::new();
        for _ in 0..(2 + rng.below(8)) {
            sentence.push_str(pool[rng.below(pool.len())]);
            if rng.below(4) != 0 {
                sentence.push(' ');
            }
        }
        out.push(sentence);
    }
    for _ in 0..per_file * 20 {
        let a = lines[rng.below(lines.len())];
        let b = lines[rng.below(lines.len())];
        let join = [" | ", "\n", " ", " and ", " or "][rng.below(5)];
        out.push(format!("{a}{join}{b}"));
    }
    out
}

/// What the mutated inputs say about the modes: wherever tree-sitter reads one without an
/// error, the lexer reads the same tokens.
#[test]
fn mutated_inputs_lex_as_tree_sitter_reads_them() {
    let seeds: Vec<u64> = std::env::var("OPENTIDE_CQL_SEEDS")
        .ok()
        .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![1, 2, 3]);
    let per_file = std::env::var("OPENTIDE_CQL_PER_FILE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let (mut compared, mut failures) = (0, Vec::new());
    for seed in seeds {
        for source in mutants(seed, per_file) {
            let Some(theirs) = leaves(&source) else {
                continue;
            };
            compared += 1;
            let ours = ours(&source);
            if ours != theirs && failures.len() < 40 {
                failures.push(format!(
                    "{source:?}: {}",
                    first_difference(&source, &ours, &theirs)
                ));
            }
        }
    }
    println!("{compared} inputs read without an error by tree-sitter, all lexed alike");
    assert!(
        failures.is_empty(),
        "{compared} compared\n{}",
        failures.join("\n")
    );
    assert!(compared > 500, "compared only {compared} mutants");
}
