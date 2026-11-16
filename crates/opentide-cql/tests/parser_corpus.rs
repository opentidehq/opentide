//! The parser over every CQL file of the corpora: the verdict (a syntax error or none) is the
//! one tree-sitter gives, on the files and on mutants of them.
//!
//! The parser is private to the crate (production still runs tree-sitter), so this test
//! includes its source.

#![expect(dead_code, reason = "the included modules are used in part")]

#[path = "../src/lexer.rs"]
mod lexer;
#[path = "../src/parser.rs"]
mod parser;
#[path = "../src/syntax.rs"]
mod syntax;

use opentide_parse::ErrorKind;
use std::path::{Path, PathBuf};
use syntax::SyntaxKind;

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

/// The query of a corpus file: the `# prod:<rule>` tag on its first line is not part of it.
fn query(file: &str) -> &str {
    match file.split_once('\n') {
        Some((tag, rest)) if tag.starts_with("# prod:") => rest,
        _ => file,
    }
}

fn tree_sitter_fails(source: &str) -> bool {
    opentide_syntax::parse(opentide_core::LanguageId::Cql, source)
        .is_none_or(|tree| opentide_syntax::first_error(tree.root_node()).is_some())
}

fn ours_fails(source: &str) -> bool {
    !parser::parse(source).1.errors.is_empty()
}

#[test]
fn every_corpus_file_has_the_verdict_tree_sitter_gives() {
    let mut compared = 0;
    let mut failures = Vec::new();
    for path in corpus() {
        let file = std::fs::read_to_string(&path).unwrap_or_default();
        let source = query(&file);
        let (theirs, ours) = (tree_sitter_fails(source), ours_fails(source));
        if theirs != ours {
            let tree = parser::parse(source).1;
            failures.push(format!(
                "{}: tree-sitter {}, ours {} {:?}",
                path.display(),
                if theirs { "fails" } else { "parses" },
                if ours { "fails" } else { "parses" },
                tree.errors.first().map(|e| (&e.message, e.gap))
            ));
        }
        compared += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(compared > 150, "compared {compared} files");
}

/// The tree is lossless: its text is the source.
#[test]
fn the_tree_holds_every_byte_of_every_corpus_file() {
    for path in corpus() {
        let file = std::fs::read_to_string(&path).unwrap_or_default();
        let source = query(&file);
        let (root, _) = parser::parse(source);
        assert_eq!(root.text().to_string(), source, "{}", path.display());
    }
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

/// Tokens a mutation inserts: every shape the modes and the grammar tell apart.
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
    "case",
    "x match { * => y }",
    "correlate(a: { b=1 }, c: { d=2 | x <=> a.y })",
    "x := a + b * -c",
    "[a := 1, b]",
    "f(a=1, b)",
    "{ a | b }",
];

fn token_ranges(source: &str) -> Vec<(usize, usize)> {
    lexer::lex(source)
        .iter()
        .filter(|l| {
            !matches!(
                SyntaxKind::from_raw(l.kind),
                SyntaxKind::WHITESPACE | SyntaxKind::LINE_COMMENT | SyntaxKind::BLOCK_COMMENT
            )
        })
        .map(|l| (usize::from(l.range.start()), usize::from(l.range.end())))
        .collect()
}

/// Inputs made from the corpus: prefixes, token deletions, duplications, swaps, insertions of
/// a sample, random sentences of corpus tokens and two lines of two files joined.
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
            let mutant = match rng.below(7) {
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
                5 => {
                    let sample = SAMPLES[rng.below(SAMPLES.len())];
                    format!("{}{sample}{}", &source[..start], &source[end..])
                }
                _ => {
                    let sample = SAMPLES[rng.below(SAMPLES.len())];
                    format!("{}{sample}{}", &source[..end], &source[end..])
                }
            };
            out.push(mutant);
        }
    }
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

/// The smallest source (by dropping runs of tokens) that still has the two engines disagree.
fn reduce(source: &str) -> String {
    let differs = |s: &str| tree_sitter_fails(s) != ours_fails(s);
    let mut cur = source.to_owned();
    loop {
        let tokens = token_ranges(&cur);
        let mut reduced = false;
        'sizes: for size in [64usize, 16, 4, 1] {
            let mut i = 0;
            while i < tokens.len() {
                let j = (i + size).min(tokens.len());
                let cand = format!("{}{}", &cur[..tokens[i].0], &cur[tokens[j - 1].1..]);
                if cand.len() < cur.len() && differs(&cand) {
                    cur = cand;
                    reduced = true;
                    break 'sizes;
                }
                i += size;
            }
        }
        if !reduced {
            return cur;
        }
    }
}

/// Mutants of the corpus get the verdict tree-sitter gives; the listed ones are the
/// reviewed exceptions of NOTES.md.
#[test]
fn mutated_inputs_have_the_verdict_tree_sitter_gives() {
    let seeds: Vec<u64> = std::env::var("OPENTIDE_CQL_SEEDS")
        .ok()
        .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![1, 2, 3]);
    let per_file = std::env::var("OPENTIDE_CQL_PER_FILE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let (mut compared, mut failures, mut total) = (0usize, Vec::new(), 0usize);
    for seed in seeds {
        for source in mutants(seed, per_file) {
            compared += 1;
            let (theirs, ours) = (tree_sitter_fails(&source), ours_fails(&source));
            if theirs != ours {
                total += 1;
                if failures.len() < 60 {
                    let shown = reduce(&source);
                    let line = format!(
                        "tree-sitter {}, ours {}: {shown:?}",
                        if theirs { "fails" } else { "parses" },
                        if ours { "fails" } else { "parses" },
                    );
                    if !failures.contains(&line) {
                        failures.push(line);
                    }
                }
            }
        }
    }
    println!("{compared} mutants, {total} verdicts differ");
    assert!(
        failures.is_empty(),
        "{total} differ\n{}",
        failures.join("\n")
    );
}

/// Nothing the parser reports is a toolkit guard on a small input.
#[test]
fn no_guard_fires_on_small_inputs() {
    for path in corpus() {
        let file = std::fs::read_to_string(&path).unwrap_or_default();
        let (_, tree) = parser::parse(query(&file));
        assert!(
            tree.errors.iter().all(|e| e.kind == ErrorKind::Syntax),
            "{}",
            path.display()
        );
    }
}

/// Inputs the mutation runs found tree-sitter and the parser disagreeing on, each reduced to
/// a minimal source: `(source, tree-sitter and the parser report an error)`. Each fails
/// without the fix it pins.
#[test]
fn pinned_regressions() {
    for (source, fails) in [
        // A negated call, `match`, `<=>` after a filter are filters there, and fail.
        ("foo !in(x)", true),
        ("foo | !in(x)", false),
        ("foo not in(x)", true),
        ("foo x match { * => a }", true),
        // `%` is an operator after an operand.
        ("x := (p * 1) % t", false),
        // A saved query's `(` and a parameter's name touch the sigil.
        ("$q (a=b)", true),
        ("? \"x\"", true),
        // The scanner reads any word before `:=` as an assignment field.
        ("#type OR:= \"fortigate\"", false),
        ("case := (@timestamp)", false),
        ("x a like := 1", false),
        // After a filter only a plain word starts an assignment.
        ("ERROR \"Success\":= \"fortigate\"", true),
        ("upperhost a[0]:= upper", true),
        ("a b := 1", false),
        // A call after an assignment's parenthesised value, then a filter.
        ("x := (a + b)f(a1, b) *", false),
        // `true` and `false` are keywords, not names.
        ("true = x", true),
        ("a=~f(true=1)", true),
        ("f(a: { }, false: { })", true),
        // `case` is a word inside parentheses.
        ("(x case )", false),
        // A reserved word is no parameter default.
        ("?{a=and}", true),
        // A comment longer than a saved query name wins.
        ("f({$/*x y()}, a)\n/* c */", true),
    ] {
        assert_eq!(
            tree_sitter_fails(source),
            fails,
            "tree-sitter on {source:?}"
        );
        assert_eq!(ours_fails(source), fails, "the parser on {source:?}");
    }
}
