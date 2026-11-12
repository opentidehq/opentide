//! `docs/internal/unsafe.md` lists every `unsafe` in the workspace's Rust,
//! with why it is sound. This test counts the `unsafe` keywords in each Rust
//! file (comments, string and character literals left out) and fails when a
//! file's count differs from the number of rows the listing gives it, so the
//! listing cannot fall behind the code.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

fn root() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
}

/// The directories whose Rust the listing covers: the workspace's members,
/// `fuzz/` and the publishing placeholders (workspaces of their own, also
/// ours).
const DIRECTORIES: &[&str] = &[
    "crates",
    "analysis",
    "bindings",
    "xtask",
    "fuzz",
    "publishing",
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in std::fs::read_dir(dir).map_err(|err| format!("{}: {err}", dir.display()))? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // Build output, libFuzzer's corpora and crash artifacts.
            if !matches!(name, "target" | "corpus" | "artifacts" | "node_modules")
                && !name.starts_with('.')
            {
                rust_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// `text` with comments and the contents of string and character literals
/// replaced by spaces, so that only code is left to search.
fn code_only(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    while i < chars.len() {
        let start = i;
        let c = chars[i];
        if c == '/' && at(i + 1) == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && at(i + 1) == '*' {
            let mut depth = 0;
            loop {
                if i >= chars.len() {
                    break;
                }
                if chars[i] == '/' && at(i + 1) == '*' {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && at(i + 1) == '/' {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            gap(&mut out, &chars[start..i.min(chars.len())]);
        } else if c == 'r' && (at(i + 1) == '"' || at(i + 1) == '#') && raw_prefix(&chars, i) {
            // A raw string: r"…", r#"…"#, br"…", cr#"…"#, … (or an
            // identifier ending in r, which `raw_prefix` refuses).
            let mut j = i + 1;
            let mut hashes = 0;
            while at(j) == '#' {
                hashes += 1;
                j += 1;
            }
            if at(j) == '"' {
                j += 1;
                loop {
                    if j >= chars.len() {
                        break;
                    }
                    if chars[j] == '"' && (1..=hashes).all(|k| at(j + k) == '#') {
                        j += 1 + hashes;
                        break;
                    }
                    j += 1;
                }
                i = j;
                gap(&mut out, &chars[start..i.min(chars.len())]);
            } else {
                out.push(c);
                i += 1;
            }
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            gap(&mut out, &chars[start..i.min(chars.len())]);
        } else if c == '\'' && (at(i + 2) == '\'' || at(i + 1) == '\\') {
            // A character literal ('x', '\n', '\u{..}'); a lifetime has no
            // closing quote and stays.
            i += 1;
            while i < chars.len() && chars[i] != '\'' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            gap(&mut out, &chars[start..i.min(chars.len())]);
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// A space for a skipped comment or literal, keeping its line breaks so
/// that line numbers in the result are the source's.
fn gap(out: &mut String, skipped: &[char]) {
    out.push(' ');
    out.extend(skipped.iter().filter(|c| **c == '\n'));
}

fn ident_before(chars: &[char], i: usize) -> bool {
    i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_')
}

/// Whether the `r` at `i` starts a raw string literal: alone (`r"`), or
/// after the `b` of a raw byte string or the `c` of a raw C string, and not
/// inside an identifier.
fn raw_prefix(chars: &[char], i: usize) -> bool {
    if !ident_before(chars, i) {
        return true;
    }
    matches!(chars[i - 1], 'b' | 'c') && !ident_before(chars, i - 1)
}

/// How many times the keyword `unsafe` stands in `code` as a word of its own.
fn unsafe_keywords(code: &str) -> usize {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices("unsafe")
        .filter(|(at, _)| {
            let before = code[..*at].chars().next_back();
            let after = code[at + "unsafe".len()..].chars().next();
            !before.is_some_and(word) && !after.is_some_and(word)
        })
        .count()
}

/// The 1-based lines of `code` where the keyword `unsafe` stands as a word.
fn unsafe_lines(code: &str) -> Vec<usize> {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices("unsafe")
        .filter(|(at, _)| {
            let before = code[..*at].chars().next_back();
            let after = code[at + "unsafe".len()..].chars().next();
            !before.is_some_and(word) && !after.is_some_and(word)
        })
        .map(|(at, _)| code[..at].matches('\n').count() + 1)
        .collect()
}

/// How far above an `unsafe` its `SAFETY:` comment may stand: past the
/// attributes and doc lines of the item it is on.
const SAFETY_WINDOW: usize = 8;

/// The rows of the listing's table, counted by their file column.
fn listed() -> Result<BTreeMap<String, usize>, Box<dyn Error>> {
    let path = root().join("docs/internal/unsafe.md");
    let text =
        std::fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))?;
    let section = text
        .split_once("## Every site")
        .map(|(_, rest)| rest)
        .ok_or("docs/internal/unsafe.md has no `## Every site` section")?;
    let section = section.split("\n## ").next().unwrap_or(section);
    let mut counts = BTreeMap::new();
    for line in section.lines() {
        let Some(cell) = line.strip_prefix("| `") else {
            continue;
        };
        let Some((file, _)) = cell.split_once('`') else {
            continue;
        };
        *counts.entry(file.to_string()).or_insert(0) += 1;
    }
    Ok(counts)
}

fn found() -> Result<BTreeMap<String, usize>, Box<dyn Error>> {
    let root = root();
    let mut files = Vec::new();
    for dir in DIRECTORIES {
        rust_files(&root.join(dir), &mut files)?;
    }
    let mut counts = BTreeMap::new();
    for file in files {
        let text = std::fs::read_to_string(&file)?;
        let count = unsafe_keywords(&code_only(&text));
        if count > 0 {
            let relative = file
                .strip_prefix(&root)?
                .to_string_lossy()
                .replace('\\', "/");
            counts.insert(relative, count);
        }
    }
    Ok(counts)
}

#[test]
fn every_unsafe_is_listed_with_its_reason() -> TestResult {
    let listed = listed()?;
    let found = found()?;
    assert!(
        !found.is_empty(),
        "no unsafe found: the scan is broken (the FFI in opentide-syntax has some)"
    );
    assert_eq!(
        found, listed,
        "left: the `unsafe` keywords in each file; right: the rows docs/internal/unsafe.md \
         gives it. Add or remove the rows, with why each site is sound"
    );
    Ok(())
}

#[test]
fn every_unsafe_has_a_safety_comment_just_above() -> TestResult {
    let root = root();
    let mut files = Vec::new();
    for dir in DIRECTORIES {
        rust_files(&root.join(dir), &mut files)?;
    }
    let mut missing = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)?;
        let lines: Vec<&str> = text.lines().collect();
        for line in unsafe_lines(&code_only(&text)) {
            let from = line.saturating_sub(SAFETY_WINDOW + 1);
            if !lines[from..line].iter().any(|l| l.contains("SAFETY:")) {
                missing.push(format!("{}:{line}", file.strip_prefix(&root)?.display()));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "an `unsafe` with no `// SAFETY:` comment in the {SAFETY_WINDOW} lines above it: {missing:?}"
    );
    Ok(())
}

#[test]
fn the_scan_keeps_line_numbers() {
    let code = code_only("/* a\nb */ \"x\ny\" r#\"\n\"#\nunsafe {}");
    assert_eq!(unsafe_lines(&code), [5]);
}

#[test]
fn the_scan_skips_comments_and_literals() {
    let code = code_only(
        "// unsafe\n/* unsafe /* nested */ unsafe */ let s = \"unsafe\"; \
         let r = r#\"unsafe \"x\" \"#; let c = '\"'; fn f<'a>() {} unsafe { x() }",
    );
    assert_eq!(unsafe_keywords(&code), 1, "{code}");
    // Raw byte and C strings, whose quotes inside must not end them.
    let code = code_only(
        "let s = br#\"a\"b\"#; unsafe { f() } let t = br#\"x \"unsafe\" y\"#; \
         let u = cr\"unsafe\"; let v = b\"unsafe\"; let w = b'\"'; let bar = 1;",
    );
    assert_eq!(unsafe_keywords(&code), 1, "{code}");
    assert_eq!(
        unsafe_keywords("unsafe_code falco_unsafe unsafe(no_mangle)"),
        1
    );
}
