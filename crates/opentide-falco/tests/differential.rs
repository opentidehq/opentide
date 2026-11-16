//! The pure-Rust tree against the tree-sitter grammar it replaces
//! (`tests/legacy`, verbatim), on `opentide_parse::differential`, over every
//! Falco condition in the repository's corpora, every prefix, seeded token
//! mutations and random sentences.
//!
//! What tree-sitter did here is highlight (the spans of `highlights.scm`),
//! `fields()` and the node `hover` reads (compared at sampled offsets).
//! Diagnostics and completions read libsinsp's parser (`src/parser.rs`), not a
//! tree, so they are the same code on both sides and not compared.
//!
//! Gates: a condition whose tree-sitter parse has no error gives identical
//! highlight spans and fields, and a clean tree from the new parser; a
//! broken one keeps its verdict: the new parser reports an error exactly when
//! tree-sitter does. `OPENTIDE_FALCO_DIFF=<file>` writes
//! the JSON report; `OPENTIDE_FALCO_SEED=<n>` picks the first seed (default 1)
//! and `OPENTIDE_DIFF_SEEDS=<k>` how many run from it.

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

/// Broken conditions of the quality comparison.
const BROKEN: &[&str] = &[
    "(a.b = c and (d.e in (f, g)",
    "a.b = c) and d",
    "a.b = \"c and d.e = f",
    "proc.name in (a, b",
    "proc.name = anyof (a, b",
    "proc.aname[2 = sshd",
    "tolower(proc.name = bash",
    "join(\",\", (a.b, ) = a",
    "proc.pname = val(proc.name",
    "a.b = ",
    "a.b",
    "a.b exists exists",
    "and",
    "not",
    "a.b !x",
    "a.b[]",
    "= a",
    "a.b in",
    "a.b contains",
];

/// Every file the run starts from.
fn sources() -> Vec<Source> {
    let mut texts: BTreeSet<(String, String)> = BTreeSet::new();
    let mut add = |origin: &str, text: String| {
        texts.insert((origin.to_owned(), text));
    };
    // Corpus fixtures: the body (the first line is the `prod:` tag), and each line.
    for path in files(&repo().join("crates/testdata/corpus/falco"), &["falco"]) {
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
    // libs' own parser and compiler tests.
    let parser: serde_json::Value =
        serde_json::from_str(&read("crates/testdata/conformance/libsinsp/parser.json"))
            .expect("json");
    for fx in parser["fixtures"].as_array().expect("fixtures") {
        if let Some(input) = fx["input"].as_str() {
            add("libsinsp/parser", input.to_owned());
        }
    }
    let compiler: serde_json::Value =
        serde_json::from_str(&read("crates/testdata/conformance/libsinsp/compiler.json"))
            .expect("json");
    for fx in compiler["fixtures"].as_array().expect("fixtures") {
        if let Some(input) = fx["filter"].as_str() {
            add("libsinsp/compiler", input.to_owned());
        }
    }
    // The oracle cases and the Sysdig fixtures: `condition:` lines.
    let mut yaml = files(&repo().join("tests/fixtures"), &["yaml", "yml"]);
    yaml.push(repo().join("crates/testdata/oracles/falco/cases.yaml"));
    for path in yaml {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for line in text.lines() {
            let line = line.trim().trim_start_matches("- ");
            if let Some(c) = line.strip_prefix("condition:") {
                add("yaml", unquote(c));
            }
        }
    }
    // Falco's default rules and macros.
    let defaults: toml::Table = read("data/catalogs/falco/defaults.toml")
        .parse()
        .expect("toml");
    for section in ["macros", "rules"] {
        for entry in defaults
            .get(section)
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(c) = entry.get("condition").and_then(toml::Value::as_str) {
                add("defaults", c.to_owned());
            }
        }
    }
    // String literals of the crate's own tests.
    for file in [
        "crates/opentide-falco/src/lib.rs",
        "crates/opentide-falco/src/compile.rs",
        "crates/opentide-falco/src/parser.rs",
        "crates/opentide-falco/tests/captures.rs",
        "crates/opentide-falco/tests/trees.rs",
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

/// Checks of every construct, valid each on its own.
const CLAUSES: &[&str] = &[
    "proc.name = bash",
    "proc.name=bash",
    "evt.type in (open, openat)",
    "evt.type in(a)",
    "fd.name startswith /etc/",
    "fd.sport > 1024",
    "fd.sport>=1024",
    "evt.dir = <",
    "evt.dir = >",
    "proc.pname exists",
    "proc.name != \"x y\"",
    "proc.name == 'it'",
    "proc.aname[2] = sshd",
    "proc.env[HOME] startswith /root",
    "k8s.pod.label['app'] = web",
    "tolower(proc.name) in (a, b)",
    "len(proc.args) > 4096",
    "getopt(proc.args, \"nt:\")[t] = value",
    "join(\",\", (proc.name, proc.pname, \"x\", 1)) = a",
    "concat(proc.name, \"-\", toupper(proc.pname)) = a",
    "fd.name = val(proc.cwd)",
    "fd.name startswith val(proc.cwd)[2]",
    "proc.name = anyof (a, b)",
    "proc.name contains allof shell_args",
    "evt.type in shell_events",
    "a_macro",
    "(a_macro)",
    "not a_macro",
    "not(a_macro)",
    "k = true",
    "k = 0x1F",
    "k = -1.5e+3",
    "k = 10.0.0.1",
    "k in (1, true, \"x\", 'y', in.proftpd)",
    "k = a<b",
    "k = !x",
    "k = [x]",
    "k.j = \"\"",
    "k.j = ''",
    "k.j in ()",
    "len(()) = 0",
];

/// Valid conditions composed from [`CLAUSES`]: every pair joined by each
/// connective, with groups, `not`, odd spacing and an `and`/`or` fragment, so
/// the differential reaches past the corpus.
fn generated() -> Vec<String> {
    let ops = [" and ", " or ", "\tand\n", " and not ", " or  "];
    let mut out = Vec::new();
    for (i, a) in CLAUSES.iter().enumerate() {
        out.push(format!("and {a}"));
        out.push(format!("or ({a})"));
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
            ("fields".to_owned(), format!("{:?}", legacy::fields(input))),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        hover_surface(legacy::hover_target(input, offset))
    }
}

/// What `hover` dispatches on. Text with whitespace in it names nothing
/// `hover` knows (no field, list, macro or keyword holds a space), so only
/// that it is such text is compared: tree-sitter and the new tree attach the
/// whitespace at the edges of the text to different nodes.
fn hover_surface(target: Option<(&str, String)>) -> Surfaces {
    let target = target.map(|(kind, word)| {
        if word.chars().any(char::is_whitespace) {
            ("other", "<spaced>".to_owned())
        } else {
            (kind, word)
        }
    });
    vec![("hover".to_owned(), format!("{target:?}"))]
}

/// The pure-Rust engine, through the crate's public functions.
struct New;

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        vec![
            (
                "syntax_error".to_owned(),
                opentide_falco::tree_has_error(input).to_string(),
            ),
            (
                "highlight".to_owned(),
                spans(
                    opentide_falco::highlight_captures(input)
                        .iter()
                        .map(|(s, c)| (s.start, s.end, *c)),
                ),
            ),
            (
                "fields".to_owned(),
                format!("{:?}", opentide_falco::tree_fields(input)),
            ),
        ]
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        hover_surface(opentide_falco::hover_target(input, offset))
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
    "a",
    "b.c",
    "proc.name",
    "evt.type",
    " ",
    "(",
    ")",
    "[",
    "]",
    ",",
    "=",
    "==",
    "!=",
    "<",
    "<=",
    ">",
    ">=",
    "\"",
    "'",
    "\\",
    " and ",
    " or ",
    "not ",
    "and",
    "or",
    "not",
    "in",
    "exists",
    " contains ",
    " startswith ",
    "anyof",
    "oneof",
    "tolower(",
    "val(",
    "getopt(",
    "len(",
    "1",
    "0x1F",
    "-2.5",
    "true",
    "\t",
    "\u{a0}",
    "é",
    "/",
    "*",
    "$",
    "{",
    "}",
    "\n",
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
    let first: u64 = std::env::var("OPENTIDE_FALCO_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let mut files = sources();
    if !full {
        // Every fourth generated condition: the pairs cover the same constructs.
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
            "falco differential (seed {seed}, {}): {} inputs, {} valid, {} broken; valid differences {}, verdict changes {}, broken-input changes {}",
            if full { "full" } else { "ci" },
            report.inputs,
            report.valid,
            report.inputs - report.valid,
            report.total(Class::Valid),
            report.total(Class::Verdict),
            report.total(Class::Broken),
        );
        if let Ok(path) = std::env::var("OPENTIDE_FALCO_DIFF") {
            std::fs::write(format!("{path}.seed{seed}.json"), report.to_json_string())
                .expect("the report file");
        }
        assert_gates(&report);
    }
}
