//! The pure-Rust parser against the tree-sitter engine it replaces, on
//! `opentide_parse::differential`: every `.spl` file under the test data,
//! every prefix, seeded token mutations and random sentences.
//!
//! The old engine is the tree-sitter engine, copied to `tests/legacy` before
//! the switch; the new one is the pure-Rust parser and the analysis on its
//! tree (`opentide_spl::syntax::analyze`). What is compared, per input:
//!
//! - `parse_error`: whether the parse has an error (the verdict);
//! - `stages`: the kind of every stage of every pipeline, subsearches
//!   included, in source order (`bare_search`, `stats_command`, ...);
//! - `tokens`: the byte range of every token (tree-sitter's leaves against
//!   the lexer's lexemes);
//! - `diagnostics`: every diagnostic of the analysis (code, severity, range,
//!   message, suggestion);
//! - `highlight`: every highlight token (range and capture);
//! - at offsets: `hover`, `completions` (labels) and `signature_help`.
//!
//! `OPENTIDE_SPL_DIFF=<file>` writes the JSON report there; `OPENTIDE_DIFF_SEEDS`
//! (`1,2,3`), `OPENTIDE_DIFF_SCALE=full` and `OPENTIDE_SPL_DIFF_EXAMPLES` choose
//! the seeds, the scale and the examples listed.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

#[allow(
    dead_code,
    clippy::too_many_lines,
    reason = "the tree-sitter engine copied verbatim: not every item is compared, and its dispatchers are long"
)]
mod legacy;
mod support;

use opentide_core::LanguageId;
use opentide_parse::differential::{self, Class, Config, Engine, Source, Surfaces};
use opentide_spl::syntax::{SyntaxKind, lex, parse};
use std::ops::Range;
use std::path::Path;
use support::{body, walk};

/// tree-sitter, as production uses it.
struct Old;

fn old_stage_kinds(node: tree_sitter::Node<'_>, out: &mut Vec<String>) {
    if node.kind() == "pipeline" {
        let mut cursor = node.walk();
        let stages: Vec<String> = node
            .named_children(&mut cursor)
            .filter(|c| c.kind() != "comment")
            .map(|c| {
                if c.kind() == "command" {
                    c.named_child(0).map_or("command", |n| n.kind()).to_owned()
                } else {
                    c.kind().to_owned()
                }
            })
            .collect();
        out.push(format!("[{}]", stages.join(" ")));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        old_stage_kinds(child, out);
    }
}

fn leaves(node: tree_sitter::Node<'_>, out: &mut Vec<Range<usize>>) {
    if node.child_count() == 0 {
        if node.end_byte() > node.start_byte() {
            out.push(node.start_byte()..node.end_byte());
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        leaves(child, out);
    }
}

fn ranges(r: &[Range<usize>]) -> String {
    r.iter()
        .map(|r| format!("{}..{}", r.start, r.end))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_diagnostics(diagnostics: &[opentide_core::Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|d| {
            format!(
                "{} {:?} {}:{}-{}:{} {} {:?}",
                d.code,
                d.severity,
                d.range.start.line,
                d.range.start.character,
                d.range.end.line,
                d.range.end.character,
                d.message,
                d.suggestion
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_tokens(tokens: &[opentide_highlight::HighlightToken]) -> String {
    tokens
        .iter()
        .map(|t| format!("{}..{} {}", t.span.start, t.span.end, t.capture))
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_at(
    hover: Option<String>,
    completions: &[opentide_core::CompletionItem],
    signature: Option<opentide_core::SignatureHelp>,
) -> Surfaces {
    vec![
        ("hover".to_owned(), hover.unwrap_or_default()),
        (
            "completions".to_owned(),
            completions
                .iter()
                .map(|c| c.label.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        ("signature_help".to_owned(), format!("{signature:?}")),
    ]
}

impl Engine for Old {
    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        render_at(
            legacy::hover(input, offset),
            &legacy::completions(input, offset),
            legacy::signature_help(input, offset),
        )
    }

    fn observe(&self, input: &str) -> Surfaces {
        let analysis = legacy::analyze(input);
        let tree = opentide_syntax::parse(LanguageId::Spl, input).expect("parser");
        let mut stages = Vec::new();
        old_stage_kinds(tree.root_node(), &mut stages);
        let mut tokens = Vec::new();
        leaves(tree.root_node(), &mut tokens);
        vec![
            (
                "parse_error".to_owned(),
                if opentide_syntax::has_error(&tree) {
                    "error"
                } else {
                    "ok"
                }
                .to_owned(),
            ),
            ("stages".to_owned(), stages.join(" ")),
            ("tokens".to_owned(), ranges(&tokens)),
            (
                "diagnostics".to_owned(),
                render_diagnostics(&analysis.diagnostics),
            ),
            ("highlight".to_owned(), render_tokens(&analysis.tokens)),
        ]
    }
}

/// The pure-Rust parser.
struct New;

fn new_name(kind: SyntaxKind) -> String {
    match kind {
        SyntaxKind::MACRO_CALL => "macro".to_owned(),
        SyntaxKind::ERROR => "ERROR".to_owned(),
        other => format!("{other:?}").to_ascii_lowercase(),
    }
}

impl Engine for New {
    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        render_at(
            opentide_spl::hover(input, offset),
            &opentide_spl::completions(input, offset),
            opentide_spl::signature_help(input, offset),
        )
    }

    fn observe(&self, input: &str) -> Surfaces {
        let (tree, parsed) = parse(input);
        let analysis = opentide_spl::syntax::analyze(input);
        // Debugging aid: the whole text of an input the old parser accepts and
        // this one does not (the report cuts texts at 300 characters).
        if let Ok(path) = std::env::var("OPENTIDE_SPL_DIFF_DUMP")
            && !parsed.errors.is_empty()
            && Old
                .observe(input)
                .iter()
                .any(|(n, v)| n == "parse_error" && v == "ok")
        {
            use std::io::Write as _;
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
            {
                let _ = writeln!(file, "{}\n---", input.replace('\n', "\\n"));
            }
        }
        let stages: Vec<String> = tree
            .descendants()
            .filter(|n| n.kind() == SyntaxKind::PIPELINE)
            .map(|n| {
                let kinds: Vec<String> = n.children().map(|c| new_name(c.kind())).collect();
                format!("[{}]", kinds.join(" "))
            })
            .collect();
        let tokens: Vec<Range<usize>> = lex(input)
            .iter()
            .filter(|l| l.kind != SyntaxKind::WHITESPACE.raw())
            .map(|l| usize::from(l.range.start())..usize::from(l.range.end()))
            .collect();
        vec![
            (
                "parse_error".to_owned(),
                if parsed.errors.is_empty() {
                    "ok"
                } else {
                    "error"
                }
                .to_owned(),
            ),
            ("stages".to_owned(), stages.join(" ")),
            ("tokens".to_owned(), ranges(&tokens)),
            (
                "diagnostics".to_owned(),
                render_diagnostics(&analysis.diagnostics),
            ),
            ("highlight".to_owned(), render_tokens(&analysis.tokens)),
        ]
    }
}

const SAMPLES: &[&str] = &[
    "|",
    "[",
    "]",
    "(",
    ")",
    ",",
    "=",
    "==",
    "!=",
    "<",
    ">",
    "<=",
    ">=",
    "index=main",
    "a",
    "b",
    "x",
    "*",
    "\"s\"",
    "'t'",
    "1",
    "AND",
    "OR",
    "NOT",
    "IN",
    "search",
    "where",
    "eval",
    "stats",
    "count",
    "by",
    "as",
    "table",
    "fields",
    "rename",
    "dedup",
    "sort",
    "head",
    "tail",
    "rex",
    "join",
    "lookup",
    "inputlookup",
    "outputlookup",
    "foreach",
    "spath",
    "tojson",
    "tstats",
    "chart",
    "timechart",
    "fillnull",
    "mvexpand",
    "makemv",
    "makeresults",
    "top",
    "bin",
    "foo",
    "`m`",
    "`m(1)`",
    "TERM(a=b)",
    "CASE(a)",
    "PREFIX(a=)",
    "dc(x)",
    "+",
    "-",
    "/",
    "%",
    ".",
    "like",
    "true",
    "span=1h",
    "limit=0",
    "sourcetype=x",
    "```c```",
];

fn sources() -> Vec<Source> {
    let mut files = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    files
        .iter()
        .map(|path| Source {
            name: path
                .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"))
                .map_or_else(|_| path.display().to_string(), |p| p.display().to_string()),
            text: body(path),
        })
        .collect()
}

/// Valid queries composed from the corpus's constructs: every base search
/// with every stage, then with two stages, picked deterministically.
fn generated() -> Vec<Source> {
    const BASES: [&str; 10] = [
        "index=main",
        "index=main sourcetype=\"x y\" error*",
        "search a=1 OR b=2",
        "(a=1 OR b=2) NOT c=3 d>=4",
        "x IN (1, 2, \"3\") y!=z",
        "TERM(a=b) CASE(C) d*",
        "`m` a=1 `n(2)`",
        "| tstats count where index=main by host",
        "| inputlookup t.csv where a=1",
        "a [ search b=1 | head 1 ]",
    ];
    const STAGES: [&str; 44] = [
        "head 5",
        "tail",
        "where a>1 AND (b<2 OR c==3)",
        "where like(x, \"a%\") OR NOT y",
        "eval z=if(a>1, \"hi\", b+c*2), w=len(x) . \"-\" . y",
        "stats count by host",
        "stats count dc(src) as c, values(*) as v by host, user span=1h",
        "eventstats avg(x) as m by y",
        "streamstats current=f window=3 sum(x) by y",
        "chart count over a by b",
        "timechart span=1h limit=0 count by host where count in top5",
        "geostats latfield=la count",
        "tstats count where index=a by PREFIX(src=)",
        "table a, b*, \"c d\"",
        "fields - a, b",
        "fields + x",
        "rename a as b, c* as d*",
        "dedup 2 a b sortby -c",
        "sort 0 -a, +b num(c) desc",
        "rex field=_raw max_match=0 \"(?<x>.)\"",
        "fillnull value=0 a b",
        "mvexpand x",
        "makemv delim=\",\" x",
        "join type=left a, b [ search c=1 ]",
        "lookup t a as b output c as d",
        "inputlookup append=t t.csv",
        "outputlookup t.csv",
        "foreach * [ eval <<FIELD>>=1 ]",
        "spath input=x path=a{}.b output=y",
        "tojson fill_null=true a, b*, str(c)",
        "makeresults count=5",
        "top limit=5 x by y",
        "bin span=1h _time",
        "regex _raw!=\"a\"",
        "convert timeformat=\"%Y\" ctime(x) AS t",
        "unknowncmd a=1 b>2 f(x) \"s\" `m`",
        "`m(1)`",
        "append [ search a ]",
        "search x=1 | head 1",
        "`m`",
        "rename a as b | table b",
        "where a IN (1, 2) AND b LIKE \"%x\"",
        "eval a=mvindex(b, 0), {d}=1",
        "stats count BY a",
    ];
    let mut out = Vec::new();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = |n: usize| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        usize::try_from(state % u64::try_from(n).unwrap_or(1)).unwrap_or(0)
    };
    for base in BASES {
        for stage in STAGES {
            out.push(format!("{base} | {stage}"));
        }
    }
    for _ in 0..600 {
        let (a, b) = (STAGES[next(STAGES.len())], STAGES[next(STAGES.len())]);
        out.push(format!("{} | {a} | {b}", BASES[next(BASES.len())]));
    }
    out.into_iter()
        .enumerate()
        .map(|(i, text)| Source {
            name: format!("generated/{i}"),
            text,
        })
        .collect()
}

/// Whether `OPENTIDE_DIFF_SCALE=full` asks for the whole run.
fn full_scale() -> bool {
    std::env::var("OPENTIDE_DIFF_SCALE").is_ok_and(|s| s == "full")
}

fn run(seed: u64, files: &[Source]) -> differential::Report {
    let verdict = |observed: &Surfaces| {
        observed
            .iter()
            .any(|(name, value)| name == "parse_error" && value == "ok")
    };
    let tokens = |text: &str| -> Vec<Range<usize>> {
        lex(text)
            .iter()
            .filter(|l| l.kind != SyntaxKind::WHITESPACE.raw())
            .map(|l| usize::from(l.range.start())..usize::from(l.range.end()))
            .collect()
    };
    let mut config = Config::new(&verdict, &tokens, SAMPLES);
    config.seed = seed;
    config.mutations_per_input = 40;
    // The default scale is a sample that runs well under two minutes in CI:
    // OPENTIDE_DIFF_SCALE=full runs every prefix, 500 sentences and 16 offsets
    // per input (minutes per seed, run by hand before a push, NOTES.md).
    if full_scale() {
        config.max_offsets = 16;
    } else {
        config.max_offsets = 2;
        config.max_prefixes = 12;
        config.sentences = 100;
    }
    if let Ok(n) = std::env::var("OPENTIDE_SPL_DIFF_EXAMPLES") {
        config.max_examples = n.parse().unwrap_or(5);
    }
    differential::run(&Old, &New, files, &config)
}

/// The corpus, the conformance and oracle files and the generated queries,
/// each with prefixes, 40 mutations and random sentences: seed 1 at a
/// sampled scale by default; `OPENTIDE_DIFF_SEEDS` and
/// `OPENTIDE_DIFF_SCALE=full` for the whole run.
#[test]
fn the_pure_rust_parser_matches_tree_sitter() {
    let mut files = sources();
    assert!(files.len() > 250, "{} files", files.len());
    files.extend(generated());
    // OPENTIDE_DIFF_SEEDS=1,2,3 runs those seeds; the default is seed 1.
    let seeds: Vec<u64> = std::env::var("OPENTIDE_DIFF_SEEDS")
        .or_else(|_| std::env::var("OPENTIDE_SPL_DIFF_SEED"))
        .ok()
        .map(|s| s.split(',').filter_map(|n| n.trim().parse().ok()).collect())
        .filter(|v: &Vec<u64>| !v.is_empty())
        .unwrap_or_else(|| vec![1]);
    for seed in seeds {
        let report = run(seed, &files);
        if let Ok(path) = std::env::var("OPENTIDE_SPL_DIFF") {
            std::fs::write(path, report.to_json_string()).expect("write the report");
        }
        println!(
            "seed {seed}: inputs {} valid {} | valid {} verdict {} broken {}",
            report.inputs,
            report.valid,
            report.total(Class::Valid),
            report.total(Class::Verdict),
            report.total(Class::Broken)
        );
        differential::assert_gates(&report);
    }
}
