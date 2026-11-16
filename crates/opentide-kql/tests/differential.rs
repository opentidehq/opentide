//! The pure-Rust parser against the tree-sitter engine it replaces, over every
//! `.kql` file of `crates/testdata`, its prefixes, seeded token mutations and
//! random sentences (`opentide_parse::differential`, #1230).
//!
//! The old engine is `tests/legacy`, a verbatim copy of the tree-sitter
//! implementation; the new one is production, reached through the public API.
//! Compared: every diagnostic under the Sentinel and Defender profiles, the
//! HIR, the highlight tokens, the column pass (pipelines, references,
//! definitions) and hover at offsets.
//! Completions and signature help read the text, not a tree: they are the
//! same function on both sides.
//!
//! Gates: valid input, zero differences; broken input, the same verdict.
//! `OPENTIDE_KQL_DIFF=<file>` writes the JSON report of every seed.

#![expect(
    clippy::expect_used,
    reason = "test helpers outside #[test] functions: a panic fails the test"
)]

mod common;
#[allow(
    dead_code,
    unused_imports,
    reason = "a verbatim copy of the old crate; not every item is compared"
)]
mod legacy;

use common::corpus;
use opentide_core::codes;
use opentide_kql::inspect::{lex_spans, pipeline_parts};
use opentide_kql::{Catalog, Profile, analyze_with_catalog, columns, hover};
use opentide_parse::differential::{Config, Engine, Source, Surfaces, assert_gates, run};

/// What a diagnostic says, on one line.
fn line(d: &opentide_core::Diagnostic) -> String {
    format!(
        "{} {:?} {}:{}-{}:{} {} [{}]",
        d.code,
        d.severity,
        d.range.start.line,
        d.range.start.character,
        d.range.end.line,
        d.range.end.character,
        d.message,
        d.suggestion.as_deref().unwrap_or("")
    )
}

fn tokens_text(tokens: &[opentide_highlight::HighlightToken]) -> String {
    tokens
        .iter()
        .map(|t| format!("{}..{} {}", t.span.start, t.span.end, t.capture))
        .collect::<Vec<_>>()
        .join("\n")
}

const PROFILES: [(&str, Profile); 2] = [
    ("sentinel", Profile::Sentinel),
    ("defender", Profile::Defender),
];

struct Old;
struct New;

/// The column pass's findings, one line each: every pipeline's operators and
/// the columns after each, every reference and definition. A macro: the old
/// engine's types are its own copies.
macro_rules! columns_text {
    ($analysis:expr, $schema:ty) => {{
        let analysis = $analysis;
        let mut out = String::new();
        for p in &analysis.pipelines {
            let names = |s: &$schema| {
                s.columns
                    .iter()
                    .map(|c| format!("{}:{}", c.name, c.type_name.as_deref().unwrap_or("?")))
                    .collect::<Vec<_>>()
                    .join(",")
            };
            out.push_str(&format!(
                "pipeline {}..{} {:?} {:?} [{}]\n",
                p.span.start,
                p.span.end,
                p.source.source,
                p.source.known,
                names(&p.source)
            ));
            for stage in &p.stages {
                out.push_str(&format!(
                    "  {} {}..{} {:?} [{}]\n",
                    stage.operator,
                    stage.span.start,
                    stage.span.end,
                    stage.output.known,
                    names(&stage.output)
                ));
            }
        }
        for r in &analysis.references {
            out.push_str(&format!(
                "ref {} {}..{} in {}..{} {:?}\n",
                r.name, r.span.start, r.span.end, r.operator.start, r.operator.end, r.column
            ));
        }
        for d in &analysis.definitions {
            out.push_str(&format!(
                "def {}..{} {:?}\n",
                d.span.start, d.span.end, d.column
            ));
        }
        out
    }};
}

/// An analysis as the differential compares it: diagnostics, the HIR, tokens.
type Observed = (
    Vec<opentide_core::Diagnostic>,
    String,
    Vec<opentide_highlight::HighlightToken>,
);

/// What both engines give for `input`, from the given functions: `analyze`
/// under the profile at an index of [`PROFILES`], `columns` as text.
fn observe(
    input: &str,
    analyze: &dyn Fn(&str, usize) -> Observed,
    columns: &dyn Fn(&str) -> String,
) -> Surfaces {
    let mut out = Vec::new();
    for (index, (name, _)) in PROFILES.iter().enumerate() {
        let (diagnostics, hir, tokens) = analyze(input, index);
        let diagnostics: Vec<String> = diagnostics.iter().map(line).collect();
        out.push((format!("diagnostics.{name}"), diagnostics.join("\n")));
        if *name == "sentinel" {
            out.push(("hir".to_owned(), hir));
            out.push(("tokens".to_owned(), tokens_text(&tokens)));
        }
    }
    out.push(("columns".to_owned(), columns(input)));
    out
}

const LEGACY_PROFILES: [legacy::Profile; 2] =
    [legacy::Profile::Sentinel, legacy::Profile::Defender];

/// The old engine's diagnostics of `input` under the profile at `index`.
fn old_diagnostics(input: &str, index: usize) -> Vec<opentide_core::Diagnostic> {
    let catalog = legacy::Catalog::for_workspace(LEGACY_PROFILES[index], input);
    legacy::analyze_with_catalog(input, &catalog).diagnostics
}

/// The new engine's diagnostics of `input` under the profile at `index`.
fn new_diagnostics(input: &str, index: usize) -> Vec<opentide_core::Diagnostic> {
    let catalog = Catalog::for_workspace(PROFILES[index].1, input);
    analyze_with_catalog(input, &catalog).diagnostics
}

impl Engine for Old {
    fn observe(&self, input: &str) -> Surfaces {
        observe(
            input,
            &|input, index| {
                let catalog = legacy::Catalog::for_workspace(LEGACY_PROFILES[index], input);
                let a = legacy::analyze_with_catalog(input, &catalog);
                (a.diagnostics, format!("{:?}", a.hir), a.tokens)
            },
            &|input| {
                columns_text!(
                    legacy::columns(input, legacy::Profile::Sentinel),
                    legacy::schema::Schema
                )
            },
        )
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![(
            "hover".to_owned(),
            format!(
                "{:?}",
                legacy::hover(input, offset, legacy::Profile::Sentinel)
            ),
        )]
    }
}

impl Engine for New {
    fn observe(&self, input: &str) -> Surfaces {
        observe(
            input,
            &|input, index| {
                let catalog = Catalog::for_workspace(PROFILES[index].1, input);
                let a = analyze_with_catalog(input, &catalog);
                (a.diagnostics, format!("{:?}", a.hir), a.tokens)
            },
            &|input| {
                columns_text!(
                    columns(input, Profile::Sentinel),
                    opentide_kql::schema::Schema
                )
            },
        )
    }

    fn observe_at(&self, input: &str, offset: usize) -> Surfaces {
        vec![(
            "hover".to_owned(),
            format!("{:?}", hover(input, offset, Profile::Sentinel)),
        )]
    }
}

/// Valid unless the diagnostics hold a syntax error.
fn verdict(surfaces: &Surfaces) -> bool {
    !surfaces.iter().any(|(name, text)| {
        name.starts_with("diagnostics")
            && text.lines().any(|l| l.starts_with(codes::KQL_PARSE_ERROR))
    })
}

fn tokens(text: &str) -> Vec<std::ops::Range<usize>> {
    lex_spans(text)
        .into_iter()
        .filter(|(_, _, trivia)| !trivia)
        .map(|(start, end, _)| start..end)
        .collect()
}

const SAMPLES: &[&str] = &[
    "T",
    "SecurityEvent",
    "|",
    "where",
    "project",
    "extend",
    "summarize",
    "by",
    "count()",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    ",",
    ";",
    "=",
    "==",
    "!=",
    "and",
    "or",
    "not",
    "has",
    "in",
    "!in",
    "between",
    "..",
    "1",
    "5m",
    "\"x\"",
    "'y'",
    "@\"z\"",
    "let",
    "x",
    "join",
    "kind",
    "inner",
    "on",
    "$left",
    "$right",
    "union",
    "take",
    "top",
    "sort",
    "asc",
    "desc",
    "mv-expand",
    "parse",
    "with",
    "*",
    "project-away",
    "datatable",
    "dynamic",
    "range",
    "from",
    "to",
    "step",
    "render",
    "evaluate",
    "dcount(a)",
    "ago(1d)",
    ".",
    ":",
    "+",
    "-",
    "/",
    "%",
    "//c\n",
    "```a```",
    "datetime(2024-01-01)",
];

fn sources() -> Vec<Source> {
    corpus()
        .into_iter()
        .map(|path| Source {
            name: path
                .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                .unwrap_or(&path)
                .display()
                .to_string(),
            text: std::fs::read_to_string(&path).expect("corpus file"),
        })
        .collect()
}

/// How much bigger than the default a run is: `OPENTIDE_KQL_SCALE=4` runs four
/// times the prefixes, mutations and sentences (by hand; CI runs 1).
fn scale() -> usize {
    std::env::var("OPENTIDE_DIFF_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// splitmix64: the generated queries are the same on every run of a seed.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Valid queries composed from the corpus: a source of one valid pipeline
/// and one to six operators of others, so the valid side of the gate is not
/// only the corpus files and their prefixes. The old engine decides which are
/// valid (the verdict); a composition it rejects counts as broken input.
fn generated(files: &[Source], seed: u64, count: usize) -> Vec<Source> {
    let mut sources = Vec::new();
    let mut operators = Vec::new();
    for file in files {
        let valid = !Old
            .observe(&file.text)
            .iter()
            .any(|(n, t)| n.starts_with("diagnostics") && t.contains(codes::KQL_PARSE_ERROR));
        if !valid {
            continue;
        }
        for (source, ops) in pipeline_parts(&file.text) {
            if !source.contains('\n') && source.len() < 120 {
                sources.push(source);
            }
            operators.extend(ops.into_iter().filter(|op| op.len() < 400));
        }
    }
    sources.sort();
    sources.dedup();
    operators.sort();
    operators.dedup();
    assert!(
        sources.len() > 20 && operators.len() > 200,
        "{} sources, {} operators",
        sources.len(),
        operators.len()
    );
    let mut state = seed;
    let pick = |state: &mut u64, n: usize| usize::try_from(next(state) % n as u64).unwrap_or(0);
    (0..count)
        .map(|i| {
            let mut query = sources[pick(&mut state, sources.len())].clone();
            for _ in 0..=pick(&mut state, 6) {
                query.push_str("\n| ");
                query.push_str(&operators[pick(&mut state, operators.len())]);
            }
            Source {
                name: format!("generated#{i}"),
                text: query,
            }
        })
        .collect()
}

fn differential(seed: u64) {
    let files = sources();
    assert!(files.len() > 150, "{} files", files.len());
    let scale = scale();
    // CI (scale 1): a sample that finishes well under two minutes in a debug
    // build. The full run (`OPENTIDE_DIFF_SCALE` 2 or more) has 40 word
    // mutations per file and more of everything else.
    let full = scale > 1;
    let mut config = Config::new(&verdict, &tokens, SAMPLES);
    config.seed = seed;
    config.max_prefixes = if full { 15 * scale } else { 8 };
    config.mutations_per_input = if full { 40.max(10 * scale) } else { 2 };
    config.sentences = if full { 150 * scale } else { 60 };
    config.max_offsets = if full { 12 } else { 4 };
    let report = run(&Old, &New, &files, &config);
    let generated = generated(&files, seed, if full { 1_000 * scale } else { 300 });
    let mut gen_config = Config::new(&verdict, &tokens, SAMPLES);
    gen_config.seed = seed;
    gen_config.max_prefixes = 1;
    gen_config.mutations_per_input = 0;
    gen_config.sentences = 0;
    gen_config.max_offsets = 4;
    let gen_report = run(&Old, &New, &generated, &gen_config);
    for (what, report) in [("corpus", &report), ("generated", &gen_report)] {
        eprintln!(
            "seed {seed} {what}: {} inputs, {} valid; valid {}, broken {}, verdict {}",
            report.inputs,
            report.valid,
            report.total(opentide_parse::differential::Class::Valid),
            report.total(opentide_parse::differential::Class::Broken),
            report.total(opentide_parse::differential::Class::Verdict),
        );
        if let Ok(path) = std::env::var("OPENTIDE_KQL_DIFF") {
            let path = format!("{path}.{seed}.{what}.json");
            std::fs::write(path, report.to_json_string()).expect("write the report");
        }
    }
    assert_gates(&report);
    assert_gates(&gen_report);
}

/// One seed in CI; `OPENTIDE_DIFF_SEEDS=1,2` and `OPENTIDE_DIFF_SCALE=4` for
/// the full run before a push (the switch PR, #1230, records its numbers).
#[test]
fn seeds() {
    let seeds = std::env::var("OPENTIDE_DIFF_SEEDS").unwrap_or_else(|_| "1".into());
    for seed in seeds.split(',').filter_map(|s| s.trim().parse().ok()) {
        differential(seed);
    }
}

/// Triage aid: with `OPENTIDE_KQL_TRIAGE=<file name part>`, prints the first
/// differing line of each surface for that file and each of its prefixes.
#[test]
fn triage() {
    let Ok(only) = std::env::var("OPENTIDE_KQL_TRIAGE") else {
        return;
    };
    let mut shown = 0;
    for file in sources().into_iter().filter(|f| f.name.contains(&only)) {
        let text = &file.text;
        let cuts: Vec<usize> = (0..=text.len())
            .filter(|i| text.is_char_boundary(*i))
            .collect();
        for &cut in cuts.iter().rev() {
            let input = &text[..cut];
            let (old, new) = (Old.observe(input), New.observe(input));
            for ((name, o), (_, n)) in old.iter().zip(&new) {
                if o != n && shown < 8 {
                    shown += 1;
                    let ol: Vec<&str> = o.lines().collect();
                    let nl: Vec<&str> = n.lines().collect();
                    let at = ol
                        .iter()
                        .zip(&nl)
                        .position(|(a, b)| a != b)
                        .unwrap_or(ol.len().min(nl.len()));
                    eprintln!(
                        "== {} cut {cut} surface {name}\ninput tail: {:?}\nold: {:?}\nnew: {:?}",
                        file.name,
                        &input[input.len().saturating_sub(120)..],
                        ol.get(at),
                        nl.get(at)
                    );
                }
            }
        }
    }
}

/// Broken input must not get noisier (LANG-COMMON.md): on every corpus file
/// and a stride of its prefixes that the old engine rejects, the new engine
/// reports no more diagnostics than the old one, under both profiles.
#[test]
fn broken_input_is_not_noisier() {
    let mut checked = 0;
    let mut noisier = Vec::new();
    for file in sources() {
        let text = &file.text;
        let cuts: Vec<usize> = (0..=text.len())
            .filter(|i| text.is_char_boundary(*i))
            .collect();
        let stride = (cuts.len() / 15).max(1);
        for &cut in cuts.iter().step_by(stride) {
            let input = &text[..cut];
            for index in 0..PROFILES.len() {
                let old = old_diagnostics(input, index);
                if !old.iter().any(|d| d.code == codes::KQL_PARSE_ERROR) {
                    continue;
                }
                checked += 1;
                let new = new_diagnostics(input, index);
                if new.len() > old.len() {
                    noisier.push(format!(
                        "{} cut {cut}: old {:?}\n  new {:?}",
                        file.name,
                        old.iter().map(|d| d.code.as_str()).collect::<Vec<_>>(),
                        new.iter().map(|d| d.code.as_str()).collect::<Vec<_>>()
                    ));
                }
            }
        }
    }
    assert!(checked > 500, "{checked} broken inputs");
    assert!(
        noisier.is_empty(),
        "{} of {checked}:\n{}",
        noisier.len(),
        noisier[..noisier.len().min(10)].join("\n")
    );
}

/// Runs `run` on a thread with a stack of `size` bytes; an overflow aborts.
fn on_stack<T: Send + 'static>(size: usize, run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(size)
        .spawn(run)
        .expect("spawn")
        .join()
        .expect("the analysis panicked")
}

fn deep(kind: &str, n: usize) -> String {
    match kind {
        "member" => format!("T | where {} == 1", vec!["a"; n].join(".")),
        "index" => format!("T | where a{} == 1", "[0]".repeat(n)),
        "union" => format!("{}T{}", "union (".repeat(n), ")".repeat(n)),
        "join" => format!("T{}{}", " | join (T".repeat(n), ") on a".repeat(n)),
        "mv-apply" => format!(
            "T{}{}",
            " | mv-apply x on (where b".repeat(n),
            ")".repeat(n)
        ),
        "pipeline" => format!("{}T | take 1{}", "(".repeat(n), ")".repeat(n)),
        "expression" => format!("T | where {}a == 1{}", "(".repeat(n), ")".repeat(n)),
        _ => unreachable!("{kind}"),
    }
}

const KINDS: [&str; 7] = [
    "member",
    "index",
    "union",
    "join",
    "mv-apply",
    "pipeline",
    "expression",
];

/// Where the tree-sitter engine did not overflow (35 levels, its measured
/// floor), the column pass's budget changes nothing: the same columns and
/// diagnostics as the old engine (moved from `tests/deep_analysis.rs`).
#[test]
fn the_budget_reads_as_deep_as_the_old_engine() {
    for kind in KINDS {
        let n = if matches!(kind, "member" | "index") {
            250
        } else {
            35
        };
        let source = deep(kind, n);
        let text = |a: &opentide_kql::schema::Analysis| {
            format!(
                "{} {} {} {:?}",
                a.pipelines.len(),
                a.references.len(),
                a.definitions.len(),
                a.diagnostics
            )
        };
        let text_old = |a: &legacy::schema::Analysis| {
            format!(
                "{} {} {} {:?}",
                a.pipelines.len(),
                a.references.len(),
                a.definitions.len(),
                a.diagnostics
            )
        };
        let old = {
            let source = source.clone();
            on_stack(256 << 20, move || {
                text_old(&legacy::columns(&source, legacy::Profile::Sentinel))
            })
        };
        let new = on_stack(1 << 20, move || text(&columns(&source, Profile::Sentinel)));
        assert_eq!(old, new, "{kind} {n}");
        // And the diagnostics.
        let source = deep(kind, n);
        let old = {
            let source = source.clone();
            on_stack(256 << 20, move || {
                format!("{:?}", old_diagnostics(&source, 0))
            })
        };
        let new = on_stack(1 << 20, move || {
            format!("{:?}", new_diagnostics(&source, 0))
        });
        assert_eq!(old, new, "{kind} {n}");
    }
}
