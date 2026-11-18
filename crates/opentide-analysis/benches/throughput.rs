//! Throughput of each language's parse and analysis (#1571, ADR 0014).
//!
//!     cargo bench -p opentide-analysis --bench throughput
//!
//! Two input sets per language:
//! - `corpus`: `crates/testdata/corpus/<lang>/`, short queries: the per-call
//!   floor an editor pays on every keystroke;
//! - `external`: `crates/testdata/conformance/external/<dirs>/`, real public
//!   rules, in subdirectories too (the `.broken.` twins left out), and the
//!   accepted queries of a reference parser's `cases.tsv`: bytes a second on
//!   realistic input. A text is a file or one `cases.tsv` row.
//!
//! Each in two modes: `parse` (the parse alone, through the language's own
//! entry point) and `analyze` (`opentide_analysis::analyze`, all of it).
//!
//! With no arguments it prints the wall-time table: release build, 1 thread,
//! ADR 0014 §6's method (a 3 s warm-up, then at least 15 rounds and 5 s, the
//! median). With `--count LANG MODE SET` it runs two warm-up passes, then one
//! pass inside `counted`, for an instruction counter such as callgrind's
//! `--toggle-collect=throughput::counted`: instructions are deterministic
//! where time is not. `--list` prints the languages, one a line.
//!
//! A language plugs in with one row of `LANGUAGES`.

use opentide_analysis::{AnalyzeRequest, LanguageId, MemoryWorkspace, analyze};
use std::path::Path;
use std::time::{Duration, Instant};

/// A language: its id, its file extensions, the corpus directory, the
/// external directories, the file names an external directory holds for
/// another profile or dialect (left out), and its parse-only entry point.
struct Language {
    name: &'static str,
    id: LanguageId,
    extensions: &'static [&'static str],
    corpus: &'static str,
    external: &'static [&'static str],
    skip: &'static [&'static str],
    parse: fn(&str),
}

/// Each parse is the language's cheapest whole parse: its crate's hidden
/// `parses`, which builds no kind names (`tests/plain_parses.rs` holds each to
/// the verdict of its `debug_kinds`).
const LANGUAGES: &[Language] = &[
    Language {
        name: "kql",
        id: LanguageId::Kql,
        extensions: &["kql"],
        corpus: "kql",
        external: &["kql"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_kql::inspect::parse_error_count(s));
        },
    },
    Language {
        name: "esql",
        id: LanguageId::Esql,
        extensions: &["esql"],
        corpus: "esql",
        external: &["esql"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_esql::syntax_tree(s));
        },
    },
    Language {
        name: "eql",
        id: LanguageId::Eql,
        extensions: &["eql"],
        corpus: "eql",
        external: &["eql"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_eql::parses(s));
        },
    },
    Language {
        name: "kuery",
        id: LanguageId::Kuery,
        extensions: &["kuery"],
        corpus: "kuery",
        external: &["kuery-opensearch-dashboards"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_kuery::parses(s));
        },
    },
    Language {
        name: "lucene",
        id: LanguageId::Lucene,
        extensions: &["lucene"],
        corpus: "lucene",
        external: &["lucene", "lucene-queryparser"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_lucene::parses(s));
        },
    },
    Language {
        name: "spl",
        id: LanguageId::Spl,
        extensions: &["spl"],
        corpus: "spl",
        external: &["spl"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_spl::parses(s));
        },
    },
    Language {
        name: "cql",
        id: LanguageId::Cql,
        extensions: &["cql"],
        corpus: "cql",
        external: &["cql"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_cql::parses(s));
        },
    },
    Language {
        name: "falco",
        id: LanguageId::Falco,
        extensions: &["falco"],
        corpus: "falco",
        external: &["falco"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_falco::parses(s));
        },
    },
    Language {
        name: "yara",
        id: LanguageId::Yara,
        extensions: &["yar", "yara"],
        corpus: "yara",
        external: &["yara"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_yara::parses(s));
        },
    },
    Language {
        name: "exabeam",
        id: LanguageId::Exabeam,
        extensions: &["exabeam"],
        corpus: "exabeam",
        external: &["exabeam"],
        skip: &[".rule."],
        parse: |s| {
            std::hint::black_box(opentide_exabeam::parses(s));
        },
    },
    Language {
        name: "yaral",
        id: LanguageId::Yaral,
        extensions: &["yaral", "yl2"],
        corpus: "yaral",
        external: &["yaral"],
        skip: &[],
        parse: |s| {
            std::hint::black_box(opentide_yaral::parses(s));
        },
    },
];

/// The texts under `dir`, its subdirectories included, in path order: each
/// file with one of `extensions` whose name holds none of `skip` (nor
/// `.broken.`), and each accepted query of a `cases.tsv`.
fn files(dir: &Path, extensions: &[&str], skip: &[&str]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for path in std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
        {
            if path.is_dir() {
                dirs.push(path);
            } else {
                paths.push(path);
            }
        }
    }
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name == "cases.tsv" {
            out.extend(cases(&text));
        } else if !name.contains(".broken.")
            && !skip.iter().any(|s| name.contains(s))
            && path
                .extension()
                .is_some_and(|e| extensions.iter().any(|x| e == *x))
        {
            out.push(text);
        }
    }
    out
}

/// The accepted queries of a `cases.tsv`. Its header's second cell says how
/// a query is written: as a JSON string, or with `\t`, `\n`, `\r` and `\\`
/// escaped (any other `\X` is `X`, as the reference parser's own test reads it).
fn cases(text: &str) -> Vec<String> {
    let json = text
        .lines()
        .next()
        .and_then(|header| header.split('\t').nth(1))
        .is_some_and(|cell| cell.contains("JSON"));
    text.lines()
        .filter_map(|line| {
            let mut cells = line.split('\t');
            if cells.next() != Some("accept") {
                return None;
            }
            let query = cells.next()?;
            if json {
                return serde_json::from_str::<String>(query).ok();
            }
            let mut out = String::with_capacity(query.len());
            let mut chars = query.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some('t') => out.push('\t'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some(other) => out.push(other),
                        None => out.push('\\'),
                    }
                } else {
                    out.push(c);
                }
            }
            Some(out)
        })
        .collect()
}

/// The texts of `set` (`corpus` or `external`) for `language`.
fn inputs(language: &Language, set: &str) -> Vec<String> {
    let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
    match set {
        "corpus" => files(
            &testdata.join("corpus").join(language.corpus),
            language.extensions,
            &[],
        ),
        "external" => language
            .external
            .iter()
            .flat_map(|dir| {
                files(
                    &testdata.join("conformance/external").join(dir),
                    language.extensions,
                    language.skip,
                )
            })
            .collect(),
        _ => panic!("unknown set {set:?}: corpus or external"),
    }
}

/// One call of `mode` on `text`.
fn call(language: &Language, mode: &str, host: &MemoryWorkspace, text: &str) {
    if mode == "parse" {
        (language.parse)(text);
    } else {
        std::hint::black_box(analyze(
            host,
            AnalyzeRequest {
                uri: format!("/w/q.{}", language.name),
                language: language.id,
                text: text.to_owned(),
            },
        ));
    }
}

/// The pass callgrind counts: every text once.
#[inline(never)]
fn measure(language: &Language, mode: &str, host: &MemoryWorkspace, texts: &[String]) {
    for text in texts {
        call(language, mode, host, text);
    }
}

/// The pass an instruction counter counts (callgrind's `--toggle-collect` on
/// this function): the warm-up passes do not go through it.
#[inline(never)]
fn counted(language: &Language, mode: &str, host: &MemoryWorkspace, texts: &[String]) {
    measure(language, mode, host, texts);
}

/// The median time of one pass over `texts`, by ADR 0014 §6: a 3 s warm-up,
/// then at least 15 rounds and 5 s.
fn pass(language: &Language, mode: &str, host: &MemoryWorkspace, texts: &[String]) -> Duration {
    let warm = Instant::now();
    while warm.elapsed() < Duration::from_secs(3) {
        measure(language, mode, host, texts);
    }
    let mut rounds = Vec::new();
    let started = Instant::now();
    while rounds.len() < 15 || started.elapsed() < Duration::from_secs(5) {
        let round = Instant::now();
        measure(language, mode, host, texts);
        rounds.push(round.elapsed());
    }
    rounds.sort();
    rounds[rounds.len() / 2]
}

#[expect(
    clippy::cast_precision_loss,
    reason = "bytes and calls of a benchmark corpus, far below 2^52"
)]
fn main() {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--bench")
        .collect();
    let host = MemoryWorkspace::default();
    if args.first().is_some_and(|a| a == "--list") {
        for language in LANGUAGES {
            println!("{}", language.name);
        }
        return;
    }
    if let [flag, name, mode, set] = args.as_slice()
        && flag == "--count"
    {
        let language = LANGUAGES
            .iter()
            .find(|l| l.name == name)
            .unwrap_or_else(|| panic!("unknown language {name:?}: see --list"));
        assert!(
            mode == "parse" || mode == "analyze",
            "unknown mode {mode:?}: parse or analyze"
        );
        let texts = inputs(language, set);
        assert!(!texts.is_empty(), "{name} has no {set} texts");
        // The warm-up: catalogs, compiled queries and memos, outside the count.
        measure(language, mode, &host, &texts);
        measure(language, mode, &host, &texts);
        counted(language, mode, &host, &texts);
        let bytes: usize = texts.iter().map(String::len).sum();
        println!("{} {bytes}", texts.len());
        return;
    }
    println!(
        "| language | corpus parse µs/call | corpus analyze µs/call | external MB/s parse | external MB/s analyze | external texts, bytes |"
    );
    println!("|---|---:|---:|---:|---:|---|");
    for language in LANGUAGES {
        let corpus = inputs(language, "corpus");
        let external = inputs(language, "external");
        let per_call = |mode: &str| {
            if corpus.is_empty() {
                return "—".to_owned();
            }
            let time = pass(language, mode, &host, &corpus);
            format!("{:.1}", time.as_secs_f64() * 1e6 / corpus.len() as f64)
        };
        let bytes: usize = external.iter().map(String::len).sum();
        let rate = |mode: &str| {
            if bytes == 0 {
                return "—".to_owned();
            }
            let time = pass(language, mode, &host, &external);
            format!("{:.1}", bytes as f64 / time.as_secs_f64() / 1e6)
        };
        println!(
            "| {} | {} | {} | {} | {} | {}, {bytes} |",
            language.name,
            per_call("parse"),
            per_call("analyze"),
            rate("parse"),
            rate("analyze"),
            external.len(),
        );
    }
}
