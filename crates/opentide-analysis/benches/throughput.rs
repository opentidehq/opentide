//! Throughput of each language's parse and analysis (#1571, ADR 0014).
//!
//!     cargo bench -p opentide-analysis --bench throughput            # wall time
//!     cargo xtask throughput [--check | --record]                    # instructions
//!
//! Two input sets per language:
//! - `corpus`: `crates/testdata/corpus/<lang>/`, short queries: the per-call
//!   floor an editor pays on every keystroke;
//! - `external`: `crates/testdata/conformance/external/<dirs>/`, real public
//!   rules, in subdirectories too (the `.broken.` twins left out), and the
//!   accepted queries of a reference parser's `cases.tsv`: bytes a second on
//!   realistic input.
//!
//! Each in two modes: `parse` (the parse alone, through the language's own
//! entry point) and `analyze` (`opentide_analysis::analyze`, all of it).
//!
//! With no arguments it prints the wall-time table: release build, 1 thread,
//! a warm-up, then rounds until at least 15 and 1 s, the median. With
//! `--count LANG MODE SET` it runs two warm-up passes, then one pass inside
//! `counted`, which `cargo xtask throughput` counts with callgrind
//! (`--toggle-collect`): instructions are deterministic where time is not.
//! `--list` prints the languages, one a line, for `cargo xtask throughput`.
//!
//! A language plugs in with one row of `LANGUAGES`.

#![expect(
    clippy::unwrap_used,
    reason = "a benchmark binary: a fixture it cannot read stops it"
)]

use opentide_analysis::{AnalyzeRequest, LanguageId, MemoryWorkspace, analyze};
use std::path::Path;
use std::time::{Duration, Instant};

/// A language: its id, its file extension, the corpus directory, the
/// external directories, and its parse-only entry point.
struct Language {
    name: &'static str,
    id: LanguageId,
    extensions: &'static [&'static str],
    corpus: &'static str,
    external: &'static [&'static str],
    parse: fn(&str),
}

/// Each parse is the language's cheapest whole parse; a language whose crate
/// has none yet uses its `debug_kinds` (which also names the kinds: its owner
/// replaces it with a plain parse).
const LANGUAGES: &[Language] = &[
    Language {
        name: "kql",
        id: LanguageId::Kql,
        extensions: &["kql"],
        corpus: "kql",
        external: &["kql"],
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
        parse: |s| {
            std::hint::black_box(opentide_spl::debug_kinds(s));
        },
    },
    Language {
        name: "cql",
        id: LanguageId::Cql,
        extensions: &["cql"],
        corpus: "cql",
        external: &["cql"],
        parse: |s| {
            std::hint::black_box(opentide_cql::debug_kinds(s));
        },
    },
    Language {
        name: "falco",
        id: LanguageId::Falco,
        extensions: &["falco"],
        corpus: "falco",
        external: &["falco"],
        parse: |s| {
            std::hint::black_box(opentide_falco::debug_kinds(s));
        },
    },
    Language {
        name: "yara",
        id: LanguageId::Yara,
        extensions: &["yar", "yara"],
        corpus: "yara",
        external: &["yara"],
        parse: |s| {
            std::hint::black_box(opentide_yara::debug_kinds(s));
        },
    },
    Language {
        name: "exabeam",
        id: LanguageId::Exabeam,
        extensions: &["exabeam"],
        corpus: "exabeam",
        external: &["exabeam"],
        parse: |s| {
            std::hint::black_box(opentide_exabeam::debug_kinds(s));
        },
    },
    Language {
        name: "yaral",
        id: LanguageId::Yaral,
        extensions: &["yaral", "yl2"],
        corpus: "yaral",
        external: &["yaral"],
        parse: |s| {
            std::hint::black_box(opentide_yaral::debug_kinds(s));
        },
    },
];

/// The texts under `dir`, its subdirectories included, in path order: each
/// file with one of `extensions` but a `.broken.` twin, and each accepted
/// query of a `cases.tsv` (`accept`, then the query as a JSON string).
fn files(dir: &Path, extensions: &[&str]) -> Vec<String> {
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
        if path.file_name().is_some_and(|n| n == "cases.tsv") {
            out.extend(text.lines().filter_map(|line| {
                let mut cells = line.split('\t');
                (cells.next() == Some("accept"))
                    .then(|| serde_json::from_str::<String>(cells.next()?).ok())
                    .flatten()
            }));
        } else if !path.to_string_lossy().contains(".broken.")
            && path
                .extension()
                .is_some_and(|e| extensions.iter().any(|x| e == *x))
        {
            out.push(text);
        }
    }
    out
}

/// The texts of `set` (`corpus` or `external`) for `language`.
fn inputs(language: &Language, set: &str) -> Vec<String> {
    let testdata = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
    match set {
        "corpus" => files(
            &testdata.join("corpus").join(language.corpus),
            &[
                "kql", "spl", "esql", "eql", "kuery", "lucene", "falco", "cql", "yar", "yara",
                "yaral", "yl2", "exabeam", "txt",
            ],
        ),
        _ => language
            .external
            .iter()
            .flat_map(|dir| {
                files(
                    &testdata.join("conformance/external").join(dir),
                    language.extensions,
                )
            })
            .collect(),
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

/// The pass `cargo xtask throughput` counts (`--toggle-collect` on this
/// function): the warm-up passes do not go through it.
#[inline(never)]
fn counted(language: &Language, mode: &str, host: &MemoryWorkspace, texts: &[String]) {
    measure(language, mode, host, texts);
}

/// The median time of one pass over `texts`, after a warm-up.
fn pass(language: &Language, mode: &str, host: &MemoryWorkspace, texts: &[String]) -> Duration {
    let warm = Instant::now();
    while warm.elapsed() < Duration::from_millis(300) {
        measure(language, mode, host, texts);
    }
    let mut rounds = Vec::new();
    let started = Instant::now();
    while rounds.len() < 15 || started.elapsed() < Duration::from_secs(1) {
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
        let language = LANGUAGES.iter().find(|l| l.name == name).unwrap();
        let texts = inputs(language, set);
        // The warm-up: catalogs, compiled queries and memos, outside the count.
        measure(language, mode, &host, &texts);
        measure(language, mode, &host, &texts);
        counted(language, mode, &host, &texts);
        let bytes: usize = texts.iter().map(String::len).sum();
        println!("{} {bytes}", texts.len());
        return;
    }
    println!(
        "| language | corpus parse µs/call | corpus analyze µs/call | external MB/s parse | external MB/s analyze | external files, bytes |"
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
