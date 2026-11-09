//! Every input a fuzz target saved (`fuzz/regressions/<target>/`, #182) runs
//! through the engine on stable Rust, as `fuzz/src/lib.rs::exercise` runs it:
//! analysis, then hover, completion and signature help at a few offsets. A
//! crash the fuzzer found stays fixed, and runs within the time budget the
//! fuzzer gave it.

use opentide_analysis::{AnalyzeRequest, LanguageId, MemoryWorkspace};
use std::path::Path;
use std::time::{Duration, Instant};

/// The fuzzer's `-timeout` in CI is 10 s per input; a debug build gets more.
const BUDGET: Duration = Duration::from_secs(30);

fn boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

fn exercise(language: LanguageId, text: &str) {
    let path = match language {
        LanguageId::TideYaml => "/w/objects/rules/fuzz.yaml",
        _ => "/w/fuzz.query",
    };
    let host = MemoryWorkspace {
        files: vec![(path.to_string(), text.to_string())],
    };
    opentide_analysis::analyze(
        &host,
        AnalyzeRequest {
            uri: path.to_string(),
            language,
            text: text.to_string(),
        },
    );
    for offset in [0, text.len() / 3, text.len() / 2, text.len()] {
        let offset = boundary(text, offset);
        let _ = opentide_analysis::hover(&host, language, text, offset);
        let _ = opentide_analysis::completions(&host, language, text, offset);
        let _ = opentide_analysis::signature_help(&host, language, text, offset);
    }
}

#[test]
fn saved_fuzz_inputs_do_not_crash_or_hang() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions");
    let targets = [
        ("kql", LanguageId::Kql),
        ("spl", LanguageId::Spl),
        ("esql", LanguageId::Esql),
        ("eql", LanguageId::Eql),
        ("kuery", LanguageId::Kuery),
        ("lucene", LanguageId::Lucene),
        ("falco", LanguageId::Falco),
        ("cql", LanguageId::Cql),
        ("tide", LanguageId::TideYaml),
    ];
    let mut ran = 0;
    for (target, language) in targets {
        let Ok(entries) = std::fs::read_dir(root.join(target)) else {
            continue;
        };
        for entry in entries.flatten() {
            let bytes = std::fs::read(entry.path()).unwrap();
            let Ok(text) = std::str::from_utf8(&bytes) else {
                continue;
            };
            let start = Instant::now();
            exercise(language, text);
            let took = start.elapsed();
            assert!(took < BUDGET, "{}: {took:?}", entry.path().display());
            ran += 1;
        }
    }
    eprintln!("{ran} saved fuzz inputs");
}
