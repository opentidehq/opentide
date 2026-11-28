//! The parse-taking entry points (#1233): [`analyze_parsed`] and
//! [`block_diagnostics_parsed`] read the host's parse of the object and
//! report exactly what [`analyze`] and [`block_diagnostics`], which parse it
//! themselves, report: on every YAML file of the test data, with and
//! without a byte-order mark.

#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every file read is the repository's own"
)]

use opentide_tide::{
    AnalyzeInput, analyze, analyze_parsed, block_diagnostics, block_diagnostics_parsed,
};
use std::path::{Path, PathBuf};

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            yaml_files(&path, out);
        } else if path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml")
        {
            out.push(path);
        }
    }
}

/// Every finding, token and symbol, as text.
fn both(source: &str, document: &opentide_core::node::Document) -> [(String, String); 2] {
    let input = AnalyzeInput {
        path: "objects/rules/a.yaml",
        source,
        elastic_tenants: &[],
    };
    let own = analyze(AnalyzeInput { ..input });
    let parsed = analyze_parsed(input, document);
    [
        (
            format!("{:?}{:?}{:?}", own.diagnostics, own.tokens, own.symbols),
            format!(
                "{:?}{:?}{:?}",
                parsed.diagnostics, parsed.tokens, parsed.symbols
            ),
        ),
        (
            format!("{:?}", block_diagnostics(source, &[])),
            format!("{:?}", block_diagnostics_parsed(source, document, &[])),
        ),
    ]
}

#[test]
fn a_parse_given_finds_what_the_engine_s_own_parse_finds() {
    let mut files = Vec::new();
    yaml_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata"),
        &mut files,
    );
    files.sort();
    // A rule whose Elastic block advises (a zero lookback) and declares
    // nothing its query carries.
    let advised = "name: A\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  \
                   schema: rule::1.1\nconfigurations:\n  elastic:\n    type: query\n    \
                   language: kuery\n    query: 'process.name: \"a\"'\n    scheduling:\n      \
                   interval: 5m\n      lookback: 0m\n";
    let mut sources: Vec<(String, String)> = vec![("advised".into(), advised.into())];
    for file in &files {
        if let Ok(text) = std::fs::read_to_string(file) {
            sources.push((file.display().to_string(), text));
        }
    }
    let mut compared = 0;
    let mut with_blocks = 0;
    for (file, text) in &sources {
        let text = text.trim_start_matches('\u{feff}').to_owned();
        let Ok(document) = opentide_core::node::load(&text) else {
            continue;
        };
        // The host parses the text after its byte-order mark.
        for source in [text.clone(), format!("\u{feff}{text}")] {
            let [(own, parsed), (blocks, blocks_parsed)] = both(&source, &document);
            assert_eq!(own, parsed, "{file}");
            assert_eq!(blocks, blocks_parsed, "{file}");
            with_blocks += usize::from(blocks != "[]");
        }
        compared += 1;
    }
    // The corpus has objects with blocks that report something.
    assert!(compared >= 100, "{compared} files");
    assert!(with_blocks > 0);
}
