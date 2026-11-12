//! `analyze()` per language, and hover in a large workspace (#181).
//!
//!     cargo bench -p opentide-analysis --bench analyze
//!
//! Each language runs its whole `testdata/corpus/<lang>/` corpus; the line is
//! the median time per file over the rounds. The workspace case is hover on a
//! rule among 1,000 indexed objects, the index built once as the language
//! server keeps it. CI runs this without gating (ci.yml, `bench`): the numbers
//! are for comparing runs, not limits.

use opentide_analysis::{
    AnalyzeRequest, IndexedObject, LanguageId, MemoryWorkspace, WorkspaceHost, analyze, hover,
};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROUNDS: usize = 15;

fn median(mut times: Vec<Duration>) -> Duration {
    times.sort();
    times[times.len() / 2]
}

fn corpus(language: &str) -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/corpus")
        .join(language);
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    files.sort();
    files
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect()
}

/// A host whose index is built once, as the server keeps it.
struct Indexed {
    files: Vec<(String, String)>,
    index: Arc<[IndexedObject]>,
}

impl WorkspaceHost for Indexed {
    fn document(&self, uri: &str) -> Option<String> {
        self.files
            .iter()
            .find(|(p, _)| p == uri)
            .map(|(_, t)| t.clone())
    }
    fn documents(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    fn indexed_objects(&self) -> Option<Arc<[IndexedObject]>> {
        Some(Arc::clone(&self.index))
    }
}

fn main() {
    let host = MemoryWorkspace::default();
    println!("{:<10} {:>6} {:>14}", "language", "files", "median/file");
    for (name, language) in [
        ("kql", LanguageId::Kql),
        ("spl", LanguageId::Spl),
        ("esql", LanguageId::Esql),
        ("eql", LanguageId::Eql),
        ("kuery", LanguageId::Kuery),
        ("lucene", LanguageId::Lucene),
        ("falco", LanguageId::Falco),
        ("cql", LanguageId::Cql),
        ("yara", LanguageId::Yara),
        ("exabeam", LanguageId::Exabeam),
        ("yaral", LanguageId::Yaral),
    ] {
        let texts = corpus(name);
        if texts.is_empty() {
            continue;
        }
        let mut times = Vec::new();
        for round in 0..=ROUNDS {
            let start = Instant::now();
            for text in &texts {
                analyze(
                    &host,
                    AnalyzeRequest {
                        uri: format!("/w/q.{name}"),
                        language,
                        text: text.clone(),
                    },
                );
            }
            // The first round warms the catalogs and compiled queries.
            if round > 0 {
                times.push(start.elapsed() / texts.len() as u32);
            }
        }
        println!("{name:<10} {:>6} {:>14?}", texts.len(), median(times));
    }

    // Hover in a 1,000-object workspace.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata");
    let rule = std::fs::read_to_string(root.join("objects/rules/rule-1.0.yaml")).unwrap();
    let objective = std::fs::read_to_string(root.join("objects/objective-1.0.yaml")).unwrap();
    let mut files = Vec::new();
    for i in 0..500 {
        let o = objective.replace(
            "00000000-0000-4000-8002-000000000001",
            &format!("00000000-0000-4000-8002-{i:012}"),
        );
        let r = rule
            .replace(
                "00000000-0000-4000-8003-000000000001",
                &format!("00000000-0000-4000-8003-{i:012}"),
            )
            .replace(
                "00000000-0000-4000-8002-000000000001",
                &format!("00000000-0000-4000-8002-{i:012}"),
            );
        files.push((format!("/w/objects/objectives/o{i}.yaml"), o));
        files.push((format!("/w/objects/rules/r{i}.yaml"), r));
    }
    let index: Arc<[IndexedObject]> = files
        .iter()
        .filter_map(|(p, t)| opentide_analysis::index_object(p, t))
        .collect::<Vec<_>>()
        .into();
    let (_, text) = files[1].clone();
    let host = Indexed { files, index };
    let at = text.find("detection_model").unwrap() + 2;
    let mut times = Vec::new();
    for _ in 0..=ROUNDS {
        let start = Instant::now();
        let _ = hover(&host, LanguageId::TideYaml, &text, at);
        times.push(start.elapsed());
    }
    println!(
        "{:<10} {:>6} {:>14?}",
        "hover",
        host.index.len(),
        median(times)
    );
}
