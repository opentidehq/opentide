//! Opt-in sweep over SigmaHQ's Lucene conversions.
//!
//! `OPENTIDE_SIGMA_LUCENE` names a directory of `.lucene` files (one query
//! each). `OPENTIDE_SIGMA_LUCENE_VERDICTS` optionally names a file of Lucene
//! verdicts, one line per query: `OK    <query>`, or `INVALID ...`/`ERROR ...`
//! followed by the query and `  :: <message>`. The sweep prints the confusion
//! matrix of engine errors against those verdicts and a tally of advisory
//! codes. It fails when an engine error lands on a query Lucene accepts.

use opentide_core::Severity;
use std::collections::{BTreeMap, HashMap};

#[test]
fn sigma_lucene_sweep() {
    let Ok(dir) = std::env::var("OPENTIDE_SIGMA_LUCENE") else {
        return;
    };
    let mut verdicts: HashMap<String, bool> = HashMap::new();
    if let Ok(path) = std::env::var("OPENTIDE_SIGMA_LUCENE_VERDICTS") {
        for line in std::fs::read_to_string(path).expect("verdicts").lines() {
            if let Some(q) = line.strip_prefix("OK    ") {
                verdicts.insert(q.trim().to_string(), true);
            } else if line.starts_with("INVALID ") || line.starts_with("ERROR ") {
                // `INVALID <Exception> <query>  :: msg` or `ERROR <pos> <query>  :: msg`
                let rest = line.splitn(3, ' ').nth(2).unwrap_or("");
                let q = rest.rsplit_once("  :: ").map_or(rest, |(q, _)| q);
                verdicts.insert(q.trim().to_string(), false);
            }
        }
    }
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("dir")
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    let mut matrix: BTreeMap<String, usize> = BTreeMap::new();
    let mut advisories: BTreeMap<String, usize> = BTreeMap::new();
    let mut false_errors = Vec::new();
    let show: Vec<String> = std::env::var("OPENTIDE_SWEEP_SHOW")
        .map(|s| s.split(',').map(String::from).collect())
        .unwrap_or_default();
    for path in entries {
        let text = std::fs::read_to_string(&path).unwrap();
        let found = opentide_lucene::analyze(&text).diagnostics;
        let engine_err = found.iter().any(|d| d.severity == Severity::Error);
        for d in &found {
            if d.severity != Severity::Error {
                *advisories.entry(d.code.clone()).or_default() += 1;
            }
            if show.contains(&d.code) {
                println!("{}: {:?} {}", path.display(), d.severity, d.message);
            }
        }
        let jar = verdicts.get(text.trim()).copied();
        let key = format!(
            "lucene={} engine={}",
            match jar {
                Some(true) => "ok",
                Some(false) => "err",
                None => "?",
            },
            if engine_err { "err" } else { "ok" }
        );
        if engine_err && jar == Some(true) {
            false_errors.push(format!("{}: {found:?}", path.display()));
        }
        if !engine_err && jar == Some(false) {
            println!("missed: {}", path.display());
        }
        *matrix.entry(key).or_default() += 1;
    }
    println!("confusion: {matrix:?}");
    println!("advisories: {advisories:?}");
    for f in false_errors.iter().take(20) {
        println!("false error: {f}");
    }
    assert!(
        false_errors.is_empty(),
        "{} false errors",
        false_errors.len()
    );
}
