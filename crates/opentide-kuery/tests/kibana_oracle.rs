//! Opt-in differential check against Kibana's KQL grammar.
//!
//! Set `OPENTIDE_KUERY_VERDICTS` to a file of lines `OK<TAB><json string>` or
//! `ERR<TAB><json string><TAB><Kibana's message>`, as produced by running
//! Kibana's compiled `grammar.peggy` over the strings. The test fails when
//! the engine reports an error on a query Kibana accepts, and prints how
//! many rejected queries it misses. Without the variable it does nothing.

use opentide_core::Severity;

/// A JSON string literal (`"..."` with `\"`, `\\`, `\n`, `\t`, `\r`, `\uXXXX`).
fn json_string(s: &str) -> String {
    let s = s.trim();
    let inner = &s[1..s.len() - 1];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(c);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

#[test]
fn kibana_verdicts() {
    let Ok(path) = std::env::var("OPENTIDE_KUERY_VERDICTS") else {
        return;
    };
    let text = std::fs::read_to_string(path).expect("verdict file");
    let (mut ok, mut err, mut missed) = (0, 0, 0);
    let mut false_errors = Vec::new();
    let mut missing = Vec::new();
    for line in text.lines() {
        let mut cols = line.splitn(3, '\t');
        let (Some(verdict), Some(query)) = (cols.next(), cols.next()) else {
            continue;
        };
        let query = json_string(query);
        let found = opentide_kuery::analyze(&query).diagnostics;
        let errors: Vec<_> = found
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .collect();
        if verdict == "OK" {
            ok += 1;
            if !errors.is_empty() {
                false_errors.push(format!("{query:?}: {errors:?}"));
            }
        } else {
            err += 1;
            let kibana = cols.next().unwrap_or("");
            if errors.is_empty() {
                missed += 1;
                missing.push(format!("{query:?}: {kibana}"));
            }
        }
    }
    println!("accepted {ok}, rejected {err}: missed {missed}");
    for m in missing.iter().take(30) {
        println!("missed: {m}");
    }
    for f in false_errors.iter().take(30) {
        println!("false error: {f}");
    }
    assert!(
        false_errors.is_empty(),
        "{} false errors",
        false_errors.len()
    );
}
