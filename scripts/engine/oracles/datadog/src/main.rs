//! Reads one JSON string a line on stdin (a query) and prints `accept` or `reject` a line: whether
//! VRL's Datadog search grammar parses the whole query (its rule `queryroot`). An accept-or-reject
//! verdict only: VRL's grammar has no precedence (VRL's Rust applies it after the parse) and its
//! parse tree is not compared.

use std::io::{BufRead, Write};

use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "../.cache/grammar.pest"]
struct Vrl;

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(query) = serde_json::from_str::<String>(&line) else {
            let _ = writeln!(out, "error");
            continue;
        };
        let verdict = if Vrl::parse(Rule::queryroot, &query).is_ok() {
            "accept"
        } else {
            "reject"
        };
        let _ = writeln!(out, "{verdict}");
    }
}
