#![allow(clippy::all, clippy::pedantic, missing_docs)]
use std::time::Instant;

fn wrap(open: &str, close: &str, atom: &str, d: usize) -> String {
    format!("{}{}{}", open.repeat(d), atom, close.repeat(d))
}
fn chain(term: &str, op: &str, n: usize) -> String { vec![term; n].join(op) }

fn query(lang: &str, kind: &str, n: usize) -> String {
    let nest = kind == "nest";
    match lang {
        "kql" => format!("T | where {}", if nest { wrap("(", ")", "a == 1", n) } else { chain("a == 1", " or ", n) }),
        "spl" => format!("index=x {}", if nest { wrap("(", ")", "a=1", n) } else { format!("({})", chain("a=1", " OR ", n)) }),
        "cql" => if nest { wrap("(", ")", "a=1", n) } else { chain("a=1", " or ", n) },
        "yaral" => {
            let t = "$e.principal.hostname = \"x\"";
            format!("rule r {{\n  meta:\n    author = \"x\"\n  events:\n    {}\n  condition:\n    $e\n}}\n", if nest { wrap("(", ")", t, n) } else { chain(t, " or ", n) })
        }
        "yara" => format!("rule r {{\n  strings:\n    $a = \"x\"\n  condition:\n    {}\n}}\n", if nest { wrap("(", ")", "$a", n) } else { chain("$a", " or ", n) }),
        "exabeam" => if nest { wrap("(", ")", "vendor:\"x\"", n) } else { chain("vendor:\"x\"", " OR ", n) },
        "falco" => if nest { wrap("(", ")", "proc.name = a", n) } else { chain("proc.name = a", " or ", n) },
        "esql" => format!("FROM logs-* | WHERE {}", if nest { wrap("(", ")", "a == 1", n) } else { chain("a == 1", " OR ", n) }),
        "eql" => format!("process where {}", if nest { wrap("(", ")", "a == 1", n) } else { chain("a == 1", " or ", n) }),
        "kuery" => if nest { wrap("(", ")", "a:1", n) } else { chain("a:1", " or ", n) },
        "lucene" => if nest { wrap("(", ")", "a:1", n) } else { chain("a:1", " OR ", n) },
        _ => panic!(),
    }
}

fn codes(lang: &str, q: &str) -> Vec<String> {
    let d: Vec<opentide_core::Diagnostic> = match lang {
        "kql" => opentide_kql::analyze(q, opentide_kql::Profile::Sentinel).diagnostics,
        "spl" => opentide_spl::analyze(q).diagnostics,
        "cql" => opentide_cql::analyze(q).diagnostics,
        "yaral" => opentide_yaral::analyze(q).diagnostics,
        "yara" => opentide_yara::analyze(q).diagnostics,
        "exabeam" => opentide_exabeam::analyze(q).diagnostics,
        "falco" => opentide_falco::analyze(q).diagnostics,
        "esql" => opentide_esql::analyze(q).diagnostics,
        "eql" => opentide_eql::analyze(q).diagnostics,
        "kuery" => opentide_kuery::analyze(q).diagnostics,
        "lucene" => opentide_lucene::analyze(q).diagnostics,
        _ => panic!(),
    };
    let mut c: Vec<String> = d.into_iter().map(|d| d.code).collect();
    c.sort(); c.dedup(); c
}

#[test]
fn probe() {
    let Ok(lang) = std::env::var("PL") else { return };
    let kind = std::env::var("PK").unwrap();
    let n: usize = std::env::var("PN").unwrap().parse().unwrap();
    let t = Instant::now();
    let r = std::thread::Builder::new().stack_size(1 << 20).spawn(move || { let q = query(&lang, &kind, n); codes(&lang, &q) }).unwrap().join().unwrap();
    println!("RESULT {:?} {:?}", t.elapsed(), r);
}
