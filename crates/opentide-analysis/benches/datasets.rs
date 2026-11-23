//! The first use of each embedded dataset (#1743): what a process pays, once,
//! the first time a command or an editor request reads it.
//!
//!     cargo bench -p opentide-analysis --features queries --bench datasets
//!
//! A dataset is read once per process, so each case runs in a process of its
//! own: with no arguments the bench starts itself once per case and round
//! (`--once NAME`), and prints the median wall time of the first use and the
//! peak resident set the process reached, release build.
//!
//! With `--count NAME` it runs one case inside `counted`, for an instruction
//! counter such as callgrind's `--toggle-collect=datasets::counted`:
//! instructions are deterministic where time is not (`cargo xtask throughput`
//! holds each case to `tests/bench/instructions.toml`, `[datasets]`). `--list`
//! prints the cases, one a line.
//!
//! A case goes through a public entry point that exists before and after a
//! change of how a dataset is stored, so the same file measures both.

#![expect(
    clippy::expect_used,
    reason = "a bench binary: a case that cannot start fails the run with its name"
)]

use opentide_analysis::{
    AnalyzeRequest, LanguageId, MemoryWorkspace, QueryRequest, analyze, analyze_query,
};
use std::process::Command;
use std::time::Instant;

/// A case: its name and what it reads.
struct Case {
    name: &'static str,
    run: fn(),
}

fn query(language: LanguageId, platform: Option<&str>, text: &str) {
    std::hint::black_box(analyze_query(&QueryRequest {
        language,
        platform: platform.map(str::to_owned),
        stack: None,
        text: text.to_owned(),
    }));
}

fn vocabulary(field: &str) {
    std::hint::black_box(opentide_schema::vocab::bundled::get(field));
}

/// One case per dataset the issue names, and per language catalog.
const CASES: &[Case] = &[
    Case {
        name: "vocab-attack",
        run: || vocabulary("att&ck"),
    },
    Case {
        name: "vocab-actors",
        run: || vocabulary("actors"),
    },
    Case {
        name: "vocab-all",
        run: || {
            for field in opentide_schema::vocab::bundled::fields() {
                vocabulary(field);
            }
        },
    },
    Case {
        // What the editor's hover and completion on a technique read: the Tide vocabularies.
        name: "tide-vocab-attack",
        run: || {
            std::hint::black_box(opentide_tide::vocab_for_field("att&ck"));
        },
    },
    Case {
        // The editor's first hover on an ATT&CK technique in a rule: what it reads of the Tide
        // vocabularies and field catalog (cold LSP hover, #1743).
        name: "hover-attack-technique",
        run: || {
            let text = "metadata:\n  schema: rule::1.0\ntechniques:\n  - T1059\n";
            let offset = text.find("T1059").map_or(0, |at| at + 2);
            let host = MemoryWorkspace::default();
            std::hint::black_box(opentide_analysis::hover(
                &host,
                LanguageId::TideYaml,
                text,
                offset,
            ));
        },
    },
    Case {
        // The editor's first completion of an ATT&CK technique in a threat: the field catalog,
        // the list of techniques and the name and aliases of each (cold LSP completion, #1745).
        name: "complete-attack-technique",
        run: || {
            let text = "metadata:\n  schema: threat::1.0\nthreat:\n  mitre_attack:\n    - ";
            let host = MemoryWorkspace::default();
            std::hint::black_box(opentide_analysis::completions(
                &host,
                LanguageId::TideYaml,
                text,
                text.len(),
            ));
        },
    },
    Case {
        name: "kql-sentinel",
        run: || query(LanguageId::Kql, Some("sentinel"), "SecurityEvent | take 1"),
    },
    Case {
        name: "kql-defender",
        run: || {
            query(
                LanguageId::Kql,
                Some("defender_for_endpoint"),
                "DeviceProcessEvents | take 1",
            );
        },
    },
    Case {
        name: "spl",
        run: || query(LanguageId::Spl, None, "index=main | stats count by host"),
    },
    Case {
        name: "esql",
        run: || query(LanguageId::Esql, None, "FROM logs-* | LIMIT 1"),
    },
    Case {
        name: "eql",
        run: || {
            query(
                LanguageId::Eql,
                None,
                "process where process.name == \"cmd.exe\"",
            );
        },
    },
    Case {
        name: "lucene-carbon-black",
        run: || {
            query(
                LanguageId::Lucene,
                Some("carbon_black_cloud"),
                "process_name:cmd.exe",
            );
        },
    },
    Case {
        name: "falco",
        run: || {
            query(
                LanguageId::Falco,
                None,
                "evt.type = open and proc.name = cat",
            );
        },
    },
    Case {
        name: "cql",
        run: || {
            query(
                LanguageId::Cql,
                Some("crowdstrike"),
                "#event_simpleName=ProcessRollup2",
            );
        },
    },
    Case {
        name: "exabeam",
        run: || query(LanguageId::Exabeam, None, "process_name = \"cmd.exe\""),
    },
    Case {
        name: "yara",
        run: || query(LanguageId::Yara, None, "rule a { condition: true }"),
    },
    Case {
        name: "yaral",
        run: || {
            query(
                LanguageId::Yaral,
                None,
                "rule a {\n  events:\n    $e.metadata.event_type = \"USER_LOGIN\"\n  condition:\n    $e\n}",
            );
        },
    },
    Case {
        name: "tide-yaml",
        run: || {
            let host = MemoryWorkspace::default();
            std::hint::black_box(analyze(
                &host,
                AnalyzeRequest {
                    uri: "rule.yml".into(),
                    language: LanguageId::TideYaml,
                    text: "name: x\nid: 00000000-0000-0000-0000-000000000000\n".into(),
                },
            ));
        },
    },
];

/// The pass `--toggle-collect` counts.
#[inline(never)]
fn counted(case: &Case) {
    (case.run)();
}

/// Peak resident set of this process, KiB (Linux; 0 elsewhere).
fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmHWM:"))
                .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}

fn find(name: &str) -> &'static Case {
    CASES
        .iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("no case `{name}`: --list prints them"))
}

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--list") => {
            for case in CASES {
                println!("{}", case.name);
            }
        }
        Some("--count") => counted(find(args.get(1).map_or("", String::as_str))),
        Some("--once") => {
            let case = find(args.get(1).map_or("", String::as_str));
            let baseline = peak_rss_kib();
            let start = Instant::now();
            (case.run)();
            let nanos = start.elapsed().as_nanos();
            println!("{nanos} {baseline} {}", peak_rss_kib());
        }
        Some("--bench") | None => {
            let rounds: usize = std::env::var("DATASET_BENCH_ROUNDS")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(15);
            let exe = std::env::current_exe().expect("this executable");
            println!(
                "{:<22} {:>12} {:>14}",
                "case", "first use ms", "RSS growth KiB"
            );
            for case in CASES {
                let mut times = Vec::new();
                let mut growth = Vec::new();
                for _ in 0..rounds {
                    let out = Command::new(&exe)
                        .args(["--once", case.name])
                        .output()
                        .expect("run the case");
                    let text = String::from_utf8_lossy(&out.stdout);
                    let mut fields = text
                        .split_whitespace()
                        .map(|f| f.parse::<f64>().unwrap_or(0.0));
                    let (nanos, before, after) = (
                        fields.next().unwrap_or(0.0),
                        fields.next().unwrap_or(0.0),
                        fields.next().unwrap_or(0.0),
                    );
                    times.push(nanos / 1e6);
                    growth.push(after - before);
                }
                println!(
                    "{:<22} {:>12.3} {:>14.0}",
                    case.name,
                    median(times),
                    median(growth)
                );
            }
        }
        // cargo bench passes `--bench`; anything else is a typo.
        Some(other) => panic!("unknown argument `{other}`"),
    }
}
