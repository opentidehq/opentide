//! EXPERIMENT (exp/pure-rust-parser-kuery): the pure-Rust parser's trees as
//! snapshots, its depth guard, and random input that must neither panic nor
//! hang.

use opentide_core::Severity;
use opentide_kuery::{analyze, parser, syntax::SyntaxKind};

fn tree(source: &str) -> String {
    let (root, parse) = parser::parse(source, true);
    let mut out = opentide_parse::debug_tree(&root, |k: SyntaxKind| format!("{k:?}"));
    for e in &parse.errors {
        let expected: Vec<&str> = e
            .expected
            .iter()
            .map(|k| {
                <opentide_kuery::syntax::Kuery as rowan::Language>::kind_from_raw(k).describe()
            })
            .filter(|d| !d.is_empty())
            .collect();
        out.push_str(&format!(
            "error {:?} at {:?}, expected {}\n",
            e.message,
            e.gap,
            expected.join(", ")
        ));
    }
    out
}

#[test]
fn trees() {
    insta::assert_snapshot!(
        "detection",
        tree(
            "event.category:process and not process.name:(\"cmd.exe\" or power shell) and source.port >= 1024"
        )
    );
    insta::assert_snapshot!(
        "nested_and_group",
        tree("(user:{ name:x or id:1 }) or a:1 and b:2 or not c")
    );
    insta::assert_snapshot!("trailing_keyword_is_a_value", tree("f:(a or)"));
    insta::assert_snapshot!("unclosed", tree("a:(b or c"));
    insta::assert_snapshot!("stray_paren", tree("a:1) and b"));
}

#[test]
fn deep_nesting_is_one_diagnostic_on_a_small_stack() {
    let run = || {
        for source in [
            "(".repeat(200_000),
            format!("{}a{}", "(".repeat(100_000), ")".repeat(100_000)),
            format!("f:{}a", "(".repeat(100_000)),
            "a:{".repeat(50_000),
        ] {
            let r = analyze(&source);
            let errors: Vec<_> = r
                .diagnostics
                .iter()
                .filter(|d| d.severity == Severity::Error)
                .collect();
            assert!(!errors.is_empty());
            let _ = opentide_kuery::ecs_diagnostics(&source);
            let _ = opentide_kuery::hover(&source, source.len() / 2);
        }
        // Nesting within the limit parses as tree-sitter did.
        let ok = format!("{}a:1{}", "(".repeat(200), ")".repeat(200));
        assert!(analyze(&ok).diagnostics.is_empty());
    };
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(run)
        .unwrap()
        .join()
        .unwrap();
}

/// Seeded random strings over KQL's alphabet: no panic, no hang.
#[test]
fn random_input_neither_panics_nor_hangs() {
    let n: usize = std::env::var("OPENTIDE_KUERY_RANDOM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let alphabet: Vec<char> = "ab:()<>={}\"\\* \t\nnotandorNOTANDOR~^?[]-_/.0é\u{a0}"
        .chars()
        .collect();
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let started = std::time::Instant::now();
    for _ in 0..n {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = usize::try_from(state % 40).unwrap();
        let mut s = String::new();
        let mut x = state;
        for _ in 0..len {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            s.push(alphabet[usize::try_from(x >> 33).unwrap() % alphabet.len()]);
        }
        let r = analyze(&s);
        let _ = opentide_kuery::ecs_diagnostics(&s);
        let _ = opentide_kuery::hover(&s, len / 2);
        let _ = opentide_kuery::completions(&s, s.len());
        assert!(
            r.tokens
                .windows(2)
                .all(|w| w[0].span.end <= w[1].span.start),
            "{s:?}"
        );
    }
    eprintln!("{n} random queries in {:?}", started.elapsed());
}
