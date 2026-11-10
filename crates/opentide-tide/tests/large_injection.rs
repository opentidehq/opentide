//! A large injected query analyses in time linear in its size.
//!
//! Every semantic token and finding of an injection is converted to a
//! position in the object file. Doing that by scanning the file from its
//! start made a Tide rule with a 1 MB YARA signature take minutes, growing
//! with the square of its size; one `LineIndex` per text makes it linear.
//! This guard fails if that comes back: a 2 MB signature must analyse within
//! a generous bound, and doubling the signature must not quadruple the time.

use opentide_tide::{AnalyzeInput, analyze};
use std::time::{Duration, Instant};

/// A HarfangLab rule whose `yara.signature` is about `bytes` long: many
/// small YARA rules, each with strings, a hex string and a condition, so the
/// signature has hundreds of thousands of tokens.
fn rule_with_signature(bytes: usize) -> String {
    let mut signature = String::from("import \"pe\"\n\n");
    let mut i = 0;
    while signature.len() < bytes {
        signature.push_str(&format!(
            "rule Generated_{i} : tag{} {{\n  meta:\n    description = \"generated rule {i}\"\n  strings:\n    $name = \"driver_{i}.sys\" ascii wide nocase\n    $hex = {{ 4D 5A 90 00 [2-4] ?? {:02X} }}\n    $re = /svc[0-9]{{2,4}}_{i}/\n  condition:\n    uint16(0) == 0x5A4D and filesize < 2MB and ($name or $hex or $re) and pe.number_of_sections > 2\n}}\n\n",
            i % 7,
            i % 256
        ));
        i += 1;
    }
    let body: String = signature
        .lines()
        .map(|l| {
            if l.is_empty() {
                "\n".to_string()
            } else {
                format!("        {l}\n")
            }
        })
        .collect();
    format!(
        "name: Generated large signature
metadata:
  uuid: 00000000-0000-4000-8003-0000000000ab
  schema: rule::1.0
  version: 1
  created: \"2026-01-01\"
  modified: \"2026-01-02\"
  tlp: clear
  author: Detection Engineering
description: |
  A HarfangLab YARA signature of many generated rules.
response:
  alert_severity: High
configurations:
  harfanglab:
    enabled: true
    schema: platform::harfanglab::1.0
    status: STAGING
    yara:
      signature: |
{body}"
    )
}

fn time_analyze(source: &str) -> (Duration, usize) {
    let start = Instant::now();
    let result = analyze(AnalyzeInput {
        path: "objects/rules/generated-large-signature.yaml",
        source,
        workspace: &[],
        elastic_tenants: &[],
    });
    (start.elapsed(), result.tokens.len())
}

#[test]
fn a_large_yara_signature_analyses_in_linear_time() {
    let small = rule_with_signature(512 * 1024);
    let large = rule_with_signature(2 * 1024 * 1024);
    // Warm the catalogs and grammars, which load once per process.
    time_analyze(&rule_with_signature(4 * 1024));
    let (t_small, tokens_small) = time_analyze(&small);
    let (t_large, tokens_large) = time_analyze(&large);
    assert!(
        tokens_large > 3 * tokens_small,
        "{tokens_small} {tokens_large}"
    );
    assert!(tokens_large > 300_000, "{tokens_large} tokens");
    // Unoptimised test builds are slow; quadratic remapping took minutes.
    assert!(
        t_large < Duration::from_secs(120),
        "2 MB signature took {t_large:?}"
    );
    // 4x the text: linear is about 4x, quadratic about 16x.
    let ratio = t_large.as_secs_f64() / t_small.as_secs_f64().max(1e-3);
    assert!(
        ratio < 9.0,
        "4x the signature took {ratio:.1}x the time ({t_small:?} -> {t_large:?})"
    );
}
