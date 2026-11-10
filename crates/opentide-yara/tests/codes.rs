//! Every yara-1.0 code, on the smallest signature that reports it, and the
//! spec's own examples clean. Each case asserts the exact set of codes, so a
//! check that starts firing elsewhere fails here too.

use opentide_core::Severity;
use opentide_yara::{Context, Dialect, Profile, analyze_with};

fn codes(source: &str, ctx: &Context) -> Vec<(String, Severity)> {
    let mut out: Vec<_> = analyze_with(source, ctx)
        .diagnostics
        .into_iter()
        .map(|d| (d.code, d.severity))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn raw() -> Context {
    Context::default()
}

const E: Severity = Severity::Error;
const W: Severity = Severity::Warning;

/// `(source, expected codes)` for a raw `.yar` file (libyara 4.5, no profile).
const RAW: &[(&str, &[(&str, Severity)])] = &[
    // Clean.
    ("rule a { condition: true }", &[]),
    ("rule a { strings: $a = \"MZ\" condition: $a at 0 }", &[]),
    (
        "import \"pe\" rule a { condition: pe.number_of_sections > 2 and pe.exports(\"x\") and pe.imphash() == \"a\" }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: for any s in pe.sections : ( s.name == \".text\" ) }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: for any k, v in pe.version_info : ( k == \"x\" and v contains \"y\" ) }",
        &[],
    ),
    (
        "import \"math\" rule a { condition: math.entropy(0, filesize) > 7.0 }",
        &[],
    ),
    (
        "rule a { strings: $a = \"abcd\" $b = \"efgh\" condition: for any of ($a, $b) : ( # > 2 and @ < 100 ) }",
        &[],
    ),
    (
        "rule a { strings: $a1 = \"abcd\" $a2 = \"efgh\" condition: any of ($a*) and #a1 in (0..100) == 1 and @a1[1] < !a2[1] }",
        &[],
    ),
    ("rule a { strings: $_x = \"abcd\" condition: true }", &[]),
    (
        "private rule p { condition: true } rule a { condition: p and any of (p) }",
        &[],
    ),
    (
        "rule a { strings: $h = { 4D 5A [2-4] ( 90 | 91 ) ~00 ?0 } condition: $h }",
        &[],
    ),
    (
        "rule a { strings: $r = /ab[cd]+e/is wide condition: $r }",
        &[],
    ),
    (
        "rule a { strings: $a = \"abc\" xor(1-255) wide condition: $a }",
        &[],
    ),
    (
        "rule a { condition: uint16(0) == 0x5A4D and uint32be(4) & 0xFF != 0 and filesize < 1MB }",
        &[],
    ),
    // Errors.
    ("rule a { condition: true and }", &[("yara_parse_error", E)]),
    (
        "include \"x.yar\" rule a { condition: true }",
        &[("yara_include", E)],
    ),
    (
        "private rule a { condition: true }",
        &[("yara_empty_signature", E)],
    ),
    ("", &[("yara_empty_signature", E)]),
    (
        "rule a { condition: true } rule a { condition: false }",
        &[("yara_duplicate_rule", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" $a = \"efgh\" condition: $a }",
        &[("yara_duplicate_string", E)],
    ),
    (
        "rule a : t t { condition: true }",
        &[("yara_duplicate_tag", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: $a and $b }",
        &[("yara_undefined_string", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: #b > 1 or $a }",
        &[("yara_undefined_string", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: $a and any of ($c*) }",
        &[("yara_undefined_string", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: $ and $a }",
        &[("yara_undefined_string", E)],
    ),
    (
        "rule a { condition: any of them }",
        &[("yara_undefined_string", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" $b = \"efgh\" condition: $a }",
        &[("yara_unreferenced_string", E)],
    ),
    (
        "rule a { condition: b }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "rule a { condition: b } rule b { condition: true }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "rule a { condition: foo(1) }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "import \"pe\" rule pe { condition: true }",
        &[("yara_rule_identifier_conflict", E)],
    ),
    (
        "rule uint8 { condition: true }",
        &[("yara_rule_identifier_conflict", E)],
    ),
    (
        "import \"foo\" rule a { condition: true }",
        &[("yara_unknown_module", E)],
    ),
    (
        "rule a { condition: pe.number_of_sections > 1 }",
        &[("yara_module_not_imported", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.nonexistent == 1 }",
        &[("yara_unknown_module_member", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.exports(1, 2) }",
        &[("yara_unknown_module_member", E)],
    ),
    (
        "import \"math\" rule a { condition: math.entropy(\"a\", \"b\") > 1 }",
        &[("yara_unknown_module_member", E)],
    ),
    (
        "rule a { condition: filesize contains \"a\" }",
        &[("yara_type", E)],
    ),
    ("rule a { condition: \"a\" + 1 > 2 }", &[("yara_type", E)]),
    (
        "rule a { condition: filesize matches \"x\" }",
        &[("yara_type", E), ("yara_type", E)],
    ),
    (
        "rule a { strings: $r = /a(b/ condition: $r }",
        &[("yara_regexp", E)],
    ),
    (
        "rule a { strings: $r = /[z-a]bc/ condition: $r }",
        &[("yara_regexp", E)],
    ),
    (
        "rule a { condition: \"x\" matches /a{3,1}/ }",
        &[("yara_regexp", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 [4-2] 03 04 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 ( 03 | [-] 04 ) 05 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 ( 03 | [1-300] 04 ) 05 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    (
        "rule a { strings: $h = { 01 0 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    (
        "rule a { strings: $a = \"abc\" base64 nocase condition: $a }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { strings: $a = \"abc\" xor nocase condition: $a }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" wide wide condition: $a }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 03 04 } xor condition: $h }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" xor(3-1) condition: $a }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" xor(300) condition: $a }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" base64(\"abc\") condition: $a }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { condition: filesize == 99999999999999999999 }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: 150% of them }",
        &[("yara_number_out_of_range", E)],
    ),
    // YARA-X-only syntax: errors under libyara.
    (
        "rule a { condition: with x = 1 : ( x == 1 ) }",
        &[("yara_parse_error", E)],
    ),
    (
        "rule a { condition: 1_000 == 1000 }",
        &[("yara_parse_error", E)],
    ),
    (
        "rule a { meta: f = 1.5 condition: true }",
        &[("yara_parse_error", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 [0x2-0x4] 03 04 } condition: $h }",
        &[("yara_parse_error", E)],
    ),
    (
        "rule a { condition: 1 of (true, false) }",
        &[("yara_parse_error", E), ("yara_parse_error", E)],
    ),
    // Warnings.
    (
        "rule a { strings: $r = /\\Release/ condition: $r }",
        &[("yara_x_incompatible", W)],
    ),
    (
        "rule a { strings: $r = /abc{/ condition: $r }",
        &[("yara_x_incompatible", W)],
    ),
    (
        "rule a { strings: $a = \"ab\" base64 condition: $a }",
        &[("yara_x_incompatible", W)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: @a[-1] == 0 }",
        &[("yara_x_incompatible", W)],
    ),
    (
        "global global rule a { condition: true } rule b { condition: true }",
        &[("yara_x_incompatible", W)],
    ),
    (
        "private rule base1 { condition: true } rule a { condition: any of (base*) }",
        &[("yara_x_incompatible", W)],
    ),
    (
        "rule a { strings: $a = \"abcd\" base64(\"!@#$%^&*(){}[].,|ABCDEFGHIJ\\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu\") condition: $a }",
        &[("yara_x_incompatible", W)],
    ),
    (
        "rule a { strings: $a = \"a\" condition: $a }",
        &[("yara_slow_pattern", W)],
    ),
    (
        "rule a { strings: $h = { ?? ?? ?? } condition: $h }",
        &[("yara_slow_pattern", W)],
    ),
    (
        "rule a { strings: $r = /a.b/ condition: $r }",
        &[("yara_slow_pattern", W)],
    ),
    (
        "rule a { condition: entrypoint == 0 }",
        &[("yara_entrypoint_deprecated", W)],
    ),
    (
        "rule a { condition: \"abc\" and true }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { condition: filesize }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: 2 of them }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: 0 of them }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { strings: $a = \"abcd\" $b = \"efgh\" condition: all of them at 0 }",
        &[("yara_suspicious_expression", W)],
    ),
];

#[test]
fn every_code_on_a_raw_signature() {
    let mut failures = Vec::new();
    for (source, expected) in RAW {
        let got = codes(source, &raw());
        let mut want: Vec<(String, Severity)> =
            expected.iter().map(|(c, s)| (c.to_string(), *s)).collect();
        want.sort_by(|a, b| a.0.cmp(&b.0));
        if got != want {
            failures.push(format!("{source}\n    want {want:?}\n    got  {got:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn profiles() {
    let hl = Context::for_profile(Profile::Harfanglab);
    let bd = Context::for_profile(Profile::Bitdefender);
    let ok = "rule a { meta: context = \"file\" condition: true }";
    assert_eq!(codes(ok, &hl), []);
    assert_eq!(codes(ok, &bd), []);
    assert_eq!(
        codes("rule a { condition: true }", &hl),
        [("yara_meta_missing".to_string(), W)]
    );
    assert_eq!(
        codes(
            "private rule p { condition: true } rule a { meta: context = \"file\" condition: p }",
            &hl
        ),
        []
    );
    assert_eq!(
        codes("rule a { meta: context = \"disk\" condition: true }", &hl),
        [("harfanglab_yara_context".to_string(), W)]
    );
    assert_eq!(
        codes(
            "import \"dotnet\" rule a { meta: context = \"file\" condition: true }",
            &hl
        ),
        [("yara_module_unconfirmed".to_string(), W)]
    );
    assert_eq!(
        codes("rule a { meta: d = \"é\" condition: true }", &bd),
        [("bitdefender_yara_ascii".to_string(), E)]
    );
    let big = format!(
        "rule a {{ meta: d = \"{}\" condition: true }}",
        "x".repeat(30_000)
    );
    assert_eq!(codes(&big, &bd), [("bitdefender_yara_size".to_string(), E)]);
    assert_eq!(codes(&big, &raw()), []);
}

#[test]
fn yara_x_dialect_accepts_its_syntax_and_refuses_libyara_only() {
    let yx = Context {
        dialect: Dialect::YaraX,
        profile: None,
    };
    assert_eq!(
        codes("rule a { condition: with x = 1 : ( x == 1 ) }", &yx),
        []
    );
    assert_eq!(
        codes("rule a { strings: $r = /\\Release/ condition: $r }", &yx),
        [("yara_x_incompatible".to_string(), E)]
    );
}

/// yara-1.0's example, and the fixtures the spec ships for it.
#[test]
fn spec_examples_are_clean() {
    let example = r#"import "pe"

private rule MZ_Header {
  condition:
    uint16(0) == 0x5A4D
}

rule Loader_Stage1 : loader {
  meta:
    description = "Stage-1 loader with an encrypted config blob"
    context = "file,memory"
  strings:
    $cfg = { 43 46 47 21 [4-16] 00 01 }
    $mutex = "Global\\qx-7731" ascii wide
  condition:
    MZ_Header and pe.number_of_sections > 3 and all of them
}
"#;
    assert_eq!(codes(example, &raw()), []);
    assert_eq!(
        codes(example, &Context::for_profile(Profile::Harfanglab)),
        []
    );
    assert_eq!(
        codes(example, &Context::for_profile(Profile::Bitdefender)),
        []
    );
}
