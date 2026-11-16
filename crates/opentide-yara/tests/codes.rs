//! Every yara-1.0 code, on the smallest signature that reports it, and the
//! spec's own examples clean. Each case asserts the exact set of codes, so a
//! check that starts firing elsewhere fails here too.

#![expect(
    clippy::cast_possible_truncation,
    reason = "positions and counts in test documents of a few lines"
)]

use opentide_core::Severity;
use opentide_yara::{Context, Profile, WARNING_CODES, YaraXSyntax, always_warning, analyze_with};

fn codes(source: &str, ctx: &Context) -> Vec<(String, Severity)> {
    let mut out: Vec<_> = analyze_with(source, ctx)
        .diagnostics
        .into_iter()
        .map(|d| (d.code, d.severity))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// A raw context that refuses YARA-X-only syntax, as a platform profile does.
fn raw() -> Context {
    Context {
        yara_x_syntax: YaraXSyntax::Refused,
        ..Context::default()
    }
}

const E: Severity = Severity::Error;
const W: Severity = Severity::Warning;

/// `(source, expected codes)` for a raw `.yar` file under a context that
/// refuses YARA-X-only syntax (YARA-X 1.x, #1225).
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
    // The modules are YARA-X's defaults less `vt` (#1225): `magic` is no
    // default, `vt` is excluded; `crx` and `zip` are known.
    (
        "import \"magic\" rule a { condition: true }",
        &[("yara_unknown_module", E)],
    ),
    (
        "import \"vt\" rule a { condition: true }",
        &[("yara_unknown_module", E)],
    ),
    (
        "import \"crx\" import \"zip\" rule a { condition: crx.is_crx or zip.is_zip }",
        &[],
    ),
    // Every YARA-X module boolean compares with `==` (YARA-X warns,
    // `bool_int_comparison`) and is refused in an ordering, as
    // `pe.is_signed` is (checked against the 1.23.0 wheel).
    (
        "import \"lnk\" rule a { condition: lnk.is_lnk == 1 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"lnk\" rule a { condition: lnk.is_lnk > 0 }",
        &[("yara_type", E)],
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
        // A branch that starts with a jump is a syntax error.
        "rule a { strings: $h = { 01 02 ( 03 | [-] 04 ) 05 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    (
        // A branch that starts with a jump is a syntax error.
        "rule a { strings: $h = { 01 02 ( 03 | [1-300] 04 ) 05 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    // YARA-X takes any jump inside an alternative: libyara refused an
    // unbounded or over-200 one (#1405 review).
    (
        "rule a { strings: $h = { 01 ( 02 [1-300] 03 | 04 ) 05 } condition: $h }",
        &[("yara_slow_pattern", W)],
    ),
    (
        "rule a { strings: $h = { 01 ( 02 [-] 03 | 04 ) 05 } condition: $h }",
        &[("yara_slow_pattern", W)],
    ),
    // YARA-X reads an index above `i64::MAX` as a negative `i64` (E007).
    (
        "rule a { strings: $a = \"abc\" condition: @a[0xFFFFFFFFFFFFFFFF] == 0 }",
        &[("yara_number_out_of_range", E)],
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
    // YARA-X-only syntax: the portability check's errors.
    (
        "rule a { strings: $a = \"abcd\" condition: for 50% of them : ( $ ) }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { condition: with x = 1 : ( x == 1 ) }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { condition: 1_000 == 1000 }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { meta: f = 1.5 condition: true }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 [0x2-0x4] 03 04 } condition: $h }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { condition: 1 of (true, false) }",
        &[("yara_x_only_syntax", E), ("yara_x_only_syntax", E)],
    ),
    // What libyara compiled and YARA-X refuses: errors (#1225).
    (
        "rule a { strings: $r = /\\Release/ condition: $r }",
        &[("yara_regexp", E)],
    ),
    (
        "rule a { strings: $r = /abc{/ condition: $r }",
        &[("yara_regexp", E)],
    ),
    (
        "rule a { strings: $a = \"ab\" base64 condition: $a }",
        &[("yara_string_modifier", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: @a[-1] == 0 }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "global global rule a { condition: true } rule b { condition: true }",
        &[("yara_parse_error", E)],
    ),
    (
        "private rule base1 { condition: true } rule a { condition: any of (base*) }",
        &[("yara_parse_error", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" base64(\"!@#$%^&*(){}[].,|ABCDEFGHIJ\\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu\") condition: $a }",
        &[("yara_parse_error", E)],
    ),
    // YARA-X's semantics where libyara's differed (each checked on the wheel).
    (
        "rule a { condition: uint64(0) == 1 and int64be(0) == 1 }",
        &[("yara_x_only_syntax", E), ("yara_x_only_syntax", E)],
    ),
    (
        "rule a { condition: float32(0) > 1.5 }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { condition: float64(0) contains \"a\" }",
        &[("yara_type", E), ("yara_x_only_syntax", E)],
    ),
    (
        "rule int64 { condition: true }",
        &[("yara_rule_identifier_conflict", E)],
    ),
    (
        "rule a { condition: \"x\" matches /(?i)abc/ }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { condition: \"x\" matches /(|abc)/ }",
        &[("yara_x_only_syntax", E)],
    ),
    (
        "rule a { condition: \"x\" matches /(?=abc)/ }",
        &[("yara_regexp", E)],
    ),
    (
        "rule a { condition: for all x in (1.0, 2.0) : (x >= 1.0) }",
        &[],
    ),
    (
        "rule a { condition: for all x in (1, 2.0) : (x >= 1.0) }",
        &[("yara_type", E)],
    ),
    (
        "rule a { condition: for any i in (\"a\", 2) : (true) }",
        &[("yara_type", E)],
    ),
    ("rule a { condition: -9223372036854775808 \\ -1 == 0 }", &[]),
    ("rule a { condition: 1 \\ 0 == 0 and 1 % 0 == 0 }", &[]),
    (
        "rule a { condition: 4611686018427387904 * -2 == 0 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { condition: 0xFFFFFFFFFFFFFFFF - 1 == 0xFFFFFFFFFFFFFFFE and -(0x8000000000000000) == -9223372036854775808 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { condition: (4 \\ 2) * (0xFFFFFFFFFFFFFFFF \\ 2) == filesize }",
        &[],
    ),
    (
        "rule a { condition: 2 * 4611686018427387904 == 1 }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { condition: -(-9223372036854775808) == 1 }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { condition: 0xFFFFFFFFFFFFFFFF + 1 == 0 }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { condition: -(0xFFFFFFFFFFFFFFFF) == 1 }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { condition: 0xFFFFFFFFFFFFFFFF & 1 == 0 and uint8(0xFFFFFFFFFFFFFFFF) == 0 }",
        &[],
    ),
    (
        "rule a { condition: for any i in (0..0x8000000000000000) : (true) }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: $a at 0xFFFFFFFFFFFFFFFF }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: $a in (0..0xFFFFFFFFFFFFFFFF) }",
        &[("yara_number_out_of_range", E)],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: 0% of them }",
        &[],
    ),
    (
        "rule a { strings: $a = \"abcd\" condition: 101% of them }",
        &[("yara_number_out_of_range", E)],
    ),
    // A `with` declaration sees the ones before it.
    (
        "rule a { condition: with a = 1, b = a + 1 : (b == 2) }",
        &[("yara_x_only_syntax", E)],
    ),
    // Two alphabets: YARA-X's.
    (
        "rule a { strings: $a = \"abcd\" base64(\"!@#$%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu\") base64wide(\"!@#$%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstv\") condition: $a }",
        &[("yara_x_only_syntax", E)],
    ),
    // Warnings.
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
        &[
            ("yara_entrypoint_deprecated", W),
            ("yara_undefined_identifier", E),
        ],
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
    ), // Review of #165 (libyara 4.5.4 and YARA-X 1.23.0 checked on each).
    // YARA-X has no identifier length limit (libyara stopped at 128).
    (
        "rule aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa { condition: true }",
        &[],
    ),
    (
        "rule aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa { condition: true }",
        &[],
    ),
    (
        "rule r : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa { condition: true }",
        &[],
    ),
    (
        "rule r { meta: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = 1 condition: true }",
        &[],
    ),
    // A module used above its import is undefined there.
    (
        "rule a { condition: pe.is_dll() }\nimport \"pe\"",
        &[("yara_module_not_imported", E)],
    ),
    (
        "import \"pe\"\nrule a { condition: pe.number_of_sections > 1 }",
        &[],
    ),
    // `.len()` is YARA-X's.
    (
        "import \"pe\"\nrule a { condition: pe.sections.len() > 1 }",
        &[("yara_x_only_syntax", E)],
    ),
    // Invariant and unsatisfiable conditions.
    (
        "rule a { condition: 1 == 1 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { condition: filesize < 0 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { condition: filesize >= 0 }",
        &[("yara_suspicious_expression", W)],
    ),
    ("rule a { condition: filesize > 0 }", &[]),
    // A negative number after an earlier `xor(a-b)` is a number, not a modifier.
    (
        "rule a { strings: $a = \"abcd\" xor(1-2) condition: $a and -99999999999999999999 }",
        &[("yara_number_out_of_range", E)],
    ),
    // A non-boolean condition, as YARA-X's non_bool_expr reads it: a
    // predicate YARA-X types as boolean is none; an integer member is.
    ("import \"pe\" rule a { condition: pe.is_dll() }", &[]),
    ("import \"pe\" rule a { condition: pe.is_32bit() }", &[]),
    ("import \"pe\" rule a { condition: pe.exports(\"x\") }", &[]),
    (
        "import \"pe\" rule a { condition: pe.number_of_sections }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"math\" rule a { condition: math.entropy(0, filesize) }",
        &[("yara_suspicious_expression", W)],
    ),
    // YARA-X reads a jump bound up to 2^32 - 1 (libyara refused 2^31 and up).
    (
        "rule a { strings: $h = { 4D 5A 90 00 [0-2147483647] 50 45 00 00 } condition: $h }",
        &[],
    ),
    (
        "rule a { strings: $h = { 4D 5A 90 00 [0-2147483648] 50 45 00 00 } condition: $h }",
        &[],
    ),
    (
        "rule a { strings: $h = { 4D 5A 90 00 [3000000000] 50 45 00 00 } condition: $h }",
        &[],
    ),
    // A bound past u32 is refused.
    (
        "rule a { strings: $h = { 01 [0-4294967296] 02 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 03 04 [4294967296] 05 06 07 08 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    // `[0-0]` skips no byte.
    (
        "rule a { strings: $h = { 01 02 03 04 [0-0] 05 06 07 08 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    // A rule named like an imported module.
    (
        "import \"pe\"\nrule pe { condition: true }",
        &[("yara_rule_identifier_conflict", E)],
    ),
    // An undefined string is the finding; libyara stops before unused ones.
    (
        "rule a { strings: $c = \"abcd\" condition: $ }",
        &[("yara_undefined_string", E)],
    ),
    (
        "rule a { strings: $d = \"abcd\" condition: any of ($c*) }",
        &[("yara_undefined_string", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 03 04 [9223372036854775813] 05 06 07 08 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    (
        "rule a { strings: $h = { 01 02 03 04 [18446744073709551621] 05 06 07 08 } condition: $h }",
        &[("yara_hex_string", E)],
    ),
    // An integer compared with a boolean (YARA-X `bool_int_comparison`).
    (
        "import \"pe\" rule a { condition: pe.is_dll() == 1 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"pe\" rule a { condition: pe.exports(\"x\") == 0 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_signed == 1 }",
        &[("yara_suspicious_expression", W)],
    ),
    // Arithmetic or an ordering on what YARA-X types as a boolean.
    (
        "import \"pe\" rule a { condition: pe.is_dll() > 0 }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_dll() * 2 > 1 }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_dll() + 1 }",
        &[("yara_suspicious_expression", W), ("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_dll() & 1 }",
        &[("yara_suspicious_expression", W), ("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: -pe.is_dll() }",
        &[("yara_suspicious_expression", W), ("yara_type", E)],
    ),
    // A non-boolean operand of `and`, `or`, `not` or a `for` body (YARA-X
    // `non_bool_expr`).
    (
        "import \"pe\" rule a { condition: true and pe.number_of_sections }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"pe\" rule a { condition: not pe.number_of_sections }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "rule a { condition: true and 1 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_dll() or 0 }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"pe\" rule a { condition: for any s in pe.sections : ( s.virtual_size ) }",
        &[("yara_suspicious_expression", W)],
    ),
    // A function member of a struct array's element.
    (
        "import \"pe\" rule a { condition: pe.signatures[0].valid_on(0) }",
        &[],
    ),
    // `defined` takes any value: its operand is no boolean context.
    (
        "import \"pe\" rule a { condition: defined pe.number_of_sections }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: not defined pe.number_of_sections }",
        &[],
    ),
    ("rule a { condition: defined 1 }", &[]),
    ("rule a { condition: defined filesize and true }", &[]),
    (
        "import \"pe\" rule a { condition: defined pe.sections[0].name }",
        &[],
    ),
    // A field called, or a function named and not called: libyara's "is not a
    // function" and "wrong usage of identifier".
    (
        "import \"pe\" rule a { condition: pe.sections[0].name(0) }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.sections[0].name() == \"x\" }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "import \"pe\" rule a { condition: for any s in pe.sections : ( s.name(0) ) }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.number_of_sections(0) }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.signatures[0].valid_on }",
        &[("yara_undefined_identifier", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.imphash and true }",
        &[("yara_undefined_identifier", E)],
    ),
    // A YARA-X boolean where YARA-X needs a number: `!=`, a float, an offset,
    // an index, a range bound, a quantifier, a function argument.
    (
        "import \"pe\" rule a { condition: 1 != pe.is_dll() }",
        &[("yara_suspicious_expression", W), ("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_dll() != pe.is_32bit() }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_dll() == pe.is_32bit() }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: pe.is_dll() == 1.0 }",
        &[("yara_suspicious_expression", W), ("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { strings: $a = \"cmd.exe\" condition: $a at pe.is_dll() }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { strings: $a = \"cmd.exe\" condition: @a[pe.is_dll()] == 0 }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { strings: $a = \"cmd.exe\" condition: pe.is_dll() of ($a) }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: pe.sections[pe.is_dll()].virtual_size == 0 }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: for any i in (0..pe.is_dll()) : (i == 0) }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: uint8(pe.is_dll()) == 0 }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" import \"math\" rule a { condition: math.entropy(0, pe.is_dll()) > 1 }",
        &[("yara_type", E)],
    ),
    // yara-1.0's integer compared with a boolean, where YARA-X is silent too.
    (
        "import \"pe\" rule a { condition: pe.is_dll() == pe.number_of_sections }",
        &[("yara_suspicious_expression", W)],
    ),
    (
        "import \"pe\" rule a { strings: $a = \"cmd.exe\" condition: #a == pe.is_dll() }",
        &[("yara_suspicious_expression", W)],
    ),
    // A YARA-X overload takes a boolean there: `console.log`'s `b` and `sb`.
    (
        "import \"pe\" import \"console\" rule a { condition: console.log(pe.is_dll()) }",
        &[],
    ),
    (
        "import \"pe\" import \"console\" rule a { condition: console.log(\"x\", pe.is_dll()) }",
        &[],
    ),
    // An enumeration mixing YARA-X booleans and integers (E003); all booleans
    // bind a boolean, which is no non-boolean body.
    (
        "import \"pe\" rule a { condition: for 1 i in (pe.is_dll(), 2) : (true) }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: for any i in (1, pe.is_dll()) : (i == 1) }",
        &[("yara_type", E)],
    ),
    (
        "import \"pe\" rule a { condition: for any i in (pe.is_dll(), pe.is_32bit()) : (i) }",
        &[],
    ),
    // A loop variable an enclosing loop binds: YARA-X shadows it, and takes
    // one named twice over a dictionary.
    (
        "rule a { condition: for any i in (1,2) : (for any i in (3,4) : (i == 3)) }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: for any s in pe.sections : (for any s in pe.sections : (s.virtual_size > 0)) }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: for all i in (pe.is_dll(), pe.is_32bit()) : (for any i in (1, 2) : (i == 1)) }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: for any k, k in pe.version_info : (true) }",
        &[],
    ),
    (
        "import \"pe\" rule a { condition: for any k, v in pe.version_info : (k == v) }",
        &[],
    ),
    (
        "rule a { condition: for any i in (1,2) : (i == 1) and for any i in (3,4) : (i == 3) } rule b { condition: for any i in (1,2) : (i == 1) }",
        &[],
    ),
    // A jump's one error.
    (
        "rule a { strings: $h = { 01 02 ( 05 [9223372036854775813] 06 | 07 ) } condition: $h }",
        &[("yara_hex_string", E)],
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

/// A refused module's message says why (#1225).
#[test]
fn a_refused_module_says_why() {
    for (module, why) in [("magic", "magic-module"), ("vt", "VirusTotal")] {
        let source = format!("import \"{module}\" rule a {{ condition: true }}");
        let found = opentide_yara::analyze_with(&source, &raw()).diagnostics;
        let message = &found
            .iter()
            .find(|d| d.code == "yara_unknown_module")
            .unwrap_or_else(|| panic!("{module}: {found:?}"))
            .message;
        assert!(message.contains("does not support"), "{message}");
        assert!(message.contains(why), "{message}");
        assert!(!message.contains(", vt,"), "{message}");
    }
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
    // Deploy joins the block's contexts with commas.
    assert_eq!(
        codes(
            "rule a { meta: context = \"file.pe,memory\" condition: true }",
            &hl
        ),
        []
    );
    assert_eq!(
        codes(
            "rule a { meta: context = \"file.pe,disk\" condition: true }",
            &hl
        ),
        [("harfanglab_yara_context".to_string(), W)]
    );
    // No blanks in the list.
    assert_eq!(
        codes(
            "rule a { meta: context = \"file.pe, memory\" condition: true }",
            &hl
        ),
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

/// YARA-X is the language (#1225): its syntax is taken where the context
/// allows it, and what it refuses is an error with the code of the problem.
#[test]
fn yara_x_is_the_language() {
    let yx = Context::default();
    assert_eq!(
        codes("rule a { condition: with x = 1 : ( x == 1 ) }", &yx),
        []
    );
    assert_eq!(
        codes("rule a { strings: $r = /\\Release/ condition: $r }", &yx),
        [("yara_regexp".to_string(), E)]
    );
    let jump = "rule a { strings: $h = { 01 02 [0-4294967296] 03 04 } condition: $h }";
    assert_eq!(codes(jump, &yx), [("yara_hex_string".to_string(), E)]);
    assert_eq!(codes(jump, &raw()), [("yara_hex_string".to_string(), E)]);
    // A rule wildcard's syntax error names the fix.
    let wildcard = "rule base1 { condition: true } rule a { condition: any of (base*) }";
    let found = analyze_with(wildcard, &yx).diagnostics;
    assert!(
        found.len() == 1 && found[0].message.contains("list the rules"),
        "{found:?}"
    );
}

/// `WARNING_CODES` is the engine's severity, the one `opentide explain` reads:
/// each of its codes is a warning in every context and profile, and every
/// other code the table expects is an error somewhere.
#[test]
fn warning_codes_are_warnings_in_every_context() {
    let contexts = [
        raw(),
        Context::default(),
        Context::for_profile(Profile::Harfanglab),
        Context::for_profile(Profile::Bitdefender),
    ];
    let mut sources: Vec<&str> = RAW.iter().map(|(source, _)| *source).collect();
    // The profile-only warnings.
    sources.extend([
        "rule a { condition: true }",
        "rule a { meta: context = \"disk\" condition: true }",
        "import \"dotnet\" rule a { meta: context = \"file\" condition: true }",
    ]);
    let mut seen = std::collections::BTreeSet::new();
    for source in &sources {
        for ctx in &contexts {
            for (code, severity) in codes(source, ctx) {
                if always_warning(&code) {
                    assert_eq!(severity, W, "{code} in {source:?} under {ctx:?}");
                    seen.insert(code);
                }
            }
        }
    }
    let all: std::collections::BTreeSet<String> = WARNING_CODES
        .iter()
        .map(|code| (*code).to_owned())
        .collect();
    assert_eq!(seen, all, "a warning-only code no case reports");
    for (_, expected) in RAW {
        for (code, severity) in *expected {
            if *severity == E {
                assert!(!always_warning(code), "{code} is an error");
            }
        }
    }
    assert!(!always_warning("yara_unknown_module"));
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

/// YARA-X takes an identifier of any length (libyara stopped at 128):
/// a loop variable, a bare name, a field, a rule name, a tag, a meta key.
#[test]
fn identifiers_have_no_length_limit() {
    let long = "a".repeat(129);
    for source in [
        format!("rule a {{ condition: for any {long} in (1..2) : ({long} > 0) }}"),
        format!("rule {long} {{ condition: true }} rule b {{ condition: {long} }}"),
        format!("rule a : {long} {{ condition: true }}"),
        format!("rule a {{ meta: {long} = 1 condition: true }}"),
        format!("rule a {{ strings: ${long} = \"cmd.exe\" condition: ${long} }}"),
    ] {
        assert_eq!(codes(&source, &raw()), [], "{source}");
    }
    let found = codes(
        &format!("import \"pe\" rule a {{ condition: pe.{long} }}"),
        &raw(),
    );
    assert_eq!(found, [("yara_unknown_module_member".to_string(), E)]);
}

/// A finding's range is the expression as written: from the module of a
/// method call (yara-x-parser spans `pe.is_dll()` from `is_dll`), and with
/// both parentheses of an operand it leaves out.
#[test]
fn ranges_cover_the_expression_as_written() {
    let ranges = |source: &str| -> Vec<(String, String)> {
        let line: Vec<&str> = source.lines().collect();
        analyze_with(source, &raw())
            .diagnostics
            .into_iter()
            .map(|d| {
                let text = line[d.range.start.line as usize];
                assert_eq!(d.range.start.line, d.range.end.line);
                (
                    d.code,
                    text[d.range.start.character as usize..d.range.end.character as usize]
                        .to_string(),
                )
            })
            .collect()
    };
    let head = "import \"pe\"\nimport \"math\"\n";
    assert_eq!(
        ranges(&format!("{head}rule a {{ condition: pe.is_dll() == 1 }}")),
        [(
            "yara_suspicious_expression".to_string(),
            "pe.is_dll() == 1".to_string()
        )]
    );
    assert_eq!(
        ranges(&format!(
            "{head}rule a {{ condition: math.entropy(0, filesize) }}"
        )),
        [(
            "yara_suspicious_expression".to_string(),
            "math.entropy(0, filesize)".to_string()
        )]
    );
    assert_eq!(
        ranges(&format!("{head}rule a {{ condition: (pe.is_dll()) == 1 }}")),
        [(
            "yara_suspicious_expression".to_string(),
            "(pe.is_dll()) == 1".to_string()
        )]
    );
    for (condition, want) in [
        ("(1) != (pe.is_dll())", "(1) != (pe.is_dll())"),
        ("(1) == (pe.is_dll())", "(1) == (pe.is_dll())"),
        ("(pe.exports(/a\\(/) == 1)", "pe.exports(/a\\(/) == 1"),
        (
            "( pe.exports(/\\)/) == 1 ) and true",
            "pe.exports(/\\)/) == 1",
        ),
        ("(pe.is_dll() /* ( */) == 1", "(pe.is_dll() /* ( */) == 1"),
    ] {
        let found = ranges(&format!("{head}rule a {{ condition: {condition} }}"));
        assert!(
            found
                .iter()
                .any(|(code, text)| code == "yara_suspicious_expression" && text == want),
            "{condition}: {found:?}"
        );
    }
    assert_eq!(
        ranges(&format!("{head}rule a {{ condition: pe.is_dll() > 0 }}")),
        [("yara_type".to_string(), "pe.is_dll()".to_string())]
    );
}

/// No finding's range cuts through a pair of parentheses the parser read
/// (in a string, a regexp or a comment a parenthesis is none), on every
/// case above.
#[test]
fn every_range_is_balanced() {
    let extra = [
        "import \"pe\" rule a { condition: (1) != (pe.is_dll()) }",
        "import \"pe\" rule a { condition: (pe.exports(/a\\(/) == 1) }",
        "import \"pe\" rule a { condition: ( pe.exports(/\\)/) == 1 ) and true }",
        "import \"pe\" rule a { condition: (pe.is_dll() /* ( */) == 1 }",
    ];
    let mut failures = Vec::new();
    for source in RAW.iter().map(|(s, _)| *s).chain(extra) {
        let starts: Vec<usize> = std::iter::once(0)
            .chain(source.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        let byte = |p: &opentide_core::Position| {
            let line = starts[p.line as usize];
            let text = &source[line..];
            let mut units = 0;
            for (i, c) in text.char_indices() {
                if units >= p.character {
                    return line + i;
                }
                units += c.len_utf16() as u32;
            }
            source.len()
        };
        let pairs = opentide_yara::paren_pairs(source);
        for d in analyze_with(source, &raw()).diagnostics {
            let (start, end) = (byte(&d.range.start), byte(&d.range.end));
            for &(open, close) in &pairs {
                if (start..end).contains(&open) != (start..end).contains(&close) {
                    failures.push(format!(
                        "{source}\n    {} at `{}` cuts `(` {open} / `)` {close}",
                        d.code,
                        &source[start..end]
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// YARA-X's own syntax, one case per construct the portability check lists.
const YARA_X_ONLY: [&str; 18] = [
    "rule a { condition: with x = 1 : ( x == 1 ) }",
    "rule a { condition: 1_000 == 1000 }",
    "rule a { condition: 1_0.5 > 1.0 }",
    "rule a { meta: f = 1.5 condition: true }",
    "rule a { meta: d = \"\"\"x\"\"\" condition: true }",
    // An escape makes the value bytes, not a string, in yara-x-parser's AST.
    "rule a { meta: d = \"\"\"x\\n\"\"\" condition: true }",
    "rule a { condition: \"\"\"x\"\"\" == \"x\" }",
    "rule a { strings: $h = { 01 02 [0x2-0x4] 03 04 } condition: $h }",
    "rule a { condition: 1 of (true, false) }",
    "rule a { strings: $a = \"abcd\" condition: 50% of them at 0 }",
    "rule a { strings: $a = \"abcd\" condition: for 50% of them : ( $ ) }",
    "rule a { strings: $a = /abc/si condition: $a }",
    "import \"pe\"\nrule a { condition: pe.sections.len() > 1 }",
    "rule a { condition: \"x\" matches /(?i)abc/ }",
    "rule a { condition: \"x\" matches /(|abc)/ }",
    "rule a { condition: uint64(0) == 1 }",
    "rule a { condition: float32be(0) > 1.5 }",
    "rule a { strings: $a = \"abcd\" base64(\"!@#$%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu\") base64wide(\"!@#$%^&*(){}[].,|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstv\") condition: $a }",
];

/// `yara_x_syntax: allowed` (a raw file, #1225): YARA-X syntax is the language.
#[test]
fn yara_x_syntax_is_taken_when_allowed() {
    for source in YARA_X_ONLY {
        let found = analyze_with(source, &Context::default()).diagnostics;
        assert!(
            found.iter().all(|d| d.severity != Severity::Error),
            "{source}: {found:?}"
        );
    }
}

/// Both profiles start at `refused`: an error naming the construct and the profile.
#[test]
fn yara_x_syntax_is_refused_by_both_profiles() {
    for profile in [Profile::Harfanglab, Profile::Bitdefender] {
        for source in YARA_X_ONLY {
            let found = analyze_with(source, &Context::for_profile(profile)).diagnostics;
            let hit: Vec<_> = found
                .iter()
                .filter(|d| d.code == "yara_x_only_syntax")
                .collect();
            assert!(
                !hit.is_empty(),
                "{source} under {}: {found:?}",
                profile.key()
            );
            assert!(
                hit.iter()
                    .all(|d| d.severity == E && d.message.contains(profile.display())),
                "{source}: {hit:?}"
            );
            assert!(!always_warning("yara_x_only_syntax"));
        }
    }
}
