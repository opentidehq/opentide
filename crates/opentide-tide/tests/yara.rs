//! YARA in Tide objects: `yara.signature` under the HarfangLab and
//! Bitdefender profiles, HarfangLab's decomposed form checked as the rule
//! deploy assembles, the block's constraint codes, and the spec's fixtures
//! (`testdata/conformance/specifications-yara/`).

use opentide_core::Diagnostic;
use opentide_tide::{AnalyzeInput, analyze};
use std::path::PathBuf;

const HEAD: &str = "name: Cmd String\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000001\n  schema: rule::1.0\n";

fn analyse(source: &str) -> Vec<Diagnostic> {
    analyze(AnalyzeInput {
        path: "objects/rules/cmd-string.yaml",
        source,
        workspace: &[],
        elastic_tenants: &[],
    })
    .diagnostics
}

/// The YARA and YARA-profile findings: `(code, field path, source text at
/// the range)`.
fn yara(source: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<_> = analyse(source)
        .into_iter()
        .filter(|d| {
            d.code.starts_with("yara_")
                || d.code.starts_with("harfanglab_")
                || d.code.starts_with("bitdefender_yara")
        })
        .map(|d| {
            let line = source
                .lines()
                .nth(d.range.start.line as usize)
                .unwrap_or("");
            // LSP columns count UTF-16 units.
            let byte = |units: u32| {
                let mut n = 0;
                for (i, c) in line.char_indices() {
                    if n >= units {
                        return i;
                    }
                    n += c.len_utf16() as u32;
                }
                line.len()
            };
            let start = byte(d.range.start.character);
            let end = if d.range.end.line == d.range.start.line {
                byte(d.range.end.character)
            } else {
                line.len()
            };
            let at = line.get(start..end.max(start)).unwrap_or("").to_string();
            (d.code, d.field_path.unwrap_or_default().join("."), at)
        })
        .collect();
    out.sort();
    out
}

fn row(code: &str, path: &str, at: &str) -> (String, String, String) {
    (code.into(), path.into(), at.into())
}

fn decomposed(strings: &str, condition: &str, imports: &str) -> String {
    format!(
        "{HEAD}configurations:\n  harfanglab:\n    enabled: true\n    schema: platform::harfanglab::1.0\n    status: STAGING\n    yara:\n      meta:\n        context:\n          - file\n        os: Windows\n{imports}      strings: |\n{strings}      condition: |\n{condition}"
    )
}

/// #165: `condition: $b` with only `$a` reports both where they are written.
#[test]
fn decomposed_strings_and_condition_report_in_their_own_fields() {
    let source = decomposed("        $a = \"cmd.exe\" ascii\n", "        $b\n", "");
    assert_eq!(
        yara(&source),
        [
            row(
                "yara_undefined_string",
                "configurations.harfanglab.yara.condition",
                "$b"
            ),
            row(
                "yara_unreferenced_string",
                "configurations.harfanglab.yara.strings",
                "$a"
            ),
        ]
    );
}

/// #165: a module used without its import.
#[test]
fn decomposed_module_needs_an_import() {
    let source = decomposed(
        "        $a = \"cmd.exe\" ascii\n",
        "        $a and pe.imphash() == \"x\"\n",
        "",
    );
    assert_eq!(
        yara(&source),
        [row(
            "yara_module_not_imported",
            "configurations.harfanglab.yara.condition",
            "pe"
        )]
    );
    let imported = decomposed(
        "        $a = \"cmd.exe\" ascii\n",
        "        $a and pe.imphash() == \"x\"\n",
        "      imports:\n        - pe\n",
    );
    assert_eq!(yara(&imported), []);
}

#[test]
fn decomposed_imports_and_headers_and_rule_names() {
    let source = decomposed(
        "        $a = \"cmd.exe\" ascii\n",
        "        $a\n",
        "      imports:\n        - pe\n        - foo\n        - dotnet\n",
    );
    assert_eq!(
        yara(&source),
        [
            row(
                "harfanglab_yara_import",
                "configurations.harfanglab.yara.imports.1",
                "foo"
            ),
            row(
                "yara_module_unconfirmed",
                "configurations.harfanglab.yara.imports.2",
                "dotnet"
            ),
        ]
    );
    let header = decomposed(
        "        $a = \"cmd.exe\" ascii\n",
        "        condition:\n          $a\n",
        "",
    );
    assert_eq!(
        yara(&header),
        [row(
            "harfanglab_yara_section_header",
            "configurations.harfanglab.yara.condition",
            "condition:"
        )]
    );
    let keyword = decomposed("        $a = \"cmd.exe\" ascii\n", "        $a\n", "")
        .replace("name: Cmd String", "name: Condition");
    assert_eq!(
        yara(&keyword),
        [row("harfanglab_yara_rule_name", "name", "Condition")]
    );
    let accent = decomposed("        $a = \"cmd.exe\" ascii\n", "        $a\n", "")
        .replace("name: Cmd String", "name: Détection");
    assert_eq!(
        yara(&accent),
        [row("harfanglab_yara_rule_name", "name", "Détection")]
    );
}

/// #165: the same bodies in a raw `.yar` file and in the decomposed block
/// give the same codes.
#[test]
fn raw_and_decomposed_agree() {
    for (strings, condition) in [
        ("$a = \"cmd.exe\" ascii", "$b"),
        ("$a = \"cmd.exe\" xor nocase", "$a"),
        ("$h = { 4D 5A [4-2] 90 }", "$h"),
        ("$a = \"x\"", "$a and filesize contains \"a\""),
        ("$a = \"cmd.exe\"\n$a = \"b.exe\"", "$a"),
    ] {
        let raw = format!(
            "import \"pe\"\nrule cmd_string {{\n  meta:\n    context = \"file.pe\"\n  strings:\n    {}\n  condition:\n    {condition}\n}}\n",
            strings.replace('\n', "\n    ")
        );
        let mut raw_codes: Vec<String> = opentide_yara::analyze_with(
            &raw,
            &opentide_yara::Context::for_profile(opentide_yara::Profile::Harfanglab),
        )
        .diagnostics
        .into_iter()
        .map(|d| d.code)
        .collect();
        raw_codes.sort();
        let block = decomposed(
            &format!("        {}\n", strings.replace('\n', "\n        ")),
            &format!("        {condition}\n"),
            "      imports:\n        - pe\n",
        );
        let block_codes: Vec<String> = yara(&block).into_iter().map(|(c, _, _)| c).collect();
        assert_eq!(raw_codes, block_codes, "{strings} / {condition}");
        assert!(!raw_codes.is_empty(), "{strings} / {condition}");
    }
}

#[test]
fn signature_under_each_profile() {
    let sig = |platform: &str, text: &str| {
        format!(
            "{HEAD}configurations:\n  {platform}:\n    enabled: true\n    schema: platform::{platform}::1.0\n    status: STAGING\n    yara:\n      signature: |\n{}",
            text.lines()
                .map(|l| format!("        {l}\n"))
                .collect::<String>()
        )
    };
    let text = "rule a {\n  strings:\n    $a = \"é-mutex\"\n  condition:\n    $a and $b\n}";
    assert_eq!(
        yara(&sig("harfanglab", text)),
        [
            row(
                "yara_meta_missing",
                "configurations.harfanglab.yara.signature",
                "a"
            ),
            row(
                "yara_undefined_string",
                "configurations.harfanglab.yara.signature",
                "$b"
            ),
        ]
    );
    assert_eq!(
        yara(&sig("bitdefender", text)),
        [
            row(
                "bitdefender_yara_ascii",
                "configurations.bitdefender.yara.signature",
                "é"
            ),
            row(
                "yara_undefined_string",
                "configurations.bitdefender.yara.signature",
                "$b"
            ),
        ]
    );
    let blank =
        format!("{HEAD}configurations:\n  bitdefender:\n    yara:\n      signature: \"\"\n");
    assert_eq!(
        yara(&blank),
        [row(
            "yara_empty_signature",
            "configurations.bitdefender.yara.signature",
            "signature"
        )]
    );
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/specifications-yara")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn spec_fixtures() {
    for valid in [
        "harfanglab-yara-signature.yaml",
        "harfanglab-yara.yaml",
        "rule-bitdefender-yara-1.0.yaml",
    ] {
        assert_eq!(yara(&fixture(valid)), [], "{valid}");
    }
    for (file, code) in [
        ("rule-yara-signature-alias.yaml", "yara_signature_alias"),
        ("rule-harfanglab-yara-include.yaml", "yara_include"),
        (
            "rule-harfanglab-yara-both-forms.yaml",
            "harfanglab_yara_form",
        ),
        (
            "rule-harfanglab-sigma-and-yara.yaml",
            "harfanglab_rule_kind",
        ),
    ] {
        let codes: Vec<String> = yara(&fixture(file))
            .into_iter()
            .map(|(c, _, _)| c)
            .collect();
        assert_eq!(codes, [code], "{file}");
    }
}

/// Hover and tokens stay on the text the author wrote: the generated rule
/// header and meta get no token.
#[test]
fn decomposed_tokens_stay_in_the_bodies() {
    let source = decomposed("        $a = \"cmd.exe\" ascii\n", "        $a\n", "");
    let result = analyze(AnalyzeInput {
        path: "objects/rules/cmd-string.yaml",
        source: &source,
        workspace: &[],
        elastic_tenants: &[],
    });
    let strings_at = source.find("$a = ").unwrap();
    let condition_at = source.rfind("$a").unwrap();
    let token_at = |offset: usize| {
        result
            .tokens
            .iter()
            .find(|t| t.span.start == offset)
            .map(|t| t.capture.clone())
    };
    assert_eq!(token_at(strings_at).as_deref(), Some("variable"));
    assert_eq!(token_at(condition_at).as_deref(), Some("variable"));
    // Nothing coloured as YARA outside the two bodies' lines.
    let yara_key = source.find("    yara:").unwrap();
    let strings_key = source.find("strings: |").unwrap();
    assert!(
        !result
            .tokens
            .iter()
            .any(|t| t.span.start > yara_key && t.span.start < strings_key && t.capture == "type"),
        "{:?}",
        result.tokens
    );
}
