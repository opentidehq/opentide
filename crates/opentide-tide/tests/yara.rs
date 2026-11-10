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

/// #165: each finding lands in the field that wrote it. `condition: $b`
/// with only `$a` is the undefined `$b` alone: libyara stops there, so `$a`
/// is not also unreferenced. `condition: true` leaves `$a` unreferenced, in
/// `strings`.
#[test]
fn decomposed_strings_and_condition_report_in_their_own_fields() {
    let source = decomposed("        $a = \"cmd.exe\" ascii\n", "        $b\n", "");
    assert_eq!(
        yara(&source),
        [row(
            "yara_undefined_string",
            "configurations.harfanglab.yara.condition",
            "$b"
        )]
    );
    let source = decomposed("        $a = \"cmd.exe\" ascii\n", "        true\n", "");
    assert_eq!(
        yara(&source),
        [row(
            "yara_unreferenced_string",
            "configurations.harfanglab.yara.strings",
            "$a"
        )]
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

/// The review of #165: the decomposed form is assembled exactly as
/// `compile_yara_deployment` (opentide 0.24, `platforms/harfanglab/deployer.py`)
/// writes it. The expected text is that function's output for this rule.
const DEPLOYED_RULE: &str = "name: Cmd String\nmetadata:\n  uuid: 00000000-0000-4000-8003-000000000018\n  schema: rule::1.0\n  version: 1\n  created: \"2026-01-01\"\n  modified: \"2026-01-02\"\n  tlp: clear\n  author: Jane \"J\" Doe\ndescription: |\n  Finds \"cmd.exe\".\nreferences:\n  public:\n    1: https://example.com/a\n    2: https://example.com/b\nstatus: STAGING\nseverity: High\nresponse:\n  alert_severity: High\nconfigurations:\n  harfanglab:\n    enabled: true\n    schema: platform::harfanglab::1.0\n    status: STAGING\n    action: \"Alert & Block\"\n    confidence: Strong\n    tags:\n      - attack.t1059\n      - cmd\n    yara:\n      meta:\n        context:\n          - file\n          - memory\n        os: Windows\n        arch:\n          - x86\n          - x64\n        classification: trojan\n      imports:\n        - pe\n      strings: |\n        $a = \"cmd.exe\" ascii\n      condition: |\n        $a and pe.is_dll()\n";

#[test]
fn decomposed_assembly_is_what_deploy_writes() {
    let injected = opentide_tide::extract_injections(DEPLOYED_RULE)
        .into_iter()
        .find(|q| q.language == opentide_core::LanguageId::Yara)
        .expect("a YARA injection");
    assert_eq!(
        injected.inner,
        "import \"pe\"\n\nrule cmd_string {\n    meta:\n        id = \"00000000-0000-4000-8003-000000000018\"\n        title = \"Cmd String\"\n        description = \"Finds \\\"cmd.exe\\\".\\n\"\n        author = \"Jane \\\"J\\\" Doe\"\n        date = \"2026-01-01\"\n        modified = \"2026-01-02\"\n        references = \"https://example.com/a\\nhttps://example.com/b\"\n        tags = \"attack.t1059;cmd\"\n        context = \"file.pe,memory\"\n        os = \"Windows\"\n        arch = \"x86,x64\"\n        classification = \"trojan\"\n        score = 70\n        confidence = \"strong\"\n    strings:\n        $a = \"cmd.exe\" ascii\n    condition:\n        $a and pe.is_dll()\n}"
    );
    assert_eq!(yara(DEPLOYED_RULE), []);
}

/// A rule cut short in generated text is still an error, in its field:
/// libyara refuses each of these.
#[test]
fn decomposed_errors_in_generated_text_are_kept() {
    for (strings, condition, field) in [
        ("        $a = \"x\"\n", "        $a and\n", "condition"),
        (
            "        $a = \"x\"\n        $b = \"y\"\n",
            "        ($a and $b\n",
            "condition",
        ),
        ("        $b = { 01 02\n", "        $b\n", "strings"),
    ] {
        let found = yara(&decomposed(strings, condition, ""));
        assert!(
            found.iter().any(|(code, path, _)| code.starts_with("yara_")
                && path == &format!("configurations.harfanglab.yara.{field}")),
            "{condition:?}: {found:?}"
        );
    }
    // An empty condition: the error points at the `condition` key.
    let source = format!(
        "{HEAD}configurations:\n  harfanglab:\n    yara:\n      meta:\n        context:\n          - file\n        os: Windows\n      strings: |\n        $a = \"x\"\n      condition: \"\"\n"
    );
    let found = yara(&source);
    assert!(
        found
            .iter()
            .any(|(code, path, _)| code == "yara_parse_error"
                && path == "configurations.harfanglab.yara.condition"),
        "{found:?}"
    );
}

/// What deploy writes unescaped breaks the rule on the tenant: a `"` in a
/// tag is the parse error, on that tag.
#[test]
fn decomposed_unescaped_meta_is_checked_where_it_is_written() {
    let source = DEPLOYED_RULE.replace("      - cmd\n", "      - cm\"d\n");
    let found = yara(&source);
    assert!(
        found
            .iter()
            .any(|(code, path, _)| code == "yara_parse_error"
                && path == "configurations.harfanglab.tags.1"),
        "{found:?}"
    );
    // A context HarfangLab does not know, on that context.
    let source = DEPLOYED_RULE.replace("          - memory\n", "          - disk\n");
    assert_eq!(
        yara(&source),
        [row(
            "harfanglab_yara_context",
            "configurations.harfanglab.yara.meta.context.1",
            "disk"
        )]
    );
}

/// `rule` in a comment is not a section header.
#[test]
fn decomposed_comments_are_not_headers() {
    let source = decomposed(
        "        $a = \"cmd.exe\"\n",
        "        /* rule of thumb:\n           any string */\n        $a\n",
        "",
    );
    assert_eq!(yara(&source), []);
}

/// A derived rule name past 128 characters, and one named like an imported
/// module (libyara accepts it, YARA-X refuses it).
#[test]
fn decomposed_rule_names_libyara_and_yara_x_refuse() {
    let long = "a".repeat(129);
    let source = decomposed("        $a = \"cmd.exe\"\n", "        $a\n", "").replacen(
        "name: Cmd String",
        &format!("name: {long}"),
        1,
    );
    assert!(
        yara(&source)
            .iter()
            .any(|(code, path, _)| code == "harfanglab_yara_rule_name" && path == "name")
    );
    let source = decomposed(
        "        $a = \"cmd.exe\"\n",
        "        $a\n",
        "      imports:\n        - pe\n",
    )
    .replacen("name: Cmd String", "name: PE", 1);
    assert_eq!(yara(&source), [row("yara_x_incompatible", "name", "P")]);
}
