//! HarfangLab YARA through the console script (harfanglab-1.0 1.2 and 1.3,
//! #899): `validate` and `lint` on 0.28.1's fixtures
//! (`tests/fixtures/harfanglab/`) and variants of its decomposed and
//! signature forms report what opentide 0.28.1 reports, finding for finding:
//! the code, the file, the field path and the line.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use serde_json::Value;

const FIXTURES: [&str; 7] = [
    "harfanglab-sigma.yaml",
    "harfanglab-yara-signature.yaml",
    "harfanglab-yara.yaml",
    "invalid/rule-harfanglab-sigma-and-yara.yaml",
    "invalid/rule-harfanglab-yara-both-forms.yaml",
    "invalid/rule-harfanglab-yara-include.yaml",
    "invalid/rule-yara-signature-alias.yaml",
];

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/harfanglab")
        .join(name);
    std::fs::read_to_string(path).unwrap()
}

/// A workspace of the fixtures and the variants of `harfanglab-yara.yaml`
/// and `harfanglab-yara-signature.yaml`.
fn workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".opentide/configurations")).unwrap();
    let rules = dir.path().join("objects/rules");
    std::fs::create_dir_all(&rules).unwrap();
    for name in FIXTURES {
        let file = Path::new(name).file_name().unwrap();
        std::fs::write(rules.join(file), fixture(name)).unwrap();
    }
    let decomposed = fixture("harfanglab-yara.yaml");
    let variant = |name: &str, n: u8, from: &str, to: &str| {
        assert!(decomposed.contains(from), "{name}");
        let text = decomposed.replace(from, to).replace(
            "00000000-0000-4000-8003-000000000018",
            &format!("00000000-0000-4000-8003-0000000000a{n}"),
        );
        std::fs::write(rules.join(format!("{name}.yaml")), text).unwrap();
    };
    variant(
        "x-header",
        1,
        "      condition: |\n        $a",
        "      condition: |\n        condition:\n          $a",
    );
    variant(
        "x-import",
        2,
        "        - pe\n",
        "        - pe\n        - nosuchmodule\n",
    );
    variant(
        "x-rulename",
        3,
        "name: HarfangLab YARA platform block",
        "name: Condition",
    );
    variant("x-incomplete", 4, "      condition: |\n        $a\n", "");
    variant(
        "x-undefined",
        5,
        "      condition: |\n        $a",
        "      condition: |\n        $a and $b",
    );
    variant(
        "x-nocontext",
        6,
        "        context:\n          - file\n",
        "        context: []\n",
    );
    variant("d-badctx", 7, "          - file\n", "          - disk\n");
    let signature = fixture("harfanglab-yara-signature.yaml");
    let at = signature.find("      signature: |").unwrap();
    let uuid = "00000000-0000-4000-8003-000000000040";
    assert!(signature.contains(uuid));
    let with = |name: &str, n: u8, yara: &str| {
        let body: String = yara
            .lines()
            .map(|line| {
                if line.is_empty() {
                    "\n".to_owned()
                } else {
                    format!("        {line}\n")
                }
            })
            .collect();
        let text = format!("{}      signature: |\n{body}", &signature[..at])
            .replace(uuid, &format!("00000000-0000-4000-8003-0000000000b{n}"));
        std::fs::write(rules.join(format!("{name}.yaml")), text).unwrap();
    };
    with(
        "s-nometa",
        1,
        "rule A {\n  strings:\n    $a = \"x\"\n  condition:\n    $a\n}",
    );
    with(
        "s-badctx",
        2,
        "rule A {\n  meta:\n    context = \"disk\"\n  strings:\n    $a = \"x\"\n  condition:\n    $a\n}",
    );
    with(
        "s-two",
        4,
        "private rule P {\n  condition:\n    true\n}\n\nrule B {\n  meta:\n    context = \"file\"\n  condition:\n    P\n}\n\nrule C {\n  condition:\n    P\n}",
    );
    dir
}

fn run(dir: &Path, command: &str) -> Value {
    let out = Command::new(env!("CARGO_BIN_EXE_opentide-cli"))
        .args(["--json", command])
        .current_dir(dir)
        .env_clear()
        .env("OPENTIDE_OUTPUT", "plain")
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

fn file(path: &Value) -> String {
    path.as_str()
        .unwrap()
        .rsplit(['/', '\\'])
        .next()
        .unwrap()
        .to_owned()
}

#[test]
fn validate_and_lint_report_what_0_28_1_reports() {
    let dir = workspace();
    let report = &run(dir.path(), "validate")["report"];
    let validated: BTreeSet<(String, String, String, u64)> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| {
            let path: Vec<&str> = issue["field_path"]
                .as_array()
                .unwrap()
                .iter()
                .map(|key| key.as_str().unwrap_or_default())
                .collect();
            (
                issue["code"].as_str().unwrap().to_owned(),
                file(&issue["file_path"]),
                path.join("."),
                issue["line"].as_u64().unwrap_or_default(),
            )
        })
        .collect();
    let row = |code: &str, file: &str, path: &str, line: u64| {
        (code.to_owned(), file.to_owned(), path.to_owned(), line)
    };
    let expected: BTreeSet<_> = [
        row(
            "schema_validation",
            "rule-harfanglab-sigma-and-yara.yaml",
            "configurations.harfanglab",
            16,
        ),
        row(
            "schema_validation",
            "rule-harfanglab-yara-both-forms.yaml",
            "configurations.harfanglab",
            16,
        ),
        // The model's yara_include gives way to the engine's, at its place.
        row(
            "yara_include",
            "rule-harfanglab-yara-include.yaml",
            "configurations.harfanglab.yara.signature",
            22,
        ),
        // Where the aliased text is written.
        row(
            "yara_signature_alias",
            "rule-yara-signature-alias.yaml",
            "configurations.harfanglab.yara.signature",
            18,
        ),
        row(
            "schema_validation",
            "x-header.yaml",
            "configurations.harfanglab",
            16,
        ),
        // harfanglab_yara_import, and no yara_unknown_module beside it.
        row(
            "schema_validation",
            "x-import.yaml",
            "configurations.harfanglab",
            16,
        ),
        row(
            "schema_validation",
            "x-incomplete.yaml",
            "configurations.harfanglab.yara",
            21,
        ),
        row("schema_validation", "x-rulename.yaml", "", 1),
        row(
            "yara_undefined_string",
            "x-undefined.yaml",
            "configurations.harfanglab.yara.condition",
            35,
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(validated, expected);
    let messages: Vec<&str> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|issue| issue["message"].as_str())
        .collect();
    for code in [
        "harfanglab_rule_kind",
        "harfanglab_yara_form",
        "harfanglab_yara_section_header",
        "harfanglab_yara_import",
        "harfanglab_yara_rule_name",
    ] {
        assert!(
            messages.iter().any(|message| message.contains(code)),
            "{code}: {messages:?}"
        );
    }

    let lint = run(dir.path(), "lint");
    let advised: BTreeSet<(String, String, u64)> = lint["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| {
            ["yara_meta_missing", "harfanglab_yara_context"]
                .contains(&finding["code"].as_str().unwrap_or_default())
        })
        .map(|finding| {
            (
                finding["code"].as_str().unwrap().to_owned(),
                file(&finding["path"]),
                finding["yaml_line"].as_u64().unwrap(),
            )
        })
        .collect();
    let advisory = |code: &str, file: &str, line: u64| (code.to_owned(), file.to_owned(), line);
    let expected: BTreeSet<_> = [
        advisory("yara_meta_missing", "x-nocontext.yaml", 22),
        advisory("harfanglab_yara_context", "d-badctx.yaml", 22),
        advisory("yara_meta_missing", "s-nometa.yaml", 23),
        advisory("harfanglab_yara_context", "s-badctx.yaml", 25),
        // Rule C, the third rule's header; the private rule P earns none.
        advisory("yara_meta_missing", "s-two.yaml", 35),
    ]
    .into_iter()
    .collect();
    assert_eq!(advised, expected);
}
