//! The two Sysdig constraint engines agree (UC-1.4, #810): the language
//! server's (`opentide_tide::analyze`, its own walk of the YAML node tree, Falco's
//! grammar from `opentide-falco`) and the CLI's model
//! (`opentide_schema::objects::platform::sysdig::block_codes`, on the YAML
//! node tree, the oracle's text scan). Both take Falco's terms from
//! `opentide_core::falco`; this test runs both on every Sysdig case of
//! `crates/opentide-schema/tests/oracle/platform_cases.toml` (each checked
//! against the oracle there) and compares the constraint codes, so the two
//! walks cannot drift apart unnoticed. A case where they differ by design is
//! listed in [`KNOWN`] with its reason.

use std::collections::BTreeSet;

use opentide_schema::node;
use opentide_schema::objects::platform::sysdig;
use opentide_tide::{AnalyzeInput, analyze};

const CASES: &str = include_str!("../../crates/opentide-schema/tests/oracle/platform_cases.toml");

/// The codes `sysdig_rule_shape` reports; the language server's other Sysdig
/// codes (`sysdig_list_self_reference`, a warning, and the `falco_*` grammar
/// findings) are its own.
const CONSTRAINT_CODES: [&str; 9] = [
    "sysdig_rule_shape",
    "sysdig_tuning_keys",
    "sysdig_priority",
    "sysdig_source",
    "sysdig_exception_shape",
    "sysdig_definition_name",
    "sysdig_definition_duplicate",
    "sysdig_definition_order",
    "sysdig_list_in_value",
];

/// Cases where the engines differ by design: (case id, reason).
const KNOWN: &[(&str, &str)] = &[(
    "platform-sysdig-macro-unparsed",
    "a macro whose condition does not parse (`m2 and (`): the editor reads conditions with \
     Falco's grammar and reports the parse error (`falco_*`), not an order it cannot see; the \
     model follows the oracle's text scan, which still finds `m2` used before it is defined",
)];

fn model_codes(yaml: &str) -> Option<BTreeSet<String>> {
    let document = node::load(yaml).ok()?;
    let block = document.root()?.get("configurations")?.get("sysdig")?;
    Some(
        sysdig::block_codes(block)
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )
}

fn editor_codes(yaml: &str) -> BTreeSet<String> {
    analyze(AnalyzeInput {
        path: "objects/rules/rule.yaml",
        source: yaml,
        workspace: &[],
        elastic_tenants: &[],
    })
    .diagnostics
    .into_iter()
    .map(|diagnostic| diagnostic.code)
    .filter(|code| CONSTRAINT_CODES.contains(&code.as_str()))
    .collect()
}

#[test]
fn the_editor_and_the_model_agree_on_the_sysdig_cases() {
    let table: toml::Table = CASES.parse().expect("platform_cases.toml parses");
    let cases = table["case"].as_array().expect("[[case]]");
    let mut compared = 0;
    let mut failures = Vec::new();
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let Some(yaml) = case.get("yaml").and_then(toml::Value::as_str) else {
            continue;
        };
        if !id.starts_with("platform-sysdig") {
            continue;
        }
        let Some(model) = model_codes(yaml) else {
            continue;
        };
        compared += 1;
        let editor = editor_codes(yaml);
        let known = KNOWN.iter().any(|(known, _)| *known == id);
        if (editor == model) == known {
            failures.push(format!(
                "{id}: editor {editor:?}, model {model:?}{}",
                if known {
                    " (listed in KNOWN, but they agree)"
                } else {
                    ""
                }
            ));
        }
    }
    assert!(compared >= 30, "only {compared} Sysdig cases compared");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
