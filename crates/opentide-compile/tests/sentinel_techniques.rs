//! The Sentinel body's techniques: the block's `alert.techniques` are sent
//! when it sets any, else the objective's ATT&CK ids. What is sent is held to
//! ATT&CK v18 (the version Sentinel is aligned to), and each id that changes
//! earns a warning.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the workspace and the rule open"
)]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::{Json, Owned, Rule, preview, sentinel};
use opentide_schema::platforms::PlatformKey;
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

const RULE: &str = "00000000-0000-4000-8003-000000000001";
const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000001";

fn objective(ids: &[&str]) -> String {
    format!(
        "name: Objective\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n  version: 1\n  \
         created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\nobjective:\n  priority: High\n  \
         type: Threat\n  mitre_attack: [{}]\n",
        ids.join(", ")
    )
}

fn rule(alert_techniques: &str) -> String {
    format!(
        "name: Sentinel rule\nmetadata:\n  uuid: {RULE}\n  schema: rule::1.0\n  version: 1\n  \
         created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: A rule.\n\
         detection_model: {OBJECTIVE}\nresponse:\n  alert_severity: High\nconfigurations:\n  \
         sentinel:\n    enabled: true\n    name: Sentinel rule\n    status: STAGING\n    \
         query: |\n      SecurityEvent\n      | take 1\n    scheduling:\n      frequency: PT1H\n      \
         lookback: PT2H\n    alert:\n      title: Sentinel rule\n      suppression: false\n{alert_techniques}    \
         grouping:\n      event: SingleAlert\n      alert:\n        enabled: false\n"
    )
}

fn compile(ids: &[&str], alert_techniques: &str) -> (Json, Vec<String>, Json) {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.create_dir("/ws/objects/objectives");
    fs.write("/ws/objects/rules/r.yaml", rule(alert_techniques));
    fs.write("/ws/objects/objectives/o.yaml", objective(ids));
    let workspace = Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap();
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", RULE).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let (body, warnings) = sentinel::compile_with_warnings(&cx, &rule, "one").unwrap();
    let entry = preview::preview(&cx, &PlatformKey::new("sentinel"), &rule);
    (
        body,
        warnings.into_iter().map(|(_, message)| message).collect(),
        entry,
    )
}

fn property(body: &Json, name: &str) -> String {
    body.get("properties")
        .and_then(|properties| properties.get(name))
        .map_or_else(|| "absent".to_owned(), Json::to_compact)
}

#[test]
fn ids_newer_than_v18_are_mapped_and_warned() {
    let (body, warnings, entry) = compile(
        &[
            "T1562.008",
            "T1562.001",
            "T1685.002",
            "T1027.018",
            "T1070.002",
        ],
        "",
    );
    assert_eq!(
        property(&body, "techniques"),
        r#"["T1562","T1027","T1070"]"#
    );
    assert_eq!(
        property(&body, "subTechniques"),
        r#"["T1562.008","T1562.001","T1070.002"]"#
    );
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("sending T1562.008 in place of T1685.002"));
    assert!(warnings[1].contains("sending T1027 in place of T1027.018"));
    assert!(warnings[0].contains(RULE));
    // The dry run's entry carries the same warnings.
    let shown = entry.get("warnings").unwrap().to_compact();
    assert!(
        shown.contains("T1685.002") && shown.contains("T1027.018"),
        "{shown}"
    );
}

#[test]
fn a_clean_objective_earns_no_warning() {
    let (body, warnings, entry) = compile(&["T1562.008", "T1070"], "");
    assert_eq!(property(&body, "techniques"), r#"["T1562","T1070"]"#);
    assert!(warnings.is_empty());
    assert!(entry.get("warnings").is_none());
}

#[test]
fn block_techniques_are_sent_and_beat_the_objectives() {
    let (body, warnings, _) = compile(&["T1562.008"], "      techniques: [T1059.001, T1003]\n");
    assert_eq!(property(&body, "techniques"), r#"["T1059","T1003"]"#);
    assert_eq!(property(&body, "subTechniques"), r#"["T1059.001"]"#);
    // Tactics come from what is sent (Execution, Credential Access).
    assert_eq!(
        property(&body, "tactics"),
        r#"["Execution","CredentialAccess"]"#
    );
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn a_block_without_techniques_sends_the_objectives() {
    let (body, _, _) = compile(&["T1562.008"], "");
    assert_eq!(property(&body, "techniques"), r#"["T1562"]"#);
    assert_eq!(property(&body, "subTechniques"), r#"["T1562.008"]"#);
}

#[test]
fn block_tactics_are_sent_in_place_of_derived_ones() {
    let (body, _, _) = compile(&["T1562.008"], "      tactics: [Persistence]\n");
    assert_eq!(property(&body, "tactics"), r#"["Persistence"]"#);
    assert_eq!(property(&body, "techniques"), r#"["T1562"]"#);
}

#[test]
fn an_objective_with_nothing_to_send_sends_no_techniques() {
    let (body, warnings, _) = compile(&["T1691"], "");
    assert_eq!(property(&body, "techniques"), "absent");
    assert_eq!(property(&body, "tactics"), "absent");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

#[test]
fn a_newer_parent_hint_lists_its_sub_techniques_v18_mappings() {
    let (_, warnings, _) = compile(&["T1685"], "");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].contains("in place of T1685, which is newer than ATT&CK v18"),
        "{}",
        warnings[0]
    );
    assert!(
        warnings[0].contains(
            "Its sub-techniques map to ATT&CK v18 as T1685.001 → T1562.002, \
             T1685.002 → T1562.008"
        ),
        "{}",
        warnings[0]
    );
    // As deploy sends it: T1685.007 replaced only a sub-technique, so it
    // stands for what its parent replaced.
    assert!(warnings[0].contains("T1685.007 → T1562"), "{}", warnings[0]);
}

#[test]
fn a_block_whose_ids_cannot_be_sent_does_not_fall_back_to_the_objectives() {
    let (body, warnings, _) = compile(&["T1562.008"], "      techniques: [T1691]\n");
    assert_eq!(property(&body, "techniques"), "absent");
    assert_eq!(property(&body, "subTechniques"), "absent");
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

#[test]
fn an_empty_list_counts_as_unset() {
    let (body, _, _) = compile(&["T1562.008"], "      techniques: []\n      tactics: []\n");
    assert_eq!(property(&body, "techniques"), r#"["T1562"]"#);
    assert_eq!(property(&body, "tactics"), r#"["DefenseEvasion"]"#);
}
