//! The Defender for Endpoint body: the technique policy sends the block's
//! `alert.techniques` as the alert template's `mitreTechniques` when it sets
//! any, else the rule's objective's (a redeploy that sent `[]` wiped the
//! tenant's).
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the workspace and the rule open"
)]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::{Json, Owned, Rule, defender};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

const UUID: &str = "00000000-0000-4000-8047-000000000001";
const OBJECTIVE: &str = "00000000-0000-4000-8002-000000000047";

fn objective_text(ids: &str) -> String {
    format!(
        "name: Objective\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n  version: 1\n  \
         created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\nobjective:\n  priority: High\n  \
         type: Threat\n  mitre_attack: [{ids}]\n"
    )
}

fn rule_text(alert: &str, model: bool) -> String {
    let model = if model {
        format!("detection_model: {OBJECTIVE}\n")
    } else {
        String::new()
    };
    format!(
        "name: Defender rule\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.0\n  version: 1\n  \
         created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: A rule.\n{model}\
         response:\n  alert_severity: High\nconfigurations:\n  defender_for_endpoint:\n    \
         status: STAGING\n    query: |\n      DeviceProcessEvents\n      | take 1\n    \
         scheduling: 1H\n    alert:\n      category: Execution\n{alert}    \
         impacted_entities:\n      device: device_id\n"
    )
}

fn compiled(alert: &str, model: bool, ids: &str) -> (Json, Vec<String>) {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.create_dir("/ws/objects/objectives");
    fs.write("/ws/objects/rules/r.yaml", rule_text(alert, model));
    fs.write("/ws/objects/objectives/o.yaml", objective_text(ids));
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
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let (body, warnings) = defender::body_with_warnings(&cx, &rule, "one").unwrap();
    (
        body,
        warnings.into_iter().map(|(_, message)| message).collect(),
    )
}

fn body(alert: &str, model: bool) -> Json {
    compiled(alert, model, "T1059.001, T1528").0
}

fn techniques(body: &Json) -> String {
    body.get("detectionAction")
        .and_then(|action| action.get("alertTemplate"))
        .and_then(|template| template.get("mitreTechniques"))
        .unwrap()
        .to_compact()
}

#[test]
fn block_techniques_are_sent_and_beat_the_objectives() {
    let own = body("      techniques: [T1528, T1059.001]\n", false);
    assert_eq!(techniques(&own), r#"["T1528","T1059.001"]"#);
    let over = body("      techniques: [T1003]\n", true);
    assert_eq!(techniques(&over), r#"["T1003"]"#);
}

#[test]
fn a_block_without_techniques_inherits_the_objectives() {
    assert_eq!(techniques(&body("", true)), r#"["T1059.001","T1528"]"#);
}

#[test]
fn no_block_techniques_and_no_objective_sends_an_empty_list() {
    assert_eq!(techniques(&body("", false)), "[]");
}

#[test]
fn an_empty_list_counts_as_unset() {
    assert_eq!(
        techniques(&body("      techniques: []\n", true)),
        r#"["T1059.001","T1528"]"#
    );
}

#[test]
fn the_objectives_non_enterprise_ids_are_left_out_with_a_warning() {
    // T1404 is a Mobile technique, T0800 an ICS one.
    let (body, warnings) = compiled("", true, "T1059, T1404, T0800");
    assert_eq!(techniques(&body), r#"["T1059"]"#);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("leaving out T1404"), "{}", warnings[0]);
    assert!(warnings[1].contains("leaving out T0800"), "{}", warnings[1]);
}

#[test]
fn the_blocks_ids_are_sent_as_written() {
    let (body, warnings) = compiled("      techniques: [T1404]\n", true, "T1059");
    assert_eq!(techniques(&body), r#"["T1404"]"#);
    assert!(warnings.is_empty(), "{warnings:?}");
}
