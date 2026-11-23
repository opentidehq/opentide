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

fn objective_text() -> String {
    format!(
        "name: Objective\nmetadata:\n  uuid: {OBJECTIVE}\n  schema: objective::1.0\n  version: 1\n  \
         created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\nobjective:\n  priority: High\n  \
         type: Threat\n  mitre_attack: [T1059.001, T1528]\n"
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

fn body(alert: &str, model: bool) -> Json {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.create_dir("/ws/objects/objectives");
    fs.write("/ws/objects/rules/r.yaml", rule_text(alert, model));
    fs.write("/ws/objects/objectives/o.yaml", objective_text());
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
    defender::body(&cx, &rule, "one").unwrap()
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
