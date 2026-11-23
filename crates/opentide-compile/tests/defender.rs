//! The Defender for Endpoint body: `alert.techniques` is what the alert
//! template sends as `mitreTechniques` (a redeploy that sent `[]` wiped the
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

fn rule_text(alert: &str) -> String {
    format!(
        "name: Defender rule\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.0\n  version: 1\n  \
         created: 2026-01-01\n  modified: 2026-01-02\n  tlp: clear\ndescription: A rule.\n\
         response:\n  alert_severity: High\nconfigurations:\n  defender_for_endpoint:\n    \
         status: STAGING\n    query: |\n      DeviceProcessEvents\n      | take 1\n    \
         scheduling: 1H\n    alert:\n      category: Execution\n{alert}    \
         impacted_entities:\n      device: device_id\n"
    )
}

fn body(alert: &str) -> Json {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", rule_text(alert));
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
fn alert_techniques_reach_the_alert_template() {
    let body = body("      techniques: [T1528, T1059.001]\n");
    assert_eq!(techniques(&body), r#"["T1528","T1059.001"]"#);
}

#[test]
fn a_block_without_techniques_sends_an_empty_list() {
    assert_eq!(techniques(&body("")), "[]");
}
