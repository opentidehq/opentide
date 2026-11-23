//! The Sentinel body's techniques: the objective's ATT&CK ids replace the
//! block's, are held to ATT&CK v18 (the version Sentinel is aligned to) and
//! earn a warning for each id that changes.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: the workspace and the rule open"
)]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::{Json, Owned, Rule, preview, sentinel};
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
    let entry = preview::preview(&cx, "sentinel", &rule);
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
fn an_objective_with_nothing_to_send_leaves_the_blocks_techniques() {
    let (body, warnings, _) = compile(&["T1691"], "      techniques: [T1059]\n");
    assert_eq!(property(&body, "techniques"), r#"["T1059"]"#);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}
