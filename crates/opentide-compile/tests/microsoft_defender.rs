//! The Microsoft Defender compiler on the specification's fixtures
//! (`tests/fixtures/microsoft_defender`, microsoft-defender-1.0): the create,
//! update and disable requests of `microsoft-defender.yaml` and the create
//! request of the complete block equal the `.api.json` goldens byte for
//! byte, pretty-printed as the specification writes them; and the tactics
//! are derived from the techniques through the `att&ck` vocabulary.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace and fixture here opens"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use opentide_compile::microsoft_defender::{self, ENDPOINT, create_body, rule_id, rule_url};
use opentide_compile::{Json, Owned, Rule};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/microsoft_defender")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(fixtures().join(name)).unwrap()
}

fn workspace(files: &[(&str, &str)]) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.create_dir("/ws/objects/objectives");
    for (path, text) in files {
        fs.write(format!("/ws/objects/{path}"), (*text).to_owned());
    }
    Workspace::open(
        fs as Arc<dyn FileSystem>,
        Options {
            roots: RootOptions {
                repo: Some(PathBuf::from("/ws")),
                cwd: PathBuf::from("/ws"),
                ..RootOptions::default()
            },
        },
    )
    .unwrap()
}

fn uuid_of(text: &str) -> String {
    text.lines()
        .find_map(|line| line.trim().strip_prefix("uuid: "))
        .unwrap()
        .to_owned()
}

/// `{"method", "url", "body"}`, as the goldens are written: two-space
/// pretty JSON and one final newline.
fn request(method: &str, url: &str, body: Json) -> String {
    let mut object = opentide_compile::json::Object::new();
    object.insert("method".into(), method.into());
    object.insert("url".into(), url.into());
    object.insert("body".into(), body);
    format!("{}\n", Json::Object(object).to_pretty(2))
}

/// The update body of the rule `text` (one of `files`) for `tenant`, its
/// warnings, and its Defender id.
fn compiled(
    text: &str,
    files: &[(&str, &str)],
    tenant: &str,
) -> (Json, Vec<(&'static str, String)>, String) {
    let mut all = vec![("rules/r.yaml", text)];
    all.extend_from_slice(files);
    let workspace = workspace(&all);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", &uuid_of(text)).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let (body, warnings) = microsoft_defender::body_with_warnings(&cx, &rule, tenant).unwrap();
    (body, warnings, rule_id(&rule))
}

#[test]
fn the_create_update_and_disable_requests_are_the_goldens() {
    let text = fixture("microsoft-defender.yaml");
    let (body, warnings, id) = compiled(&text, &[], "contoso");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        request("POST", ENDPOINT, create_body(&id, &body)),
        fixture("rule-microsoft-defender.create.api.json")
    );
    assert_eq!(
        request("PATCH", &rule_url(&id), body),
        fixture("rule-microsoft-defender.update.api.json")
    );
    // The same rule under a DISABLEMENT status (`DISABLED`).
    let disabled = text.replace("    status: STAGING\n", "    status: DISABLED\n");
    assert_ne!(disabled, text);
    let (body, _, id) = compiled(&disabled, &[], "contoso");
    assert_eq!(
        request("PATCH", &rule_url(&id), body),
        fixture("rule-microsoft-defender.disable.api.json")
    );
}

#[test]
fn the_complete_blocks_create_request_is_the_golden() {
    // Deployed to contoso: the exclusion scoped to fabrikam is left out.
    let text = fixture("microsoft-defender-complete.yaml");
    let (body, warnings, id) = compiled(&text, &[], "contoso");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        request("POST", ENDPOINT, create_body(&id, &body)),
        fixture("rule-microsoft-defender-complete.create.api.json")
    );
}

#[test]
fn a_tenants_exclusion_is_appended_to_the_query() {
    let text = fixture("microsoft-defender-complete.yaml");
    let (body, _, _) = compiled(&text, &[], "fabrikam");
    let query = body
        .get("queryCondition")
        .and_then(|condition| condition.get("queryText"))
        .and_then(Json::as_str)
        .unwrap();
    assert!(query.contains("DeviceName != BuildAgent"), "{query}");
    assert!(query.starts_with("let BuildAgent"), "{query}");
}

const MINIMAL: &str = "name: Minimal\nmetadata:\n  uuid: 00000000-0000-4000-8003-0000000000e9\n  \
    schema: rule::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  \
    tlp: clear\ndescription: A rule.\n{model}configurations:\n  microsoft_defender:\n    \
    status: STAGING\n    query: DeviceProcessEvents | take 1\n    schedule:\n      \
    frequency: NRT\n{alert}";

fn minimal(model: &str, alert: &str) -> String {
    MINIMAL.replace("{model}", model).replace("{alert}", alert)
}

#[test]
fn unset_keys_are_left_out_and_defaults_apply() {
    // Written upper case, the id is the lowercase canonical uuid.
    let upper = minimal("", "").replace("0000000000e9\n  schema", "0000000000E9\n  schema");
    let (body, warnings, id) = compiled(&upper, &[], "contoso");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(id, "00000000-0000-4000-8003-0000000000e9");
    assert_eq!(
        body.to_compact(),
        r#"{"displayName":"Minimal","description":"A rule.","status":"enabled","queryCondition":{"queryText":"DeviceProcessEvents | take 1"},"schedule":{"frequency":"PT0S"},"detectionAction":{"alertTemplate":{"title":"Minimal","description":"A rule.","severity":"medium"}}}"#
    );
}

#[test]
fn durations_are_iso_8601() {
    for (written, sent) in [
        ("1H", "PT1H"),
        ("24H", "PT24H"),
        ("1D", "P1D"),
        ("NRT", "PT0S"),
    ] {
        let text = minimal("", "").replace("frequency: NRT", &format!("frequency: {written}"));
        let (body, _, _) = compiled(&text, &[], "contoso");
        assert_eq!(
            body.get("schedule").unwrap().to_compact(),
            format!(r#"{{"frequency":"{sent}"}}"#)
        );
    }
}

#[test]
fn critical_is_sent_as_high_and_the_responses_severity_is_the_default() {
    let text = minimal("response:\n  alert_severity: Critical\n", "");
    let (body, _, _) = compiled(&text, &[], "contoso");
    let severity = body
        .get("detectionAction")
        .and_then(|action| action.get("alertTemplate"))
        .and_then(|template| template.get("severity"))
        .and_then(Json::as_str);
    assert_eq!(severity, Some("high"));
}

const OBJECTIVE: &str = "name: Objective\nmetadata:\n  uuid: 00000000-0000-4000-8002-0000000000e9\n  \
    schema: objective::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  \
    tlp: clear\nobjective:\n  priority: High\n  type: Threat\n  mitre_attack: [{ids}]\n";

fn template_tactics(body: &Json) -> Option<String> {
    body.get("detectionAction")
        .and_then(|action| action.get("alertTemplate"))
        .and_then(|template| template.get("tactics"))
        .map(Json::to_compact)
}

#[test]
fn the_objectives_techniques_are_used_when_the_block_sets_none() {
    let objective = OBJECTIVE.replace("{ids}", "T1059.001");
    let text = minimal(
        "detection_model: 00000000-0000-4000-8002-0000000000e9\n",
        "",
    );
    let (body, warnings, _) = compiled(&text, &[("objectives/o.yaml", &objective)], "contoso");
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        template_tactics(&body).as_deref(),
        Some(
            r#"[{"tactic":"Execution","techniques":[{"technique":"T1059","subTechniques":["T1059.001"]}]}]"#
        )
    );
    // The block's own list wins; the two are never merged.
    let own = minimal(
        "detection_model: 00000000-0000-4000-8002-0000000000e9\n",
        "    alert:\n      techniques: [T1071]\n",
    );
    let (body, _, _) = compiled(&own, &[("objectives/o.yaml", &objective)], "contoso");
    assert_eq!(
        template_tactics(&body).as_deref(),
        Some(r#"[{"tactic":"CommandAndControl","techniques":[{"technique":"T1071"}]}]"#)
    );
}

#[test]
fn unknown_and_non_enterprise_techniques_are_left_out_with_a_warning() {
    let text = minimal("", "    alert:\n      techniques: [T9999, T0800]\n");
    let (body, warnings, _) = compiled(&text, &[], "contoso");
    assert_eq!(
        template_tactics(&body),
        None,
        "no technique left: no tactics"
    );
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].1.contains("T9999"), "{warnings:?}");
    assert!(warnings[1].1.contains("T0800"), "{warnings:?}");
}

#[test]
fn a_parent_and_its_sub_technique_share_one_entry() {
    let text = minimal(
        "",
        "    alert:\n      techniques: [T1059.003, T1059, T1059.001]\n",
    );
    let (body, _, _) = compiled(&text, &[], "contoso");
    assert_eq!(
        template_tactics(&body).as_deref(),
        Some(
            r#"[{"tactic":"Execution","techniques":[{"technique":"T1059","subTechniques":["T1059.001","T1059.003"]}]}]"#
        )
    );
}

#[test]
fn a_dry_run_shows_the_first_call() {
    let workspace = |text: &str| workspace(&[("rules/r.yaml", text)]);
    for (status, method) in [
        ("STAGING", Some("PATCH")),
        ("DISABLED", Some("PATCH")),
        ("REMOVED", Some("DELETE")),
        ("DESIGN", None),
    ] {
        let text = minimal("", "").replace("status: STAGING", &format!("status: {status}"));
        let workspace = workspace(&text);
        let owned = Owned::new(
            &Vocabularies::bundled(),
            &workspace.configuration().resolved,
        );
        let index = workspace.index().clone();
        let cx = owned.context(&index);
        let object = index.get("rule", &uuid_of(&text)).unwrap();
        let rule = Rule::new(object.root().unwrap(), None);
        let writes = microsoft_defender::compile(&cx, &rule, "contoso").unwrap();
        assert_eq!(writes.first().map(|write| write.method), method, "{status}");
        if let Some(write) = writes.first() {
            assert_eq!(write.url, rule_url("00000000-0000-4000-8003-0000000000e9"));
        }
    }
}
