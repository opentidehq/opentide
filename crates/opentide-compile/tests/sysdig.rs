//! The Sysdig compiler on blocks the compile corpus does not hold: the
//! failures a block's definitions give, the expansion's corners and the
//! tuning's body. The corpus's bodies are compared with the oracle by
//! `tests/oracle.rs`.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here opens"
)]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::preview;
use opentide_compile::strategy::StatusStrategy;
use opentide_compile::{Json, Owned, Rule, sysdig};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

const UUID: &str = "00000000-0000-4000-8005-000000000901";

fn workspace(block: &str) -> Workspace {
    workspace_with("", block)
}

/// A workspace whose rule has the top-level keys `top` besides the block.
fn workspace_with(top: &str, block: &str) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write(
        "/ws/objects/rules/r.yaml",
        format!(
            "name: Rule\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.0\n\
             description: \"a\\u001cb  c\"\n{top}configurations:\n  sysdig:\n{block}"
        ),
    );
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

/// The dry run's body of the block, or its error's code and reason.
fn body(block: &str) -> Result<String, (String, String)> {
    body_with("", block)
}

/// The dry run's body of the block in a rule with the top-level keys `top`.
fn body_with(top: &str, block: &str) -> Result<String, (String, String)> {
    let workspace = workspace_with(top, block);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    sysdig::compile_body(&cx, &rule, None)
        .map(|body| body.to_compact())
        .map_err(|error| (error.code.to_owned(), error.reason))
}

fn details(block: &str) -> Json {
    let text = body(block).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut json = Json::Null;
    if let Some(details) = parsed.get("details") {
        json = Json::Str(details.to_string());
    }
    json
}

#[test]
fn a_macro_sees_only_earlier_macros() {
    let (code, reason) = body(
        "    status: STAGING\n    condition: m1\n    macros:\n    - name: m1\n      \
         condition: m2 and proc.name = x\n    - name: m2\n      condition: evt.type = open\n",
    )
    .unwrap_err();
    assert_eq!(code, "compile_failed");
    assert_eq!(
        reason,
        "Sysdig cannot compile this rule: macro \"m1\" uses the block macro \"m2\", which is \
         itself or defined after it: Falco refuses it as an undefined macro"
    );
}

#[test]
fn a_macro_cannot_use_itself() {
    let (code, reason) = body(
        "    status: STAGING\n    condition: m1\n    macros:\n    - name: m1\n      \
         condition: m1 and proc.name = x\n",
    )
    .unwrap_err();
    assert_eq!(code, "compile_failed");
    assert_eq!(
        reason,
        "Sysdig cannot compile this rule: macro \"m1\" uses the block macro \"m1\", which is \
         itself or defined after it: Falco refuses it as an undefined macro"
    );
}

#[test]
fn a_tuple_exception_without_comps_compares_with_equals() {
    // No comps: every field compares with `=`, which takes one value, so a
    // block list as a whole tuple item is refused, not expanded.
    let (_, reason) = body(
        "    status: STAGING\n    condition: proc.name = x\n    exceptions:\n    - name: t\n      \
         fields: [proc.name]\n      values:\n      - [shells]\n    lists:\n    - name: shells\n      \
         items: [bash, sh]\n",
    )
    .unwrap_err();
    assert_eq!(
        reason,
        "Sysdig cannot compile this rule: exception \"t\": the block list \"shells\" appears in a \
         value where Falco's expansion would not produce a value list"
    );
}

#[test]
fn float_items_are_written_as_python_writes_them() {
    let out = details(
        "    status: STAGING\n    condition: proc.name in (l)\n    lists:\n    - name: l\n      \
         items: [1.0e+16, 1.0e-5, 0.5]\n",
    );
    let Json::Str(text) = out else { panic!() };
    assert!(
        text.contains("\"condition\":\"proc.name in ( 1e+16, 1e-05, 0.5 )\""),
        "{text}"
    );
}

#[test]
fn a_low_severity_is_a_notice() {
    let text = body_with(
        "response:\n  alert_severity: Low\n",
        "    status: STAGING\n    condition: proc.name = x\n",
    )
    .unwrap();
    assert!(text.contains("\"priority\":\"notice\""), "{text}");
}

#[test]
fn a_list_inside_a_value_is_refused() {
    let lists = "    lists:\n    - name: shells\n      items: [bash, sh]\n";
    let (_, reason) = body(&format!(
        "    status: STAGING\n    condition: proc.name = x\n    exceptions:\n    - name: e\n      \
         fields: proc.name\n      values: [\"a,shells\"]\n{lists}"
    ))
    .unwrap_err();
    assert_eq!(
        reason,
        "Sysdig cannot compile this rule: exception \"e\": the block list \"shells\" appears in a \
         value where Falco's expansion would not produce a value list"
    );
    // A list as all of a tuple item, under a comparison that takes one value.
    let (_, reason) = body(&format!(
        "    status: STAGING\n    condition: proc.name = x\n    exceptions:\n    - name: t\n      \
         fields: [proc.name]\n      comps: [\"=\"]\n      values:\n      - [shells]\n{lists}"
    ))
    .unwrap_err();
    assert!(
        reason.contains("exception \"t\": the block list \"shells\""),
        "{reason}"
    );
    // Inside a nested value list, and inside a tuple item.
    for values in ["      - [[\"x shells\"]]\n", "      - [\"(shells)\"]\n"] {
        let (_, reason) = body(&format!(
            "    status: STAGING\n    condition: proc.name = x\n    exceptions:\n    - name: n\n      \
             fields: [proc.name]\n      comps: [in]\n      values:\n{values}{lists}"
        ))
        .unwrap_err();
        assert!(reason.contains("the block list \"shells\""), "{reason}");
    }
}

#[test]
fn an_unknown_status_fails_with_its_name() {
    let (code, reason) = body("    status: NOPE\n    condition: proc.name = x\n").unwrap_err();
    assert_eq!(code, "compile_failed");
    assert!(
        reason.starts_with(
            "Sysdig cannot compile this rule: Status \"NOPE\" is not defined in deployment \
             configuration. Available statuses: DESIGN, "
        ),
        "{reason}"
    );
}

#[test]
fn a_priority_falco_does_not_know_fails() {
    let (_, reason) =
        body("    status: STAGING\n    condition: proc.name = x\n    priority: urgent\n")
            .unwrap_err();
    assert_eq!(reason, "Sysdig cannot compile this rule: \"URGENT\"");
}

#[test]
fn a_new_rule_derives_its_fields() {
    let text =
        body("    status: PRODUCTION\n    condition: proc.name = x\n    output: \"\"\n").unwrap();
    assert_eq!(
        text,
        "{\"name\":\"Rule\",\"description\":\"a b c\",\"tags\":[\"maturity_stable\"],\
         \"details\":{\"ruleType\":\"FALCO\",\"append\":false,\"source\":\"syscall\",\
         \"condition\":{\"condition\":\"proc.name = x\",\"components\":[]},\
         \"output\":\"Rule | evt_type=%evt.type user=%user.name user_uid=%user.uid \
         process=%proc.name proc_exepath=%proc.exepath parent=%proc.pname \
         command=%proc.cmdline terminal=%proc.tty container_id=%container.id \
         container_name=%container.name image=%container.image.repository\",\
         \"priority\":\"warning\"}}"
    );
    // A strategy neither released nor previewed is a sandbox rule; a source
    // without default fields gets the name alone.
    let text = body("    status: DESIGN\n    source: github\n    condition: x.y = 1\n").unwrap();
    assert!(text.contains("\"tags\":[\"maturity_sandbox\"]"), "{text}");
    assert!(text.contains("\"output\":\"Rule\""), "{text}");
}

#[test]
fn a_tuning_without_a_condition_sends_its_exceptions() {
    let text = body(
        "    status: STAGING\n    append_to_rule: Tuned\n    exceptions:\n    - name: e\n      \
         fields: [proc.name, proc.pname]\n      values:\n      - [a, b]\n      - plain\n",
    )
    .unwrap();
    assert_eq!(
        text,
        "{\"name\":\"Tuned\",\"description\":\"\",\"tags\":[],\"details\":{\"ruleType\":\
         \"FALCO\",\"append\":true,\"exceptions\":[{\"name\":\"e\",\"fields\":[\"proc.name\",\
         \"proc.pname\"],\"values\":[[\"a\",\"b\"],\"plain\"]}]}}"
    );
}

#[test]
fn definitions_of_the_same_name_keep_the_last() {
    let out = details(
        "    status: STAGING\n    condition: m and proc.name in (l)\n    macros:\n    - name: m\n      \
         condition: a.b = 1\n    - name: m\n      condition: a.b = 2\n    lists:\n    - name: l\n      \
         items: [x]\n    - name: l\n      items: [y, 1, 2.5, true]\n    exceptions:\n    - name: e\n      \
         fields: [a.b]\n      comps: [in]\n      values:\n      - [l]\n      - [[l, z]]\n",
    );
    let Json::Str(text) = out else { panic!() };
    assert!(
        text.contains("\"condition\":\"(a.b = 2) and proc.name in ( y, 1, 2.5, true )\""),
        "{text}"
    );
    assert!(
        text.contains(
            "\"values\":[[[\"y\",\"1\",\"2.5\",\"true\"]],[[\"y\",\"1\",\"2.5\",\"true\",\"z\"]]]"
        ),
        "{text}"
    );
}

#[test]
fn a_rule_without_a_block_fails() {
    let workspace = workspace("    status: STAGING\n    condition: x.y = 1\n");
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let mut bare = rule.clone();
    bare.data = Json::Null;
    let error = sysdig::compile_body(&cx, &bare, None).unwrap_err();
    assert!(error.reason.contains("has no sysdig block"), "{error}");
    // A failing block's preview is a failure entry that names Sysdig.
    let mut unknown = rule;
    if let Json::Object(data) = &mut unknown.data
        && let Some(Json::Object(configurations)) = data.get_mut("configurations")
        && let Some(Json::Object(block)) = configurations.get_mut("sysdig")
    {
        block.insert("status".into(), "NOPE".into());
    }
    let entry = preview::preview(&cx, "sysdig", &unknown, &[]);
    assert_eq!(entry.get("status").and_then(Json::as_str), Some("failed"));
    assert!(
        entry
            .get("error")
            .and_then(Json::as_str)
            .is_some_and(|error| error.starts_with("Sysdig cannot compile this rule: ")),
        "{}",
        entry.to_compact()
    );
    assert!(sysdig::strategy(&cx, &unknown).is_err());
    for (strategy, tag) in [
        (StatusStrategy::Release, "maturity_stable"),
        (StatusStrategy::Universal, "maturity_stable"),
        (StatusStrategy::Preview, "maturity_incubating"),
        (StatusStrategy::Disablement, sysdig::SANDBOX_TAG),
        (StatusStrategy::Inert, sysdig::SANDBOX_TAG),
    ] {
        assert_eq!(sysdig::maturity_tag(strategy), tag);
    }
}
