//! The dry run's Elastic entry (`preview_on`): the deploy body compiled for
//! the first tenant the run sends the rule to, as `opentide deploy` compiles
//! it, so a tenant's `tags`, `index` and `suppression = false` are in it.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::{Json, Owned, Rule, deploy, elastic, modifiers, preview};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

const UUID: &str = "00000000-0000-4000-8099-000000000181";

/// A rule on no index of its own, with alert suppression.
const RULE: &str = "name: Suppressed rule\nmetadata:\n  uuid: 00000000-0000-4000-8099-000000000181\n  \
     schema: rule::1.0\n  version: 1\n  created: 2026-01-01\n  modified: 2026-01-02\n  tlp: \
     clear\ndescription: A rule.\nresponse:\n  alert_severity: High\nconfigurations:\n  \
     elastic:\n    status: STAGING\n    type: query\n    language: kuery\n    query: \
     'process.name: \"cmd.exe\"'\n    scheduling:\n      interval: 5m\n    suppression:\n      \
     group_by: [host.name]\n";

/// Two tenants: `basic` (a Basic licence: no suppression; its own tags and
/// index; a modifier that runs its rules hourly), then `full`.
const PLATFORM: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"basic\"\nstrategies \
     = [\"PREVIEW\"]\n[tenants.setup]\nurl = \"https://kibana.invalid\"\ntags = [\"soc\"]\nindex \
     = [\"winlogbeat-*\"]\nsuppression = false\n\n[[tenants]]\nname = \"full\"\nstrategies = \
     [\"PREVIEW\"]\n[tenants.setup]\nurl = \"https://kibana-full.invalid\"\n\n[[modifiers]]\nname \
     = \"basic hourly\"\n[modifiers.conditions]\ntenants = [\"basic\"]\n[modifiers.modifications]\n\
     \"scheduling.interval\" = \"1h\"\n";

fn workspace() -> Workspace {
    workspace_with(RULE)
}

fn workspace_with(rule: &str) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", rule.to_owned());
    fs.write(
        "/ws/.opentide/configurations/platforms/elastic.toml",
        PLATFORM.to_owned(),
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

#[test]
fn a_dry_run_shows_the_body_a_deploy_compiles_for_the_first_tenant() {
    let workspace = workspace();
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let tenants = vec!["basic".to_owned(), "full".to_owned()];
    let entry = preview::preview_on(&cx, "elastic", &rule, &tenants);
    assert_eq!(entry.get("tenant").and_then(Json::as_str), Some("basic"));
    let shown = entry.get("api_request").unwrap().clone();
    // The body `opentide deploy` sends to `basic`, byte for byte: the rule
    // with `basic`'s modifiers, compiled with its setup.
    let table = deploy::tenant(&cx, "elastic", "basic").unwrap();
    let modified = modifiers::rule_for_tenant(
        &modifiers::of_platform(cx.config, "elastic"),
        "elastic",
        &rule,
        "basic",
    );
    let sent = preview::elastic_request(
        &modified,
        elastic::compile(&cx, &modified, &elastic::Setup::from_tenant(table)).unwrap(),
    );
    assert_eq!(shown.to_compact(), sent.to_compact());
    // The modifier is in it: hourly, in the Kibana rule and the block.
    assert!(
        shown.to_compact().contains("\"interval\":\"1h\""),
        "{shown:?}"
    );
    // And the tenant's setup is in it.
    let payload = shown.get("payload").unwrap();
    let tags = payload.get("tags").unwrap().to_compact();
    assert!(tags.contains("\"soc\""), "{tags}");
    // opentide's marker leads the tags, in lower case (it was `OpenTide`).
    assert!(tags.starts_with("[\"opentide\","), "{tags}");
    assert!(!tags.contains("OpenTide"), "{tags}");
    assert_eq!(
        payload.get("index").unwrap().to_compact(),
        "[\"winlogbeat-*\"]"
    );
    assert!(payload.get("alert_suppression").is_none(), "{payload:?}");
    // Compiled without a tenant, the rule keeps its suppression.
    let offline = preview::preview(&cx, "elastic", &rule);
    assert!(offline.get("tenant").is_none());
    let offline = offline.get("api_request").unwrap().get("payload").unwrap();
    assert!(offline.get("alert_suppression").is_some(), "{offline:?}");
    assert!(offline.get("index").is_none(), "{offline:?}");
    assert!(
        offline.to_compact().contains("\"interval\":\"5m\""),
        "{offline:?}"
    );
}

/// #1982: a duration past `ELASTIC_MAX_SECONDS` saturated into the payload
/// (`from: now-340282366920938463463374607431768211455s`); the compiler now
/// refuses the rule, as the model does, naming the field.
#[test]
fn a_duration_past_the_deployable_bound_refuses_the_rule() {
    let huge = "9".repeat(40) + "s";
    for (field, rule) in [
        (
            "lookback",
            RULE.replace(
                "interval: 5m\n",
                &format!("interval: 5m\n      lookback: {huge}\n"),
            ),
        ),
        (
            "interval",
            RULE.replace("interval: 5m\n", &format!("interval: {huge}\n")),
        ),
        (
            "interval",
            RULE.replace("interval: 5m\n", "interval: 9223372036854775808s\n"),
        ),
    ] {
        let workspace = workspace_with(&rule);
        let owned = Owned::new(
            &Vocabularies::bundled(),
            &workspace.configuration().resolved,
        );
        let index = workspace.index().clone();
        let cx = owned.context(&index);
        let object = index.get("rule", UUID).unwrap();
        let rule = Rule::new(object.root().unwrap(), None);
        let error = elastic::compile(&cx, &rule, &elastic::Setup::none()).unwrap_err();
        assert_eq!(error.code, "compile_invalid_rule", "{error}");
        assert_eq!(
            error.field,
            ["configurations", "elastic", "scheduling", field],
            "{error}"
        );
        assert!(
            error.reason.contains("at most 9223372036854775807 seconds"),
            "{error}"
        );
    }
    // At the bound, the window is exact: interval plus lookback, no saturation.
    let rule = RULE.replace(
        "interval: 5m\n",
        "interval: 9223372036854775807s\n      lookback: 9223372036854775807s\n",
    );
    let workspace = workspace_with(&rule);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let body = elastic::compile(&cx, &rule, &elastic::Setup::none()).unwrap();
    assert_eq!(
        body.get("from").and_then(Json::as_str),
        Some("now-18446744073709551614s")
    );
}

/// Tags, authors and techniques are each sent once, in the order they first
/// came: opentide's marker, then the tenant's tags, then the rule's (#1957).
#[test]
fn tags_authors_and_techniques_are_each_sent_once_in_first_order() {
    let rule = RULE
        .replace(
            "  tlp: clear\n",
            "  tlp: clear\n  author: é\n  contributors: [😀, é, '', 😀, É]\n",
        )
        .replace(
            "    status: STAGING\n",
            "    status: STAGING\n    tags: [😀, opentide, é, soc, 😀, e\u{301}]\n",
        )
        .replace(
            "description: A rule.\n",
            "description: A rule.\ntechniques: [T1059.001, T1003, T1059.001]\n",
        );
    let workspace = workspace_with(&rule);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let setup = elastic::Setup {
        tags: vec!["soc".to_owned(), "é".to_owned(), "soc".to_owned()],
        ..elastic::Setup::none()
    };
    let body = elastic::compile(&cx, &rule, &setup).unwrap();
    assert_eq!(
        body.get("tags").unwrap().to_compact(),
        "[\"opentide\",\"soc\",\"é\",\"😀\",\"e\u{301}\"]"
    );
    assert_eq!(
        body.get("author").unwrap().to_compact(),
        "[\"é\",\"😀\",\"É\"]"
    );
    assert_eq!(elastic::rule_techniques(&cx, &rule), ["T1059.001", "T1003"]);
}
