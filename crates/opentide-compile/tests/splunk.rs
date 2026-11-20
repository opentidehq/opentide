//! A Splunk block's `advanced` table (0.24.0, #878): the `savedsearches.conf`
//! keys a deploy sends as written. The oracle (0.23.0) refuses the table, so
//! the compile corpus cannot hold such a rule (`tests/oracle.rs` compares
//! every rule of it with the oracle); these are the cases of 0.24.0's
//! `tests/test_platforms/test_splunk_deployer.py`.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers: every workspace here opens"
)]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::json::Object;
use opentide_compile::{Json, Owned, Rule, deploy, splunk};
use opentide_schema::vocab::Vocabularies;
use opentide_workspace::{FileSystem, MemoryFs, Options, RootOptions, Workspace};

const UUID: &str = "00000000-0000-4000-8005-000000000901";

/// The platform's configuration: a modifier that fills gaps, one that
/// overrides on PRODUCTION, and one tenant whose actions include email.
const SPLUNK_TOML: &str = r#"[platform]
enabled = true

[[modifiers]]
name = "defaults"
[modifiers.conditions]
default = true
[modifiers.modifications]
"alert.track" = "default"
"dispatch.latest_time" = "now"

[[modifiers]]
name = "production"
[modifiers.conditions]
status = ["PRODUCTION"]
[modifiers.modifications]
"alert.digest_mode" = "modifier"

[[tenants]]
name = "es"
[tenants.setup]
url = "splunk.example.org"
token = "$SPLUNK_TOKEN"
actions_enabled = ["notable", "email", "misp_alert_create_event"]
default_actions = ["notable"]
"#;

/// A custom alert action opentide has no block for, as a production rule
/// carries it, and keys the block or the modifiers also set.
const ADVANCED: &str = "    advanced:
      action.misp_alert_create_event.param.title: \"Canary token triggered\"
      action.misp_alert_create_event.param.distribution: 0
      action.misp_alert_create_event.param.ratio: 0.5
      action.misp_alert_create_event.param.publish_on_creation: false
      action.misp_alert_create_event.param.tags:
      alert.track: true
      alert.digest_mode: true
      alert_threshold: 10
      alert.managedBy: soc
      description: not the rule's
";

fn workspace(block: &str) -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.write(
        "/ws/.opentide/configurations/platforms/splunk.toml",
        SPLUNK_TOML.to_owned(),
    );
    fs.create_dir("/ws/objects/rules");
    fs.write(
        "/ws/objects/rules/r.yaml",
        format!(
            "name: Canary\nmetadata:\n  uuid: {UUID}\n  schema: rule::1.0\n\
             description: Canary token\nconfigurations:\n  splunk:\n    status: PRODUCTION\n    \
             query: index=main sourcetype=canarytokens\n{block}"
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

/// The settings update a deploy of the block sends (the second write):
/// its keys and values, in order.
fn settings(block: &str) -> Object {
    settings_at(
        block,
        Some(splunk::Clock {
            random: (7, 7),
            now: (4, 3),
        }),
    )
}

/// [`settings`] compiled with `clock`: `None` is a dry run's.
fn settings_at(block: &str, clock: Option<splunk::Clock>) -> Object {
    let workspace = workspace(block);
    let owned = Owned::new(
        &Vocabularies::bundled(),
        &workspace.configuration().resolved,
    );
    let index = workspace.index().clone();
    let cx = owned.context(&index);
    let object = index.get("rule", UUID).unwrap();
    let rule = Rule::new(object.root().unwrap(), None);
    let tenant = deploy::tenants(&cx, splunk::PLATFORM)[0];
    let writes = splunk::compile(&cx, &rule, tenant, clock).unwrap();
    assert_eq!(writes.len(), 3, "create, settings, then the late settings");
    let Json::Object(body) = writes[1].body.clone() else {
        panic!("a settings update is an object")
    };
    let mut body = body;
    if let Json::Object(late) = &writes[2].body {
        for (key, value) in late {
            body.insert(key.clone(), value.clone());
        }
    }
    body
}

fn text(body: &Object, key: &str) -> Option<String> {
    body.get(key).map(|value| match value {
        Json::Str(text) => text.clone(),
        other => other.to_compact(),
    })
}

#[test]
fn advanced_keys_reach_the_saved_search_as_text() {
    let body = settings(ADVANCED);
    for (key, value) in [
        (
            "action.misp_alert_create_event.param.title",
            "Canary token triggered",
        ),
        ("action.misp_alert_create_event.param.distribution", "0"),
        ("action.misp_alert_create_event.param.ratio", "0.5"),
        // A boolean as every other boolean setting, `null` as the empty value
        // (0.20.1 sent the text `None`).
        (
            "action.misp_alert_create_event.param.publish_on_creation",
            "0",
        ),
        ("action.misp_alert_create_event.param.tags", ""),
    ] {
        assert_eq!(body.get(key), Some(&Json::Str(value.to_owned())), "{key}");
    }
}

#[test]
fn an_action_whose_parameters_are_set_there_is_triggered() {
    let body = settings(ADVANCED);
    assert_eq!(
        body.get("action.misp_alert_create_event"),
        Some(&Json::Int(1))
    );
    assert_eq!(
        text(&body, "actions").as_deref(),
        Some("misp_alert_create_event")
    );
}

#[test]
fn an_advanced_key_wins_over_the_block_and_yields_to_an_overriding_modifier() {
    let body = settings(ADVANCED);
    // Over a value the block sets, and over a default modifier, which only
    // fills gaps.
    assert_eq!(text(&body, "alert_threshold").as_deref(), Some("10"));
    assert_eq!(text(&body, "alert.managedBy").as_deref(), Some("soc"));
    assert_eq!(text(&body, "alert.track").as_deref(), Some("1"));
    // Under a modifier that overrides, which applies after it.
    assert_eq!(
        text(&body, "alert.digest_mode").as_deref(),
        Some("modifier")
    );
    // `description` is the rule's, written after the table.
    assert_eq!(text(&body, "description").as_deref(), Some("Canary token"));
}

#[test]
fn without_the_table_nothing_of_it_is_sent() {
    let body = settings("");
    assert!(
        body.keys()
            .all(|key| !key.starts_with("action.misp_alert_create_event")),
        "{body:?}"
    );
    assert_eq!(text(&body, "alert.track").as_deref(), Some("default"));
    assert_eq!(text(&body, "actions").as_deref(), Some("notable"));
}

/// A drawn schedule (`frequency` with no `custom_time`, the tenant's
/// `frequency_scheduling` unset) runs at the rule's own minute and hour
/// (#1711): a deploy at any time and a dry run, which has no clock, write
/// the same `cron_schedule`.
#[test]
fn a_drawn_schedule_is_the_rules_own_in_a_deploy_and_a_dry_run() {
    let block = "    scheduling:\n      schedule:\n        frequency: 2h\n";
    let (minute, _) = splunk::rule_minute_and_hour(UUID);
    let expected = format!("{minute} */2 * * *");
    for now in [0, 3_600 * 13 + 60 * 21] {
        let clock = splunk::Clock::for_rule(UUID, jiff::Timestamp::from_second(now).unwrap());
        let sent = settings_at(block, Some(clock));
        assert_eq!(
            text(&sent, "cron_schedule").as_deref(),
            Some(expected.as_str())
        );
    }
    let shown = settings_at(block, None);
    assert_eq!(
        text(&shown, "cron_schedule").as_deref(),
        Some(expected.as_str())
    );
}
