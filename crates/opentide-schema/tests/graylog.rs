//! The Graylog block model (`platform::graylog::1.0`): every constraint code
//! at the path graylog-1.0 fixes for it, the nested models, and the
//! repository's fixtures. The cases are 0.28.0's
//! `tests/test_platforms/test_graylog_model.py`.
#![expect(
    clippy::unwrap_used,
    reason = "test helpers outside #[test]: a fixture that cannot be read fails the test"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use opentide_schema::FromNode;
use opentide_schema::error::{ErrorKind, SchemaError};
use opentide_schema::from_node::Context;
use opentide_schema::node::{self, Node};
use opentide_schema::objects::platform::graylog::{
    self, GraylogConfig, GraylogEventField, StringOrList, block_findings, constraint_codes,
    event_field_kind, list_ok,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn yaml(text: &str) -> Node {
    node::load(text).unwrap().root().unwrap().as_ref().clone()
}

/// A block: the shared keys and `query: EventID:1` (unless `extra` sets
/// one), then `extra` (YAML lines at the block's level).
fn block(extra: &str) -> Node {
    let query = if extra.starts_with("query:") {
        ""
    } else {
        "query: EventID:1\n"
    };
    yaml(&format!(
        "enabled: true\nschema: platform::graylog::1.0\nstatus: STAGING\n{query}{extra}"
    ))
}

fn codes(extra: &str) -> BTreeSet<&'static str> {
    block_findings(&block(extra))
        .into_iter()
        .map(|finding| finding.code)
        .collect()
}

fn convert(node: &Node) -> (Option<GraylogConfig>, Vec<SchemaError>) {
    let mut cx = Context::new();
    let value = GraylogConfig::from_node(node, &mut cx);
    (value, cx.into_errors())
}

/// Each error's type and path.
fn errors(node: &Node) -> Vec<(String, Vec<String>)> {
    let (value, errors) = convert(node);
    assert!(value.is_none() || !errors.is_empty() || errors.is_empty());
    errors
        .iter()
        .map(|error| {
            (
                error.kind.pydantic_type().unwrap_or_default().to_owned(),
                error.field_path(),
            )
        })
        .collect()
}

fn set(codes: &[&'static str]) -> BTreeSet<&'static str> {
    codes.iter().copied().collect()
}

#[test]
fn block_codes() {
    let cases: &[(&str, &[&'static str])] = &[
        ("", &[]),
        ("query: '  '", &["graylog_query_blank"]),
        ("streams: sysmon", &[]),
        ("streams: [a, a]", &["graylog_list_shape"]),
        ("notifications: ['']", &["graylog_list_shape"]),
        ("priority: Urgent", &["graylog_priority"]),
        ("event_limit: 0", &["graylog_event_limit"]),
        (
            "event_limit: 10\naggregation: {condition: count() > 1}",
            &["graylog_event_limit"],
        ),
        ("schedule: {every: 0m}", &["graylog_schedule"]),
        ("schedule: {cron: '0 */5 * * * ?'}", &["graylog_schedule"]),
        (
            "schedule: {cron: '0 */5 * * * ?', window: 5m, timezone: Mars/Base}",
            &["graylog_schedule"],
        ),
        ("schedule: {every: PT5M, window: 1h10m}", &[]),
        ("aggregation: {group_by: source}", &["graylog_aggregation"]),
        (
            "aggregation: {group_by: [src ip], condition: count() > 1}",
            &["graylog_field_name"],
        ),
        (
            "event_fields: {host: source, x: '${source.a}-${source.b}', y: {template: LOLBin}}",
            &[],
        ),
        (
            "event_fields: {owner: {lookup: {table: t, key_field: source}}}",
            &[],
        ),
        ("event_fields: {x: two words}", &["graylog_event_field"]),
        (
            "event_fields: {x: {lookup: {table: t}}}",
            &["graylog_event_field"],
        ),
        ("event_fields: {host: source}\nevent_key: host", &[]),
        (
            "event_fields: {host: source}\nevent_key: [user]",
            &["graylog_event_key"],
        ),
    ];
    for (extra, expected) in cases {
        assert_eq!(codes(extra), set(expected), "{extra}");
    }
}

#[test]
fn each_code_is_reported_at_its_spec_path() {
    let cases: &[(&str, &str, &[&str])] = &[
        ("query: ''", "graylog_query_blank", &["query"]),
        ("tags: [x, x]", "graylog_list_shape", &["tags"]),
        (
            "stream_categories: [1]",
            "graylog_list_shape",
            &["stream_categories"],
        ),
        (
            "aggregation: {group_by: [a, a], condition: count() > 1}",
            "graylog_list_shape",
            &["aggregation", "group_by"],
        ),
        (
            "schedule: {every: 5m, cron: '0 0 * * * ?'}",
            "graylog_schedule",
            &["schedule"],
        ),
        ("schedule: 5m", "graylog_schedule", &["schedule"]),
        (
            "schedule: {every: 1w}",
            "graylog_schedule",
            &["schedule", "every"],
        ),
        (
            "schedule: {window: 0s}",
            "graylog_schedule",
            &["schedule", "window"],
        ),
        (
            "schedule: {cron: '*/5 * * * *', window: 5m}",
            "graylog_schedule",
            &["schedule", "cron"],
        ),
        (
            "schedule: {cron: '0 0 * * * ?'}",
            "graylog_schedule",
            &["schedule", "window"],
        ),
        (
            "schedule: {every: 5m, timezone: Nowhere/City}",
            "graylog_schedule",
            &["schedule", "timezone"],
        ),
        ("event_limit: 1001", "graylog_event_limit", &["event_limit"]),
        ("event_limit: true", "graylog_event_limit", &["event_limit"]),
        ("aggregation: {}", "graylog_aggregation", &["aggregation"]),
        (
            "aggregation: {condition: count() >= 3 or count() < 9}",
            "graylog_aggregation",
            &["aggregation", "condition"],
        ),
        (
            "event_fields: {bad name: source}",
            "graylog_event_field",
            &["event_fields", "bad name"],
        ),
        (
            "event_fields: [source]",
            "graylog_event_field",
            &["event_fields"],
        ),
        (
            "event_fields: {x: {template: ' '}}",
            "graylog_event_field",
            &["event_fields", "x"],
        ),
        ("event_key: host", "graylog_event_key", &["event_key"]),
        ("priority: high", "graylog_priority", &["priority"]),
        (
            "aggregation: {group_by: src ip, condition: count() > 1}",
            "graylog_field_name",
            &["aggregation", "group_by"],
        ),
    ];
    for (extra, code, path) in cases {
        let found = errors(&block(extra));
        let path: Vec<String> = path.iter().map(|part| (*part).to_owned()).collect();
        assert!(
            found.contains(&((*code).to_owned(), path.clone())),
            "{extra}: {found:?}"
        );
    }
}

#[test]
fn the_messages_are_the_oracles() {
    let message = |extra: &str| {
        let (_, errors) = convert(&block(extra));
        errors
            .iter()
            .map(|error| error.message.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        message("query: ''"),
        ["query must not be empty: it is the Graylog search query"]
    );
    assert_eq!(
        message("schedule: {every: 5m, cron: '0 0 * * * ?'}"),
        [
            "every and cron are exclusive",
            "window is required with cron"
        ]
    );
    assert_eq!(
        message("schedule: {every: 5m, timezone: 3}"),
        ["3 is not an IANA time zone (UTC, Europe/Paris)"]
    );
    assert_eq!(
        message("priority: high"),
        ["\"high\" is not one of Informational, Low, Medium, High, Critical"]
    );
    assert_eq!(
        message("event_fields: {1: source}"),
        ["1 is not a field name ([A-Za-z0-9_.@-]+)"]
    );
    assert_eq!(
        message("event_limit: 5\naggregation: {condition: count() > 1}"),
        ["event_limit is for filters: an aggregation creates one event per group"]
    );
    assert_eq!(
        message("event_limit: x"),
        ["event_limit is an integer from 1 to 1,000, on a filter only"]
    );
    assert_eq!(
        message("aggregation: {group_by: [a b, c], condition: count() > 1}"),
        ["not field names ([A-Za-z0-9_.@-]+): a b"]
    );
    assert_eq!(
        message("event_fields: {h: source}\nevent_key: [h, u, v]"),
        ["not event_fields names: u, v"]
    );
    assert_eq!(
        message("aggregation: {condition: total() > 1}"),
        ["\"total\" is not an aggregation function"]
    );
}

#[test]
fn every_constraint_code_has_a_case() {
    let expected = set(&[
        "graylog_query_blank",
        "graylog_list_shape",
        "graylog_schedule",
        "graylog_event_limit",
        "graylog_aggregation",
        "graylog_event_field",
        "graylog_event_key",
        "graylog_priority",
        "graylog_field_name",
    ]);
    assert_eq!(constraint_codes().collect::<BTreeSet<_>>(), expected);
}

#[test]
fn a_constraint_error_is_typed_by_its_code() {
    let (value, errors) = convert(&block("priority: high"));
    assert!(value.is_none());
    assert_eq!(errors[0].kind, ErrorKind::Constraint("graylog_priority"));
    assert_eq!(errors[0].input, None);
}

#[test]
fn a_missing_query_is_graylog_query_blank() {
    let node = yaml("enabled: true\nstatus: STAGING\n");
    assert!(errors(&node).contains(&("graylog_query_blank".to_owned(), vec!["query".to_owned()])));
}

#[test]
fn status_is_required() {
    let node = yaml("enabled: true\nquery: EventID:1\n");
    assert!(errors(&node).contains(&("missing".to_owned(), vec!["status".to_owned()])));
}

#[test]
fn unknown_keys_fail() {
    for extra in [
        "rule_type: filter",
        "schedule: {every: 5m, interval: 5m}",
        "aggregation: {condition: count() > 1, series: []}",
    ] {
        assert!(
            errors(&block(extra))
                .iter()
                .any(|(kind, _)| kind == "extra_forbidden"),
            "{extra}"
        );
    }
}

#[test]
fn an_unknown_key_in_an_event_field_map_fails() {
    let found = errors(&block(
        "event_fields: {x: {template: a, require_values: true}}",
    ));
    assert!(found.contains(&(
        "graylog_event_field".to_owned(),
        vec!["event_fields".to_owned(), "x".to_owned()]
    )));
}

#[test]
fn a_bad_grace_period_fails() {
    let (value, errors) = convert(&block("grace_period: soon"));
    assert!(value.is_none());
    assert_eq!(
        errors[0].message,
        "Value error, Invalid duration format: \"soon\""
    );
    let (value, _) = convert(&block("grace_period: 0s"));
    assert_eq!(value.unwrap().grace_period.as_deref(), Some("0s"));
}

#[test]
fn backlog_is_zero_or_more() {
    let (value, _) = convert(&block("backlog: -1"));
    assert!(value.is_none());
    let (value, _) = convert(&block("backlog: 0"));
    assert_eq!(value.unwrap().backlog, Some(0));
}

#[test]
fn alert_defaults_to_true() {
    let (value, _) = convert(&block(""));
    assert!(value.unwrap().alert);
    let (value, _) = convert(&block("alert: false"));
    assert!(!value.unwrap().alert);
}

fn fixture_block(path: &Path) -> Node {
    let text = std::fs::read_to_string(path).unwrap();
    let document = node::load(&text).unwrap();
    document
        .root()
        .and_then(|root| root.get("configurations"))
        .and_then(|configurations| configurations.get("graylog"))
        .unwrap()
        .as_ref()
        .clone()
}

#[test]
fn valid_fixtures_load() {
    let root = repo().join("tests/fixtures/graylog");
    for name in [
        "block-graylog.yaml",
        "rule-graylog-aggregation-1.0.yaml",
        "rule-graylog-filter-1.1.yaml",
    ] {
        let node = fixture_block(&root.join(name));
        assert_eq!(block_findings(&node), [], "{name}");
        let (value, errors) = convert(&node);
        assert_eq!(errors, [], "{name}");
        assert!(value.is_some(), "{name}");
    }
}

#[test]
fn the_aggregation_fixture_reads_into_the_model() {
    let node =
        fixture_block(&repo().join("tests/fixtures/graylog/rule-graylog-aggregation-1.0.yaml"));
    let block = convert(&node).0.unwrap();
    assert_eq!(block.streams, Some(StringOrList::One("sysmon".into())));
    assert_eq!(block.stream_aliases(), ["sysmon"]);
    assert_eq!(
        block.tags,
        Some(StringOrList::Many(vec![
            "Office".into(),
            "initial access".into()
        ]))
    );
    let fields = block.event_fields.unwrap();
    assert!(matches!(fields["host"], GraylogEventField::Text(ref text) if text == "source"));
    assert!(matches!(fields["owner"], GraylogEventField::Lookup(_)));
    assert_eq!(block.grace_period.as_deref(), Some("30m"));
    assert_eq!(
        block.aggregation.unwrap().condition,
        "count() >= 3 OR card(parent_image_lc) >= 2"
    );
}

#[test]
fn a_dump_validates_again() {
    let node =
        fixture_block(&repo().join("tests/fixtures/graylog/rule-graylog-aggregation-1.0.yaml"));
    let block = convert(&node).0.unwrap();
    let text = serde_json::to_string(&block).unwrap();
    let again = convert(&yaml(&text)).0.unwrap();
    assert_eq!(again, block);
    // garde runs the same check on a block built in memory.
    let pins = opentide_schema::Pins::default();
    garde::Validate::validate_with(&block, &pins).unwrap();
    let mut broken = block;
    broken.priority = Some("high".into());
    let error = garde::Validate::validate_with(&broken, &pins).unwrap_err();
    assert!(error.to_string().contains("graylog_priority"), "{error}");
}

#[test]
fn invalid_fixtures_report_their_code() {
    let root = repo().join("tests/fixtures/graylog/invalid");
    for (name, code) in [
        ("rule-graylog-condition.yaml", "graylog_aggregation"),
        ("rule-graylog-event-field.yaml", "graylog_event_field"),
        ("rule-graylog-event-key.yaml", "graylog_event_key"),
        ("rule-graylog-schedule.yaml", "graylog_schedule"),
    ] {
        let found: BTreeSet<&str> = block_findings(&fixture_block(&root.join(name)))
            .into_iter()
            .map(|finding| finding.code)
            .collect();
        assert!(found.contains(code), "{name}: {found:?}");
    }
}

#[test]
fn list_fields() {
    let ok = |text: &str| list_ok(Some(&yaml(text)));
    assert!(ok("[]") && ok("x") && !ok("{a: 1}") && !ok("[a, 1]") && !ok("' '"));
    assert_eq!(
        graylog::as_list(Some(&StringOrList::One("sysmon".into()))),
        ["sysmon"]
    );
    assert!(graylog::as_list(None).is_empty());
}

#[test]
fn event_field_value_forms() {
    for (text, kind) in [
        ("source", Some("field")),
        ("winlog.event_data.User", Some("field")),
        ("'${source.User}@${source.Domain}'", Some("template")),
        ("{template: LOLBin}", Some("template")),
        (
            "{lookup: {table: owners, key_field: source}}",
            Some("lookup"),
        ),
        ("two words", None),
        ("{template: ''}", None),
        ("{lookup: {table: owners, key_field: ''}}", None),
        ("{template: a, lookup: {}}", None),
        ("3", None),
    ] {
        assert_eq!(event_field_kind(&yaml(text)), kind, "{text}");
    }
}

#[test]
fn a_block_without_status_is_left_to_the_field() {
    let node = yaml("query: ''\npriority: high\n");
    assert!(graylog::findings(&node).is_empty());
    assert!(!block_findings(&node).is_empty());
}

#[test]
fn condition_refusals() {
    let mut cases: Vec<String> = [
        "",
        "count() >= 3 or count() < 9",
        "total(bytes) > 1",
        "avg() > 1",
        "count(a, b) > 1",
        "percentile(bytes) > 1",
        "percentile(bytes, 101) > 1",
        "percentile(bytes, 0) > 1",
        "count() >= ",
        "(count() > 1",
        "count() = 1",
        "count() > 1 count() > 2",
        "count(src ip) > 1",
        "count() > 1.",
        "count() > x",
        "count() > 1 $",
        // Arguments are comma separated (graylog-1.1): no missing or trailing comma.
        "percentile(bytes 95) > 1",
        "count(x,) > 1",
        "percentile(bytes, 95,) > 1",
        "max(,a) > 1",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    cases.push(format!("{}count() > 1{}", "(".repeat(33), ")".repeat(33)));
    cases.push(format!("{}count() > 1", "NOT ".repeat(33)));
    for text in &cases {
        assert!(graylog::parse_condition(text).is_err(), "{text}");
    }
    // Refused, not a stack overflow.
    for text in [
        format!("{}count() > 1{}", "(".repeat(5000), ")".repeat(5000)),
        format!("{}count() > 1", "NOT ".repeat(50_000)),
    ] {
        let error = graylog::parse_condition(&text).unwrap_err();
        assert!(error.message.contains("nests deeper than 32"));
    }
}

#[test]
fn every_one_field_function() {
    for function in [
        "avg",
        "latest",
        "min",
        "percentage",
        "stddev",
        "sumofsquares",
        "variance",
    ] {
        let (_, series) =
            graylog::condition::compile_condition(&format!("{function}(bytes) > 1")).unwrap();
        assert_eq!(
            series,
            [
                serde_json::json!({"id": format!("{function}-bytes"), "type": function, "field": "bytes"})
            ]
        );
    }
}

#[test]
fn the_tenant_fixture_reads_into_the_configuration_model() {
    use opentide_schema::configuration::models::GraylogConfiguration;
    let text = std::fs::read_to_string(repo().join("tests/fixtures/graylog/tenant.toml")).unwrap();
    let merged = opentide_schema::configuration::toml::parse(&text).unwrap();
    let mut cx = Context::new();
    let configuration = GraylogConfiguration::from_node(&merged, &mut cx);
    // The fixture's `[platform]` carries the retired `identifier`,
    // `subschema` and `flags`: only the tenants are this test's.
    assert!(
        cx.into_errors()
            .iter()
            .all(|error| error.field_path()[0] == "platform")
    );
    let _ = configuration;
    let tenants = opentide_schema::configuration::toml::parse(&text)
        .unwrap()
        .get("tenants")
        .unwrap()
        .as_ref()
        .clone();
    let mut cx = Context::new();
    let tenants =
        Vec::<opentide_schema::configuration::models::GraylogTenant>::from_node(&tenants, &mut cx);
    assert_eq!(cx.into_errors(), []);
    let tenant = &tenants.unwrap()[0];
    let setup = &tenant.setup;
    assert_eq!(setup.url, "https://graylog.example.com");
    assert_eq!(setup.streams.items(), ["sysmon"]);
    assert_eq!(setup.tags.items(), ["managed-by-opentide"]);
    assert_eq!(
        setup.stream_ids["sysmon"].as_str(),
        "65f0c0ffee0123456789abcd"
    );
    assert_eq!(
        setup.notification_ids["soc-slack"].as_str(),
        "65f0c0ffee0123456789abcf"
    );
    assert!(!setup.allow_leading_wildcard);
}

#[test]
fn a_tenant_id_is_24_lower_case_hex() {
    use opentide_schema::configuration::models::GraylogSetup;
    let setup = |extra: &str| {
        let text = format!("url = \"https://g\"\ntoken = \"$T\"\n{extra}");
        let node = opentide_schema::configuration::toml::parse(&text).unwrap();
        let mut cx = Context::new();
        let value = GraylogSetup::from_node(&node, &mut cx);
        (value, cx.into_errors())
    };
    let (value, errors) = setup("");
    assert_eq!(errors, []);
    let value = value.unwrap();
    assert!(value.streams.items().is_empty() && value.stream_ids.is_empty());
    let (_, errors) = setup("[stream_ids]\nsysmon = \"65F0C0FFEE0123456789ABCD\"\n");
    assert_eq!(errors[0].field_path(), ["stream_ids", "sysmon"]);
    let (_, errors) = setup("streams = [\" \"]\n");
    assert!(!errors.is_empty());
    let (_, errors) = setup("token = \"literal\"\n".replace("token", "x").as_str());
    assert!(!errors.is_empty());
}

// --- advisories (test_graylog_advisories.py) ------------------------------------

use opentide_schema::objects::platform::graylog::{
    TenantView, advisories, leading_wildcard_allowed,
};

fn tenant(name: &str, has_streams: bool, allow_leading_wildcard: bool) -> TenantView<'_> {
    TenantView {
        name,
        has_streams,
        allow_leading_wildcard,
    }
}

fn rule(extra: &str) -> Node {
    let extra: String = extra
        .lines()
        .flat_map(|line| ["    ", line, "\n"])
        .collect();
    yaml(&format!(
        "name: Encoded PowerShell\nconfigurations:\n  graylog:\n    enabled: true\n    \
         status: STAGING\n    query: EventID:1\n{extra}"
    ))
}

fn advisory_codes(extra: &str, tenants: &[TenantView<'_>]) -> Vec<&'static str> {
    advisories(&rule(extra), tenants)
        .into_iter()
        .map(|advisory| advisory.code)
        .collect()
}

#[test]
fn overlapping_window() {
    let prod = [tenant("prod", true, false)];
    for (extra, expected) in [
        (
            "schedule: {every: 5m, window: 15m}",
            &["graylog_overlapping_window"][..],
        ),
        ("schedule: {window: 10m}", &["graylog_overlapping_window"]),
        ("schedule: {every: 15m, window: 15m}", &[]),
        ("schedule: {every: 15m, window: 5m}", &[]),
        (
            "schedule: {every: 5m, window: 15m}\naggregation: {condition: count() > 1}",
            &[],
        ),
        ("schedule: {cron: '0 0 * * * ?', window: 2h}", &[]),
        ("schedule: {every: bad, window: 15m}", &[]),
    ] {
        assert_eq!(advisory_codes(extra, &prod), expected, "{extra}");
    }
    let found = advisories(&rule("schedule: {window: 10m}"), &prod);
    assert_eq!(
        found[0].field_path,
        ["configurations", "graylog", "schedule"]
    );
    assert_eq!(
        found[0].message,
        "the window (10m) is longer than the interval (5m): on a filter, each message alerts \
         once per overlapping run"
    );
}

#[test]
fn all_streams() {
    let prod = tenant("prod", true, false);
    let bare = tenant("prod", false, false);
    let lab = tenant("lab", false, false);
    let cases: Vec<(&str, Vec<TenantView<'_>>, &[&str])> = vec![
        ("", vec![prod.clone()], &[]),
        ("", vec![bare.clone()], &["graylog_all_streams"]),
        (
            "",
            vec![prod.clone(), lab.clone()],
            &["graylog_all_streams"],
        ),
        ("", vec![], &[]),
        ("streams: sysmon", vec![bare.clone()], &[]),
        ("stream_categories: [edr]", vec![bare.clone()], &[]),
        ("tenants: [prod]", vec![prod.clone(), lab.clone()], &[]),
        ("streams: [a, a]", vec![bare.clone()], &[]),
    ];
    for (extra, tenants, expected) in cases {
        assert_eq!(advisory_codes(extra, &tenants), expected, "{extra}");
    }
    let found = advisories(&rule(""), &[lab]);
    assert_eq!(found[0].field_path, ["configurations", "graylog"]);
    assert_eq!(
        found[0].message,
        "the block sets no streams or stream_categories, and tenant(s) lab set no streams \
         either: the definition searches every stream the token's user can read"
    );
}

#[test]
fn a_rule_without_a_graylog_block_has_none() {
    assert!(advisories(&yaml("configurations: {splunk: {}}"), &[]).is_empty());
    assert!(advisories(&yaml("{}"), &[]).is_empty());
}

#[test]
fn leading_wildcard_allowed_on_every_targeted_tenant() {
    let allowed = tenant("prod", true, true);
    let lab = tenant("lab", true, false);
    let block = |extra: &str| yaml(&format!("status: STAGING\n{extra}"));
    assert!(!leading_wildcard_allowed(&block(""), &[]));
    assert!(leading_wildcard_allowed(
        &block(""),
        std::slice::from_ref(&allowed)
    ));
    assert!(!leading_wildcard_allowed(
        &block(""),
        &[allowed.clone(), lab.clone()]
    ));
    assert!(leading_wildcard_allowed(
        &block("tenants: [prod]"),
        &[allowed, lab]
    ));
}

#[test]
fn one_definition_title_per_enabled_block() {
    use opentide_schema::objects::platform::graylog::{
        definition_title, title_duplicate_message, title_duplicates,
    };
    let rule_with = |name: &str, block: &str| {
        yaml(&format!(
            "name: {name}\nconfigurations:\n  graylog:\n    status: STAGING\n    \
             query: EventID:1\n{block}"
        ))
    };
    let a = rule_with("Encoded PowerShell", "    enabled: true\n");
    let b = rule_with("Encoded PowerShell", "    enabled: true\n");
    let c = rule_with(
        "Own title",
        "    enabled: true\n    name: Encoded PowerShell\n",
    );
    let off = rule_with("Encoded PowerShell", "    enabled: false\n");
    assert_eq!(definition_title(&a), Some("Encoded PowerShell"));
    assert_eq!(definition_title(&c), Some("Encoded PowerShell"));
    assert_eq!(definition_title(&off), None);
    assert_eq!(definition_title(&yaml("name: x")), None);
    let rules: Vec<(&str, &Node)> = vec![("a", &a), ("b", &b), ("c", &c), ("d", &off)];
    assert_eq!(
        title_duplicates("a", "Encoded PowerShell", &rules),
        ["b", "c"]
    );
    assert!(title_duplicates("d", "Encoded PowerShell", &rules).contains(&"a"));
    let (message, suggestion) = title_duplicate_message("Encoded PowerShell", &["b", "c"]);
    assert_eq!(
        message,
        "Graylog event definition title \"Encoded PowerShell\" is also the title of rule(s) b, c; \
         Graylog's alert list cannot tell them apart"
    );
    assert_eq!(
        suggestion,
        "Set a distinct configurations.graylog.name on one of the rules"
    );
}
