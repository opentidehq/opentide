use indexmap::IndexMap;

use super::super::facts::StatusDefinition;
use super::super::platforms::KQL;
use super::super::settings::{CodeSetting, Setting, SettingTable};
use super::*;
use StatusStrategy::{Deletion, Disablement, Preview, Release};

fn definition(name: &str, strategy: StatusStrategy) -> StatusDefinition {
    StatusDefinition {
        name: name.to_owned(),
        description: format!("{name}  meaning\nwrapped"),
        strategy,
    }
}

fn deployment(status: &str, strategy: Option<StatusStrategy>) -> PlatformDeployment {
    let runs = strategy
        .map(|strategy| {
            crate::strategy::DEPLOYABLE
                .into_iter()
                .filter(|run| crate::strategy::deploys(strategy, *run))
                .collect()
        })
        .unwrap_or_default();
    PlatformDeployment {
        platform: "sentinel".to_owned(),
        label: "Microsoft Sentinel".to_owned(),
        enabled: true,
        status: status.to_owned(),
        definition: strategy.map(|strategy| definition(status, strategy)),
        runs,
        scope: TenantScope::All,
        targets: Vec::new(),
        unknown_tenants: Vec::new(),
        platform_enabled: Some(true),
        orphaned_ids: IndexMap::new(),
    }
}

fn target(name: &str, runs: &[StatusStrategy], accepts: &[StatusStrategy]) -> TenantTarget {
    TenantTarget {
        name: name.to_owned(),
        runs: runs.to_vec(),
        accepts: accepts.to_vec(),
        ..TenantTarget::default()
    }
}

#[test]
fn runs_say_what_deploys_a_block_and_what_it_does() {
    assert_eq!(runs_text(&deployment("S", Some(Preview))), "PREVIEW runs");
    assert_eq!(
        runs_text(&deployment("U", Some(StatusStrategy::Universal))),
        "PREVIEW and RELEASE runs"
    );
    assert_eq!(
        runs_text(&deployment("D", Some(Disablement))),
        "RELEASE runs, which disable it"
    );
    assert_eq!(
        runs_text(&deployment("X", Some(Deletion))),
        "RELEASE runs, which delete it"
    );
    assert_eq!(
        runs_text(&deployment("I", Some(StatusStrategy::Inert))),
        "never deployed"
    );
    assert_eq!(runs_text(&deployment("?", None)), "unknown status");
    let mut off = deployment("S", Some(Preview));
    off.platform_enabled = Some(false);
    assert_eq!(runs_text(&off), "never deployed: platform not enabled");
}

#[test]
fn tenants_name_who_a_block_reaches() {
    let mut found = deployment("S", Some(Preview));
    found.targets = vec![
        target("a", &[Preview], &[Preview]),
        target("b", &[], &[Release]),
    ];
    assert_eq!(tenants_text(&found), "`a`");
    found.scope = TenantScope::Listed;
    assert_eq!(tenants_text(&found), "listed: `a`");
    found.targets = vec![target("b", &[], &[Release])];
    assert_eq!(tenants_text(&found), "listed: `b`");
    found.scope = TenantScope::All;
    assert_eq!(tenants_text(&found), "none");
    found.scope = TenantScope::None;
    assert_eq!(tenants_text(&found), "no tenant configured");
    found.scope = TenantScope::Unknown;
    assert_eq!(
        tenants_text(&found),
        "every tenant that is not manual (not configured here)"
    );
}

#[test]
fn a_tenant_row_says_why_no_run_reaches_it() {
    let mut found = deployment("S", Some(Preview));
    let reached =
        |found: &PlatformDeployment, target: &TenantTarget| tenant_row(found, target)[2].clone();
    assert_eq!(
        reached(&found, &target("a", &[Preview], &[Preview, Release])),
        "PREVIEW runs"
    );
    assert_eq!(
        reached(&found, &target("b", &[], &[Release])),
        "no run: the tenant takes RELEASE runs only"
    );
    assert_eq!(
        reached(&found, &target("c", &[], &[])),
        "no run: the tenant takes none of the rule's runs"
    );
    found.runs.clear();
    assert_eq!(
        reached(&found, &target("d", &[], &[Release])),
        "no run: no run deploys this status"
    );
    found.platform_enabled = Some(false);
    assert_eq!(
        reached(&found, &target("e", &[], &[Release])),
        "no run: the platform is not enabled"
    );
    let mut described = target("f", &[], &[]);
    described.description = "Lab | EU".to_owned();
    described.remote_id = "42".to_owned();
    let row = tenant_row(&found, &described);
    assert_eq!(row[1], "`f`<br>Lab \\| EU");
    assert_eq!(row[3], "`42`");
    assert_eq!(tenant_row(&found, &target("g", &[], &[]))[3], "-");
}

#[test]
fn the_deployment_section_warns_of_what_keeps_a_block_from_deploying() {
    assert_eq!(
        deployment_body(Flavor::Github, &[]),
        "> [!NOTE]\n> This rule has no platform configuration: no run deploys it anywhere.\n\n"
    );
    let mut off = deployment("STAGING", Some(Preview));
    off.platform_enabled = Some(false);
    off.runs.clear();
    let unknown = deployment("DRAFT", None);
    let mut no_tenant = deployment("STAGING", Some(Preview));
    no_tenant.scope = TenantScope::None;
    let mut missing = deployment("PROD", Some(Release));
    missing.scope = TenantScope::Listed;
    missing.unknown_tenants = vec!["ghost".to_owned(), "x".to_owned()];
    missing.enabled = false;
    let body = deployment_body(Flavor::Generic, &[off, unknown, no_tenant, missing]);
    assert!(
        body.starts_with("What `opentide deploy` does with this rule"),
        "{body}"
    );
    assert!(
        body.contains("| Microsoft Sentinel | `PROD` | RELEASE runs | listed: none | no |\n")
            || body.contains("| Microsoft Sentinel | `PROD` | RELEASE runs | none | no |\n"),
        "{body}"
    );
    // Each status is explained once, its description on one line.
    assert_eq!(
        body.matches("- `STAGING` (strategy `PREVIEW`): STAGING meaning wrapped")
            .count(),
        1,
        "{body}"
    );
    assert!(body.contains("- `PROD` (strategy `RELEASE`): PROD meaning wrapped"));
    assert!(body.contains(
        "> **Warning:** Microsoft Sentinel is not enabled in this workspace: no run deploys \
         this block."
    ));
    assert!(body.contains(
        "> **Warning:** Microsoft Sentinel: status `DRAFT` is not defined in `deployment.toml`, \
         so no run deploys this block."
    ));
    assert!(body.contains(
        "> **Warning:** Microsoft Sentinel configures no tenant: a run that deploys this block \
         fails until one is added to the platform file."
    ));
    assert!(body.contains("> **Warning:** Microsoft Sentinel has no tenant named `ghost`, `x`."));
}

#[test]
fn tenant_targeting_lists_targets_and_ids_left_behind() {
    assert_eq!(tenants_body(&[deployment("S", Some(Preview))]), "");
    let mut found = deployment("S", Some(Preview));
    found.targets = vec![target("a", &[Preview], &[Preview])];
    found.orphaned_ids.insert("old".to_owned(), "7".to_owned());
    assert_eq!(
        tenants_body(&[found]),
        "| Platform | Tenant | Reached by | Remote ID |\n| --- | --- | --- | --- |\n\
         | Microsoft Sentinel | `a` | PREVIEW runs | - |\n\
         | Microsoft Sentinel | `old` | not targeted | `7` |\n"
    );
}

fn json(text: &str) -> Json {
    serde_json::from_str(text).unwrap()
}

#[test]
fn a_blocks_summary_line() {
    let block = json(r#"{"enabled": false, "status": "S", "schema": "platform::sentinel::1.0"}"#);
    let mut found = deployment("S", Some(Preview));
    found.targets = vec![target("a", &[Preview], &[Preview])];
    assert_eq!(
        block_summary(&block, Some(&found)),
        "Status `S` · deployed by PREVIEW runs · tenants: `a` · schema \
         `platform::sentinel::1.0` · block disabled\n\n"
    );
    let block = json(r#"{"enabled": true, "status": "D"}"#);
    assert_eq!(
        block_summary(&block, Some(&deployment("D", None))),
        "Status `D` · unknown status · tenants: none\n\n"
    );
    assert_eq!(block_summary(&block, None), "Status `D`\n\n");
}

#[test]
fn settings_put_code_first_then_rows_then_tables() {
    assert_eq!(
        settings_body(&BlockSettings::default()),
        "The block sets nothing beyond its deployment status.\n\n"
    );
    let settings = BlockSettings {
        rows: vec![
            Setting {
                path: "name".into(),
                value: "Rule a".into(),
                description: "The | name.".into(),
                default: false,
            },
            Setting {
                path: "alert.create".into(),
                value: "`true`".into(),
                description: String::new(),
                default: true,
            },
        ],
        code: vec![
            CodeSetting {
                path: "query".into(),
                code: "T | take 1".into(),
                language: Some(KQL),
                description: "KQL.".into(),
            },
            CodeSetting {
                path: "guide".into(),
                code: "line\nline".into(),
                language: None,
                description: "Investigation guide.".into(),
            },
        ],
        tables: vec![SettingTable {
            path: "entities[0].mappings".into(),
            columns: vec!["identifier".into(), "column".into()],
            rows: vec![vec!["`Name`".into(), "-".into()]],
            description: "Mappings.".into(),
        }],
    };
    assert_eq!(
        settings_body(&settings),
        "**`query`** (KQL)\n\n```kql\nT | take 1\n```\n\n\
         **`guide`** (Text): Investigation guide.\n\n```text\nline\nline\n```\n\n\
         | Setting | Value | Description |\n| --- | --- | --- |\n\
         | `name` | Rule a | The \\| name. |\n\
         | `alert.create` | `true` *(default)* |  |\n\n\
         **`entities[0].mappings`**: Mappings.\n\n\
         | `identifier` | `column` |\n| --- | --- |\n| `Name` | - |"
    );
}

#[test]
fn a_platform_section_is_named_by_its_label() {
    let block = json(r#"{"enabled": true, "status": "S", "name": "Rule name"}"#);
    let section = platform_section("sentinel", &block, None, None);
    assert_eq!(section.title, "Microsoft Sentinel");
    assert!(
        section.body.starts_with("Status `S`\n\n| Setting |"),
        "{}",
        section.body
    );
    assert!(
        section
            .body
            .contains("| `name` | Rule name *(default)* | Platform-specific rule name. |"),
        "{}",
        section.body
    );
}

#[test]
fn detectors_and_examples() {
    assert_eq!(detectors_body(&[]), "");
    assert_eq!(examples_body(&[]), "");
    let detectors: Vec<opentide_schema::objects::ExternalDetector> = serde_json::from_str(
        r#"[{"name": "V", "technology": "EDR", "description": "d", "link": "https://v"},
            {"name": "W", "technology": "SIEM", "description": "e"}]"#,
    )
    .unwrap();
    assert_eq!(
        detectors_body(&detectors),
        "**Existing detectors**\n\n| Detector | Technology | Description | Link |\n\
         | --- | --- | --- | --- |\n| V | EDR | d | [Reference](https://v) |\n| W | SIEM | e | - |"
    );
    let examples: Vec<opentide_schema::objects::DetectionExample> = serde_json::from_str(
        r#"[{"description": "An\n example", "link": "https://e", "language": "kql", "query": "T\n"},
            {"description": "B", "link": "https://f", "query": "x"},
            {"description": "C", "link": "https://g"}]"#,
    )
    .unwrap();
    assert_eq!(
        examples_body(&examples),
        "**Examples**\n\n1. An example ([source](https://e))\n\n```kql\nT\n```\n\n\
         2. B ([source](https://f))\n\n```text\nx\n```\n\n3. C ([source](https://g))"
    );
}

#[test]
fn small_helpers() {
    assert!(covers_technique("T1003", "T1003"));
    assert!(covers_technique("T1003.001", "T1003"));
    assert!(!covers_technique("T10030", "T1003"));
    assert_eq!(codes(&[]), "-");
    assert_eq!(codes(&["T1".to_owned(), "T2".to_owned()]), "`T1`, `T2`");
    assert_eq!(or_dash(String::new(), "*None*"), "*None*");
    assert_eq!(prose("  "), "");
    assert_eq!(reference_value("https://x"), "[https://x](https://x)");
    assert_eq!(reference_value("a | b"), "a \\| b");
    let entry = Enriched {
        key: "k".into(),
        label: String::new(),
        link: "ftp://x".into(),
        ..Enriched::default()
    };
    assert_eq!(entry_link(&entry, "fallback", None), "fallback");
    let linked = Enriched {
        label: "L".into(),
        link: "https://l".into(),
        ..entry
    };
    assert_eq!(entry_link(&linked, "f", Some("`T`")), "[`T`](https://l)");
    assert_eq!(
        unique(&["a".to_owned(), "b".to_owned(), "a".to_owned()]),
        [&"a".to_owned(), &"b".to_owned()]
    );
    assert_eq!(killchain_phases(None), Vec::<String>::new());
}

#[test]
fn percentages_round_half_to_even_as_python_does() {
    assert_eq!(percent(1, 2), "50");
    assert_eq!(percent(1, 8), "12");
    assert_eq!(percent(3, 8), "38");
    assert_eq!(percent(5, 8), "62");
    assert_eq!(percent(1, 3), "33");
    assert_eq!(percent(2, 3), "67");
    assert_eq!(percent(0, 0), "0");
}

#[test]
fn statuses_take_their_strategys_colour_deeper_later() {
    let definitions = [
        definition("DRAFT", StatusStrategy::Inert),
        definition("TESTING", Preview),
        definition("STAGING", Preview),
        definition("PRODUCTION", Release),
        definition("REMOVED", Deletion),
    ];
    let colours = status_colours(&definitions);
    let colour = |name: &str| {
        colours
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, colour)| *colour)
    };
    assert_eq!(colour("DRAFT"), Some("#667085"));
    assert_eq!(colour("TESTING"), Some("#fdb022"));
    assert_eq!(colour("STAGING"), Some("#f79009"));
    assert_eq!(colour("PRODUCTION"), Some("#039855"));
    assert_eq!(colour("REMOVED"), Some("#b42318"));
    assert_eq!(colour("ELSE"), None);
    // More statuses than shades: the last ones share the deepest.
    let many: Vec<StatusDefinition> = (0..6)
        .map(|index| definition(&format!("S{index}"), StatusStrategy::Universal))
        .collect();
    let colours = status_colours(&many);
    assert_eq!(colours[0].1, "#84caff");
    assert_eq!(colours[5].1, "#2e90fa");
}
