//! The dry run's Elastic entry (`preview_on`): the deploy body compiled for
//! the first tenant the run sends the rule to, as `opentide deploy` compiles
//! it, so a tenant's `tags`, `index` and `suppression = false` are in it.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

use std::path::PathBuf;
use std::sync::Arc;

use opentide_compile::{Json, Owned, Rule, deploy, elastic, preview};
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
/// index), then `full`.
const PLATFORM: &str = "[platform]\nenabled = true\n\n[[tenants]]\nname = \"basic\"\nstrategies \
     = [\"PREVIEW\"]\n[tenants.setup]\nurl = \"https://kibana.invalid\"\ntags = [\"soc\"]\nindex \
     = [\"winlogbeat-*\"]\nsuppression = false\n\n[[tenants]]\nname = \"full\"\nstrategies = \
     [\"PREVIEW\"]\n[tenants.setup]\nurl = \"https://kibana-full.invalid\"\n";

fn workspace() -> Workspace {
    let fs = Arc::new(MemoryFs::new());
    fs.create_dir("/ws/.opentide/configurations/platforms");
    fs.create_dir("/ws/objects/rules");
    fs.write("/ws/objects/rules/r.yaml", RULE.to_owned());
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
    // The body `opentide deploy` sends to `basic`, byte for byte.
    let table = deploy::tenant(&cx, "elastic", "basic").unwrap();
    let sent = preview::elastic_request(
        &rule,
        elastic::compile(&cx, &rule, &elastic::Setup::from_tenant(table)).unwrap(),
    );
    assert_eq!(shown.to_compact(), sent.to_compact());
    // And the tenant's setup is in it.
    let payload = shown.get("payload").unwrap();
    let tags = payload.get("tags").unwrap().to_compact();
    assert!(tags.contains("\"soc\""), "{tags}");
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
}
