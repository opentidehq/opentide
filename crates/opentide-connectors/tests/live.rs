//! Live parity on a test tenant (UC-4.2, #832): a maintainer's step, never
//! run in CI (`#[ignore]`). Each test reads a test tenant's `setup` table from
//! the TOML file `OPENTIDE_LIVE_<PLATFORM>` names (the keys of
//! `[tenants.setup]` in `configurations/platforms/<platform>.toml`, `$NAME`
//! credentials read from the environment) and skips when it is unset. It
//! deploys the cassettes' test rule, checks and runs a query, disables the
//! rule and deletes it, and prints what the tenant answered, to set beside
//! the Python CLI's run on the same tenant. **Test tenants only, never
//! production.**
//!
//! ```text
//! OPENTIDE_LIVE_DEFENDER_FOR_ENDPOINT=defender.toml \
//! OPENTIDE_LIVE_ELASTIC=elastic.toml OPENTIDE_LIVE_SENTINEL_ONE=s1.toml \
//!   cargo test -p opentide-connectors --test live -- --ignored --nocapture
//! ```

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use opentide_compile::json::Json;
use opentide_connectors::connector::TenantContext;
use opentide_connectors::connector::{QueryRequest, TimeWindow};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::defender::{self, Defender};
use opentide_connectors::elastic::{self, Elastic, ElasticRule, Strategy};
use opentide_connectors::runtime::block_on;
use opentide_connectors::sentinel_one::{self, SentinelOne};
use opentide_connectors::{Environment, HttpClient, HttpSettings, Tenant};
use tokio_util::sync::CancellationToken;

/// The test tenant of *platform*, or `None` when its variable is unset.
fn tenant(platform: &str, settings: &HttpSettings) -> Option<(Tenant, HttpClient, toml::Table)> {
    let variable = format!("OPENTIDE_LIVE_{}", platform.to_uppercase());
    let Ok(path) = std::env::var(&variable) else {
        println!("{variable} is unset: skipped");
        return None;
    };
    let setup: toml::Table = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let env = Environment::process();
    let tenant =
        Tenant::from_setup(platform, "live", &setup, &env, Resolve::Required, settings).unwrap();
    let http = HttpClient::new(&tenant.label, &tenant.http, &env, None).unwrap();
    Some((tenant, http, setup))
}

fn last_hour() -> TimeWindow {
    let now = jiff::Timestamp::now();
    TimeWindow {
        start: now
            .checked_sub(jiff::SignedDuration::from_hours(1))
            .unwrap(),
        end: now,
    }
}

#[test]
#[ignore = "reaches a live test tenant: OPENTIDE_LIVE_DEFENDER_FOR_ENDPOINT"]
fn live_defender_deploy_validate_query_disable() {
    let Some((tenant, http, _)) = tenant(defender::PLATFORM, &defender::http_settings()) else {
        return;
    };
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let inputs = support::fixture("defender");
    let rule = inputs.get("deploy").unwrap().get("rule").unwrap().clone();
    let connector = Defender::new();
    block_on(async {
        let created = connector.create_rule(cx, &rule).await.unwrap();
        println!("created {created:?}");
        let id = created.id.to_string();
        let query = "DeviceProcessEvents | project Timestamp, DeviceId, ReportId";
        let now = jiff::Timestamp::now();
        let check = connector
            .check(
                cx,
                &QueryRequest::new(query, "kql", TimeWindow::check(now)),
                now,
            )
            .await;
        println!("check {check:?}");
        let rows = connector
            .run(cx, &QueryRequest::new(query, "kql", last_hour()), now)
            .await;
        println!("query {rows:?}");
        let mut disabled = rule.clone();
        if let Json::Object(top) = &mut disabled {
            top.insert("isEnabled".into(), Json::Bool(false));
        }
        connector.update_rule(cx, &disabled, &id).await.unwrap();
        println!("disabled {id}");
        connector.delete_rule(cx, &id).await.unwrap();
        println!("deleted {id}");
    })
    .unwrap();
}

#[test]
#[ignore = "reaches a live test tenant: OPENTIDE_LIVE_ELASTIC"]
fn live_elastic_deploy_validate_query_disable() {
    let settings = elastic::http_settings(std::time::Duration::from_secs(30));
    let Some((tenant, http, setup)) = tenant(elastic::PLATFORM, &settings) else {
        return;
    };
    let index: Vec<String> = setup
        .get("index")
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let inputs = support::fixture("elastic");
    let raw = &support::items(inputs.get("deploy").unwrap())[0];
    let mut rule = ElasticRule {
        rule_id: support::text(raw.get("rule_id").unwrap()).to_owned(),
        name: support::text(raw.get("name").unwrap()).to_owned(),
        strategy: Strategy::Active,
        block: raw.get("block").unwrap().clone(),
        payload: raw.get("payload").unwrap().clone(),
    };
    block_on(async {
        println!("deploy {:?}", Elastic.deploy_rule(cx, &rule, &index).await);
        let now = jiff::Timestamp::now();
        println!(
            "validate {:?}",
            Elastic.validate_rule(cx, &rule, &index, now).await
        );
        for (language, text) in [
            ("esql", "FROM logs-* | LIMIT 5"),
            ("lucene", "*"),
            ("eql", "any where true"),
            ("kuery", "*"),
        ] {
            let mut request = QueryRequest::new(text, language, last_hour());
            request.limit = 5;
            println!("{language} {:?}", Elastic.run(cx, &request, &index).await);
        }
        rule.strategy = Strategy::Disablement;
        println!("disable {:?}", Elastic.deploy_rule(cx, &rule, &index).await);
        rule.strategy = Strategy::Deletion;
        println!("delete {:?}", Elastic.deploy_rule(cx, &rule, &index).await);
    })
    .unwrap();
}

#[test]
#[ignore = "reaches a live test tenant: OPENTIDE_LIVE_SENTINEL_ONE"]
fn live_sentinel_one_deploy_validate_query_disable() {
    let Some((tenant, http, _)) = tenant(sentinel_one::PLATFORM, &sentinel_one::http_settings())
    else {
        return;
    };
    let cancel = CancellationToken::new();
    let cx = TenantContext {
        tenant: &tenant,
        http: &http,
        cancel: &cancel,
    };
    let inputs = support::fixture("sentinel_one");
    let rules = support::items(inputs.get("deploy").unwrap().get("rules").unwrap());
    let mut rule = rules[1].clone();
    // The fixture's site; the test tenant's own account or site instead.
    if let Json::Object(top) = &mut rule {
        let mut filter = opentide_compile::json::Object::new();
        let account = tenant.secret("account_id").unwrap().expose().to_owned();
        filter.insert("accountIds".into(), Json::Array(vec![Json::Str(account)]));
        top.insert("filter".into(), Json::Object(filter));
    }
    block_on(async {
        let id = SentinelOne
            .create_update_rule(cx, &rule, None)
            .await
            .unwrap();
        println!("created {id}");
        let query = "src.process.name = 'cmd.exe'";
        let now = jiff::Timestamp::now();
        println!(
            "validate_query {:?}",
            SentinelOne.validate_query(cx, query, now).await
        );
        let check = SentinelOne
            .check(
                cx,
                &QueryRequest::new(query, "powerquery", TimeWindow::check(now)),
            )
            .await;
        println!("check {check:?}");
        println!(
            "query {:?}",
            SentinelOne
                .run(cx, &QueryRequest::new(query, "powerquery", last_hour()))
                .await
        );
        SentinelOne.disable_rule(cx, id).await.unwrap();
        println!("disabled {id}");
        SentinelOne.delete_rule(cx, id).await.unwrap();
        println!("deleted {id}");
    })
    .unwrap();
}
