//! Elastic Security against the cassettes recorded from the Python client
//! (`tests/cassettes/elastic/`, `cargo xtask cassettes record
//! elastic/<scenario>`): every request the connector sends must be the
//! Python client's, in order (a JSON body as the same data), the retries of a gateway's
//! answer included.

#![expect(clippy::unwrap_used, reason = "a test: a failed set-up is a failure")]

mod support;

use opentide_compile::json::Json;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::QueryRequest;
use opentide_connectors::elastic::{self, Deployed, Elastic, ElasticError, ElasticRule, Strategy};
use opentide_connectors::runtime::block_on;
use support::{Replayed, fixture, items, text, timestamp, window};

const SETUP: &str = r#"
ssl = true
url = "https://kibana.elastic.invalid"
elasticsearch_url = "https://es.elastic.invalid"
api_key = "$ELASTIC_API_KEY"
space = "soc"
index = ["logs-*", "winlogbeat-*"]
"#;

fn setup_index() -> Vec<String> {
    vec!["logs-*".into(), "winlogbeat-*".into()]
}

fn replay(scenario: &str) -> Replayed {
    Replayed::start(
        scenario,
        elastic::PLATFORM,
        SETUP,
        "ELASTIC_API_KEY",
        &elastic::http_settings(std::time::Duration::from_secs(30)),
    )
}

fn rules(key: &str) -> Vec<ElasticRule> {
    let inputs = fixture("elastic");
    items(inputs.get(key).unwrap())
        .iter()
        .map(|rule| ElasticRule {
            rule_id: text(rule.get("rule_id").unwrap()).to_owned(),
            name: text(rule.get("name").unwrap()).to_owned(),
            strategy: match text(rule.get("status").unwrap()) {
                "REMOVED" => Strategy::Deletion,
                "DISABLED" => Strategy::Disablement,
                _ => Strategy::Active,
            },
            block: rule.get("block").unwrap().clone(),
            payload: rule.get("payload").unwrap().clone(),
        })
        .collect()
}

fn summary(deployed: &Deployed) -> String {
    match deployed {
        Deployed::Failed {
            event,
            status,
            error,
        } => {
            format!("{event} {status:?}: {error}")
        }
        other => format!("{other:?}"),
    }
}

#[test]
fn elastic_deploy_sends_what_the_python_deployer_sent() {
    let tenant = replay("elastic/deploy");
    let seen = block_on(async {
        let mut seen = Vec::new();
        for rule in rules("deploy") {
            match Elastic
                .deploy_rule(tenant.cx(), &rule, &setup_index())
                .await
            {
                Ok(outcome) => seen.push(format!(
                    "{} {}{}",
                    &rule.rule_id[34..],
                    summary(&outcome.deployed),
                    if outcome.warnings.is_empty() {
                        String::new()
                    } else {
                        format!(" {:?}", outcome.warnings)
                    }
                )),
                // The tenant refuses the key: the rest of the batch is not sent.
                Err(ElasticError::Tenant(error)) => {
                    seen.push(format!("{} tenant: {error}", &rule.rule_id[34..]));
                    break;
                }
                Err(other) => panic!("{other:?}"),
            }
        }
        seen
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        seen,
        [
            "01 Created",
            "02 Updated",
            "03 Recreated",
            "04 refusing_to_modify_prebuilt_rule None: refusing to modify prebuilt rule",
            "05 Deleted",
            "06 Created",
            "07 Created",
            "08 Created",
            "09 elasticsearch_checks_failed None: Data view 'dv-missing' lookup failed (HTTP 404)",
            "0a tenant: Tenant replayed auth error: HTTP 401",
        ]
    );
}

#[test]
fn elastic_a_single_byte_off_fails() {
    let mut rule = rules("deploy").remove(0);
    if let Json::Object(payload) = &mut rule.payload {
        payload.insert("risk_score".into(), Json::Int(74));
    }
    let tenant = replay("elastic/deploy");
    let _ = block_on(async {
        Elastic
            .deploy_rule(tenant.cx(), &rule, &setup_index())
            .await
    });
    let mismatches = tenant.verify();
    // The lookup is the recorded one; the create's body is not.
    assert_eq!(mismatches[0].index, 1, "{mismatches:?}");
    assert!(mismatches[0].detail.starts_with("bodies differ at byte "));
}

#[test]
fn elastic_query_sends_what_the_python_runner_sent() {
    let inputs = fixture("elastic");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("elastic/query");
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "", window);
            request.limit = match item.get("limit") {
                Some(Json::Int(limit)) => usize::try_from(*limit).unwrap(),
                _ => 100,
            };
            request.language = item
                .get("language")
                .map(|l| text(l).to_owned())
                .unwrap_or_default();
            request.index = item
                .get("index")
                .map(|index| items(index).iter().map(|i| text(i).to_owned()).collect())
                .unwrap_or_default();
            request.data_view = item.get("data_view").map(|v| text(v).to_owned());
            outcomes.push(Elastic.run(tenant.cx(), &request, &setup_index()).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    let rows = |at: usize| {
        let result = outcomes[at].as_ref().unwrap();
        (
            serde_json::to_string(&result.rows).unwrap(),
            result.truncated,
            result.language.clone().unwrap_or_default(),
        )
    };
    assert_eq!(
        rows(0),
        (
            r#"[{"host.name":"ws-1","user.name":"alice"}]"#.into(),
            true,
            "esql".into()
        )
    );
    assert_eq!(
        rows(2),
        (
            r#"[{"_index":"logs-1","process.name":"cmd.exe","tags":["a"]},{"_index":"logs-2","process.name":"cmd.exe","host":{}}]"#.into(),
            false,
            "lucene".into()
        )
    );
    assert_eq!(
        rows(3),
        (
            r#"[{"_sequence":1,"_index":"logs-1","process.name":"cmd.exe"},{"_sequence":1,"_index":"logs-1","process.name":"whoami.exe"}]"#.into(),
            false,
            "eql".into()
        )
    );
    assert_eq!(
        rows(4),
        (
            r#"[{"_index":".internal.preview.alerts-security.alerts-soc","@timestamp":"2026-10-27T07:58:00.000Z","process.name":"powershell.exe","process.pid":4242}]"#.into(),
            false,
            "kuery".into()
        )
    );
    assert_eq!(
        outcomes[4].as_ref().unwrap().vendor_query_id.as_deref(),
        Some("p-1")
    );
    assert_eq!(rows(5).2, "kuery");
    // The data view's title is the index; seven hits, one row asked for.
    assert!(rows(6).1);
    let refusals: Vec<String> = [1, 7, 8]
        .iter()
        .map(|&at| match &outcomes[at] {
            Err(refused @ ConnectorError::Refused { .. }) => refused.text(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(
        refusals,
        [
            "Elastic refused the ES|QL query on replayed (HTTP 400): Unknown index [nope]",
            "Elastic did not answer the Lucene query on replayed with JSON: HTTP 504 with an HTML \
             page titled \"Gateway Timeout\": HTTP 504 Gateway Timeout is what a gateway or proxy \
             in front of the tenant answers when the tenant does not answer it in time, so the \
             url and port are not at fault when other requests to the same address succeed",
            "Kibana refused the KQL query on replayed: Expected AND but found ':'",
        ]
    );
}

#[test]
fn elastic_validate_checks_and_previews_each_rule() {
    let inputs = fixture("elastic");
    let now = timestamp(inputs.get("now").unwrap());
    let tenant = replay("elastic/validate");
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for rule in rules("validate") {
            outcomes.push(
                match Elastic
                    .validate_rule(tenant.cx(), &rule, &setup_index(), now)
                    .await
                {
                    Ok(warnings) => format!("ok {warnings:?}"),
                    Err(ElasticError::Rule(error)) => format!("rule: {error}"),
                    Err(other) => format!("{other:?}"),
                },
            );
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        outcomes,
        [
            r#"ok ["the rule matched no index yet"]"#,
            r#"ok ["ES|QL sources not onboarded yet: missing-*", "the rule matched no index yet"]"#,
            "rule: ES|QL parsing exception: line 1:20: mismatched input 'error'",
            "rule: Preview validation failed for rule 'Elastic rule 14': Expected AND but found ':'",
            r#"rule: Rule schema error on preview: {"statusCode": 400, "error": "Bad Request", "message": "[from]: bad"}"#,
            "rule: Field 'message' is not aggregatable in sources: logs-*",
        ]
    );
}

#[test]
fn elastic_advisories_name_the_codes_of_a_rule() {
    let rule = rules("validate").remove(1);
    let severity = rule.payload.get("severity").and_then(Json::as_str).unwrap();
    assert_eq!(
        elastic::advisories(&rule.block, severity, true, false).unwrap(),
        Vec::<String>::new()
    );
}

#[test]
fn elastic_query_runs_through_the_framework_traits_with_the_tenant_index() {
    use opentide_connectors::Platform as _;
    let inputs = fixture("elastic");
    let query = inputs.get("query").unwrap();
    let window = window(query.get("window").unwrap());
    let tenant = replay("elastic/query");
    assert_eq!(tenant.tenant.list("index"), setup_index().as_slice());
    let runner = Elastic.query_runner().unwrap();
    assert!(Elastic.live_validator().is_some());
    assert!(
        Elastic.deployer().is_none(),
        "deploy takes the rule's block: deploy_rule"
    );
    let outcomes = block_on(async {
        let mut outcomes = Vec::new();
        for item in items(query.get("queries").unwrap()) {
            let mut request = QueryRequest::new(text(item.get("text").unwrap()), "", window);
            request.limit = match item.get("limit") {
                Some(Json::Int(limit)) => usize::try_from(*limit).unwrap(),
                _ => 100,
            };
            request.language = item
                .get("language")
                .map(|l| text(l).to_owned())
                .unwrap_or_default();
            request.index = item
                .get("index")
                .map(|index| items(index).iter().map(|i| text(i).to_owned()).collect())
                .unwrap_or_default();
            request.data_view = item.get("data_view").map(|v| text(v).to_owned());
            outcomes.push(runner.run(tenant.cx(), &request).await);
        }
        outcomes
    })
    .unwrap();
    assert_eq!(tenant.verify(), Vec::new());
    assert_eq!(
        outcomes[0].as_ref().unwrap().language.as_deref(),
        Some("esql")
    );
    assert!(matches!(outcomes[1], Err(ConnectorError::Refused { .. })));
}
