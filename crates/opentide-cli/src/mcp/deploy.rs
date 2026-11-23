//! `deploy_rule` (`tool_deploy_rule`): one rule's deployment to a platform,
//! previewed (`dry_run`, the default: nothing is sent), or with `dry_run`
//! false the command line's own `deploy --uuid` for that rule, run in this
//! process with the run strategies the rule's platform status maps to.

use opentide_compile::strategy::{Statuses, deployed_by};
use opentide_schema::node::Value;
use opentide_workspace::{Workspace, fields};

use super::catalog::{known_platform, require};
use super::tools::Context;
use crate::json::Json;

fn error(uuid: &str, status: &str, dry_run: bool, rest: Vec<(&str, Json)>) -> Json {
    let mut members = vec![
        ("action", Json::str("error")),
        ("tenant", Json::Null),
        ("rule_id", Json::str(uuid)),
        ("status", Json::str(status)),
        ("dry_run", Json::Bool(dry_run)),
    ];
    members.extend(rest);
    Json::object(members)
}

/// The refusal of a deploy to `platform` when its merged configuration
/// declares no `[[tenants]]` table (`_missing_tenants`).
fn missing_tenants(workspace: &Workspace, uuid: &str, platform: &str) -> Option<Json> {
    let tenants = workspace
        .configuration()
        .resolved
        .tree
        .get("systems")
        .and_then(|systems| systems.get(platform))
        .and_then(|system| system.get("tenants"));
    if let Some(Value::Seq(items)) = tenants.map(|node| &node.value)
        && items.iter().any(|item| matches!(item.value, Value::Map(_)))
    {
        return None;
    }
    let path = format!(".opentide/configurations/platforms/{platform}.toml");
    Some(error(
        uuid,
        "failed",
        false,
        vec![
            ("platform", Json::str(platform)),
            (
                "message",
                Json::Str(format!(
                    "Cannot deploy: {platform} has no tenants configured in {path}"
                )),
            ),
            (
                "advice",
                Json::Str(format!("add (or uncomment) a [[tenants]] entry in {path}")),
            ),
            (
                "missing_tenants",
                Json::object([(platform, Json::Str(path))]),
            ),
        ],
    ))
}

/// Why a deploy failed, from its `--json` document: its `error`, which names
/// the rule and the tenant's or the platform's own words (the `message` is
/// only the tally). An `error` equal to the message is the envelope's copy of
/// the tally, no cause: then the first failure's own `error`. Empty when the
/// document names none.
fn failure_cause(document: Option<&Json>, message: &str) -> String {
    let text = |value: Option<&Json>| {
        value
            .and_then(Json::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
    };
    let error = text(document.and_then(|document| document.get("error")))
        .filter(|error| error != message.trim());
    error
        .or_else(|| {
            let first = match document.and_then(|document| document.get("failures")) {
                Some(Json::Array(items)) => items.first(),
                _ => None,
            };
            text(first.and_then(|failure| failure.get("error")))
        })
        .unwrap_or_default()
}

/// The platform of a rule that names exactly one block in `configurations`,
/// for a call that left `platform` out; else the refusal, as data, listing them.
fn only_platform<'a>(
    rule: &'a opentide_workspace::Object,
    uuid: &str,
    dry_run: bool,
) -> Result<&'a str, Json> {
    let names: Vec<&str> = match rule
        .root()
        .and_then(|root| root.get("configurations"))
        .map(|blocks| &blocks.value)
    {
        Some(Value::Map(entries)) => entries
            .iter()
            .filter(|entry| matches!(entry.value.value, Value::Map(_)))
            .filter_map(|entry| match &entry.key.value {
                Value::Str(name) => Some(&**name),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    if let [name] = names[..] {
        return Ok(name);
    }
    let message = if names.is_empty() {
        "The rule has no platform block to deploy; pass platform".to_owned()
    } else {
        format!(
            "The rule has {} platform blocks ({}); pass platform to choose one",
            names.len(),
            names.join(", ")
        )
    };
    Err(error(
        uuid,
        "error",
        dry_run,
        vec![
            ("message", Json::Str(message)),
            (
                "platforms",
                Json::Array(names.iter().map(|name| Json::str(*name)).collect()),
            ),
        ],
    ))
}

/// A dry run's answer: the header the tool always had, then what the
/// command line's `deploy --dry-run` reported (`plan`, `changes`, `payloads`,
/// ...). `message` is the command's, which says why when nothing would deploy.
fn preview(uuid: &str, status: &str, platform: &str, message: &str, cli: Option<&Json>) -> Json {
    let mut members = vec![
        ("action".to_owned(), Json::str("dry-run")),
        ("tenant".to_owned(), Json::Null),
        ("rule_id".to_owned(), Json::str(uuid)),
        ("status".to_owned(), Json::str(status)),
        ("dry_run".to_owned(), Json::Bool(true)),
        ("platform".to_owned(), Json::str(platform)),
        (
            "message".to_owned(),
            Json::str(if message.is_empty() {
                "dry-run"
            } else {
                message
            }),
        ),
    ];
    if let Some(Json::Object(entries)) = cli {
        for (key, value) in entries {
            if !members.iter().any(|(name, _)| name == key) {
                members.push((key.clone(), value.clone()));
            }
        }
    }
    Json::Object(members.into_iter().collect())
}

/// `deploy_rule`.
#[expect(clippy::too_many_lines, reason = "kept whole; split when next touched")]
pub fn deploy_rule(
    uuid: &str,
    platform: Option<&str>,
    dry_run: bool,
    context: &Context<'_>,
) -> Result<Json, String> {
    let workspace = require(context)?;
    let index = workspace.index();
    let Some(rule) = index
        .objects
        .get("rule")
        .and_then(|bucket| bucket.get(uuid))
    else {
        return Ok(error(uuid, "not_found", dry_run, Vec::new()));
    };
    let platform = match platform.filter(|name| !name.is_empty()) {
        Some(name) => name,
        None => match only_platform(rule, uuid, dry_run) {
            Ok(name) => name,
            Err(refusal) => return Ok(refusal),
        },
    };
    if !known_platform(platform) {
        return Ok(error(
            uuid,
            "unknown_platform",
            dry_run,
            vec![
                ("platform", Json::str(platform)),
                (
                    "message",
                    Json::Str(format!("Unknown platform {platform:?}")),
                ),
            ],
        ));
    }
    if !dry_run && let Some(missing) = missing_tenants(&workspace, uuid, platform) {
        return Ok(missing);
    }
    let block_status = rule
        .root()
        .and_then(|root| root.get("configurations"))
        .and_then(|blocks| blocks.get(platform))
        .and_then(|block| block.get("status"))
        .and_then(|status| fields::text(Some(status)));
    // Checked before the dry run returns: the preview says what the real
    // call would, and a rule with no block for `platform` deploys nothing.
    let Some(status) = block_status else {
        let name = rule
            .root()
            .and_then(|root| root.get("name"))
            .map(|node| match &node.value {
                Value::Str(text) => text.clone(),
                other => other.to_string().into(),
            })
            .unwrap_or_default();
        return Ok(error(
            uuid,
            "error",
            dry_run,
            vec![
                ("platform", Json::str(platform)),
                (
                    "message",
                    Json::Str(format!("Rule {name:?} has no {platform} status to deploy")),
                ),
            ],
        ));
    };
    // The status resolves to its strategy before the dry run returns too: a
    // status the deployment configuration does not define is refused either way.
    let statuses = Statuses::from_resolved(&workspace.configuration().resolved);
    let strategy = statuses
        .strategy(&status)
        .map_err(|problem| problem.to_string())?;
    let runs = deployed_by(strategy);
    let deployed = |message: &str| {
        Json::object([
            ("action", Json::str("deploy")),
            ("tenant", Json::Null),
            ("rule_id", Json::str(uuid)),
            ("status", Json::str(&status)),
            ("dry_run", Json::Bool(false)),
            ("platform", Json::str(platform)),
            ("message", Json::str(message)),
        ])
    };
    if runs.is_empty() {
        // INERT: no run deploys it, and nothing is sent.
        let message = if dry_run {
            format!("Nothing would deploy: status {status} is INERT, no strategy deploys it")
        } else {
            String::new()
        };
        return Ok(if dry_run {
            preview(uuid, &status, platform, &message, None)
        } else {
            deployed(&message)
        });
    }
    let mut argv = vec!["--json".to_owned()];
    if let Some(repo) = context.repo {
        argv.extend(["--repo".to_owned(), repo.to_owned()]);
    }
    argv.push("deploy".to_owned());
    if dry_run {
        argv.push("--dry-run".to_owned());
    }
    argv.extend([
        "--uuid".to_owned(),
        uuid.to_owned(),
        "--platform".to_owned(),
        platform.to_owned(),
    ]);
    for run in &runs {
        argv.extend(["--strategy".to_owned(), run.name().to_owned()]);
    }
    let cwd = context.cwd.map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    );
    let run = crate::embed::run_interruptible(
        &argv,
        context.env,
        &cwd,
        context.version,
        false,
        context.interrupt.cloned().unwrap_or_default(),
    );
    let document = Json::parse(String::from_utf8_lossy(&run.stdout).trim()).ok();
    let text_of = |key: &str| {
        document
            .as_ref()
            .and_then(|document| document.get(key))
            .and_then(Json::as_str)
            .map(str::trim)
            .unwrap_or_default()
            .to_owned()
    };
    let message = text_of("message");
    if dry_run && run.exit_code == 0 {
        return Ok(preview(
            uuid,
            &status,
            platform,
            &message,
            document.as_ref(),
        ));
    }
    if run.exit_code != 0 {
        let cause = failure_cause(document.as_ref(), &message);
        let mut rest = vec![
            ("platform", Json::str(platform)),
            (
                "message",
                Json::Str(if !cause.is_empty() {
                    cause
                } else if message.is_empty() {
                    "Deployment failed: the deployer reported a rule error (see the log for its \
                     code, for example external_id_in_rule)"
                        .to_owned()
                } else {
                    format!("Deployment failed: {message}")
                }),
            ),
            ("error", Json::str("deployment_failed")),
        ];
        if let Some(advice) = document
            .as_ref()
            .and_then(|document| document.get("failure"))
            .and_then(|failure| failure.get("advice"))
            .filter(|advice| !matches!(advice, Json::Null))
        {
            rest.push(("advice", advice.clone()));
        }
        return Ok(error(uuid, "failed", false, rest));
    }
    Ok(deployed(&message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::Env;

    #[test]
    fn without_a_workspace_the_deploy_is_refused() {
        let env = Env::default();
        let context = Context {
            env: &env,
            cwd: None,
            repo: None,
            version: "1",
            workspace_problem: Some("workspace_not_found: none".into()),
            interrupt: None,
        };
        assert_eq!(
            deploy_rule("u", Some("sentinel"), true, &context),
            Err("workspace_not_found: none".to_owned())
        );
    }

    #[test]
    fn the_cause_is_the_error_unless_it_is_the_tally() {
        let tally = "Deployment failed · 1 failed, 0 not attempted · 0.0s";
        let parse = |text: &str| Json::parse(text).unwrap();
        let own = parse(r#"{"message": "t", "error": "Deployment to x failed on R: why"}"#);
        assert_eq!(
            failure_cause(Some(&own), "t"),
            "Deployment to x failed on R: why"
        );
        // The envelope copies the tally into `error`: the first failure says why.
        let copied = parse(&format!(
            r#"{{"message": "{tally}", "error": "{tally}", "failures": [{{"id": "u", "error": "refused"}}]}}"#
        ));
        assert_eq!(failure_cause(Some(&copied), tally), "refused");
        let bare = parse(&format!(r#"{{"message": "{tally}", "error": "{tally}"}}"#));
        assert_eq!(failure_cause(Some(&bare), tally), "");
        assert_eq!(failure_cause(None, ""), "");
    }

    #[test]
    fn an_error_names_the_rule_and_its_status() {
        let json = error("u", "not_found", true, Vec::new());
        assert_eq!(json.get("action"), Some(&Json::str("error")));
        assert_eq!(json.get("tenant"), Some(&Json::Null));
        assert_eq!(json.get("dry_run"), Some(&Json::Bool(true)));
    }
}
