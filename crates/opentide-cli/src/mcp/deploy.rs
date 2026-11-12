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

/// `deploy_rule`.
pub fn deploy_rule(
    uuid: &str,
    platform: &str,
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
    if !known_platform(platform) {
        return Ok(error(
            uuid,
            "unknown_platform",
            dry_run,
            vec![
                ("platform", Json::str(platform)),
                (
                    "message",
                    Json::Str(format!(
                        "Unknown platform {}",
                        crate::render::codeframe::quoted(platform)
                    )),
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
    let status_json = block_status.clone().map_or(Json::Null, Json::Str);
    if dry_run {
        return Ok(Json::object([
            ("action", Json::str("dry-run")),
            ("tenant", Json::Null),
            ("rule_id", Json::str(uuid)),
            ("status", status_json),
            ("dry_run", Json::Bool(true)),
            ("platform", Json::str(platform)),
            ("message", Json::str("dry-run")),
        ]));
    }
    let Some(status) = block_status else {
        let name = rule
            .root()
            .and_then(|root| root.get("name"))
            .map(|node| match &node.value {
                Value::Str(text) => text.clone(),
                other => other.to_string(),
            })
            .unwrap_or_default();
        return Ok(error(
            uuid,
            "error",
            false,
            vec![
                ("platform", Json::str(platform)),
                (
                    "message",
                    Json::Str(format!(
                        "Rule {} has no {platform} status to deploy",
                        crate::render::codeframe::quoted(&name)
                    )),
                ),
            ],
        ));
    };
    let statuses = Statuses::from_resolved(&workspace.configuration().resolved);
    let strategy = statuses
        .strategy(&status)
        .map_err(|problem| problem.exception_text())?;
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
        return Ok(deployed(""));
    }
    let mut argv = vec!["--json".to_owned()];
    if let Some(repo) = context.repo {
        argv.extend(["--repo".to_owned(), repo.to_owned()]);
    }
    argv.extend([
        "deploy".to_owned(),
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
    let run = crate::embed::run_captured(&argv, context.env, &cwd, context.version, false);
    let document = Json::parse(String::from_utf8_lossy(&run.stdout).trim()).ok();
    let message = document
        .as_ref()
        .and_then(|document| document.get("message"))
        .and_then(Json::as_str)
        .unwrap_or_default()
        .to_owned();
    if run.exit_code != 0 {
        let mut rest = vec![
            ("platform", Json::str(platform)),
            (
                "message",
                Json::Str(if message.is_empty() {
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
        };
        assert_eq!(
            deploy_rule("u", "sentinel", true, &context),
            Err("workspace_not_found: none".to_owned())
        );
    }

    #[test]
    fn an_error_names_the_rule_and_its_status() {
        let json = error("u", "not_found", true, Vec::new());
        assert_eq!(json.get("action"), Some(&Json::str("error")));
        assert_eq!(json.get("tenant"), Some(&Json::Null));
        assert_eq!(json.get("dry_run"), Some(&Json::Bool(true)));
    }
}
