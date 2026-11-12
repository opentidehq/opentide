//! `validate query --live` on a platform plugin (UC-4.5, #835).
//!
//! A plugin platform has no compiler of its own in Rust: what it checks live
//! is the `query` of each rule's block of `configurations` for it. Each rule
//! that has the platform's block goes to each of the platform's tenants
//! (`platforms/<id>.toml`'s `[[tenants]]`), through the connectors'
//! [`LiveValidator`] as the plugin implements it ([`crate::plugins`]). A
//! tenant that fails fails the run (exit 1); the others still run.
//!
//! A plugin's `deploy` is the built-in platforms' (`deploy_send`, UC-4.5b):
//! strategies, deployment state and the dry run's plan.
//!
//! [`LiveValidator`]: opentide_connectors::connector::LiveValidator

use std::path::Path;
use std::time::Duration;

use opentide_compile::Json as Compiled;
use opentide_connectors::connector::{LiveCheck, QueryRequest, TenantContext, TimeWindow};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{ConnectorError, Environment, HttpClient, HttpSettings, Tenant};
use tokio_util::sync::CancellationToken;

use super::{Report, open, placement};
use crate::env::Env;
use crate::envelope::{Failure, Outcome};
use crate::json::Json;

/// What a run reads besides its options.
pub struct Context<'a> {
    /// `--repo`.
    pub repo: Option<&'a str>,
    /// The environment.
    pub env: &'a Env,
    /// The working directory.
    pub cwd: &'a Path,
    /// `--proxy`.
    pub proxy: Option<&'a str>,
    /// Whether Ctrl-C was pressed.
    pub interrupted: &'a dyn Fn() -> bool,
    /// Now, for a live check's window.
    pub now: jiff::Timestamp,
}

/// Which rules a run takes.
#[derive(Clone, Debug, Default)]
pub struct Selection {
    /// `--all`.
    pub all: bool,
    /// `--uuid` values.
    pub uuids: Vec<String>,
    /// `--file` values.
    pub files: Vec<String>,
}

impl Selection {
    fn is_empty(&self) -> bool {
        !self.all && self.uuids.is_empty() && self.files.is_empty()
    }

    fn takes(&self, uuid: &str, path: &Path, cwd: &Path) -> bool {
        if self.all {
            return true;
        }
        if self.uuids.iter().any(|wanted| wanted == uuid) {
            return true;
        }
        self.files.iter().any(|file| {
            let given = cwd.join(file);
            given == path
                || std::fs::canonicalize(&given)
                    .ok()
                    .zip(std::fs::canonicalize(path).ok())
                    .is_some_and(|(given, path)| given == path)
        })
    }
}

/// One rule with the platform's block.
struct Rule {
    uuid: String,
    name: String,
    block: Compiled,
}

/// One configured tenant.
struct Configured {
    name: String,
    setup: toml::Table,
}

/// The workspace's rules with the platform's block that *selection* takes,
/// and the platform's tenants.
fn read(
    platform: &str,
    selection: &Selection,
    cx: &Context<'_>,
) -> Result<(Vec<Rule>, Vec<Configured>), String> {
    let (_, options) = placement(cx.repo, cx.env, cx.cwd);
    let workspace = open(options)?;
    let mut rules = Vec::new();
    if let Some(objects) = workspace.index().objects.get("rule") {
        for object in objects.values() {
            let Some(root) = object.document.root() else {
                continue;
            };
            let document = Compiled::from_node(root);
            let Some(block) = document
                .get("configurations")
                .and_then(|blocks| blocks.get(platform))
                .cloned()
            else {
                continue;
            };
            if !selection.takes(&object.uuid, &object.path, cx.cwd) {
                continue;
            }
            rules.push(Rule {
                uuid: object.uuid.clone(),
                name: document
                    .get("name")
                    .and_then(Compiled::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                block,
            });
        }
    }
    let config = Compiled::from_node(&workspace.configuration().resolved.tree);
    let tenants = opentide_compile::plan::tenants(&config, platform)
        .into_iter()
        .map(|tenant| Configured {
            name: opentide_compile::deploy::tenant_name(tenant).to_owned(),
            setup: tenant
                .get("setup")
                .and_then(Compiled::as_object)
                .map(|setup| {
                    setup
                        .iter()
                        .filter_map(|(key, value)| {
                            super::query::toml_value(value).map(|value| (key.clone(), value))
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
        .collect();
    crate::app::release(workspace);
    Ok((rules, tenants))
}

/// The tenant and its client, or why not.
fn connect(
    platform: &str,
    configured: &Configured,
    environment: &Environment,
    proxy: Option<&str>,
) -> Result<(Tenant, HttpClient), ConnectorError> {
    let tenant = Tenant::from_setup(
        platform,
        &configured.name,
        &configured.setup,
        environment,
        Resolve::Required,
        &HttpSettings::default(),
    )?;
    let http = HttpClient::new(&tenant.label, &tenant.http, environment, proxy)?;
    Ok((tenant, http))
}

/// Runs *work* (an operation on *tenant*, cancelled through *cancel*),
/// stopped by Ctrl-C.
fn on_tenant<T: Send>(
    tenant: &Tenant,
    cancel: &CancellationToken,
    interrupted: &dyn Fn() -> bool,
    work: opentide_connectors::connector::BoxFuture<'_, Result<T, ConnectorError>>,
) -> Result<T, ConnectorError> {
    let ran = opentide_connectors::runtime::block_on(async {
        let watch = async {
            while !interrupted() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            cancel.cancel();
            std::future::pending::<()>().await;
        };
        tokio::select! {
            result = work => result,
            () = watch => Err(ConnectorError::Cancelled),
        }
    });
    ran.map_err(|message| ConnectorError::Crashed {
        platform: tenant.label.platform.clone(),
        tenant: tenant.label.tenant.clone(),
        message,
    })?
}

/// What a tenant's failure reads as.
fn failure_text(error: &ConnectorError) -> String {
    match error {
        ConnectorError::Refused {
            message,
            detail: Some(detail),
            ..
        } => format!("{message}: {detail}"),
        other => other.to_string(),
    }
}

fn finished(
    command: &str,
    data: Vec<(String, Json)>,
    summary: Vec<(String, Json)>,
    failed: Option<String>,
    message: String,
) -> Report {
    let mut report = Report::failed(command, 1, Failure::new("", ""));
    report.outcome = match failed {
        Some(first) => Outcome {
            command: command.to_owned(),
            status: "failed".into(),
            message: first.clone(),
            data,
            exit_code: 1,
            summary,
            next_actions: Vec::new(),
            failure: Some(Failure::new(super::COMMAND_FAILED, first)),
        },
        None => Outcome {
            command: command.to_owned(),
            status: "completed".into(),
            message,
            data,
            exit_code: 0,
            summary,
            next_actions: Vec::new(),
            failure: None,
        },
    };
    report
}

fn queries(count: usize) -> String {
    format!("{count} quer{}", if count == 1 { "y" } else { "ies" })
}

/// `opentide validate query --live --platform <plugin>`: each selected
/// rule's `configurations.<platform>.query` checked on each tenant.
pub fn validate_live(
    platform: &str,
    selection: &Selection,
    timeout: Duration,
    cx: &Context<'_>,
) -> Report {
    const COMMAND: &str = "validate query";
    let registry = crate::plugins::registry();
    let Some(validator) = registry
        .get(platform)
        .and_then(opentide_connectors::Platform::live_validator)
    else {
        let mut report = Report::failed(
            COMMAND,
            1,
            Failure::new(
                super::COMMAND_FAILED,
                format!("query validation not supported for {platform}"),
            ),
        );
        report.outcome.data = vec![
            ("platform".into(), Json::str(platform)),
            ("valid".into(), Json::Null),
            ("supported".into(), Json::Bool(false)),
        ];
        return report;
    };
    let all = Selection {
        all: selection.is_empty(),
        ..selection.clone()
    };
    let (rules, tenants) = match read(platform, &all, cx) {
        Ok(read) => read,
        Err(message) => return Report::error(COMMAND, message),
    };
    let environment = Environment::from_pairs(cx.env.iter());
    let mut results = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0;
    for configured in &tenants {
        let connected = connect(platform, configured, &environment, cx.proxy);
        for rule in &rules {
            let Some(query) = rule.block.get("query").and_then(Compiled::as_str) else {
                continue;
            };
            if (cx.interrupted)() {
                break;
            }
            checked += 1;
            let language = rule
                .block
                .get("language")
                .and_then(Compiled::as_str)
                .unwrap_or_default();
            let mut request = QueryRequest::new(query, language, TimeWindow::check(cx.now));
            request.timeout = timeout;
            let request = request.for_check();
            let verdict: Result<LiveCheck, String> = match &connected {
                Err(error) => Err(error.to_string()),
                Ok((tenant, http)) => {
                    let cancel = CancellationToken::new();
                    let context = TenantContext {
                        tenant,
                        http,
                        cancel: &cancel,
                    };
                    on_tenant(
                        tenant,
                        &cancel,
                        cx.interrupted,
                        validator.validate(context, &request),
                    )
                    .map_err(|error| failure_text(&error))
                }
            };
            let (errors, warnings) = match verdict {
                Ok(check) => (check.errors, check.warnings),
                Err(message) => (vec![message], Vec::new()),
            };
            if let Some(first) = errors.first() {
                failures.push(format!(
                    "{} on tenant {}: {first}",
                    rule.name, configured.name
                ));
            }
            results.push(Json::object([
                ("uuid", Json::str(&rule.uuid)),
                ("name", Json::str(&rule.name)),
                ("tenant", Json::str(&configured.name)),
                ("valid", Json::Bool(errors.is_empty())),
                (
                    "errors",
                    Json::Array(errors.iter().map(Json::str).collect()),
                ),
                (
                    "warnings",
                    Json::Array(warnings.iter().map(Json::str).collect()),
                ),
            ]));
        }
    }
    let data = vec![
        ("platform".to_owned(), Json::str(platform)),
        ("supported".to_owned(), Json::Bool(true)),
        ("valid".to_owned(), Json::Bool(failures.is_empty())),
        ("results".to_owned(), Json::Array(results)),
    ];
    let summary = vec![
        ("checked".to_owned(), Json::from(checked)),
        ("failed".to_owned(), Json::from(failures.len())),
    ];
    let failed = failures.first().map(|first| {
        format!(
            "{} of {} live checks failed on {platform}: {first}",
            failures.len(),
            queries(checked)
        )
    });
    finished(
        COMMAND,
        data,
        summary,
        failed,
        format!(
            "{} valid on {} {platform} tenant{}",
            queries(checked),
            tenants.len(),
            if tenants.len() == 1 { "" } else { "s" }
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_selection_takes_every_rule_its_uuids_or_its_files() {
        let cwd = Path::new("/ws");
        let path = Path::new("/ws/rules/a.yaml");
        assert!(Selection::default().is_empty());
        let all = Selection {
            all: true,
            ..Selection::default()
        };
        assert!(all.takes("u", path, cwd));
        let uuid = Selection {
            uuids: vec!["u".into()],
            ..Selection::default()
        };
        assert!(uuid.takes("u", path, cwd) && !uuid.takes("v", path, cwd));
        let file = Selection {
            files: vec!["rules/a.yaml".into()],
            ..Selection::default()
        };
        assert!(file.takes("v", path, cwd));
        assert!(!file.takes("v", Path::new("/ws/rules/b.yaml"), cwd));
    }

    #[test]
    fn failures_read_with_the_tenants_reason() {
        let refused = ConnectorError::Refused {
            platform: "acme".into(),
            tenant: "t".into(),
            message: "rule refused".into(),
            detail: Some("bad field".into()),
        };
        assert_eq!(failure_text(&refused), "rule refused: bad field");
        assert_eq!(failure_text(&ConnectorError::Cancelled), "interrupted");
        assert_eq!(queries(1), "1 query");
        assert_eq!(queries(0), "0 queries");
    }
}
