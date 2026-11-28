//! The failure model of a run: a tenant or platform that could not deploy,
//! what a failure stops (the rule, its tenant or the run), and a connector
//! error read as a failure in words.

use opentide_connectors::ConnectorError;
use opentide_connectors::connector::{DeployError, DeployScope};

use super::{RuleResult, bounded};
use crate::json::Json;

/// A tenant (or a whole platform, with no tenant) that could not deploy.
#[derive(Debug, Clone)]
pub(super) struct Unusable {
    pub(super) platform: String,
    pub(super) tenant: Option<String>,
    pub(super) error: String,
}

impl Unusable {
    fn to_json(&self) -> Json {
        let mut fields = vec![("platform".to_owned(), Json::str(&self.platform))];
        if let Some(tenant) = &self.tenant {
            fields.push(("tenant".into(), Json::str(tenant)));
        }
        fields.push(("error".into(), Json::str(&self.error)));
        Json::Object(fields.into_iter().collect())
    }
}

/// What a failure stops: one rule, the rest of its tenant, or the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stops {
    /// The rule fails; the run goes on with the next one.
    Rule,
    /// The tenant cannot be used (its credentials, its connection): its
    /// remaining rules are not attempted, the other tenants go on.
    Tenant,
    /// An interrupt: nothing more is sent.
    Run,
}

/// A failure, in words: the failed rule's line and the run's message say it
/// (`failure`), and what it stops.
#[derive(Debug, Clone)]
pub(super) struct Raised {
    problem: String,
    pub(super) stops: Stops,
}

impl Raised {
    /// A failure of the rule being sent.
    pub(super) fn new(problem: impl Into<String>) -> Self {
        Self {
            problem: problem.into(),
            stops: Stops::Rule,
        }
    }

    /// The same failure, stopping `stops`.
    pub(super) fn stopping(self, stops: Stops) -> Self {
        Self { stops, ..self }
    }

    /// The problem, for the run's message.
    pub(super) fn error(&self) -> String {
        self.problem.trim().to_owned()
    }

    /// The problem on one bounded line, for the rule being sent.
    pub(super) fn describe(&self) -> String {
        bounded(&self.problem)
    }
}

/// What follows the first of `count` failures in the run's error.
pub(super) fn more_failures(count: usize) -> String {
    match count.saturating_sub(1) {
        0 => String::new(),
        1 => " (and 1 more failure)".to_owned(),
        more => format!(" (and {more} more failures)"),
    }
}

/// Every failure of a run, each with its line for the run's `error`: the
/// failed rules (platform, tenant, id, name, error), then the tenants and
/// platforms that could not deploy.
pub(super) fn failures(
    results: &[RuleResult],
    unusable: &[Unusable],
    refused: &[String],
) -> Vec<(String, Json)> {
    // Rules refused before any platform was planned (`external_id_in_rule`).
    let refused = refused.iter().map(|uuid| {
        let error = "external_id_in_rule: the rule still carries vendor ids; deploy reads them \
                     only from .opentide/states/deployment/";
        (
            format!("Deployment refused rule {uuid}: {error}"),
            Json::object([("id", Json::str(uuid)), ("error", Json::str(error))]),
        )
    });
    let rules = results
        .iter()
        .filter(|result| result.status == "failed")
        .map(|result| {
            let error = result.error.clone().unwrap_or_default();
            let mut fields = vec![("platform".to_owned(), Json::str(&result.platform))];
            if let Some(tenant) = &result.tenant {
                fields.push(("tenant".into(), Json::str(tenant)));
            }
            fields.push(("id".into(), Json::str(&result.id)));
            fields.push(("name".into(), Json::str(&result.name)));
            fields.push(("error".into(), Json::str(&error)));
            (
                format!(
                    "Deployment to {} failed on {}: {error}",
                    result.platform, result.name
                ),
                Json::Object(fields.into_iter().collect()),
            )
        });
    let tenants = unusable.iter().map(|failure| {
        let line = match &failure.tenant {
            Some(tenant) => format!(
                "Deployment to {} failed on tenant {tenant}: {}",
                failure.platform, failure.error
            ),
            None => format!(
                "Deployment to {} failed: {}",
                failure.platform, failure.error
            ),
        };
        (line, failure.to_json())
    });
    refused.chain(rules).chain(tenants).collect()
}

/// A connector error as a failure: of the rule for an answer the tenant
/// refused, of the tenant for its connection or credentials, of the run for
/// an interrupt.
pub(super) fn raised(error: &ConnectorError) -> Raised {
    let stops = match error {
        ConnectorError::Cancelled => Stops::Run,
        ConnectorError::Unreachable { .. }
        | ConnectorError::Timeout { .. }
        | ConnectorError::Setup { .. }
        | ConnectorError::MissingCredential { .. }
        | ConnectorError::Crashed { .. }
        | ConnectorError::Authentication { .. }
        | ConnectorError::Gateway { .. }
        | ConnectorError::NetworkUnavailable { .. } => Stops::Tenant,
        // Exhaustive: a new kind must say what it stops, as
        // `DeployError::from` must say what it fails.
        ConnectorError::Answer { .. }
        | ConnectorError::Refused { .. }
        | ConnectorError::QueryTimedOut { .. } => Stops::Rule,
    };
    described(error).stopping(stops)
}

/// A rule's failure for an unset variable of the setup: the rule only.
pub(super) fn unset_variable(error: &ConnectorError) -> Raised {
    raised(error).stopping(Stops::Rule)
}

/// A `Deployer`'s failure, raised by `raise` from its connector error: the
/// tenant stopped whenever the `Deployer` says the tenant failed, as the SDKs
/// report it (`DeployError::scope`), whatever the error's kind.
pub(super) fn scoped(failed: DeployError, raise: impl FnOnce(ConnectorError) -> Raised) -> Raised {
    let tenant = failed.scope == DeployScope::Tenant;
    let raised = raise(failed.into_connector());
    if tenant && raised.stops == Stops::Rule {
        raised.stopping(Stops::Tenant)
    } else {
        raised
    }
}

/// A rule's failure on the by-uuid path, or a retirement's, raised. A failure
/// the connector made with a code of its own (Defender's
/// `microsoft_defender_rule_conflict`, Splunk's
/// `splunk_renamed_search_not_deleted`, HarfangLab's
/// `harfanglab_request_invalid`) keeps it in the row's error
/// (`code: message`), as Bitdefender's and Google SecOps' do:
/// [`DeployError::into_connector`] makes it a [`ConnectorError::Refused`],
/// which has no code (#1886, #1894). A failure that came from a connector
/// error, or the generic `tenant_refused`, reads as it did.
pub(super) fn coded_failure(failed: DeployError) -> Raised {
    let own = (failed.connector.is_none() && failed.failure.code != "tenant_refused")
        .then_some(failed.failure.code);
    scoped(failed, |error| match own {
        Some(code) => raised(&coded(code, error)),
        None => raised(&error),
    })
}

/// *error* with *code* before its message (`code: message`), as the row's
/// error shows a coded failure; an error of another kind is kept.
fn coded(code: &str, error: ConnectorError) -> ConnectorError {
    match error {
        ConnectorError::Refused {
            platform,
            tenant,
            detail,
            message,
        } => ConnectorError::Refused {
            platform,
            tenant,
            detail,
            message: format!("{code}: {message}"),
        },
        other => other,
    }
}

/// A connector error's words: its own message, the tenant's reason after a
/// refusal, and the tenant that refused the credentials.
fn described(error: &ConnectorError) -> Raised {
    match error {
        ConnectorError::Cancelled => Raised::new("interrupted"),
        ConnectorError::Authentication {
            platform,
            tenant,
            message,
            ..
        } => Raised::new(format!("{platform} tenant '{tenant}': {message}")),
        ConnectorError::Refused {
            message,
            detail: Some(detail),
            ..
        } if !detail.trim().is_empty() && !message.contains(detail.trim()) => {
            Raised::new(format!("{message}: {}", detail.trim()))
        }
        other => Raised::new(other.to_string()),
    }
}
