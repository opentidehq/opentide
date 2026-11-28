//! SentinelOne's sender: the [`Sender`] method that sends one rule of
//! `--platform sentinel_one`.

use opentide_compile::Json as CJson;
use opentide_connectors::connector::{
    DeployError, DeployRequest, DeployScope, Deployer, Operation, TenantContext,
};

use super::{Planned, Raised, Sender, Stops, action_verb, raised};

impl Sender<'_, '_> {
    /// One rule sent to SentinelOne: the id the tenant gave it. The console's
    /// refusal is raised by its code, a refused key failing the tenant.
    pub(super) fn sentinel_one_deploy(
        &mut self,
        tenant: &str,
        context: TenantContext<'_>,
        rule: &opentide_compile::Rule,
        action: &Planned,
        body: &CJson,
    ) -> Result<Option<String>, Raised> {
        use opentide_connectors::sentinel_one::SentinelOne;
        // The console's refusal, by its code: each kind's event.
        let refused = |error: DeployError, action: &Planned| {
            let failure = &error.failure;
            let detail = failure.field("detail").unwrap_or_default();
            match failure.code {
                _ if error.connector.is_some() => {
                    return raised(&error.into_connector());
                }
                "sentinel_one_rule_invalid" => tracing::error!(
                    detail,
                    critical = true,
                    "received_code_400_invalid_user_input_received"
                ),
                "sentinel_one_unauthorized" => tracing::error!(
                    detail,
                    advice = "Check your configuration and API permissions again",
                    critical = true,
                    "received_code_401_unauthorized_access"
                ),
                "sentinel_one_rule_not_found" => tracing::error!(
                    detail,
                    advice = "Check in the SentinelOne console whether the rule still exists. If not, remove its sentinel_one entry from the rule's deployment state in .opentide/states/deployment/",
                    critical = true,
                    "fatal_error"
                ),
                "sentinel_one_request_failed" => tracing::error!(
                    detail = format!(
                        "Unforeseen error with code [{}]",
                        failure.status.unwrap_or_default()
                    )
                    .as_str(),
                    context = detail,
                    critical = true,
                    "fatal_error"
                ),
                _ => {}
            }
            // A refused key (`sentinel_one_unauthorized`) fails the
            // tenant: its other rules are not attempted.
            let stops = if error.scope == DeployScope::Tenant {
                Stops::Tenant
            } else {
                Stops::Rule
            };
            // Its code leads the row's error, as every coded failure's does
            // (`coded_failure`, #1894).
            Raised::new(format!(
                "{}: could not {} the rule on tenant '{tenant}': {}",
                failure.code,
                action_verb(action),
                failure.message
            ))
            .stopping(stops)
        };
        // The Deployer's request: the stored id addresses an update
        // or a delete; the body is the compiled rule.
        let compiled = || body.to_compact().into_bytes();
        let request = match action {
            Planned::Delete(id) => DeployRequest::delete(id.clone()),
            Planned::Update(id) => DeployRequest::new(id.clone(), Operation::Update, compiled()),
            Planned::Create => DeployRequest::new(rule.uuid.clone(), Operation::Create, compiled()),
        };
        let outcome = self
            .block(async { Ok(SentinelOne.deploy(context, &request).await) })
            .map_err(|error| raised(&error))?
            .map_err(|error| refused(error, action))?;
        Ok(outcome.remote_id)
    }
}
