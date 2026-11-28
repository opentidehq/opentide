//! Sysdig Secure's sender (`SysdigDeploy`): the [`Sender`] methods that
//! deploy the rules of `--platform sysdig`.

use opentide_compile::Json as CJson;
use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployScope, Deployer,
};
use opentide_schema::platforms::PlatformId;

use super::{
    Batch, Connection, DeployLog, Planned, Raised, RuleResult, Sender, TENANTS_AT_ONCE,
    operation_of,
};
use crate::commands::deploy_state::ExternalId;
use crate::json::Json;

impl Sender<'_, '_> {
    /// Sysdig: each rule planned from deployment state, then created and
    /// added to its runtime policies, updated, disabled or deleted
    /// (`SysdigDeploy`).
    pub(super) fn sysdig(
        &mut self,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        self.tenants(TENANTS_AT_ONCE, batches, log, Self::sysdig_tenant)
    }

    /// One tenant's rules of [`sysdig`](Self::sysdig).
    fn sysdig_tenant(&mut self, batch: &Batch, log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Sysdig.as_str();
        let planned = self.screen(PLATFORM, batch, log);
        if planned.is_empty() {
            return Ok(());
        }
        let opener = opentide_connectors::sysdig::Sysdig;
        let Some(connection) = self.open_or_fail(PLATFORM, batch, log, &opener)? else {
            return Ok(());
        };
        let tenant_policies: Vec<String> =
            match opentide_compile::deploy::setup(&batch.table, "policies") {
                Some(CJson::Array(items)) => items.iter().map(Json::to_text).collect(),
                _ => Vec::new(),
            };
        for (rule, action) in planned {
            connection.rule_begins();
            if self.sysdig_rule(&connection, batch, rule, &action, &tenant_policies, log)? {
                break;
            }
        }
        Ok(())
    }

    /// One Sysdig rule: compiled, sent, and its result logged. `true` when
    /// the tenant failed and the rest of its rules are left out.
    fn sysdig_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        tenant_policies: &[String],
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        const PLATFORM: &str = PlatformId::Sysdig.as_str();
        use opentide_connectors::sysdig::Sysdig;
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = self.strategy_of(rule, PLATFORM);
        let body = strategy.clone().and_then(|_| {
            opentide_compile::sysdig::compile_body(self.compile, rule, Some(&batch.table)).map_err(
                |error| Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name)),
            )
        });
        let (strategy, body) = match (strategy, body) {
            (Ok(strategy), Ok(body)) => (strategy, body),
            (Err(raised), _) | (_, Err(raised)) => {
                self.close(log, result, Err(raised.clone()))?;
                return Ok(false);
            }
        };
        let policies = opentide_compile::sysdig::block_policies(rule)
            .unwrap_or_else(|| tenant_policies.to_vec());
        let recreate_refusal = self.recreate_refusal(&rule.uuid, PLATFORM, &tenant);
        let (operation, stored) = operation_of(action, strategy);
        let mut request = DeployRequest::new(
            stored.unwrap_or_default(),
            operation,
            serde_json::to_vec(&body).unwrap_or_default(),
        )
        .with_policies(Some(policies));
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(Sysdig.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                let forget = done.remote_id.is_none();
                self.sysdig_done(&mut result, &rule.uuid, &tenant, &done, stored);
                if forget {
                    self.record_deleted(&mut result, PLATFORM, &tenant);
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                if let Some(done) = &error.partial {
                    self.sysdig_done(&mut result, &rule.uuid, &tenant, done, stored);
                }
                match recreate_refusal
                    .as_ref()
                    .filter(|refusal| refusal.code == error.failure.code)
                {
                    Some(refusal) => {
                        self.report_failure(refusal, &rule.uuid, PLATFORM, &tenant);
                        result.fail(&refusal.message);
                    }
                    None => {
                        tracing::error!(
                            uuid = rule.uuid.as_str(),
                            tenant = tenant.as_str(),
                            status_code = error.failure.status,
                            error = error.failure.message.as_str(),
                            "sysdig_request_failed"
                        );
                        self.rule_error(&mut result, &error.failure.message);
                    }
                }
                log.finished(result);
            }
            Err(error) => {
                self.tenant_deploy_failed(
                    connection,
                    PlatformId::Sysdig.as_str(),
                    "sysdig_tenant_deployment_failed",
                    &tenant,
                    error,
                    result,
                    log,
                )?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What a Sysdig deploy did, failed or not: its warnings, then the id
    /// of a rule it created (its `sysdig_rule_created` event), recorded
    /// when it is not the `stored` one.
    fn sysdig_done(
        &mut self,
        result: &mut RuleResult,
        uuid: &str,
        tenant: &str,
        done: &DeployOutcome,
        stored: Option<&str>,
    ) {
        const PLATFORM: &str = PlatformId::Sysdig.as_str();
        for warning in &done.warnings {
            self.warned = true;
            tracing::warn!(
                uuid,
                tenant,
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            tracing::info!(
                uuid,
                rule_id = event
                    .fields
                    .iter()
                    .find(|(key, _)| key == "rule_id")
                    .map_or("", |(_, id)| id.as_str()),
                "{}",
                event.name
            );
        }
        if let Some(id) = done.remote_id.as_deref().filter(|id| Some(*id) != stored) {
            let external = id
                .parse::<i64>()
                .map_or_else(|_| ExternalId::Text(id.to_owned()), ExternalId::Int);
            self.record_created(result, PLATFORM, tenant, &external);
        }
    }
}
