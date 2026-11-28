//! Graylog's sender (`GraylogDeploy`): the [`Sender`] methods that deploy
//! the rules of `--platform graylog`.

use opentide_compile::strategy::StatusStrategy;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployScope, Deployer, Operation,
};
use opentide_connectors::tenant_codes;
use opentide_schema::platforms::PlatformId;

use super::{
    Batch, Connection, DeployLog, Planned, Raised, RuleResult, Sender, Stops, TENANTS_AT_ONCE,
};
use crate::commands::deploy_state::{ExternalId, StateError};

impl Sender<'_, '_> {
    /// Graylog: the version is read once per tenant (a vulnerable one warned
    /// about), then each rule's event definition, compiled for it, is
    /// created, updated, unscheduled or deleted through the platform's
    /// `Deployer` (`GraylogDeploy`).
    pub(super) fn graylog(
        &mut self,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        self.tenants(TENANTS_AT_ONCE, batches, log, Self::graylog_tenant)
    }

    /// One tenant's rules of [`graylog`](Self::graylog).
    fn graylog_tenant(&mut self, batch: &Batch, log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Graylog.as_str();
        use opentide_connectors::graylog::Client;
        let tenant = batch.tenant.name.clone();
        let planned = self.screen(PLATFORM, batch, log);
        if planned.is_empty() {
            return Ok(());
        }
        let Some(connection) = self.connect_or_fail(PLATFORM, batch, log)? else {
            return Ok(());
        };
        // The version is read once, before any write. A refused token, an
        // unsupported version or an unreachable tenant stops the tenant.
        let version = match self.block(Client::new(self.context(&connection)).version()) {
            Ok(Ok(version)) => version,
            Ok(Err(error)) => {
                let code = if error.forbidden() {
                    "graylog_forbidden"
                } else {
                    tenant_codes::GRAYLOG.request_failed
                };
                self.unusable(PLATFORM, Some(&tenant), &error.reason());
                log.unreached_on(
                    PLATFORM,
                    &tenant,
                    "not_attempted",
                    &format!("not attempted: tenant {tenant} failed"),
                );
                tracing::error!(
                    tenant = tenant.as_str(),
                    code,
                    error = error.reason().as_str(),
                    critical = true,
                    "graylog_tenant_deployment_failed"
                );
                return Ok(());
            }
            Err(error) => {
                let code = match &error {
                    ConnectorError::Refused { .. } => "graylog_version_unsupported",
                    ConnectorError::Authentication { .. } => "graylog_tenant_unauthenticated",
                    _ => tenant_codes::GRAYLOG.unreachable,
                };
                self.unusable(PLATFORM, Some(&tenant), &error.text());
                log.unreached_on(
                    PLATFORM,
                    &tenant,
                    "not_attempted",
                    &format!("not attempted: tenant {tenant} failed"),
                );
                tracing::error!(
                    tenant = tenant.as_str(),
                    code,
                    error = error.text().as_str(),
                    critical = true,
                    "graylog_tenant_deployment_failed"
                );
                return Ok(());
            }
        };
        if opentide_compile::graylog::is_vulnerable(version) {
            self.warned = true;
            tracing::warn!(
                tenant = tenant.as_str(),
                detail = format!(
                    "Graylog {version} does not revoke access tokens reliably ({}); upgrade \
                     to 6.3.12, 7.0.16, 7.1.12 or later",
                    opentide_compile::graylog::ADVISORY
                ),
                "graylog_version_vulnerable"
            );
        }
        // The version read was the tenant's opening: what follows is a rule's.
        connection.mark_opened();
        for (rule, action) in planned {
            connection.rule_begins();
            if self.graylog_rule(&connection, batch, rule, &action, version, log)? {
                break;
            }
        }
        Ok(())
    }

    /// A Graylog rule the tenant refused: what the deploy did before the
    /// failure, then the failure; a refused re-creation is logged as the
    /// request it stopped.
    fn graylog_rule_failed(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        tenant: &str,
        error: &DeployError,
        recreate_refusal: Option<&StateError>,
    ) {
        if let Some(done) = &error.partial {
            self.graylog_done(&rule.uuid, tenant, done);
        }
        let failure = &error.failure;
        // The state's refusal is logged as the request it
        // stopped, as before.
        let code = if recreate_refusal.is_some_and(|refusal| refusal.code == failure.code) {
            tenant_codes::GRAYLOG.request_failed
        } else {
            failure.code
        };
        match failure.status {
            Some(status) => tracing::error!(
                uuid = rule.uuid.as_str(),
                tenant = tenant,
                status_code = status,
                code,
                error = failure.message.as_str(),
                "{}",
                code
            ),
            None => tracing::error!(
                uuid = rule.uuid.as_str(),
                tenant = tenant,
                code,
                error = failure.message.as_str(),
                detail = failure.field("detail").unwrap_or_default(),
                "{}",
                code
            ),
        }
        self.rule_error(result, &failure.message);
    }

    /// The request a Graylog rule sends: a delete names the recorded id
    /// alone (no compile); anything else sends the definition compiled for
    /// the tenant's version, after logging that version's warnings. `Err` is
    /// the reason the rule fails, a compile failure logged with its code.
    fn graylog_request(
        &mut self,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        version: opentide_compile::graylog::Version,
        operation: Operation,
        stored: Option<&str>,
    ) -> Result<DeployRequest, String> {
        use opentide_compile::compiler::{Compiler, Graylog, GraylogTarget};
        if let Planned::Delete(id) = action {
            // A delete sends the recorded id alone: no rule compile.
            return Ok(DeployRequest::delete(id.clone()));
        }
        let tenant = batch.tenant.name.as_str();
        // The dry run's compile ([`Compiler`]): the tenant's `setup` table,
        // whose `stream_ids` and `notification_ids` resolve the block's
        // aliases, and its name.
        let target = GraylogTarget {
            version,
            tenant: Some(&batch.table),
        };
        let compiled = Graylog::compile(self.compile, rule, target).map_err(|error| {
            // An alias the tenant does not define (or any other compile
            // failure) fails the rule with its own code
            // (`_deployment_error(exc.code)`), and the reason keeps the
            // hint the dry run shows (what to add to which table).
            tracing::error!(
                uuid = rule.uuid.as_str(),
                tenant,
                name = rule.name.as_str(),
                code = error.code,
                error = error.reason.as_str(),
                "{}",
                error.code
            );
            error.to_string()
        })?;
        // The version's own warnings (a field it cannot take, a priority it
        // collapses).
        for (code, message) in &compiled.warnings {
            self.warned = true;
            tracing::warn!(
                uuid = rule.uuid.as_str(),
                tenant,
                detail = message.as_str(),
                "{code}"
            );
        }
        serde_json::to_vec(&Graylog::body(&compiled))
            .map(|body| DeployRequest::new(stored.unwrap_or(&rule.uuid), operation, body))
            .map_err(|error| format!("the compiled definition is not JSON: {error}"))
    }

    /// One Graylog rule: compiled for the tenant's version, sent, and its
    /// result logged. `true` when the tenant failed and the rest of its rules
    /// are left out.
    fn graylog_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        version: opentide_compile::graylog::Version,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        const PLATFORM: &str = PlatformId::Graylog.as_str();
        // The version is read: the deployer reads it no more.
        let graylog = opentide_connectors::graylog::Graylog::on_version(version);
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        // A strategy screening missed fails the rule, as on the other
        // platforms: it does not leave the tenant.
        let disable = match self.strategy_of(rule, PLATFORM) {
            Ok(strategy) => strategy == StatusStrategy::Disablement,
            Err(raised) => {
                self.close(log, result, Err(raised))?;
                return Ok(false);
            }
        };
        let (operation, stored) = match &action {
            Planned::Create => (Operation::Create, None),
            Planned::Update(id) if disable => (Operation::Disable, Some(id.as_str())),
            Planned::Update(id) => (Operation::Update, Some(id.as_str())),
            Planned::Delete(id) => (Operation::Delete, Some(id.as_str())),
        };
        let mut request =
            match self.graylog_request(batch, rule, action, version, operation, stored) {
                Ok(request) => request,
                Err(reason) => {
                    self.rule_error(&mut result, &reason);
                    log.finished(result);
                    return Ok(false);
                }
            };
        let recreate_refusal = self.recreate_refusal(&rule.uuid, PLATFORM, &tenant);
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(graylog.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                self.graylog_done(&rule.uuid, &tenant, &done);
                match done.remote_id.as_deref() {
                    None => self.record_deleted(&mut result, PLATFORM, &tenant),
                    Some(id) if Some(id) != stored => self.record_created(
                        &mut result,
                        PLATFORM,
                        &tenant,
                        &ExternalId::Text(id.to_owned()),
                    ),
                    Some(_) => {}
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                self.graylog_rule_failed(
                    &mut result,
                    rule,
                    &tenant,
                    &error,
                    recreate_refusal.as_ref(),
                );
                log.finished(result);
            }
            Err(error) => {
                let before_any = self.before_any_rule(connection, PLATFORM, &tenant, log);
                let error = error.into_connector();
                let text = error.text();
                let code = match &error {
                    ConnectorError::Authentication { .. } => "graylog_tenant_unauthenticated",
                    _ => tenant_codes::GRAYLOG.unreachable,
                };
                self.failed = true;
                tracing::error!(
                    tenant = tenant.as_str(),
                    code,
                    error = text.as_str(),
                    critical = true,
                    "graylog_tenant_deployment_failed"
                );
                if before_any {
                    // No write was taken yet: no rule was sent (#1701).
                    self.unused(PLATFORM, &tenant, log, &text);
                    return Ok(true);
                }
                result.fail(&text);
                log.finished(result);
                // An interrupt stops the run, not the tenant.
                if self.interrupted() {
                    return Err(Raised::new("interrupted").stopping(Stops::Run));
                }
                self.stop_tenant(PlatformId::Graylog.as_str(), &tenant, log);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What a Graylog deploy did, failed or not: its warnings, but the
    /// version's, which the tenant warned of once; then what was done.
    fn graylog_done(&mut self, uuid: &str, tenant: &str, done: &DeployOutcome) {
        for warning in &done.warnings {
            if warning.code == opentide_connectors::graylog::VERSION_VULNERABLE {
                continue;
            }
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
            let definition_id = event
                .fields
                .iter()
                .find(|(key, _)| key == "definition_id")
                .map_or("", |(_, id)| id.as_str());
            tracing::info!(uuid, definition_id, "{}", event.name);
        }
    }
}
