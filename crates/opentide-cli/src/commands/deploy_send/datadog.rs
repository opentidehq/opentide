//! Datadog Cloud SIEM's sender: the [`Sender`] methods that deploy the
//! rules of `--platform datadog`.

use opentide_compile::Json as CJson;
use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployScope, Deployer, TenantContext,
};

use super::{
    Batch, Connection, DeployLog, Planned, Raised, RuleResult, Sender, Stops, TENANTS_AT_ONCE,
    UNCHANGED, operation_of, raised,
};
use crate::commands::deploy_state::{ExternalId, StateError};

impl Sender<'_, '_> {
    /// Datadog Cloud SIEM (RFC rfc-datadog-cloud-siem §8.3): each rule
    /// planned from deployment state, then validated and created, updated
    /// only when a property opentide owns differs (or disabled) by the
    /// recorded id, or deleted. A refused key, an unknown site or a tenant
    /// with no answer stops its batch.
    pub(super) fn datadog(
        &mut self,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let datadog = opentide_connectors::datadog::Datadog::new();
        self.tenants(TENANTS_AT_ONCE, batches, log, |sender, batch, log| {
            sender.datadog_tenant(&datadog, batch, log)
        })
    }

    /// One tenant's rules of [`datadog`](Self::datadog).
    fn datadog_tenant(
        &mut self,
        datadog: &opentide_connectors::datadog::Datadog,
        batch: &Batch,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let platform = opentide_compile::datadog::PLATFORM;
        let tenant = batch.tenant.name.clone();
        let planned = self.screen(platform, batch, log);
        if planned.is_empty() {
            return Ok(());
        }
        let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
            return Ok(());
        };
        let cancel = self.cancel.clone();
        let context = TenantContext {
            tenant: &connection.tenant,
            http: &connection.http,
            cancel: &cancel,
        };
        let opened = self
            .block(async { Ok(datadog.open(context).await) })
            .map_err(DeployError::from)
            .and_then(|opened| opened);
        if let Err(error) = opened {
            // An unset key variable or a site that is not one: no rule
            // on the tenant can deploy.
            let text = error.into_connector().text();
            tracing::error!(
                tenant = tenant.as_str(),
                error = text.as_str(),
                critical = true,
                "datadog_tenant_deployment_failed"
            );
            self.unusable(platform, Some(&tenant), &text);
            log.unreached_on(
                platform,
                &tenant,
                "not_attempted",
                &format!("not attempted: tenant {tenant} failed"),
            );
            return Ok(());
        }
        connection.mark_opened();
        for (rule, action) in planned {
            connection.rule_begins();
            if self.datadog_rule(&connection, batch, rule, &action, datadog, log)? {
                break;
            }
        }
        Ok(())
    }

    /// One Datadog rule: compiled for the tenant, sent, and its result
    /// logged. `true` when the tenant failed and the rest of its rules are
    /// left out.
    fn datadog_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        datadog: &opentide_connectors::datadog::Datadog,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        let platform = opentide_compile::datadog::PLATFORM;
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(platform, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = match self.strategy_of(rule, platform) {
            Ok(strategy) => strategy,
            Err(raised) => {
                self.close(log, result, Err(raised))?;
                return Ok(false);
            }
        };
        let compiled = if matches!(action, Planned::Delete(_)) {
            Ok(None)
        } else {
            use opentide_compile::compiler::{Compiler, Datadog};
            // The dry run's compile ([`Compiler`]), so it shows this body. A
            // disable is compiled without the tenant there (RFC §8.2).
            Datadog::compile(self.compile, rule, Some(&batch.table))
                .map(|compiled| Some(Datadog::body(&compiled)))
                .map_err(|error| {
                    Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
                })
        };
        let compiled = match compiled {
            Ok(compiled) => compiled,
            Err(raised) => {
                self.close(log, result, Err(raised))?;
                return Ok(false);
            }
        };
        let recreate_refusal = self.recreate_refusal(&rule.uuid, platform, &tenant);
        let (operation, stored) = operation_of(action, strategy);
        let body = compiled.unwrap_or(CJson::Null);
        let mut request = DeployRequest::new(
            stored.unwrap_or_default(),
            operation,
            serde_json::to_vec(&body).unwrap_or_default(),
        );
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        match self
            .block(async { Ok(datadog.deploy(context, &request).await) })
            .map_err(|error| raised(&error))?
        {
            Ok(done) => {
                self.datadog_done(&rule.uuid, &tenant, &done);
                // The tenant already held the rule as compiled: nothing was
                // written (#1711).
                if done.unchanged() {
                    result.action = Some(UNCHANGED.to_owned());
                }
                match done.remote_id.as_deref() {
                    None => self.record_deleted(&mut result, platform, &tenant),
                    Some(id) if Some(id) != stored => self.record_created(
                        &mut result,
                        platform,
                        &tenant,
                        &ExternalId::Text(id.to_owned()),
                    ),
                    Some(_) => {}
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                self.datadog_rule_failed(
                    &mut result,
                    rule,
                    &tenant,
                    &error,
                    recreate_refusal.as_ref(),
                );
                log.finished(result);
            }
            Err(error) => {
                return self.datadog_tenant_failed(connection, &tenant, &error, result, log);
            }
        }
        Ok(false)
    }

    /// A Datadog rule the tenant refused: what the deploy did before the
    /// failure, then the failure, a refused re-creation as its own.
    fn datadog_rule_failed(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        tenant: &str,
        error: &DeployError,
        recreate_refusal: Option<&StateError>,
    ) {
        let platform = opentide_compile::datadog::PLATFORM;
        if let Some(done) = &error.partial {
            self.datadog_done(&rule.uuid, tenant, done);
        }
        let failure = &error.failure;
        match recreate_refusal.filter(|refusal| refusal.code == failure.code) {
            Some(refusal) => {
                self.report_failure(refusal, &rule.uuid, platform, tenant);
                result.fail(&refusal.message);
            }
            None => {
                tracing::error!(
                    code = failure.code,
                    error = failure.message.as_str(),
                    detail = failure.field("detail"),
                    errors = failure.field("errors"),
                    uuid = rule.uuid.as_str(),
                    tenant,
                    "{}",
                    failure.code
                );
                self.rule_error(result, &format!("{}: {}", failure.code, failure.message));
            }
        }
    }

    /// A Datadog deploy the tenant failed on: the rule fails, an interrupt
    /// stops the run, and otherwise the tenant's other rules are not
    /// attempted (`true`). A failure before the tenant took anything leaves
    /// the rule `not attempted` too.
    fn datadog_tenant_failed(
        &mut self,
        connection: &Connection,
        tenant: &str,
        error: &DeployError,
        mut result: RuleResult,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        let platform = opentide_compile::datadog::PLATFORM;
        tracing::error!(
            code = error.failure.code,
            tenant,
            error = error.failure.message.as_str(),
            critical = true,
            "datadog_tenant_deployment_failed"
        );
        if self.before_any_rule(connection, platform, tenant, log) {
            self.unused(platform, tenant, log, &error.failure.message);
            return Ok(true);
        }
        self.failed = true;
        result.fail(&error.failure.message);
        log.finished(result);
        if self.interrupted() {
            return Err(Raised::new("interrupted").stopping(Stops::Run));
        }
        self.stop_tenant(platform, tenant, log);
        Ok(true)
    }

    /// What a Datadog deploy did, failed or not: its warnings, then what was
    /// done (an update names the properties it changed).
    fn datadog_done(&mut self, uuid: &str, tenant: &str, done: &DeployOutcome) {
        for warning in &done.warnings {
            self.warned = true;
            tracing::warn!(
                code = warning.code.as_str(),
                uuid,
                tenant,
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            let field = |name: &str| {
                event
                    .fields
                    .iter()
                    .find(|(key, _)| key == name)
                    .map_or("", |(_, value)| value.as_str())
            };
            tracing::info!(
                uuid,
                rule_id = field("rule_id"),
                changed = field("changed"),
                "{}",
                event.name
            );
        }
    }
}
