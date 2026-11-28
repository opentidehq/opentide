//! Exabeam New-Scale SIEM's sender (`ExabeamDeploy`): the [`Sender`]
//! methods that deploy the rules of `--platform exabeam`.

use opentide_compile::Json as CJson;
use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployScope, Deployer, TenantContext,
};
use opentide_schema::platforms::PlatformId;

use super::{
    Batch, Connection, DeployLog, Planned, Raised, RuleResult, Sender, Stops, TENANTS_AT_ONCE,
    operation_of, raised,
};
use crate::commands::deploy_state::{ExternalId, StateError};

impl Sender<'_, '_> {
    /// Exabeam New-Scale SIEM (`ExabeamDeploy`): each rule planned from
    /// deployment state, then created after a name check, updated (or
    /// disabled) by the recorded id, or deleted. A refused key, a tenant
    /// without the licence or with no answer stops its batch.
    pub(super) fn exabeam(
        &mut self,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let exabeam = opentide_connectors::exabeam::Exabeam::new();
        self.tenants(TENANTS_AT_ONCE, batches, log, |sender, batch, log| {
            sender.exabeam_tenant(&exabeam, batch, log)
        })
    }

    /// One tenant's rules of [`exabeam`](Self::exabeam).
    fn exabeam_tenant(
        &mut self,
        exabeam: &opentide_connectors::exabeam::Exabeam,
        batch: &Batch,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let platform = opentide_compile::exabeam::PLATFORM;
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
        // The credentials, then the sign-in, once: the rules reuse the
        // token (#1701).
        let opened = self
            .block(async { Ok(exabeam.open(context).await) })
            .map_err(DeployError::from)
            .and_then(|opened| opened);
        if let Err(error) = opened {
            // An unset credential variable, or a sign-in refused or never
            // answered: no rule on the tenant can deploy.
            let text = error.into_connector().text();
            tracing::error!(
                tenant = tenant.as_str(),
                error = text.as_str(),
                critical = true,
                "exabeam_tenant_deployment_failed"
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
            if self.exabeam_rule(&connection, batch, rule, &action, exabeam, log)? {
                break;
            }
        }
        Ok(())
    }

    /// An Exabeam rule the tenant refused: what the deploy did before the
    /// failure, then the failure, a refused re-creation as its own.
    fn exabeam_rule_failed(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        tenant: &str,
        error: &DeployError,
        recreate_refusal: Option<&StateError>,
        object_name: Option<&str>,
    ) {
        let platform = opentide_compile::exabeam::PLATFORM;
        if let Some(done) = &error.partial {
            self.exabeam_done(&rule.uuid, &rule.name, tenant, done);
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
                    existing_id = failure.field("existing_id"),
                    errors = failure.field("errors"),
                    trace_id = failure.field("trace_id"),
                    uuid = rule.uuid.as_str(),
                    tenant = tenant,
                    name = failure.field("name").or(object_name),
                    "{}",
                    failure.code
                );
                self.rule_error(result, &format!("{}: {}", failure.code, failure.message));
            }
        }
    }

    /// One Exabeam rule: compiled, sent, and its result logged. `true` when
    /// the tenant failed and the rest of its rules are left out.
    fn exabeam_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        exabeam: &opentide_connectors::exabeam::Exabeam,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        let platform = opentide_compile::exabeam::PLATFORM;
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
            // A delete sends no body.
            Ok(None)
        } else {
            use opentide_compile::compiler::{Compiler, Exabeam};
            // The dry run's compile ([`Compiler`]), so it shows this body.
            Exabeam::compile(self.compile, rule, Some(&batch.table))
                .map(|compiled| Some(Exabeam::body(&compiled)))
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
        // The update path's lines name the object; the create path's
        // name the Exabeam rule (the event carries it); a delete's none.
        let object_name = (!matches!(action, Planned::Delete(_))).then_some(rule.name.as_str());
        let context = self.context(connection);
        match self
            .block(async { Ok(exabeam.deploy(context, &request).await) })
            .map_err(|error| raised(&error))?
        {
            Ok(done) => {
                self.exabeam_done(&rule.uuid, &rule.name, &tenant, &done);
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
                self.exabeam_rule_failed(
                    &mut result,
                    rule,
                    &tenant,
                    &error,
                    recreate_refusal.as_ref(),
                    object_name,
                );
                log.finished(result);
            }
            Err(error) => {
                self.exabeam_tenant_failed(connection, &tenant, &error, result, log)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// An Exabeam deploy the tenant failed on: the rule fails, an interrupt
    /// stops the run, and otherwise the tenant's other rules are not
    /// attempted. A failure before the tenant took anything
    /// ([`Sender::before_any_rule`]) leaves the rule `not attempted` too.
    fn exabeam_tenant_failed(
        &mut self,
        connection: &Connection,
        tenant: &str,
        error: &DeployError,
        mut result: RuleResult,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let platform = PlatformId::Exabeam.as_str();
        tracing::error!(
            code = error.failure.code,
            tenant,
            error = error.failure.message.as_str(),
            critical = true,
            "exabeam_tenant_deployment_failed"
        );
        if self.before_any_rule(connection, platform, tenant, log) {
            // The sign-in or the connection failed on the tenant's first
            // request: no rule was sent (#1701).
            self.unused(platform, tenant, log, &error.failure.message);
            return Ok(());
        }
        self.failed = true;
        result.fail(&error.failure.message);
        log.finished(result);
        // An interrupt stops the run, not the tenant.
        if self.interrupted() {
            return Err(Raised::new("interrupted").stopping(Stops::Run));
        }
        self.stop_tenant(platform, tenant, log);
        Ok(())
    }

    /// What an Exabeam deploy did, failed or not: its warnings (the two
    /// about the deployed rule name it), then what was done.
    fn exabeam_done(&mut self, uuid: &str, name: &str, tenant: &str, done: &DeployOutcome) {
        for warning in &done.warnings {
            self.warned = true;
            let named = matches!(
                warning.code.as_str(),
                "exabeam_schedule_retained" | "exabeam_rule_auto_disabled"
            );
            tracing::warn!(
                code = warning.code.as_str(),
                uuid,
                tenant,
                name = named.then_some(name),
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            let rule_id = event
                .fields
                .iter()
                .find(|(key, _)| key == "rule_id")
                .map_or("", |(_, id)| id.as_str());
            tracing::info!(uuid, rule_id, "{}", event.name);
        }
    }
}
