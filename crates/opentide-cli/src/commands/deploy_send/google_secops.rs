//! Google Security Operations' sender (`GoogleSecopsDeploy`): the [`Sender`]
//! methods that deploy the rules of `--platform google_secops`.

use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployScope, Deployer,
};
use opentide_connectors::tenant_codes;
use opentide_schema::platforms::PlatformId;

use super::{
    Batch, Connection, DeployLog, Planned, Raised, RuleResult, Sender, Stops, TENANTS_AT_ONCE,
    operation_of,
};
use crate::commands::deploy_state::{ExternalId, StateError};

impl Sender<'_, '_> {
    /// Google Security Operations: each rule verified, created, updated,
    /// disabled, archived or deleted by the id deployment state records
    /// (`GoogleSecopsDeploy`). Credentials that cannot be loaded, refused
    /// credentials or an instance that cannot be reached stop the tenant.
    pub(super) fn google_secops(
        &mut self,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let connector =
            opentide_connectors::google_secops::GoogleSecops::new(self.environment.clone());
        self.tenants(TENANTS_AT_ONCE, batches, log, |sender, batch, log| {
            sender.google_secops_tenant(&connector, batch, log)
        })
    }

    /// One tenant's rules of [`google_secops`](Self::google_secops).
    fn google_secops_tenant(
        &mut self,
        connector: &opentide_connectors::google_secops::GoogleSecops,
        batch: &Batch,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        use opentide_connectors::google_secops::Instance;
        let platform = PlatformId::GoogleSecops.as_str();
        let tenant = batch.tenant.name.clone();
        let planned = self.screen(platform, batch, log);
        if planned.is_empty() {
            return Ok(());
        }
        let Some(connection) = self.connect_or_fail(platform, batch, log)? else {
            return Ok(());
        };
        // The instance and credentials, then the sign-in, once: the
        // rules reuse the token (#1701).
        let ready = Instance::of(&connection.tenant)
            .and_then(|_| connector.authorizer(&connection.tenant))
            .and_then(|_| {
                self.block(async {
                    Ok(connector
                        .open(self.context(&connection))
                        .await
                        .map_err(DeployError::into_connector))
                })
                .and_then(|opened| opened)
            });
        match ready {
            Ok(()) => connection.mark_opened(),
            Err(error) => {
                // Unset or unreadable credentials: no rule on the tenant can deploy.
                let text = error.text();
                self.google_secops_tenant_failed(&tenant, &text);
                self.unusable(platform, Some(&tenant), &text);
                log.unreached_on(
                    platform,
                    &tenant,
                    "not_attempted",
                    &format!("not attempted: tenant {tenant} failed"),
                );
                return Ok(());
            }
        }
        for (rule, action) in planned {
            connection.rule_begins();
            if self.google_secops_rule(&connection, batch, rule, &action, connector, log)? {
                break;
            }
        }
        Ok(())
    }

    /// A Google SecOps rule the tenant refused: what the deploy did before
    /// the failure, then each failure, a refused re-creation as its own.
    fn google_secops_rule_failed(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        tenant: &str,
        stored: Option<&str>,
        error: &DeployError,
        recreate_refusal: Option<&StateError>,
    ) {
        let platform = PlatformId::GoogleSecops.as_str();
        if let Some(done) = &error.partial {
            self.google_secops_done(result, &rule.uuid, tenant, done, stored);
            // A rule to retire that the tenant lost: its id
            // is forgotten, before the failure that preceded it.
            if done
                .warnings
                .iter()
                .any(|warning| warning.code == "google_secops_rule_missing")
            {
                self.record_deleted(result, platform, tenant);
            }
        }
        for failure in std::iter::once(&error.failure).chain(&error.more) {
            match recreate_refusal.filter(|refusal| refusal.code == failure.code) {
                Some(refusal) => {
                    self.report_failure(refusal, &rule.uuid, platform, tenant);
                    result.fail(&refusal.message);
                }
                None => {
                    tracing::error!(
                        uuid = rule.uuid.as_str(),
                        tenant = tenant,
                        name = rule.name.as_str(),
                        code = failure.code,
                        error = failure.message.as_str(),
                        "{}",
                        failure.code
                    );
                    self.rule_error(result, &format!("{}: {}", failure.code, failure.message));
                }
            }
        }
    }

    /// One Google SecOps rule: compiled, sent, and its result logged. `true`
    /// when the tenant failed and the rest of its rules are left out.
    fn google_secops_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        connector: &opentide_connectors::google_secops::GoogleSecops,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        let platform = PlatformId::GoogleSecops.as_str();
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(platform, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = match self.strategy_of(rule, platform) {
            Ok(strategy) => strategy,
            Err(raised) => {
                self.close(log, result, Err(raised))?;
                return Ok(false);
            }
        };
        // The plan's payload: the text, and the run state, run
        // frequency and sections the deploy reads beside it.
        let payload = match opentide_compile::google_secops::compile_deployment(self.compile, rule)
        {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(
                    uuid = rule.uuid.as_str(),
                    tenant = tenant.as_str(),
                    name = rule.name.as_str(),
                    error = error.reason.as_str(),
                    "compile_failed"
                );
                self.rule_error(&mut result, &format!("compile_failed: {}", error.reason));
                log.finished(result);
                return Ok(false);
            }
        };
        let recreate_refusal = self.recreate_refusal(&rule.uuid, platform, &tenant);
        let (operation, stored) = operation_of(action, strategy);
        let body = match serde_json::to_vec(&payload) {
            Ok(body) => body,
            Err(error) => {
                self.rule_error(&mut result, &format!("compile_failed: {error}"));
                log.finished(result);
                return Ok(false);
            }
        };
        let mut request = DeployRequest::new(stored.unwrap_or_default(), operation, body);
        if let Some(refusal) = &recreate_refusal {
            request = request
                .refusing_recreate(DeployFailure::new(refusal.code, refusal.message.clone()));
        }
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(connector.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                self.google_secops_done(&mut result, &rule.uuid, &tenant, &done, stored);
                if done.remote_id.is_none() {
                    self.record_deleted(&mut result, platform, &tenant);
                }
                log.finished(result);
            }
            Err(error) if error.scope == DeployScope::Rule => {
                self.google_secops_rule_failed(
                    &mut result,
                    rule,
                    &tenant,
                    stored,
                    &error,
                    recreate_refusal.as_ref(),
                );
                log.finished(result);
            }
            Err(error) => {
                // Refused credentials or an unreachable instance fail every rule on it.
                let before_any = self.before_any_rule(connection, platform, &tenant, log);
                let text = error.into_connector().text();
                self.google_secops_tenant_failed(&tenant, &text);
                if before_any {
                    // The sign-in or the connection failed on the tenant's
                    // first request: no rule was sent (#1701).
                    self.unused(platform, &tenant, log, &text);
                    return Ok(true);
                }
                result.fail(&text);
                log.finished(result);
                // An interrupt stops the run, not the tenant.
                if self.interrupted() {
                    return Err(Raised::new("interrupted").stopping(Stops::Run));
                }
                self.stop_tenant(PlatformId::GoogleSecops.as_str(), &tenant, log);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// What a Google SecOps deploy did, failed or not: its warnings, then the
    /// id of a rule it created (`google_secops_rule_created`), recorded when
    /// it is not the `stored` one.
    fn google_secops_done(
        &mut self,
        result: &mut RuleResult,
        uuid: &str,
        tenant: &str,
        done: &DeployOutcome,
        stored: Option<&str>,
    ) {
        const PLATFORM: &str = PlatformId::GoogleSecops.as_str();
        for warning in &done.warnings {
            self.warned = true;
            tracing::warn!(
                uuid,
                tenant,
                code = warning.code.as_str(),
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
        if let Some(id) = done.remote_id.as_deref().filter(|id| Some(*id) != stored) {
            self.record_created(result, PLATFORM, tenant, &ExternalId::Text(id.to_owned()));
        }
    }

    /// A Google SecOps tenant no rule can deploy to (`_tenant_failed`): its
    /// code (`google_secops_credentials_missing`,
    /// `google_secops_tenant_unauthorized`) when the error names one, else
    /// `google_secops_tenant_unreachable`.
    fn google_secops_tenant_failed(&mut self, tenant: &str, text: &str) {
        let code = text
            .split_once(": ")
            .map(|(code, _)| code)
            .filter(|code| code.starts_with("google_secops_") && !code.contains(' '))
            .unwrap_or(tenant_codes::GOOGLE_SECOPS.unreachable);
        tracing::error!(
            code,
            tenant,
            error = text,
            critical = true,
            "google_secops_tenant_deployment_failed"
        );
        self.failed = true;
    }
}
