//! Bitdefender GravityZone's sender (`BitdefenderDeploy`): the [`Sender`]
//! methods that deploy the rules of `--platform bitdefender`.

use opentide_compile::Json as CJson;
use opentide_compile::strategy::StatusStrategy;
use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, DeployScope, Deployer,
};
use opentide_schema::platforms::PlatformId;

use super::{
    Batch, Connection, DeployLog, Planned, Raised, RuleResult, Sender, TENANTS_AT_ONCE,
    operation_of,
};
use crate::commands::deploy_state::{self, ExternalId, StateError};

impl Sender<'_, '_> {
    /// Bitdefender GravityZone: each rule planned from deployment state,
    /// compiled for the tenant (its targets resolved), then created (its id
    /// recorded), updated or disabled with the whole payload, or deleted
    /// (its id forgotten) (`BitdefenderDeploy.deploy_tenant`).
    pub(super) fn bitdefender(
        &mut self,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        self.tenants(TENANTS_AT_ONCE, batches, log, Self::bitdefender_tenant)
    }

    /// One tenant's rules of [`bitdefender`](Self::bitdefender).
    fn bitdefender_tenant(&mut self, batch: &Batch, log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Bitdefender.as_str();
        let planned = self.screen(PLATFORM, batch, log);
        let planned = self.bitdefender_yara_limit(batch, planned, log);
        if planned.is_empty() {
            return Ok(());
        }
        let opener = opentide_connectors::bitdefender::Bitdefender;
        let Some(connection) = self.open_or_fail(PLATFORM, batch, log, &opener)? else {
            return Ok(());
        };
        // A value that is not a boolean fails each rule `compile_rule` compiles,
        // naming the key; a deletion compiles nothing and sends no actions.
        let automatic =
            opentide_compile::bitdefender::automatic_actions_on(&batch.table).unwrap_or(true);
        for (rule, action) in planned {
            connection.rule_begins();
            if self.bitdefender_rule(&connection, batch, rule, &action, automatic, log)? {
                break;
            }
        }
        Ok(())
    }

    /// The request a Bitdefender rule sends: a delete names the recorded id
    /// alone; anything else sends the compiled rule's `params`, and says when
    /// the tenant runs no automatic actions while the rule has some.
    fn bitdefender_request(
        &self,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        strategy: StatusStrategy,
        automatic: bool,
    ) -> Result<DeployRequest, opentide_compile::rule::CompileError> {
        use opentide_compile::bitdefender::{compile_rule, create_params};
        const PLATFORM: &str = PlatformId::Bitdefender.as_str();
        if let Planned::Delete(id) = action {
            // A delete sends the recorded id alone.
            return Ok(DeployRequest::delete(id.clone()));
        }
        let (operation, stored) = operation_of(action, strategy);
        let actions_unsupported = !automatic
            && rule
                .block(PLATFORM)
                .and_then(|block| block.get("actions"))
                .is_some_and(|actions| !actions.is_null());
        let compiled = compile_rule(self.compile, rule, strategy, Some(&batch.table))?;
        let mut body = opentide_compile::json::Object::new();
        body.insert("params".into(), create_params(&compiled));
        if actions_unsupported {
            body.insert("actions_unsupported".into(), CJson::Bool(true));
        }
        Ok(DeployRequest::new(
            stored.unwrap_or_default(),
            operation,
            serde_json::to_vec(&CJson::Object(body)).unwrap_or_default(),
        ))
    }

    /// One Bitdefender rule: compiled, sent, and its result logged. `true` when
    /// the tenant failed and the rest of its rules are left out.
    fn bitdefender_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        action: &Planned,
        automatic: bool,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        use opentide_connectors::bitdefender::Bitdefender;
        const PLATFORM: &str = PlatformId::Bitdefender.as_str();
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        let strategy = match self.strategy_of(rule, PLATFORM) {
            Ok(strategy) => strategy,
            Err(raised) => {
                self.close(log, result, Err(raised.clone()))?;
                return Ok(false);
            }
        };
        let (_, stored) = operation_of(action, strategy);
        let mut request = match self.bitdefender_request(batch, rule, action, strategy, automatic) {
            Ok(request) => request,
            Err(error) => {
                let message = format!("{}: {}", error.code, error.reason);
                tracing::error!(
                    code = error.code,
                    uuid = rule.uuid.as_str(),
                    tenant = tenant.as_str(),
                    name = rule.name.as_str(),
                    error = message.as_str(),
                    "{}",
                    error.code
                );
                self.rule_error(&mut result, &message);
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
            .block(async { Ok(Bitdefender.deploy(context, &request).await) })
            .unwrap_or_else(|error| Err(DeployError::from(error)));
        match deployed {
            Ok(done) => {
                self.bitdefender_done(&rule.uuid, &tenant, &done);
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
                if let Some(done) = &error.partial {
                    self.bitdefender_done(&rule.uuid, &tenant, done);
                }
                let failure = &error.failure;
                if let Some(refusal) = recreate_refusal
                    .as_ref()
                    .filter(|refusal| refusal.code == failure.code)
                {
                    self.report_failure(refusal, &rule.uuid, PLATFORM, &tenant);
                    self.failed = true;
                    result.fail(&refusal.message);
                } else {
                    tracing::error!(
                        code = failure.code,
                        uuid = rule.uuid.as_str(),
                        tenant = tenant.as_str(),
                        error = failure.message.as_str(),
                        detail = failure.field("detail").unwrap_or_default(),
                        "{}",
                        failure.code
                    );
                    self.rule_error(
                        &mut result,
                        &format!("{}: {}", failure.code, failure.message),
                    );
                }
                log.finished(result);
            }
            Err(error) => {
                self.tenant_deploy_failed(
                    connection,
                    PlatformId::Bitdefender.as_str(),
                    "bitdefender_tenant_deployment_failed",
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

    /// What a Bitdefender deploy did, failed or not: its warnings (the
    /// unraised ones only said), then what was done.
    fn bitdefender_done(&mut self, uuid: &str, tenant: &str, done: &DeployOutcome) {
        for warning in &done.warnings {
            if warning.raised {
                self.warned = true;
            }
            tracing::warn!(
                uuid,
                tenant,
                detail = warning.message.as_str(),
                "{}",
                warning.code
            );
        }
        for event in &done.events {
            match event.fields.iter().find(|(key, _)| key == "rule_id") {
                Some((_, rule_id)) => {
                    tracing::info!(uuid, rule_id = rule_id.as_str(), "{}", event.name);
                }
                None => tracing::info!(uuid, "{}", event.name),
            }
        }
    }

    /// GravityZone's cap on YARA rules per company: when the YARA rules
    /// deployment state records on the tenant plus those the run creates pass
    /// the limit, each YARA create is refused before anything is sent.
    /// Updates and deletes go on; a deletion makes no room in the same run,
    /// since the rules are sent in plan order. A recorded rule is counted by
    /// the kind its workspace block has now; one the workspace no longer
    /// holds, or whose block does not read, is not counted.
    fn bitdefender_yara_limit<'b>(
        &mut self,
        batch: &Batch,
        planned: Vec<(&'b opentide_compile::Rule, Planned)>,
        log: &mut DeployLog<'_>,
    ) -> Vec<(&'b opentide_compile::Rule, Planned)> {
        use opentide_compile::bitdefender::{
            PLATFORM, YARA_RULE_LIMIT_CODE, is_yara, yara_rule_limit,
        };
        let tenant = batch.tenant.name.as_str();
        let created = planned
            .iter()
            .filter(|(rule, action)| matches!(action, Planned::Create) && is_yara(rule))
            .count();
        if created == 0 {
            return planned;
        }
        let root = self.workspace.root().to_path_buf();
        let recorded = deploy_state::recorded(&root, PLATFORM, tenant)
            .iter()
            .filter(|uuid| {
                crate::commands::validate_live::rule_of(self.workspace, uuid)
                    .is_some_and(|rule| is_yara(&rule))
            })
            .count();
        let Some(message) = yara_rule_limit(tenant, recorded, created) else {
            return planned;
        };
        let error = StateError {
            code: YARA_RULE_LIMIT_CODE,
            message,
        };
        planned
            .into_iter()
            .filter(|(rule, action)| {
                let refused = matches!(action, Planned::Create) && is_yara(rule);
                if refused {
                    self.report_failure(&error, &rule.uuid, PLATFORM, tenant);
                    log.refused(PLATFORM, tenant, &rule.uuid, &rule.name, &error.message);
                }
                !refused
            })
            .collect()
    }
}
