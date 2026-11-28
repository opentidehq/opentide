//! Elastic Security's sender (`ElasticDeploy`): the [`Sender`] methods that
//! deploy the rules of `--platform elastic`, and what a tenant's rules share.

use opentide_compile::Json as CJson;
use opentide_compile::strategy::StatusStrategy;
use opentide_connectors::connector::{
    DeployError, DeployOutcome, DeployRequest, DeployScope, Deployer, Operation,
};
use opentide_schema::platforms::PlatformId;

use super::{
    Batch, Connection, DeployLog, Raised, RuleResult, Sender, Stops, TENANTS_AT_ONCE, UNCHANGED,
    raised,
};
use crate::json::Json;

impl Sender<'_, '_> {
    /// Elastic: each rule deleted, or checked then created or updated; a
    /// tenant that refuses the key stops its batch (`ElasticDeploy`).
    pub(super) fn elastic(
        &mut self,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        self.tenants(TENANTS_AT_ONCE, batches, log, Self::elastic_tenant)
    }

    /// One tenant's rules of [`elastic`](Self::elastic).
    fn elastic_tenant(&mut self, batch: &Batch, log: &mut DeployLog<'_>) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Elastic.as_str();
        let opener = opentide_connectors::elastic::Elastic;
        let Some(connection) = self.open_or_fail(PLATFORM, batch, log, &opener)? else {
            return Ok(());
        };
        let mut tenant_state = ElasticTenant {
            suppression_off: matches!(
                opentide_compile::deploy::setup(&batch.table, "suppression"),
                Some(CJson::Bool(false))
            ),
            warned_rules: Vec::new(),
        };
        for sent in &batch.rules {
            connection.rule_begins();
            if self.elastic_rule(&connection, batch, &sent.rule, &mut tenant_state, log)? {
                break;
            }
        }
        Ok(())
    }

    /// An Elastic deploy the tenant failed on (unreachable, or a key or
    /// privilege it refuses): the rule fails, an interrupt stops the run, and
    /// otherwise the tenant's other rules are not attempted.
    fn elastic_tenant_failed(
        &mut self,
        connection: &Connection,
        error: DeployError,
        mut result: RuleResult,
        tenant: &str,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        const PLATFORM: &str = PlatformId::Elastic.as_str();
        let before_any = self.before_any_rule(connection, PLATFORM, tenant, log);
        let stopped = match error.connector {
            // The tenant could not be reached.
            Some(connector) => {
                result.fail(&raised(&connector).describe());
                connector.to_string()
            }
            // A key or privilege the tenant refuses.
            None => {
                result.fail(&error.failure.message);
                error.failure.message
            }
        };
        tracing::error!(
            tenant = tenant,
            error = stopped.as_str(),
            critical = true,
            "elastic_tenant_deployment_failed"
        );
        if before_any {
            // The key or the connection failed on the tenant's first
            // request: no rule was sent (#1701).
            self.unused(PLATFORM, tenant, log, &stopped);
            return Ok(());
        }
        log.finished(result);
        // An interrupt stops the run, not the tenant.
        if self.interrupted() {
            return Err(Raised::new("interrupted").stopping(Stops::Run));
        }
        self.stop_tenant(PlatformId::Elastic.as_str(), tenant, log);
        Ok(())
    }

    /// One Elastic rule: screened by its status, compiled, sent, and its
    /// result logged. `true` when the tenant failed and the rest of its rules
    /// are left out.
    fn elastic_rule(
        &mut self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        tenant_state: &mut ElasticTenant,
        log: &mut DeployLog<'_>,
    ) -> Result<bool, Raised> {
        const PLATFORM: &str = PlatformId::Elastic.as_str();
        use opentide_connectors::elastic::{Elastic, FAILURE_EVENTS};
        let tenant = batch.tenant.name.clone();
        let mut result = RuleResult::new(PLATFORM, Some(&tenant), &rule.uuid, &rule.name);
        let Some(raw) = rule.block(PLATFORM).filter(|block| block.is_filled()) else {
            result.skip("no Elastic configuration");
            log.finished(result);
            return Ok(false);
        };
        let status = raw.get("status").map(Json::to_text).unwrap_or_default();
        let strategy = match self.compile.statuses.strategy(&status) {
            Ok(strategy) => strategy,
            Err(error) => {
                self.rule_error(&mut result, &error.to_string());
                log.finished(result);
                return Ok(false);
            }
        };
        if strategy == StatusStrategy::Inert {
            result.skip(&format!("status {status} is inert"));
            log.finished(result);
            return Ok(false);
        }
        let request = match self.elastic_request(rule, raw, strategy, tenant_state, batch) {
            Ok(request) => request,
            Err(text) => {
                self.rule_error(&mut result, &text);
                log.finished(result);
                return Ok(false);
            }
        };
        let context = self.context(connection);
        let deployed = self
            .block(async { Ok(Elastic.deploy(context, &request).await) })
            .unwrap_or_else(|error| {
                let mut failed = DeployError::from(error);
                failed.scope = DeployScope::Tenant;
                Err(failed)
            });
        match deployed {
            Ok(done) => {
                self.elastic_warnings(rule, &done);
                // An `upsert` reads as what Kibana did: a create, or an
                // update (#1662, E10); a rule Kibana already held as it is,
                // whatever the plan, is unchanged (#1711).
                if done.unchanged() {
                    result.action = Some(UNCHANGED.to_owned());
                } else if log.planned_action(PLATFORM, Some(&tenant), &rule.uuid) == Some("upsert")
                {
                    result.action = elastic_done_action(&done).map(str::to_owned);
                }
                log.finished(result);
            }
            // The rule itself failed: the other rules go on.
            Err(error) if error.scope == DeployScope::Rule => {
                if let Some(done) = &error.partial {
                    self.elastic_warnings(rule, done);
                }
                let failure = &error.failure;
                if FAILURE_EVENTS.contains(&failure.code) {
                    self.elastic_failure(
                        &mut result,
                        rule,
                        failure.code,
                        failure.status,
                        &failure.message,
                    );
                } else {
                    self.rule_error(&mut result, &failure.message);
                }
                log.finished(result);
            }
            Err(error) if error.is_interrupted() => {
                result.fail("interrupted");
                log.finished(result);
                self.failed = true;
                tracing::error!(
                    tenant = tenant.as_str(),
                    error = "interrupted",
                    critical = true,
                    "elastic_tenant_deployment_failed"
                );
                return Err(Raised::new("interrupted").stopping(Stops::Run));
            }
            Err(error) => {
                self.elastic_tenant_failed(connection, error, result, &tenant, log)?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The request an Elastic rule sends, compiled for its tenant as the dry
    /// run compiles it (`compiler::Elastic`; a deletion compiles nothing),
    /// after its warnings: suppression the tenant's licence omits, techniques
    /// outside the enterprise matrix. `Err` is the reason the rule fails.
    fn elastic_request(
        &mut self,
        rule: &opentide_compile::Rule,
        raw: &CJson,
        strategy: StatusStrategy,
        tenant_state: &mut ElasticTenant,
        batch: &Batch,
    ) -> Result<DeployRequest, String> {
        use opentide_compile::compiler::{Compiler, Elastic};
        let tenant = batch.tenant.name.as_str();
        let block = opentide_compile::preview::config_dump(PlatformId::Elastic, raw);
        if strategy != StatusStrategy::Deletion
            && tenant_state.suppression_off
            && block
                .get("suppression")
                .is_some_and(|value| !value.is_null())
            && !tenant_state.warned_rules.contains(&rule.uuid)
        {
            self.warned = true;
            tracing::warn!(
                rule = rule.name.as_str(),
                rule_id = rule.uuid.as_str(),
                tenant,
                "suppression_omitted_basic_license"
            );
            tenant_state.warned_rules.push(rule.uuid.clone());
        }
        let compiled = if strategy == StatusStrategy::Deletion {
            None
        } else {
            match Elastic::compile(self.compile, rule, Some(&batch.table)) {
                Ok(compiled) => Some(compiled),
                Err(error) => {
                    return Err(format!("Rule {} ({}): {error}", rule.uuid, rule.name));
                }
            }
        };
        let non_enterprise = strategy != StatusStrategy::Deletion
            && opentide_compile::elastic::rule_techniques(self.compile, rule)
                .iter()
                .any(|id| {
                    self.compile
                        .attack
                        .name(id)
                        .is_some_and(opentide_compile::attack::non_enterprise)
                });
        if non_enterprise {
            self.warned = true;
        }
        Ok(match compiled {
            None => DeployRequest::delete(rule.uuid.clone()),
            Some(compiled) => {
                // The body the dry run shows for it.
                let body = Elastic::body(&compiled);
                let operation = if strategy == StatusStrategy::Disablement {
                    Operation::Disable
                } else {
                    Operation::Update
                };
                match serde_json::to_vec(&body) {
                    Ok(body) => DeployRequest::new(rule.uuid.clone(), operation, body),
                    Err(error) => {
                        return Err(format!("the compiled rule is not JSON: {error}"));
                    }
                }
            }
        })
    }

    /// The Elasticsearch checks' warnings of an Elastic deploy, failed or not.
    fn elastic_warnings(&mut self, rule: &opentide_compile::Rule, done: &DeployOutcome) {
        for warning in &done.warnings {
            if warning.code != opentide_connectors::elastic::CHECK_WARNING {
                continue;
            }
            self.warned = true;
            tracing::warn!(
                rule_id = rule.uuid.as_str(),
                rule = rule.name.as_str(),
                warning = warning.message.as_str(),
                "elasticsearch_check_warning"
            );
        }
    }

    /// `_deployment_error` for an Elastic rule, with the fields its event logs.
    fn elastic_failure(
        &mut self,
        result: &mut RuleResult,
        rule: &opentide_compile::Rule,
        event: &str,
        status: Option<u16>,
        error: &str,
    ) {
        let rule_id = rule.uuid.as_str();
        match (event, status) {
            ("elasticsearch_checks_failed", _) => {
                tracing::error!(rule_id, rule = rule.name.as_str(), error, "{}", event);
            }
            ("refusing_to_modify_prebuilt_rule", _) => {
                tracing::error!(rule_id, name = rule.name.as_str(), "{}", event);
            }
            (_, Some(status)) => {
                tracing::error!(rule_id, status_code = status, error, "{}", event);
            }
            (_, None) => tracing::error!(rule_id, error, "{}", event),
        }
        if event == "recreate_elastic_rule_failed" {
            tracing::error!(rule_id, "elastic_rule_deleted_not_recreated");
        }
        let message = match status {
            Some(status) => format!("HTTP {status}: {error}"),
            None if event == "refusing_to_modify_prebuilt_rule" => event.replace('_', " "),
            None => error.to_owned(),
        };
        self.rule_error(result, &message);
    }
}

/// What an Elastic deploy did to a rule, as a plan's action: `create` for a
/// rule Kibana did not have, `update` for one it replaced or recreated.
fn elastic_done_action(done: &DeployOutcome) -> Option<&'static str> {
    done.events
        .iter()
        .find_map(|event| match event.name.as_str() {
            "elastic_rule_created" => Some("create"),
            "elastic_rule_updated" | "elastic_rule_recreated" => Some("update"),
            _ => None,
        })
}

/// What an Elastic tenant's rules share: whether it turns suppression off,
/// and the rules already warned about that.
struct ElasticTenant {
    suppression_off: bool,
    warned_rules: Vec<String>,
}
