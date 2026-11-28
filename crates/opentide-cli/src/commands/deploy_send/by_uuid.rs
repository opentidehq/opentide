//! The by-uuid senders (Sentinel, Microsoft Defender, Splunk, Carbon Black
//! Cloud, HarfangLab): the [`Sender`] methods that send a tenant's rules
//! addressed by their UUID, and the requests each platform's rule sends.

use opentide_compile::Json as CJson;
use opentide_compile::strategy::StatusStrategy;
use opentide_connectors::connector::{
    DeployError, DeployFailure, DeployOutcome, DeployRequest, Deployer, Operation, TenantContext,
};
use opentide_schema::platforms::PlatformId;

use super::{
    Batch, Connection, DeployLog, Raised, RuleResult, Sender, TENANTS_AT_ONCE, UNCHANGED,
    coded_failure, raised, resolved_table, unset_variable,
};

impl Sender<'_, '_> {
    /// Sentinel, Splunk, Carbon Black Cloud and HarfangLab: the rule's UUID
    /// (or name) addresses it, nothing is kept in deployment state.
    pub(super) fn by_uuid(
        &mut self,
        platform: &str,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        self.tenants(TENANTS_AT_ONCE, batches, log, |sender, batch, log| {
            sender.by_uuid_tenant(platform, batch, log)
        })
    }

    /// One tenant's rules of [`by_uuid`](Self::by_uuid).
    fn by_uuid_tenant(
        &mut self,
        platform: &str,
        batch: &Batch,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let cx = self.cx;
        let tenant = batch.tenant.name.clone();
        // The registry's engine opens the tenant and deploys its rules.
        let deployer = match cx
            .registry
            .get(platform)
            .and_then(opentide_connectors::Platform::deployer)
        {
            Some(deployer) => deployer,
            None => &NoOpen,
        };
        let Some(connection) = self.open_or_fail(platform, batch, log, deployer)? else {
            return Ok(());
        };
        for sent in &batch.rules {
            let rule = &sent.rule;
            // A HarfangLab tenant takes both kinds: each rule goes to the
            // endpoint of its own block's kind.
            if PlatformId::parse(platform) == Some(PlatformId::Harfanglab) {
                let block = rule.block(platform);
                if block.is_none() {
                    tracing::warn!(
                        detail = rule.name.as_str(),
                        "skipping_rule_no_harfanglab_config"
                    );
                    log.skipped(
                        platform,
                        &tenant,
                        &rule.uuid,
                        &rule.name,
                        "no HarfangLab configuration",
                    );
                    continue;
                }
                if opentide_compile::harfanglab::Kind::of(rule).is_none() {
                    log.skipped(
                        platform,
                        &tenant,
                        &rule.uuid,
                        &rule.name,
                        "neither a sigma nor a yara rule",
                    );
                    continue;
                }
            }
            let mut result = RuleResult::new(platform, Some(&tenant), &rule.uuid, &rule.name);
            connection.rule_begins();
            // Sentinel's `upsert` reads as what ARM did (OT-3).
            let upsert = log.planned_action(platform, Some(&tenant), &rule.uuid) == Some("upsert");
            let outcome =
                self.by_uuid_rule(platform, &connection, batch, rule, &mut result, upsert);
            if self.raised_before_any_rule(&connection, platform, &tenant, log, &outcome) {
                break;
            }
            if let Err(raised) = self.close(log, result, outcome) {
                self.tenant_failed(platform, &tenant, log, raised, true)?;
                break;
            }
        }
        Ok(())
    }

    fn deployer(
        &self,
        platform: &str,
    ) -> Result<&dyn opentide_connectors::connector::Deployer, Raised> {
        self.cx
            .registry
            .get(platform)
            .and_then(opentide_connectors::Platform::deployer)
            .ok_or_else(|| Raised::new(format!("Cannot find a deployment engine for {platform}")))
    }

    /// The request a Sentinel rule sends: the compiled analytic rule, or its
    /// deletion (announced).
    fn sentinel_request(
        &mut self,
        platform: &str,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        deletion: bool,
    ) -> Result<DeployRequest, Raised> {
        let tenant = batch.tenant.name.as_str();
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        // The engine is found before the rule compiles, as before.
        self.deployer(platform)?;
        Ok(if deletion {
            tracing::warn!(
                arg0 = rule.name.as_str(),
                "the_rule_will_be_removed_from_the_sentinel_workspace"
            );
            DeployRequest::delete(rule.uuid.clone())
        } else {
            use opentide_compile::compiler::{Compiler, Sentinel};
            // The dry run's compile ([`Compiler`]), so it shows this body.
            let compiled = Sentinel::compile(self.compile, rule, tenant).map_err(compile_error)?;
            let body = Sentinel::body(&compiled);
            let warnings = compiled.1;
            // Once per rule, not once per tenant: the body, and so the
            // warning, is the same on each.
            if !warnings.is_empty() && self.warn_once(rule.uuid.clone()) {
                self.warned = true;
                for (code, message) in warnings {
                    tracing::warn!(detail = message.as_str(), "{code}");
                }
            }
            DeployRequest::new(
                rule.uuid.clone(),
                Operation::Update,
                body.to_compact().into_bytes(),
            )
        })
    }

    /// The request a Microsoft Defender rule sends (microsoft-defender-1.0,
    /// Deploy): addressed by its Defender rule id, `opentide-` and its
    /// lowercase canonical uuid (#1886), with the compiled update body; a
    /// DELETION carries none. The objective's techniques
    /// left out of the alert's tactics are warned about once per rule.
    fn microsoft_defender_request(
        &mut self,
        platform: &str,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        strategy: StatusStrategy,
    ) -> Result<DeployRequest, Raised> {
        use opentide_compile::compiler::{Compiler, MicrosoftDefender};
        use opentide_compile::microsoft_defender::rule_id;
        let tenant = batch.tenant.name.as_str();
        self.deployer(platform)?;
        let id = rule_id(rule);
        if strategy == StatusStrategy::Deletion {
            return Ok(DeployRequest::delete(id));
        }
        // The body the dry run shows in its `PATCH` write.
        let compiled = MicrosoftDefender::compile(self.compile, rule, tenant)
            .map_err(|error| Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name)))?;
        let body = MicrosoftDefender::body(&compiled);
        let warnings = compiled.1;
        if !warnings.is_empty() && self.warn_once(format!("{platform}:{}", rule.uuid)) {
            self.warned = true;
            for (code, message) in warnings {
                tracing::warn!(detail = message.as_str(), "{code}");
            }
        }
        let operation = if strategy == StatusStrategy::Disablement {
            Operation::Disable
        } else {
            Operation::Update
        };
        Ok(DeployRequest::new(
            id,
            operation,
            body.to_compact().into_bytes(),
        ))
    }

    /// The request a Splunk rule sends: its saved search's settings under its
    /// name (` - Rule` for a correlation search), or its deletion.
    fn splunk_request(
        &self,
        platform: &str,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        deletion: bool,
    ) -> Result<DeployRequest, Raised> {
        use opentide_compile::compiler::{Compiler, Splunk, SplunkTarget};
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        // A schedule drawn at random takes its minute and hour from the
        // rule's UUID: the same on every deploy, so a rule redeployed as it
        // is stays unchanged on the tenant (#1711), and rules still spread
        // over the day.
        let clock = opentide_compile::splunk::Clock::for_rule(&rule.uuid, self.cx.now);
        // The writes the dry run shows; the settings sent are their updates.
        let compiled = Splunk::compile(
            self.compile,
            rule,
            SplunkTarget {
                tenant: &batch.table,
                clock: Some(clock),
            },
        )
        .map_err(compile_error)?;
        let mut name = rule.name.trim().to_owned();
        let correlation = match rule
            .block(platform)
            .and_then(|block| block.get("correlation_search"))
        {
            Some(CJson::Bool(set)) => *set,
            _ => opentide_compile::splunk::enterprise_security(&batch.table)
                .map_err(compile_error)?,
        };
        if correlation {
            name.push_str(" - Rule");
        }
        Ok(DeployRequest::new(
            name,
            if deletion {
                Operation::Delete
            } else {
                Operation::Update
            },
            if deletion {
                // A retirement names the rule too, so the connector deletes
                // the saved searches an earlier name of it left (#1657).
                let mut named = opentide_compile::json::Object::new();
                named.insert(
                    "description".into(),
                    opentide_compile::splunk::retired_description(rule).into(),
                );
                CJson::Object(named).to_compact().into_bytes()
            } else {
                Splunk::body(&compiled).to_compact().into_bytes()
            },
        ))
    }

    /// The request a Carbon Black Cloud rule sends: its report, retired when
    /// it is not deployed; `None` when the rule compiles to no report.
    fn carbon_black_request(
        &self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
    ) -> Result<Option<DeployRequest>, Raised> {
        use opentide_compile::compiler::{CarbonBlack, Compiler};
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        let table =
            resolved_table(&batch.table, &connection.tenant).map_err(|e| unset_variable(&e))?;
        let compiled = CarbonBlack::compile(self.compile, rule, &table).map_err(compile_error)?;
        let Some(report) = &compiled else {
            return Ok(None);
        };
        // The report's fields, as the Deployer reads them; a rule that
        // is not deployed retires its IOC.
        let operation = if report.deployment {
            Operation::Update
        } else {
            Operation::Delete
        };
        Ok(Some(
            DeployRequest::new(
                rule.uuid.clone(),
                operation,
                CarbonBlack::body(&compiled).to_compact().into_bytes(),
            )
            .at(self.cx.now),
        ))
    }

    /// The request a HarfangLab rule sends: its own kind and the rule
    /// compiled for it (`compiler::Harfanglab`); a delete names the kind.
    fn harfanglab_request(
        &self,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        deletion: bool,
    ) -> Result<DeployRequest, Raised> {
        use opentide_compile::compiler::{Compiler, Harfanglab};
        let compile_error = |error: opentide_compile::rule::CompileError| {
            Raised::new(format!("Rule {} ({}): {error}", rule.uuid, rule.name))
        };
        // The block's own kind picks the endpoint (platform-harfanglab 1.6).
        if opentide_compile::harfanglab::Kind::of(rule).is_none() {
            return Err(Raised::new(format!(
                "HarfangLab rule {} is neither a sigma nor a yara rule",
                rule.uuid
            )));
        }
        let table =
            resolved_table(&batch.table, &connection.tenant).map_err(|e| unset_variable(&e))?;
        // The write the dry run shows; the request sends its body.
        let compiled = Harfanglab::compile(self.compile, rule, &table).map_err(compile_error)?;
        if compiled.writes.is_empty() {
            return Err(Raised::new(format!(
                "HarfangLab compiled no request for rule {}",
                rule.uuid
            )));
        }
        let body = Harfanglab::body(&compiled);
        Ok(DeployRequest::new(
            rule.uuid.clone(),
            if deletion {
                Operation::Delete
            } else {
                Operation::Update
            },
            serde_json::to_vec(&body).unwrap_or_default(),
        ))
    }

    fn by_uuid_rule(
        &mut self,
        platform: &str,
        connection: &Connection,
        batch: &Batch,
        rule: &opentide_compile::Rule,
        result: &mut RuleResult,
        upsert: bool,
    ) -> Result<(), Raised> {
        let strategy = self.strategy_of(rule, platform)?;
        let deletion = strategy == StatusStrategy::Deletion;
        let id = PlatformId::parse(platform);
        let request = match id {
            Some(PlatformId::Sentinel) => self.sentinel_request(platform, batch, rule, deletion)?,
            Some(PlatformId::MicrosoftDefender) => {
                self.microsoft_defender_request(platform, batch, rule, strategy)?
            }
            Some(PlatformId::Splunk) => self.splunk_request(platform, batch, rule, deletion)?,
            Some(PlatformId::CarbonBlackCloud) => {
                match self.carbon_black_request(connection, batch, rule)? {
                    Some(request) => request,
                    None => return Ok(()),
                }
            }
            _ => self.harfanglab_request(connection, batch, rule, deletion)?,
        };
        let deployer = self.deployer(platform)?;
        let context = self.context(connection);
        let answer = self
            .block(async { Ok(deployer.deploy(context, &request).await) })
            .map_err(|error| raised(&error))?;
        let answer = match answer {
            // A DELETION whose rule id the tenant does not have. Not "already
            // gone": a rule opentide 1.0.0 deployed under the bare uuid may
            // still run there (#1886).
            Err(failed)
                if id == Some(PlatformId::MicrosoftDefender)
                    && deletion
                    && failed.failure.status == Some(404) =>
            {
                result.skip(&format!(
                    "no rule {} on the tenant",
                    opentide_compile::microsoft_defender::rule_id_of(&rule.uuid)
                ));
                return Ok(());
            }
            other => other,
        };
        let (outcome, failed) = match answer {
            Ok(outcome) => (outcome, None),
            // What the deploy did before it failed (the old saved searches
            // a Splunk rule's cleanup deleted) is still reported.
            Err(mut failed) => {
                let done = failed
                    .partial
                    .take()
                    .map(|done| *done)
                    .unwrap_or_else(|| DeployOutcome::new(None, request.operation));
                (done, Some(failed))
            }
        };
        for warning in &outcome.warnings {
            match id {
                // `splunk_alert_deleted`: the saved search the tenant had;
                // `splunk_renamed_search_deleted`: one an earlier name of
                // the rule left, which the result lists (#1657).
                Some(PlatformId::Splunk) => {
                    tracing::warn!(name = warning.message.as_str(), "{}", warning.code);
                    if warning.code == opentide_connectors::splunk::RENAMED_DELETED {
                        result.removed.push(warning.message.clone());
                    }
                }
                // `report_deleted_with_rule`, `report_auto_deleted`: said, not raised.
                Some(PlatformId::CarbonBlackCloud) => {
                    tracing::warn!(report = warning.message.as_str(), "{}", warning.code);
                }
                // `microsoft_defender_rule_absent`: a DISABLEMENT found no
                // rule with the rule id; nothing was created.
                Some(PlatformId::MicrosoftDefender) => {
                    self.warned |= warning.raised;
                    tracing::warn!(detail = warning.message.as_str(), "{}", warning.code);
                    if warning.code == opentide_connectors::microsoft_defender::RULE_ABSENT {
                        result.skip("not on the tenant: nothing to disable");
                    }
                }
                _ => {}
            }
        }
        // The tenant already held it: nothing was written (#1711). A
        // rename's cleanup may still have deleted old copies (`removed`).
        if failed.is_none() && outcome.unchanged() {
            result.action = Some(UNCHANGED.to_owned());
        } else if failed.is_none() && id == Some(PlatformId::MicrosoftDefender) && upsert {
            // Defender's `PATCH` first (microsoft-defender-1.0, Deploy): an
            // `upsert` reads as what Graph did, a create after a `404` or an
            // update.
            if let Some(action) =
                outcome
                    .events
                    .iter()
                    .find_map(|event| match event.name.as_str() {
                        opentide_connectors::microsoft_defender::RULE_CREATED => Some("create"),
                        opentide_connectors::microsoft_defender::RULE_UPDATED => Some("update"),
                        _ => None,
                    })
            {
                result.action = Some(action.to_owned());
            }
        } else if failed.is_none() && id == Some(PlatformId::Sentinel) && upsert {
            // Sentinel reads before it writes (OT-3): an `upsert` reads as
            // what ARM did, a create or an update; none found keeps the plan's.
            if let Some(action) =
                outcome
                    .events
                    .iter()
                    .find_map(|event| match event.name.as_str() {
                        opentide_connectors::sentinel::RULE_CREATED => Some("create"),
                        opentide_connectors::sentinel::RULE_UPDATED => Some("update"),
                        _ => None,
                    })
            {
                result.action = Some(action.to_owned());
            }
        }
        failed.map_or(Ok(()), |failed| Err(coded_failure(failed)))
    }
}

/// A platform with no engine opens nothing: its first rule says so
/// (`Sender::deployer`).
struct NoOpen;

impl Deployer for NoOpen {
    fn deploy<'a>(
        &'a self,
        _cx: TenantContext<'a>,
        _request: &'a DeployRequest,
    ) -> opentide_connectors::connector::BoxFuture<'a, Result<DeployOutcome, DeployError>> {
        Box::pin(async {
            Err(DeployError::rule(DeployFailure::new(
                "deployer_missing",
                "no deployment engine",
            )))
        })
    }
}
