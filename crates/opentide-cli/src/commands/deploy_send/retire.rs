//! `--prune`'s retirements: the [`Sender`] methods that delete the rules
//! whose file is gone, tenant by tenant.

use opentide_compile::Json as CJson;
use opentide_compile::plan;
use opentide_connectors::connector::{DeployRequest, Deployer, Operation};
use opentide_schema::platforms::{PlatformId, PlatformKey};

use super::{
    Connection, DeployLog, Raised, RuleResult, Sender, coded_failure, raised, tenant_batch,
};

impl Sender<'_, '_> {
    /// The rules of *platform* whose file is gone, retired tenant by tenant
    /// (`--prune`, #1713): each a delete through the platform's `Deployer`,
    /// by the id deployment state records (then forgotten) or, on a platform
    /// that keeps none, by the rule's UUID or Splunk name. A platform that
    /// cannot retire a deleted rule skips it and says why; a rule the
    /// tenant no longer has (`404`) is skipped as already gone.
    pub(super) fn retire(
        &mut self,
        platform: &str,
        retirements: &[&super::deploy_retire::Retirement],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        use super::deploy_retire::Request;
        let mut tenants: Vec<&str> = Vec::new();
        for retirement in retirements {
            if !tenants.contains(&retirement.tenant.as_str()) {
                tenants.push(&retirement.tenant);
            }
        }
        let tables: Vec<CJson> =
            plan::tenants(&self.compile.config.clone(), &PlatformKey::new(platform))
                .into_iter()
                .cloned()
                .collect();
        for tenant in tenants {
            // A tenant the platform's own rules stopped: its retirements
            // are not attempted ([`DeployLog::settle`]).
            if self
                .stopped_tenants
                .iter()
                .any(|(name, stopped)| name == platform && stopped == tenant)
            {
                continue;
            }
            let mine: Vec<&super::deploy_retire::Retirement> = retirements
                .iter()
                .copied()
                .filter(|retirement| retirement.tenant == tenant)
                .collect();
            let row = |retirement: &super::deploy_retire::Retirement| {
                let mut result =
                    RuleResult::new(platform, Some(tenant), &retirement.uuid, &retirement.name);
                result.action = Some("delete".to_owned());
                result.retired = true;
                result
            };
            // A platform that cannot retire it says so, before any tenant
            // is opened.
            let mut sendable = Vec::new();
            for retirement in mine {
                match &retirement.request {
                    Request::Unsupported(reason) => {
                        let mut result = row(retirement);
                        result.skip(reason);
                        result.seconds = Some(0.0);
                        log.finished(result);
                    }
                    Request::Delete {
                        rule_id,
                        body,
                        state,
                    } => sendable.push((retirement, rule_id, body, *state)),
                }
            }
            if sendable.is_empty() {
                continue;
            }
            let Some(deployer) = self
                .cx
                .registry
                .get(platform)
                .and_then(opentide_connectors::Platform::deployer)
            else {
                for (retirement, ..) in sendable {
                    let mut result = row(retirement);
                    self.rule_error(
                        &mut result,
                        &format!("Cannot find a deployment engine for {platform}"),
                    );
                    log.finished(result);
                }
                continue;
            };
            let batch = tenant_batch(&tables, tenant);
            let Some(connection) = self.open_or_fail(platform, &batch, log, deployer)? else {
                continue;
            };
            for (retirement, rule_id, body, state) in sendable {
                let mut result = row(retirement);
                connection.rule_begins();
                let request = DeployRequest::new(rule_id.clone(), Operation::Delete, body.clone())
                    .at(self.cx.now);
                let outcome = self.retire_rule(
                    platform,
                    tenant,
                    deployer,
                    &connection,
                    &request,
                    state,
                    &mut result,
                );
                if self.raised_before_any_rule(&connection, platform, tenant, log, &outcome) {
                    break;
                }
                if let Err(raised) = self.close(log, result, outcome) {
                    self.tenant_failed(platform, tenant, log, raised, true)?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// One retirement's delete on an open tenant: a recorded id is forgotten
    /// once the tenant deleted the rule, or once it says it has none (`404`,
    /// skipped as already gone).
    #[expect(
        clippy::too_many_arguments,
        reason = "one retirement on its open tenant, and the row it fills"
    )]
    fn retire_rule(
        &mut self,
        platform: &str,
        tenant: &str,
        deployer: &dyn Deployer,
        connection: &Connection,
        request: &DeployRequest,
        state: bool,
        result: &mut RuleResult,
    ) -> Result<(), Raised> {
        let context = self.context(connection);
        let answer = self
            .block(async { Ok(deployer.deploy(context, request).await) })
            .map_err(|error| raised(&error))?;
        match answer {
            Ok(done) => {
                for warning in &done.warnings {
                    if warning.code == opentide_connectors::splunk::RENAMED_DELETED {
                        result.removed.push(warning.message.clone());
                    }
                }
            }
            // Gone already: nothing to retire, and nothing to keep. A
            // Defender rule opentide 1.0.0 deployed under the bare uuid may
            // still run, so the row names the id asked for (#1886).
            Err(failed) if failed.failure.status == Some(404) => {
                if PlatformId::parse(platform) == Some(PlatformId::MicrosoftDefender) {
                    result.skip(&format!(
                        "no rule {} on the tenant",
                        opentide_compile::microsoft_defender::rule_id_of(&request.rule_id)
                    ));
                } else {
                    result.skip("already gone from the tenant");
                }
            }
            Err(failed) => return Err(coded_failure(failed)),
        }
        if state {
            self.record_deleted(result, platform, tenant);
        }
        Ok(())
    }
}
