//! The platform plugins' sender: the [`Sender`] methods that deploy a
//! plugin platform's rules through its `Deployer`, the body a plugin is
//! sent and how its failures read.

use opentide_compile::Json as CJson;
use opentide_compile::strategy::StatusStrategy;
use opentide_connectors::connector::{DeployRequest, Deployer, Operation};
use opentide_connectors::credentials::Mode as Resolve;
use opentide_connectors::{ConnectorError, HttpClient, Tenant};

use super::{
    Batch, Connection, DeployLog, Planned, Raised, RuleResult, Sender, Stops, raised, scoped,
};
use crate::commands::deploy_state::ExternalId;

impl Sender<'_, '_> {
    /// A platform plugin (UC-4.5b, #835): each rule planned from deployment
    /// state as the built-in platforms that keep ids are, then sent through
    /// the plugin's `Deployer`: created (the id it returns recorded), updated
    /// or disabled (by the stored id), or deleted (the id forgotten).
    pub(super) fn plugin(
        &mut self,
        platform: &str,
        batches: &[Batch],
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let cx = self.cx;
        let deployer = cx
            .registry
            .get(platform)
            .and_then(opentide_connectors::Platform::deployer)
            .ok_or_else(|| Raised::new(format!("platform plugin {platform} cannot deploy")))?;
        // One tenant at a time: a plugin's Python code was written for one
        // call at a time, and nothing says it can take calls from several
        // threads.
        self.tenants(1, batches, log, |sender, batch, log| {
            sender.plugin_tenant(deployer, platform, batch, log)
        })
    }

    /// One tenant's rules of [`plugin`](Self::plugin).
    fn plugin_tenant(
        &mut self,
        deployer: &dyn Deployer,
        platform: &str,
        batch: &Batch,
        log: &mut DeployLog<'_>,
    ) -> Result<(), Raised> {
        let planned = self.screen(platform, batch, log);
        if planned.is_empty() {
            return Ok(());
        }
        let Some(connection) = self.open_or_fail(platform, batch, log, deployer)? else {
            return Ok(());
        };
        for (rule, action) in planned {
            let tenant = batch.tenant.name.as_str();
            let mut result = RuleResult::new(platform, Some(tenant), &rule.uuid, &rule.name);
            connection.rule_begins();
            let outcome =
                self.plugin_rule(deployer, platform, &connection, rule, &action, &mut result);
            if self.raised_before_any_rule(&connection, platform, tenant, log, &outcome) {
                break;
            }
            if let Err(raised) = self.close(log, result, outcome) {
                self.tenant_failed(platform, tenant, log, raised, true)?;
                break;
            }
        }
        Ok(())
    }

    /// A plugin tenant's connection: every `$NAME` of its setup must be set,
    /// since no built-in check names the keys a plugin reads.
    pub(super) fn connect_plugin(
        &self,
        platform: &str,
        batch: &Batch,
    ) -> Result<Connection, Raised> {
        let tenant = Tenant::from_setup(
            platform,
            &batch.tenant.name,
            &batch.tenant.setup,
            &self.environment,
            Resolve::Required,
            &opentide_connectors::HttpSettings::default(),
        )
        .map_err(|error| Raised::new(error.to_string()))?;
        let http = HttpClient::new(
            &tenant.label,
            &tenant.http,
            &self.environment,
            self.cx.proxy,
        )
        .map_err(|error| Raised::new(error.to_string()))?;
        Ok(Connection::new(tenant, http))
    }

    /// One rule on a plugin's tenant: the request the plugin receives (its
    /// `body` the rule, its block for the platform, and the stored id), then
    /// the deployment state the answer changes.
    fn plugin_rule(
        &mut self,
        deployer: &dyn opentide_connectors::connector::Deployer,
        platform: &str,
        connection: &Connection,
        rule: &opentide_compile::Rule,
        action: &Planned,
        result: &mut RuleResult,
    ) -> Result<(), Raised> {
        let tenant = connection.tenant.label.tenant.clone();
        let disables = self.strategy_of(rule, platform)? == StatusStrategy::Disablement;
        let (operation, stored) = match action {
            Planned::Create => (Operation::Create, None),
            Planned::Update(id) if disables => (Operation::Disable, Some(id.as_str())),
            Planned::Update(id) => (Operation::Update, Some(id.as_str())),
            Planned::Delete(id) => (Operation::Delete, Some(id.as_str())),
        };
        let request = DeployRequest::new(
            rule.uuid.clone(),
            operation,
            plugin_body(rule, platform, stored)
                .to_compact()
                .into_bytes(),
        );
        let context = self.context(connection);
        // The plugin sends from Python, outside the tenant's client: what it
        // sent and what the tenant took cannot be counted, so from its first
        // call the tenant may have taken a rule.
        connection.sends_elsewhere();
        let done = self
            .block(async { Ok(deployer.deploy(context, &request).await) })
            .map_err(|error| plugin_raised(&error))?
            .map_err(|failed| scoped(failed, |error| plugin_raised(&error)))?;
        match (operation, done.remote_id) {
            (Operation::Delete, _) => self.record_deleted(result, platform, &tenant),
            (Operation::Create, Some(id)) if !id.trim().is_empty() => {
                self.record_created(result, platform, &tenant, &ExternalId::Text(id));
            }
            (Operation::Create, _) => self.rule_error(
                result,
                &format!(
                    "platform plugin {platform} created rule {} on tenant {} but returned no \
                     remote_id, so deployment state cannot record it: the next deploy creates \
                     it again",
                    rule.uuid,
                    tenant.trim()
                ),
            ),
            (_, Some(id)) if Some(id.as_str()) != stored && !id.trim().is_empty() => {
                // The plugin answered another id for the rule (it recreated
                // it): the state follows the platform.
                self.record_created(result, platform, &tenant, &ExternalId::Text(id));
            }
            _ => {}
        }
        Ok(())
    }
}

/// What a platform plugin's `Deployer` receives as the body (UC-4.5b): the
/// rule's document with the tenant's modifiers applied, its block for the
/// platform, and, for an update, a disable or a delete, the id deployment
/// state holds. `opentide.plugins` hands the plugin `remote_id` as the
/// request's own field.
fn plugin_body(rule: &opentide_compile::Rule, platform: &str, stored: Option<&str>) -> CJson {
    let mut body = opentide_compile::json::Object::new();
    body.insert("rule".into(), rule.data.clone());
    body.insert(
        "configuration".into(),
        rule.block(platform).cloned().unwrap_or(CJson::Null),
    );
    if let Some(id) = stored {
        body.insert("remote_id".into(), CJson::Str(id.to_owned()));
    }
    CJson::Object(body)
}

/// A plugin's failure as the exception that stops the run: the tenant
/// refused the rule or the credentials, or the plugin raised.
pub(super) fn plugin_raised(error: &ConnectorError) -> Raised {
    match error {
        ConnectorError::Refused {
            message,
            detail: Some(detail),
            ..
        } => Raised::new(format!("PlatformRefused: {message}: {detail}")),
        ConnectorError::Refused { message, .. } => {
            Raised::new(format!("PlatformRefused: {message}"))
        }
        ConnectorError::Authentication { message, .. } => {
            Raised::new(format!("PlatformAuthenticationError: {message}")).stopping(Stops::Tenant)
        }
        ConnectorError::Crashed { message, .. } => Raised::new(format!("PluginError: {message}")),
        other => raised(other),
    }
}
