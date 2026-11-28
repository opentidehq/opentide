//! CrowdStrike Falcon's sender: the [`Sender`] method that sends one rule
//! of `--platform crowdstrike`.

use opentide_compile::Json as CJson;
use opentide_connectors::ConnectorError;
use opentide_connectors::connector::{DeployRequest, Deployer, Operation, TenantContext};

use super::{Planned, Raised, Sender, action_verb, raised, scoped};
use crate::json::Json;

impl Sender<'_, '_> {
    /// One rule sent to CrowdStrike through a signed-in session: the id the
    /// tenant gave it. The tenant's refusal is raised with its answer.
    pub(super) fn crowdstrike_deploy(
        &mut self,
        context: TenantContext<'_>,
        session: &opentide_connectors::crowdstrike::Crowdstrike,
        rule: &opentide_compile::Rule,
        action: &Planned,
        body: &CJson,
    ) -> Result<Option<String>, Raised> {
        let refused = |error: ConnectorError, action: &Planned| match &error {
            ConnectorError::Refused {
                message, detail, ..
            } => {
                let context = detail
                    .as_deref()
                    .and_then(|text| serde_json::from_str::<CJson>(text).ok())
                    .map(|value| Json::to_text(&value))
                    .unwrap_or_default();
                tracing::error!(
                    detail = message.as_str(),
                    context = context.as_str(),
                    critical = true,
                    "fatal_error"
                );
                Raised::new(format!(
                    "could not {} the rule: {message}",
                    action_verb(action)
                ))
            }
            other => raised(other),
        };
        // The Deployer's request: the stored id addresses an update
        // (its one-rule list, the id in it) or a delete.
        let request = match action {
            Planned::Delete(id) => DeployRequest::delete(id.clone()),
            Planned::Update(id) => {
                let mut list = body.clone();
                if let CJson::Object(object) = &mut list {
                    object.insert("id".into(), id.clone().into());
                }
                let bytes = serde_json::to_vec(&CJson::Array(vec![list])).unwrap_or_default();
                DeployRequest::new(id.clone(), Operation::Update, bytes)
            }
            Planned::Create => DeployRequest::new(
                rule.uuid.clone(),
                Operation::Create,
                serde_json::to_vec(&body).unwrap_or_default(),
            ),
        };
        let outcome = self
            .block(async { Ok(session.deploy(context, &request).await) })
            .map_err(|error| refused(error, action))?
            .map_err(|failed| scoped(failed, |error| refused(error, action)))?;
        Ok(outcome.remote_id)
    }
}
