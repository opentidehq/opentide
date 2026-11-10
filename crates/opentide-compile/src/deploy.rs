//! What the deployers whose body is built from a tenant share: the writes a
//! deploy sends for one rule to one tenant, what the deployment state makes
//! of it (create, update or delete, `deployment/external_ids.py`
//! `plan_external_id`) and a tenant's settings.

use crate::Context;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// One request a deploy sends: its method, its URL (or, for an SDK that
/// builds the URL itself, the REST path), and its body (`null` for none).
#[derive(Debug, Clone, PartialEq)]
pub struct Write {
    /// `POST`, `PUT`, `PATCH` or `DELETE`.
    pub method: &'static str,
    /// The URL.
    pub url: String,
    /// The JSON body, `null` when the request has none.
    pub body: Json,
}

impl Write {
    /// A request.
    pub fn new(method: &'static str, url: impl Into<String>, body: Json) -> Self {
        Self {
            method,
            url: url.into(),
            body,
        }
    }

    /// `{"method", "url", "body"}`.
    pub fn to_json(&self) -> Json {
        let mut object = Object::new();
        object.insert("method".into(), self.method.into());
        object.insert("url".into(), self.url.clone().into());
        object.insert("body".into(), self.body.clone());
        Json::Object(object)
    }
}

/// The writes, in the order they are sent, as a JSON array.
pub fn writes_json(writes: &[Write]) -> Json {
    Json::Array(writes.iter().map(Write::to_json).collect())
}

/// What a deployer does for a rule on a tenant that records ids
/// (`ExternalIdAction`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No id is recorded: the rule is created.
    Create,
    /// The id recorded: the rule is updated (disabled included).
    Update(String),
    /// The id recorded, and the status is a DELETION: the rule is deleted.
    Delete(String),
}

/// The strategy of `status`, or the error the oracle's `check_status` raises,
/// in `display`'s words.
pub fn strategy(
    cx: &Context<'_>,
    display: &str,
    status: &str,
) -> Result<StatusStrategy, CompileError> {
    cx.statuses
        .strategy(status)
        .map_err(|error| CompileError::failed(display, &error.exception_text()))
}

/// The action for a rule with `status` whose recorded id on the tenant is
/// `known`: update (delete, for a DELETION) a recorded rule, create an
/// unrecorded one, and nothing (`None`) for a DELETION or DISABLEMENT status
/// without an id: nothing is known to exist there (`external_id_missing`).
pub fn action(
    cx: &Context<'_>,
    display: &str,
    status: &str,
    known: Option<&str>,
) -> Result<Option<Action>, CompileError> {
    let strategy = strategy(cx, display, status)?;
    Ok(match known {
        Some(id) if strategy == StatusStrategy::Deletion => Some(Action::Delete(id.to_owned())),
        Some(id) => Some(Action::Update(id.to_owned())),
        None if matches!(
            strategy,
            StatusStrategy::Deletion | StatusStrategy::Disablement
        ) =>
        {
            None
        }
        None => Some(Action::Create),
    })
}

/// A tenant's `setup` value at `key`.
pub fn setup<'t>(tenant: &'t Json, key: &str) -> Option<&'t Json> {
    tenant
        .get("setup")
        .and_then(|setup| setup.get(key))
        .filter(|value| !value.is_null())
}

/// A tenant's `name`.
pub fn tenant_name(tenant: &Json) -> &str {
    tenant
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or_default()
}

/// A value as Python's `str()` writes it: a string as is, a number or a
/// boolean as its text.
pub fn text(value: &Json) -> String {
    match value {
        Json::Str(text) => text.clone(),
        Json::Bool(flag) => if *flag { "True" } else { "False" }.to_owned(),
        Json::Null => "None".to_owned(),
        Json::Float(float) => opentide_schema::configuration::repr::float_text(*float),
        other => other.to_compact(),
    }
}

/// A setup string, `""` when unset.
pub fn setup_text(tenant: &Json, key: &str) -> String {
    setup(tenant, key).map(text).unwrap_or_default()
}

/// The platform's configuration (`platforms.<platform>` of the resolved
/// configuration).
pub fn platform_config<'c>(cx: &'c Context<'_>, platform: &str) -> Option<&'c Json> {
    cx.config
        .get("platforms")
        .and_then(|platforms| platforms.get(platform))
}

/// The tenants configured for `platform`, in their order.
pub fn tenants<'c>(cx: &'c Context<'_>, platform: &str) -> Vec<&'c Json> {
    crate::plan::tenants(cx.config, platform)
}

/// The tenant of `platform` named `name`.
pub fn tenant<'c>(cx: &'c Context<'_>, platform: &str, name: &str) -> Option<&'c Json> {
    tenants(cx, platform)
        .into_iter()
        .find(|tenant| tenant_name(tenant) == name)
}

/// A string of the rule at `path` (`metadata.author`), Python-truthy.
pub fn rule_text<'r>(rule: &'r Rule, path: &[&str]) -> Option<&'r str> {
    let mut value = &rule.data;
    for key in path {
        value = value.get(key)?;
    }
    value.as_str().filter(|text| !text.is_empty())
}

/// The rule's value at `path`, unless absent or `null`.
pub fn rule_value<'r>(rule: &'r Rule, path: &[&str]) -> Option<&'r Json> {
    let mut value = &rule.data;
    for key in path {
        value = value.get(key)?;
    }
    (!value.is_null()).then_some(value)
}

/// The rule's techniques it inherits through its detection model
/// (`techniques_resolver`), or the error the oracle's resolver raises.
pub fn inherited_techniques(
    cx: &Context<'_>,
    display: &str,
    rule: &Rule,
) -> Result<Vec<String>, CompileError> {
    crate::attack::techniques(cx.index, &rule.uuid)
        .map_err(|missing| CompileError::failed(display, &crate::strategy::python_repr(&missing.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_written_as_python_writes_them() {
        assert_eq!(text(&Json::Int(42)), "42");
        assert_eq!(text(&Json::Str("x".into())), "x");
        assert_eq!(text(&Json::Bool(true)), "True");
        assert_eq!(text(&Json::Float(1.5)), "1.5");
        assert_eq!(text(&Json::Null), "None");
    }

    #[test]
    fn a_write_is_method_url_and_body() {
        let write = Write::new("DELETE", "https://x/1", Json::Null);
        assert_eq!(
            writes_json(&[write]).to_compact(),
            r#"[{"method":"DELETE","url":"https://x/1","body":null}]"#
        );
    }
}
