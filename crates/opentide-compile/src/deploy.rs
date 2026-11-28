//! What the deployers whose body is built from a tenant share: the writes a
//! deploy sends for one rule to one tenant, what the deployment state makes
//! of it (create, update or delete, `deployment/external_ids.py`
//! `plan_external_id`) and a tenant's settings.

use opentide_schema::platforms::PlatformKey;

use crate::Context;
use crate::json::{Json, Object};
use crate::rule::{CompileError, Rule};
use crate::strategy::StatusStrategy;

/// The WHATWG URL path-segment percent-encode set, the one
/// `url::Url::path_segments_mut().push` applies: controls, space,
/// `"#<>?`{}`, `/` and `%` are escaped, every other ASCII character is kept
/// (non-ASCII is always escaped as UTF-8). Encode a value that becomes one
/// segment of a request's path with it.
pub const PATH_SEGMENT: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%');

/// One request a deploy sends: its method, its URL (or, for an SDK that
/// builds the URL itself, the REST path), and its body (`null` for none).
#[derive(Debug, Clone, PartialEq)]
pub struct Write {
    /// `POST`, `PUT`, `PATCH` or `DELETE`.
    pub method: &'static str,
    /// The URL, or the REST path for an SDK that builds the URL itself.
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

/// What a dry run shows for a value a deploy learns only as it sends the
/// request: `<send-time:NAME>` (`minute`, `hour`, `timestamp`).
pub fn send_time(name: &str) -> String {
    format!("<send-time:{name}>")
}

/// What a dry run shows for a value a deploy reads from the tenant as it
/// sends (a Carbon Black watchlist and its id): `<tenant-read:NAME>`.
pub fn tenant_read(name: &str) -> String {
    format!("<tenant-read:{name}>")
}

/// What a dry run that reaches no tenant shows for a value the tenant's
/// `setup` gives: `<tenant:KEY>`.
pub fn tenant_value(key: &str) -> String {
    format!("<tenant:{key}>")
}

/// Whether `text` is a whole [`tenant_value`] placeholder.
pub fn is_tenant_value(text: &str) -> bool {
    text.strip_prefix("<tenant:")
        .and_then(|rest| rest.strip_suffix('>'))
        .is_some_and(|key| !key.is_empty() && !key.contains(['<', '>']))
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
        .map_err(|error| CompileError::failed(display, &error.to_string()))
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

/// A tenant's `name`; empty when it is unset or not a string.
pub fn tenant_name(tenant: &Json) -> &str {
    tenant
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or_default()
}

/// A setup string, `""` when unset.
pub fn setup_text(tenant: &Json, key: &str) -> String {
    setup(tenant, key).map(Json::to_text).unwrap_or_default()
}

/// A tenant's on-or-off setup value at `key`: `default` when it is unset,
/// else the boolean it holds. Nothing else is on or off: `0`, `""`, `"no"`
/// and `"true"` are refused, and so is a `$NAME` placeholder, which a deploy
/// never resolves for these settings (only `ssl` is resolved, by the
/// connectors). The error names the key; callers wrap it in their platform's
/// [`CompileError`].
pub fn setup_switch(tenant: &Json, key: &str, default: bool) -> Result<bool, String> {
    match setup(tenant, key) {
        None => Ok(default),
        Some(Json::Bool(on)) => Ok(*on),
        Some(Json::Str(name)) if name.starts_with('$') => Err(format!(
            "{key} is the placeholder {name:?}, which is not resolved for this setting: \
             write true or false"
        )),
        Some(other) => Err(format!(
            "{key} must be true or false, got {:?}",
            other.to_text()
        )),
    }
}

/// The platform's configuration (`platforms.<platform>` of the resolved
/// configuration).
pub fn platform_config<'c>(cx: &'c Context<'_>, platform: &str) -> Option<&'c Json> {
    cx.config
        .get("platforms")
        .and_then(|platforms| platforms.get(platform))
}

/// The tenants configured for `platform`, in their order.
pub fn tenants<'c>(cx: &'c Context<'_>, platform: &PlatformKey) -> Vec<&'c Json> {
    crate::plan::tenants(cx.config, platform)
}

/// The tenant of `platform` named `name`.
pub fn tenant<'c>(cx: &'c Context<'_>, platform: &PlatformKey, name: &str) -> Option<&'c Json> {
    tenants(cx, platform)
        .into_iter()
        .find(|tenant| tenant_name(tenant) == name)
}

/// A string of the rule at `path` (`metadata.author`), not empty.
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
        .map_err(|missing| CompileError::failed(display, &format!("{:?}", missing.0)))
}

/// The strings of a list.
pub fn strings(value: Option<&Json>) -> Vec<String> {
    match value {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The ATT&CK ids a platform sends, by one policy on every platform whose
/// block holds a list: the block's `own` techniques when it sets any (an empty
/// list is unset), otherwise those `rule` resolves through its objective.
/// Explicit beats inherited; the two are never merged. De-duplicated, in order.
pub fn platform_techniques(
    cx: &Context<'_>,
    display: &str,
    rule: &Rule,
    own: Vec<String>,
) -> Result<Vec<String>, CompileError> {
    pick_techniques(own, || inherited_techniques(cx, display, rule))
}

fn pick_techniques(
    own: Vec<String>,
    inherited: impl FnOnce() -> Result<Vec<String>, CompileError>,
) -> Result<Vec<String>, CompileError> {
    let chosen = if own.is_empty() { inherited()? } else { own };
    Ok(opentide_core::text::unique(chosen))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_blocks_techniques_win_and_are_deduplicated() {
        let own = vec!["T1059".to_owned(), "T1003".to_owned(), "T1059".to_owned()];
        let picked = pick_techniques(own, || Ok(vec!["T1562".to_owned()])).unwrap();
        assert_eq!(picked, ["T1059", "T1003"]);
    }

    #[test]
    fn an_empty_list_inherits_the_objectives_deduplicated() {
        let inherited = || {
            Ok(vec![
                "T1562".to_owned(),
                "T1562".to_owned(),
                "T1070".to_owned(),
            ])
        };
        assert_eq!(
            pick_techniques(Vec::new(), inherited).unwrap(),
            ["T1562", "T1070"]
        );
    }

    #[test]
    fn a_path_segment_escapes_separators_and_keeps_index_patterns() {
        let encoded =
            |value: &str| percent_encoding::utf8_percent_encode(value, PATH_SEGMENT).to_string();
        assert_eq!(encoded("logs-*,x_y.z~"), "logs-*,x_y.z~");
        assert_eq!(encoded("a b/c?d#e%"), "a%20b%2Fc%3Fd%23e%25");
        assert_eq!(encoded("é"), "%C3%A9");
    }

    #[test]
    fn placeholders_name_what_they_stand_for() {
        assert_eq!(send_time("minute"), "<send-time:minute>");
        assert_eq!(tenant_value("url"), "<tenant:url>");
        assert_eq!(tenant_read("watchlist"), "<tenant-read:watchlist>");
        assert!(is_tenant_value("<tenant:api>"));
        assert!(!is_tenant_value("<tenant:>"));
        assert!(!is_tenant_value("EU-1"));
        assert!(!is_tenant_value("<send-time:minute>"));
        assert!(!is_tenant_value("<tenant-read:watchlist>"));
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
