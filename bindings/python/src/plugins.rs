//! The platform plugin host (UC-4.5, #835): the platforms Python packages
//! register in the `opentide.platforms` entry-point group, behind the
//! connectors' traits.
//!
//! Discovery and every call go through the SDK layer, `opentide.plugins`:
//! `_discover()` loads the entry points (skipping the built-in platforms'),
//! and `_invoke(plugin, method, *arguments)` calls one plugin method with
//! JSON text and answers JSON text, `{"ok": ...}` or `{"error": {...}}`, so
//! no Python object outlives the call. The GIL is taken for that call alone,
//! on a blocking thread of the run's runtime: a run waiting on a plugin
//! still answers Ctrl-C, and the other tenants' work goes on.

use std::sync::{Arc, OnceLock};

use opentide_connectors::connector::{
    BoxFuture, ConfigurationCheck, ConfigurationFinding, DeployOutcome, DeployRequest, Deployer,
    LiveCheck, LiveValidator, Operation, Platform, QueryColumn, QueryOutcome, QueryRequest,
    QueryRunner, TenantContext, TimeWindow,
};
use opentide_connectors::credentials::Credential;
use opentide_connectors::plugin::{ENTRY_POINT_GROUP, PluginError, PluginHost};
use opentide_connectors::{ConnectorError, Tenant};
use pyo3::prelude::*;
use serde_json::{Value, json};

/// The SDK module that discovers and calls plugins.
const SDK: &str = "opentide.plugins";

/// One loaded plugin.
#[expect(
    clippy::struct_excessive_bools,
    reason = "what the plugin overrides, one flag per connector trait"
)]
struct Entry {
    /// The entry point's name: the platform's identifier.
    id: String,
    /// The plugin object.
    plugin: Py<PyAny>,
    /// Whether it deploys.
    deploy: bool,
    /// Whether it checks queries on a tenant.
    validate: bool,
    /// Whether it runs queries.
    query: bool,
    /// Whether it checks its configuration block.
    configuration: bool,
}

/// The host the binding installs: discovery runs once per process, the
/// first time a run asks for the plugins.
#[derive(Default)]
pub struct PythonPlugins {
    loaded: OnceLock<Vec<Result<Arc<Entry>, PluginError>>>,
}

impl PluginHost for PythonPlugins {
    fn platforms(&self) -> Vec<Result<Box<dyn Platform>, PluginError>> {
        self.loaded
            .get_or_init(discover)
            .iter()
            .map(|loaded| match loaded {
                Ok(entry) => Ok(Box::new(PythonPlatform(Arc::clone(entry))) as Box<dyn Platform>),
                Err(error) => Err(error.clone()),
            })
            .collect()
    }
}

/// `opentide.plugins._discover()`: each entry point, loaded or not.
fn discover() -> Vec<Result<Arc<Entry>, PluginError>> {
    let found = Python::attach(|py| -> PyResult<Vec<Result<Arc<Entry>, PluginError>>> {
        let listed = py.import(SDK)?.call_method0("_discover")?;
        let mut out = Vec::new();
        for item in listed.try_iter()? {
            let item = item?;
            let id: String = item.get_item("id")?.extract()?;
            if let Some(error) = item.get_item("error")?.extract::<Option<String>>()? {
                out.push(Err(PluginError {
                    platform: id,
                    message: error,
                }));
                continue;
            }
            let flag = |name: &str| -> PyResult<bool> { item.get_item(name)?.extract() };
            out.push(Ok(Arc::new(Entry {
                deploy: flag("deploy")?,
                validate: flag("validate")?,
                query: flag("query")?,
                configuration: flag("configuration")?,
                plugin: item.get_item("plugin")?.unbind(),
                id,
            })));
        }
        Ok(out)
    });
    found.unwrap_or_else(|error| {
        vec![Err(PluginError {
            platform: ENTRY_POINT_GROUP.to_owned(),
            message: error.to_string(),
        })]
    })
}

/// A plugin as a platform.
struct PythonPlatform(Arc<Entry>);

impl Platform for PythonPlatform {
    fn id(&self) -> &str {
        &self.0.id
    }
    fn deployer(&self) -> Option<&dyn Deployer> {
        self.0.deploy.then_some(self as &dyn Deployer)
    }
    fn live_validator(&self) -> Option<&dyn LiveValidator> {
        self.0.validate.then_some(self as &dyn LiveValidator)
    }
    fn query_runner(&self) -> Option<&dyn QueryRunner> {
        self.0.query.then_some(self as &dyn QueryRunner)
    }
    fn configuration_check(&self) -> Option<&dyn ConfigurationCheck> {
        self.0
            .configuration
            .then_some(self as &dyn ConfigurationCheck)
    }
    fn is_plugin(&self) -> bool {
        true
    }
}

/// `opentide.plugins._invoke(plugin, method, *arguments)`, with the GIL for
/// that call alone; its JSON answer, or the Python error's text.
fn call(entry: &Entry, method: &str, arguments: &[String]) -> Result<String, String> {
    Python::attach(|py| -> PyResult<String> {
        let mut args: Vec<Bound<'_, PyAny>> = vec![
            entry.plugin.bind(py).clone(),
            method.into_pyobject(py)?.into_any(),
        ];
        for argument in arguments {
            args.push(argument.into_pyobject(py)?.into_any());
        }
        let tuple = pyo3::types::PyTuple::new(py, args)?;
        py.import(SDK)?.getattr("_invoke")?.call1(tuple)?.extract()
    })
    .map_err(|error| error.to_string())
}

/// The plugin's answer: its `ok` value, or the error it maps to.
fn answer(text: &str, platform: &str, tenant: &str) -> Result<Value, ConnectorError> {
    let crashed = |message: String| ConnectorError::Crashed {
        platform: platform.to_owned(),
        tenant: tenant.to_owned(),
        message,
    };
    let document: Value = serde_json::from_str(text)
        .map_err(|error| crashed(format!("the plugin answered no JSON: {error}")))?;
    if let Some(ok) = document.get("ok") {
        return Ok(ok.clone());
    }
    let error = document.get("error").cloned().unwrap_or(Value::Null);
    let field = |name: &str| error.get(name).and_then(Value::as_str).map(str::to_owned);
    let message = field("message").unwrap_or_else(|| "the plugin failed".to_owned());
    let detail = field("detail");
    Err(match field("kind").as_deref() {
        Some("refused") => ConnectorError::Refused {
            platform: platform.to_owned(),
            tenant: tenant.to_owned(),
            message,
            detail,
        },
        Some("authentication") => ConnectorError::Authentication {
            platform: platform.to_owned(),
            tenant: tenant.to_owned(),
            message,
            detail,
        },
        _ => crashed(message),
    })
}

/// Calls *method* on a blocking thread and reads its answer.
fn invoke(
    entry: &Arc<Entry>,
    method: &'static str,
    arguments: Vec<String>,
    tenant: String,
) -> BoxFuture<'static, Result<Value, ConnectorError>> {
    let entry = Arc::clone(entry);
    Box::pin(async move {
        let platform = entry.id.clone();
        let joined = tokio::task::spawn_blocking(move || call(&entry, method, &arguments)).await;
        match joined {
            Ok(Ok(text)) => answer(&text, &platform, &tenant),
            Ok(Err(message)) => Err(ConnectorError::Crashed {
                platform,
                tenant,
                message,
            }),
            Err(_) => Err(ConnectorError::Crashed {
                platform,
                tenant,
                message: "the plugin call stopped unexpectedly".to_owned(),
            }),
        }
    })
}

/// The tenant as the plugin reads it: its name, its setup with each value
/// resolved (a placeholder is `null`), its lists, whether TLS is verified and
/// the timeout.
fn tenant_json(tenant: &Tenant) -> String {
    let setup: serde_json::Map<String, Value> = tenant
        .setup
        .iter()
        .map(|(key, value)| {
            let value = match value {
                Credential::Value(secret) => Value::String(secret.expose().to_owned()),
                Credential::Placeholder { .. } => Value::Null,
            };
            (key.clone(), value)
        })
        .collect();
    json!({
        "platform": tenant.label.platform,
        "name": tenant.label.tenant,
        "setup": setup,
        "lists": tenant.lists,
        "verify_tls": tenant.http.tls.verify,
        "timeout": tenant.http.timeout.as_secs_f64(),
    })
    .to_string()
}

fn operation_name(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Update => "update",
        Operation::Disable => "disable",
        Operation::Delete => "delete",
    }
}

fn operation_of(name: Option<&str>, asked: Operation) -> Operation {
    match name {
        Some("create") => Operation::Create,
        Some("update") => Operation::Update,
        Some("disable") => Operation::Disable,
        Some("delete") => Operation::Delete,
        _ => asked,
    }
}

/// The deploy request: the body as JSON when it is JSON, else as text.
fn deploy_json(request: &DeployRequest) -> String {
    let body = serde_json::from_slice::<Value>(&request.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&request.body).into_owned()));
    json!({
        "rule_id": request.rule_id,
        "operation": operation_name(request.operation),
        "body": body,
    })
    .to_string()
}

fn query_json(request: &QueryRequest) -> String {
    json!({
        "text": request.text,
        "language": request.language,
        "start": TimeWindow::utc_z(request.window.start),
        "end": TimeWindow::utc_z(request.window.end),
        "limit": request.limit,
        "index": request.index,
        "data_view": request.data_view,
        "timeout": request.timeout.as_secs_f64(),
    })
    .to_string()
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map_or_else(|| item.to_string(), str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A query result as the plugin wrote it, its rows in their columns' order.
fn outcome_of(value: &Value) -> Result<QueryOutcome, String> {
    let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    let rows = match value.get("rows") {
        None | Some(Value::Null) => Vec::new(),
        Some(rows) => {
            // Re-read in order: serde_json's map sorts its keys.
            let ordered: opentide_compile::Json = serde_json::from_str(&rows.to_string())
                .map_err(|error| format!("rows: {error}"))?;
            match ordered {
                opentide_compile::Json::Array(items) => items
                    .into_iter()
                    .map(|item| match item {
                        opentide_compile::Json::Object(row) => Ok(row),
                        _ => Err("rows: a row is not an object".to_owned()),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err("rows: not a list".to_owned()),
            }
        }
    };
    let columns = match value.get("columns").and_then(Value::as_array) {
        Some(columns) => columns
            .iter()
            .map(|column| QueryColumn {
                name: column
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                kind: column
                    .get("type")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
            .collect(),
        None => opentide_connectors::connector::columns_of(&rows),
    };
    let flag = |name: &str| value.get(name).and_then(Value::as_bool).unwrap_or(false);
    Ok(QueryOutcome {
        columns,
        rows,
        truncated: flag("truncated"),
        partial: flag("partial"),
        warnings: strings(value.get("warnings")),
        vendor_query_id: text("vendor_query_id"),
        sent: text("sent"),
        language: text("language"),
    })
}

impl Deployer for PythonPlatform {
    fn deploy<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a DeployRequest,
    ) -> BoxFuture<'a, Result<DeployOutcome, ConnectorError>> {
        let tenant = cx.tenant.label.tenant.clone();
        let asked = request.operation;
        let work = invoke(
            &self.0,
            "deploy",
            vec![tenant_json(cx.tenant), deploy_json(request)],
            tenant,
        );
        Box::pin(async move {
            let value = work.await?;
            Ok(DeployOutcome {
                remote_id: value
                    .get("remote_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                operation: operation_of(value.get("operation").and_then(Value::as_str), asked),
            })
        })
    }
}

impl QueryRunner for PythonPlatform {
    fn run<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<QueryOutcome, ConnectorError>> {
        let tenant = cx.tenant.label.tenant.clone();
        let platform = self.0.id.clone();
        let work = invoke(
            &self.0,
            "run_query",
            vec![tenant_json(cx.tenant), query_json(request)],
            tenant.clone(),
        );
        Box::pin(async move {
            let value = work.await?;
            outcome_of(&value).map_err(|message| ConnectorError::Crashed {
                platform,
                tenant,
                message,
            })
        })
    }
}

impl LiveValidator for PythonPlatform {
    fn validate<'a>(
        &'a self,
        cx: TenantContext<'a>,
        request: &'a QueryRequest,
    ) -> BoxFuture<'a, Result<LiveCheck, ConnectorError>> {
        let tenant = cx.tenant.label.tenant.clone();
        let platform = self.0.id.clone();
        let work = invoke(
            &self.0,
            "validate_query",
            vec![tenant_json(cx.tenant), query_json(request)],
            tenant.clone(),
        );
        Box::pin(async move {
            let value = work.await?;
            let result = match value.get("result") {
                None | Some(Value::Null) => None,
                Some(result) => {
                    Some(
                        outcome_of(result).map_err(|message| ConnectorError::Crashed {
                            platform,
                            tenant,
                            message,
                        })?,
                    )
                }
            };
            Ok(LiveCheck {
                result,
                errors: strings(value.get("errors")),
                warnings: strings(value.get("warnings")),
            })
        })
    }
}

impl ConfigurationCheck for PythonPlatform {
    fn check(&self, block: &Value) -> Result<Vec<ConfigurationFinding>, ConnectorError> {
        let text =
            call(&self.0, "check_configuration", &[block.to_string()]).map_err(|message| {
                ConnectorError::Crashed {
                    platform: self.0.id.clone(),
                    tenant: String::new(),
                    message,
                }
            })?;
        let value = answer(&text, &self.0.id, "")?;
        Ok(value
            .get("findings")
            .and_then(Value::as_array)
            .map(|found| {
                found
                    .iter()
                    .map(|finding| ConfigurationFinding {
                        path: strings(finding.get("path")),
                        message: finding
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        warning: finding
                            .get("warning")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_map_to_connector_errors() {
        assert_eq!(answer(r#"{"ok": 1}"#, "acme", "t").expect("ok"), json!(1));
        let refused = answer(
            r#"{"error": {"kind": "refused", "message": "no", "detail": "why"}}"#,
            "acme",
            "t",
        );
        assert!(matches!(
            refused,
            Err(ConnectorError::Refused { ref message, detail: Some(ref detail), .. })
                if message == "no" && detail == "why"
        ));
        let auth = answer(
            r#"{"error": {"kind": "authentication", "message": "bad key"}}"#,
            "acme",
            "t",
        );
        assert!(matches!(auth, Err(ConnectorError::Authentication { .. })));
        let other = answer(r#"{"error": {"message": "boom"}}"#, "acme", "t");
        assert!(
            matches!(other, Err(ConnectorError::Crashed { ref message, .. }) if message == "boom")
        );
        let bare = answer("{}", "acme", "t");
        assert!(
            matches!(bare, Err(ConnectorError::Crashed { ref message, .. }) if message == "the plugin failed")
        );
        assert!(matches!(
            answer("not json", "acme", "t"),
            Err(ConnectorError::Crashed { .. })
        ));
    }

    #[test]
    fn query_results_keep_their_column_order() {
        let outcome = outcome_of(&json!({
            "rows": [{"z": 1, "a": 2}],
            "truncated": true,
            "warnings": ["w", 3],
            "language": "acmeql",
        }))
        .expect("read");
        assert_eq!(
            outcome.columns,
            [QueryColumn::named("a"), QueryColumn::named("z")]
        );
        assert!(outcome.truncated && !outcome.partial);
        assert_eq!(outcome.warnings, ["w", "3"]);
        assert_eq!(outcome.language.as_deref(), Some("acmeql"));
        let typed = outcome_of(&json!({"columns": [{"name": "n", "type": "long"}], "rows": null}))
            .expect("read");
        assert_eq!(typed.columns[0].kind.as_deref(), Some("long"));
        assert!(typed.rows.is_empty());
        assert!(outcome_of(&json!({"rows": {}})).is_err());
        assert!(outcome_of(&json!({"rows": [1]})).is_err());
    }

    #[test]
    fn requests_cross_as_json() {
        let request = DeployRequest {
            rule_id: "r".into(),
            operation: Operation::Disable,
            body: br#"{"b": 1}"#.to_vec(),
        };
        let sent: Value = serde_json::from_str(&deploy_json(&request)).expect("json");
        assert_eq!(sent["operation"], "disable");
        assert_eq!(sent["body"]["b"], 1);
        let text = DeployRequest {
            body: b"plain".to_vec(),
            ..request
        };
        let sent: Value = serde_json::from_str(&deploy_json(&text)).expect("json");
        assert_eq!(sent["body"], "plain");
        for operation in [
            Operation::Create,
            Operation::Update,
            Operation::Disable,
            Operation::Delete,
        ] {
            assert_eq!(
                operation_of(Some(operation_name(operation)), Operation::Create),
                operation
            );
        }
        assert_eq!(operation_of(None, Operation::Update), Operation::Update);
        let now = jiff::Timestamp::UNIX_EPOCH;
        let query = QueryRequest::new("x", "acmeql", TimeWindow::check(now));
        let sent: Value = serde_json::from_str(&query_json(&query)).expect("json");
        assert_eq!(sent["limit"], 100);
        assert_eq!(sent["end"], "1970-01-01T00:00:00.000Z");
    }
}
