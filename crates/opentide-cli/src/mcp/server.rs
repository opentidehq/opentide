//! The rmcp [`ServerHandler`]: the handshake, the lists, and each call routed
//! to its Rust implementation or to the [`Delegate`].

use std::future::Future;
use std::path::PathBuf;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CustomRequest, CustomResult,
    ErrorCode, ListResourceTemplatesResult, ListResourcesResult, ListToolsResult,
    PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
    ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{Delegate, NATIVE_TOOLS, tools};
use crate::env::Env;

/// What the Python server says of itself (`scripts/build/mcp_manifest.py`).
const MANIFEST: &str = include_str!("../../data/mcp/manifest.json");

/// The manifest's parts, as rmcp types.
struct Manifest {
    info: ServerConfig,
    tools: ListToolsResult,
    resources: ListResourcesResult,
    templates: ListResourceTemplatesResult,
}

impl Manifest {
    /// The compiled-in manifest, with the package's `version`.
    #[expect(
        clippy::expect_used,
        reason = "the manifest is compiled in, and tests/mcp.rs reads every part of it"
    )]
    fn load(version: &str) -> Manifest {
        let manifest: Value = serde_json::from_str(MANIFEST).expect("data/mcp/manifest.json");
        let info = json!({
            "protocolVersion": manifest["protocolVersion"],
            "capabilities": manifest["capabilities"],
            "serverInfo": {"name": manifest["name"], "version": version},
            "instructions": manifest["instructions"],
        });
        Manifest {
            info: from_value(info).expect("the manifest's initialize result"),
            tools: from_value(json!({"tools": manifest["tools"]})).expect("the manifest's tools"),
            resources: from_value(json!({"resources": manifest["resources"]}))
                .expect("the manifest's resources"),
            templates: from_value(json!({"resourceTemplates": manifest["resourceTemplates"]}))
                .expect("the manifest's resource templates"),
        }
    }
}

fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, serde_json::Error> {
    serde_json::from_value(value)
}

/// The MCP server.
pub struct Server {
    manifest: Manifest,
    env: Env,
    cwd: Option<PathBuf>,
    repo: Option<String>,
    delegate: Option<&'static dyn Delegate>,
}

impl Server {
    /// A server for the workspace `env`, `cwd` and `repo` (`--repo`) place,
    /// answering for the package `version`, with the host's `delegate`.
    pub fn new(
        env: Env,
        cwd: Option<PathBuf>,
        repo: Option<String>,
        version: &str,
        delegate: Option<&'static dyn Delegate>,
    ) -> Server {
        Server {
            manifest: Manifest::load(version),
            env,
            cwd,
            repo,
            delegate,
        }
    }

    /// Serves on stdin and `rpc` until the client closes stdin.
    ///
    /// # Errors
    ///
    /// The transport failed to start or the service stopped abnormally.
    pub async fn run(self, rpc: tokio::fs::File) -> std::io::Result<()> {
        // A last message without its newline is read at end of input, as the
        // Python server reads it: the transport only takes whole lines.
        let stdin = tokio::io::AsyncReadExt::chain(tokio::io::stdin(), &b"\n"[..]);
        let service = match self.serve((stdin, rpc)).await {
            Ok(service) => service,
            Err(error) => {
                // The client left (or never sent `initialize`): nothing to serve.
                tracing::debug!(%error, "the MCP session did not start");
                return Ok(());
            }
        };
        service.waiting().await.map_err(std::io::Error::other)?;
        Ok(())
    }

    /// The answer to `tools/call`, as the Python server gives it.
    pub fn call(&self, name: &str, arguments: &serde_json::Map<String, Value>) -> Answer {
        if NATIVE_TOOLS.contains(&name) {
            let context = tools::Context {
                env: &self.env,
                cwd: self.cwd.as_deref(),
                repo: self.repo.as_deref(),
                workspace_problem: self.delegate.and_then(Delegate::workspace_problem),
            };
            return Answer::Result(tools::call(name, arguments, &context));
        }
        let Some(delegate) = self.delegate else {
            return Answer::Result(tools::error_result(&undelegated(&format!("tool {name}"))));
        };
        let arguments = Value::Object(arguments.clone()).to_string();
        delegated(delegate.call_tool(name, &arguments))
    }

    /// The answer to `resources/read`, as the Python server gives it.
    pub fn read(&self, uri: &str) -> Answer {
        let Some(delegate) = self.delegate else {
            return Answer::Error(json!({
                "code": ErrorCode::INTERNAL_ERROR.0,
                "message": undelegated(&format!("resource {uri}")),
            }));
        };
        delegated(delegate.read_resource(uri))
    }
}

/// A delegated answer: the JSON-RPC `result` or `error`.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// The `result`.
    Result(Value),
    /// The `error`: `{code, message, data}`.
    Error(Value),
}

fn undelegated(what: &str) -> String {
    format!(
        "engine_not_ported: the {what} is answered by the Python package's MCP server, \
         which this process does not host; run `opentide mcp start` from the opentide package"
    )
}

/// The delegate's answer read; the keys only a 2026-07-28 response carries
/// (`resultType`, `ttlMs`, `cacheScope`) dropped, as the Python server's
/// request loop drops them for a client that negotiated `initialize`.
fn delegated(answer: Result<String, String>) -> Answer {
    let parsed = answer.and_then(|text| {
        serde_json::from_str::<Value>(&text).map_err(|error| format!("unreadable answer: {error}"))
    });
    match parsed {
        Ok(Value::Object(mut answer)) => {
            if let Some(Value::Object(mut result)) = answer.remove("result") {
                for key in ["resultType", "ttlMs", "cacheScope"] {
                    result.remove(key);
                }
                return Answer::Result(Value::Object(result));
            }
            match answer.remove("error") {
                Some(error) => Answer::Error(error),
                None => Answer::Error(internal("the answer has neither result nor error")),
            }
        }
        Ok(_) => Answer::Error(internal("the answer is not an object")),
        Err(problem) => Answer::Error(internal(&problem)),
    }
}

fn internal(message: &str) -> Value {
    json!({"code": ErrorCode::INTERNAL_ERROR.0, "message": message})
}

fn error_data(error: &Value) -> ErrorData {
    let code = error
        .get("code")
        .and_then(Value::as_i64)
        .and_then(|code| i32::try_from(code).ok())
        .unwrap_or(ErrorCode::INTERNAL_ERROR.0);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    ErrorData::new(ErrorCode(code), message, error.get("data").cloned())
}

fn invalid_result(error: &serde_json::Error) -> ErrorData {
    ErrorData::internal_error(format!("Handler returned an invalid result: {error}"), None)
}

impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        self.manifest.info.clone()
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(self.manifest.tools.clone()))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResponse, ErrorData>> + Send + '_ {
        let arguments = request.arguments.unwrap_or_default();
        std::future::ready(match self.call(&request.name, &arguments) {
            Answer::Result(result) => from_value::<CallToolResult>(result)
                .map(CallToolResponse::from)
                .map_err(|error| invalid_result(&error)),
            Answer::Error(error) => Err(error_data(&error)),
        })
    }

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(self.manifest.resources.clone()))
    }

    fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourceTemplatesResult, ErrorData>> + Send + '_ {
        std::future::ready(Ok(self.manifest.templates.clone()))
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResponse, ErrorData>> + Send + '_ {
        std::future::ready(match self.read(&request.uri) {
            Answer::Result(result) => from_value::<ReadResourceResult>(result)
                .map(ReadResourceResponse::from)
                .map_err(|error| invalid_result(&error)),
            Answer::Error(error) => Err(error_data(&error)),
        })
    }

    /// A method the server has no handler for: the Python server's answer,
    /// `Method not found` with the method as its data.
    fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CustomResult, ErrorData>> + Send + '_ {
        std::future::ready(Err(ErrorData::new(
            ErrorCode::METHOD_NOT_FOUND,
            "Method not found",
            Some(Value::String(request.method)),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_reads_into_every_part() {
        let manifest = Manifest::load("1.2.3");
        assert_eq!(manifest.info.server_info.name, "opentide");
        assert_eq!(manifest.info.server_info.version, "1.2.3");
        let instructions = manifest.info.instructions.unwrap_or_default();
        assert!(
            instructions.starts_with(
                "opentide: Spec-driven development for agentic detection engineering."
            ),
            "{instructions}"
        );
        let names: Vec<&str> = manifest
            .tools
            .tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect();
        for name in NATIVE_TOOLS
            .iter()
            .chain(super::super::DELEGATED_TOOLS.iter().map(|(name, _)| name))
        {
            assert!(names.contains(name), "{name} is not in the manifest");
        }
        assert_eq!(
            names.len(),
            NATIVE_TOOLS.len() + super::super::DELEGATED_TOOLS.len(),
            "every tool is native or delegated: {names:?}"
        );
        assert!(!manifest.resources.resources.is_empty());
        assert!(!manifest.templates.resource_templates.is_empty());
    }

    #[test]
    fn a_delegated_answer_drops_what_only_a_stateless_client_reads() {
        let answer = delegated(Ok(json!({"result": {
            "content": [], "isError": true, "resultType": "complete",
            "ttlMs": 0, "cacheScope": "private",
        }})
        .to_string()));
        assert_eq!(
            answer,
            Answer::Result(json!({"content": [], "isError": true}))
        );
    }

    #[test]
    fn a_delegated_error_keeps_its_code_and_data() {
        let answer = delegated(Ok(json!({"error": {
            "code": -32602, "message": "Unknown resource: x", "data": {"uri": "x"},
        }})
        .to_string()));
        let Answer::Error(error) = answer else {
            panic!("not an error: {answer:?}");
        };
        let data = error_data(&error);
        assert_eq!(data.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(data.message, "Unknown resource: x");
        assert_eq!(data.data, Some(json!({"uri": "x"})));
    }

    #[test]
    fn an_unreadable_answer_is_an_internal_error() {
        for answer in [
            Ok("not json".to_owned()),
            Ok("[]".to_owned()),
            Err("gone".to_owned()),
        ] {
            let Answer::Error(error) = delegated(answer) else {
                panic!("not an error");
            };
            assert_eq!(error["code"], ErrorCode::INTERNAL_ERROR.0);
        }
    }

    #[test]
    fn without_a_delegate_a_delegated_tool_says_why() {
        let server = Server::new(Env::from_pairs::<&str, &str>([]), None, None, "1", None);
        let Answer::Result(result) = server.call("search", &serde_json::Map::new()) else {
            panic!("not a result");
        };
        assert_eq!(result["isError"], true);
        assert!(
            result["content"][0]["text"]
                .as_str()
                .is_some_and(|text| text.starts_with("engine_not_ported")),
            "{result}"
        );
        assert!(matches!(server.read("opentide://index"), Answer::Error(_)));
    }
}
