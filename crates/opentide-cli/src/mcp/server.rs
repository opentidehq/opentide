//! The rmcp [`ServerHandler`]: the handshake, the lists, and each call
//! routed to its tool or resource.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

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
use tokio_util::sync::CancellationToken;

use super::{resources, tools};
use crate::app::Interrupt;
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
        reason = "the manifest is compiled in, and the_manifest_reads_into_every_part (and tests/test_mcp/test_bridge.py) reads every part of it"
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
///
/// Each tool call and resource read runs apart from the runtime's thread
/// (`Server::apart`), so the server keeps reading the client meanwhile: a
/// `ping` or a list is answered, and `notifications/cancelled` stops the
/// call. They run one at a time, in the order they came, as they ran when
/// the server waited for each.
pub struct Server {
    manifest: Manifest,
    state: Arc<State>,
    /// Held by the call or read running; queued ones wait for it.
    turn: Arc<tokio::sync::Mutex<()>>,
    /// The session's end ([`Server::run`]): the call running, interrupted,
    /// and whether the session is over, so a queued call does not start.
    ending: Arc<Ending>,
}

/// What [`Server::run`] stops when the session ends.
#[derive(Default)]
struct Ending {
    /// The running call's [`Interrupt`].
    running: std::sync::Mutex<Option<Interrupt>>,
    /// The session is over: a call that gets its turn now does not run.
    over: std::sync::atomic::AtomicBool,
}

/// Interrupts a call's work when its handler ends ([`Server::apart`]).
#[cfg(not(target_os = "wasi"))]
struct StopOnDrop(Interrupt);

#[cfg(not(target_os = "wasi"))]
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.request();
    }
}

/// What the tools and resources run against.
struct State {
    env: Env,
    cwd: Option<PathBuf>,
    repo: Option<String>,
    version: String,
    workspace_problem: Option<String>,
}

impl State {
    fn context<'a>(&'a self, interrupt: Option<&'a Interrupt>) -> tools::Context<'a> {
        tools::Context {
            env: &self.env,
            cwd: self.cwd.as_deref(),
            repo: self.repo.as_deref(),
            version: &self.version,
            workspace_problem: self.workspace_problem.clone(),
            interrupt,
        }
    }
}

impl Server {
    /// A server for the workspace `env`, `cwd` and `repo` (`--repo`) place,
    /// answering for the package `version`; `workspace_problem` is why there
    /// is no workspace to serve (an Agent Plugin launch that found none).
    pub fn new(
        env: Env,
        cwd: Option<PathBuf>,
        repo: Option<String>,
        version: &str,
        workspace_problem: Option<String>,
    ) -> Server {
        Server {
            manifest: Manifest::load(version),
            state: Arc::new(State {
                env,
                cwd,
                repo,
                version: version.to_owned(),
                workspace_problem,
            }),
            turn: Arc::default(),
            ending: Arc::default(),
        }
    }

    /// Runs `work` on the runtime's blocking pool once the calls before it
    /// are done, with an [`Interrupt`] of its own that `cancelled` sets: the
    /// commands it runs stop as Ctrl-C stops them, and no other call is
    /// interrupted. A cancelled call answers nothing (rmcp drops the answer
    /// of a cancelled request, as MCP has it); the next call waits until it
    /// has stopped. WASI has no threads: there the work runs on this thread,
    /// and the server reads the client again once it is done.
    async fn apart<T: Send + 'static>(
        &self,
        cancelled: &CancellationToken,
        work: impl FnOnce(&State, &Interrupt) -> T + Send + 'static,
    ) -> Result<T, ErrorData> {
        let stopped = || ErrorData::internal_error("Request cancelled", None);
        let turn = tokio::select! {
            turn = Arc::clone(&self.turn).lock_owned() => turn,
            () = cancelled.cancelled() => return Err(stopped()),
        };
        let state = Arc::clone(&self.state);
        let interrupt = Interrupt::default();
        {
            // Under the lock the session's end takes: a call either starts
            // before it, and is interrupted, or sees it and does not start.
            let mut running = self
                .ending
                .running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.ending.over.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(stopped());
            }
            *running = Some(interrupt.clone());
        }
        #[cfg(target_os = "wasi")]
        {
            let _turn = turn;
            Ok(work(&state, &interrupt))
        }
        #[cfg(not(target_os = "wasi"))]
        {
            let running = tokio::task::spawn_blocking({
                let interrupt = interrupt.clone();
                move || {
                    let _turn = turn;
                    work(&state, &interrupt)
                }
            });
            // Cancelled, or dropped unfinished (the session ending drops its
            // handlers), the work is interrupted; once it has finished,
            // interrupting it changes nothing.
            let _stop = StopOnDrop(interrupt);
            tokio::select! {
                ran = running => ran.map_err(|_| {
                    ErrorData::internal_error("the call stopped unexpectedly", None)
                }),
                () = cancelled.cancelled() => Err(stopped()),
            }
        }
    }

    /// Serves on `input` (stdin) and `rpc` until the client closes `input`.
    ///
    /// # Errors
    ///
    /// The transport failed to start or the service stopped abnormally.
    pub async fn run<I, O>(self, input: I, rpc: O) -> std::io::Result<()>
    where
        I: tokio::io::AsyncRead + Send + Unpin + 'static,
        O: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        // A last message without its newline is still read at end of input:
        // the transport only takes whole lines.
        let stdin = tokio::io::AsyncReadExt::chain(input, &b"\n"[..]);
        let (turn, ending) = (Arc::clone(&self.turn), Arc::clone(&self.ending));
        let served = self.serve_until_closed(stdin, rpc).await;
        // The session is over, but its handlers live on in the process's
        // runtime, which is never dropped (#1558): no queued call starts, the
        // running one is interrupted as Ctrl-C interrupts a command, and the
        // server returns once it has stopped (its deploy state written), as
        // it did when dropping a runtime of its own waited for it.
        {
            let mut running = ending
                .running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ending.over.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(running) = running.take() {
                running.request();
            }
        }
        drop(turn.lock_owned().await);
        served
    }

    /// [`Server::run`]'s service, until the client closes its input.
    async fn serve_until_closed<I, O>(self, stdin: I, rpc: O) -> std::io::Result<()>
    where
        I: tokio::io::AsyncRead + Send + Unpin + 'static,
        O: tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
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

    /// The answer to `tools/call`.
    pub fn call(&self, name: &str, arguments: &serde_json::Map<String, Value>) -> Answer {
        Answer::Result(tools::call(name, arguments, &self.state.context(None)))
    }

    /// The answer to `resources/read`.
    pub fn read(&self, uri: &str) -> Answer {
        resources::read(uri, &self.state.context(None))
    }
}

/// An answer: the JSON-RPC `result` or `error`.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// The `result`.
    Result(Value),
    /// The `error`: `{code, message, data}`.
    Error(Value),
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

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let arguments = request.arguments.unwrap_or_default();
        let result = self
            .apart(&context.ct, move |state, interrupt| {
                tools::call(&request.name, &arguments, &state.context(Some(interrupt)))
            })
            .await?;
        from_value::<CallToolResult>(result)
            .map(CallToolResponse::from)
            .map_err(|error| invalid_result(&error))
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

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let answer = self
            .apart(&context.ct, move |state, interrupt| {
                resources::read(&request.uri, &state.context(Some(interrupt)))
            })
            .await?;
        match answer {
            Answer::Result(result) => from_value::<ReadResourceResult>(result)
                .map(ReadResourceResponse::from)
                .map_err(|error| invalid_result(&error)),
            Answer::Error(error) => Err(error_data(&error)),
        }
    }

    /// A method the server has no handler for: `Method not found`, with the
    /// method as its data.
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
        assert_eq!(
            names,
            super::super::TOOLS,
            "every tool of the manifest is answered"
        );
        assert!(!manifest.resources.resources.is_empty());
        assert!(!manifest.templates.resource_templates.is_empty());
    }

    #[test]
    fn an_error_keeps_its_code_and_data() {
        let error = json!({"code": -32602, "message": "Unknown resource: x", "data": {"uri": "x"}});
        let data = error_data(&error);
        assert_eq!(data.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(data.message, "Unknown resource: x");
        assert_eq!(data.data, Some(json!({"uri": "x"})));
        assert_eq!(error_data(&json!({})).code, ErrorCode::INTERNAL_ERROR);
    }

    #[test]
    fn a_catalogue_tool_hears_the_launchs_workspace_problem() {
        let server = Server::new(
            Env::from_pairs::<&str, &str>([]),
            None,
            None,
            "1",
            Some("workspace_not_found: nothing here".into()),
        );
        let arguments = serde_json::from_value(json!({"queries": "loud"})).unwrap();
        let Answer::Result(result) = server.call("validation_report", &arguments) else {
            panic!("not a result");
        };
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["content"][0]["text"],
            "Error executing tool validation_report: workspace_not_found: nothing here"
        );
        let Answer::Error(error) = server.read("opentide://index") else {
            panic!("a resource without a workspace is an error");
        };
        assert_eq!(error["message"], "Error reading resource opentide://index");
        let Answer::Result(_) = server.read("opentide://vocabularies") else {
            panic!("a bundled resource needs no workspace");
        };
    }
}
