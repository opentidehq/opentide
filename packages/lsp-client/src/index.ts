/**
 * opentide language client.
 *
 * The factory is `createOpentideClient`. There is no `createOtideClient`.
 *
 * Three transports reach the same engine:
 *
 * - `stdio` runs `opentide-lsp --stdio` once and speaks JSON-RPC to it
 *   (`opentide/analyze`, `opentide/highlight`).
 * - `worker` speaks the same JSON-RPC to the same server running in a Web
 *   Worker (`worker`: `serveLanguageServer` from `@opentide/lsp-worker`, over
 *   `opentide-wasm`), one message per `postMessage`. Given a loaded `module`
 *   instead, it calls `highlight()` and `legend()` in this thread and does not
 *   analyze.
 * - `wasi` runs the `wasm32-wasip1` `opentide-lsp` CLI under `node:wasi`, one
 *   `analyze` or `highlight` per call. Under Node 22, run the process with
 *   `--no-turbo-fast-api-calls`: `node:wasi`'s fast `path_open` call can start
 *   a garbage collection inside the call, which segfaults the process once
 *   the WASI instances hold enough memory.
 *
 * A transport that cannot answer rejects. It never returns an empty result in
 * place of one.
 */

export type Transport = "stdio" | "worker" | "wasi";

/** A language the server handles: its LSP language id and file globs. */
export interface OpentideLanguage {
  id: string;
  name: string;
  patterns: string[];
}

/**
 * Every language the server handles. `kql` is Microsoft KQL; `kuery` is
 * Kibana KQL (Elastic `language: kuery`). Tide YAML is scoped to `objects/`,
 * where the server owns diagnostics (turn yamlls off there).
 *
 * `cql` is the CrowdStrike Query Language (Falcon LogScale, Next-Gen SIEM).
 * Cassandra's CQL uses the `.cql` extension too: where a workspace holds
 * Cassandra scripts, leave out the `.cql` file pattern and match `cql` by
 * language id alone.
 *
 * `opentide-config` is configuration TOML (`.opentide/configurations/`). The
 * host that runs the server checks it (`opentide lsp start`); `opentide-lsp`
 * on its own reports nothing for it, so `analyze` and `highlight` refuse it.
 * Keep the editor's TOML grammar for it.
 */
export const LANGUAGES: readonly OpentideLanguage[] = [
  { id: "opentide-yaml", name: "Tide YAML", patterns: ["**/objects/**/*.yaml", "**/objects/**/*.yml"] },
  { id: "kql", name: "KQL (Microsoft)", patterns: ["**/*.kql"] },
  { id: "spl", name: "SPL", patterns: ["**/*.spl"] },
  { id: "esql", name: "ES|QL", patterns: ["**/*.esql"] },
  { id: "eql", name: "EQL", patterns: ["**/*.eql"] },
  { id: "kuery", name: "Kibana KQL", patterns: ["**/*.kuery"] },
  { id: "lucene", name: "Lucene", patterns: ["**/*.lucene"] },
  { id: "falco", name: "Falco", patterns: ["**/*.falco"] },
  { id: "cql", name: "CrowdStrike Query Language", patterns: ["**/*.cql"] },
  { id: "yara", name: "YARA", patterns: ["**/*.yar", "**/*.yara"] },
  { id: "opentide-config", name: "opentide configuration", patterns: ["**/.opentide/configurations/**/*.toml"] },
];

/** A document filter by language id. */
export interface LanguageFilter {
  language: string;
}

/** A document filter by file pattern, for `file:` URIs only. */
export interface FileFilter {
  scheme: "file";
  pattern: string;
}

/** A document filter by file pattern, for a URI of any scheme. */
export interface PatternFilter {
  pattern: string;
}

/**
 * LSP document selector for every language, by language id and by file
 * pattern, so a file is served even when no extension registered its id
 * (for example `.esql` when Elastic's own extension owns the id). Its
 * patterns match `file:` URIs only: use it on the desktop.
 *
 * A plain array, so it is vscode-languageclient's `documentSelector` as it
 * is; do not change it in place.
 */
export const DOCUMENT_SELECTOR: Array<LanguageFilter | FileFilter> = LANGUAGES.flatMap((l) => [
  { language: l.id },
  ...l.patterns.map((pattern): FileFilter => ({ scheme: "file", pattern })),
]);

/**
 * The same selector with no scheme, for web hosts (vscode.dev, github.dev),
 * where documents are `vscode-vfs:`, `vscode-remote:` or other virtual URIs,
 * not `file:` ones. A pattern without a scheme matches the URI's path
 * whatever its scheme. A plain array, like `DOCUMENT_SELECTOR`.
 */
export const WEB_DOCUMENT_SELECTOR: Array<LanguageFilter | PatternFilter> = LANGUAGES.flatMap((l) => [
  { language: l.id },
  ...l.patterns.map((pattern): PatternFilter => ({ pattern })),
]);

/** The `opentide-wasm` exports the `worker` transport calls when given a `module`. */
export interface HighlightModule {
  highlight(language_id: string, bytes: Uint8Array): unknown;
  legend(): unknown;
}

/**
 * The client's end of a channel to a worker serving the language server: a
 * `Worker`, or one port of a `MessageChannel`. Each message is one JSON-RPC
 * message as JSON text.
 */
export interface WorkerPort {
  postMessage(message: string): void;
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  start?(): void;
  /** A `MessagePort`'s. */
  close?(): void;
  /** A `Worker`'s. */
  terminate?(): void;
}

/**
 * What a host with no filesystem tells the server about its workspace on
 * `initialize` (`initializationOptions.workspace`), so references resolve and
 * declared datasets apply: whole object documents, objects known by their
 * metadata alone, and the text of `visibility.toml`.
 */
export interface SuppliedWorkspace {
  documents?: { uri: string; text: string }[];
  objects?: { uuid: string; schema: string; name?: string; uri?: string }[];
  visibility?: string;
}

/**
 * What changed in a supplied workspace (`opentide/didChangeWorkspace`): documents and objects added or
 * changed, the URIs of files that are gone (`opentide-object:<uuid>` for an object supplied without a
 * `uri`), and `visibility.toml`'s new text, or `null` when it is gone.
 */
export interface WorkspaceChange {
  documents?: { uri: string; text: string }[];
  objects?: { uuid: string; schema: string; name?: string; uri?: string }[];
  removed?: string[];
  visibility?: string | null;
}

export interface OpentideClientOptions {
  transport: Transport;
  /** stdio: the server binary. Default `opentide-lsp`, found on `PATH`. */
  command?: string;
  /** stdio: arguments. Default `["--stdio"]`. */
  args?: string[];
  /** stdio: workspace root sent on `initialize` (a `file:` URI). */
  rootUri?: string;
  /** stdio and worker: the workspace sent on `initialize`, for a server that cannot read one from disk. */
  workspace?: SuppliedWorkspace;
  /** worker: a worker serving the language server (`serveLanguageServer` in `@opentide/lsp-worker`). */
  worker?: WorkerPort;
  /** worker, without `worker`: the loaded module (`loadHighlightModule` in `@opentide/lsp-worker`). */
  module?: HighlightModule;
  /** wasi: the `wasm32-wasip1` `opentide-lsp` build, as a path, its bytes, or a compiled module. */
  wasi?: string | URL | Uint8Array | WebAssembly.Module;
}

export interface HighlightToken {
  capture: string;
  start: number;
  end: number;
}

export interface HighlightResult {
  language_id: string;
  tokens: HighlightToken[];
  legend: string[];
}

export interface Position {
  line: number;
  character: number;
}

export interface Diagnostic {
  code: string;
  severity: "error" | "warning" | "information" | "hint";
  message: string;
  range: { start: Position; end: Position };
  field_path?: string[];
  suggestion?: string;
  object_uuid?: string;
  object_type?: string;
}

export interface AnalyzeResult {
  diagnostics: Diagnostic[];
}

export interface OpentideClient {
  transport: Transport;
  highlight(languageId: string, text: string): Promise<HighlightResult>;
  legend(): Promise<string[]>;
  analyze(languageId: string, text: string): Promise<AnalyzeResult>;
  /**
   * Tell the server the supplied workspace changed (`opentide/didChangeWorkspace`): what `workspace` gave
   * on `initialize` is all a server with no filesystem reads. stdio and worker (with `worker`); the
   * other transports have no session to update, and reject.
   */
  updateWorkspace(change: WorkspaceChange): Promise<void>;
  dispose(): Promise<void>;
}

/** The languages `analyze` and `highlight` take: not `opentide-config`, which only a host checks. */
const LANGUAGE_IDS = new Set(LANGUAGES.map((l) => l.id).filter((id) => id !== "opentide-config"));

/** The server reads an unknown id as a default language; refuse it here instead. */
function checkLanguage(languageId: string): void {
  if (languageId === "opentide-config") {
    throw new Error(
      "opentide-config is checked by the host that runs the server (opentide lsp start), not by analyze or highlight",
    );
  }
  if (!LANGUAGE_IDS.has(languageId)) {
    throw new Error(`unknown language ${JSON.stringify(languageId)}; expected one of ${[...LANGUAGE_IDS].join(", ")}`);
  }
}

/** File suffix the CLI detects `languageId` from. */
function extensionFor(languageId: string): string {
  return languageId === "opentide-yaml" ? "yaml" : languageId;
}

function encodeMessage(body: unknown): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify(body));
  const header = new TextEncoder().encode(`Content-Length: ${json.length}\r\n\r\n`);
  const out = new Uint8Array(header.length + json.length);
  out.set(header, 0);
  out.set(json, header.length);
  return out;
}

/**
 * Splits a byte stream into JSON-RPC messages framed by `Content-Length`.
 * Bytes may arrive in any chunking; `push` returns every message completed.
 */
export class MessageDecoder {
  private buffer = new Uint8Array(0);

  push(chunk: Uint8Array): unknown[] {
    const joined = new Uint8Array(this.buffer.length + chunk.length);
    joined.set(this.buffer, 0);
    joined.set(chunk, this.buffer.length);
    this.buffer = joined;
    const messages: unknown[] = [];
    for (;;) {
      const end = indexOfHeaderEnd(this.buffer);
      if (end < 0) break;
      const header = new TextDecoder().decode(this.buffer.subarray(0, end));
      const match = /^content-length:\s*(\d+)\s*$/im.exec(header);
      if (!match) throw new Error(`JSON-RPC header without Content-Length: ${JSON.stringify(header)}`);
      const start = end + 4;
      const length = Number(match[1]);
      if (this.buffer.length < start + length) break;
      messages.push(JSON.parse(new TextDecoder().decode(this.buffer.subarray(start, start + length))));
      this.buffer = this.buffer.slice(start + length);
    }
    return messages;
  }
}

function indexOfHeaderEnd(bytes: Uint8Array): number {
  for (let i = 0; i + 3 < bytes.length; i++) {
    if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) return i;
  }
  return -1;
}

interface RpcResponse {
  id?: number;
  method?: string;
  result?: unknown;
  error?: { code: number; message: string };
}

/**
 * One JSON-RPC session with the server, started on first use: the
 * `initialize` handshake, requests matched to their responses, and
 * `shutdown`/`exit` on dispose. A subclass opens the channel and writes to it.
 */
abstract class Connection {
  private ready: Promise<void> | undefined;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private closed: Error | undefined;
  protected readonly options: OpentideClientOptions;

  constructor(options: OpentideClientOptions) {
    this.options = options;
  }

  /** Start the server and pass each message it sends to `receive`. */
  protected abstract open(): Promise<void>;
  /** Send one message to the server. */
  protected abstract write(message: object): void;
  /** The process id sent on `initialize`. */
  protected abstract processId(): number | null;
  /** Wait for the server to go after `exit`, then make sure it has. */
  protected abstract close(): Promise<void>;

  request(method: string, params: unknown): Promise<unknown> {
    return this.start().then(() => this.send(method, params));
  }

  /** A notification, once the session is up. */
  notification(method: string, params: unknown): Promise<void> {
    return this.start().then(() => {
      if (this.closed) throw this.closed;
      this.notify(method, params);
    });
  }

  private start(): Promise<void> {
    this.ready ??= (async () => {
      await this.open();
      await this.send("initialize", {
        processId: this.processId(),
        rootUri: this.options.rootUri ?? null,
        capabilities: {},
        ...(this.options.workspace ? { initializationOptions: { workspace: this.options.workspace } } : {}),
      });
      this.notify("initialized", {});
    })();
    return this.ready;
  }

  private send(method: string, params: unknown): Promise<unknown> {
    if (this.closed) return Promise.reject(this.closed);
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.write({ jsonrpc: "2.0", id, method, params });
    });
  }

  private notify(method: string, params: unknown): void {
    if (!this.closed) this.write({ jsonrpc: "2.0", method, params });
  }

  protected receive(message: RpcResponse): void {
    // Notifications from the server (publishDiagnostics) carry no id.
    if (message.id === undefined || message.method !== undefined) return;
    const waiter = this.pending.get(message.id);
    if (!waiter) return;
    this.pending.delete(message.id);
    if (message.error) waiter.reject(new Error(`${message.error.message} (${message.error.code})`));
    else waiter.resolve(message.result);
  }

  protected fail(error: Error): void {
    this.closed ??= error;
    for (const waiter of this.pending.values()) waiter.reject(error);
    this.pending.clear();
  }

  async dispose(): Promise<void> {
    if (!this.ready) return;
    try {
      await this.ready;
      await this.send("shutdown", null);
      this.notify("exit", null);
    } catch {
      // Already gone: nothing to shut down.
    } finally {
      await this.close();
      this.fail(new Error("client disposed"));
    }
  }
}

/** One `opentide-lsp --stdio` process. */
class StdioConnection extends Connection {
  private child: import("node:child_process").ChildProcessWithoutNullStreams | undefined;
  private stderr = "";

  protected async open(): Promise<void> {
    const { spawn } = await import("node:child_process");
    const command = this.options.command ?? "opentide-lsp";
    const child = spawn(command, this.options.args ?? ["--stdio"], { stdio: ["pipe", "pipe", "pipe"] });
    this.child = child;
    const decoder = new MessageDecoder();
    child.stdout.on("data", (chunk: Uint8Array) => {
      for (const message of decoder.push(chunk) as RpcResponse[]) this.receive(message);
    });
    child.stderr.on("data", (chunk: Uint8Array) => {
      this.stderr = (this.stderr + new TextDecoder().decode(chunk)).slice(-4096);
    });
    child.on("error", (e) => this.fail(new Error(`cannot start ${command}: ${e.message}`)));
    // A write to a server that died (EPIPE) is reported through `close`.
    child.stdin.on("error", () => {});
    child.on("close", (code, signal) => {
      const detail = this.stderr.trim() ? `: ${this.stderr.trim()}` : "";
      this.fail(new Error(`${command} exited (${signal ?? code})${detail}`));
    });
  }

  protected write(message: object): void {
    this.child!.stdin.write(encodeMessage(message));
  }

  protected processId(): number | null {
    return process.pid;
  }

  protected async close(): Promise<void> {
    const child = this.child;
    if (!child) return;
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise<void>((resolve) => child.once("close", () => resolve()));
      const timeout = new Promise<void>((resolve) => {
        // Node's timer has `unref`, so a server that never exits does not keep the process alive.
        const timer = setTimeout(resolve, 2000) as unknown as { unref?: () => void };
        timer.unref?.();
      });
      await Promise.race([exited, timeout]);
    }
    if (child.exitCode === null && child.signalCode === null) child.kill();
  }
}

/** The language server in a worker (`serveLanguageServer` in `@opentide/lsp-worker`), one message per `postMessage`. */
class WorkerConnection extends Connection {
  protected async open(): Promise<void> {
    const port = this.options.worker!;
    port.addEventListener("message", (event) => {
      const text = typeof event.data === "string" ? event.data : JSON.stringify(event.data);
      try {
        this.receive(JSON.parse(text) as RpcResponse);
      } catch {
        this.fail(new Error(`the worker posted something that is not JSON-RPC: ${text.slice(0, 200)}`));
      }
    });
    port.start?.();
  }

  protected write(message: object): void {
    this.options.worker!.postMessage(JSON.stringify(message));
  }

  protected processId(): number | null {
    return null;
  }

  protected async close(): Promise<void> {
    const port = this.options.worker!;
    port.close?.();
    port.terminate?.();
  }
}

/** A client of a JSON-RPC connection to the server: the stdio process, or the worker. */
function connectionClient(transport: Transport, connection: Connection): OpentideClient {
  const highlight = async (languageId: string, text: string): Promise<HighlightResult> => {
    checkLanguage(languageId);
    return (await connection.request("opentide/highlight", { language: languageId, text })) as HighlightResult;
  };
  return {
    transport,
    highlight,
    async legend() {
      return (await highlight("kql", "")).legend;
    },
    async analyze(languageId, text) {
      checkLanguage(languageId);
      const uri = `untitled:query.${extensionFor(languageId)}`;
      return (await connection.request("opentide/analyze", { language: languageId, text, uri })) as AnalyzeResult;
    },
    updateWorkspace: (change) => connection.notification("opentide/didChangeWorkspace", change),
    dispose: () => connection.dispose(),
  };
}

function stdioClient(options: OpentideClientOptions): OpentideClient {
  return connectionClient("stdio", new StdioConnection(options));
}

function workerClient(options: OpentideClientOptions): OpentideClient {
  if (options.worker) return connectionClient("worker", new WorkerConnection(options));
  const module = options.module;
  if (!module) {
    throw new Error(
      "the worker transport needs `worker` (a worker running serveLanguageServer from @opentide/lsp-worker) or `module` (loadHighlightModule)",
    );
  }
  return {
    transport: "worker",
    async highlight(languageId, text) {
      checkLanguage(languageId);
      return module.highlight(languageId, new TextEncoder().encode(text)) as HighlightResult;
    },
    async legend() {
      return [...(module.legend() as Iterable<string>)];
    },
    async analyze() {
      throw new Error(
        "analyze needs the language server: pass `worker` (serveLanguageServer from @opentide/lsp-worker), not a highlight `module`",
      );
    },
    async updateWorkspace() {
      throw new Error(
        "updateWorkspace needs the language server: pass `worker` (serveLanguageServer from @opentide/lsp-worker), not a highlight `module`",
      );
    },
    async dispose() {},
  };
}

function wasiClient(options: OpentideClientOptions): OpentideClient {
  const source = options.wasi;
  if (!source) {
    throw new Error("the wasi transport needs `wasi`: the wasm32-wasip1 opentide-lsp build");
  }
  let compiled: Promise<WebAssembly.Module> | undefined;
  const load = (): Promise<WebAssembly.Module> =>
    (compiled ??= (async () => {
      if (source instanceof WebAssembly.Module) return source;
      if (source instanceof Uint8Array) return WebAssembly.compile(source as unknown as BufferSource);
      const { readFile } = await import("node:fs/promises");
      return WebAssembly.compile(await readFile(source));
    })());

  /** Run one CLI subcommand on `text`, as `opentide-lsp <command> /work/query.<ext>`. */
  const run = async (command: "analyze" | "highlight", languageId: string, text: string): Promise<unknown> => {
    checkLanguage(languageId);
    const [{ WASI }, fs, { tmpdir }, { join }] = await Promise.all([
      import("node:wasi"),
      import("node:fs"),
      import("node:os"),
      import("node:path"),
    ]);
    const module = await load();
    const dir = fs.mkdtempSync(join(tmpdir(), "opentide-wasi-"));
    try {
      const file = `query.${extensionFor(languageId)}`;
      fs.writeFileSync(join(dir, file), text);
      const out = fs.openSync(join(dir, "stdout"), "w");
      const err = fs.openSync(join(dir, "stderr"), "w");
      let code: number;
      try {
        const wasi = new WASI({
          version: "preview1",
          args: ["opentide-lsp", command, `/work/${file}`, "--language", languageId],
          preopens: { "/work": dir },
          stdout: out,
          stderr: err,
          returnOnExit: true,
        });
        const instance = await WebAssembly.instantiate(module, wasi.getImportObject() as WebAssembly.Imports);
        code = wasi.start(instance);
      } finally {
        fs.closeSync(out);
        fs.closeSync(err);
      }
      if (code !== 0) {
        const stderr = fs.readFileSync(join(dir, "stderr"), "utf8").trim();
        throw new Error(`opentide-lsp ${command} exited ${code}${stderr ? `: ${stderr}` : ""}`);
      }
      return JSON.parse(fs.readFileSync(join(dir, "stdout"), "utf8"));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };

  const highlight = async (languageId: string, text: string): Promise<HighlightResult> =>
    (await run("highlight", languageId, text)) as HighlightResult;
  return {
    transport: "wasi",
    highlight,
    async legend() {
      return (await highlight("kql", "")).legend;
    },
    async analyze(languageId, text) {
      // The CLI prints the diagnostics array; the RPC wraps it.
      return { diagnostics: (await run("analyze", languageId, text)) as Diagnostic[] };
    },
    async updateWorkspace() {
      throw new Error("the wasi transport runs the CLI once per call: there is no session whose workspace to update");
    },
    async dispose() {},
  };
}

export function createOpentideClient(options: OpentideClientOptions): OpentideClient {
  switch (options.transport) {
    case "stdio":
      return stdioClient(options);
    case "worker":
      return workerClient(options);
    case "wasi":
      return wasiClient(options);
    default:
      throw new Error(`unsupported transport ${String((options as { transport: unknown }).transport)}`);
  }
}

/** @deprecated Never use this name. */
export function createOtideClient(_options: OpentideClientOptions): never {
  throw new Error("createOtideClient is not a valid export; use createOpentideClient");
}

export { encodeMessage };
