/**
 * opentide language client.
 *
 * The factory is `createOpentideClient`. There is no `createOtideClient`.
 *
 * Three transports reach the same engine:
 *
 * - `stdio` runs `opentide-lsp --stdio` once and speaks JSON-RPC to it
 *   (`opentide/analyze`, `opentide/highlight`).
 * - `worker` calls a loaded `opentide-wasm` module (wasm-bindgen, see
 *   `@opentide/lsp-worker`). It highlights; it does not analyze.
 * - `wasi` runs the `wasm32-wasip1` `opentide-lsp` CLI under `node:wasi`, one
 *   `analyze` or `highlight` per call. Under Node 22, run the process with
 *   `--single-threaded-gc`: its concurrent GC races with many `node:wasi`
 *   instances and segfaults the process.
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
 */
export const LANGUAGES: readonly OpentideLanguage[] = [
  { id: "opentide-yaml", name: "Tide YAML", patterns: ["**/objects/**/*.yaml", "**/objects/**/*.yml"] },
  { id: "kql", name: "KQL (Microsoft)", patterns: ["**/*.kql"] },
  { id: "spl", name: "SPL", patterns: ["**/*.spl"] },
  { id: "esql", name: "ES|QL", patterns: ["**/*.esql"] },
  { id: "eql", name: "EQL", patterns: ["**/*.eql"] },
  { id: "kuery", name: "Kibana KQL", patterns: ["**/*.kuery"] },
  { id: "lucene", name: "Lucene", patterns: ["**/*.lucene"] },
];

/**
 * LSP document selector for every language, by language id and by file
 * pattern, so a file is served even when no extension registered its id
 * (for example `.esql` when Elastic's own extension owns the id).
 */
export const DOCUMENT_SELECTOR: ReadonlyArray<{ language: string } | { scheme: string; pattern: string }> =
  LANGUAGES.flatMap((l) => [
    { language: l.id },
    ...l.patterns.map((pattern) => ({ scheme: "file", pattern })),
  ]);

/** The `opentide-wasm` exports the `worker` transport calls. */
export interface HighlightModule {
  highlight(language_id: string, bytes: Uint8Array): unknown;
  legend(): unknown;
}

export interface OpentideClientOptions {
  transport: Transport;
  /** stdio: the server binary. Default `opentide-lsp`, found on `PATH`. */
  command?: string;
  /** stdio: arguments. Default `["--stdio"]`. */
  args?: string[];
  /** stdio: workspace root sent on `initialize` (a `file:` URI). */
  rootUri?: string;
  /** worker: the loaded module (`loadHighlightModule` in `@opentide/lsp-worker`). */
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
  dispose(): Promise<void>;
}

const LANGUAGE_IDS = new Set(LANGUAGES.map((l) => l.id));

/** The server reads an unknown id as a default language; refuse it here instead. */
function checkLanguage(languageId: string): void {
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

/** One `opentide-lsp --stdio` process, started on first use. */
class StdioConnection {
  private child: import("node:child_process").ChildProcessWithoutNullStreams | undefined;
  private ready: Promise<void> | undefined;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  private stderr = "";
  private closed: Error | undefined;
  private readonly options: OpentideClientOptions;

  constructor(options: OpentideClientOptions) {
    this.options = options;
  }

  request(method: string, params: unknown): Promise<unknown> {
    return this.start().then(() => this.send(method, params));
  }

  private start(): Promise<void> {
    this.ready ??= (async () => {
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
      await this.send("initialize", { processId: process.pid, rootUri: this.options.rootUri ?? null, capabilities: {} });
      this.notify("initialized", {});
    })();
    return this.ready;
  }

  private send(method: string, params: unknown): Promise<unknown> {
    if (this.closed) return Promise.reject(this.closed);
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.child!.stdin.write(encodeMessage({ jsonrpc: "2.0", id, method, params }));
    });
  }

  private notify(method: string, params: unknown): void {
    if (!this.closed) this.child!.stdin.write(encodeMessage({ jsonrpc: "2.0", method, params }));
  }

  private receive(message: RpcResponse): void {
    // Notifications from the server (publishDiagnostics) carry no id.
    if (message.id === undefined || message.method !== undefined) return;
    const waiter = this.pending.get(message.id);
    if (!waiter) return;
    this.pending.delete(message.id);
    if (message.error) waiter.reject(new Error(`${message.error.message} (${message.error.code})`));
    else waiter.resolve(message.result);
  }

  private fail(error: Error): void {
    this.closed ??= error;
    for (const waiter of this.pending.values()) waiter.reject(error);
    this.pending.clear();
  }

  async dispose(): Promise<void> {
    if (!this.ready) return;
    const child = this.child;
    try {
      await this.ready;
      const exited = new Promise<void>((resolve) => child!.once("close", () => resolve()));
      await this.send("shutdown", null);
      this.notify("exit", null);
      const timeout = new Promise<void>((resolve) => setTimeout(resolve, 2000).unref());
      await Promise.race([exited, timeout]);
    } catch {
      // Already gone: nothing to shut down.
    } finally {
      if (child && child.exitCode === null && child.signalCode === null) child.kill();
      this.fail(new Error("client disposed"));
    }
  }
}

function stdioClient(options: OpentideClientOptions): OpentideClient {
  const connection = new StdioConnection(options);
  const highlight = async (languageId: string, text: string): Promise<HighlightResult> => {
    checkLanguage(languageId);
    return (await connection.request("opentide/highlight", { language: languageId, text })) as HighlightResult;
  };
  return {
    transport: "stdio",
    highlight,
    async legend() {
      return (await highlight("kql", "")).legend;
    },
    async analyze(languageId, text) {
      checkLanguage(languageId);
      const uri = `untitled:query.${extensionFor(languageId)}`;
      return (await connection.request("opentide/analyze", { language: languageId, text, uri })) as AnalyzeResult;
    },
    dispose: () => connection.dispose(),
  };
}

function workerClient(options: OpentideClientOptions): OpentideClient {
  const module = options.module;
  if (!module) {
    throw new Error("the worker transport needs `module`: load it with loadHighlightModule from @opentide/lsp-worker");
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
      throw new Error("analyze is not available on the worker transport: opentide-wasm exports highlight() and legend() only");
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
      if (source instanceof Uint8Array) return WebAssembly.compile(source);
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
