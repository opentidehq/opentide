/**
 * WASM worker host for `opentide-wasm`.
 *
 * Artifact: wasm32-unknown-unknown + wasm-bindgen.
 * Do not mix WASI into this module. vscode.dev uses a separate wasm32-wasip1 binary.
 *
 * The module runs two ways:
 *
 * - `serveLanguageServer` runs the language server itself (`opentide-lsp`, the
 *   server `--stdio` runs) inside a Web Worker. Each message the worker
 *   receives is one JSON-RPC message from the client, as JSON text with no
 *   `Content-Length` header, and each message it posts is one from the server:
 *   what `@codemirror/lsp-client`'s `Transport` sends, and what
 *   `createOpentideClient({ transport: "worker", worker })` speaks.
 * - `loadHighlightModule` loads `highlight()` and `legend()` to call in the
 *   same thread: `createOpentideClient({ transport: "worker", module })`.
 */

export interface WorkerHighlightModule {
  highlight(language_id: string, bytes: Uint8Array): unknown;
  legend(): string[];
}

/** What wasm-bindgen's glue for `opentide_wasm.wasm` exports. */
export interface GlueModule {
  default?: unknown;
  highlight?: unknown;
  legend?: unknown;
  version?: unknown;
  LanguageServer?: unknown;
}

/**
 * The glue: the URL of its JavaScript file, or the module itself when the
 * host has imported it already (a bundler's `import * as glue from
 * "./opentide_wasm.js"`, which puts the glue in the worker's own chunk).
 */
export type Glue = string | URL | GlueModule;

/** Where `--target web` glue reads the module from: a URL, a `Response`, bytes, or a compiled module. */
export type WasmSource = string | URL | Response | BufferSource | WebAssembly.Module;

function describe(glue: Glue): string {
  return typeof glue === "string" || glue instanceof URL ? String(glue) : "the glue module";
}

/**
 * Import the glue (unless it is a module already) and initialise it.
 *
 * For `wasm-bindgen --target web` glue, `wasm` is passed to its initialiser;
 * when omitted, the glue fetches `opentide_wasm_bg.wasm` next to itself.
 * `--target nodejs` glue loads its module on import and ignores `wasm`.
 */
async function initialise(glue: Glue, wasm: WasmSource | undefined): Promise<GlueModule | undefined> {
  if (!glue) {
    throw new Error("glueUrl is required");
  }
  // A URL known only at run time: a bundler is told not to resolve it.
  const module =
    typeof glue === "string" || glue instanceof URL ? ((await import(/* @vite-ignore */ String(glue))) as GlueModule) : glue;
  // `--target web` exports an async initialiser as the default export;
  // `--target nodejs` is CommonJS, whose exports may sit on `default`.
  if (typeof module.default === "function") {
    await (module.default as (init?: { module_or_path: unknown }) => Promise<unknown>)(
      wasm === undefined ? undefined : { module_or_path: wasm },
    );
  }
  return (typeof module.highlight === "function" ? module : module.default) as GlueModule | undefined;
}

/** Load the glue and return `highlight()` and `legend()`. */
export async function loadHighlightModule(glueUrl: Glue, wasm?: WasmSource): Promise<WorkerHighlightModule> {
  const exports = await initialise(glueUrl, wasm);
  if (typeof exports?.highlight !== "function" || typeof exports.legend !== "function") {
    throw new Error(`${describe(glueUrl)} is not opentide-wasm glue: it exports no highlight() and legend()`);
  }
  const { highlight, legend } = exports as { highlight: WorkerHighlightModule["highlight"]; legend: () => Iterable<string> };
  return {
    highlight: (language_id, bytes) => highlight(language_id, bytes),
    legend: () => [...legend()],
  };
}

/** One session of the language server: its open documents and its workspace. */
export interface LanguageServerSession {
  /** One JSON-RPC message in, as JSON text; the messages the server sends back, in order. */
  handle(message: string): string[];
  /** Whether the client has sent `exit`. */
  readonly closed: boolean;
  /** Release the session's memory in the module (wasm-bindgen classes have it). */
  free?(): void;
}

/** The language server in a loaded module. */
export interface LanguageServerModule {
  /** A new session, as a new `--stdio` process would be. */
  createSession(): LanguageServerSession;
  /** The engine's version. */
  version(): string;
}

/** Load the glue and return the language server it carries (`opentide-wasm`'s `LanguageServer`). */
export async function loadLanguageServer(glue: Glue, wasm?: WasmSource): Promise<LanguageServerModule> {
  const exports = await initialise(glue, wasm);
  const Server = exports?.LanguageServer;
  const version = exports?.version;
  if (typeof Server !== "function" || typeof version !== "function") {
    throw new Error(`${describe(glue)} is not opentide-wasm glue with the language server: it exports no LanguageServer`);
  }
  return {
    createSession: () => new (Server as new () => LanguageServerSession)(),
    version: () => String((version as () => unknown)()),
  };
}

/**
 * The end of a channel the server talks through: `self` inside a dedicated
 * worker, or one port of a `MessageChannel`.
 */
export interface ServerPort {
  postMessage(message: string): void;
  addEventListener(type: "message", listener: (event: { data: unknown }) => void): void;
  start?(): void;
  close?(): void;
}

/** The id of a JSON-RPC request (a message with a method and an id), if `text` is one. */
function requestId(text: string): string | number | undefined {
  try {
    const message = JSON.parse(text) as { id?: unknown; method?: unknown };
    const { id } = message;
    return typeof message.method === "string" && (typeof id === "string" || typeof id === "number") ? id : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Serve the language server on `port` until the client sends `exit`.
 *
 * Every message the port receives is one JSON-RPC message from the client and
 * every message posted back is one from the server, each as JSON text with no
 * `Content-Length` header (a message that arrives as an object is read as its
 * JSON). Messages that arrive while `server` loads are handled in order once
 * it has. If it fails to load, or the module stops, each request is answered
 * with an error that says so, so the client's `initialize` fails at once
 * instead of timing out; nothing is answered empty.
 *
 * After `exit` the port is closed: inside a dedicated worker, `self.close()`
 * ends the worker. The promise resolves then.
 */
export function serveLanguageServer(
  port: ServerPort,
  server: LanguageServerModule | Promise<LanguageServerModule>,
): Promise<void> {
  let session: LanguageServerSession | undefined;
  let failure: string | undefined;
  let waiting: string[] | undefined = [];
  let finished!: () => void;
  const done = new Promise<void>((resolve) => (finished = resolve));

  const refuse = (text: string) => {
    const id = requestId(text);
    if (id !== undefined) {
      port.postMessage(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32603, message: failure } }));
    }
  };
  const handle = (text: string) => {
    if (!session || failure !== undefined) return refuse(text);
    let replies: string[];
    try {
      replies = session.handle(text);
    } catch (error) {
      failure = `the opentide language server stopped: ${error instanceof Error ? error.message : String(error)}`;
      return refuse(text);
    }
    for (const reply of replies) port.postMessage(reply);
    if (session.closed) {
      session.free?.();
      session = undefined;
      failure = "the opentide language server has exited";
      port.close?.();
      finished();
    }
  };

  port.addEventListener("message", (event) => {
    const text = typeof event.data === "string" ? event.data : JSON.stringify(event.data);
    if (waiting) waiting.push(text);
    else handle(text);
  });
  port.start?.();
  Promise.resolve(server)
    .then((module) => module.createSession())
    .then(
      (created) => {
        session = created;
      },
      (error: unknown) => {
        failure = `the opentide language server did not load: ${error instanceof Error ? error.message : String(error)}`;
      },
    )
    .then(() => {
      const queued = waiting ?? [];
      waiting = undefined;
      for (const text of queued) handle(text);
    });
  return done;
}
