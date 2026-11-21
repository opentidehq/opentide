// @opentide/wasi-host: the extension host's half of `opentide/fetch` (W2,
// docs/engine/connector-transport.md).
//
// The WASI build of opentide runs under VS Code's WASI host, which gives it
// no sockets. Its `opentide serve` asks the client to make each tenant
// request: a server-to-client JSON-RPC request `opentide/fetch`, whose id is
// a string ("h1", "h2", ...). `FetchHost` answers those requests from the
// extension host, with Node's own HTTP stack: the tenant's TLS verification
// and CA bundles, its proxy (a CONNECT tunnel), its connect and read
// timeouts, redirects as the native transport follows them (on the tenant's
// origin only), and cancellation when the
// server withdraws a request (`$/cancelRequest`). VS Code's proxy support
// (`http.proxy`, the OS certificate store), which patches Node's `https`,
// applies as it does to any extension.
//
// The native `opentide serve` speaks the same protocol, so one client drives
// both builds.
//
// `opentide mcp start` in the WASI build asks the same way when it is started
// with OPENTIDE_FETCH=stdio: its `opentide/fetch` requests (ids
// "opentide-fetch-1", ...) are lines on its stdout among its MCP messages, and
// the answers go in on its stdin among the client's. `McpFetchBridge` splits
// the two on that stdio pair, so an extension that serves MCP to an agent
// bridges the module's stdio with it.

import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import * as tls from "node:tls";

/** The method of the server's request. */
export const FETCH_METHOD = "opentide/fetch";

/** `initialize`'s params that ask the server to send its tenant requests here. */
export const FETCH_CAPABILITY = { capabilities: { fetch: true } } as const;

/** The most redirects followed, as reqwest's default policy. */
export const MAX_REDIRECTS = 10;

/** One request the server asks the client to make (`opentide/fetch`'s params). */
export interface FetchParams {
  /** The id of the `run` it belongs to. */
  run: string | null;
  platform: string;
  tenant: string;
  method: string;
  url: string;
  /** In the order written; a name may repeat. */
  headers: [string, string][];
  /** base64, or null for no body. */
  body: string | null;
  connect_timeout_ms: number;
  read_timeout_ms: number;
  tls: { verify: boolean; ca_bundles: string[] };
  /** The tenant's proxy URL (credentials included), or null to go direct. */
  proxy: string | null;
}

/** The tenant's answer (`opentide/fetch`'s result). */
export interface FetchResult {
  status: number;
  headers: [string, string][];
  /** After redirects. */
  url: string;
  /** base64. */
  body: string;
  /** From sending the request to the answer's headers. */
  elapsed_ms: number;
}

/** Why there is no answer: `data.kind` of the error the server reads. */
export type FailureKind = "connect" | "timeout" | "aborted" | "unreachable" | "answer";

/** A failure with its kind, as `perform` rejects. */
export class FetchFailure extends Error {
  readonly kind: FailureKind;

  constructor(kind: FailureKind, message: string) {
    super(message);
    this.kind = kind;
    this.name = "FetchFailure";
  }
}

/** Makes one request: Node's HTTP stack by default, a stand-in in tests. */
export type Perform = (params: FetchParams, signal: AbortSignal) => Promise<FetchResult>;

/** What a `FetchHost` writes: one JSON-RPC message to the server. */
export type Send = (message: object) => void;

/**
 * Answers a server's `opentide/fetch` requests. Hand it every message the
 * server sends; it takes the ones that are its own.
 */
export class FetchHost {
  private readonly send: Send;
  private readonly perform: Perform;
  private readonly inFlight = new Map<string, AbortController>();

  constructor(send: Send, options: { perform?: Perform } = {}) {
    this.send = send;
    this.perform = options.perform ?? performRequest;
  }

  /** The number of requests in flight. */
  get pending(): number {
    return this.inFlight.size;
  }

  /**
   * Takes *message* when it is the server's `opentide/fetch` or its
   * withdrawal (`$/cancelRequest` from `opentide serve`, MCP's
   * `notifications/cancelled` from `opentide mcp start`); whether it did.
   */
  handle(message: unknown): boolean {
    if (!isObject(message)) {
      return false;
    }
    if (message.method === FETCH_METHOD && typeof message.id === "string") {
      this.start(message.id, message.params);
      return true;
    }
    if (
      (message.method === "$/cancelRequest" || message.method === "notifications/cancelled") &&
      isObject(message.params)
    ) {
      const id = message.method === "$/cancelRequest" ? message.params.id : message.params.requestId;
      if (typeof id === "string" && this.inFlight.has(id)) {
        this.inFlight.get(id)?.abort();
        this.inFlight.delete(id);
        return true;
      }
    }
    return false;
  }

  /** Aborts every request in flight, unanswered: the server has gone. */
  dispose(): void {
    for (const controller of this.inFlight.values()) {
      controller.abort();
    }
    this.inFlight.clear();
  }

  private start(id: string, params: unknown): void {
    const controller = new AbortController();
    this.inFlight.set(id, controller);
    const answered = (reply: object): void => {
      // A withdrawn request is not answered: the server has stopped waiting.
      if (this.inFlight.get(id) === controller) {
        this.inFlight.delete(id);
        this.send({ jsonrpc: "2.0", id, ...reply });
      }
    };
    const checked = fetchParams(params);
    if (typeof checked === "string") {
      answered({ error: { code: -32602, message: checked, data: { kind: "unreachable" } } });
      return;
    }
    this.perform(checked, controller.signal).then(
      (result) => answered({ result }),
      (error: unknown) => {
        const failure = asFailure(error, controller.signal);
        answered({
          error: { code: -32000, message: failure.message, data: { kind: failure.kind } },
        });
      },
    );
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** *params* as `FetchParams`, or what is wrong with them. */
export function fetchParams(params: unknown): FetchParams | string {
  if (!isObject(params)) {
    return "opentide/fetch takes an object";
  }
  const { method, url, headers, body, tls: settings } = params;
  if (typeof method !== "string" || typeof url !== "string") {
    return "opentide/fetch needs a method and a url";
  }
  if (
    !Array.isArray(headers) ||
    !headers.every(
      (pair) => Array.isArray(pair) && pair.length === 2 && pair.every((part) => typeof part === "string"),
    )
  ) {
    return "opentide/fetch's headers are [name, value] pairs";
  }
  if (body !== null && body !== undefined && typeof body !== "string") {
    return "opentide/fetch's body is base64 or null";
  }
  const number = (value: unknown, fallback: number): number =>
    typeof value === "number" && Number.isFinite(value) && value > 0 ? value : fallback;
  const verify = isObject(settings) && settings.verify === false ? false : true;
  const bundles =
    isObject(settings) && Array.isArray(settings.ca_bundles)
      ? settings.ca_bundles.filter((pem): pem is string => typeof pem === "string")
      : [];
  return {
    run: typeof params.run === "string" ? params.run : null,
    platform: typeof params.platform === "string" ? params.platform : "",
    tenant: typeof params.tenant === "string" ? params.tenant : "",
    method,
    url,
    headers: headers as [string, string][],
    body: typeof body === "string" ? body : null,
    connect_timeout_ms: number(params.connect_timeout_ms, 120_000),
    read_timeout_ms: number(params.read_timeout_ms, 120_000),
    tls: { verify, ca_bundles: bundles },
    proxy: typeof params.proxy === "string" && params.proxy !== "" ? params.proxy : null,
  };
}

/** *error* as a failure of a kind the server reads. */
function asFailure(error: unknown, signal: AbortSignal): FetchFailure {
  if (signal.aborted) {
    return new FetchFailure("aborted", "the request was withdrawn");
  }
  if (error instanceof FetchFailure) {
    return error;
  }
  return new FetchFailure("unreachable", error instanceof Error ? error.message : String(error));
}

/** Error codes of a connection that could not be made. */
const CONNECT_CODES = new Set([
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ECONNRESET",
  "EPIPE",
  "ETIMEDOUT",
  "CERT_HAS_EXPIRED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

/** A socket error before the answer's headers, as the server reads it. */
function connectFailure(error: unknown): FetchFailure {
  const code = isObject(error) && typeof error.code === "string" ? error.code : "";
  const message = error instanceof Error ? error.message : String(error);
  if (code === "" || CONNECT_CODES.has(code) || code.startsWith("ERR_TLS") || code.startsWith("ERR_SSL")) {
    return new FetchFailure("connect", message);
  }
  return new FetchFailure("unreachable", message);
}

/** The CA certificates a tenant trusts: the default store and its bundles. */
function trusted(bundles: string[]): string[] | undefined {
  return bundles.length === 0 ? undefined : [...tls.rootCertificates, ...bundles];
}

/** One exchange, no redirect followed. */
interface Exchange {
  status: number;
  headers: [string, string][];
  body: Buffer;
  elapsed: number;
}

/** A socket to *target* through the proxy *proxy* (HTTP CONNECT). */
function tunnel(proxy: URL, target: URL, signal: AbortSignal): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const port = target.port || (target.protocol === "https:" ? "443" : "80");
    const headers: Record<string, string> = { host: `${target.hostname}:${port}` };
    if (proxy.username !== "") {
      const credentials = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
      headers["proxy-authorization"] = `Basic ${Buffer.from(credentials).toString("base64")}`;
    }
    const module = proxy.protocol === "https:" ? https : http;
    const request = module.request({
      host: proxy.hostname,
      port: proxy.port || (proxy.protocol === "https:" ? 443 : 80),
      method: "CONNECT",
      path: `${target.hostname}:${port}`,
      headers,
      signal,
    });
    request.once("connect", (answer, socket) => {
      if (answer.statusCode === 200) {
        resolve(socket);
      } else {
        socket.destroy();
        reject(new FetchFailure("connect", `the proxy answered the tunnel with HTTP ${answer.statusCode}`));
      }
    });
    request.once("error", (error) => reject(connectFailure(error)));
    request.end();
  });
}

/** Sends one request and reads its answer whole, within the tenant's limits. */
async function exchange(
  url: URL,
  method: string,
  headers: [string, string][],
  body: Buffer | null,
  params: FetchParams,
  signal: AbortSignal,
): Promise<Exchange> {
  const secure = url.protocol === "https:";
  if (!secure && url.protocol !== "http:") {
    throw new FetchFailure("unreachable", `URL scheme is not allowed: ${url.protocol}`);
  }
  const proxy = params.proxy === null ? null : new URL(params.proxy.includes("://") ? params.proxy : `http://${params.proxy}`);
  const started = Date.now();
  // Through a proxy, an https request is tunnelled; an http one goes to the
  // proxy with its absolute URL.
  let socket: net.Socket | undefined;
  if (proxy !== null && secure) {
    socket = await withTimeout(tunnel(proxy, url, signal), params.connect_timeout_ms, "connect", signal);
  }
  // In the order written; a repeated name sends each of its values.
  const outgoing: Record<string, string | string[]> = {};
  for (const [name, value] of headers) {
    const known = outgoing[name];
    outgoing[name] = known === undefined ? value : [...(Array.isArray(known) ? known : [known]), value];
  }
  const options: https.RequestOptions = {
    method,
    headers: outgoing,
    signal,
    rejectUnauthorized: params.tls.verify,
    ca: trusted(params.tls.ca_bundles),
    servername: net.isIP(url.hostname) === 0 ? url.hostname : undefined,
  };
  let target: URL | string = url;
  if (socket !== undefined) {
    const tunnelled = socket;
    options.createConnection = () =>
      tls.connect({
        socket: tunnelled,
        servername: net.isIP(url.hostname) === 0 ? url.hostname : undefined,
        rejectUnauthorized: params.tls.verify,
        ca: trusted(params.tls.ca_bundles),
      });
  } else if (proxy !== null) {
    options.host = proxy.hostname;
    options.port = proxy.port || 80;
    options.path = url.href;
    // The tenant's Host, not the proxy's, as requests sends it.
    if (!Object.keys(outgoing).some((name) => name.toLowerCase() === "host")) {
      outgoing.host = url.host;
    }
    target = `http://${proxy.host}`;
  }
  const module = secure ? https : http;
  return new Promise<Exchange>((resolve, reject) => {
    let settled = false;
    const fail = (failure: FetchFailure): void => {
      if (!settled) {
        settled = true;
        clearTimeout(connectTimer);
        request.destroy();
        reject(failure);
      }
    };
    const request = module.request(target, options);
    // The connect limit runs until the connection (TLS included) is up; the
    // read limit, from then on, for each wait on the answer.
    const connectTimer = setTimeout(
      () => fail(new FetchFailure("connect", `no connection within ${params.connect_timeout_ms} ms`)),
      params.connect_timeout_ms,
    );
    request.once("socket", (opened) => {
      const connected = (): void => {
        clearTimeout(connectTimer);
        opened.setTimeout(params.read_timeout_ms, () =>
          fail(new FetchFailure("timeout", `no answer within ${params.read_timeout_ms} ms`)),
        );
      };
      if (opened.connecting) {
        opened.once(secure ? "secureConnect" : "connect", connected);
      } else {
        connected();
      }
    });
    request.once("error", (error) => {
      if (signal.aborted) {
        fail(new FetchFailure("aborted", "the request was withdrawn"));
      } else {
        fail(connectFailure(error));
      }
    });
    request.once("response", (answer) => {
      const elapsed = Date.now() - started;
      const pairs: [string, string][] = [];
      for (let index = 0; index + 1 < answer.rawHeaders.length; index += 2) {
        pairs.push([answer.rawHeaders[index].toLowerCase(), answer.rawHeaders[index + 1]]);
      }
      const chunks: Buffer[] = [];
      answer.on("data", (chunk: Buffer) => chunks.push(chunk));
      answer.once("error", (error) =>
        fail(signal.aborted ? new FetchFailure("aborted", "the request was withdrawn") : new FetchFailure("answer", error.message)),
      );
      answer.once("aborted", () => fail(new FetchFailure("answer", "the connection closed before the answer's end")));
      answer.once("end", () => {
        if (!settled) {
          settled = true;
          clearTimeout(connectTimer);
          resolve({ status: answer.statusCode ?? 0, headers: pairs, body: Buffer.concat(chunks), elapsed });
        }
      });
    });
    if (body !== null) {
      request.write(body);
    }
    request.end();
  });
}

/** *work*, or a failure of *kind* after *ms*. */
function withTimeout<T>(work: Promise<T>, ms: number, kind: FailureKind, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new FetchFailure(kind, `no connection within ${ms} ms`)), ms);
    const aborted = (): void => {
      clearTimeout(timer);
      reject(new FetchFailure("aborted", "the request was withdrawn"));
    };
    signal.addEventListener("abort", aborted, { once: true });
    work.then(
      (value) => {
        clearTimeout(timer);
        signal.removeEventListener("abort", aborted);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        signal.removeEventListener("abort", aborted);
        reject(error);
      },
    );
  });
}

/**
 * Whether a redirect from *from* to *to* is followed, as the native
 * transport's `follows_redirect`: on the same origin, or from `http` to
 * `https` on the same host with default ports. Any other hop would carry a
 * platform's own credential header (Carbon Black's `X-Auth-Token`,
 * Bitdefender's `X-API-Key`) to another host, so it is not taken (#1142).
 */
export function followsRedirect(from: URL, to: URL): boolean {
  if (from.origin === to.origin) {
    return true;
  }
  return (
    from.protocol === "http:" &&
    to.protocol === "https:" &&
    from.hostname === to.hostname &&
    from.port === "" &&
    to.port === ""
  );
}

/** Headers no redirect to another origin carries (as reqwest strips them). */
const SENSITIVE = new Set(["authorization", "cookie", "proxy-authorization", "www-authenticate"]);

/**
 * Makes the request *params* describe with Node's HTTP stack, following
 * redirects as the native transport does: at most `MAX_REDIRECTS`, and only
 * those `followsRedirect` takes (any other is the answer); a 303, and a 301
 * or 302 to a POST, become a GET without a body; the standard credentials
 * are not sent to another origin (an http to https upgrade).
 */
export async function performRequest(params: FetchParams, signal: AbortSignal): Promise<FetchResult> {
  let url = new URL(params.url);
  let method = params.method;
  let headers = params.headers;
  let body: Buffer | null = params.body === null ? null : Buffer.from(params.body, "base64");
  let elapsed: number | undefined;
  for (let redirects = 0; ; redirects += 1) {
    const answer = await exchange(url, method, headers, body, params, signal);
    elapsed ??= answer.elapsed;
    const location = answer.headers.find(([name]) => name === "location")?.[1];
    const next = location === undefined ? undefined : new URL(location, url);
    const redirected =
      [301, 302, 303, 307, 308].includes(answer.status) && next !== undefined && followsRedirect(url, next);
    if (!redirected || next === undefined || redirects >= MAX_REDIRECTS) {
      return {
        status: answer.status,
        headers: answer.headers,
        url: url.href,
        body: answer.body.toString("base64"),
        elapsed_ms: elapsed,
      };
    }
    if (answer.status === 303 || ((answer.status === 301 || answer.status === 302) && method === "POST")) {
      method = "GET";
      body = null;
      headers = headers.filter(([name]) => !["content-type", "content-length"].includes(name.toLowerCase()));
    }
    if (next.origin !== url.origin) {
      headers = headers.filter(([name]) => !SENSITIVE.has(name.toLowerCase()));
    }
    url = next;
  }
}

// ---- opentide mcp start, its tenant requests among its MCP messages ----

/** The variable that makes the WASI build's `opentide mcp start` ask its client for each tenant request. */
export const MCP_FETCH_VARIABLE = "OPENTIDE_FETCH";

/**
 * The environment to start the WASI module's `opentide mcp start` with, added
 * to whatever else it is given (the native build ignores it).
 */
export const MCP_FETCH_ENVIRONMENT = { [MCP_FETCH_VARIABLE]: "stdio" } as const;

/** The prefix of the ids of `opentide mcp start`'s requests: no MCP client's id starts so by accident. */
export const MCP_FETCH_ID_PREFIX = "opentide-fetch-";

/** Where a `McpFetchBridge` writes: whole lines, each with its newline, ready for a pipe. */
export interface McpFetchSink {
  /** To the module's stdin: the client's MCP messages and the answers to its tenant requests. */
  toServer: (line: string) => void;
  /** To the MCP client: the module's MCP messages, its tenant requests taken out. */
  toClient: (line: string) => void;
}

/** Splits a stream of chunks into lines, holding back a partial one. */
class LineSplitter {
  private readonly decoder = new TextDecoder();
  private partial = "";

  push(chunk: string | Uint8Array): string[] {
    this.partial += typeof chunk === "string" ? chunk : this.decoder.decode(chunk, { stream: true });
    const lines: string[] = [];
    for (let end = this.partial.indexOf("\n"); end >= 0; end = this.partial.indexOf("\n")) {
      lines.push(this.partial.slice(0, end + 1));
      this.partial = this.partial.slice(end + 1);
    }
    return lines;
  }

  /** What is left when the stream ends: a last line without its newline. */
  end(): string | undefined {
    const rest = this.partial + this.decoder.decode();
    this.partial = "";
    return rest === "" ? undefined : `${rest}\n`;
  }
}

/**
 * Splits `opentide mcp start`'s tenant requests from its MCP messages on its
 * stdio pair. Started with `MCP_FETCH_ENVIRONMENT`, the WASI module writes
 * each tenant request as an `opentide/fetch` line on stdout among its MCP
 * messages, and reads the answer on stdin among the client's. The bridge sits
 * between the module and the MCP client:
 *
 * - `fromServer(chunk)`: the module's stdout. An `opentide/fetch` line (and
 *   the `notifications/cancelled` that withdraws one) is the host's, which
 *   answers it with `FetchHost`; every other line goes to `toClient`.
 * - `fromClient(chunk)`: the client's messages, to `toServer` a whole line at
 *   a time, so an answer the host writes never lands inside one.
 *
 * Neither direction reorders anything: the MCP messages reach each side in the
 * order they were written. `toServer` is called for answers asynchronously, as
 * each request finishes.
 *
 * What the bridge keeps from the client, and from the agent behind it:
 *
 * - **A tenant request never reaches the client.** It carries the tenant's
 *   credentials (the `Authorization` and API-key headers, the CA bundles). A
 *   line that mentions `opentide/fetch` and cannot be read as a message of the
 *   host's is dropped, not forwarded: nothing that might hold a credential
 *   goes to `toClient` on a failure to understand it.
 * - **The client cannot answer a tenant request.** A client line that is a
 *   response (it has no `method`) to an id with the `MCP_FETCH_ID_PREFIX`, or
 *   that mentions the prefix and cannot be read, is dropped: the module trusts
 *   an answer on its stdin for the request it asked, and an agent could
 *   otherwise forge the result of a deploy or a query.
 * - **A response to a request the client cancelled is dropped.** The module may
 *   still finish a call it was told to cancel, and MCP has the receiver send
 *   no response for it.
 * - **After `dispose()` no new tenant request is started.**
 */
export class McpFetchBridge {
  private readonly sink: McpFetchSink;
  private readonly host: FetchHost;
  private readonly fromModule = new LineSplitter();
  private readonly fromAgent = new LineSplitter();
  /** Request ids the client cancelled (as their JSON text): their responses are dropped. */
  private readonly cancelled = new Set<string>();
  private disposed = false;

  constructor(sink: McpFetchSink, options: { perform?: Perform } = {}) {
    this.sink = sink;
    this.host = new FetchHost(
      (message) => {
        // After the module has gone there is nobody to answer.
        if (!this.disposed) {
          this.sink.toServer(`${JSON.stringify(message)}\n`);
        }
      },
      options,
    );
  }

  /** The number of tenant requests in flight. */
  get pending(): number {
    return this.host.pending;
  }

  /** A chunk of the module's stdout. */
  fromServer(chunk: string | Uint8Array): void {
    for (const line of this.fromModule.push(chunk)) {
      this.serverLine(line);
    }
  }

  /** A chunk of the client's messages for the module. */
  fromClient(chunk: string | Uint8Array): void {
    for (const line of this.fromAgent.push(chunk)) {
      this.clientLine(line);
    }
  }

  /** The module's stdout ended: a last line without its newline is delivered. */
  endServer(): void {
    const rest = this.fromModule.end();
    if (rest !== undefined) {
      this.serverLine(rest);
    }
  }

  /** The client's input ended: a last line without its newline is delivered. */
  endClient(): void {
    const rest = this.fromAgent.end();
    if (rest !== undefined) {
      this.clientLine(rest);
    }
  }

  /** Aborts every request in flight, unanswered: the module has gone. */
  dispose(): void {
    this.disposed = true;
    this.host.dispose();
  }

  private clientLine(line: string): void {
    if (line.includes(MCP_FETCH_ID_PREFIX)) {
      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        // Fail closed: a line that names the prefix and cannot be read is not passed on.
        return;
      }
      if (forgesAnAnswer(message)) {
        return;
      }
    }
    if (line.includes("notifications/cancelled")) {
      const id = cancelledRequest(line);
      if (id !== undefined) {
        this.cancelled.add(id);
        // Bounded: the oldest are forgotten (a cancelled request that was already answered).
        while (this.cancelled.size > MAX_CANCELLED) {
          const oldest = this.cancelled.values().next().value;
          if (oldest === undefined) break;
          this.cancelled.delete(oldest);
        }
      }
    }
    this.sink.toServer(line);
  }

  private serverLine(line: string): void {
    if (line.includes("opentide/fetch")) {
      let message: unknown;
      try {
        message = JSON.parse(line);
      } catch {
        // Fail closed: a line that mentions the method and cannot be read may
        // hold a tenant's credentials, and is never forwarded.
        return;
      }
      if (!isObject(message) || message.method === "opentide/fetch") {
        // A tenant request (or something shaped so it cannot be told from
        // one): the host's alone, started only while the bridge is live.
        if (!this.disposed && isObject(message)) {
          this.host.handle(message);
        }
        return;
      }
      // Valid JSON that is not a request: an MCP message that mentions the
      // method in its text (a tool's result), passed on below.
    }
    if (line.includes("notifications/cancelled")) {
      const message = parseObject(line);
      if (message !== undefined && this.takesWithdrawal(message)) {
        return;
      }
    }
    if (this.cancelled.size > 0 && this.dropsCancelledResponse(line)) {
      return;
    }
    this.sink.toClient(line);
  }

  /** Whether *message* withdraws one of the module's tenant requests: the host's, handled. */
  private takesWithdrawal(message: Record<string, unknown>): boolean {
    if (message.method !== "notifications/cancelled") {
      return false;
    }
    const params = message.params;
    if (!isObject(params) || typeof params.requestId !== "string" || !params.requestId.startsWith(MCP_FETCH_ID_PREFIX)) {
      return false;
    }
    // A withdrawal of a request already answered has nothing to abort, and is not the client's either.
    this.host.handle(message);
    return true;
  }

  /** Whether *line* is the response to a request the client cancelled; the id is then forgotten. */
  private dropsCancelledResponse(line: string): boolean {
    for (const id of this.cancelled) {
      if (!line.includes(`"id":${id}`)) {
        continue;
      }
      const message = parseObject(line);
      if (message !== undefined && message.method === undefined && JSON.stringify(message.id) === id) {
        this.cancelled.delete(id);
        return true;
      }
    }
    return false;
  }
}

/** How many cancelled request ids the bridge remembers. */
const MAX_CANCELLED = 256;

/** *line* as an object, or undefined. */
function parseObject(line: string): Record<string, unknown> | undefined {
  try {
    const message: unknown = JSON.parse(line);
    return isObject(message) ? message : undefined;
  } catch {
    return undefined;
  }
}

/** The id (as JSON text) of the request a `notifications/cancelled` line cancels. */
function cancelledRequest(line: string): string | undefined {
  const message = parseObject(line);
  if (message === undefined || message.method !== "notifications/cancelled" || !isObject(message.params)) {
    return undefined;
  }
  const id = message.params.requestId;
  return typeof id === "string" || typeof id === "number" ? JSON.stringify(id) : undefined;
}

/**
 * Whether the client message *message* answers (or is shaped to look like an
 * answer to) a request of the module's: a response, with no `method`, to an
 * id that starts with `MCP_FETCH_ID_PREFIX`. A batch holding one is one.
 */
function forgesAnAnswer(message: unknown): boolean {
  if (Array.isArray(message)) {
    return message.some(forgesAnAnswer);
  }
  return (
    isObject(message) &&
    typeof message.id === "string" &&
    message.id.startsWith(MCP_FETCH_ID_PREFIX) &&
    typeof message.method !== "string"
  );
}
