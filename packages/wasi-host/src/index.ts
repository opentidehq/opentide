// @opentide/wasi-host: the extension host's half of `opentide/fetch` (W2,
// docs/engine/connector-transport.md).
//
// The WASI build of opentide runs under VS Code's WASI host, which gives it
// no sockets. Its `opentide serve` asks the client to make each tenant
// request: a server-to-client JSON-RPC request `opentide/fetch`, whose id is
// a string ("h1", "h2", ...). `FetchHost` answers those requests from the
// extension host, with Node's own HTTP stack: the tenant's TLS verification
// and CA bundles, its proxy (a CONNECT tunnel), its connect and read
// timeouts, redirects as reqwest follows them, and cancellation when the
// server withdraws a request (`$/cancelRequest`). VS Code's proxy support
// (`http.proxy`, the OS certificate store), which patches Node's `https`,
// applies as it does to any extension.
//
// The native `opentide serve` speaks the same protocol, so one client drives
// both builds.

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
   * withdrawal; whether it did.
   */
  handle(message: unknown): boolean {
    if (!isObject(message)) {
      return false;
    }
    if (message.method === FETCH_METHOD && typeof message.id === "string") {
      this.start(message.id, message.params);
      return true;
    }
    if (message.method === "$/cancelRequest" && isObject(message.params)) {
      const id = message.params.id;
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

/** Headers no redirect to another origin carries (as reqwest strips them). */
const SENSITIVE = new Set(["authorization", "cookie", "proxy-authorization", "www-authenticate"]);

/**
 * Makes the request *params* describe with Node's HTTP stack, following
 * redirects as reqwest does: at most `MAX_REDIRECTS`; a 303, and a 301 or
 * 302 to a POST, become a GET without a body; credentials are not sent to
 * another origin.
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
    const redirected = [301, 302, 303, 307, 308].includes(answer.status) && location !== undefined;
    if (!redirected || redirects >= MAX_REDIRECTS) {
      return {
        status: answer.status,
        headers: answer.headers,
        url: url.href,
        body: answer.body.toString("base64"),
        elapsed_ms: elapsed,
      };
    }
    const next = new URL(location, url);
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
