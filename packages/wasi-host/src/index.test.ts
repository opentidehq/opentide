import assert from "node:assert/strict";
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  FETCH_CAPABILITY,
  FetchFailure,
  type FetchParams,
  type FetchResult,
  FetchHost,
  McpFetchBridge,
  MCP_FETCH_ENVIRONMENT,
  fetchParams,
  followsRedirect,
  performRequest,
} from "./index.ts";

const root = fileURLToPath(new URL("../../../", import.meta.url));

// ---- Node's HTTP stack, against servers on the loopback ----

/** A server on the loopback answering with *handler*; its origin. */
async function serve(handler: http.RequestListener): Promise<{ origin: string; close: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

function params(overrides: Partial<FetchParams>): FetchParams {
  return {
    run: "1",
    platform: "elastic",
    tenant: "soc",
    method: "GET",
    url: "http://127.0.0.1:9/",
    headers: [],
    body: null,
    connect_timeout_ms: 2000,
    read_timeout_ms: 2000,
    tls: { verify: true, ca_bundles: [] },
    proxy: null,
    ...overrides,
  };
}

async function failure(work: Promise<unknown>): Promise<FetchFailure> {
  try {
    await work;
  } catch (error) {
    assert.ok(error instanceof FetchFailure, String(error));
    return error;
  }
  assert.fail("the request was answered");
}

test("a request is sent as written and its answer read whole", async () => {
  let seen: { method?: string; url?: string; headers: string[]; body: string } = { headers: [], body: "" };
  const server = await serve((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      seen = {
        method: request.method,
        url: request.url,
        headers: request.rawHeaders,
        body: Buffer.concat(chunks).toString(),
      };
      response.writeHead(201, [
        ["Content-Type", "application/json"],
        ["X-Twice", "a"],
        ["X-Twice", "b"],
      ]);
      response.end('{"ok":true}');
    });
  });
  try {
    const result = await performRequest(
      params({
        method: "POST",
        url: `${server.origin}/api/rules?id=1`,
        headers: [
          ["Content-Type", "application/json"],
          ["Authorization", "Bearer token"],
        ],
        body: Buffer.from('{"a":1}').toString("base64"),
      }),
      new AbortController().signal,
    );
    assert.equal(seen.method, "POST");
    assert.equal(seen.url, "/api/rules?id=1");
    assert.equal(seen.body, '{"a":1}');
    // The platform's headers, in the order it wrote them.
    const names = seen.headers.filter((_, index) => index % 2 === 0).map((name) => name.toLowerCase());
    assert.ok(names.indexOf("content-type") < names.indexOf("authorization"), names.join(","));
    assert.equal(result.status, 201);
    assert.equal(Buffer.from(result.body, "base64").toString(), '{"ok":true}');
    assert.deepEqual(
      result.headers.filter(([name]) => name === "x-twice"),
      [
        ["x-twice", "a"],
        ["x-twice", "b"],
      ],
    );
    assert.equal(result.url, `${server.origin}/api/rules?id=1`);
    assert.ok(result.elapsed_ms >= 0);
  } finally {
    await server.close();
  }
});

test("redirects are followed on the tenant's origin only", async () => {
  let reached = 0;
  const other = await serve((request, response) => {
    reached += 1;
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(`${request.method} ${request.headers.authorization ?? "no authorization"}`);
  });
  const first = await serve((request, response) => {
    if (request.url === "/moved") {
      response.writeHead(302, { location: "/here" });
      response.end();
    } else if (request.url === "/here") {
      response.writeHead(200);
      response.end(`${request.method} ${request.headers.authorization ?? "no authorization"}`);
    } else {
      response.writeHead(307, { location: `${other.origin}/elsewhere` });
      response.end();
    }
  });
  try {
    const signal = new AbortController().signal;
    const posted = await performRequest(
      params({
        method: "POST",
        url: `${first.origin}/moved`,
        headers: [["authorization", "Bearer token"]],
        body: Buffer.from("x").toString("base64"),
      }),
      signal,
    );
    assert.equal(Buffer.from(posted.body, "base64").toString(), "GET Bearer token");
    assert.equal(posted.url, `${first.origin}/here`);
    // #1142: a redirect to another origin is the answer; the other host,
    // which would get Carbon Black's X-Auth-Token, receives nothing.
    const away = await performRequest(
      params({ url: `${first.origin}/away`, headers: [["x-auth-token", "secret"]] }),
      signal,
    );
    assert.equal(away.status, 307);
    assert.equal(away.url, `${first.origin}/away`);
    assert.equal(reached, 0, "the other origin was asked");
  } finally {
    await first.close();
    await other.close();
  }
});

test("which redirects are followed", () => {
  const from = new URL("https://defense.conferdeploy.net/appservices");
  assert.ok(followsRedirect(from, new URL("https://defense.conferdeploy.net/other")));
  assert.ok(followsRedirect(from, new URL("https://DEFENSE.conferdeploy.net:443/a")));
  for (const to of [
    "https://evil.example/",
    "http://defense.conferdeploy.net/a",
    "https://defense.conferdeploy.net:8443/a",
    "https://defense.conferdeploy.net.evil.example/a",
  ]) {
    assert.ok(!followsRedirect(from, new URL(to)), to);
  }
  const plain = new URL("http://graylog.lab/api");
  assert.ok(followsRedirect(plain, new URL("https://graylog.lab/api")));
  assert.ok(!followsRedirect(plain, new URL("https://other.lab/api")));
  assert.ok(!followsRedirect(plain, new URL("https://graylog.lab:9000/api")));
});

test("a refused connection, a silent tenant and a withdrawn request fail by kind", async () => {
  const closed = await serve(() => {});
  const refused = closed.origin;
  await closed.close();
  assert.equal((await failure(performRequest(params({ url: `${refused}/` }), new AbortController().signal))).kind, "connect");

  const silent = await serve(() => {});
  try {
    const slow = await failure(
      performRequest(params({ url: `${silent.origin}/`, read_timeout_ms: 300 }), new AbortController().signal),
    );
    assert.equal(slow.kind, "timeout");
    const controller = new AbortController();
    const pending = performRequest(params({ url: `${silent.origin}/` }), controller.signal);
    setTimeout(() => controller.abort(), 100);
    assert.equal((await failure(pending)).kind, "aborted");
  } finally {
    await silent.close();
  }
  assert.equal(
    (await failure(performRequest(params({ url: "ftp://127.0.0.1/q" }), new AbortController().signal))).kind,
    "unreachable",
  );
});

test("an http request through the tenant's proxy goes to the proxy with its URL", async () => {
  let asked = "";
  const proxy = await serve((request, response) => {
    asked = `${request.url} ${request.headers.host}`;
    response.writeHead(200);
    response.end("via the proxy");
  });
  try {
    const result = await performRequest(
      params({ url: "http://tenant.invalid:8089/services/server/info", proxy: proxy.origin }),
      new AbortController().signal,
    );
    assert.equal(asked, "http://tenant.invalid:8089/services/server/info tenant.invalid:8089");
    assert.equal(Buffer.from(result.body, "base64").toString(), "via the proxy");
  } finally {
    await proxy.close();
  }
});

// ---- the protocol ----

test("the host takes its own messages and answers each request once", async () => {
  const sent: Record<string, unknown>[] = [];
  let release: () => void = () => {};
  const host = new FetchHost((message) => sent.push(message as Record<string, unknown>), {
    perform: (request, signal) =>
      new Promise<FetchResult>((resolve, reject) => {
        if (request.url.endsWith("/refused")) {
          reject(new FetchFailure("connect", "refused"));
          return;
        }
        if (request.url.endsWith("/held")) {
          signal.addEventListener("abort", () => reject(new Error("aborted")));
          return;
        }
        release = () => resolve({ status: 200, headers: [], url: request.url, body: "", elapsed_ms: 1 });
      }),
  });
  const ask = (id: string, url: string) =>
    host.handle({ jsonrpc: "2.0", id, method: "opentide/fetch", params: params({ url }) });
  assert.equal(host.handle({ jsonrpc: "2.0", id: 1, result: {} }), false);
  assert.equal(host.handle({ jsonrpc: "2.0", method: "progress", params: {} }), false);
  assert.equal(ask("h1", "https://t.invalid/ok"), true);
  assert.equal(ask("h2", "https://t.invalid/refused"), true);
  assert.equal(ask("h3", "https://t.invalid/held"), true);
  assert.equal(host.handle({ jsonrpc: "2.0", id: "h4", method: "opentide/fetch", params: 7 }), true);
  // Withdrawn: never answered.
  assert.equal(host.handle({ jsonrpc: "2.0", method: "$/cancelRequest", params: { id: "h3" } }), true);
  assert.equal(host.handle({ jsonrpc: "2.0", method: "$/cancelRequest", params: { id: 2 } }), false);
  release();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(
    sent.map((message) => message.id),
    ["h4", "h2", "h1"],
  );
  assert.deepEqual(sent[0].error, {
    code: -32602,
    message: "opentide/fetch takes an object",
    data: { kind: "unreachable" },
  });
  assert.deepEqual(sent[1].error, { code: -32000, message: "refused", data: { kind: "connect" } });
  assert.deepEqual((sent[2].result as FetchResult).status, 200);
  assert.equal(host.pending, 0);
});

test("params are read with the server's defaults", () => {
  assert.equal(typeof fetchParams({ method: "GET" }), "string");
  assert.equal(typeof fetchParams({ method: "GET", url: "https://x.invalid/", headers: [["a"]] }), "string");
  const read = fetchParams({ method: "GET", url: "https://x.invalid/", headers: [], tls: { verify: false } });
  assert.ok(typeof read !== "string");
  assert.equal(read.tls.verify, false);
  assert.equal(read.read_timeout_ms, 120_000);
  assert.equal(read.proxy, null);
});

// ---- opentide serve, its tenant requests answered from the golden cassettes ----

/** A cassette's request, as `opentide-cassette` records it. */
interface Recorded {
  method: string;
  url: string;
  headers: [string, string][];
  body: string | { base64: string };
}

interface Cassette {
  interactions: { request: Recorded; response: { status: number; headers: [string, string][]; body: Recorded["body"] } }[];
}

const SECRET = "golden-stand-in-credential";
/** `opentide-cassette`'s transport headers, left out of a recording. */
const TRANSPORT = new Set([
  "host",
  "user-agent",
  "accept-encoding",
  "connection",
  "content-length",
  "transfer-encoding",
  "te",
  "keep-alive",
  "proxy-connection",
  "proxy-authorization",
  "upgrade",
  "expect",
  "x-opentide-cassette-origin",
]);

function bytes(body: Recorded["body"]): Buffer {
  return typeof body === "string" ? Buffer.from(body) : Buffer.from(body.base64, "base64");
}

/** *request* as the recording proxy records it: redacted, sorted. */
function recorded(request: FetchParams): Recorded {
  const redact = (text: string) => text.split(SECRET).join("REDACTED");
  const headers = request.headers
    .map(([name, value]): [string, string] => [name.toLowerCase(), value])
    .filter(([name, value]) => !TRANSPORT.has(name) && !(name === "accept" && value.trim() === "*/*"))
    .map(([name, value]): [string, string] => {
      if (["authorization", "cookie", "x-api-key"].includes(name) || name.endsWith("-token") || name.endsWith("-key")) {
        const scheme = value.trim().split(" ");
        return [name, scheme.length > 1 ? `${scheme[0]} REDACTED` : "REDACTED"];
      }
      return [name, redact(value)];
    })
    .sort((a, b) => (a[0] + a[1] < b[0] + b[1] ? -1 : 1));
  const body = request.body === null ? "" : redact(Buffer.from(request.body, "base64").toString());
  return { method: request.method, url: redact(request.url), headers, body };
}

/** Whether two bodies agree: as JSON data when both are JSON, else as text. */
function sameBody(want: string, got: string): boolean {
  try {
    return JSON.stringify(JSON.parse(want)) === JSON.stringify(JSON.parse(got));
  } catch {
    return want === got;
  }
}

/** Whether *headers* (as recorded: names in lower case) say the body is a form. */
function isForm(headers: [string, string][]): boolean {
  return headers.some(
    ([name, value]) => name === "content-type" && value.split(";")[0].trim().toLowerCase() === "application/x-www-form-urlencoded",
  );
}

/**
 * A form text's decoded fields, ordered by name (a stable sort: a repeated
 * name's values stay in the order they came), as opentide-cassette's
 * `replay::fields`: `+` and `%20`, `~` and `%7E` are the same.
 */
function formFields(text: string): [string, string][] {
  return [...new URLSearchParams(text)].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
}

/**
 * Whether two `application/x-www-form-urlencoded` bodies hold the same
 * fields once decoded, names in any order (opentide-cassette's
 * `replay::same_form`, which the Rust replays use).
 */
function sameForm(want: string, got: string): boolean {
  return want === got || JSON.stringify(formFields(want)) === JSON.stringify(formFields(got));
}

/** Whether a body sent agrees with the recorded one, by the recorded request's type. */
function sameRequestBody(want: Recorded, wantBody: string, got: string): boolean {
  return isForm(want.headers) ? sameForm(wantBody, got) : sameBody(wantBody, got);
}

test("a form body is compared as its decoded fields, in any order", () => {
  const recorded = "client_id=app&client_secret=REDACTED&grant_type=client_credentials&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default";
  // The fields in another order, another (valid) encoding of the same text.
  assert.ok(sameForm(recorded, "grant_type=client_credentials&client_id=app&client_secret=REDACTED&scope=https%3a%2f%2fgraph.microsoft.com%2f.default"));
  assert.ok(sameForm("q=a+b&n=%7E", "n=~&q=a%20b"));
  // A value, a field more or less, or a repeated name's values in another order: different.
  assert.ok(!sameForm(recorded, recorded.replace("client_id=app", "client_id=other")));
  assert.ok(!sameForm(recorded, `${recorded}&client_info=1`));
  assert.ok(!sameForm("a=1&a=2", "a=2&a=1"));
  assert.ok(!sameForm("flag=True", "flag=true"));
  // Only a recorded form body is read as a form; JSON stays JSON data.
  const form: Recorded = { method: "POST", url: "https://x.invalid/t", headers: [["content-type", "application/x-www-form-urlencoded"]], body: "" };
  const json: Recorded = { method: "POST", url: "https://x.invalid/t", headers: [["content-type", "application/json"]], body: "" };
  assert.ok(sameRequestBody(form, "a=1&b=2", "b=2&a=1"));
  assert.ok(!sameRequestBody(json, "a=1&b=2", "b=2&a=1"));
  assert.ok(sameRequestBody(json, '{"a": 1, "b": 2}', '{"a":1,"b":2}'));
});

/** Answers from *name*'s cassette in order; checks each request against it. */
function cassetteHost(name: string): { perform: (params: FetchParams) => Promise<FetchResult>; mismatches: string[]; asked: number } {
  const cassette: Cassette = JSON.parse(readFileSync(join(root, `tests/cassettes/${name}.json`), "utf8"));
  const state = { mismatches: [] as string[], asked: 0 };
  return {
    get mismatches() {
      return state.mismatches;
    },
    get asked() {
      return state.asked;
    },
    perform: async (request: FetchParams): Promise<FetchResult> => {
      const interaction = cassette.interactions[state.asked];
      state.asked += 1;
      if (interaction === undefined) {
        throw new FetchFailure("connect", "past the cassette's end");
      }
      const got = recorded(request);
      const want = interaction.request;
      const wantBody = bytes(want.body).toString();
      if (
        got.method !== want.method ||
        got.url !== want.url ||
        JSON.stringify(got.headers) !== JSON.stringify(want.headers) ||
        !sameRequestBody(want, wantBody, got.body as string)
      ) {
        state.mismatches.push(`request ${state.asked - 1}: ${JSON.stringify(got)} is not ${JSON.stringify(want)}`);
      }
      return {
        status: interaction.response.status,
        headers: interaction.response.headers,
        url: request.url,
        body: bytes(interaction.response.body).toString("base64"),
        elapsed_ms: 1,
      };
    },
  };
}

/** `opentide serve` in *ws*, as a client sees it: one JSON message a line. */
class ServeClient {
  readonly process: ChildProcessWithoutNullStreams;
  private buffer = "";
  private waiting: ((message: Record<string, unknown>) => void)[] = [];
  private queued: Record<string, unknown>[] = [];
  private next = 0;
  readonly host: FetchHost;

  constructor(server: Server, ws: string, perform: (params: FetchParams) => Promise<FetchResult>) {
    // WASI gives the module no working directory: the host names it in PWD.
    this.process = spawn(server.command, [...server.args, "serve"], {
      cwd: ws,
      env: { PATH: process.env.PATH ?? "", HOME: ws, PWD: ws, NO_COLOR: "1", TZ: "UTC", LANG: "C.UTF-8" },
    });
    this.host = new FetchHost((message) => this.write(message), { perform });
    this.process.stdout.setEncoding("utf8");
    this.process.stdout.on("data", (chunk: string) => {
      this.buffer += chunk;
      let end = this.buffer.indexOf("\n");
      while (end >= 0) {
        const line = this.buffer.slice(0, end);
        this.buffer = this.buffer.slice(end + 1);
        end = this.buffer.indexOf("\n");
        const message = JSON.parse(line) as Record<string, unknown>;
        if (this.host.handle(message)) {
          continue;
        }
        const waiter = this.waiting.shift();
        if (waiter) waiter(message);
        else this.queued.push(message);
      }
    });
  }

  write(message: object): void {
    this.process.stdin.write(`${JSON.stringify(message)}\n`);
  }

  private message(): Promise<Record<string, unknown>> {
    const queued = this.queued.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve) => this.waiting.push(resolve));
  }

  /** Sends a request; its id. */
  request(method: string, params: object): number {
    this.next += 1;
    this.write({ jsonrpc: "2.0", id: this.next, method, params });
    return this.next;
  }

  async call(method: string, params: object): Promise<Record<string, unknown>> {
    return this.answer(this.request(method, params));
  }

  async answer(id: number): Promise<Record<string, unknown>> {
    for (;;) {
      const message = await this.message();
      if (message.id === id) return message;
    }
  }

  async close(): Promise<void> {
    this.write({ jsonrpc: "2.0", method: "exit" });
    this.process.stdin.end();
    await new Promise((resolve) => this.process.once("exit", resolve));
  }
}

/** How to start `opentide serve`: a command and the arguments before `serve`. */
interface Server {
  name: string;
  command: string;
  args: string[];
}

// The native server: CI sets OPENTIDE_BIN; locally the debug build is used
// when it exists. The WASI build (`scripts/engine/build-wasm.sh cli`) runs
// the same cases under Node's own WASI when OPENTIDE_WASI_CLI names it: the
// module has no network, so every tenant request goes through the host.
// The debug build is in the target pool CARGO_TARGET_DIR names (AGENTS.md),
// else in the checkout's target/.
const targetDir = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : join(root, "target");
const debugBinary = join(targetDir, "debug/opentide-cli");
// Both are resolved here: the server is spawned in a scratch workspace, where
// a relative path would name nothing.
const nativeBinary =
  process.env.OPENTIDE_BIN === undefined
    ? existsSync(debugBinary)
      ? debugBinary
      : undefined
    : resolve(process.env.OPENTIDE_BIN);
const wasiModule = process.env.OPENTIDE_WASI_CLI === undefined ? undefined : resolve(process.env.OPENTIDE_WASI_CLI);
// A path that is set must exist: CI names a binary it built, and a wrong one
// fails the run rather than skipping its cases.
for (const [variable, path] of [
  ["OPENTIDE_BIN", process.env.OPENTIDE_BIN === undefined ? undefined : nativeBinary],
  ["OPENTIDE_WASI_CLI", wasiModule],
] as const) {
  if (path !== undefined && !existsSync(path)) {
    throw new Error(`${variable} names ${path}, which does not exist`);
  }
}
const SERVERS: (Server | string)[] = [
  nativeBinary === undefined
    ? "native: no opentide binary (OPENTIDE_BIN)"
    : { name: "native", command: nativeBinary, args: [] },
  wasiModule === undefined
    ? "wasi: no WASI module (OPENTIDE_WASI_CLI)"
    : {
        name: "wasi",
        command: process.execPath,
        // Node's fast WASI calls can crash a large instance (scripts/engine/wasi-run.mjs).
        args: ["--no-turbo-fast-api-calls", join(root, "scripts/engine/wasi-run.mjs"), wasiModule],
      },
];

interface GoldenCase {
  fixture: string;
  argv: string[];
  credential: string;
  cassette: string;
  exit: number;
}

const CASES: GoldenCase[] = [
  {
    fixture: "tenants",
    argv: [
      "query",
      "--platform",
      "defender_for_endpoint",
      "--from",
      "2099-01-01T00:00:00Z",
      "--to",
      "2099-01-01T01:00:00Z",
      "--limit",
      "1",
      "DeviceProcessEvents | project Timestamp, DeviceName",
    ],
    credential: "DEFENDER_CLIENT_SECRET",
    cassette: "golden/query-defender",
    exit: 0,
  },
  {
    fixture: "live-tenants",
    argv: ["validate", "query", "--live", "--platform", "splunk", "--uuid", "00000000-0000-4000-8046-000000000001"],
    credential: "SPLUNK_TOKEN",
    cassette: "golden/validate-live-splunk-parsed",
    exit: 0,
  },
  {
    fixture: "deploy-tenants",
    argv: ["deploy", "--platform", "crowdstrike", "--strategy", "PREVIEW", "--strategy", "RELEASE", "--all", "--keep-deprecated"],
    credential: "CROWDSTRIKE_CLIENT_SECRET",
    cassette: "golden/deploy-crowdstrike",
    exit: 0,
  },
  {
    fixture: "share-misp",
    argv: ["share", "push"],
    credential: "MISP_API_KEY",
    cassette: "golden/share-push",
    exit: 3,
  },
];

for (const server of SERVERS) {
  for (const golden of CASES) {
    const name = typeof server === "string" ? server.split(":")[0] : server.name;
    test(
      `serve (${name}): ${golden.argv.slice(0, 2).join(" ")} through the host, from ${golden.cassette}`,
      { skip: typeof server === "string" ? server : false },
      async () => {
        const scratch = realpathSync(mkdtempSync(join(tmpdir(), "wasi-host-")));
        const ws = join(scratch, "ws");
        cpSync(join(root, "tests/golden/fixtures", golden.fixture), ws, { recursive: true });
        const cassette = cassetteHost(golden.cassette);
        const client = new ServeClient(server as Server, ws, cassette.perform);
        try {
          const initialized = await client.call("initialize", FETCH_CAPABILITY);
          assert.deepEqual((initialized.result as Record<string, unknown>).capabilities, { fetch: true });
          const answer = await client.call("run", {
            argv: golden.argv,
            env: { [golden.credential]: SECRET },
          });
          const result = answer.result as { exit_code: number; document: Record<string, unknown> };
          assert.equal(result.exit_code, golden.exit, JSON.stringify(result.document));
          assert.deepEqual(cassette.mismatches, []);
          const recording: Cassette = JSON.parse(readFileSync(join(root, `tests/cassettes/${golden.cassette}.json`), "utf8"));
          assert.equal(cassette.asked, recording.interactions.length, "every recorded request, and no other");
        } finally {
          await client.close();
          rmSync(scratch, { recursive: true, force: true });
        }
      },
    );
  }
}

// A run cancelled while the host holds its request: the server withdraws the
// request (the host aborts it) and the run ends interrupted. The WASI build
// has no thread reading the client while the run waits: the run reads the
// cancel itself (`Server::pump`), so this is its proof there.
for (const server of SERVERS) {
  const name = typeof server === "string" ? server.split(":")[0] : server.name;
  test(
    `serve (${name}): a run cancelled while the host holds its request is interrupted`,
    { skip: typeof server === "string" ? server : false },
    async () => {
      const scratch = realpathSync(mkdtempSync(join(tmpdir(), "wasi-host-")));
      const ws = join(scratch, "ws");
      cpSync(join(root, "tests/golden/fixtures/tenants"), ws, { recursive: true });
      let held: () => void = () => {};
      const asked = new Promise<void>((resolve) => {
        held = resolve;
      });
      let aborted = false;
      const client = new ServeClient(server as Server, ws, (_params, signal) => {
        held();
        return new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => {
            aborted = true;
            reject(new Error("aborted"));
          });
        });
      });
      try {
        await client.call("initialize", FETCH_CAPABILITY);
        const id = client.request("run", {
          argv: ["query", "--platform", "elastic", "--from", "2099-01-01T00:00:00Z", "--to", "2099-01-01T01:00:00Z", "FROM logs-*"],
          env: { ELASTIC_API_KEY: SECRET },
        });
        await asked;
        client.write({ jsonrpc: "2.0", method: "$/cancelRequest", params: { id } });
        const answer = await client.answer(id);
        const result = answer.result as { exit_code: number; document: Record<string, unknown> };
        assert.equal(result.exit_code, 130, JSON.stringify(result.document));
        assert.ok(aborted, "the server withdraws its request");
        assert.equal(client.host.pending, 0);
      } finally {
        await client.close();
        rmSync(scratch, { recursive: true, force: true });
      }
    },
  );
}

// `opentide mcp start` answers each message as soon as it reads it: an
// interactive client sends the next request only once the last one is
// answered. The WASI build reads its client with blocking reads on one
// thread, so it must not wait for more input before answering.
for (const server of SERVERS) {
  const name = typeof server === "string" ? server.split(":")[0] : server.name;
  test(
    `mcp (${name}): each request is answered before the client sends the next`,
    { skip: typeof server === "string" ? server : false },
    async () => {
      const scratch = realpathSync(mkdtempSync(join(tmpdir(), "wasi-mcp-")));
      const ws = join(scratch, "ws");
      cpSync(join(root, "tests/golden/fixtures/tenants"), ws, { recursive: true });
      const { command, args } = server as Server;
      const child = spawn(command, [...args, "mcp", "start"], {
        cwd: ws,
        env: { PATH: process.env.PATH ?? "", HOME: ws, PWD: ws, NO_COLOR: "1", TZ: "UTC", LANG: "C.UTF-8" },
      });
      let buffer = "";
      const answers = new Map<number, (message: Record<string, unknown>) => void>();
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        buffer += chunk;
        for (let end = buffer.indexOf("\n"); end >= 0; end = buffer.indexOf("\n")) {
          const message = JSON.parse(buffer.slice(0, end)) as Record<string, unknown>;
          buffer = buffer.slice(end + 1);
          answers.get(message.id as number)?.(message);
        }
      });
      const send = (message: object): void => {
        child.stdin.write(`${JSON.stringify(message)}\n`);
      };
      // The answer to request *id*, sent alone: stdin stays open and quiet.
      const call = (id: number, method: string, params: object): Promise<Record<string, unknown>> => {
        const answered = new Promise<Record<string, unknown>>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error(`no answer to ${method} while the client waits`)), 60_000);
          answers.set(id, (message) => {
            clearTimeout(timer);
            resolve(message);
          });
        });
        send({ jsonrpc: "2.0", id, method, params });
        return answered;
      };
      try {
        const initialized = await call(1, "initialize", {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "wasi-host-test", version: "0" },
        });
        assert.ok(initialized.result, JSON.stringify(initialized));
        send({ jsonrpc: "2.0", method: "notifications/initialized" });
        const tools = await call(2, "tools/list", {});
        const listed = (tools.result as { tools: { name: string }[] }).tools.map((tool) => tool.name);
        assert.ok(listed.length > 0, JSON.stringify(tools));
        const again = await call(3, "tools/list", {});
        assert.deepEqual(again.result, tools.result);
      } finally {
        child.stdin.end();
        if (child.exitCode === null) await new Promise((resolve) => child.once("exit", resolve));
        rmSync(scratch, { recursive: true, force: true });
      }
    },
  );
}

// The protocol versions `opentide mcp start` speaks: the VS Code bridge serves
// the WASI module to editors on MCP 2026-07-28, which has no `initialize`. The
// legacy handshake negotiates the versions before it, `server/discover`
// answers the revisions it supports, and a request that carries its version
// and capabilities in `_meta` is answered with no handshake at all.
for (const server of SERVERS) {
  const name = typeof server === "string" ? server.split(":")[0] : server.name;
  test(
    `mcp (${name}): initialize negotiates the legacy versions, server/discover and stateless requests answer 2026-07-28`,
    { skip: typeof server === "string" ? server : false, timeout: 180_000 },
    async () => {
      const scratch = realpathSync(mkdtempSync(join(tmpdir(), "wasi-mcp-")));
      const ws = join(scratch, "ws");
      cpSync(join(root, "tests/golden/fixtures/tenants"), ws, { recursive: true });
      const { command, args } = server as Server;
      const child = spawn(command, [...args, "mcp", "start"], {
        cwd: ws,
        env: { PATH: process.env.PATH ?? "", HOME: ws, PWD: ws, NO_COLOR: "1", TZ: "UTC", LANG: "C.UTF-8" },
      });
      let buffer = "";
      const answers = new Map<number, (message: Record<string, unknown>) => void>();
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        buffer += chunk;
        for (let end = buffer.indexOf("\n"); end >= 0; end = buffer.indexOf("\n")) {
          const message = JSON.parse(buffer.slice(0, end)) as Record<string, unknown>;
          buffer = buffer.slice(end + 1);
          answers.get(message.id as number)?.(message);
        }
      });
      let next = 0;
      const call = (method: string, params: object): Promise<Record<string, unknown>> => {
        next += 1;
        const id = next;
        const answered = new Promise<Record<string, unknown>>((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error(`no answer to ${method}`)), 60_000);
          answers.set(id, (message) => {
            clearTimeout(timer);
            resolve(message);
          });
        });
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
        return answered;
      };
      const meta = {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
      };
      try {
        // Without `initialize` and without them, a request is refused, naming what it lacks.
        const refused = await call("tools/list", {});
        assert.equal((refused.error as { code: number }).code, -32602, JSON.stringify(refused));
        assert.match((refused.error as { message: string }).message, /io\.modelcontextprotocol\/protocolVersion/);
        // `server/discover` (no handshake before it) lists what the server supports.
        const discovered = (await call("server/discover", { _meta: meta })).result as {
          supportedVersions: string[];
          capabilities: Record<string, unknown>;
          _meta: Record<string, { name: string }>;
        };
        assert.deepEqual(discovered.supportedVersions, ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"]);
        assert.ok("tools" in discovered.capabilities, JSON.stringify(discovered));
        assert.equal(discovered._meta["io.modelcontextprotocol/serverInfo"].name, "opentide");
        // A stateless request: its version and capabilities in `_meta`.
        const listed = (await call("tools/list", { _meta: meta })).result as { tools: { name: string }[] };
        assert.ok(listed.tools.length > 0 && listed.tools.some((tool) => tool.name === "search"), JSON.stringify(listed));
        // Legacy `initialize`: the version asked for when it is known, else the newest that has `initialize`.
        for (const [asked, answered] of [
          ["2024-11-05", "2024-11-05"],
          ["2025-06-18", "2025-06-18"],
          ["2025-11-25", "2025-11-25"],
          ["2026-07-28", "2025-11-25"],
        ]) {
          const initialized = await call("initialize", {
            protocolVersion: asked,
            capabilities: {},
            clientInfo: { name: "wasi-host-test", version: "0" },
          });
          assert.equal((initialized.result as { protocolVersion: string }).protocolVersion, answered, asked);
        }
        child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
        // Still serving after the handshake.
        assert.ok(Array.isArray(((await call("tools/list", { _meta: meta })).result as { tools: unknown[] }).tools));
      } finally {
        child.stdin.end();
        if (child.exitCode === null) await new Promise((resolve) => child.once("exit", resolve));
        rmSync(scratch, { recursive: true, force: true });
      }
    },
  );
}

// `opentide mcp start` in the WASI module (#1180, #1142). A live `deploy_rule`
// runs the command line's deploy inside the server's runtime, and WASI has
// no other thread to hand it to. The deploy built a runtime of its own there
// and dropped it inside the server's, which tokio refuses with a panic, a
// trap in the module: the server died and answered nothing more. Through
// opentide_connectors::runtime the deploy builds none there; it fails as
// any deploy without the network does in this build, and the server goes on.
test(
  "mcp (wasi): a live deploy_rule fails without taking the server down",
  {
    skip: wasiModule === undefined ? "wasi: no WASI module (OPENTIDE_WASI_CLI)" : false,
    timeout: 120_000,
  },
  async () => {
    const scratch = realpathSync(mkdtempSync(join(tmpdir(), "wasi-host-")));
    const ws = join(scratch, "ws");
    cpSync(join(root, "tests/golden/fixtures/deploy-tenants"), ws, { recursive: true });
    const server = spawn(
      process.execPath,
      ["--no-turbo-fast-api-calls", join(root, "scripts/engine/wasi-run.mjs"), wasiModule as string, "mcp", "start"],
      {
        cwd: ws,
        env: {
          PATH: process.env.PATH ?? "",
          HOME: ws,
          PWD: ws,
          NO_COLOR: "1",
          TZ: "UTC",
          LANG: "C.UTF-8",
          CROWDSTRIKE_CLIENT_SECRET: SECRET,
        },
      },
    );
    let buffer = "";
    let stderr = "";
    // Everything the module wrote on stdout.
    const written: Record<string, unknown>[] = [];
    const waiting = new Map<number, { resolve: (message: Record<string, unknown>) => void; reject: (error: Error) => void }>();
    server.stderr.setEncoding("utf8");
    server.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    // A server that dies (a panic is a trap in the module) answers nothing
    // more. `close`, not `exit`: its last lines may still be in the pipe.
    const exited = new Promise<void>((resolve) => server.once("close", () => resolve()));
    void exited.then(() => {
      for (const { reject } of waiting.values()) {
        reject(new Error(`the server exited before answering:\n${stderr.slice(-2000)}`));
      }
      waiting.clear();
    });
    server.stdout.setEncoding("utf8");
    server.stdout.on("data", (chunk: string) => {
      buffer += chunk;
      for (let end = buffer.indexOf("\n"); end >= 0; end = buffer.indexOf("\n")) {
        const line = buffer.slice(0, end).trim();
        buffer = buffer.slice(end + 1);
        if (line === "") continue;
        const message = JSON.parse(line) as Record<string, unknown>;
        written.push(message);
        if (typeof message.id === "number") {
          waiting.get(message.id)?.resolve(message);
          waiting.delete(message.id);
        }
      }
    });
    let next = 0;
    const request = (method: string, params: object): Promise<Record<string, unknown>> => {
      next += 1;
      const id = next;
      const answered = new Promise<Record<string, unknown>>((resolve, reject) => waiting.set(id, { resolve, reject }));
      server.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
      return answered;
    };
    try {
      // Every request is sent first and the input closed: a server that dies
      // rejects them all at once (the request-at-a-time path is the test
      // above).
      const initialized = request("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "wasi-host-test", version: "0" },
      });
      server.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })}\n`);
      const deployed = request("tools/call", {
        name: "deploy_rule",
        arguments: { uuid: "00000000-0000-4000-8047-000000000021", platform: "crowdstrike", dry_run: false },
      });
      const listed = request("tools/list", {});
      // Awaited below; a crash rejects them all at once.
      for (const pending of [deployed, listed]) pending.catch(() => {});
      server.stdin.end();
      await initialized;
      const result = (await deployed).result as { content: { text: string }[] };
      const text = result.content.map((part) => part.text).join("\n");
      assert.match(text, /"status": ?"failed"/, text);
      assert.match(text, /needs the network, which the WASI build of opentide does not have/, text);
      assert.doesNotMatch(text, /stopped unexpectedly/, text);
      // The server still serves after the deploy.
      assert.ok(Array.isArray(((await listed).result as { tools: unknown[] }).tools));
      // Without OPENTIDE_FETCH the stream is MCP alone: no request of the
      // server's own (a tenant request is `opentide/fetch`, and only a bridge
      // may consume a stream that has any).
      assert.ok(written.length >= 3, JSON.stringify(written));
      for (const message of written) {
        assert.equal(message.jsonrpc, "2.0", JSON.stringify(message));
        assert.notEqual(message.method, "opentide/fetch", JSON.stringify(message));
        assert.ok(!String(message.id).startsWith("opentide-fetch-"), JSON.stringify(message));
        // The server writes answers; the only message of its own MCP allows here is a notification.
        assert.ok(message.method === undefined || String(message.method).startsWith("notifications/"), JSON.stringify(message));
      }
    } finally {
      server.stdin.end();
      await exited;
      rmSync(scratch, { recursive: true, force: true });
    }
  },
);

// ---- opentide mcp start, its tenant requests among its MCP messages (OPENTIDE_FETCH=stdio) ----

/** A message as a line, the way MCP's stdio frames it. */
const line = (message: object): string => `${JSON.stringify(message)}\n`;

/** A `McpFetchBridge` with its two sinks collected, and a `perform` that records what it is asked. */
function bridged(perform?: (params: FetchParams, signal: AbortSignal) => Promise<FetchResult>) {
  const toServer: Record<string, unknown>[] = [];
  const toClient: Record<string, unknown>[] = [];
  const raw = { toServer: [] as string[], toClient: [] as string[] };
  const bridge = new McpFetchBridge(
    {
      toServer: (text) => {
        raw.toServer.push(text);
        toServer.push(JSON.parse(text) as Record<string, unknown>);
      },
      toClient: (text) => {
        raw.toClient.push(text);
        try {
          toClient.push(JSON.parse(text) as Record<string, unknown>);
        } catch {
          // Not JSON: kept in `raw` only.
        }
      },
    },
    { perform },
  );
  return { bridge, toServer, toClient, raw };
}

const fetchRequest = (id: string, url = "https://t.invalid/x"): object => ({
  jsonrpc: "2.0",
  id,
  method: "opentide/fetch",
  params: { method: "GET", url, headers: [] },
});

test("the mcp bridge answers the module's tenant requests and passes its MCP messages through in order", async () => {
  const { bridge, toServer, toClient } = bridged(async (request) => ({
    status: 200,
    headers: [],
    url: request.url,
    body: "",
    elapsed_ms: 1,
  }));
  const before = { jsonrpc: "2.0", method: "notifications/progress", params: { progress: 1 } };
  const after = { jsonrpc: "2.0", id: 4, result: { content: [] } };
  // Chunks cut anywhere: inside a line, between two, at a multi-byte character.
  const text = line(before) + line(fetchRequest("opentide-fetch-1")) + line(after);
  const encoded = Buffer.from(text);
  for (let at = 0; at < encoded.length; at += 7) {
    bridge.fromServer(encoded.subarray(at, at + 7));
  }
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(toClient, [before, after], "the tenant request is the host's, not the client's");
  assert.equal(toServer.length, 1);
  assert.equal(toServer[0].id, "opentide-fetch-1");
  assert.equal((toServer[0].result as FetchResult).status, 200);
  assert.equal(bridge.pending, 0);
});

test("the mcp bridge hands the module the client's messages one whole line at a time", async () => {
  const { bridge, raw } = bridged(async (request) => ({ status: 204, headers: [], url: request.url, body: "", elapsed_ms: 0 }));
  const ping = line({ jsonrpc: "2.0", id: 1, method: "ping" });
  // The client's line arrives in two chunks, an answer is ready between them:
  // it must not land inside the line.
  bridge.fromClient(ping.slice(0, 10));
  bridge.fromServer(line(fetchRequest("opentide-fetch-2")));
  await new Promise((resolve) => setTimeout(resolve, 20));
  bridge.fromClient(ping.slice(10));
  assert.equal(raw.toServer.length, 2);
  assert.equal((JSON.parse(raw.toServer[0]) as { id: string }).id, "opentide-fetch-2");
  assert.equal(raw.toServer[1], ping);
  // A last line without its newline is delivered once the input ends.
  bridge.fromClient('{"jsonrpc":"2.0","id":2,"method":"ping"}');
  assert.equal(raw.toServer.length, 2);
  bridge.endClient();
  assert.equal(raw.toServer[2], line({ jsonrpc: "2.0", id: 2, method: "ping" }));
});

test("the mcp bridge aborts a request the module withdraws and does not pass the withdrawal on", async () => {
  let aborted = false;
  const { bridge, toServer, toClient } = bridged(
    (_request, signal) =>
      new Promise<FetchResult>((_resolve, reject) => {
        signal.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("aborted"));
        });
      }),
  );
  bridge.fromServer(line(fetchRequest("opentide-fetch-1")));
  assert.equal(bridge.pending, 1);
  bridge.fromServer(
    line({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "opentide-fetch-1", reason: "x" } }),
  );
  // A withdrawal of one already answered is the host's too, not the client's.
  bridge.fromServer(
    line({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "opentide-fetch-9" } }),
  );
  // But a cancellation of anything else is an MCP message.
  const theirs = { jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 3 } };
  bridge.fromServer(line(theirs));
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.ok(aborted, "the request was aborted");
  assert.equal(toServer.length, 0, "a withdrawn request is not answered");
  assert.deepEqual(toClient, [theirs]);
  assert.equal(bridge.pending, 0);
});

test("the mcp bridge never forwards a line that might hold a tenant request, and starts none once disposed", async () => {
  let performed = 0;
  let release: () => void = () => {};
  const { bridge, raw } = bridged(
    () =>
      new Promise<FetchResult>((resolve) => {
        performed += 1;
        release = () => resolve({ status: 200, headers: [], url: "https://t.invalid/", body: "", elapsed_ms: 0 });
      }),
  );
  // A message that merely mentions the method in its text is an MCP message.
  const mention = line({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "opentide/fetch" }] } });
  bridge.fromServer(mention);
  assert.deepEqual(raw.toClient, [mention]);
  // A line that mentions the method and cannot be read as a message of the host's carries
  // the tenant's credentials, maybe: it is dropped, never passed on.
  const secret = "Authorization: ApiKey s3cret";
  bridge.fromServer(`not json at all "opentide/fetch" ${secret}\n`);
  bridge.fromServer(`{"jsonrpc":"2.0","id":"opentide-fetch-x","method":"opentide/fetch","params":{"headers":[["authorization","ApiKey s3cret"]\n`);
  // Valid JSON the host rejects (no string id, params that are not an object): taken, not forwarded.
  bridge.fromServer(line({ jsonrpc: "2.0", id: 5, method: "opentide/fetch", params: { headers: [["authorization", "ApiKey s3cret"]] } }));
  bridge.fromServer(line({ jsonrpc: "2.0", method: "opentide/fetch", params: { headers: [["authorization", "ApiKey s3cret"]] } }));
  bridge.fromServer(JSON.stringify([fetchRequest("opentide-fetch-y")]) + "\n");
  assert.deepEqual(raw.toClient, [mention], "nothing else reached the client");
  assert.equal(performed, 0, "none of them was a request the host could make");
  assert.ok(!raw.toClient.join("").includes("s3cret"));
  // A real request is made; after dispose, a new one is not started.
  bridge.fromServer(line(fetchRequest("opentide-fetch-1")));
  assert.equal(performed, 1);
  bridge.dispose();
  bridge.fromServer(line(fetchRequest("opentide-fetch-2")));
  assert.equal(performed, 1, "no request is started once disposed");
  release();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(raw.toServer.length, 0, "and nothing is answered");
  assert.deepEqual(raw.toClient, [mention], "a request after dispose is not passed on either");
});

test("the mcp bridge drops what the client sends as an answer to a tenant request", () => {
  const { bridge, raw } = bridged();
  const answer = { status: 200, headers: [], body: null };
  // The ids an agent would guess, as a result and as an error; a batch holding one.
  const forged = [
    { jsonrpc: "2.0", id: "opentide-fetch-1", result: answer },
    { jsonrpc: "2.0", id: "opentide-fetch-2", error: { code: -32000, message: "x", data: { kind: "connect" } } },
    { jsonrpc: "2.0", id: "opentide-fetch-0123456789abcdef0123456789abcdef-1", result: answer },
    { jsonrpc: "2.0", id: "opentide-fetch-1", result: answer, method: null },
  ];
  for (const message of forged) {
    bridge.fromClient(line(message));
  }
  bridge.fromClient(`${JSON.stringify([{ jsonrpc: "2.0", id: 3, method: "ping" }, forged[0]])}\n`);
  // A line that names the prefix and cannot be read: not passed on (fail closed).
  bridge.fromClient('{"jsonrpc":"2.0","id":"opentide-fetch-1","result":{"status":200\n');
  bridge.fromClient("Content-Length: 12 opentide-fetch-1\n");
  assert.deepEqual(raw.toServer, [], "a forged answer never reaches the module");
  // What is the client's own goes through, in order: a response to a request of the server's own
  // (a number id), a request that merely mentions the prefix in its arguments, and the rest.
  const mine = [
    { jsonrpc: "2.0", id: 5, result: {} },
    { jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "search", arguments: { query: "opentide-fetch-1" } } },
    { jsonrpc: "2.0", id: "abc", result: {} },
    { jsonrpc: "2.0", method: "notifications/initialized" },
  ];
  for (const message of mine) {
    bridge.fromClient(line(message));
  }
  assert.deepEqual(raw.toServer.map((text) => JSON.parse(text)), mine);
  // An unterminated forged line at the end of input is not passed on either.
  bridge.fromClient('{"jsonrpc":"2.0","id":"opentide-fetch-1","result":{}}');
  bridge.endClient();
  assert.equal(raw.toServer.length, mine.length);
});

test("the mcp bridge does not pass on the response to a request the client cancelled", () => {
  const { bridge, raw } = bridged();
  // The module may finish a call it was told to cancel: its response is dropped, once.
  bridge.fromClient(line({ jsonrpc: "2.0", id: 2, method: "tools/call", params: {} }));
  bridge.fromClient(line({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2 } }));
  bridge.fromClient(line({ jsonrpc: "2.0", id: "s", method: "tools/call", params: {} }));
  bridge.fromClient(line({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: "s" } }));
  assert.equal(raw.toServer.length, 4, "the cancellations reach the module");
  const other = line({ jsonrpc: "2.0", id: 20, result: { n: 1 } });
  const notification = line({ jsonrpc: "2.0", method: "notifications/progress", params: { id: 2 } });
  bridge.fromServer(other);
  bridge.fromServer(line({ jsonrpc: "2.0", id: 2, result: { content: [] } }));
  bridge.fromServer(notification);
  bridge.fromServer(line({ jsonrpc: "2.0", id: "s", error: { code: -32603, message: "Request cancelled" } }));
  assert.deepEqual(raw.toClient, [other, notification]);
  // Once dropped the id is forgotten: nothing else is held back.
  const later = line({ jsonrpc: "2.0", id: 2, result: {} });
  bridge.fromServer(later);
  assert.deepEqual(raw.toClient, [other, notification, later]);
});

test("the mcp bridge's environment turns the module's side on", () => {
  assert.deepEqual({ ...MCP_FETCH_ENVIRONMENT }, { OPENTIDE_FETCH: "stdio" });
});

/**
 * `opentide mcp start` in the WASI module with `OPENTIDE_FETCH=stdio`, its
 * stdio through a `McpFetchBridge`: a client's end of it, and a scripted host.
 */
class McpSession {
  readonly bridge: McpFetchBridge;
  readonly messages: Record<string, unknown>[] = [];
  readonly leaked: string[] = [];
  readonly process: ChildProcessWithoutNullStreams;
  readonly exited: Promise<void>;
  private readonly waiting = new Map<number, (message: Record<string, unknown>) => void>();
  private stderr = "";
  private closed = false;

  constructor(ws: string, perform: (params: FetchParams, signal: AbortSignal) => Promise<FetchResult>) {
    this.process = spawn(
      process.execPath,
      ["--no-turbo-fast-api-calls", join(root, "scripts/engine/wasi-run.mjs"), wasiModule as string, "mcp", "start"],
      {
        cwd: ws,
        env: {
          PATH: process.env.PATH ?? "",
          HOME: ws,
          PWD: ws,
          NO_COLOR: "1",
          TZ: "UTC",
          LANG: "C.UTF-8",
          ELASTIC_API_KEY: SECRET,
          ...MCP_FETCH_ENVIRONMENT,
        },
      },
    );
    this.bridge = new McpFetchBridge(
      {
        toServer: (text) => {
          if (!this.closed) this.process.stdin.write(text);
        },
        toClient: (text) => {
          if (text.includes("opentide-fetch-")) this.leaked.push(text);
          const message = JSON.parse(text) as Record<string, unknown>;
          this.messages.push(message);
          if (typeof message.id === "number") this.waiting.get(message.id)?.(message);
        },
      },
      { perform },
    );
    this.process.stdout.on("data", (chunk: Buffer) => this.bridge.fromServer(chunk));
    this.process.stderr.setEncoding("utf8");
    this.process.stderr.on("data", (chunk: string) => {
      this.stderr += chunk;
    });
    this.exited = new Promise((resolve) => this.process.once("close", () => resolve()));
  }

  /** What the module wrote on stderr, for a failure's message. */
  get log(): string {
    return this.stderr.slice(-2000);
  }

  send(message: object): void {
    this.bridge.fromClient(line(message));
  }

  /** The answer to request *id*, or a failure if the module exits or keeps quiet. */
  answer(id: number): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const known = this.messages.find((message) => message.id === id && message.method === undefined);
      if (known !== undefined) {
        resolve(known);
        return;
      }
      const timer = setTimeout(() => reject(new Error(`no answer to ${id}:\n${this.log}`)), 90_000);
      this.waiting.set(id, (message) => {
        clearTimeout(timer);
        resolve(message);
      });
      void this.exited.then(() => reject(new Error(`the module exited before answering ${id}:\n${this.log}`)));
    });
  }

  request(id: number, method: string, params: object): Promise<Record<string, unknown>> {
    const answered = this.answer(id);
    this.send({ jsonrpc: "2.0", id, method, params });
    return answered;
  }

  async initialize(): Promise<void> {
    await this.request(1, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "wasi-host-test", version: "0" },
    });
    this.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  }

  /** Ends the client's input and waits for the module to exit. */
  async close(): Promise<void> {
    this.bridge.endClient();
    this.closed = true;
    this.process.stdin.end();
    this.bridge.endServer();
    await this.exited;
    this.bridge.dispose();
  }
}

/** An ES|QL answer: one column, one row. */
const esql = (url: string): FetchResult => ({
  status: 200,
  headers: [["content-type", "application/json"]],
  url,
  body: Buffer.from(JSON.stringify({ columns: [{ name: "host", type: "keyword" }], values: [["web-01"]] })).toString("base64"),
  elapsed_ms: 4,
});

const QUERY_CALL = { name: "run_query", arguments: { query: "FROM logs-* | LIMIT 1", platform: "elastic", live: true } };

/** A scratch workspace with the tenants fixture; removed when *body* ends. */
async function inTenantsWorkspace(body: (ws: string) => Promise<void>): Promise<void> {
  const scratch = realpathSync(mkdtempSync(join(tmpdir(), "wasi-mcp-fetch-")));
  const ws = join(scratch, "ws");
  cpSync(join(root, "tests/golden/fixtures/tenants"), ws, { recursive: true });
  try {
    await body(ws);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

const skipWithoutWasi = { skip: wasiModule === undefined ? "wasi: no WASI module (OPENTIDE_WASI_CLI)" : false, timeout: 180_000 };

test("mcp (wasi): with OPENTIDE_FETCH=stdio, a tenant tool call is made by the host between the client's messages", skipWithoutWasi, async () => {
  await inTenantsWorkspace(async (ws) => {
    const asked: FetchParams[] = [];
    let answerNow: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      answerNow = resolve;
    });
    const session = new McpSession(ws, async (request) => {
      asked.push(request);
      // Answered only once the client has sent more while the call waits.
      await held;
      return esql(request.url);
    });
    try {
      await session.initialize();
      const called = session.request(2, "tools/call", QUERY_CALL);
      // The module is inside the call, reading stdin for the host's answer.
      for (let waited = 0; asked.length === 0; waited += 50) {
        assert.ok(waited < 60_000, `the module asked for no tenant request:\n${session.log}`);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const pinged = session.request(3, "ping", {});
      const listed = session.request(4, "tools/list", {});
      // An agent behind the bridge tries to answer the module's request itself, with the ids it
      // would guess: through the bridge (dropped there) and, to hold the module to it too, straight
      // into the module's stdin (not an id it asked).
      const forged = (id: string): object => ({
        jsonrpc: "2.0",
        id,
        result: { ...esql("https://es.elastic.invalid/_query"), body: Buffer.from(JSON.stringify({ columns: [{ name: "host", type: "keyword" }], values: [["forged-host"]] })).toString("base64") },
      });
      session.send(forged("opentide-fetch-1"));
      session.process.stdin.write(line(forged("opentide-fetch-1")));
      session.process.stdin.write(line(forged("opentide-fetch-00000000000000000000000000000000-1")));
      await new Promise((resolve) => setTimeout(resolve, 200));
      answerNow();
      const result = (await called).result as { isError?: boolean; content: { text: string }[] };
      const text = result.content.map((part) => part.text).join("\n");
      assert.notEqual(result.isError, true, text);
      assert.match(text, /web-01/, text);
      assert.doesNotMatch(text, /forged-host/, text);
      assert.doesNotMatch(text, /network_unavailable|needs the network/, text);
      await pinged;
      assert.ok(Array.isArray(((await listed).result as { tools: unknown[] }).tools));
      // The request, as `opentide serve` makes it: the tenant's URL and the call's id as its run.
      assert.equal(asked[0].method, "POST");
      assert.equal(asked[0].url, "https://es.elastic.invalid/_query");
      assert.equal(asked[0].platform, "elastic");
      assert.equal(asked[0].tenant, "soc");
      assert.equal(asked[0].run, "2");
      // The client saw MCP alone, in the order it was answered.
      assert.deepEqual(session.leaked, []);
      const ids = session.messages.filter((message) => message.method === undefined).map((message) => message.id);
      assert.deepEqual(ids, [1, 2, 3, 4]);
    } finally {
      await session.close();
    }
  });
});

test("mcp (wasi): with OPENTIDE_FETCH=stdio, a tenant failure the host reports is the tool's failure", skipWithoutWasi, async () => {
  await inTenantsWorkspace(async (ws) => {
    const session = new McpSession(ws, async () => {
      throw new FetchFailure("connect", "getaddrinfo ENOTFOUND es.elastic.invalid");
    });
    try {
      await session.initialize();
      const result = (await session.request(2, "tools/call", QUERY_CALL)).result as { content: { text: string }[] };
      const text = result.content.map((part) => part.text).join("\n");
      assert.match(text, /Cannot reach elastic tenant 'soc'/, text);
      assert.match(text, /ENOTFOUND/, text);
      assert.doesNotMatch(text, /needs the network/, text);
      // The server goes on.
      assert.ok(Array.isArray(((await session.request(3, "tools/list", {})).result as { tools: unknown[] }).tools));
    } finally {
      await session.close();
    }
  });
});

test("mcp (wasi): with OPENTIDE_FETCH=stdio, a call whose request goes unanswered fails when the client's input ends", skipWithoutWasi, async () => {
  await inTenantsWorkspace(async (ws) => {
    const asked: FetchParams[] = [];
    const session = new McpSession(ws, (request) => {
      asked.push(request);
      return new Promise<FetchResult>(() => {});
    });
    try {
      await session.initialize();
      const called = session.request(2, "tools/call", QUERY_CALL);
      called.catch(() => {});
      for (let waited = 0; asked.length === 0; waited += 50) {
        assert.ok(waited < 60_000, `the module asked for no tenant request:\n${session.log}`);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      // EOF: the host never answers, and the client leaves.
      session.bridge.endClient();
      session.process.stdin.end();
      const result = (await called).result as { content: { text: string }[] };
      const text = result.content.map((part) => part.text).join("\n");
      assert.match(text, /closed its input before answering an opentide\/fetch request/, text);
      assert.doesNotMatch(text, /network_unavailable|needs the network/, text);
    } finally {
      await session.close();
    }
  });
});

test("mcp (wasi): with OPENTIDE_FETCH=stdio, cancelling the call withdraws its request and aborts the host's", skipWithoutWasi, async () => {
  await inTenantsWorkspace(async (ws) => {
    const asked: FetchParams[] = [];
    let aborted = false;
    const session = new McpSession(
      ws,
      (request, signal) =>
        new Promise<FetchResult>((_resolve, reject) => {
          asked.push(request);
          signal.addEventListener("abort", () => {
            aborted = true;
            reject(new Error("aborted"));
          });
        }),
    );
    try {
      await session.initialize();
      session.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: QUERY_CALL });
      for (let waited = 0; asked.length === 0; waited += 50) {
        assert.ok(waited < 60_000, `the module asked for no tenant request:\n${session.log}`);
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      session.send({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2, reason: "user" } });
      // The module stops the call (its answer, if any, is the client's to ignore) and serves on.
      const listed = await session.request(3, "tools/list", {});
      assert.ok(Array.isArray((listed.result as { tools: unknown[] }).tools));
      assert.ok(aborted, "the host aborted the request the module withdrew");
      // The module may still finish the cancelled call; MCP has no response go out for it, and the bridge sends none.
      assert.equal(
        session.messages.find((message) => message.id === 2 && message.method === undefined),
        undefined,
        "the cancelled call's response reached the client",
      );
      assert.equal(session.bridge.pending, 0);
      assert.deepEqual(session.leaked, []);
    } finally {
      await session.close();
    }
  });
});
