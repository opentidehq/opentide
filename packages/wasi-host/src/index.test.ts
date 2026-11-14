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
  fetchParams,
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

test("redirects are followed as reqwest follows them", async () => {
  const other = await serve((request, response) => {
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
    const away = await performRequest(
      params({ url: `${first.origin}/away`, headers: [["authorization", "Bearer token"]] }),
      signal,
    );
    assert.equal(Buffer.from(away.body, "base64").toString(), "GET no authorization");
  } finally {
    await first.close();
    await other.close();
  }
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
        !sameBody(wantBody, got.body as string)
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
const debugBinary = join(root, "target/debug/opentide-cli");
const nativeBinary = process.env.OPENTIDE_BIN ?? (existsSync(debugBinary) ? debugBinary : undefined);
const wasiModule = process.env.OPENTIDE_WASI_CLI === undefined ? undefined : resolve(process.env.OPENTIDE_WASI_CLI);
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
