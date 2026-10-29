import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadHighlightModule } from "../../lsp-worker/src/index.ts";
import {
  createOpentideClient,
  createOtideClient,
  DOCUMENT_SELECTOR,
  encodeMessage,
  LANGUAGES,
  MessageDecoder,
  type OpentideClient,
} from "./index.ts";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const generatedLegend: string[] = JSON.parse(readFileSync(join(root, "highlights/generated/legend.json"), "utf8"));

// Host tests run against built artifacts. CI sets the variable for each one it
// builds; locally, the debug server is used when it exists.
const debugServer = join(root, "target/debug/opentide-lsp");
const server = process.env.OPENTIDE_LSP_BIN ?? (existsSync(debugServer) ? debugServer : undefined);
const wasiBinary = process.env.OPENTIDE_WASI_BIN;
const wasmGlue = process.env.OPENTIDE_WASM_GLUE;

const TIDE_RULE = `name: Two platforms
metadata:
  uuid: 00000000-0000-4000-8003-000000000099
  schema: rule::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
description: Sentinel and Splunk in one rule.
status: STAGING
detection_model: 00000000-0000-4000-8002-000000000001
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
  splunk:
    search: index=main | head 1
`;

const SAMPLES: Record<string, string> = {
  kql: "SecurityEvent | where EventID == 4688 | take 1",
  spl: "index=main | stats count by host",
  esql: "FROM logs-* | WHERE x == 1",
  eql: 'process where process.name : "cmd.exe"',
  kuery: "event.category:process and not user.name:SYSTEM",
  lucene: "event.category:process AND process.name:/power.*/",
  "opentide-yaml": TIDE_RULE,
};

/** Diagnostic codes the native CLI reports for `text`, the reference for every transport. */
function cliCodes(binary: string, languageId: string, text: string): string[] {
  const dir = mkdtempSync(join(tmpdir(), "opentide-cli-"));
  try {
    // A file outside a workspace makes the CLI index its grandparent directory.
    mkdirSync(join(dir, "q"));
    const file = join(dir, "q", `query.${languageId === "opentide-yaml" ? "yaml" : languageId}`);
    writeFileSync(file, text);
    const run = spawnSync(binary, ["analyze", file, "--language", languageId], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    return (JSON.parse(run.stdout) as { code: string }[]).map((d) => d.code).sort();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function using<T>(client: OpentideClient, body: (c: OpentideClient) => Promise<T>): Promise<T> {
  try {
    return await body(client);
  } finally {
    await client.dispose();
  }
}

test("document selector covers every language", () => {
  const ids = LANGUAGES.map((l) => l.id);
  assert.deepEqual(ids, ["opentide-yaml", "kql", "spl", "esql", "eql", "kuery", "lucene"]);
  for (const id of ids) {
    assert.ok(DOCUMENT_SELECTOR.some((s) => "language" in s && s.language === id), id);
  }
  assert.ok(DOCUMENT_SELECTOR.some((s) => "pattern" in s && s.pattern === "**/*.esql"));
  assert.ok(!DOCUMENT_SELECTOR.some((s) => "pattern" in s && s.pattern === "**/*.sql"), "no SQL");
});

test("decoder reassembles messages split across chunks", () => {
  const bytes = new Uint8Array([
    ...encodeMessage({ id: 1, result: "é" }),
    ...encodeMessage({ id: 2, result: [1, 2] }),
  ]);
  const decoder = new MessageDecoder();
  const out: unknown[] = [];
  for (let i = 0; i < bytes.length; i += 7) out.push(...decoder.push(bytes.subarray(i, i + 7)));
  assert.deepEqual(out, [{ id: 1, result: "é" }, { id: 2, result: [1, 2] }]);
});

test("decoder rejects a header without Content-Length", () => {
  assert.throws(() => new MessageDecoder().push(new TextEncoder().encode("X: 1\r\n\r\n{}")), /Content-Length/);
});

test("an unknown transport or language is refused", async () => {
  assert.throws(() => createOpentideClient({ transport: "tcp" as never }), /unsupported transport/);
  const client = createOpentideClient({ transport: "worker", module: { highlight: () => ({}), legend: () => [] } });
  await assert.rejects(client.highlight("sql", "select 1"), /unknown language "sql"/);
});

test("a transport without its artifact is refused, not answered empty", async () => {
  assert.throws(() => createOpentideClient({ transport: "worker" }), /needs `module`/);
  assert.throws(() => createOpentideClient({ transport: "wasi" }), /needs `wasi`/);
  const missing = createOpentideClient({ transport: "stdio", command: join(tmpdir(), "no-such-opentide-lsp") });
  await assert.rejects(missing.analyze("kql", "T | take 1"), /cannot start|exited/);
  await missing.dispose();
});

test("a server that dies rejects the pending request with its exit status", async () => {
  const client = createOpentideClient({
    transport: "stdio",
    command: process.execPath,
    args: ["-e", "process.stdin.once('data', () => { console.error('boom'); process.exit(3); })"],
  });
  await assert.rejects(client.analyze("kql", "T"), /exited \(3\): boom/);
  await client.dispose();
});

test("worker transport highlights and refuses to analyze", async () => {
  const calls: [string, string][] = [];
  const client = createOpentideClient({
    transport: "worker",
    module: {
      highlight: (id, bytes) => {
        calls.push([id, new TextDecoder().decode(bytes)]);
        return { language_id: id, tokens: [{ capture: "keyword", start: 0, end: 4 }], legend: ["keyword"] };
      },
      legend: () => ["keyword"],
    },
  });
  assert.equal((await client.highlight("kql", "take")).tokens.length, 1);
  assert.deepEqual(calls, [["kql", "take"]]);
  assert.deepEqual(await client.legend(), ["keyword"]);
  await assert.rejects(client.analyze("kql", "take"), /not available on the worker transport/);
});

test("stdio: the server's diagnostics, tokens and legend", { skip: !server && "no opentide-lsp build (set OPENTIDE_LSP_BIN)" }, async () => {
  await using(createOpentideClient({ transport: "stdio", command: server }), async (client) => {
    assert.deepEqual(await client.legend(), generatedLegend);
    for (const [id, text] of Object.entries(SAMPLES)) {
      const tokens = (await client.highlight(id, text)).tokens;
      assert.ok(tokens.length > 0, `${id}: no tokens`);
      const codes = (await client.analyze(id, text)).diagnostics.map((d) => d.code).sort();
      assert.deepEqual(codes, cliCodes(server!, id, text), id);
    }
    // Faults reach the client, so an empty list above is not a dead transport.
    const broken = await client.analyze("kql", "SecurityEvent | wher EventID == 1");
    assert.ok(broken.diagnostics.length > 0);
    const rule = (await client.highlight("opentide-yaml", TIDE_RULE)).tokens.map((t) => t.capture);
    assert.ok(rule.includes("operator.pipe"), "injected KQL and SPL are highlighted");
  });
});

test("stdio: requests after dispose reject", { skip: !server && "no opentide-lsp build" }, async () => {
  const client = createOpentideClient({ transport: "stdio", command: server });
  await client.highlight("kql", "T");
  await client.dispose();
  await assert.rejects(client.highlight("kql", "T"), /disposed|exited/);
});

test("wasi: the CLI under node:wasi matches the native CLI", { skip: !wasiBinary && "set OPENTIDE_WASI_BIN" }, async () => {
  const client = createOpentideClient({ transport: "wasi", wasi: wasiBinary });
  assert.deepEqual(await client.legend(), generatedLegend);
  for (const [id, text] of Object.entries(SAMPLES)) {
    assert.ok((await client.highlight(id, text)).tokens.length > 0, `${id}: no tokens`);
    if (server) {
      const codes = (await client.analyze(id, text)).diagnostics.map((d) => d.code).sort();
      assert.deepEqual(codes, cliCodes(server, id, text), id);
    }
  }
  const broken = await client.analyze("esql", "FROM logs-* | WEHRE x == 1");
  assert.ok(broken.diagnostics.some((d) => d.code === "esql_unknown_command"));
});

test("worker: opentide-wasm glue highlights like the native server", { skip: !wasmGlue && "set OPENTIDE_WASM_GLUE" }, async () => {
  const module = await loadHighlightModule(pathToFileURL(resolve(wasmGlue!)));
  const client = createOpentideClient({ transport: "worker", module });
  assert.deepEqual(await client.legend(), generatedLegend);
  for (const [id, text] of Object.entries(SAMPLES)) {
    assert.ok((await client.highlight(id, text)).tokens.length > 0, `${id}: no tokens`);
  }
});

test("createOtideClient is rejected", () => {
  assert.throws(() => createOtideClient({ transport: "stdio" }), /createOpentideClient/);
});
