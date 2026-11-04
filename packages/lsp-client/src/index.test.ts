import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  type LanguageServerModule,
  loadHighlightModule,
  loadLanguageServer,
  serveLanguageServer,
} from "../../lsp-worker/src/index.ts";
import {
  createOpentideClient,
  createOtideClient,
  DOCUMENT_SELECTOR,
  encodeMessage,
  LANGUAGES,
  MessageDecoder,
  type OpentideClient,
  WEB_DOCUMENT_SELECTOR,
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
  falco: "spawned_process and container and proc.name in (shell_binaries)",
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
  assert.deepEqual(ids, ["opentide-yaml", "kql", "spl", "esql", "eql", "kuery", "lucene", "falco", "opentide-config"]);
  for (const selector of [DOCUMENT_SELECTOR, WEB_DOCUMENT_SELECTOR]) {
    for (const id of ids) {
      assert.ok(selector.some((s) => "language" in s && s.language === id), id);
    }
    assert.ok(selector.some((s) => "pattern" in s && s.pattern === "**/*.esql"));
    assert.ok(!selector.some((s) => "pattern" in s && s.pattern === "**/*.sql"), "no SQL");
  }
});

// The language ids docs/EDITORS.md promises editors (#197).
function editorLanguageIds(): string[] {
  const editors = readFileSync(join(root, "docs/EDITORS.md"), "utf8");
  const line = editors.match(/^Language ids are the server's: (.*)$/m);
  assert.ok(line, "docs/EDITORS.md lists the language ids");
  return [...line[1].split(". ")[0].matchAll(/`([^`]+)`/g)].map((m) => m[1]);
}

test("document selector covers each language docs/EDITORS.md lists, opentide-config included", () => {
  const documented = editorLanguageIds();
  assert.ok(documented.includes("opentide-config"), documented.join(", "));
  assert.deepEqual([...documented].sort(), LANGUAGES.map((l) => l.id).sort());
  for (const id of documented) {
    assert.ok(DOCUMENT_SELECTOR.some((s) => "language" in s && s.language === id), id);
  }
});

/** A glob as VS Code's document filters read one: `**` crosses folders, `*` does not. */
function globRegExp(glob: string): RegExp {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    if (glob.startsWith("**/", i)) {
      out += "(?:.*/)?";
      i += 2;
    } else if (glob.startsWith("**", i)) {
      out += ".*";
      i += 1;
    } else if (glob[i] === "*") {
      out += "[^/]*";
    } else {
      out += glob[i].replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${out}$`);
}

/** Whether a selector picks a document, as VS Code scores a filter: every field it sets must match. */
function selects(
  selector: ReadonlyArray<{ language?: string; scheme?: string; pattern?: string }>,
  uri: string,
  languageId: string,
): boolean {
  const url = new URL(uri);
  const scheme = url.protocol.replace(/:$/, "");
  const path = url.pathname.replace(/^\/+/, "");
  return selector.some(
    (f) =>
      (f.language === undefined || f.language === languageId) &&
      (f.scheme === undefined || f.scheme === scheme) &&
      (f.pattern === undefined || globRegExp(f.pattern).test(path)),
  );
}

test("the web selector matches vscode-vfs: URIs by pattern; the desktop one only file: URIs", () => {
  // A language id no extension registered, as on vscode.dev without one.
  const plain = "plaintext";
  const cases: Array<[string, boolean]> = [
    ["vscode-vfs://github/opentidehq/detections/objects/rules/rule.yaml", true],
    ["vscode-vfs://github/opentidehq/detections/.opentide/configurations/platforms/sentinel.toml", true],
    ["vscode-vfs://github/opentidehq/detections/queries/hunt.esql", true],
    ["vscode-vfs://github/opentidehq/detections/pyproject.toml", false],
    ["vscode-vfs://github/opentidehq/detections/notes/readme.yaml", false],
  ];
  for (const [uri, expected] of cases) {
    assert.equal(selects(WEB_DOCUMENT_SELECTOR, uri, plain), expected, uri);
    assert.equal(selects(DOCUMENT_SELECTOR, uri, plain), false, `desktop selector matched ${uri}`);
    const file = uri.replace("vscode-vfs://github/", "file:///home/user/");
    assert.equal(selects(DOCUMENT_SELECTOR, file, plain), expected, file);
  }
  assert.ok(WEB_DOCUMENT_SELECTOR.every((f) => !("scheme" in f)), "no scheme in the web selector");
  assert.ok(selects(WEB_DOCUMENT_SELECTOR, "vscode-vfs://github/o/r/x.txt", "opentide-config"), "by language id");
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
  // Configuration TOML is a host's to check (#158); the client does not answer it empty.
  await assert.rejects(client.highlight("opentide-config", "[x]"), /checked by the host/);
});

test("a transport without its artifact is refused, not answered empty", async () => {
  assert.throws(() => createOpentideClient({ transport: "worker" }), /needs `worker`/);
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
  await assert.rejects(client.analyze("kql", "take"), /analyze needs the language server/);
});

/** A stand-in for opentide-wasm's LanguageServer that answers what the client asks and logs it. */
function fakeServer(log: { method?: string; params?: unknown }[]): LanguageServerModule {
  return {
    version: () => "0.0.0",
    createSession() {
      let closed = false;
      return {
        get closed() {
          return closed;
        },
        handle(text: string) {
          const message = JSON.parse(text) as { id?: number; method?: string; params?: { language?: string } };
          log.push(message);
          const reply = (result: unknown) => [JSON.stringify({ jsonrpc: "2.0", id: message.id, result })];
          switch (message.method) {
            case "initialize":
              return reply({ capabilities: {}, serverInfo: { name: "fake" } });
            case "opentide/analyze":
              // A notification may come first; the client matches the response by id.
              return [
                JSON.stringify({ jsonrpc: "2.0", method: "window/logMessage", params: { type: 3, message: "hi" } }),
                ...reply({ diagnostics: [{ code: "kql_parse_error", severity: "error", message: "x", range: {} }] }),
              ];
            case "opentide/highlight":
              return reply({ language_id: message.params?.language, tokens: [{ capture: "keyword", start: 0, end: 4 }], legend: ["keyword"] });
            case "shutdown":
              return reply(null);
            case "exit":
              closed = true;
              return [];
            default:
              return [];
          }
        },
      };
    },
  };
}

test("worker transport: JSON-RPC to the language server in a worker, one message per postMessage", async () => {
  const log: { method?: string; params?: unknown }[] = [];
  const { port1, port2 } = new MessageChannel();
  const served = serveLanguageServer(port2, fakeServer(log));
  const workspace = { objects: [{ uuid: "00000000-0000-4000-8002-000000000001", schema: "objective::1.0", name: "Parent" }] };
  const client = createOpentideClient({ transport: "worker", worker: port1, workspace });
  assert.deepEqual((await client.analyze("kql", "T | wher x")).diagnostics.map((d) => d.code), ["kql_parse_error"]);
  assert.equal((await client.highlight("kql", "take")).tokens.length, 1);
  await client.dispose();
  await served;
  assert.deepEqual(
    log.map((m) => m.method),
    ["initialize", "initialized", "opentide/analyze", "opentide/highlight", "shutdown", "exit"],
  );
  const init = log[0]!.params as { processId: unknown; initializationOptions: unknown };
  assert.equal(init.processId, null);
  assert.deepEqual(init.initializationOptions, { workspace });
});

test("worker transport: a server that fails to load fails initialize with the reason, not an empty answer", async () => {
  const { port1, port2 } = new MessageChannel();
  void serveLanguageServer(port2, Promise.reject(new Error("404 Not Found")));
  const client = createOpentideClient({ transport: "worker", worker: port1 });
  await assert.rejects(client.analyze("kql", "T"), /did not load: 404 Not Found/);
  await client.dispose();
  port2.close();
});

test("worker transport: messages that arrive while the server loads wait for it", async () => {
  const log: { method?: string }[] = [];
  let release!: (module: LanguageServerModule) => void;
  const { port1, port2 } = new MessageChannel();
  const served = serveLanguageServer(port2, new Promise<LanguageServerModule>((resolve) => (release = resolve)));
  const client = createOpentideClient({ transport: "worker", worker: port1 });
  const analyzed = client.analyze("kql", "T");
  setTimeout(() => release(fakeServer(log)), 20);
  assert.equal((await analyzed).diagnostics.length, 1);
  await client.dispose();
  await served;
  assert.equal(log[0]!.method, "initialize");
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

test("worker: the language server in opentide-wasm answers like the native server", { skip: !wasmGlue && "set OPENTIDE_WASM_GLUE" }, async () => {
  const glue = pathToFileURL(resolve(wasmGlue!));
  const serve = (workspace?: Parameters<typeof createOpentideClient>[0]["workspace"]) => {
    const { port1, port2 } = new MessageChannel();
    const served = serveLanguageServer(port2, loadLanguageServer(glue));
    return { client: createOpentideClient({ transport: "worker", worker: port1, workspace }), served };
  };

  const { client, served } = serve();
  await using(client, async (client) => {
    assert.deepEqual(await client.legend(), generatedLegend);
    for (const [id, text] of Object.entries(SAMPLES)) {
      assert.ok((await client.highlight(id, text)).tokens.length > 0, `${id}: no tokens`);
      if (server) {
        const codes = (await client.analyze(id, text)).diagnostics.map((d) => d.code).sort();
        assert.deepEqual(codes, cliCodes(server, id, text), id);
      }
    }
    const broken = await client.analyze("kql", "SecurityEvent | wher EventID == 1");
    assert.ok(broken.diagnostics.length > 0);
    const rule = await client.analyze("opentide-yaml", TIDE_RULE);
    assert.ok(rule.diagnostics.some((d) => d.code === "invalid_ref"), "nothing indexed: the detection model is unknown");
  });
  await served;

  // A workspace supplied on initialize resolves the reference.
  const objective = { uuid: "00000000-0000-4000-8002-000000000001", schema: "objective::1.0", name: "Parent" };
  const supplied = serve({ objects: [objective] });
  await using(supplied.client, async (client) => {
    const rule = await client.analyze("opentide-yaml", TIDE_RULE);
    assert.ok(!rule.diagnostics.some((d) => d.code === "invalid_ref"), JSON.stringify(rule.diagnostics));
  });
  await supplied.served;
});

test("createOtideClient is rejected", () => {
  assert.throws(() => createOtideClient({ transport: "stdio" }), /createOpentideClient/);
});
