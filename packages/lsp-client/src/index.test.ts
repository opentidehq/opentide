import assert from "node:assert/strict";
import test from "node:test";
import { createOpentideClient, createOtideClient, DOCUMENT_SELECTOR, LANGUAGES } from "./index.ts";

test("document selector covers every language", () => {
  const ids = LANGUAGES.map((l) => l.id);
  assert.deepEqual(ids, ["opentide-yaml", "kql", "spl", "esql", "eql", "kuery", "lucene"]);
  for (const id of ids) {
    assert.ok(DOCUMENT_SELECTOR.some((s) => "language" in s && s.language === id), id);
  }
  assert.ok(DOCUMENT_SELECTOR.some((s) => "pattern" in s && s.pattern === "**/*.esql"));
  assert.ok(!DOCUMENT_SELECTOR.some((s) => "pattern" in s && s.pattern === "**/*.sql"), "no SQL");
});

test("createOpentideClient stdio", async () => {
  const client = createOpentideClient({ transport: "stdio" });
  assert.equal(client.transport, "stdio");
  const legend = await client.legend();
  assert.ok(legend.includes("tide.keyword"));
  const hl = await client.highlight("kql", "SecurityEvent | take 1");
  assert.equal(hl.language_id, "kql");
  assert.ok(Array.isArray(hl.tokens));
});

test("createOtideClient is rejected", () => {
  assert.throws(() => createOtideClient({ transport: "stdio" }), /createOpentideClient/);
});
