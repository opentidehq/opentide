import assert from "node:assert/strict";
import test from "node:test";
import { createOpentideClient, createOtideClient } from "./index.ts";

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
