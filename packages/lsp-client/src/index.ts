/**
 * opentide language client.
 *
 * The factory is `createOpentideClient`. There is no `createOtideClient`.
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

export interface OpentideClientOptions {
  transport: Transport;
  command?: string;
  args?: string[];
  workerUrl?: string;
  wasiPath?: string;
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

export interface OpentideClient {
  transport: Transport;
  highlight(languageId: string, text: string): Promise<HighlightResult>;
  legend(): Promise<string[]>;
  analyze(languageId: string, text: string): Promise<unknown>;
  dispose(): Promise<void>;
}

function encodeMessage(body: unknown): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify(body));
  const header = new TextEncoder().encode(`Content-Length: ${json.length}\r\n\r\n`);
  const out = new Uint8Array(header.length + json.length);
  out.set(header, 0);
  out.set(json, header.length);
  return out;
}

/** Language ids whose raw-file suffix is the id itself. */
const QUERY_EXTENSIONS = new Set(LANGUAGES.map((l) => l.id).filter((id) => id !== "opentide-yaml"));

export function createOpentideClient(options: OpentideClientOptions): OpentideClient {
  if (options.transport !== "stdio" && options.transport !== "worker" && options.transport !== "wasi") {
    throw new Error(`unsupported transport ${String(options.transport)}`);
  }
  return {
    transport: options.transport,
    async highlight(languageId, text) {
      if (options.transport === "worker" && typeof (globalThis as { highlight?: unknown }).highlight === "function") {
        const fn = (globalThis as { highlight: (id: string, bytes: Uint8Array) => unknown }).highlight;
        return fn(languageId, new TextEncoder().encode(text)) as HighlightResult;
      }
      if (options.transport === "stdio" && options.command) {
        const { spawnSync } = await import("node:child_process");
        const { mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
        const { tmpdir } = await import("node:os");
        const { join } = await import("node:path");
        const dir = mkdtempSync(join(tmpdir(), "opentide-hl-"));
        const ext = languageId.includes("yaml") || languageId === "tide"
          ? "yaml"
          : QUERY_EXTENSIONS.has(languageId) ? languageId : "kql";
        const file = join(dir, `query.${ext}`);
        writeFileSync(file, text);
        try {
          const result = spawnSync(
            options.command,
            options.args ?? ["highlight", file, "--language", languageId],
            { encoding: "utf8" },
          );
          if (result.status === 0 && result.stdout) {
            return JSON.parse(result.stdout) as HighlightResult;
          }
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      }
      return {
        language_id: languageId,
        tokens: [],
        legend: await this.legend(),
      };
    },
    async legend() {
      return [
        "comment",
        "keyword",
        "operator",
        "operator.pipe",
        "function",
        "function.builtin",
        "type",
        "variable",
        "property",
        "string",
        "number",
        "boolean",
        "constant",
        "punctuation",
        "punctuation.bracket",
        "punctuation.delimiter",
        "error",
        "tide.keyword",
        "tide.property",
        "tide.uuid",
        "tide.schema",
      ];
    },
    async analyze() {
      return { diagnostics: [] };
    },
    async dispose() {},
  };
}

/** @deprecated Never use this name. */
export function createOtideClient(_options: OpentideClientOptions): never {
  throw new Error("createOtideClient is not a valid export; use createOpentideClient");
}

export { encodeMessage };
