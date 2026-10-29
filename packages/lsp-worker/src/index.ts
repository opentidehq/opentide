/**
 * WASM worker host for `opentide-wasm`.
 *
 * Artifact: wasm32-unknown-unknown + wasm-bindgen.
 * Do not mix WASI into this module. vscode.dev uses a separate wasm32-wasip1 binary.
 *
 * Load the module inside the Web Worker that serves your editor, then pass it
 * to `createOpentideClient({ transport: "worker", module })`.
 */

export interface WorkerHighlightModule {
  highlight(language_id: string, bytes: Uint8Array): unknown;
  legend(): string[];
}

interface Glue {
  default?: unknown;
  highlight?: unknown;
  legend?: unknown;
}

/**
 * Import wasm-bindgen's glue for `opentide_wasm.wasm` and initialise it.
 *
 * `glueUrl` is the glue's JavaScript file. For `wasm-bindgen --target web`
 * glue, `wasm` (a URL, a `Response`, bytes or a compiled module) is passed to
 * its initialiser; when omitted, the glue fetches `opentide_wasm_bg.wasm` next
 * to itself. `--target nodejs` glue loads its module on import and ignores
 * `wasm`.
 */
export async function loadHighlightModule(
  glueUrl: string | URL,
  wasm?: string | URL | Response | BufferSource | WebAssembly.Module,
): Promise<WorkerHighlightModule> {
  if (!glueUrl) {
    throw new Error("glueUrl is required");
  }
  const glue = (await import(String(glueUrl))) as Glue;
  // `--target web` exports an async initialiser as the default export;
  // `--target nodejs` is CommonJS, whose exports may sit on `default`.
  if (typeof glue.default === "function") {
    await (glue.default as (init?: { module_or_path: unknown }) => Promise<unknown>)(
      wasm === undefined ? undefined : { module_or_path: wasm },
    );
  }
  const exports = (typeof glue.highlight === "function" ? glue : glue.default) as Glue | undefined;
  if (typeof exports?.highlight !== "function" || typeof exports.legend !== "function") {
    throw new Error(`${String(glueUrl)} is not opentide-wasm glue: it exports no highlight() and legend()`);
  }
  const { highlight, legend } = exports as { highlight: WorkerHighlightModule["highlight"]; legend: () => Iterable<string> };
  return {
    highlight: (language_id, bytes) => highlight(language_id, bytes),
    legend: () => [...legend()],
  };
}
