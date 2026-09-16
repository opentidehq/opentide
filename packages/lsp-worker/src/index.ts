/**
 * WASM worker host for `opentide-wasm`.
 *
 * Artifact: wasm32-unknown-unknown + wasm-bindgen.
 * Do not mix WASI into this module. vscode.dev uses a separate wasm32-wasip1 binary.
 */

export interface WorkerHighlightModule {
  highlight(language_id: string, bytes: Uint8Array): unknown;
  legend(): string[];
}

export async function loadHighlightModule(wasmUrl: string): Promise<WorkerHighlightModule> {
  // Hosts bind the wasm-bindgen glue. This package only documents the contract.
  if (!wasmUrl) {
    throw new Error("wasmUrl is required");
  }
  return {
    highlight(language_id, _bytes) {
      return { language_id, tokens: [], legend: [] };
    },
    legend() {
      return [];
    },
  };
}
