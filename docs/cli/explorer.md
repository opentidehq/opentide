---
title: opentide explorer
description: Build, preview, and serve the OpenTide explorer static UI from engine exports.
---

# opentide explorer

Builds the [OpenTide explorer](https://github.com/OpenTideHQ/explorer) static site from corpus exports. GitHub Pages workflows emitted by `opentide setup ci github --explorer-pages` call `opentide explorer build`.

```bash
opentide generate explorer     # write explorer.bundle.json
opentide explorer build        # generate exports + static export
opentide explorer dev          # local Next.js preview
opentide explorer serve        # HTTP server for a previous build
```

`opentide generate` does **not** run the explorer phase. Use `generate explorer` or `explorer build` explicitly. `explorer build` always regenerates the bundle first so CI does not need a separate generate step.

## explorer build

```bash
opentide explorer build \
  --output ./out/explorer \
  --base-path /library \
  --explorer-path ../explorer
```

| Flag | Env | Purpose |
|------|-----|---------|
| `--output` | — | Static site directory (default `<repo>/out/explorer`) |
| `--base-path` | — | Next.js `basePath` (GitHub Pages project sites) |
| `--exports-dir` | — | Directory with `explorer.bundle.json` (default `.opentide/exports`) |
| `--schemas-dir` | — | JSON Schema directory for explorer type codegen |
| `--skip-install` | — | Skip `pnpm install` when `node_modules` already exists |
| `--explorer-path` | `OPENTIDE_EXPLORER_PATH` | Local explorer checkout |
| `--explorer-git` | `EXPLORER_GIT_URL` | Git URL to shallow-clone |
| `--explorer-ref` | `EXPLORER_GIT_REF` | Branch, tag, or commit (default `main`) |
| `--version` | `EXPLORER_VERSION` | Git ref cloned into the cache directory |

Resolution order matches the explorer README: git URL, local path, sibling `../explorer`, version ref, then a cache clone of `https://github.com/OpenTideHQ/explorer.git` into `~/.cache/opentide/explorer-src/`.

Required: Node ≥ 20.19 and pnpm 9+ (unless `--skip-install` and `node_modules` is present). Required export: `explorer.bundle.json`. Optional: `explorer.search.json`, `explorer.coverage.json`, `attack-navigator.json`.

## explorer dev / serve

`dev` copies exports into the explorer `public/data` directory and runs `pnpm dev`. `serve` serves `--output` with `python3 -m http.server` (default port `4173`).

## generate explorer

```bash
opentide generate explorer
```

Writes `.opentide/exports/explorer.bundle.json` and `explorer.search.json` from the indexed corpus. This is the engine-side replacement for explorer's mock bundle generator.

## Source

`src/opentide/cli/explorer_app.py`, `src/opentide/cli/services/explorer.py`, `src/opentide/export/explorer_export.py`
