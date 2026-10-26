---
title: opentide explorer
description: Build or serve the interactive corpus explorer from your repository's exports.
---

# opentide explorer

The corpus explorer is a static web UI for browsing threats, objectives, signals and rules and the links between them. `opentide explorer` exports the corpus and hands it to the [`@opentide/explorer`](https://github.com/opentidehq/explorer) npm package, which builds the site with Next.js and can serve it locally.

```bash
opentide explorer serve
opentide explorer serve --port 8080 --host 0.0.0.0
opentide explorer build
opentide explorer build --output site --base-path /detections
opentide --json explorer build
```

Both commands first run [`opentide generate explorer`](./generate.md), which writes `explorer.bundle.json` and `explorer.search.json` under `.opentide/exports/` in the repository (`--repo` / `OPENTIDE_REPO_ROOT`). They then run the package through `npx`:

```bash
npx --yes --package @opentide/explorer@0.5 opentide-explorer build --exports-dir .opentide/exports --output out/explorer
```

## Requirements

**Node.js 20.19 or newer**, with `node` and `npx` on `PATH`. The commands check both before exporting anything and fail with exit code `1` and a message saying what to install when either is missing or too old. The first run downloads the package and its dependencies into the npm cache, so it needs access to the npm registry (or the mirror your `.npmrc` names).

opentide pins the package to the `0.5` release line: `npx` runs the newest `0.5.x`. To run another build, such as a local tarball or a fork, set `OPENTIDE_EXPLORER_PACKAGE` to any spec `npx --package` accepts:

```bash
OPENTIDE_EXPLORER_PACKAGE=./opentide-explorer-0.5.0.tgz opentide explorer build
```

## `explorer build`

Exports the corpus and builds the static site.

| Flag | Default | Purpose |
|------|---------|---------|
| `--output` | `out/explorer` in the repository | Directory the site is written to. A relative path is relative to the current directory |
| `--base-path` | none (site at `/`) | URL prefix the site is served under, for example `/my-repo` on GitHub Pages project sites |

The output directory holds plain HTML, JavaScript and the exported JSON, ready for any static host. With `--json`, the package's build log goes to stderr and stdout carries one result document with `command`, `package`, `node`, `exports_dir` and `output`. A build that fails reports the package's exit status in `exit_status`.

## `explorer serve`

Exports the corpus, builds the site (always without a base path), and serves it on a local HTTP server until you press Ctrl-C. Stopping the server is a successful exit.

| Flag | Default | Purpose |
|------|---------|---------|
| `--port` | `4173` | Port to listen on; `0` picks a free one |
| `--host` | `127.0.0.1` | Address to listen on. `0.0.0.0` exposes the explorer to your network |
| `--output` | `out/explorer` in the repository | Directory the site is built into before it is served |

Add `out/` to the repository's `.gitignore` if you build there; the site is regenerated on every run.

## In CI

`opentide setup ci github --explorer-pages` writes a job that runs `opentide generate explorer` and then the same `npx` build with `--base-path /<repository name>`, and a second job that publishes the site to GitHub Pages. See [CI/CD → Corpus explorer on GitHub Pages](../usage/workflows/ci-cd.md#corpus-explorer-on-github-pages).
