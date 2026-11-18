---
title: Smoke test before a release candidate
description: The checklist a maintainer runs by hand before cutting a release candidate - every surface from locally built packages, every platform's validate, offline engine and dry-run deploy, with the exact commands and what each should print. Nothing is published.
---

# Smoke test before a release candidate

One pass, by hand, on a clean machine, before the release train's internal candidate
([release-management](https://github.com/opentidehq/opentide/blob/development/.agents/skills/release-management/SKILL.md)).
It installs what the release would ship, **built locally**, and uses it as a user would. **Nothing is
published:** no tag, no registry, no tenant written to (every deploy is `--dry-run`).

What CI already holds is not repeated here; this page is what CI cannot see:

- **CI holds the packages:** `scripts/build/smoke_release.sh`, the npm local-registry test, the wheel
  smoke. It also holds every command's output (the snapshot cases, [`tests/golden/README.md`](https://github.com/opentidehq/opentide/blob/development/tests/golden/README.md)) and the
  language wiring (`xtask/tests/language_wiring.rs`).
- **This page is the editors, a person reading the output, and a clean environment.**
  [`test-plan.md`](test-plan.md) is the migration's phase plan, kept for history.

Tick each box; a step that does not print what it says is a release blocker until it is
explained. Record the commit, the machine, and anything surprising, in the release's issue.

## 0. Build the packages (from the commit to release)

- [ ] **Wheel:**
  ```bash
  pipx install maturin==1.16.0
  maturin build --release --locked --out dist
  ```
  Expected: `dist/opentide-<version>-cp310-abi3-<platform>.whl`.
- [ ] **npm tarball:**
  ```bash
  (cd bindings/node && npm ci && node build.mjs --release && npm pack --pack-destination ../../dist)
  ```
  Expected: `dist/opentide-opentide-<version>.tgz`, with this machine's `opentide.<platform>.node`
  inside (`tar -tzf`).
- [ ] **Binaries:**
  ```bash
  cargo build --locked --release -p opentide --features cli --bin opentide
  cargo build --locked --release -p opentide-lsp
  ```
  Expected: `target/release/opentide` and `target/release/opentide-lsp`.
- [ ] **WebAssembly worker:** `bash scripts/engine/build-wasm.sh browser`, with `wasm-bindgen`
  installed. Expected: `browser artifact: wasm-bindgen imports only`, then
  `browser artifact: highlight() works for kql, spl, ...`, every query language listed.

## 1. Install in clean environments

- [ ] **Wheel:**
  ```bash
  python3 -m venv /tmp/st-py && /tmp/st-py/bin/pip install dist/opentide-*.whl
  ```
  Then `/tmp/st-py/bin/opentide --version`. Expected: `opentide <version>`, the workspace's version.
- [ ] **npm:**
  ```bash
  mkdir /tmp/st-node && cd /tmp/st-node && npm init -y && npm install <repo>/dist/opentide-opentide-*.tgz
  ```
  Then `npx opentide --version`. Expected: the same line.
- [ ] **Binary:** `<repo>/target/release/opentide --version` and `opentide-lsp --version`.
  Expected: the same version from both.

The rest of this page runs `opentide` from the wheel's environment
(`export PATH=/tmp/st-py/bin:$PATH`). Repeat section 3 with `npx opentide` and the binary when time
allows: they are one program, so a difference is a packaging bug.

## 2. A workspace with every platform

```bash
SMOKE=$(mktemp -d)
cp -r tests/golden/fixtures/deploy-tenants/. "$SMOKE"
cp tests/fixtures/bitdefender/rule-bitdefender-detection-1.0.yaml \
   tests/fixtures/bitdefender/rule-bitdefender-yara-1.0.yaml \
   tests/fixtures/graylog/rule-graylog-aggregation-1.0.yaml \
   tests/fixtures/exabeam/rule-exabeam-threshold-1.0.yaml \
   tests/fixtures/google_secops/rule-google-secops-process-1.0.yaml "$SMOKE/objects/rules/"
cd "$SMOKE" && git init -q
opentide setup platforms --yes --bitdefender --graylog --exabeam --google-secops
```

The deploy fixture brings nine platforms with a tenant each; the last four are added without one
(a dry run needs none).

## 3. The command line

| Step | Command | Expected |
|---|---|---|
| [ ] Validate | `opentide validate` | `✓ 30 objects valid · 24 queries · 1 warning`, exit 0 |
| [ ] JSON | `opentide --json validate` | one JSON document, `"status": "passed"`, `"exit_code": 0`, nothing else on stdout |
| [ ] Queries offline | `opentide validate query` | `passed`, 24 queries, 0 errors |
| [ ] Lint | `opentide lint` | 61 findings: 31 warnings, 30 notes, no error; exit 0 |
| [ ] Info | `opentide info` | the 13 platforms, each `enabled` with its capabilities (`deploy, validate, query` for the tenant-checked ones), and `✓ 30 rules` |
| [ ] Generate | `opentide generate` | 63 files written, exit 0; `git status` shows `.opentide/`, `.vscode/`, `docs/` |
| [ ] Doctor | `opentide doctor` | no failed check (warnings are expected: no credentials) |
| [ ] Explain | `opentide explain yaml_parse` | the page, exit 0 |
| [ ] A broken file | `printf 'name: [\n' > objects/rules/broken.yaml && opentide validate` | `error[yaml_parse]` framed at the line, exit 1; remove the file |
| [ ] New | `opentide new rule --name Smoke --platform google_secops --platform bitdefender`, then `opentide validate --file objects/rules/smoke.yaml` | written, with its placeholders listed; validate reports no `yaml_parse` (#1617); remove the file |
| [ ] TUI | `opentide tui` | opens on the Catalogue tab; `1`–`6` switch tabs; `q` quits and restores the terminal |

## 4. Every platform

For each platform, run the offline engine and the dry-run deploy:

```bash
opentide --json validate query --platform <p>
opentide --json deploy --dry-run --all --strategy PREVIEW --strategy RELEASE --platform <p>
```

The deploy is expected to exit 0 with `"dry_run": true` and an `api_request` in each `payloads`
entry. Read one payload per platform: it is the request a live deploy would send.

| Platform | Offline engine (`validate query`) | Dry-run deploy (`summary`) | `--live` (optional, needs a tenant) |
|---|---|---|---|
| [ ] `sentinel` | passed, 2 queries | upsert 1 | [ ] passed |
| [ ] `defender_for_endpoint` | passed, 3 | create 1, update 1 | [ ] passed |
| [ ] `splunk` | passed, 2 | upsert 1 | [ ] passed |
| [ ] `sentinel_one` | exit 2, `usage_missing_option`: no offline engine, `--live` required | create 1, update 1 | [ ] passed |
| [ ] `crowdstrike` | passed, 3 | create 1, update 1 | `supported: false`, exit 1 |
| [ ] `harfanglab` | passed, 1 | upsert 2 | `supported: false`, exit 1 |
| [ ] `carbon_black_cloud` | passed, 2 | upsert 1 | [ ] passed |
| [ ] `elastic` | passed, 4 | upsert 3 | [ ] passed |
| [ ] `sysdig` | passed, 3 | create 1, update 1 | `supported: false`, exit 1 |
| [ ] `bitdefender` | passed, 1 | create 2 | `supported: false`, exit 1 |
| [ ] `graylog` | passed, 1 | create 1 | [ ] passed |
| [ ] `exabeam` | passed, 1 | create 1 | [ ] passed |
| [ ] `google_secops` | passed, 1 | create 1 | [ ] passed |

`--live` is `opentide --json validate query --live --platform <p>` with the platform's tenant
configured (`opentide setup platforms`, the credentials in the environment it names). It reads the
tenant and writes nothing. Skip a platform with no tenant to hand. Where it says
`supported: false`, check that the message names the platform and that nothing was sent.

## 5. MCP over stdio

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"validate_query","arguments":{"platform":"sentinel","query":"SecurityEvent | take 10"}}}' \
  | opentide mcp start
```

- [ ] Three responses, one JSON object a line, nothing else on stdout:
  - `serverInfo` `opentide` at the version;
  - 10 tools, `validate_query` and `deploy_rule` among them;
  - `"status": "passed"`, `"language": "kql"`.
- [ ] In an MCP client (`opentide setup mcp`, [MCP docs](../mcp/index.md)), ask it to validate a
  query of each language and to explain a code. It calls the tools and reports what they return.

## 6. Editors

- [ ] **Neovim (headless):** `nvim --headless --clean -l scripts/engine/nvim-smoke.lua target/release/opentide-lsp`.
  Expected: exit 0. It attaches Neovim's own LSP client and checks diagnostics and hover.
- [ ] **Neovim, by hand:**
  1. Source `editors/nvim/opentide.lua`, with `opentide` and `opentide-lsp` on `PATH`.
  2. Open `$SMOKE/objects/rules/sentinel-a-create.yaml`, then break its `query` (`| wherre`).
  3. Expected: a diagnostic on that line, hover on `SecurityEvent`, completion after `| `, and a
     diagnostic in `.opentide/configurations/platforms/splunk.toml` when a key is misspelt.
- [ ] **VS Code:**
  1. Install the opentide extension built from opentidehq/vscode-extension (its README: package a
     `.vsix`, then **Extensions: Install from VSIX…**), with its server pointed at this build's
     `opentide-lsp`.
  2. Open `$SMOKE`.
  3. Expected:
     - the same diagnostics, hover and completion as in Neovim, in a rule and in a `.kql` file;
     - semantic colours in a YARA-L block;
     - the "N rules use this objective" lens on an objective.

## 7. SDKs

- [ ] **Python (the wheel's environment):**
  ```bash
  python -c "from opentide import Workspace; ws = Workspace.open('$SMOKE'); print(ws.info()['counts'])"
  ```
  Expected: `rules` 30, and no traceback.
- [ ] **Node (`/tmp/st-node`):**
  ```bash
  node -e "const {Workspace}=require('@opentide/opentide'); Workspace.open('$SMOKE').then(ws => console.log(ws.validate({}).summary))"
  ```
  Expected: `objects: 30`, `errors: 0`.
- [ ] The snippets of [the Python SDK pages](../sdk/workspace.md) and
  [TypeScript](../sdk/typescript.md) run as written against `$SMOKE`.

## 8. Clean up

- [ ] **Remove the scratch files and environments:** `rm -rf "$SMOKE" /tmp/st-py /tmp/st-node dist`. Nothing was written outside them.
- [ ] **Record the result** in the release's issue. Note anything that differed from this page, and
  update the page when the difference is intended.
