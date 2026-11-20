---
title: Smoke test before a release candidate
description: The checklist a maintainer runs by hand before cutting a release candidate - every surface from locally built packages, every platform's validate, offline engine and dry-run deploy, with the exact commands and what each should print. Nothing is published.
---

# Smoke test before a release candidate

One pass, by hand, on a clean machine, before the release train's internal candidate
([release-management](../../.agents/skills/release-management/SKILL.md)).
It installs what the release would ship, **built locally**, and uses it as a user would. **Nothing is
published:** no tag, no registry, no tenant written to (every deploy is `--dry-run`).

What CI already holds is not repeated here; this page is what CI cannot see:

- **CI holds the packages:** `scripts/build/smoke_release.sh`, the npm local-registry test, the wheel
  smoke. It also holds the dry-run payloads and the MCP stdio session, which sections 4 and 5 run
  again because a person reads what they print. It also holds every command's output (the snapshot cases, [`tests/golden/README.md`](../../tests/golden/README.md)) and the
  language wiring (`xtask/tests/language_wiring.rs`).
- **This page is the editors, a person reading the output, and a clean environment.**
  [`test-plan.md`](test-plan.md) is the migration's phase plan, kept for history.

Tick each box; a step that does not print what it says is a release blocker until it is
explained. Record the commit, the machine, and anything surprising, in the release's issue.

## 0. Build the packages (from the commit to release)

Everything below runs from one shell. Builds and scratch files go to `$OUT`; the npm packages are
stamped with a version in a throwaway worktree, because `release.py npm-version` edits tracked
files.

```bash
REPO=$(git rev-parse --show-toplevel)
OUT=$(mktemp -d)
V=$(cargo metadata --no-deps --format-version 1 --manifest-path "$REPO/Cargo.toml" \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "opentide"))')
```

To smoke-test what CI built rather than a local build, download the `release` job's artifacts
of a run on this commit (wheels, `npm-packages`, the binaries; development versions,
`X.Y.Z-dev.N`): the steps below take them in place of the local ones.

- [ ] **Wheel:**
  ```bash
  (cd "$REPO" && pipx run maturin==1.16.0 build --locked --out "$OUT/dist")
  ```
  `uvx maturin==1.16.0` does the same where `pipx` is not installed (`uv` is the dev setup's).
  Expected: `$OUT/dist/opentide-$V-cp310-abi3-<platform>.whl`.
- [ ] **npm packages** (this machine's native package, with its addon):
  ```bash
  git -C "$REPO" worktree add --detach "$OUT/npm-tree" HEAD
  (cd "$OUT/npm-tree" \
    && python3 scripts/engine/release.py npm-version "$V-dev.1" \
    && (cd bindings/node && npm ci && OPENTIDE_VERSION="$V-dev.1" node build.mjs --release) \
    && node scripts/engine/npm-local-registry/test.mjs --version "$V-dev.1" --pack "$OUT/npm" --work "$OUT/npm-work" --keep)
  ```
  This is CI's npm install test on this machine's build:
  - it packs the packages into `$OUT/npm`, the other platforms' native packages as stand-ins;
  - it publishes them to a throwaway local registry, with no uplink, and installs
    `@opentide/opentide` in a clean project;
  - it checks that npm chose this machine's native package, that `npx opentide --version` prints
    `$V-dev.1`, that the SDK loads from CommonJS and ESM, and that `tsc` resolves its types.

  Expected: its last lines are `PASS: @opentide/opentide@$V-dev.1 installs from a local registry and
  runs on <platform>` and `kept $OUT/npm-work`, and it exits 0.
- [ ] **Binaries:**
  ```bash
  (cd "$REPO" && cargo build --locked --release -p opentide --features cli --bin opentide && cargo build --locked --release -p opentide-lsp)
  ```
  Expected: `$REPO/target/release/opentide` and `$REPO/target/release/opentide-lsp`.
- [ ] **WebAssembly worker:**
  ```bash
  cargo install wasm-bindgen-cli --version 0.2.128 --locked
  (cd "$REPO" && bash scripts/engine/build-wasm.sh browser)
  ```
  `wasm-bindgen` must be the version `Cargo.lock` pins; without it the script skips `highlight()`
  and still exits 0. Expected, three lines:
  - `browser artifact: wasm-bindgen imports only`;
  - `browser artifact: highlight() works for kql, spl, ...`, with every query language;
  - `browser artifact: the language server answers initialize, diagnostics, hover and completion`.

## 1. Install in clean environments

- [ ] **Wheel:**
  ```bash
  python3 -m venv "$OUT/py" && "$OUT/py/bin/pip" install "$OUT"/dist/opentide-*.whl
  "$OUT/py/bin/opentide" --version
  ```
  Expected: `opentide $V`.
- [ ] **npm:** done in section 0 (`npx opentide --version` printed `$V-dev.1`).
- [ ] **Binaries:**
  ```bash
  "$REPO/target/release/opentide" --version
  "$REPO/target/release/opentide-lsp" --version
  ```
  Expected: `opentide $V` and `opentide-lsp $V`.

```bash
export PATH="$OUT/py/bin:$REPO/target/release:$PATH"
```

From here, `opentide` is the wheel's and `opentide-lsp` the binary's. Repeat section 3 with
`"$REPO/target/release/opentide"` when time allows: they are one program, so a difference is a
packaging bug.

## 2. A workspace with every platform

```bash
SMOKE="$OUT/smoke"
cp -r "$REPO/tests/golden/fixtures/deploy-tenants" "$SMOKE"
cp "$REPO/tests/fixtures/bitdefender/rule-bitdefender-detection-1.0.yaml" \
   "$REPO/tests/fixtures/bitdefender/rule-bitdefender-yara-1.0.yaml" \
   "$REPO/tests/fixtures/graylog/rule-graylog-aggregation-1.0.yaml" \
   "$REPO/tests/fixtures/exabeam/rule-exabeam-threshold-1.0.yaml" \
   "$REPO/tests/fixtures/google_secops/rule-google-secops-process-1.0.yaml" "$SMOKE/objects/rules/"
cd "$SMOKE" && git init -q
opentide setup platforms --yes --bitdefender --graylog --exabeam --google-secops
```

The deploy fixture brings nine platforms with a tenant each. The last four are added without one;
a dry run needs none. Sections 3 to 5 run in `$SMOKE`.

## 3. The command line

| Step | Command | Expected |
|---|---|---|
| [ ] Validate | `opentide validate` | `✓ 30 objects valid · 24 queries · 1 warning`, exit 0 |
| [ ] JSON | `opentide --json validate` | one JSON document, `"status": "passed"`, `"exit_code": 0`, nothing else on stdout |
| [ ] Queries offline | `opentide validate query` | `passed`, 24 queries, 0 errors |
| [ ] Lint | `opentide lint` | 61 findings: 31 warnings, 30 notes, no error; exit 0 |
| [ ] Info | `opentide info` | the 13 platforms, each `enabled` with its capabilities (`deploy, validate, query` for the tenant-checked ones), and `✓ 30 rules` |
| [ ] Generate | `opentide generate` | 63 files written, exit 0; `git status` lists `.opentide/`, `.vscode/` and `docs/` (and `objects/`: nothing in `$SMOKE` is committed) |
| [ ] Doctor | `opentide doctor` | no failed check (warnings are expected: no credentials) |
| [ ] Explain | `opentide explain yaml_parse` | the page, exit 0 |
| [ ] A broken file | `printf 'name: [\n' > objects/rules/broken.yaml && opentide validate` | `error[yaml_parse]` framed at the line, exit 1; remove the file |
| [ ] New | `opentide new rule --name Smoke --platform google_secops --platform bitdefender`, then `opentide validate --file objects/rules/smoke.yaml` | written, with a count of placeholders to replace; validate reports no `yaml_parse` (#1617); remove the file |
| [ ] TUI | `opentide tui` | opens on the Catalogue tab; `1`–`6` switch tabs; `q` quits and restores the terminal |

## 4. Every platform

For each platform, run the offline engine and the dry-run deploy:

```bash
opentide --json validate query --platform <p>
opentide --json deploy --dry-run --all --strategy PREVIEW --strategy RELEASE --platform <p>
```

The deploy is expected to exit 0 with `"dry_run": true`; `payloads` is keyed by platform, and each
rule's entry under it has an `api_request`. Read one payload per platform: it is the request a live deploy would send, on every platform ([`deploy`](../cli/deploy.md#payloads)). For Defender for Endpoint, SentinelOne, CrowdStrike, HarfangLab, Splunk and Carbon Black Cloud it is the list of requests the entry's `tenant` receives, each `{method, url, body}`: a Defender create is a `POST` whose body carries `displayName`, `queryCondition` and `isEnabled: true`, and a rule the deployment state records is a `PATCH` of its id. A value a deploy learns only as it sends is a placeholder: Splunk's `<send-time:minute>` in a `frequency` schedule of a `frequency_scheduling = "current"` tenant, Carbon Black's `<send-time:timestamp>` and `<tenant-read:watchlist>`.

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

- [ ] **Neovim, headless:** `nvim --headless --clean -l "$REPO/scripts/engine/nvim-smoke.lua" "$REPO/target/release/opentide-lsp"`.
  Neovim comes from the system's packages (`apt-get install neovim`, as the nightly does) or a
  Neovim release. Expected: exit 0 and a line `nvim-smoke: ..., one diagnostic (kql_unknown_operator), ...`. The nightly runs it on a debug build; this is the release build. It attaches
  Neovim's own client and requires one `kql_unknown_operator` diagnostic.
- [ ] **Neovim, by hand:**
  1. Source `$REPO/editors/nvim/opentide.lua`. It starts `opentide-lsp --stdio` for rules and
     queries, and `opentide lsp start` for configuration files, so both must be on `PATH`.
  2. Open `$SMOKE/objects/rules/sentinel-a-create.yaml` and break its `query` (`| wherre`).
  3. Expected: a diagnostic on that line, hover on `SecurityEvent`, and completion after `| `.
  4. Write `SecurityEvent | wherre x` to `$SMOKE/q.kql` and open it. Expected: the same diagnostic.
  5. Misspell a key in `.opentide/configurations/platforms/splunk.toml`. Expected: a diagnostic.
- [ ] **VS Code** (by hand, in a desktop session: an agent's container skips it and says so):
  1. Install the opentide extension built from opentidehq/vscode-extension (its README: package a
     `.vsix`, then **Extensions: Install from VSIX…**), with its server pointed at this build's
     `opentide-lsp`.
  2. Open `$SMOKE`.
  3. Expected:
     - the same diagnostics, hover and completion as in Neovim, in a rule and in `q.kql`;
     - semantic colours in `rule-google-secops-process-1.0.yaml`'s YARA-L.

## 7. SDKs

- [ ] **Python (the wheel's environment):**
  ```bash
  python -c "from opentide import Workspace; ws = Workspace.open('$SMOKE'); print(ws.info()['counts'])"
  ```
  Expected: `rules` 30, and no traceback.
- [ ] **Node** (the package as built, with its addon):
  ```bash
  node -e "const {Workspace}=require('$OUT/npm-tree/bindings/node'); Workspace.open('$SMOKE').then(ws => console.log(ws.validate({}).summary))"
  ```
  Expected: `objects: 30`, `errors: 0`, `warnings: 1` (the Bitdefender fixture's
  `bitdefender_severity_collapsed`).
- [ ] The snippets of [the Python SDK pages](../sdk/workspace.md) and
  [TypeScript](../sdk/typescript.md) run as written against a copy of `$SMOKE`, each fence from that
  directory (the TypeScript ones with `@opentide/opentide` resolving to `$OUT/npm-tree/bindings/node`).
  Expected:
  - every fence runs, except the tenant operations (`Connection`): they need a configured tenant and
    stop with `credential_unset`, naming `S1_API_TOKEN` (`$SMOKE`'s SentinelOne tenant has no
    credentials). The test suite runs them against the SentinelOne stand-in of `tests/cassettes/`;
  - the `strict: true` validation exits 1: strict fails the Bitdefender fixture's one warning.

## 8. Clean up

- [ ] **Remove the scratch files and builds:**
  ```bash
  cd "$REPO" && git worktree remove --force "$OUT/npm-tree" && rm -rf "$OUT"
  ```
  The builds also wrote:
  - `$REPO/target/` and `$REPO/bindings/node/node_modules`;
  - the `cargo install`ed `wasm-bindgen`;
  - any MCP client configuration `opentide setup mcp` wrote.

  Remove what you do not keep.
- [ ] **Record the result** in the release's issue. Note anything that differed from this page, and
  update the page when the difference is intended.
