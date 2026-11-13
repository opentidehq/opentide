---
title: Catch-up plan 0.28
description: Porting everything development shipped in 0.24.0 to 0.28.0 into the Rust workspace before 1.0.0-rc.1, and moving the golden oracle to 0.28.0.
---

# Catch-up plan: development 0.24.0–0.28.0 into `integration/unified-core`

Planning document for the Rust rewrite (epic #790). It covers porting everything `development` shipped
in Python after the fork into the Rust workspace before `1.0.0-rc.1`, then moving the golden oracle
from 0.23.0 to 0.28.0. It was written read-only against `origin/development` = `3acbea603` (tag
`v0.28.0`) and `origin/integration/unified-core` = `4d998ba14` (train 9, #1027), fetched 2026-11-13.

## 0. Facts this plan rests on

| Fact | Value |
|---|---|
| Merge base | `f41fe5e5c` (Merge #785, `docs: prepare 0.23.0`, tag `v0.23.0`), the golden oracle's commit |
| development since | 22 first-parent merges, 142 commits; releases 0.24.0, 0.24.1, 0.25.0, 0.26.0, 0.27.0, 0.28.0 |
| integration since | 1,285 commits; Python implementation removed by UC-6.2 (#841); `src/opentide/` keeps `_cli.py`, `sdk.py`, `models/` (Rust classes), `plugins.py`, `analysis.py`, `data/`, `schemas/data/` |
| Engine on integration | language-server **0.12.0** (CQL), imported with history (`docs/engine/IMPORT.md`, merge `3833048b`, ls `b92fa305`); workspace `version = "0.12.0"`, `rust-version = "1.85"`, toolchain pinned `1.99.1` |
| Engine on development | language-server **0.16.0** from crates.io (`1acb6db16`), path 0.11.0 → 0.11.1 → 0.12.1 → 0.13.0 → 0.14.0 → 0.15.0 → 0.16.0 |
| language-server | `main` stops at `v0.16.0` = `7402e154`; 116 commits after `b92fa305`; no commits after 0.16.0 |
| Specifications lock | `data/specifications.lock.json` is **byte-identical** on both branches: `specifications_git_sha` `6b1bbaa4e882`, vocabulary digest `4a618aec…`, pins digest `ef5f2b4e…`. No vocabulary or pin file changed on development (`src/opentide/data/vocabulary/`, `src/opentide/data/pins/` untouched) |
| Oracle wheel | `opentide-0.28.0-cp310-abi3-manylinux_2_28_x86_64.whl`, SHA-256 `1700f673d17265420df7486c9685420c5733e1dcab4c413da8b5683b68e9624b`, uploaded 2026-11-12T17:43:13Z, tag commit `3acbea603112e71cc31e3ee1c4285a2b06fa29d3` |
| Trial merge | `git merge --no-commit --no-ff origin/development` into integration: 24 content conflicts, 98 modify/delete, 328 additions, 32 clean modifications (§3.2) |

Two consequences shape everything below:

1. **The engine catch-up is not a pin bump.** integration owns the engine crates, and since the
   0.12.0 import it rewrote `opentide-tide` (the YAML is `opentide_core::node`, serde_yaml is gone,
   #850; Tide diagnostics come from `opentide-workspace`'s validate, `b7f4c3235`). language-server
   0.13–0.16 wrote its new Tide block modules on `serde_yaml::Value`. The language crates import
   cleanly; the Tide block modules have to be ported onto `Node`.
2. **Two implementations of each platform's checks exist upstream.** development checks each new
   block in Python (`platforms/<p>/constraints.py`, `checks.py`, `catalog.py`), and language-server
   checks the same codes again in Rust (`opentide-tide/src/{bitdefender,graylog,exabeam,google_secops,yara}.rs`)
   "so the editor and `opentide validate` agree". In this workspace there should be one
   implementation, in `opentide-schema`, that reaches the editor through `opentide-workspace`'s
   validate, as UC-2.6 made the language server do. The language-server modules are the reference
   for that port, and their tests become its tests.

---

## 1. Inventory

### 1.1 Releases and pull requests (first-parent order)

| Merge | PR | Release | What changed (user-visible) | Python touched (main files) | Unit |
|---|---|---|---|---|---|
| `619c1b13b` | #789 | — | Unified-core plan doc (`docs/internal/unified-core.md`) | none | M0 |
| `6c176dfe6` | #878 | 0.24.0 | Splunk `advanced` table validates and deploys again (`ffeaf5980`, `429f25d15`); engine 0.11.1 → 0.12.1 (CQL in editor/TUI; catalog accepts `advanced`; `crowdstrike_unsupported` retired) (`948fb8afc`, `b8517c36a`, `361fe4410`); 0.24.0 notes (`2479b97da`) | `models/platform.py` (+21, `SplunkConfig.advanced`), `platforms/splunk/deployer.py` (+18), `analysis.py` (+21) | F1, C1, M0 |
| `eb333aa20` | #882 | 0.24.1 | `typer>=0.27.0,<0.29`; `setup ci` providers through Typer's public API, an invalid provider names the closest (`cfe3c1815`) | `cli/enums.py`, `cli/setup_app.py`, `pyproject.toml` | F4 (verify only) |
| `080608201` | #897 | 0.24.1 | The diagnostics reference escapes `<` outside code spans (MDX); `scripts/build/check_docs_mdx.py` and `validate-docs.sh` fail on docs MDX cannot render (`d3e1db4e4`, `3db40abb2`) | `cli/services/explain.py` (`_mdx_prose`, `reference_markdown`) | F3, M0 |
| `cdc33aa60` | #904 | 0.24.1 | Release notes 0.24.1 | none | M0 |
| `3f3b40e7a` | #909 | — | Engine pinned to language-server's YARA work (#165) (`fdb6706dd`) | none (`analysis/Cargo.*`) | E1 |
| `b1625411a` | #901 | 0.25.0 | **HarfangLab YARA**: `yara.signature` (whole YARA text, sent verbatim); **breaking #899**, one kind per block (`harfanglab_rule_kind`), `harfanglab_yara_section_header`, `_import`, `_rule_name`, `_yara_form`, `yara_signature_alias`; YARA checked offline in validate, lint, `validate query`, MCP; lint `yara_meta_missing`, `harfanglab_yara_context` (harfanglab-1.0 rev 1.2/1.3) (`2f5156a5c` … `9e5b5f2ef`, 14 commits) | `platforms/harfanglab/yara.py` (+774, new), `platforms/harfanglab/deployer.py`, `models/platform_configs.py`, `models/platform.py`, `models/rule.py`, `validation/session.py` (+105), `validation/query_platforms.py`, `cli/services/lint.py` (+73), `cli/services/explain.py`, `cli/services/validation.py`, `mcp_server/tools.py`, `analysis.py`, `_native.pyi` | H1 |
| `73ce1e90b` | #902 | 0.25.0 | **Bitdefender GravityZone** platform (`platform::bitdefender::1.0`): model, `bitdefender_*` codes, advisories, name duplicates, YARA signature checks, deployer over JSON-RPC (`createCustomRule`, `updateCustomRule`, `deleteCustomRule`), dry run resolving targets, `setup platforms --bitdefender`, `new` scaffold (`c44c651ab` … `3c39b2ed4`, 13 commits) | `platforms/bitdefender/{advisories,catalog,client,compile,criteria,deployer}.py` (new, 1,721 lines), `validation/{yara_signature,bitdefender_names,bitdefender_advisories}.py` (new), `validation/{session,errors,compile_check}.py`, `models/{platform,platform_configs,platform_schema,system_config,deployment_enums}.py`, `models/configuration/platforms.py` (+91), `platforms/{config,enabled,plugins}.py`, `deployment/{preview,planning}.py`, `states/deployment.py`, `loading/platform_loader.py`, `cli/{completion,enums,setup_app}.py`, `cli/services/{deploy,deploy_plan,doctor,lint,new,validation,setup/platforms}.py`, `cli/ui/results/deploy.py`; data `bitdefender/criteria.toml` (3,684 lines), 27 explain pages | P-BD |
| `c16347eed` | #921 | — | Engine pinned to language-server `2e7fff0` (Bitdefender block checks, ls #228) | none | E1 |
| `834bda36b` | #923 | 0.25.0 | Bitdefender `yara.signature` checked offline under the engine's `bitdefender` profile; `yara_module_unconfirmed` lint (`ce806fe8f`) | `mcp_server/tools.py`, `validation/query_platforms.py`; 2 explain pages | P-BD |
| `c7cc58367` | #938 | 0.25.0 | Engine 0.13.0 from crates.io (`dc184cf39`) | none | E1 |
| `a422d2d76`, `3313e3ddf` | #939, #942 | 0.25.0 | Notes | none | M0 |
| `6e693286e` | #970 | 0.26.0 | **Graylog** platform (`platform::graylog::1.0`): event definitions on Graylog 6.3–7.2, `/api/system` version, `/api/search/validate` before each save, `/api/events/definitions`, `opentide query` on `/api/search/messages`, `validate query --live`; `graylog_*` codes, `graylog_all_streams`, `graylog_title_duplicate`; Lucene Graylog dialect offline (`dbb219094` … `5d02181a3`). Also **fix: legacy external-id key with a text value** (`d0c08892f`, issue #913) | `platforms/graylog/{advisories,client,compile,constraints,deployer,runner,validator}.py` (new, 2,125 lines), `validation/{graylog_advisories,graylog_titles,errors,session,query_platforms}.py`, `query/{rules,runner,service}.py`, `analysis.py`, the same model/CLI/deploy files as #902; 38 explain pages | P-GL, F2 |
| `5bf2380d2` | #984 | 0.26.0 | **Docs redesign**: one page layout (breadcrumb, subtitle, TLP banner, overview, TOC, Metadata last), Deployment section and deployment map, every platform setting by YAML path, fenced queries per language, catalogue overview (`docs/README.md`), kill-chain maps, ATT&CK coverage in matrix order, CVE details (CVSS, EPSS, KEV, CWE), redrawn Mermaid (`cd74cfaf3`, `8a986b215`, `e8a92ee7e`, `c0cafd31f`, `fd962f93b`, `f85c4f14f`) | `documentation/**` (37 files; new `facts/{deployment,platforms,settings}.py`, `diagram/{mermaid,model}.py`, `markdown/{page,text}.py`, `parts/{common,objective,rule,threat}.py`, `vocabulary.py`; `parts/sections.py` removed), `vulnerability_lookup.py` (+177), `models/system_config.py` (`tenant_skip_reason`), `deployment/planning.py`, `cli/enums.py` (`platform_label`) | D1, D2, D3 |
| `1c3ba5c53` | #990 | 0.26.0 | Engine 0.14.0 (`94c35a2ad`) | none | E1 |
| `f00ed0378` | #995 | 0.26.0 | Notes | none | M0 |
| `13bc1a202` | #983 | 0.27.0 | **Exabeam New-Scale SIEM** (`platform::exabeam::1.0`): correlation rules (`/correlation-rules/v2/rules`), OAuth (`/auth/v1/token`), name check before create, 100 req/min pacing, `validate query --live` and `query` through `/search/v2/events`; 13 `exabeam_*` codes, `exabeam_name_duplicate`, two advisories; Exabeam Query Language offline (`5732a4116` … `e2280a001`, 12 commits) | `platforms/exabeam/{advisories,client,compile,constraints,deployer,runner,validator}.py` (new, 1,989 lines), `validation/{exabeam_advisories,exabeam_names,errors,session,query_platforms}.py`, `query/*`, `analysis.py` (+39), `cli/ui/diagnostics.py`, `documentation/facts/platforms.py`; 28 explain pages | P-EX |
| `7c9672f81` | #1001 | — | Plain-language release headlines, release-notes skill (`b0c2f13f4`) | none | M0 |
| `999d3ab28` | #1003 | 0.27.0 | Notes | none | M0 |
| `f34fc0f05` | #997 | 0.28.0 | **Google Security Operations** (`platform::google_secops::1.0`, rev 1.2): YARA-L rule assembled from sections plus derived meta, `:verifyRuleText`, rules and `rules/{id}/deployment` on `https://{location}-chronicle.googleapis.com`, archive/delete, run frequency, schedule, data access scope, service-account key or ADC, `opentide query` via `:udmSearch`; `google_secops_*` and `yaral_section_*` codes; YARA-L offline (`82a6a263b` … `1acb6db16`, 23 commits) | `platforms/google_secops/{advisories,checks,client,compile,deployer,diagnostics,runner,validator,yaral}.py` (new, 2,524 lines), `validation/google_secops.py`, `validation/{errors,session,query_platforms}.py`, `query/service.py`, `states/deployment.py`, `cli/services/new.py`, `pyproject.toml` (`google-auth>=2.30`); 33 explain pages | P-GS |
| `3acbea603` | #1009 | 0.28.0 | Notes; tag `v0.28.0` | none | M0 |

Commit `42fe9a1e2` (docs: prepare 0.28.0) and the other notes commits change only
`CHANGELOG.md`, `docs/usage/releases.md`, `.github/release-notes/`, `README.md` and version claims
in `docs/`.

### 1.2 Non-Python changes on development

| Path | Change | Unit |
|---|---|---|
| `.agents/skills/release-notes/SKILL.md` | Rewritten around a ≤25-word plain-language headline (#1001) | M0 |
| `.agents/skills/release-management/SKILL.md` | "headline" wording; rationale in the Release body only | M0 |
| `.agents/skills/docs-maintenance/SKILL.md` | Link depth fixed (`../../../docs/`) | M0 |
| `.agents/skills/uv/SKILL.md` | Rust 1.95+ | E1 |
| `AGENTS.md` | Platform matrix for 13 platforms, per-platform notes, Rust 1.95 | X1 (integration's AGENTS.md is restructured; the matrix belongs in `crates/opentide-connectors/AGENTS.md`) |
| `.github/workflows/ci.yml` | `check_bitdefender_catalogue.py` step | none: superseded (one catalogue, `data/catalogs/bitdefender/criteria.toml`, after E1) |
| `.github/workflows/docs.yml`, `scripts/validate-docs.sh`, `scripts/build/check_docs_mdx.py` | MDX check of docs prose | M0 |
| `scripts/build/check_bitdefender_catalogue.py`, `scripts/ci-local.sh` | Bitdefender catalogue parity with the pinned engine | none: superseded |
| `pyproject.toml`, `uv.lock` | typer cap, `google-auth`, platform entry points | none: integration's `pyproject.toml` depends on `pydantic` alone and declares no built-in platform entry points |
| `src/opentide/data/configurations/platforms/{bitdefender,graylog,exabeam,google_secops}.toml` | Bundled tenant templates | P-* |
| `src/opentide/data/diagnostics/*.md` (130 new) | 28 bitdefender, 38 graylog, 28 exabeam, 26 google_secops, 7 yaral, 2 yara, 1 harfanglab | P-*, H1 |
| `src/opentide/data/bitdefender/{criteria.toml,NOTICE}` | GravityZone criteria catalogue | P-BD (one copy with `data/catalogs/bitdefender/`) |
| `src/opentide/data/setup/skills/detection-workflow/SKILL.md` | One line per new platform | P-* |
| `src/opentide/schemas/data/platform_templates/*.template.yaml` | 4 new, harfanglab changed | P-*, H1 (written by `cargo xtask codegen`) |
| `tests/fixtures/{bitdefender,graylog,exabeam,google_secops,harfanglab}/` | Block, rule, tenant and `*.api.json` request fixtures, `invalid/` cases (4, 4, 5, 6, 4) | P-*, H1 (Rust test inputs) |
| `tests/fixtures/tide_corpus/current/` | `rule-0014-bitdefender-gravityzone.yaml`, `rule-0015-graylog-event-definition.yaml`, `rule-0015-exabeam-correlation.yaml`, `rule-0016-google-secops-yaral.yaml`, 4 platform TOMLs | P-* on the train (§4) |
| `tests/corpus_support.py` | `CORPUS_RULE_UUIDS` for the 4 platforms | P-* on the train |
| `tests/fixtures/vulnerability_lookup/{cve-2023-4966,cve-2024-3094,epss-cve-2023-4966}.json` | CVE detail fixtures | D3 |
| `tests/fixtures/configuration_schemas/*`, `tests/fixtures/generation/tide_workspace/.opentide/templates/rule.1.0.template.yaml`, `tests/fixtures/deployment/modifier_flatten_expected.json` | Regenerated fixtures | P-*, H1, F1 |
| `docs/**` | Feature pages for every unit; version claims; releases page | per unit; M0 for history only |
| `.github/release-notes/v0.24.0.md` … `v0.28.0.md`, `v0.23.0.md` headline | Release bodies | M0 |

### 1.3 Analysis engine 0.12.0 → 0.16.0 (language-server, `b92fa305..7402e154`)

| ls release | ls PRs | What | Lands in |
|---|---|---|---|
| 0.12.1 (`7d7b537`, #225) | `49584f0`, `bd15b67` | Tide catalog accepts Splunk `advanced`; Tide grammar regenerated | F1: the catalog is generated from `opentide-schema` on integration, so this is the model change |
| 0.13.0 (`70bbaa4`, #240) | #227, #229, #230, #231, #232, #233 (YARA 1–6), #235, #236, #237, #238, #239, #228 | `opentide-yara` (on `yara-x-parser`, `yara-x-fmt`), tree-sitter-opentide-yara, `catalogs/yara/` (13 modules), YARA in HarfangLab and Bitdefender blocks (`opentide-tide/src/yara.rs`, 1,122 lines), editor features (rename, formatting, signature help), Bitdefender block checks and criteria completion (`opentide-tide/src/bitdefender.rs`, 2,498 lines; `catalogs/bitdefender/criteria.toml`), one `LineIndex` per text (#238, perf), Rust 1.95 | E1, E2-Y, H1, P-BD |
| 0.13.0+ (`20113f5`, #241) | | Each native target in the pinned toolchain | E1 (check against integration's `rust-toolchain.toml`) |
| 0.14.0 (`f9720b6`, #242/#244) | | Lucene Graylog dialect (`opentide-lucene/src/graylog.rs`, 575 lines), 7 `graylog_*` language codes, Graylog block checks and aggregation-function completion (`opentide-tide/src/graylog.rs`, 1,683 lines, `compile_condition`) | E1, E2-GE, P-GL |
| 0.15.0 (`954723c`, #243/#246) | | `opentide-exabeam` crate, tree-sitter-opentide-exabeam, `catalogs/exabeam/` (CIM fields and values, Apache-2.0), `rule`/`search` profiles, Exabeam block checks (`opentide-tide/src/exabeam.rs`, 766 lines) | E1, E2-GE, P-EX |
| 0.16.0 (`7402e15`, #245/#247) | | `opentide-yaral` crate, tree-sitter-opentide-yaral, `catalogs/yaral/` (UDM, functions), `LanguageId::Yaral`, Google SecOps sections as one injected rule (`opentide-tide/src/google_secops.rs`, 1,264 lines), hunts as YARA-L searches, `catalogs/tz/zones.txt` | E1, E2-L, P-GS |

Changed existing crates (ls diff): `opentide-core/src/lib.rs` (+842: codes, `LineIndex`, `LanguageId`),
`opentide-lucene` (+391 lib, +575 graylog), `opentide-kql` (306), `opentide-spl`, `opentide-esql`,
`opentide-eql`, `opentide-cql`, `opentide-falco`, `opentide-highlight`, `opentide-syntax`,
`opentide-analysis` (lib +88, `yara.rs`, `config.rs`, `ecs.rs`), `opentide-lsp` (`handlers.rs` +205,
`session.rs`, `main.rs`), `opentide-tide/src/{lib,injection,intel,refs}.rs`, `Cargo.toml`
(3 members, `rust-version = "1.95"`), `fuzz/` (3 targets), `editors/{nvim,helix,zed}`,
`packages/lsp-client`, `highlights/`. integration's engine crates have **not** taken any of it: they
are at 0.12.0 plus integration's own work (opentide-tide `lib.rs` −2,229 lines, `lint.rs` removed,
`yaml.rs` added; opentide-lsp `session.rs` +825/−; `data/catalogs/tide/schemas/*` regenerated
from Rust).

### 1.4 What integration already has

| Item | State on integration | Consequence |
|---|---|---|
| CQL in the editor and `opentide tui` (0.24.0 Added) | In since the 0.12.0 import (`3833048b`); integration goes further: `validate`/`lint` check CQL offline (#874, `192214de9`) | C1 is verification only. The CQL difference from the oracle stays approved after the move: 0.28.0's `validation/query_platforms.py` still says "CrowdStrike is never checked" |
| `crowdstrike_unsupported` retired | `crates/opentide-cli/src/explain.rs` `RETIRED` | none |
| Legacy external-id keys (#913) | `opentide-workspace/src/validate/objects.rs` reports `external_id_in_rule` from the node, without a vocabulary lookup; `opentide-schema/src/objects/platform/tests.rs::legacy_external_id_keys_are_superseded_by_external_id_in_rule` | F2 adds the text-id regression test and a golden case, probably no code |
| Typer pin (0.24.1) | No Typer: clap | F4: verify `setup ci <bad>` names the providers and the closest one |
| Diagnostics reference | `docs/cli/diagnostics.md` has **no generator** on integration (`render_diagnostics_docs.py` is gone; `scripts/build/README.md` still names it) | F3 adds one in Rust, with the MDX escaping |

### 1.5 Open PRs into development

**#1015** "Keep agent skills in step with releases; fix packaged skills, YARA warning pages, Elastic and Exabeam docs" (`claude/affectionate-pascal-9myyu3`, 23 files). Five commits:

| Part | Files | Treatment |
|---|---|---|
| `docs(agents)`: companion PR on opentidehq/skills in the definition of done; release-management Step 5 | `AGENTS.md`, `.agents/skills/{release-management,review-checklist}/SKILL.md` | Take on integration (X2): non-Python, but integration's `AGENTS.md` is restructured, so apply by hand |
| `fix(setup)`: frontmatter on the 4 packaged authoring skills; a packaged slug the catalogue lists installs the catalogue's copy (partly reverses #405) | `cli/services/setup/{skills,skills_registry}.py`, `data/setup/skills/authoring/*/SKILL.md` | Port (X2): `crates/opentide-cli/src/commands/setup/` skills install; the SKILL.md frontmatter is data and comes as is. Changes the `skills/*` cassettes (it fetches the catalogue's `detection-engineering`) |
| `fix(explain)`: warning wording for `yara_module_unconfirmed`, `yara_entrypoint_deprecated`, `yara_slow_pattern`, `yara_suspicious_expression` (`YARA_WARNING_CODES`) | `cli/services/explain.py`, `analysis.py`, `docs/cli/diagnostics.md` | Port (X2): `crates/opentide-cli/src/explain.rs`, from the engine's severity (`opentide-yara` `check.rs`) rather than a second list |
| `docs(elastic)`: `validate query --live` previews write alerts | `AGENTS.md`, `docs/cli/validate.md` | Take (X2) |
| `test(exabeam)`: `network-session` in the sequence fixture | `tests/fixtures/exabeam/rule-exabeam-sequence-1.0.*` | Take with P-EX |

Recommendation: **land #1015 on development first** (it waits on opentidehq/skills#37) so the
next `git merge origin/development` brings its non-Python files, and port its three code fixes as
X2. If a 0.28.1 is released with it, make the oracle 0.28.1 instead of 0.28.0 (§4.1): its fixes then
need no ledger entries.

**#993** "feat(mcp): tool annotations and interactive MCP Apps views" (`claude/beautiful-cray-yukamq`, 12 files: `mcp_server/{server,ui}.py`, `mcp_server/views/view.html` 736 lines, `docs/mcp/{index,tools,views,meta}`, 3 test files).

Recommendation: **do not merge it into development; port it to integration (X3)**. It is all
Python MCP server code plus one static page, development will not release from that server for
long, and the oracle (0.28.0) will not contain it in any case. In Rust: `rmcp` already models
`ToolAnnotations` (title, `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) in
`crates/opentide-cli/src/mcp/tools.rs`; the views are a `ui://` resource in
`crates/opentide-cli/src/mcp/resources.rs` serving `view.html` (move it under
`crates/opentide-cli/data/mcp/views/`, `include_str!`), and `_meta.ui.resourceUri` on `coverage`,
`validation_report` and `get_chaining`. Its differences from the recorded MCP sessions are
`json-extend:` ledger entries in `tests/golden/APPROVED_DIFFS.toml` (command `mcp start`). Close #993
with a pointer to the port.

### 1.6 Out of scope, noted

- opentidehq/specifications `main` is 21 commits ahead of the lock (`9e2e980740c8`), including a vocabulary ingest (`f51b8e2bdd`) and **platform-google-secops 1.3** (`9e2e980`, #91: a keyword-derived rule name takes the `r_` prefix), which 0.28.0 does not implement. Neither branch synced the vocabulary (#866 is open on development). Port 1.3 after the oracle move, as a ledgered difference.
- specifications#92 (language-exabeam 1.1, `exabeam_unknown_value`) and language-server#248 are open; not in 0.28.0.
- The bench baseline (`tests/bench/oracle-requirements.txt`, `budgets.toml`) measures opentide 0.23.0's Python; leave it alone in this plan. Moving it is a CI-recorded change of its own (`xtask/AGENTS.md`, bench).

---

## 2. Mapping onto the Rust workspace

### 2.1 Where a platform lives (Sysdig and HarfangLab as the model)

A built-in platform on integration spans these places. The line numbers mark the hard-coded platform
lists R0 replaces (§5, R0).

| Crate | Files |
|---|---|
| `opentide-core` | `codes` (`codes::ALL`, `codes::describe`; each code needs a section in `docs/cli/diagnostics.md`, `tests/diagnostics_docs.rs`); shared term tables (`src/falco.rs` is Sysdig's) |
| `opentide-schema` | `src/objects/platform/<p>.rs` (the model and its `NamedCheck`, e.g. `sysdig::block_codes` as `sysdig_rule_shape`), `objects/platform/mod.rs` (`registered()` ~l.255, `PlatformConfig` ~l.569, the parse match ~l.620, `LEGACY_KEYS`, `NAMED_CHECKS`), `objects/rule.rs` (~l.91), `objects/platform/schema.rs`, `configuration/models.rs` (tenant models, list ~l.1112), `configuration/bundled.rs`, `configuration/checks.rs`, `generate/{models,configuration}.rs`, `python.rs`, `tests/oracle/{platform_cases.toml,objects_table.json,config_table.json,configuration_schemas.json}` |
| `opentide-workspace` | `src/info.rs` (`platform(...)` ~l.62), `src/state.rs` (id kinds, `INTEGER_ID_PLATFORMS` ~l.40), `src/validate/objects.rs` (~l.27; workspace checks such as name duplicates), `src/validate/states.rs`, `src/lint/mod.rs` (advisories) |
| `opentide-compile` | `src/<p>.rs` (request bodies), `src/plan.rs` (~l.21, l.34), `src/preview.rs` (`config_dump` ~l.48), `src/dry_run.rs`, `src/modifiers.rs`, `src/ci/mod.rs` (~l.86), `src/generate/docs/catalog.rs` (labels) |
| `opentide-connectors` | `src/<p>.rs` (client, deploy, query, live check), `src/lib.rs` (~l.181), `src/connector.rs`, `src/plugin.rs` (built-in names ~l.86), `src/tenant.rs`, `src/credentials.rs`, `src/retry.rs`; `tests/<p>.rs` against the cassette |
| `opentide-tide`, `opentide-analysis` | Editor: query injection (`injection.rs`), block walkers, completion and hover; language routing |
| `opentide-cli` | `src/app.rs` (clap choices ~l.1204), `commands/{deploy_send,deploy_state (~l.24),doctor (~l.56),new (~l.76) and new/,query (~l.46, l.58),query_rule,validate_query (~l.54, LIVE_QUERY_PLATFORMS),validate_live,completion/}.rs`, `commands/setup/{files (~l.237),wizard (~l.76)}.rs`, `src/queries.rs` (`QUERY_FILE_SUFFIXES`), `src/explain.rs`, `src/mcp/{catalog (~l.607),queries (~l.23),resources}.rs`, `src/tree.rs`, `src/usage.rs`, `data/mcp/manifest.json`, `src/tui/configuration.rs` |
| `opentide` (facade), bindings | `crates/opentide/src/connectors.rs` (capabilities); `bindings/python` (the PyO3 classes behind `src/opentide/models/platform.py` and `__init__.py`; `cargo xtask stubs`); `bindings/node/src/tenants.rs` (capabilities), `index.d.ts` |
| `xtask` | `src/corpus/{generate (~l.1261),vocab (~l.12),structural}.rs`, `src/payloads/{probe.py (~l.57),plan.rs}`, `src/schema/probe.py`, `src/spec_fields.rs` |
| Data and generated | `src/opentide/data/configurations/platforms/<p>.toml`, `src/opentide/data/diagnostics/<code>.md`, `src/opentide/schemas/data/platform_templates/<p>.template.yaml` and `data/catalogs/tide/schemas/*.json` (`cargo xtask codegen`) |
| Goldens | `tests/golden/cases.toml`, `tests/golden/fixtures/{live-tenants,deploy-tenants}/`, `tests/cassettes/<p>/{tenant.py,client.py}`, `tests/cassettes/scenarios.toml` (`<p>/deploy`, `<p>/query`, `<p>/validate`, `golden/deploy-<p>`, `golden/query-<p>`, `golden/validate-live-<p>`), `tests/golden/mcp/sessions.toml` |

The Python → Rust map for a platform package:

| development (Python) | integration (Rust) |
|---|---|
| `models/platform_configs.py`, `models/platform.py` (`<P>Config`), `models/platform_schema.py`, `models/rule.py` | `opentide-schema/src/objects/platform/<p>.rs`, `mod.rs`, `objects/rule.rs` |
| `platforms/<p>/constraints.py`, `checks.py`, `catalog.py`, `yaral.py` (block codes) | `opentide-schema` `NamedCheck` (`<p>_rule_shape` style) in `objects/platform/<p>.rs`; shared tables in `opentide-core` |
| `platforms/<p>/advisories.py`, `validation/<p>_advisories.py` | `opentide-workspace/src/lint/mod.rs` (and validate warnings) |
| `validation/<p>_names.py`, `graylog_titles.py`, `google_secops.py` (duplicates) | `opentide-workspace/src/validate/objects.rs` (workspace checks) |
| `validation/session.py`, `query_platforms.py`, `analysis.py` | `opentide-cli/src/queries.rs`, `commands/validate_query.rs`, `opentide-analysis` routing |
| `models/configuration/platforms.py`, `models/system_config.py`, `platforms/config.py` | `opentide-schema/src/configuration/{models,bundled,checks}.rs` |
| `platforms/<p>/compile.py` | `opentide-compile/src/<p>.rs` |
| `deployment/preview.py`, `deployment/planning.py` | `opentide-compile/src/{preview,plan,dry_run}.rs` |
| `platforms/<p>/client.py`, `deployer.py`, `runner.py`, `validator.py` | `opentide-connectors/src/<p>.rs` (and `<p>/` modules when large) |
| `states/deployment.py` | `opentide-workspace/src/state.rs`, `validate/states.rs`, `opentide-cli/src/commands/deploy_state.rs` |
| `query/{rules,runner,service}.py` | `opentide-cli/src/commands/{query,query_rule}.rs` |
| `cli/services/{new,doctor,setup/platforms,deploy,deploy_plan}.py`, `cli/{enums,completion,setup_app}.py`, `cli/ui/**` | `opentide-cli/src/commands/**`, `src/app.rs`, `src/render/**` |
| `mcp_server/tools.py` | `opentide-cli/src/mcp/{queries,tools}.rs` |
| `documentation/**`, `vulnerability_lookup.py` | `opentide-compile/src/generate/docs/**`, `opentide-connectors/src/vulnerability.rs` |

### 2.2 Per unit

| Unit | Crates and modules | Specifications | Engine |
|---|---|---|---|
| **H1** HarfangLab YARA, #899 | `opentide-schema/src/objects/platform/harfanglab.rs` (`yara.signature`, one-kind rule `harfanglab_rule_kind`, `harfanglab_yara_form`, `_section_header`, `_import`, `_rule_name`, `yara_signature_alias`, `yara_include`, `yara_empty_signature`, `yara_duplicate_rule`); a shared **decomposed-YARA assembly** (Python `deployed_signature`/`compile_yara_deployment`, ls `opentide-tide/src/yara.rs` "deploy-exact" assembly) in `opentide-schema` so `opentide-compile/src/harfanglab.rs` (deploy) and `opentide-tide` (editor injection) use one copy; `opentide-workspace/src/lint/mod.rs` (`yara_meta_missing`, `harfanglab_yara_context`); `opentide-cli/src/queries.rs` (harfanglab → `yara`; `.yar`, `.yara`), `commands/validate_query.rs`, `mcp/queries.rs`; template regenerated | harfanglab-1.0 rev 1.2 (one kind) and 1.3 (context lists, 128-character name); yara-1.0 as ls 0.16.0 implements it (spec rev 1.3–1.5) | E1 (`opentide-yara`), E2-Y (injection) |
| **P-BD** Bitdefender | as §2.1; `opentide-core` (criteria terms) or `opentide-schema` reading **one** criteria catalogue `data/catalogs/bitdefender/criteria.toml` (drop `src/opentide/data/bitdefender/`); `opentide-connectors/src/bitdefender.rs` (JSON-RPC Incidents API, pacing per API key); `opentide-compile/src/bitdefender.rs` (`compile_rule`, `resolve_targets`, `create_params`, `update_params`, `delete_params`, `request_body`); dry run resolving targets against the first tenant | bitdefender-1.0 rev 1.1 as 0.28.0 implements it (blank target alias is `bitdefender_targets_shape`); specs main is at rev 1.4: diff it, port only 0.28.0's behaviour now | E1 (`bitdefender` YARA profile in `opentide-yara`), E2-Y |
| **P-GL** Graylog | as §2.1; `opentide-compile/src/graylog.rs` (`compile_definition`, bodies per server version 6.3/7.0/7.1/7.2, `derive_*`), `opentide-connectors/src/graylog.rs` (`/api/system`, `/api/events/definitions`, `/api/search/validate`, `/api/search/messages`); condition grammar and Quartz cron once (ls `graylog.rs` `compile_condition` and its Quartz reader are already Rust: move them to `opentide-core` or `opentide-schema`); IANA zones from `jiff`'s tz database or ls `catalogs/tz/zones.txt`; `graylog_all_streams` needs tenants (lint, `opentide-workspace` with configuration) | graylog-1.0 as 0.26.0 implements it; ls 0.14.0 follows platform-graylog 1.1 clarifications (specs #86): note each difference | E1 (Lucene `graylog` dialect), E2-GE |
| **P-EX** Exabeam | as §2.1; `opentide-compile/src/exabeam.rs` (`compile_rule`, `create_request`, `search_body`), `opentide-connectors/src/exabeam.rs` (`/auth/v1/token` OAuth client credentials, `/correlation-rules/v2/rules`, `/search/v2/events`, pacing 100/min across tenants, name check before create, `exabeam_name_conflict`) | exabeam-1.0 (RFC 0018), language exabeam-1.0 | E1 (`opentide-exabeam`), E2-GE |
| **P-GS** Google SecOps | as §2.1; the **assembled rule** (Python `compile.assemble`/`AssembledRule`, `SectionPlace`, `Location`; ls `google_secops.rs` section line map) once, in `opentide-schema`, used by `opentide-compile/src/google_secops.rs` (deploy, meta derivation), `opentide-tide` (injection) and the live check's `locate` (Python `diagnostics.py`); `opentide-connectors/src/google_secops.rs` (`:verifyRuleText`, rules, `rules/{id}/deployment`, archive, `:udmSearch`, Retry-After/`RetryInfo` then 5/15/60 s, no create resend after 5xx); OAuth 2.0 for service-account keys and ADC with quota project | google-secops-1.0 rev 1.2 (0.28.0); yara-l-1.0 rev 1.1; rev 1.3 (#91) after the move | E1 (`opentide-yaral`), E2-L |
| **C1** CQL editor/TUI | none (verify) | none | in since 0.12.0 |
| **D1–D3** Docs redesign | `opentide-compile/src/generate/docs/{mod,render,catalog,mermaid,vocab,cve,flavor}.rs` and `templates/*.md.j2` (minijinja), `opentide-connectors/src/vulnerability.rs` (EPSS, CVSS, KEV, CWE), `opentide-workspace` (deployment facts: `tenant_skip_reason` as one function shared with `opentide-compile/src/plan.rs`) | none | none |
| **F1** Splunk `advanced` | `opentide-schema/src/objects/platform/splunk.rs` (`advanced` table of scalars, not deprecated, out of completion), `opentide-compile/src/splunk.rs` (each key over block values, under modifiers; `null` → empty, bool → `1`/`0`, list/table refused), `preview.rs` dump | splunk-1.0 as 0.24.0 | catalog generated from the model |
| **F2** legacy external-id text values | `opentide-workspace/src/validate/objects.rs` (test) | none | none |
| **F3** diagnostics reference | new `cargo xtask docs diagnostics [--check]` (or a test in `opentide-cli`) rendering `docs/cli/diagnostics.md` from `opentide_cli::explain`, with the MDX escaping of `_mdx_prose` | none | none |

### 2.3 Engine: what is already in integration's engine crates

None of 0.12.1–0.16.0. Check:

```bash
git -C <ls-clone> diff --stat b92fa305296d0866d99e68081d9138313a535216 v0.16.0 -- crates   # 1040 files, +220,934/−6,193 in the whole tree
git ls-tree --name-only origin/integration/unified-core crates/ | grep -E 'yara|exabeam'    # nothing
```

The new crates are foundation tier 2 in `xtask/layers.toml` (beside `opentide-cql`): they depend on
`opentide-core`, `-syntax`, `-highlight`, and `yara-x-parser`, `yara-x-fmt` (yara) or `regex-syntax`
(yaral, exabeam).

---

## 3. Merge mechanics

### 3.1 Recommendation: one early merge commit (M0), features ported after

Integration must contain development's history, by merge, never rebase or force-push. Merging is
all-or-nothing for history: whichever commit first has `origin/development` as a parent carries the
whole 142-commit merge and all 154 conflicts. If "each port PR merges development", the first port
PR to land carries that merge anyway, and parallel port PRs each resolve the same conflicts
differently. So: **one merge commit, M0, early, on its own PR**, whose resolution keeps integration
behaving exactly as it does now (golden check against 0.23.0 still green), and records every
development change it does not apply in a manifest that the port units work down.

M0's resolution rule:

| Paths | Resolution |
|---|---|
| Every Python file of the old implementation (`src/opentide/{cli,platforms,validation,deployment,documentation,mcp_server,query,loading,states,models/configuration}/**`, `src/opentide/vulnerability_lookup.py`, `src/opentide/_native.pyi`) and `analysis/` | Deleted (as integration has them): 98 modify/delete conflicts resolved by `git rm`, 54 added `.py` files dropped |
| Python tests of the old implementation (`tests/test_{cli,platforms,validation,documentation,deployment,query,loading,models,lsp,mcp,vulnerability_lookup}/**`) | Deleted / dropped |
| `src/opentide/{models/platform.py, models/platform_configs.py, models/rule.py, analysis.py}` (content conflicts) | Integration's version (Rust classes); the new classes come with each P-unit |
| `pyproject.toml`, `uv.lock` | Integration's version (no Typer, no google-auth, no entry points) |
| `.github/workflows/ci.yml`, `scripts/ci-local.sh`, `.agents/skills/uv/SKILL.md`, `AGENTS.md` | Integration's version (the Bitdefender catalogue check is superseded; the matrix is X1) |
| History and process files (allowlist below) | development's changes taken |
| Everything else development changed (data, fixtures, templates, docs pages, corpus) | Integration's version **now**; listed in the manifest with the unit that takes it |

The allowlist M0 takes from development:

- `.github/release-notes/v0.24.0.md` … `v0.28.0.md` (added), `v0.23.0.md` (headline)
- `CHANGELOG.md`: integration's `[Unreleased]`, then development's `[0.28.0]` … `[0.24.0]`, then `[0.23.0]` onward, plus the footer compare links
- `docs/usage/releases.md` (the release history page; keep integration's version claims elsewhere)
- `.agents/skills/release-notes/SKILL.md`, `.agents/skills/release-management/SKILL.md`, `.agents/skills/docs-maintenance/SKILL.md` (clean merges; check them against integration's release-train text)
- `docs/internal/unified-core.md` and its entry in `docs/internal/meta.json` (integration's `AGENTS.md` links to the plan on the `docs/unified-core-plan` branch: point it here)
- `scripts/build/check_docs_mdx.py`, the `scripts/validate-docs.sh` hook, the `docs.yml` path triggers, `tests/test_docs/test_docs_mdx.py`, **if** `scripts/validate-docs.sh` passes on integration's docs; otherwise F3 takes them

Why not take the data and docs now: each of them changes what CI checks on integration before the
Rust code exists.

- The 130 explain pages: `opentide explain`'s list and MCP `explain` change, so golden cases differ.
- Platform templates: `cargo xtask codegen --check` fails on templates Rust does not generate, and on the HarfangLab template's two new lines.
- Platform TOMLs and `configuration_schemas`: these are the configuration router.
- `detection-workflow/SKILL.md` is installed by `setup skills`.
- Corpus rules and TOMLs: every `tide-corpus` golden case changes.
- Feature docs: `tests/test_docs/test_docs_commands_golden.py` resolves every documented invocation, such as `opentide setup platforms --bitdefender`, against the Rust command tree.

Recipe (in a worktree; `git switch -c chore/merge-development-0.28 origin/integration/unified-core`):

```bash
git merge --no-ff --no-commit 3acbea603112e71cc31e3ee1c4285a2b06fa29d3     # v0.28.0
# 1. Integration's side for everything integration has; drop what only development added
git status --porcelain | awk '$1=="DU"{print $2}' | xargs git rm -q --            # 98 deleted-in-HEAD paths
git diff --cached --name-only --diff-filter=A | grep -vxF -f allowlist.txt | xargs git rm -q --cached --
git checkout HEAD -- $(git diff --name-only HEAD | grep -vxF -f allowlist.txt)    # UU and clean M back to ours
# 2. The allowlist: keep the merge's result, hand-resolve CHANGELOG.md, docs/internal/meta.json, docs.yml
# 3. Write the manifest (below), run scripts/ci-local.sh --full and cargo xtask golden check --engine rust
git commit                                                                         # a merge commit: two parents
```

The manifest (`docs/internal/catchup-0.28.md`, removed by O2 when empty) lists, for every path
`git diff --name-only f41fe5e5c 3acbea603` returns that is not deleted Python and not on the
allowlist, the unit that brings it. Each port PR takes its paths with
`git checkout 3acbea603 -- <path>` (or edits them into shape) and deletes its rows. The train
(§4) is mergeable only when this check prints nothing but superseded paths:

```bash
git diff --name-only f41fe5e5c 3acbea603 -- . ':!*.py' ':!analysis' ':!tests/test_*' \
  | while read -r p; do git diff --quiet 3acbea603 HEAD -- "$p" || echo "$p"; done
```

Later merges of development (for #1015, a 0.28.x, anything else) are ordinary
`git merge origin/development`. They bring only post-M0 changes. A path M0 kept at integration's
version merges cleanly unless development changes it again, in which case the conflict is resolved
the same way.

### 3.2 Conflicts of `git merge origin/development` into integration

Run in `/home/user/wt/plan-merge` (detached at `4d998ba14`, `git merge --no-commit --no-ff origin/development`, then `git merge --abort`; worktree removed).

**Content conflicts (UU), 24:**

```
.agents/skills/uv/SKILL.md            docs/cli/validate.md                     docs/usage/installation.md
.github/workflows/ci.yml              docs/index.md                            pyproject.toml
.github/workflows/docs.yml            docs/internal/meta.json                  scripts/ci-local.sh
AGENTS.md                             docs/mcp/configuration.md                src/opentide/analysis.py
CHANGELOG.md                          docs/sdk/platforms.md                    src/opentide/models/platform.py
docs/cli/diagnostics.md               docs/usage/concepts/deployment-state.md  src/opentide/models/platform_configs.py
docs/cli/explain.md                   docs/usage/concepts/platforms.md         src/opentide/models/rule.py
docs/cli/lsp.md                                                                tests/test_package/test_public_api.py
                                                                               uv.lock
```

**Modified on development, deleted on integration (DU), 98:**

- `analysis/Cargo.lock`, `analysis/Cargo.toml`, `src/opentide/_native.pyi`
- `src/opentide/cli/`: `commands/{query,validate}.py`, `completion.py`, `enums.py`, `setup_app.py`, `services/{deploy,deploy_plan,doctor,explain,lint,new,validation,setup/platforms}.py`, `ui/diagnostics.py`, `ui/results/{catalogue,deploy}.py`
- `src/opentide/deployment/{planning,preview}.py`
- `src/opentide/documentation/`: `catalog.py`, `context.py`, `diagram/{__init__,builders,sanitize}.py`, `format/{azure_devops,github,gitlab,protocol}.py`, `markdown/links.py`, `objects/{base,objective,rule,threat}.py`, `parts/__init__.py`, `publish/index.py`, `vocabulary.py`
- `src/opentide/loading/platform_loader.py`, `src/opentide/mcp_server/tools.py`
- `src/opentide/models/{configuration/platforms,deployment_enums,platform_schema,system_config}.py`
- `src/opentide/platforms/{config,enabled,plugins}.py`, `platforms/harfanglab/deployer.py`, `platforms/splunk/deployer.py`, `platforms/sysdig/compile.py`
- `src/opentide/query/{rules,runner,service}.py`, `src/opentide/states/deployment.py`
- `src/opentide/validation/{compile_check,errors,query_platforms,session}.py`, `src/opentide/vulnerability_lookup.py`
- 39 test files: `tests/test_cli/e2e/{__snapshots__/test_info_e2e.ambr,test_analysis_engine_e2e,test_deploy_e2e,test_docs_rendering_e2e,test_info_catalog_e2e,test_info_e2e,test_validate_e2e}.py`, `tests/test_cli/{test_app,test_completion,test_enums,test_explain,test_flow_conformance,test_lint_platform_advisories,test_new,test_setup_cli}.py`, `tests/test_deployment/{__snapshots__/test_deploy_payloads.ambr,test_deploy_payloads.py}`, `tests/test_documentation/{__snapshots__/test_snapshots.ambr,_snapshot_helpers,test_diagram_builders,test_diagram_snapshots,test_formatters,test_links,test_object_renderers,test_publish_index,test_renderers,test_rule_status_facts}.py`, `tests/test_loading/{test_bundled_platform_templates,test_loader_validate_agree}.py`, `tests/test_lsp/test_lsp_catalog.py`, `tests/test_mcp/test_tools_query.py`, `tests/test_models/{test_platform,test_platform_query_contract,test_spec_field_descriptions}.py`, `tests/test_platforms/{test_capabilities,test_splunk_deployer}.py`, `tests/test_query/test_query_core.py`, `tests/test_validation/test_errors.py`, `tests/test_vulnerability_lookup/test_client.py`

**Added on development (A, merge would add), 328:** 54 Python modules (`src/opentide/platforms/{bitdefender (7),graylog (8),exabeam (8),google_secops (10)}/`, `platforms/harfanglab/yara.py`, `validation/{yara_signature,bitdefender_names,bitdefender_advisories,graylog_titles,graylog_advisories,exabeam_names,exabeam_advisories,google_secops}.py`, `documentation/{facts (4),parts (4),markdown/{page,text},diagram/{mermaid,model}}.py`, plus `scripts/build/{check_bitdefender_catalogue,check_docs_mdx}.py`), 130 explain pages, 38 test modules, 87 fixture files (including the 4 corpus rules and TOMLs), the 4 platform TOMLs, `data/bitdefender/{criteria.toml,NOTICE}`, the 4 platform templates, 6 release notes, `docs/internal/unified-core.md`.

**Clean modifications (M), 32:** `.agents/skills/{docs-maintenance,release-management,release-notes}/SKILL.md`, `.github/release-notes/v0.23.0.md`, `README.md`, `docs/cli/{deploy,generate,index,info,new,query,setup}.md`, `docs/internal/cli-experience.md`, `docs/mcp/{index,installation,tools}.md`, `docs/sdk/{installation,models}.md`, `docs/usage/{index,quickstart,releases,troubleshooting,why-opentide}.md`, `docs/usage/workflows/{agentic-setup,ci-cd}.md`, `scripts/validate-docs.sh`, `src/opentide/data/setup/skills/detection-workflow/SKILL.md`, `src/opentide/schemas/data/platform_templates/harfanglab.template.yaml`, `tests/corpus_support.py`, `tests/fixtures/configuration_schemas/configurations.router.json`, `tests/fixtures/deployment/modifier_flatten_expected.json`, `tests/fixtures/generation/tide_workspace/.opentide/templates/rule.1.0.template.yaml`.

No conflict touches `crates/`, `bindings/`, `xtask/`, `tests/golden/` or `tests/cassettes/`. The
engine catch-up (E1) is a separate history merge (language-server's), not part of this one.

### 3.3 The engine import (E1) is a second, separate merge

Repeat `docs/engine/IMPORT.md` "Repeating it at a later commit" with
`sha=7402e1543c06bc30b2b50b812d3411da560ee4d4` (v0.16.0). The filtered history up to `b92fa305`
must reproduce the 0.12.0 run's tip `f0c19938` (the invocation is deterministic), so the merge
brings exactly the 116 new commits. Expect conflicts in `Cargo.toml`, `Cargo.lock`,
`rust-toolchain.toml`, `crates/opentide-{core,tide,analysis,lsp,syntax,highlight,kql,spl,esql,eql,lucene,cql,falco}/`,
`data/catalogs/tide/` (keep integration's generated files and regenerate with `cargo xtask codegen`),
`highlights/`, `editors/`, `packages/lsp-client/`, `fuzz/`, and `crates/CHANGELOG.md` (insert
0.12.1–0.16.0 below `[Unreleased]`). Add a row to IMPORT.md's "Imports since" table.

---

## 4. Golden oracle move (0.23.0 → 0.28.0)

### 4.1 Order

1. **Before any port: O1, preview tooling** (on integration). `cargo xtask golden record` gets
   `--oracle FILE` (an alternative `ORACLE`, e.g. `tests/golden/ORACLE.next` naming 0.28.0) and
   `--out DIR` (recordings outside `tests/golden/cases`, sharing the content-addressed `blobs/`
   format), and `golden check` gets `--recordings DIR`; `cassettes record` and `mcp record` take the
   same oracle file. Workers then judge their port against 0.28.0 locally
   (`golden record --oracle tests/golden/ORACLE.next --out target/golden-next --filter 'validate*/**'`
   then `golden check --engine rust --recordings target/golden-next --filter …`) without committing
   recordings.
2. **Ports on a train branch** `train/catchup-0.28`, cut from integration after M0, R0 and O1
   land. On the train, the `Golden compare` job is report-only (its failures are expected: the
   recordings are still 0.23.0's). Instead, each port PR posts its preview `golden check` summary for
   its area: zero differences, or each one explained. Each port adds its case **definitions**
   (`cases.toml`, fixture files, cassette scenarios with stand-in tenants and clients, MCP sessions),
   but no recordings. Merge `integration/unified-core` into the train regularly (merge, never rebase).
3. **Last on the train: O2, the oracle move**. Re-record everything from 0.28.0, so every case,
   including the new platforms', comes from 0.28.0. Then reconcile, and merge the train into
   integration with `Golden compare` gating again.

If a 0.28.1 with #1015 ships before O2, use it as the oracle instead (the same steps).

### 4.2 O2 steps

| Step | Command / file |
|---|---|
| Oracle | `tests/golden/ORACLE`: `tag = "v0.28.0"`, `commit = "3acbea603112e71cc31e3ee1c4285a2b06fa29d3"`, `version = "0.28.0"`, `wheel = "opentide-0.28.0-cp310-abi3-manylinux_2_28_x86_64.whl"`, `wheel_sha256 = "1700f673d17265420df7486c9685420c5733e1dcab4c413da8b5683b68e9624b"`, `exclude_newer` after 2026-11-12T17:43:13Z (0.28.0 adds `google-auth`), `python` kept unless 0.28.0 needs another |
| Lock | `cargo xtask golden lock` (rewrites `tests/golden/oracle-requirements.txt`); the same for `tests/corpora/oracle.in` / `oracle-requirements.txt` |
| Cassettes | `cargo xtask cassettes record --all` (the clients run the oracle's modules: `tests/cassettes/<p>/client.py` for every platform, new ones included), `cassettes check` |
| Goldens | `cargo xtask golden record --check-determinism` (all cases, the new platforms' with their cassettes) |
| MCP | `cargo xtask mcp record --python <0.28.0 venv>/bin/python` (0.28.0 still has the Python MCP server) |
| Oracle tables | Re-run `crates/opentide-schema/tests/oracle/{objects_table,config_table,configuration_schemas,from_node_table,yaml_table}.py`, `crates/opentide-compile/tests/ci/oracle.py`, `xtask/oracle/{config_resolve,registry_export}.py`, `xtask/src/{payloads,schema}/probe.py` with the 0.28.0 interpreter; extend `probe.py` and `platform_cases.toml` with the four platforms |
| Corpora | `cargo xtask corpus codes`, `corpus faults` against 0.28.0 (`tests/corpora/codes.toml`, `COVERAGE.md`, `KNOWN_GAPS.md`) |
| Since-oracle | `crates/opentide-cli/tests/common/since_oracle.rs`: rebase its list on 0.28.0's `opentide --json commands` (CQL stays) |
| Reconcile | `cargo xtask golden check --engine rust --report r.json`, `mcp replay`, `payloads`, `schema diff`, `config diff`, `registry diff`, `validate diff`, `lint diff`, `vocab diff`: each difference is fixed in Rust or approved in `APPROVED_DIFFS.toml` / `payloads/APPROVED.toml` / `vocab/APPROVED.toml` with a changelog entry; the ~1,168 existing ledger entries are re-checked, and every one that 0.28.0 makes stale is removed (the ledger's stale check enforces it) |
| Docs | `tests/golden/README.md` "The oracle" (`v0.28.0`, `3acbea60`), `.agents/skills/golden/SKILL.md`, `xtask/AGENTS.md`, `crates/opentide-cli/src/tree.rs` and other "0.23.0, the oracle" comments; `docs/internal/catchup-0.28.md` deleted |

The recordings budget is 128 MiB (`xtask/src/golden/coverage.rs` `BUDGET_BYTES`), with 68.8 MiB used.
Four platforms add cases, and the redesigned docs add bytes to every `generate` case. Check
`COVERAGE.md` after recording, and raise the budget in O2 if it is exceeded, stating the reason.

---

## 5. Work units

### 5.1 Overview

| Id | Unit | Size | Depends on | Branch |
|---|---|---|---|---|
| M0 | Merge development v0.28.0, allowlist resolution, manifest | M | — | integration |
| R0 | One platform registry (behaviour-neutral) | M | — | integration |
| O1 | Preview-oracle tooling | S | — | integration |
| E1 | Engine import at language-server v0.16.0 (language crates, Lucene dialect, editor features for files) | L | M0 (for docs/diagnostics sections) | train |
| E2-Y | YARA injection in HarfangLab and Bitdefender blocks | M | E1 | train |
| E2-GE | Graylog query and Exabeam sequence injection, hunts | M | E1 | train |
| E2-L | Google SecOps section injection (assembled rule), YARA-L hunts | L | E1 | train |
| H1 | HarfangLab YARA, the #899 breaking change | L | R0, E2-Y | train |
| P-BD | Bitdefender GravityZone | L | R0, E1, E2-Y, H1 | train |
| P-GL | Graylog | L | R0, E2-GE | train |
| P-EX | Exabeam | L | R0, E2-GE | train |
| P-GS | Google SecOps | L | R0, E2-L | train |
| C1 | CQL in editor/TUI: verify | S | E1 | train |
| F1 | Splunk `advanced` | S | — | train |
| F2 | Legacy external-id text values | S | — | train |
| F3 | Diagnostics reference generator, MDX escaping | S | — (E1 for its sections) | integration or train |
| F4 | `setup ci` invalid provider: verify | S | — | train |
| D1 | Docs pages: layout, facts, settings, deployment section | L | R0 | train |
| D2 | Docs diagrams: Mermaid model, kill-chain maps, ATT&CK coverage, catalogue overview | M | D1 | train |
| D3 | CVE details: CVSS, EPSS, KEV, CWE | M | D1 | train |
| X1 | Agent-facing docs: AGENTS.md matrix, skills, README, docs pages left in the manifest | S | all P-*, H1 | train |
| X2 | #1015 ports (packaged skills, YARA warning pages, docs) | S | #1015 merged on development; E1 | train (or integration after O2) |
| U-0.28.1 | development after v0.28.0: #1029 (notes, `--strict`, `--verbose`) and #1015's packaged skills | M | — | train (`feat/port-0.28.1`) |
| X3 | #993 port (MCP annotations, MCP Apps views) | M | — | integration after O2 |
| O2 | Oracle move, recording, reconciliation, train merge | L | every unit above but X3 | train |

Parallel lanes:

```
integration:  M0 ─┬─ R0 ─┬─ O1 ─┐                          (all three in parallel)
                  │      │      │
train:            └──────┴──────┴── E1 ──┬── E2-Y ── H1 ── P-BD
                                         ├── E2-GE ─┬─ P-GL
                                         │          └─ P-EX
                                         ├── E2-L ── P-GS
                                         └── C1
              F1, F2, F3, F4, U-0.28.1 (any time) ; D1 ── D2, D3 (from R0) ; X1 (after P-*) ; O2 last
after O2:     X3 (and X2 if #1015 lands late)
```

At peak, seven workers can run at once: YARA lane, Graylog, Exabeam, SecOps, docs, fixes, and one
of D2/D3. The P-units edit shared files: `docs/usage/concepts/platforms.md`, `app.rs`, `setup/files.rs`,
`cases.toml`, `scenarios.toml`, `tests/fixtures/tide_corpus/current/`. R0 shrinks those edits to one
row each. Merge P-units one at a time onto the train, and resolve the docs-page hunks by taking
development's final text for that platform.

### 5.2 Briefs

Every brief uses the same base:

- Branch from `train/catchup-0.28`, or from `integration/unified-core` where marked, and open the PR
  against that branch.
- Use a worktree with its own Cargo target pool (root `AGENTS.md`, "Parallel agents").
- Read `.agents/skills/{rust,rust-engine,golden,review-checklist}/SKILL.md`.
- Python behaviour comes from `git show 3acbea603:<path>`, and for U-0.28.1 from development's
  tip that M0 merged (`a15c78c73`). Port the data, not the formatting: use
  crates (clap, minijinja, serde_json, jiff, reqwest, regex) and never reproduce a Python library's
  layout byte for byte. Where only layout differs from 0.28.0, the difference is approved in the
  ledger at O2.
- Take your rows of `docs/internal/catchup-0.28.md`: the data, fixtures, explain pages and docs pages
  development added for your feature, from `3acbea603` (U-0.28.1: `a15c78c73`).
- Definition of done: `scripts/ci-local.sh --full` passes, plus `cargo xtask check-layers`,
  `cargo xtask codegen --check` and `cargo xtask stubs --check` where models changed. Every fix has a
  regression test. `CHANGELOG.md` `[Unreleased]` names only deliberate differences from 0.28.0.
- Post the preview golden summary against 0.28.0 for your filter (O1).

---

#### M0: merge development v0.28.0 into integration

- **Goal.** integration contains development's history through `3acbea603`. Its behaviour does not change.
- **Do.** §3.1 recipe and allowlist. Hand-resolve `CHANGELOG.md` (integration's `[Unreleased]` on top, then 0.28.0 … 0.24.0), `docs/internal/meta.json`, `.github/workflows/docs.yml`. Fix `AGENTS.md`'s link to the unified-core plan. Write `docs/internal/catchup-0.28.md`: one row per deferred path with its unit, the "superseded" paths (`scripts/build/check_bitdefender_catalogue.py`, the `ci.yml` step, `pyproject.toml`, `uv.lock`), and the check command of §3.1.
- **Tests.** No new tests. `cargo xtask golden check --engine rust`, `mcp replay`, `codegen --check` and `pytest` are unchanged and green; `scripts/validate-docs.sh` passes with the MDX check.
- **Done.** A two-parent merge commit (never squash: the PR must merge with a merge commit or be pushed as one; ask the maintainer how train merges are made). `git merge-base --is-ancestor 3acbea603 HEAD` holds, and CI is green.

#### R0: one platform registry (integration)

- **Goal.** Adding a platform is one row plus its modules, not about 25 list edits.
- **Do.** Add `opentide_core::platform` (or `opentide_schema::platforms`): a `PLATFORMS` table with `id`, label, config class name, external-id kind (`Int` or text with its pattern), `deploys`, `live_check`, `query_runner`, offline languages and query-file suffixes. Replace the hard-coded lists of §2.1: `opentide-cli` `app.rs`, `deploy_state.rs` `INTEGER_ID_PLATFORMS`, `doctor.rs`, `new.rs`, `query.rs`, `setup/files.rs`, `setup/wizard.rs`, `validate_query.rs`, `mcp/{catalog,queries}.rs`; `opentide-compile` `plan.rs`, `preview.rs`, `ci/mod.rs`; `opentide-connectors` `lib.rs`, `plugin.rs`; `opentide-schema` `configuration/models.rs`, `objects/rule.rs`; `opentide-workspace` `info.rs`, `state.rs`, `validate/{objects,states}.rs`; `xtask/src/corpus/{generate,vocab}.rs`. Keep each list's order: the order is behaviour (help text, JSON arrays).
- **Tests.** A unit test that every table row appears in each consumer, plus the unchanged golden check.
- **Done.** `golden check --engine rust` green with no new ledger entries; `cargo xtask check-layers` green.

#### O1: preview-oracle tooling (integration)

- **Goal.** Port workers can compare with 0.28.0 before O2.
- **Do.** `xtask/src/golden/{mod,oracle}.rs`: `--oracle FILE` for `record`, `lock` (writing the requirements beside that file), `cassettes record` and `mcp record`; `--out DIR` for `record`; `--recordings DIR` for `check`/`diff`. Commit `tests/golden/ORACLE.next` (the §4.2 values) and its `oracle-requirements.next.txt`. A CI job on the train records the preview into a cache and uploads its `golden check` report as an artifact (non-gating).
- **Tests.** `xtask/tests/golden_compare.rs` cases for the three flags; `cargo nextest run -p xtask`.
- **Done.** `cargo xtask golden record --oracle tests/golden/ORACLE.next --out target/golden-next --filter 'explain/*'` works on Linux and leaves `tests/golden/` untouched.

#### E1: engine import at language-server v0.16.0 (train)

- **Goal.** The engine knows YARA, YARA-L, the Exabeam Query Language and the Lucene Graylog dialect as standalone languages, with history.
- **Do.**
  - Run `docs/engine/IMPORT.md`'s filter-repo invocation at `7402e154` and `git merge --no-ff` it (§3.3).
  - Take whole: `crates/opentide-{yara,yaral,exabeam}`, `grammars/tree-sitter-opentide-{yara,yaral,exabeam}`, `data/catalogs/{yara,yaral,exabeam,tz,bitdefender}`, `highlights/` (yara, yaral, exabeam TextMate grammars and queries), `editors/{nvim,helix,zed}`, `packages/lsp-client`, the fuzz targets, and the changes to `opentide-lucene` (`graylog.rs`), `opentide-core` (codes, `LanguageId::{Yara,Yaral,Exabeam}`, `LineIndex` #238), `-kql`, `-spl`, `-esql`, `-eql`, `-cql`, `-falco`, `-highlight` and `-syntax`, merged onto integration's versions of those crates.
  - In `opentide-analysis` and `opentide-lsp`, take the per-language routing and file features: `.yar`/`.yara`, `.yaral`/`.yl2`, `.exabeam`; YARA rename and formatting (`yara-x-fmt`); `renameProvider`, `documentFormattingProvider`; signature help.
  - Leave out the Tide-block modules `opentide-tide/src/{bitdefender,graylog,exabeam,google_secops,yara,yaml_scalar}.rs` and their hunks in `opentide-tide/src/{lib,injection}.rs` (serde_yaml): delete them in the merge, record them in the manifest for E2-*, P-*, H1. They stay in history.
  - Place the three crates in `xtask/layers.toml` (foundation tier 2, and say why). Apply the workspace lints. Set `rust-version = "1.95"` (keep integration's toolchain pin, 1.99.1). Keep the workspace version (the release train sets 1.0.0-rc.1).
  - Licences: YARA-X and libyara BSD-3-Clause, the Exabeam catalog Apache-2.0, tz. Update `NOTICE`, `about.toml`, `deny.toml` (`cargo deny check`).
  - Codes: every new code in `opentide_core::codes` and a section in `docs/cli/diagnostics.md` (take development's sections for these codes from `3acbea603:docs/cli/diagnostics.md`).
  - Add the 0.12.1–0.16.0 sections to `crates/CHANGELOG.md`, a row to `docs/engine/IMPORT.md`, and `.agents/skills/uv/SKILL.md` Rust 1.95.
- **Tests.** The imported crates' own tests (`crates/opentide-yara/tests`, yaral, exabeam; `opentide-lucene/tests/graylog_verdicts.rs`; the conformance corpora under `crates/testdata/conformance/{yara-x,external/yara,external/yaral,exabeam,…}` and `crates/testdata/oracles/graylog/`); `opentide-lsp/tests/e2e_stdio.rs` for `.yar` hover and rename; `fuzz` smoke; `cargo xtask lsp parity`.
- **Golden.** None committed. Engine codes show up in `explain`, so expect report-only differences.
- **Done.** `cargo nextest run --workspace --profile ci` green, `cargo xtask check-layers` green, no `serde_yaml` in any `Cargo.toml` (#850), and `docs/engine/IMPORT.md` updated.

#### E2-Y: YARA in HarfangLab and Bitdefender blocks (train)

- **Goal.** The editor, `opentide tui` and the `queries` check analyse `configurations.{harfanglab,bitdefender}.yara.signature` under each platform's profile, and HarfangLab's decomposed `strings`, `condition` and `imports` as the one rule deploy assembles, with each finding placed where it is written.
- **Do.** Port ls `opentide-tide/src/yara.rs` (the `signature` injection and the decomposed assembly with its line map) onto `opentide_core::node` (`opentide-tide/src/yaml.rs`). The assembly itself is H1's shared function in `opentide-schema`; until H1 lands, keep it in `opentide-tide` behind one function H1 moves. Wire `opentide-analysis` and `opentide-cli/src/queries.rs` so harfanglab → `yara` (profile `harfanglab`) and bitdefender → `yara` (profile `bitdefender`). Block constraint codes are **not** here (H1, P-BD).
- **Tests.** ls `opentide-tide/tests/yara.rs` (717 lines) and `large_injection.rs` (the 1 MB signature in about 1 s), ported to `Node`; `opentide-analysis/tests/tide_corpus.rs`.
- **Done.** A `.yaml` rule with a broken `yara.signature` gets `yara_parse_error` at the right line in `opentide lsp start` and in `opentide validate`'s `queries` check.

#### E2-GE: Graylog and Exabeam queries in blocks and hunts (train)

- **Goal.** `configurations.graylog.query` and `system: graylog` hunts are checked as Lucene in the Graylog dialect; `configurations.exabeam.sequences[].query` under the `rule` profile; `system: exabeam` hunts under `search`.
- **Do.** The injection rows in `opentide-tide/src/injection.rs`. Graylog's `graylog_leading_wildcard` depends on the tenants (`allow_leading_wildcard`): the editor always reports it, `validate` drops it when every targeted tenant allows it (0.26.0). Aggregation-function completion and hover for `aggregation.condition` come from ls `graylog.rs`, on `Node`.
- **Tests.** ls `opentide-analysis/tests/{graylog,external_exabeam}.rs`, `opentide-tide/tests/{graylog_spec,exabeam_spec}.rs` (the injection parts).
- **Done.** Graylog and Exabeam rules in `crates/testdata/` get the language codes in the editor and the `queries` check.

#### E2-L: Google SecOps sections and YARA-L hunts (train)

- **Goal.** `setup`, `events`, `outcome`, `condition`, `export` (text) and `match`, `options` (YAML) are analysed as the one rule deploy assembles, with generated text (header, meta, labels, rendered `match`/`options`) marked synthetic. `system: google_secops` hunts are checked as YARA-L searches.
- **Do.** Port ls `opentide-tide/src/google_secops.rs` onto `Node`. The assembly and section line map are P-GS's shared function in `opentide-schema`, the same function deploy and `verifyRuleText` locating use: build it here and let P-GS extend it. A `condition: #e > 0` plain scalar loads as null: report `yaral_section_empty` with that reason.
- **Tests.** ls `opentide-tide/tests/google_secops.rs` (439 lines), `crates/testdata/corpus/yaral`, Google's examples under `crates/testdata/conformance/google-yaral/`.
- **Done.** The section texts of `tests/fixtures/google_secops/rule-google-secops-{process,spray}-1.0.yaml` (from `3acbea603`) get findings on their own YAML lines.

#### H1: HarfangLab YARA and the #899 breaking change (train)

- **Goal.** 0.25.0's HarfangLab behaviour (`b1625411a`).
- **Do.**
  - Model, in `opentide-schema/src/objects/platform/harfanglab.rs`: `yara.signature`; one kind per block (`harfanglab_rule_kind`); `harfanglab_yara_form`, `_section_header`, `_import`, `_rule_name` (keyword, non-ASCII, longer than 128); `yara_signature_alias` (a signature written as a YAML alias: the node loader keeps aliases, so check the node); `yara_include`, `yara_empty_signature`, `yara_duplicate_rule`, as a `NamedCheck`.
  - Move the decomposed assembly here as the one function used by `opentide-compile/src/harfanglab.rs` and `opentide-tide`. Port Python `platforms/harfanglab/yara.py` (`deployed_signature`, `derived_rule_name`, `rule_name_problem`, `decomposed_context`, `signature_codes`).
  - Deploy: a signature is sent verbatim as the YaraFile `content`, with `\n` line endings and one trailing newline. Same endpoint, payload, name and identity by `metadata.uuid` as the decomposed form.
  - Lint (`opentide-workspace/src/lint/mod.rs`): `yara_meta_missing`, `harfanglab_yara_context` (comma-joined `file`, `memory`, `file.pe`, `file.elf`, `file.macho`; `meta.context: []` deploys none). Reported even when the engine does not load, and never fail validate.
  - `validate`: report a YARA language code once, at the engine's place (`d048b6a85`); `--queries warn` keeps the model's YARA error (`ae9a92dfa`).
  - `validate query --platform harfanglab` and `.yar`/`.yara` files offline; `--live` → `supported: false`. MCP `validate_query`.
  - Explain pages `harfanglab_yara_context`, `yara_meta_missing`, `yara_signature_alias`. Regenerate the HarfangLab template (`cargo xtask codegen`). Docs `cli/{validate,lsp}.md`, `usage/concepts/platforms.md` (HarfangLab section), `docs/cli/diagnostics.md`.
- **Tests.** Port the cases of `3acbea603:tests/test_platforms/test_harfanglab_yara.py` and its snapshot `tests/test_platforms/__snapshots__/test_harfanglab_yara.ambr` (deploy payloads); `tests/fixtures/harfanglab/{harfanglab-sigma,harfanglab-yara,harfanglab-yara-signature}.yaml` and `invalid/` (4) as `opentide-schema/tests/oracle/platform_cases.toml` cases; `tests/test_cli/e2e/test_harfanglab_yara_e2e.py` as `opentide-cli` integration tests.
- **Golden cases (definitions).** `validate` on a fixture with a both-kinds block (the breaking change), `validate query --platform harfanglab --file x.yar`, `lint` on a block without `context`, `deploy --dry-run` of a `yara.signature` rule, the `harfanglab/deploy` cassette client extended with a signature rule, MCP `validate_query` on harfanglab.
- **Done.** The block a `sigma` + `yara` rule had in 0.23.0 now fails with `harfanglab_rule_kind` at its field path, and the deployed YaraFile content equals 0.28.0's for both forms.

#### P-BD: Bitdefender GravityZone (train)

- **Goal.** 0.25.0's Bitdefender platform (`73ce1e90b`, `834bda36b`).
- **Do.**
  - §2.1 checklist with R0's row: `bitdefender`, label "Bitdefender GravityZone", 24-hex text id, deploys, no live check, no query runner, offline `yara` (profile `bitdefender`).
  - Model `BitdefenderConfig` and the `bitdefender_*` codes as one `NamedCheck`: `bitdefender_rule_kind`, `_target`, `_criterion_shape`, `_criterion_relation`, `_criterion_value`, `_criteria_combination`, `_action_scope`, `_targets_shape`, `_severity`, `_criterion_field` (error, or warning on XDR targets), `_yara_ascii`, `_yara_size` (30,000). These read **one** criteria catalogue: `data/catalogs/bitdefender/criteria.toml`, the same file ls's editor completion reads.
  - Workspace check `bitdefender_name_duplicate`. Advisories `bitdefender_registry_full_hive`, `_contains_no_wildcard`, `_severity_collapsed` in validate (warn) and lint. YARA `yara_include`, `yara_empty_signature`, `yara_duplicate_rule`, `yara_signature_alias` (H1's), and lint `yara_module_unconfirmed`.
  - Compile (`opentide-compile/src/bitdefender.rs`): `gravityzone_name`, `derive_description`, `derive_severity`, `derive_tags`, `automatic_actions`, `derive_settings`, `resolve_targets`, `create_params`, `update_params` (always the whole payload), `delete_params`, `request_body`.
  - Dry run: the `createCustomRule` request resolved against the first tenant, or the unresolved targets named.
  - Connector: JSON-RPC Incidents API, API key, pacing keyed by the key itself (`8651a1312`), the name-conflict retry, exclusion rules (`type: 2`) never touched.
  - Tenant config (`src/opentide/data/configurations/platforms/bitdefender.toml`), `setup platforms --bitdefender`, `new rule --platform bitdefender` (scaffold with a severity, `d61d74370`), doctor, info, completion.
  - Python model class `BitdefenderConfig` (bindings, `src/opentide/models/{platform,__init__}.py`, `cargo xtask stubs`); node capabilities.
  - Editor walker: do not import ls `bitdefender.rs`'s constraint checks as a second implementation; take its criteria completion and hover only. Its 269-line `tests/bitdefender_spec.rs` becomes the model's test.
  - 28 `bitdefender_*` explain pages (26 from #902, `bitdefender_yara_ascii` and `_yara_size` from #923), docs (`usage/concepts/{platforms,deployment-state}.md`, `cli/{setup,new,deploy,info,validate,explain,query}.md`, `mcp/{configuration,installation}.md`, `sdk/{models,platforms}.md`).
- **Tests.**
  - `tests/fixtures/bitdefender/` from `3acbea603`: `rule-bitdefender-{detection,yara}-1.0.yaml` with their `*.create/update/disable.api.json` as compile snapshot tests, `invalid/` (4) as platform cases, `block-bitdefender.yaml`, `tenant.toml`.
  - The cases of `tests/test_platforms/test_bitdefender_{model,compile,deployer,advisories,setup}.py` and `tests/test_validation/test_yara_engine_dedupe.py`.
  - `opentide-connectors/tests/bitdefender.rs` against the new cassette.
- **Golden cases (definitions).** Corpus rule `rule-0014-bitdefender-gravityzone.yaml` and `Configurations/platforms/bitdefender.toml` in `tests/fixtures/tide_corpus/current/` (UUID `00000000-0000-4000-8003-0000b1d0f001`, `tests/corpus_support.py`). `setup platforms --bitdefender`. `new rule --platform bitdefender`. `validate query --platform bitdefender [--live]`. `deploy --dry-run --platform bitdefender`. A `deploy-tenants` stand-in tenant (`tests/cassettes/bitdefender/tenant.py`, from the fake API in `test_bitdefender_deployer.py`) with create, update, disable and delete rules. Scenarios `bitdefender/deploy` and `golden/deploy-bitdefender`. `explain bitdefender_criterion_field`.
- **Done.** The Rust compile output equals every `*.api.json` fixture, and the preview golden check for `*bitdefender*` cases shows only explained differences.

#### P-GL: Graylog (train)

- **Goal.** 0.26.0's Graylog platform (`6e693286e`).
- **Do.**
  - §2.1 checklist. R0 row: `graylog`, 24-hex id, deploys, live check, query runner, offline `lucene` (dialect `graylog`).
  - Model `GraylogConfig`, and the `graylog_*` codes as one `NamedCheck` from Python `constraints.py` (`block_findings`, `parse_condition`, `cron_ok` Quartz, `timezone_ok`, `duration_ms`, nesting ≤ 32, comma-separated arguments). Reuse ls `graylog.rs`'s Rust parser, moved below `opentide-tide`.
  - Advisories `graylog_overlapping_window`, `graylog_all_streams` (only for a tenant with no streams, `c1caf746c`), `graylog_title_duplicate` (workspace).
  - Compile (`opentide-compile/src/graylog.rs`): `parse_version`, `is_vulnerable`, `compile_definition`, `create_body`/`update_body` per version 6.3, 7.0, 7.1 and 7.2, `derive_title`, `derive_priority`, `derive_field_spec`, `window_ms`, `stream_aliases`.
  - Connector: `/api/system` once per tenant, `/api/search/validate` before every save but a disable, `/api/events/definitions` CRUD, the unconfirmed non-JSON create (`071a1fd09`). The live check takes `ERROR` explanations with Graylog's line and column. `opentide query` uses `/api/search/messages`, with `--index` as stream aliases.
  - Setup, new, doctor, info, completion, bindings, 38 explain pages, docs.
- **Tests.** `tests/fixtures/graylog/` (aggregation and filter rules × versions `.api.json`, `invalid/` (4)), the cases of `tests/test_platforms/test_graylog_{model,compile,deployer,runner,advisories,setup}.py`, ls `tests/graylog_spec.rs` (123 lines) for the model, and `opentide-connectors/tests/graylog.rs`.
- **Golden cases (definitions).**
  - Corpus `rule-0015-graylog-event-definition.yaml` (UUID `…00000091a7e0`) and `graylog.toml`.
  - `live-tenants` and `deploy-tenants` stand-ins (`tests/cassettes/graylog/tenant.py`, which answers `/api/system` with a 7.2 version and one 6.3 tenant).
  - Scenarios `graylog/{deploy,query,validate}`, `golden/{deploy,query,validate-live}-graylog`.
  - `validate query --platform graylog --file x.lucene`.
- **Done.** Request bodies equal the fixtures for each server version, and the preview check is clean.

#### P-EX: Exabeam (train)

- **Goal.** 0.27.0's Exabeam platform (`13bc1a202`).
- **Do.**
  - §2.1 checklist. R0 row: `exabeam`, lower-case UUID id, deploys, live check (the filter through Search), query runner (at most 3,000 rows), offline `exabeam` (`rule` profile for sequences, `search` for hunts and files).
  - Model `ExabeamConfig` and the 13 `exabeam_*` codes at the spec's field paths (Python `constraints.py` `block_findings`, `name_length_finding`, `delay_minutes`, `uses_context_table`).
  - Workspace check `exabeam_name_duplicate`, case-insensitive. Advisories `exabeam_outcome_silent`, `exabeam_correlation_window` (ordered windows plus a minute between each, `d733efd06`).
  - Compile (`opentide-compile/src/exabeam.rs`): `exabeam_name`, `derive_description` with the ATT&CK line, `derive_severity`, `compile_body`, `create_request`, `update_request` (whole rule), `search_body`, `live_search_request` (last 15 minutes).
  - Connector: OAuth `client_id`/`client_secret` per `region`, a name check before create (`exabeam_name_conflict`; refuse, never adopt), disable with `enabled: false`, and pacing of 100 requests a minute across all Exabeam tenants (the `governor` crate or the connectors' existing limiter). `400` fails a live check, and any answer but `200` is an error.
  - Setup, new, doctor, info, completion, bindings, 28 explain pages, docs. Take #1015's `network-session` fixture fix.
- **Tests.** `tests/fixtures/exabeam/` (sequence and threshold rules with `create/update/disable/validate.api.json`, `state/`, `invalid/` (5)), the cases of `tests/test_platforms/test_exabeam_{model,compile,deployer,runner,engine,setup}.py`, and ls `tests/exabeam_spec.rs` (354 lines).
- **Golden cases (definitions).** Corpus `rule-0015-exabeam-correlation.yaml` (UUID `…0000e8ab0001`) and `exabeam.toml`; stand-in tenant `tests/cassettes/exabeam/tenant.py`, with the token endpoint on the region host; scenarios `exabeam/{deploy,query,validate}` and `golden/{deploy,query,validate-live}-exabeam`; `.exabeam` file offline.
- **Done.** The fixtures match, pacing is tested with a paused clock (`tokio::time::pause`), and the preview check is clean.

#### P-GS: Google Security Operations (train)

- **Goal.** 0.28.0's Google SecOps platform (`f34fc0f05`), as platform-google-secops rev 1.2.
- **Do.**
  - §2.1 checklist. R0 row: `google_secops`, `ru_…` text id, deploys, live check (`verifyRuleText`), query runner (`udmSearch`, `queryDialect=YL2`, no `--rule`), offline `yaral`.
  - Model `GoogleSecopsConfig` with the sections. Codes `google_secops_rule_name`, `_severity`, `_run_frequency`, `_schedule`, `_meta_key`, and the YAML-level `yaral_section_missing`, `_empty`, `_header`, `_alias`, `yaral_match_shape`, `yaral_match_window`, `yaral_option` (Python `checks.py`, `yaral.py`).
  - Workspace check `google_secops_name_duplicate`, case-insensitive. Advisories `google_secops_risk_score_missing`, `google_secops_rule_id_literal`, `google_secops_live_frequency_unavailable`.
  - Assembled rule, once in `opentide-schema` (shared with E2-L): header, derived `meta` (author, description, severity, priority, ATT&CK `technique` as the comma-separated list, `opentide_uuid`, `opentide_version`; no tactic, `5aebedccb`), sections with their line map.
  - Compile: `schedule_customizations`, `run_state`, `instance_resource`, `default_endpoint` (`https://{location}-chronicle.googleapis.com`).
  - Connector (`opentide-connectors/src/google_secops.rs`):
    - `verifyRuleText` before every create and text update.
    - Send the text only when it changed.
    - A bound rule is unarchived first; its text, `scope` and run state are each updated only where they differ.
    - `PREVIEW`/`RELEASE`/`UNIVERSAL`/`DISABLEMENT`/`DELETION`: archive, or `deletion = "delete"` without `force`, archiving when Google refuses.
    - `runFrequency` only when the block names one. `data_access_scope` takes an id or a full name.
    - Waits: on 429, and on 503 except for a create, honour `Retry-After` or `RetryInfo`, else wait 5, 15 and 60 s, bounded (`8380279e0`).
    - Never resend a create after a 5xx or no answer (`google_secops_create_unconfirmed`).
    - Warnings `google_secops_rule_execution_limited`, `_rule_compilation_failed`.
    - The live check maps compile errors and warnings to section key and line (Python `diagnostics.py` `read_verify_answer`, `locate`).
  - Credentials:
    - A service-account key as JSON or a path (`type: service_account` only); otherwise Application Default Credentials (the `GOOGLE_APPLICATION_CREDENTIALS` file, the gcloud well-known file, the metadata server), with the quota project.
    - Use `google-cloud-auth` if it can send through the tenant's HTTP client (proxy, CA, timeouts). Otherwise use `jsonwebtoken` (RS256) and send the token exchange on the tenant's `reqwest` client.
    - A token that cannot be obtained stops the tenant (`google_secops_credentials_missing`, `google_secops_tenant_unauthorized`).
  - Setup (`project`, `location`, `instance`, `credentials`), new (`26` lines in `new.py`), doctor, info, completion, bindings, 33 explain pages, docs.
- **Tests.**
  - `tests/fixtures/google_secops/`: process and spray rules with `.yaral` assembled text and `verify/create/deployment/disable/archive.api.json`, `invalid/` (6), `tenant.toml`.
  - The cases of `tests/test_platforms/test_google_secops_{model,compile,deployer,live,setup}.py`.
  - The JWT path with a fixed clock and a test key.
- **Golden cases (definitions).**
  - Corpus `rule-0016-google-secops-yaral.yaml` (UUID `…00000000ec01`) and `google_secops.toml`.
  - The stand-in tenant serves `oauth2.googleapis.com` and `<location>-chronicle.googleapis.com`. **Use an ADC `authorized_user` file in the cassettes**: its refresh-token form body is deterministic, while a service-account JWT carries `iat`/`exp` and a signature that change every run, so a cassette cannot replay it byte for byte.
  - Scenarios `google_secops/{deploy,query,validate}`, `golden/{deploy,query,validate-live}-google-secops`.
  - `validate query --file x.yaral`. MCP `validate_query` with `google_secops`.
- **Done.** The assembled text equals each `.yaml`'s `.yaral` fixture, the requests equal the `.api.json` fixtures, and the preview check is clean. Rev 1.3 (#91) is left for after O2.

#### C1: CQL in the editor and TUI (train)

- **Goal.** Confirm 0.24.0's CQL work is all in.
- **Do.** Check `opentide lsp start` hover, completion and highlighting on `configurations.crowdstrike.query` and `system: crowdstrike` hunts, and `opentide tui` findings. Check that `crowdstrike_unsupported` is explained as retired. Confirm the CQL ledger entries and `since_oracle.rs` still describe a real difference from 0.28.0 (0.28.0's `validation/query_platforms.py`: "CrowdStrike is never checked").
- **Done.** A short PR, or none, plus a note in the manifest.

#### F1: Splunk `advanced` table (train)

- **Goal.** 0.24.0's fix (`ffeaf5980`, `429f25d15`).
- **Do.**
  - Model `advanced: map<str, scalar>` on `SplunkConfig`: a list or table value is refused. It is not deprecated, it is left out of editor completion, and the generated catalog accepts it (0.12.1).
  - Compile: each key is sent as written, over a value the block sets and under the tenant's modifiers. `null` is sent as an empty string, and a bool as `1`/`0`.
  - `deploy --dry-run`'s dump shows `advanced`.
  - Take `tests/fixtures/deployment/modifier_flatten_expected.json`.
- **Tests.** The cases of `tests/test_platforms/test_splunk_deployer.py` and `tests/test_models/test_platform_query_contract.py` from `3acbea603`. `opentide-compile/tests/` payload snapshot. `xtask payloads` diff entry.
- **Done.** A rule with `action.<name>.param.*` in `advanced` validates and its payload carries the keys.

#### F2: legacy external-id key with a text value (train)

- **Do.** Port `tests/test_validation/test_errors.py`'s new case (`d0c08892f`): a `rule_id::<tenant>` key whose value is a string is `external_id_in_rule`, not a crash. Add a golden case definition (a fixture edit on `tide-corpus-typo`, or a new edit fixture).
- **Done.** A test passes, and there is likely no code change. Close #913.

#### F3: diagnostics reference generator with MDX escaping

- **Goal.** `docs/cli/diagnostics.md` is generated again, and it stays MDX-safe (#897).
- **Do.** Add `cargo xtask docs diagnostics [--check]` (or a `opentide-cli` test with `UPDATE=1`) that renders the reference from `opentide_cli::explain` (every page, headings one level down, `text` fences marked `illustrative` unless they are a command). Escape `<` that cannot open a tag outside code spans (`_mdx_prose`). Bring `scripts/build/check_docs_mdx.py` here if M0 did not take it. Fix `scripts/build/README.md`. Add a CI step running `--check` in the docs or lint job.
- **Tests.** `cql_link_outside_correlate`'s `<=>` renders as `&lt;=>`; code spans are untouched; drift fails `--check`.
- **Done.** The committed reference equals the generated one.

#### F4: `setup ci` invalid provider (train)

- **Do.** Check that `opentide setup ci bogus` names `github`, `gitlab` and `azure` and suggests the closest, as 0.24.1 does. Add a golden case definition.
- **Done.** The preview check is clean, or the difference is ledgered with a reason.

#### D1: generated documentation pages (train)

- **Goal.** 0.26.0's page layout and content (`cd74cfaf3`, `e8a92ee7e`, `fd962f93b`, `f85c4f14f`).
- **Do.** Rework `opentide-compile/src/generate/docs/` (`render.rs`, `templates/{rule,objective,threat,index,macros}.md.j2`):
  - Breadcrumb, subtitle (kind, schema, version, modification date, TLP), TLP banner above `TLP:CLEAR`, description, overview table per kind, one-line contents (`[[_TOC_]]` on GitLab and Azure DevOps), sections, Metadata last.
  - The rule Deployment section: status, strategy from `deployment.toml`, runs, and tenants reached by deploy's own rules. Use one `tenant_skip_reason` shared with `opentide-compile/src/plan.rs` (Python `models/system_config.py`).
  - Tenant targeting with each tenant's remote id from `.opentide/states/deployment/`. Warnings: platform not enabled, unknown status, unknown listed tenant, platform with no tenant. Never resolve credentials.
  - Platform configuration: every value by YAML path with the field description, model defaults marked, read from `opentide-schema`'s schema so a new field or platform needs no generator change (Python `documentation/facts/settings.py`). Queries fenced in their language, and lists of small objects as tables.
  - Plain-language values as text, identifiers as code. ATT&CK tables with tactic and first sentence, with no citation markers. Folder indexes with status, signals, threats and kill chain.
  - Python sources: `documentation/{facts/{deployment,platforms,settings},markdown/{page,text},parts/{common,rule,objective,threat},objects/*,publish/index,vocabulary}.py`.
- **Tests.** Port the cases of `tests/test_documentation/{test_parts,test_page,test_facts,test_object_renderers,test_publish_index}.py` as insta snapshots, then compare against the preview golden `generate docs*` cases. Differences that are only layout get ledger entries at O2.
- **Done.** The preview check of `generate.docs*` and `generate/…` docs files has only approved-layout differences.

#### D2: diagrams, kill chain, ATT&CK coverage, catalogue overview (train)

- **Goal.** 0.26.0's Mermaid and overview work (`c0cafd31f`).
- **Do.** `opentide-compile/src/generate/docs/mermaid.rs`, ported from Python `diagram/{model,mermaid,builders,sanitize}.py`:
  - Detection coverage runs left to right. Threat chaining is laned by kill-chain phase, with one direction per relation pair and line styles per relation.
  - Nodes are coloured by kind, the page's object is outlined, and there is a legend.
  - Azure DevOps gets a subset (`graph`, no lanes or styles). GitHub and GitLab get `accTitle`.
  - Kill-chain maps (Unified Kill Chain) and the docs root `docs/README.md` "Detection catalogue": threat landscape, a pie chart by status coloured by strategy, rules per platform and status, coverage per phase and tactic with uncovered techniques.
  - The ATT&CK matrix's tactic order, sub-techniques counting for their parent, and the Actors table with group aliases.
- **Tests.** The cases of `test_mermaid.py`, `test_diagram_builders.py`, `test_diagram_snapshots.py`.
- **Done.** As D1.

#### D3: CVE details (train)

- **Goal.** With `[cve] retrieve_details`, each CVE shows CVSS score and version, EPSS (one more Vulnerability-Lookup call per CVE), KEV/active exploitation, CWE, affected products and the vector. A threat's overview counts its CVEs with the highest score, with a warning per CVE exploited in the wild.
- **Do.** `opentide-connectors/src/vulnerability.rs` (the EPSS call; parse the CVE record as 0.28.0's `vulnerability_lookup.py` does), `opentide-compile/src/generate/docs/cve.rs` (rendering).
- **Tests.** `tests/fixtures/vulnerability_lookup/{cve-2023-4966,cve-2024-3094,epss-cve-2023-4966}.json` and the cases of `tests/test_vulnerability_lookup/test_client.py`. A cassette scenario `golden/generate-docs-cve` (stand-in Vulnerability-Lookup) for a golden case.
- **Done.** The fixtures parse to the 0.28.0 values.

#### X1: agent-facing docs and leftovers (train)

- **Do.**
  - The platform capability matrix and per-platform notes for 13 platforms, with Rust paths, in `crates/opentide-connectors/AGENTS.md`, linked from `AGENTS.md`.
  - `README.md` ("thirteen security platforms").
  - `src/opentide/data/setup/skills/detection-workflow/SKILL.md`.
  - The docs pages still in the manifest, and the version claims kept as integration's.
- **Done.** The manifest has only superseded rows.

#### X2: #1015 ports

- **Do.** After #1015 merges on development: `git merge origin/development` into the train (or integration). Then port:
  - (a) Frontmatter on the packaged skills (data).
  - (b) A packaged slug the catalogue lists installs the catalogue's copy, falling back to the package (`crates/opentide-cli/src/commands/setup/` skills), with re-recorded `skills/*` cassettes.
  - (c) Explain wording from the engine's severity for warning-only YARA codes.
  - (d) Docs.
- **Done.** If the oracle is 0.28.1, there are no ledger entries for these; otherwise each one is ledgered.

#### U-0.28.1: development after v0.28.0 (train, `feat/port-0.28.1`)

- **Goal.** What development merged after `v0.28.0` for 0.28.1: #1029 and the packaged-skills part
  of #1015. M0 merged both commits (`072fccb07`, `a15c78c73`) for history and left their files at
  integration's version; this unit ports them.
- **Do.**
  - **#1029** (`072fccb07`, optional fields are notes): a third severity, a note, that `--strict`
    never fails on and that `validate`, `lint` and `validate query` hide unless `--verbose`
    (`crates/opentide-cli`: the root options, the code frame and the diagnostics UI; the `--json`
    output keeps every finding, as 0.28.1 does). `metadata_recommended` becomes a note by default,
    and `lint` gains a `recommended` check (a rule's `configurations` and `response`) with a
    `[recommended]` table in `lint.toml`. Data: `src/opentide/data/configurations/lint.toml`,
    `data/diagnostics/{metadata_recommended,recommended_field_missing}.md`.
  - **#1015's packaged skills** (`a15c78c73`): frontmatter on the packaged authoring skills, and a
    packaged slug the catalogue lists installs the catalogue's copy (`setup skills`, partly
    reversing #405). This changes the `skills/*` cassettes, which fetch the catalogue's
    `detection-engineering`.
  - Take the manifest's U-0.28.1 rows (`docs/cli/{global-options,lint}.md`,
    `docs/usage/{repository-setup,workflows/agentic-setup}.md`, the skills paragraphs of
    `docs/cli/setup.md` and `docs/usage/troubleshooting.md`, the notes and `--verbose` part of
    `docs/cli/validate.md`, the two explain pages, `lint.toml`, the four packaged `SKILL.md`).
  - #1015's other fixes stay where the manifest puts them: `exabeam_unknown_value` with P-EX, the
    YARA warning wording and the Graylog and YARA-L lint warnings in `docs/cli/diagnostics.md`
    with F3, the YARA lane and P-GS. X2 keeps the agent-facing docs.
- **Tests.** A note never fails `--strict` and is hidden without `--verbose` (CLI E2E, both
  renderers); the `recommended` check reports a rule missing `configurations`; `setup skills`
  installs the catalogue's copy of a packaged slug (cassette).
- **Golden.** Case definitions for `--verbose` and `lint --check recommended`; the preview check
  runs against development's tip, not 0.28.0, so expect differences until the oracle moves (§4.1).
- **Done.** The preview summary for `validate*`, `lint*` and `setup skills` is clean or explained,
  and the manifest's U-0.28.1 rows are gone.

#### X3: #993 port (integration, after O2)

- See §1.5. Size M: annotations S, views M.
- **Tests.** Every tool carries a title and hints (unit test). The `ui://` resource contains no remote loads and no `innerHTML`, and the escaped ATT&CK JSON cannot close `<script>`. Over stdio, `resources/read` returns `text/html;profile=mcp-app`.

#### O2: oracle move and train merge (train)

- **Goal.** The goldens are 0.28.0's, every case passes or is approved, and the train merges into integration.
- **Do.** §4.2 in full. Swap `ORACLE.next` into `ORACLE`. Run the manifest check (§3.1). Update the docs and skills that name the oracle. Merge `integration/unified-core` into the train one last time, then merge the train into integration.
- **Tests.** Every oracle comparison listed in §4.2 is green, with determinism checked (`golden record --check-determinism`).
- **Done.** `Golden compare` is gating and green on integration with ORACLE = 0.28.0, `docs/internal/catchup-0.28.md` is deleted, and `1.0.0-rc.1` can be cut.

---

## 6. Decisions for the maintainer

Decided by the orchestrator (technical): 1 yes, one implementation per platform; 2 yes, a
`train/catchup-0.28` branch with report-only goldens until O2; 4 merge commits only (PRs merge with
merge_method=merge, never squash or rebase); 5 the bench oracle stays at 0.23.0. Open with the
maintainer: 3 (0.28.0 or 0.28.1).


1. **One implementation of each platform's checks** (in `opentide-schema`, reaching the editor through `opentide-workspace` validate), with language-server's Tide block walkers taken only for injection, completion and hover. The Sysdig precedent keeps two walkers plus an agreement test (`opentide-tide/src/sysdig.rs`, `the_editor_and_the_model_agree_on_the_sysdig_cases`). This plan recommends against repeating that four times.
2. **Train branch with report-only goldens until O2**, versus ledgering every port against 0.23.0 on integration. The docs redesign alone changes every `generate` case, and the new platforms change `generate schemas` blobs and every help screen that lists platforms. Ledgering against an oracle about to be replaced is wasted work.
3. **Oracle 0.28.0 or 0.28.1** (§1.5): 0.28.1 only if #1015 ships first.
4. **How train merges keep two parents** (M0, E1, the train into integration): a merge commit, never squash.
5. **Bench oracle** stays at 0.23.0 for now (§1.6).

## 7. Risks

- **E1 merge size.** opentide-tide and opentide-lsp diverged on both sides. Keeping the Tide block modules out of E1 bounds it. Budget E1 as the longest single unit, and start it first.
- **Cassette determinism** for Google OAuth (JWT) and the Exabeam token: choose deterministic credential flows in scenarios (P-GS). Exabeam's client-credentials body is deterministic, with its secret redacted.
- **Pacing and retries in cassettes** (Bitdefender, Exabeam, Google Retry-After): the stand-in tenants must not answer 429 in golden scenarios, or replay timing becomes part of the case. Test waits in Rust with a paused tokio clock.
- **Shared-file conflicts across P-units**: R0 first, then merge P-units one at a time onto the train.
- **Recordings budget** (§4.2).
- **Spec drift**: specifications `main` is ahead of what 0.28.0 implements (bitdefender rev 1.4, graylog 1.1, google-secops 1.3, language-exabeam 1.1). Port 0.28.0's behaviour now and file follow-ups.
