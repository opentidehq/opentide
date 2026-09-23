---
title: Releases
description: Public package versions of the OpenTide DetectionOps engine on PyPI.
---

# Releases

The engine is the [`opentide`](https://pypi.org/project/opentide/) package. Pin a version in CI. Source of truth for notes is [`CHANGELOG.md`](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md) in the repository; GitHub Releases are tagged `v*` and publish to PyPI.

## 0.5.0 — 23 September 2026

Minor on 0.4.0. **Upgrade if your threats follow `threat::1.0` and list their `impact` / `leverage` names** — 0.4.0 rejected every such threat with `Input should be a valid string`. A threat written the way 0.4.0 required (`impact: Data Breach`) now fails until it becomes a one-item list, so update threats before upgrading a pipeline.

**Install**

```bash
pip install opentide==0.5.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Then run `opentide generate` so new threats start from the list template.

**What changes for authors and scripts**

- `threat.impact` and `threat.leverage` are non-empty YAML lists of vocabulary names. A single string fails with `must be a YAML list of … vocabulary names`; a value or list item that joins several names with `;` fails too. Give every name its own item and keep all of them ([#189](https://github.com/OpenTideHQ/opentide/issues/189)). See [Troubleshooting](./troubleshooting.md#threat-impact--leverage-input-should-be-a-valid-string-must-be-a-yaml-list-or-packs-several-vocabulary-names).
- SDK: `ThreatBody.impact` / `.leverage` are `list[str]`. Threat templates, editor schemas, and the explorer bundle carry lists.

```yaml
threat:
  impact:
    - Data Breach
    - Identity Theft
  leverage:
    - Elevation of privilege
```

**What this version fixes**

- Threats written to the `threat::1.0` spec validate, and `validate` no longer suggests a single name for a `;`-joined value, which would drop the others ([#189](https://github.com/OpenTideHQ/opentide/issues/189)).
- The spec's threat conformance fixtures run in CI, so the engine cannot drift from `threat::1.0` again.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.5.0/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.5.0)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.4.0 — 22 September 2026

Minor on 0.3.0. **Upgrade if a first-run command crashed, printed a traceback, or quietly did nothing.** Fixes the first-user bugs filed against 0.3.0 and the test-harness gaps that let them ship. A few fixes change output scripts can depend on, so read the first list before upgrading a pipeline.

**Install**

```bash
pip install opentide==0.4.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Then regenerate CI and hooks: `opentide setup ci <github|gitlab|azure> --yes` and `opentide setup hooks --yes`.

**Security: regenerate GitHub CI**

The inflight job from `opentide setup ci github` in 0.3.0 pushed the pull request head to the default branch, so an up-to-date pull request landed there unreviewed. Inflight jobs now commit only `.opentide/inflight/` shards from a worktree of the default branch ([#244](https://github.com/OpenTideHQ/opentide/issues/244)).

**What changes for scripts**

- `validate query` is an offline syntax check by default and needs no SDK. Use `--live` for the tenant round-trip ([#239](https://github.com/OpenTideHQ/opentide/issues/239)).
- `query` is required and non-blank on Splunk and Carbon Black; `splunk::2.x` `search` / `cron_schedule` map onto `query` / `scheduling` in both `validate` and `deploy` ([#233](https://github.com/OpenTideHQ/opentide/issues/233)). See [Upgrading to 0.4.0](./concepts/platforms.md#upgrading-to-040).
- `opentide --json setup` without `--yes` exits with a JSON error instead of starting the wizard ([#255](https://github.com/OpenTideHQ/opentide/issues/255)).
- MCP: `search` always returns a list, `coverage` for a parent technique includes sub-techniques, `opentide://vocabularies` is an index, and `run_query` is an explicit stub ([#252](https://github.com/OpenTideHQ/opentide/issues/252), [#253](https://github.com/OpenTideHQ/opentide/issues/253), [#254](https://github.com/OpenTideHQ/opentide/issues/254), [#258](https://github.com/OpenTideHQ/opentide/issues/258)).
- `mcp` is pinned `<2`; `fastmcp` is no longer a dependency ([#256](https://github.com/OpenTideHQ/opentide/issues/256)).
- Positional `PATH` on `setup` subcommands is deprecated; use `--path` / `-C` ([#248](https://github.com/OpenTideHQ/opentide/issues/248)).

**What this version fixes**

- CLI: nested `deploy metadata` / `generate inflight prune` ran the parent command ([#243](https://github.com/OpenTideHQ/opentide/issues/243)); `info coverage --technique` failed to parse ([#257](https://github.com/OpenTideHQ/opentide/issues/257)); `generate docs --changed` crashed without a git HEAD and missed changes off non-`main` trunks, on pushed feature branches, and in non-ASCII file names ([#241](https://github.com/OpenTideHQ/opentide/issues/241), [#251](https://github.com/OpenTideHQ/opentide/issues/251)); `generate extract` failed at import ([#242](https://github.com/OpenTideHQ/opentide/issues/242)); `generate explorer` was not registered ([#202](https://github.com/OpenTideHQ/opentide/issues/202)); Sentinel-only runs loaded every engine, and a broken engine ended deploy with a traceback ([#246](https://github.com/OpenTideHQ/opentide/issues/246)).
- Validation: `validate --file` ignored the directory ([#240](https://github.com/OpenTideHQ/opentide/issues/240)); unparseable YAML raised a traceback ([#250](https://github.com/OpenTideHQ/opentide/issues/250)).
- Setup: GitLab and Azure inflight jobs never pushed, GitHub and Azure jobs assumed a `main` trunk, and concurrent inflight jobs failed or dropped each other's shards ([#244](https://github.com/OpenTideHQ/opentide/issues/244)); the pre-commit hook validated `OPENTIDE_REPO_ROOT` instead of the commit, missed nested or additional workspaces, and was installed into a user-wide `core.hooksPath` ([#249](https://github.com/OpenTideHQ/opentide/issues/249)); `setup --path DIR --yes <subcommand>` ignored both flags, and refusing other group options hid the subcommand's `--help` ([#248](https://github.com/OpenTideHQ/opentide/issues/248)).
- Output: `--no-color`, `FORCE_COLOR=0`, and `PY_COLORS=0` still let ANSI escapes through on CI runners ([#282](https://github.com/OpenTideHQ/opentide/pull/282)).
- MCP: `coverage` and actor search ignored `rule.techniques` / `threat.actors` ([#252](https://github.com/OpenTideHQ/opentide/issues/252)); schemas resolved to `{}` ([#254](https://github.com/OpenTideHQ/opentide/issues/254)); `validate_query` accepted garbage ([#245](https://github.com/OpenTideHQ/opentide/issues/245)); `opentide-mcp` tracebacked without the extra ([#256](https://github.com/OpenTideHQ/opentide/issues/256)).
- Docs: tutorial and CLI samples now match live output, and every documented command is checked against the CLI in CI ([#247](https://github.com/OpenTideHQ/opentide/issues/247), [#270](https://github.com/OpenTideHQ/opentide/issues/270)).

**Links**

- [PyPI](https://pypi.org/project/opentide/0.4.0/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.4.0)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.3.0 — 21 September 2026

Minor maintenance on 0.2.1. **Upgrade for current runtime and toolchain floors (cryptography 50.x, typer 0.27) and a clean GitHub Code Quality pass.**

**Install**

```bash
pip install opentide==0.3.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version changes**

- Recreated stale Dependabot uv upgrades on current trunk ([#235](https://github.com/OpenTideHQ/opentide/pull/235)): cryptography 50.0.1 (CVE-2026-69247), dulwich 1.2.15, typer 0.27.2 (extra `all` removed; rich/shellingham/colorama are default deps), syrupy 5.5.3, ruff 0.16.8, ty 0.0.82 (dev extra only).
- Cleared GitHub Code Quality findings from the CodeQL `python-code-quality` suite ([#236](https://github.com/OpenTideHQ/opentide/pull/236)).

**Links**

- [PyPI](https://pypi.org/project/opentide/0.3.0/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.3.0)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.2.1 — 18 September 2026

Patch on 0.2.0. **Upgrade if you validate `threat.cve` identifiers or generate threat documentation that should link to CIRCL Vulnerability-Lookup.**

**Install**

```bash
pip install opentide==0.2.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version adds**

- CVE validation and generated threat CVE tables use [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) instead of scraping NVD through `mitrecve` ([#109](https://github.com/OpenTideHQ/opentide/issues/109)).
- `opentide validate --check cve` looks up CVE, GHSA, and GCVE identifiers. GNA 0 GCVE ids map to CVE. Generated docs link to `https://vulnerability.circl.lu/vuln/{id}` and can enrich published date, severity, and aliases.
- `threat.cve` is a first-class optional list on the threat body.

**What this version changes**

- Bundled `[cve]` defaults point at Vulnerability-Lookup. Legacy NVD link prefixes are remapped. The CVE check stays opt-in so default `opentide validate` stays offline.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.2.1/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.2.1)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.2.0 — 18 September 2026

Minor on 0.1.8. **Upgrade if you generate templates or VS Code snippets — optional YAML now hugs `#` to each key, spacers stay blank, and rule `configurations` are commented platform stubs rather than `{}`.**

**Install**

```bash
pip install opentide==0.2.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version changes**

- `opentide generate templates` walks Pydantic `FieldInfo` instead of the JSON Schema `gen_template` walker ([#223](https://github.com/OpenTideHQ/opentide/issues/223)).
- Optional sections are commented YAML with `#` hugging each key; nested optionals are not commented again; spacer blanks stay blank.
- Rule `configurations` are commented platform stubs (`#sentinel:`) rather than `{}`.
- VS Code snippet conversion treats commented nested keys as mapping children, so `configurations:` is not turned into a tabstop.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.2.0/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.2.0)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.8 — 16 September 2026

Patch on 0.1.7. **Upgrade if first-time `setup` / `generate` logged missing object folders as errors, dumped YAML `null`, attached live children under `#key:` parents, skipped platform TOML from `setup repo --platform`, emitted Title-Case UUID documentation paths, or looked up `objective.priority` in `criticality::1.0`.**

**Install**

```bash
pip install opentide==0.1.8
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version adds**

- VS Code snippets with `tide-*` prefixes, YAML scope, descriptions, and tabstops ([#194](https://github.com/OpenTideHQ/opentide/issues/194)).
- `opentide setup vscode --mcp` ([#193](https://github.com/OpenTideHQ/opentide/issues/193)).

**What this version fixes**

- Missing object folders log at debug, not error.
- Optional template `#key:` blocks comment nested children.
- Templates never emit YAML `null`.
- `setup repo --platform` writes enabled platform TOML.
- Objective `priority` is not checked against `criticality::1.0`.
- GitHub docs use lowercase slug paths; UUID permalinks stay GitLab-only.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.8/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.8)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.7 — 16 September 2026

Patch on 0.1.6. **Upgrade if VS Code YAML reported "Matches multiple schemas", generated templates hid required nested fields, `setup vscode` skipped snippets or crashed on a missing path, JSON validate stamped every check failed, or `invalid_ref` pointed at parent objects.**

**Install**

```bash
pip install opentide==0.1.7
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- `invalid_ref` reports the leaf UUID field; JSON validate uses per-check `status`; vocabulary names skip list indices.
- VS Code `yaml.schemas` uses recursive per-folder globs (`objects/threats/**/*.yaml`) instead of the router wildcard.
- MCP templates use `servers` (VS Code/Cursor), host-specific repo-root env, `extensions.json`, and `AGENTS.md`.
- Generated templates inline `$ref` bodies and keep nested required fields uncommented.
- `setup vscode` generates templates/schemas first, creates a missing target path ([#200](https://github.com/opentidehq/opentide/pull/200)), and fails when snippets cannot be written.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.7/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.7)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.6 — 15 September 2026

Patch on 0.1.5. **Upgrade if `opentide generate` crashed on unquoted YAML dates, or if interactive `opentide setup` crashed after choosing a CI provider.**

**Install**

```bash
pip install opentide==0.1.6
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- Unquoted `created: 2026-09-11` metadata dates no longer crash generate JSON export (`Object of type date is not JSON serializable`).
- Interactive setup no longer raises `validate must be callable` on optional CI feature checkboxes.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.6/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.6)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.5 — 13 September 2026

Patch on 0.1.4. **Upgrade if you regenerate ATT&CK or MISP vocabularies, or if you run the weekly ingest workflow.**

**Install**

```bash
pip install opentide==0.1.5
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version adds**

- Weekly (and `workflow_dispatch`) ingest for MITRE ATT&CK STIX and MISP threat actors, with RFC 0003 per-key versions and matching schema pin bumps.

**What this version fixes**

- ATT&CK groups stay catalog-only; live objects pin G-ids through `threat.actors.name` → `actors::*`.
- Later ingest cycles fetch `chore/vocab-upstream` before `git push --force-with-lease`.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.5/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.5)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.4 — 13 September 2026

Patch on 0.1.3. **Upgrade if `opentide generate` crashed on `threat.actors`, or if you wrote actors as vocabulary ID strings.**

**Install**

```bash
pip install opentide==0.1.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- `threat.actors` is a list of objects (`name: att&ck::G0006`, optional `sighting` / `references`), not `list[str]`.
- `opentide generate` no longer raises `'str' object has no attribute 'get'` on those fields.
- Nested vocabulary fields are checked against the pinned vocabs.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.4/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.4)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.3 — 11 September 2026

Patch on 0.1.2. **Upgrade if you ran `setup ci`, deployed or validated queries locally, followed the tutorial, or installed without Azure/pandas extras.**

**Install**

```bash
pip install opentide==0.1.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- `opentide setup ci` emits parseable GitHub, GitLab, and Azure YAML.
- `opentide deploy` and `validate query` default `DEPLOYMENT_PLAN` to `FULL` when the env var is unset.
- Tutorial objects validate and lint; `generate docs` writes under the detection repository.
- `opentide info` reports `can_deploy: true` after a base `pip install`. Azure and pandas extras are not required for dry-run.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.3/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.3)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.2 — 11 September 2026

Patch on 0.1.1. **Upgrade if you scaffold new repos, generate an empty catalogue, or install agent skills.**

**Install**

```bash
pip install opentide==0.1.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version adds**

- `opentide setup ci` sets `OPENTIDE_REPO_ROOT` in generated GitHub, GitLab, and Azure pipelines.
- `opentide setup env` writes `.env.example`; `opentide setup hooks` installs validate-on-commit.
- `opentide lint` for filename slugs and recommended metadata (`--fix`, `--strict`).
- `opentide migrate objects` for CoreTide `Configurations/` and `Objects/` layouts.

**What this version changes**

- Skills install from the live OpenTideHQ/skills catalogue. GitHub must be reachable — there is no packaged fallback.

**What this version fixes**

- `opentide generate` completes on a freshly scaffolded empty repository.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.2/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.2)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.1 — 11 September 2026

Patch on the public 0.1.0 beta. **Upgrade if you installed 0.1.0 from PyPI.**

**Install**

```bash
pip install opentide==0.1.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

**What this version fixes**

- `opentide generate` and `opentide validate` no longer crash with `UnicodeDecodeError` after pip compiles `__pycache__` next to bundled configuration TOMLs.
- `opentide setup skills discover` and `show` run as subcommands instead of being treated as a repository path.
- Starter skills (`opentide-detection-rule`, `detection-engineering`) install from the packaged trees when GitHub is unreachable.

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.1/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.1)
- [CHANGELOG](https://github.com/OpenTideHQ/opentide/blob/development/CHANGELOG.md)

## 0.1.0 — 9 September 2026

First public beta. Not 1.0.

**Install**

```bash
pip install opentide==0.1.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Python **3.10–3.14**. One wheel: CLI, MCP (`opentide-mcp`), SDK, seven platform adapters. Enable platforms with `opentide setup platforms` — not with pip extras.

**What this version is**

- A version you can pin, instead of a CoreTide submodule SHA.
- `opentide setup` for repo, CI, MCP, and skills.
- Honest capability: seven platforms deploy; five validate query syntax (Sentinel, Defender, Splunk, SentinelOne, Carbon Black). CrowdStrike and HarfangLab are deploy-only.

**What it is not**

- A hard cut for existing instances. Pinned CoreTide checkouts keep resolving. Migrate when you next touch CI — [migration guide](./migration/index.md).
- A freeze forever. For **four weeks** after 0.1.0 the maintainers treat this as a support window: deployer bugs, docs, agent setup, migration questions. File issues on [OpenTideHQ/opentide](https://github.com/OpenTideHQ/opentide/issues).

**Links**

- [PyPI](https://pypi.org/project/opentide/0.1.0/)
- [GitHub Release](https://github.com/OpenTideHQ/opentide/releases/tag/v0.1.0)
- [Announcement](https://opentide.org/blog/the-engine-is-opentide/)
- [Installation](./installation.md)
