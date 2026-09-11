---
title: Troubleshooting
description: Common OpenTide failures — validation errors, generation drift, platform loading, and deployment — with fixes.
---

# Troubleshooting

The failures you are most likely to hit, why they happen, and how to fix them. If your problem is a genuine bug, open an issue on [opentide](https://github.com/OpenTideHQ/opentide/issues).

## Setup and paths

### `Could not resolve repository root` / objects not found

OpenTide does not know where your content lives. Set the repo root explicitly:

```bash
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
# or per-command
opentide --repo /path/to/detection-repo validate
```

See [Installation → environment variables](./installation.md#environment-variables).

### The command `opentide` is not found

The CLI ships as an extra. Install it:

```bash
pip install 'opentide==0.1.2'
```

Inside a virtualenv, confirm it is on `PATH` (`which opentide`). For MCP/agent hosts, point the host at the venv's `opentide-mcp` — see [MCP configuration](../mcp/configuration.md).

### `UnicodeDecodeError` reading bundled configurations after pip install

`0.1.0` loaded every file under nested configuration directories as UTF-8 TOML. A pip install compiles `opentide/data/configurations/__init__.py` to `__pycache__/*.pyc`. Python 3.13+ bytecode starts with `0xf3`, which is not valid UTF-8, so `validate` and `generate` crashed.

Upgrade:

```bash
pip install 'opentide==0.1.2'
```

`0.1.1` and later skip hidden/dunder directories and load nested `*.toml` only.

### `setup skills discover` starts an install wizard or reports skills unavailable

`0.1.0` bound a positional `PATH` on the skills group, so Click treated `discover` and `show` as a path. The install wizard then ran and tried to download from GitHub.

```bash
pip install 'opentide==0.1.2'
opentide setup skills discover
opentide setup skills --generic --yes
```

Use `--path` / `-C` for the repository root. Skills are discovered and installed from the live [OpenTideHQ/skills](https://github.com/OpenTideHQ/skills) catalogue; GitHub must be reachable.

### `setup skills` warns that the remote catalogue is unavailable

`opentide setup skills` fetches `manifest.json` from GitHub, then downloads each requested skill. It does not install a packaged snapshot. If you see `Could not fetch skills catalogue from OpenTideHQ/skills@main`, check network access and that [OpenTideHQ/skills](https://github.com/OpenTideHQ/skills) is publicly reachable, then retry:

```bash
opentide setup skills discover --refresh
opentide setup skills --generic --yes
```

## Generation

### `opentide generate` crashes with `subschemas` on a new repo

Snippet generation used a legacy `Paths.Core.subschemas` path that the current layout never populates, so `opentide generate` aborted after docs and exports. This is fixed in **0.1.2**. An empty catalogue is valid: generate writes empty exports and creates `.vscode` snippets from whatever templates exist.

### `validate` complains that schemas are missing

Validation checks objects against generated JSON Schemas. If they do not exist yet, generate them first:

```bash
opentide generate
opentide validate --strict
```

Run [`generate`](../cli/generate.md) after cloning a repo, after upgrading the OpenTide package, and whenever schema revisions change.

### Editor stopped validating YAML

Your IDE reads the generated router at `.opentide/schemas/opentide.schema.json`. If it is stale or missing:

```bash
opentide generate schemas
```

Then reload your editor's YAML/schema association.

## Validation errors

### `unknown schema identifier` / object won't load

`metadata.schema` must be a registered identifier such as `rule::1.0`. A typo (`rule:1.0`, `rule::1`, `rules::1.0`) means no model matches. Fix the value; the valid identifiers are `threat::1.0`, `objective::1.0`, `rule::1.0`. See [Schema revision](./concepts/schema-revision.md).

### `duplicate UUID`

Two objects share a `metadata.uuid`. UUIDs must be unique across the repo — you almost certainly copy-pasted an object. Generate a fresh one:

```bash
python -c "import uuid; print(uuid.uuid4())"
```

### `unknown objective` / dangling reference

A `detection_model` or `objective.threats` UUID points at an object that does not exist. This is the [dangling reference](./concepts/object-model.md#anti-patterns-to-avoid) anti-pattern — usually a typo or a deleted file. Fix the UUID or restore the target.

### `unknown status`

A rule's `status` (or a platform block's `status`) is not defined in the merged `deployment.toml`. Use a bundled status (`STAGING`, `PRODUCTION`, …) or add your own — see [Configuration → deployment statuses](./configuration.md#deployment-statuses-and-strategies).

### Warnings fail my build but pass locally

Warnings alone exit `0` by default and are listed in `--json` output under `warnings`. Pass `--strict` to fail the run with exit `1`. If your pipeline uses `--strict`, reproduce it locally with the same flag:

```bash
opentide validate --strict
```

See [Exit codes](../cli/exit-codes.md).

## Query validation

### `supported: false` for a platform

CrowdStrike and HarfangLab are **deploy-only** — they cannot validate query syntax, and OpenTide reports this honestly rather than faking a pass. This is expected behaviour, not an error. Validate queries on a supporting platform (Sentinel, Defender, Splunk, SentinelOne, Carbon Black). See [Platforms](./concepts/platforms.md#query-validation-policy).

### MCP `validate_query` always returns valid

The MCP `validate_query` and `run_query` tools are **stubs** — they do not parse queries yet. Use the CLI (`opentide validate query --platform …`) for real syntax checks, or the MCP `validation_report` tool for structured object validation. See [Agentic setup](./workflows/agentic-setup.md).

## Platforms and deployment

### A platform I configured is not loaded

Platforms load only when enabled in your workspace config:

```toml
# .opentide/configurations/platforms/sentinel.toml
[platform]
enabled = true
```

Verify with `opentide info --platform sentinel`. See [Configuration → enabling a platform](./configuration.md#enabling-a-platform).

### Deploy fails with an authentication error

Credentials are missing or wrong. OpenTide reads them from your platform TOML, typically via environment variables. Confirm the variables are set in your shell (or CI secrets) and match the keys the platform expects (`opentide info --platform <name>`). Never commit secrets — see [Configuration → credentials](./configuration.md#credentials).

### `deploy metadata` seems to do nothing

`opentide deploy metadata` (Splunk lookup tables) currently signals intent in logs — full metadata deployment is pending. See [`deploy`](../cli/deploy.md).

## Still stuck?

- Re-run with debug logging: `DEBUG=1 opentide validate --strict`.
- Compare your object against a known-good [fixture](https://github.com/OpenTideHQ/specifications/blob/main/fixtures/valid).
- Check the [CLI reference](../cli/index.md) for the exact flags and [exit codes](../cli/exit-codes.md).
