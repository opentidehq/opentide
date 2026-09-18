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
pip install 'opentide==0.1.8'
```

Inside a virtualenv, confirm it is on `PATH` (`which opentide`). For MCP/agent hosts, point the host at the venv's `opentide-mcp` — see [MCP configuration](../mcp/configuration.md).

### `UnicodeDecodeError` reading bundled configurations after pip install

`0.1.0` loaded every file under nested configuration directories as UTF-8 TOML. A pip install compiles `opentide/data/configurations/__init__.py` to `__pycache__/*.pyc`. Python 3.13+ bytecode starts with `0xf3`, which is not valid UTF-8, so `validate` and `generate` crashed.

Upgrade:

```bash
pip install 'opentide==0.1.8'
```

`0.1.1` skips hidden/dunder directories and loads nested `*.toml` only.

### `setup skills discover` starts an install wizard or reports skills unavailable

`0.1.0` bound a positional `PATH` on the skills group, so Click treated `discover` and `show` as a path. The install wizard then ran and tried to download from GitHub.

```bash
pip install 'opentide==0.1.8'
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

### Interactive `opentide setup` crashes with `validate must be callable`

Selecting GitHub Actions (or another CI provider) in the wizard then failed on **CI workflow features**:

```text
ValueError: validate must be callable
```

`0.1.5` passed `validate=None` into Questionary for optional checkboxes. **0.1.6** omits the argument when a selection is optional. Non-interactive `opentide setup --ci github` was already fine. Upgrade:

```bash
pip install 'opentide==0.1.8'
opentide setup
```

### `setup vscode` crashes with `FileNotFoundError`

Generate-first `opentide setup vscode` `chdir`s into the target before writing files. **0.1.6** raised `FileNotFoundError` when that path did not exist yet. **0.1.7** creates the directory first (same as other setup commands). Upgrade:

```bash
pip install 'opentide==0.1.8'
opentide setup vscode
```

### `setup vscode` reports success but snippets are missing

`0.1.6` wrote `.vscode/settings.json` even when templates (and therefore snippets) were missing. **0.1.7** generates templates and schemas first, then fails (`status: failed`) if snippets were requested but could not be written. Re-run:

```bash
pip install 'opentide==0.1.8'
opentide setup vscode
```

Pass `--no-generate` only when `.opentide/templates` already exist. A missing target directory is created automatically.

### `could_not_find_object_folder` at error on an empty repo

`0.1.7` logged missing `objects/{threats,objectives,rules}` at **error** during generate-first `setup vscode` or `generate` on a brand-new scaffold. Those folders are empty until you author YAML. **0.1.8** logs absence at **debug** (once per path). A path that exists but is not a directory still logs at error. Upgrade:

```bash
pip install 'opentide==0.1.8'
opentide generate
```

### `setup repo --platform` does not enable Sentinel (or other) TOML

`0.1.7` accepted `--platform sentinel` on `opentide setup repo` but did not write `.opentide/configurations/platforms/sentinel.toml`. The parent `opentide setup --platform` path already did. **0.1.8** runs platform setup from `setup repo --platform` as well, so `generate` emits `#sentinel:` configuration stubs. Upgrade and re-run:

```bash
pip install 'opentide==0.1.8'
opentide setup repo --yes --name SOC --platform sentinel
opentide generate
```

### Generated templates contain YAML `null` or attach children under the wrong parent

`0.1.7` dumped `default: None` as YAML `null`, and commented `#organisation:` without commenting nested `uuid` / `name`, so those keys parsed as children of `metadata.tlp`. **0.1.8** patched the legacy JSON Schema walker. **0.2.0** replaces that walker: templates come from Pydantic `FieldInfo`, optional sections are commented as whole blocks with `#` hugging each key (nested optionals are not commented again), and there are no `null` tokens. Upgrade and regenerate:

```bash
pip install -U opentide
opentide generate templates
```

Confirm `.opentide/templates/rule.1.0.template.yaml` has no `null`, `metadata.tlp` is a scalar, and `configurations:` lists commented platform stubs (`#sentinel:`) rather than `{}`.

### `setup ci` YAML fails to parse in GitHub, GitLab, or Azure

`0.1.2` built pipeline files with `textwrap.dedent` around already-indented step blocks, which produced invalid YAML. This is fixed in **0.1.3**. Re-run:

```bash
opentide setup ci github --yes
```

### `deploy` or `validate query` crashes locally with `illegal_deployment_plan`

`0.1.2` treated an unset `DEPLOYMENT_PLAN` as the string `"None"`. Unset or blank now defaults to `FULL`. This is fixed in **0.1.3**. You can still set `--plan` or `DEPLOYMENT_PLAN` explicitly.

### Tutorial objects fail `validate --strict` or `lint --strict`

`0.1.2` tutorial YAML omitted `metadata.created` / `modified` and used filename/severity values that lint rejected. Copy the examples from the current [Tutorial](./tutorial.md), or upgrade to **0.1.3** and re-run `opentide setup` so templates include dates.

### `info` reports `can_deploy: false` after `pip install opentide`

`0.1.2` imported Azure and pandas when loading Sentinel (and other) deployers, so a base install reported no deploy capability. **0.1.3** lazy-loads those SDKs. Re-run `opentide info` after upgrading. CrowdStrike and HarfangLab still report `can_validate: false` by design.

## Generation

### `opentide generate` crashes with `Object of type date is not JSON serializable`

Unquoted `metadata.created` / `modified` values (`created: 2026-09-11`) are valid Tide YAML. PyYAML loads them as `datetime.date`, and `0.1.5` crashed when writing `.opentide/exports/objects.export.json`. **0.1.6** stringifies those timestamps at YAML load. Upgrade:

```bash
pip install 'opentide==0.1.8'
opentide generate
```

Quoted dates (`created: "2026-09-11"`) already worked; you do not need to quote them.

### Generated templates comment out required nested fields

`0.1.6` expanded `$ref` / `$defs` in templates but nested objects still inherited a shallow parent `required` list, so required fields under array items were commented out. **0.1.7** uses each nested object's own required list. Upgrade and regenerate:

```bash
pip install 'opentide==0.1.8'
opentide generate
```

### `opentide generate` crashes with `'str' object has no attribute 'get'`

`0.1.3` leaked `threat.actors` as `list[str]` while table export still called `.get("name")`. **0.1.4** restores the CoreTide object form (`name`, optional `sighting` / `references`). Upgrade:

```bash
pip install 'opentide==0.1.8'
```

Write actors as objects, not bare IDs:

```yaml
actors:
  - name: att&ck::G0006
```

### `opentide generate` crashes with `subschemas` on a new repo

Snippet generation used a legacy `Paths.Core.subschemas` path that the current layout never populates, so `opentide generate` aborted after docs and exports. This is fixed in **0.1.2**. An empty catalogue is valid: generate writes empty exports and creates `.vscode` snippets from whatever templates exist.

### `validate` complains that schemas are missing

Validation checks objects against generated JSON Schemas. If they do not exist yet, generate them first:

```bash
opentide generate
opentide validate --strict
```

Run [`generate`](../cli/generate.md) after cloning a repo, after upgrading the OpenTide package, and whenever schema revisions change.

### Editor stopped validating YAML / "Matches multiple schemas"

`0.1.6` mapped the bundled `opentide.schema.json` router against `objects/**/*.yaml`. The Red Hat YAML extension cannot narrow that `oneOf` router, so it reports **Matches multiple schemas** and disables autocompletion. **0.1.7** maps each object folder recursively (`objects/threats/**/*.yaml` → `threat.1.0.schema.json`, and the same for objectives and rules). Nested files under those folders stay associated.

```bash
pip install 'opentide==0.1.8'
opentide setup vscode
```

Then reload the YAML language server. If schemas are stale or missing:

```bash
opentide generate schemas
```

## Documentation

### GitHub docs land under `docs/Threats/{uuid}.md` instead of slug paths

`0.1.7` applied GitLab `uuid_permalinks` to every flavour and built index links from the UUID while page files used slugify. GitHub pages were therefore `simulated-actor.md` while indexes linked to `{uuid}.md`, and folders used Title Case (`docs/Threats`). **0.1.8** scopes UUID permalinks to GitLab and writes lowercase `docs/{rules,objectives,threats}/<slug>.md`. Upgrade and regenerate:

```bash
pip install 'opentide==0.1.8'
opentide generate docs
```

### Docs warn that `objective.priority: Critical` is not in `criticality::1.0`

Objective `priority` is an unconstrained alert-style string (High / Critical), not an incident `criticality::1.0` token. **0.1.7** looked it up in that vocab. **0.1.8** renders the author value as-is. Threat `criticality` and impact vocab spelling (including `Impairement`) are unchanged. Upgrade:

```bash
pip install 'opentide==0.1.8'
opentide generate docs
```

## Validation errors

### `invalid_ref` points at a parent object (`detection`, not `detection_model`)

`0.1.6` attributed `invalid_ref` to the nested object that contained the UUID. **0.1.7** reports the leaf field (`detection_model`, `objective.threats`, …). Vocabulary names also skip YAML list indices (`[0]`). Upgrade:

```bash
pip install 'opentide==0.1.8'
opentide validate --strict
```

### JSON `validate` stamps every check `invalid`

`--json` used a single repo-wide `valid`/`invalid` for every check name. A vocab failure then looked like a failing `uuid` or `metadata` check. **0.1.7** emits per-check `status`. Upgrade:

```bash
pip install 'opentide==0.1.8'
opentide validate --json
```

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
