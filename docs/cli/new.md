---
title: opentide new
description: Scaffold a threat, objective or rule from the generated template, named the way lint expects and valid as soon as it is written.
---

# opentide new

Scaffold one object from the workspace's generated template. The new file validates as soon as it is written: required values nobody has chosen yet are filled with placeholders, and the command lists them so you replace them before review.

```bash
opentide new threat --name "Credential Dumping"
opentide new objective --name "Detect Credential Dumping" --threat 00000000-0000-4000-8001-000000000001
opentide new rule --name "Suspicious LSASS Access" --platform sentinel --objective 00000000-0000-4000-8002-000000000001
opentide validate --file objects/rules/suspicious-lsass-access.yaml
```

## Subcommands and options

| Subcommand | Options |
|------------|---------|
| `threat` | `--name`, `--path` |
| `objective` | `--name`, `--threat UUID` (repeatable: fills `objective.threats`), `--path` |
| `rule` | `--name`, `--platform` (repeatable: one configuration block each), `--objective UUID` (fills `detection_model`), `--path` |

| Option | Purpose |
|--------|---------|
| `--name` | The object's `name`. The filename is its slug |
| `--path` | A file to write, or a folder to write it in. A file name without `.yaml` or `.yml` gets `.yaml`, the only files the catalogue loads. Default: the family's folder from the workspace configuration (`objects/threats/`, `objects/objectives/`, `objects/rules/`) |
| `--platform` | `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `crowdstrike`, `harfanglab`, `carbon_black_cloud` or `elastic` |
| `--objective`, `--threat` | The UUID of an object already in the catalogue. A malformed UUID exits `2` with `usage_invalid_value`; one no object carries exits `2` with `reference_not_found` |

## What the new file holds

`new` starts from `.opentide/templates/<family>.<major>.<minor>.template.yaml` for the family's latest revision (`rule.1.1`), the template `opentide generate templates` writes, so the comments that list every optional key stay in the file. A rule keeps the commented blocks of the platforms it was given only; a comment under `configurations:` points at the template for the others. The editor's default revision in the workspace configuration can be older; a new object never starts on it, so `opentide rules unreviewed` does not list it for its schema. When the template or the family's JSON schema is missing, `new` runs `opentide generate templates schemas` first; its steps print, and `generated` in the JSON names them.

| Key | Value |
|-----|-------|
| `name` | `--name` |
| `metadata.uuid` | A fresh UUID v4. Signal UUIDs in an objective are fresh too |
| `metadata.created`, `modified` | Today, unquoted (`2026-10-23`) |
| `metadata.version` | `1` |
| `metadata.tlp` | `amber`, so a new object is never cleared for sharing by accident |
| `metadata.author` | `git config user.name`, read from the workspace. Left out, with a warning, when git has none |
| `metadata.organisation` | The `{uuid, name}` most objects in the catalogue carry. Left out, with a warning, when none does |
| Each `--platform` block | `enabled: true` and the first deployment status whose strategy is `INERT` (`DESIGN` by default), so the block deploys nothing until you move its status on. When no status has strategy `INERT`, the block is `enabled: false` and its status is a placeholder, with a warning |
| Detection logic in each block | Placeholders for what the platform needs to deploy: the `query`, Defender's `scope`, SentinelOne's `condition.single_event.query`, HarfangLab's `sigma` block, Sentinel's `scheduling.frequency` and `lookback` (`1h`) |
| Sentinel grouping | `grouping.event: SingleAlert` and `grouping.alert.enabled: false`, Sentinel's own defaults, which its deploy requires |
| `response` | The template's defaults (`alert_severity: Informational`), so a deploy never reads an empty block |
| Any other required value | A placeholder: the first value the generated schema allows, or `...` for free text. A required block whose keys are all optional keeps the defaults the template shows, or else gets its first key as a placeholder, so uncommenting another key keeps the YAML valid |

The filename follows the convention [`opentide lint`](./lint.md) checks: `slugify(name)`, with `-{uuid[:8]}` appended when that name is already taken in the folder. `new` never overwrites a file: a `--path` that exists, or a file that appears there while `new` runs, exits `1` with `path_exists`.

### Placeholders

Every line holding a placeholder ends in `# opentide:placeholder`. The file validates, so `validate` and the commit hook pass, but [`opentide lint`](./lint.md#placeholders) reports each marked line as a `placeholder` warning, and `lint --strict` in CI fails until you replace the value and delete the marker. An ATT&CK technique or a category picked to make the file valid is never mistaken for one somebody chose.

### Outside a workspace

`new` writes only into a workspace. When neither `.opentide/` nor `objects/` is in the directory `--repo` names, or the one discovery finds, it exits `1` with `workspace_not_found` and suggests `opentide setup`, the same test as `doctor`'s `workspace` check. Otherwise a stray `new` in your home directory would make it the workspace every folder below it discovers.

## Prompts

At an interactive terminal in `human` mode, `new` asks for a missing `--name`, and for `new rule`, which enabled platforms to add blocks for. Everywhere else it never prompts: with `--json`, without a terminal, or under a coding agent, a missing `--name` exits `2` with `failure.code` `usage_needs_input` and `failure.argument` `--name`. `--platform`, `--objective` and `--threat` are optional and never block.

## Output

The outcome line names the file and how many placeholders it holds, a note says how to find them, and the next step validates the file. When the workspace has no template or schema for the family yet, `new` runs `opentide generate templates schemas` first, and its steps print above. This is a tutorial workspace:

```text illustrative
✓ Created objects/rules/suspicious-lsass-access.yaml · 4 placeholders to replace
  note: each ends in '# opentide:placeholder'; opentide lint lists them
→ opentide validate --file objects/rules/suspicious-lsass-access.yaml · check it
```

A rule block for a platform the workspace has not enabled is written anyway, with a warning: [`validate`](./validate.md) reports it the same way, and deploy skips it.

### JSON

`--json` adds these keys to the [envelope](./json-output.md):

| Key | Value |
|-----|-------|
| `path` | The new file, relative to the current directory when it is inside it, otherwise to the workspace |
| `file_path` | The same file, absolute |
| `uuid` | `metadata.uuid` |
| `type`, `schema` | The family and its schema identifier (`rule`, `rule::1.1`) |
| `name`, `author`, `organisation`, `platforms` | What was written; `author` and `organisation` are `null` when left out |
| `placeholders` | Dotted keys whose value is a placeholder to replace |
| `detail` | The note human output prints under the outcome line; absent when there is no placeholder. `placeholders` lists the keys |
| `generated` | The generation phases that ran first; absent when none did |

`summary` holds `created` and `placeholders`; `next_actions` holds the `opentide validate --file` command.

## Source

`src/opentide/cli/commands/new.py`, `src/opentide/cli/services/new.py`
