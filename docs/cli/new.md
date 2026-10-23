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
| `--path` | A file to write, or a folder to write it in. Default: the family's folder from the workspace configuration (`objects/threats/`, `objects/objectives/`, `objects/rules/`) |
| `--platform` | `sentinel`, `defender_for_endpoint`, `splunk`, `sentinel_one`, `crowdstrike`, `harfanglab`, `carbon_black_cloud` or `elastic` |
| `--objective`, `--threat` | The UUID of an object already in the catalogue. A malformed UUID exits `2` with `usage_invalid_value`; one no object carries exits `2` with `reference_not_found` |

## What the new file holds

`new` starts from `.opentide/templates/<family>.<major>.<minor>.template.yaml`, the template `opentide generate templates` writes, so the comments that list every optional key stay in the file. When the template or the family's JSON schema is missing, `new` runs `opentide generate templates schemas` first and says so in a warning.

| Key | Value |
|-----|-------|
| `name` | `--name` |
| `metadata.uuid` | A fresh UUID v4. Signal UUIDs in an objective are fresh too |
| `metadata.created`, `modified` | Today, unquoted (`2026-10-23`) |
| `metadata.version` | `1` |
| `metadata.tlp` | `amber`, so a new object is never cleared for sharing by accident |
| `metadata.author` | `git config user.name`, read from the workspace. Left out, with a warning, when git has none |
| `metadata.organisation` | The `{uuid, name}` most objects in the catalogue carry. Left out when none does |
| Each `--platform` block | `enabled: true` and the first deployment status whose strategy is `INERT` (`DESIGN` by default), so the block deploys nothing until you move its status on |
| Any other required value | A placeholder: the first value the generated schema allows, or `...` for free text |

The filename follows the convention [`opentide lint`](./lint.md) checks: `slugify(name)`, with `-{uuid[:8]}` appended when that name is already taken in the folder. `new` never overwrites a file: a `--path` that exists exits `1` with `path_exists`.

## Prompts

At an interactive terminal in `human` mode, `new` asks for a missing `--name`, and for `new rule`, which enabled platforms to add blocks for. Everywhere else it never prompts: with `--json`, without a terminal, or under a coding agent, a missing `--name` exits `2` with `failure.code` `usage_needs_input` and `failure.argument` `--name`. `--platform`, `--objective` and `--threat` are optional and never block.

## Output

The outcome line names the file and how many placeholders it holds, a note lists them by key, and the next step validates the file. This is a tutorial workspace that had not generated its templates yet (the section headers `opentide generate` prints are left out):

```text illustrative
warning: Generated templates and schemas first: this workspace had none for rule
✓ Created objects/rules/suspicious-lsass-access.yaml · 2 placeholder values to replace
  note: replace the placeholder value of description, configurations.sentinel.query
→ opentide validate --file objects/rules/suspicious-lsass-access.yaml · check the new rule
```

A rule block for a platform the workspace has not enabled is written anyway, with a warning: [`validate`](./validate.md) reports it the same way, and deploy skips it.

### JSON

`--json` adds these keys to the [envelope](./json-output.md):

| Key | Value |
|-----|-------|
| `path` | The new file, relative to the current directory when it is inside it, otherwise to the workspace |
| `file_path` | The same file, absolute |
| `uuid` | `metadata.uuid` |
| `type`, `schema` | The family and its schema identifier (`rule`, `rule::1.0`) |
| `name`, `author`, `organisation`, `platforms` | What was written; `author` and `organisation` are `null` when left out |
| `placeholders` | Dotted keys whose value is a placeholder to replace |
| `generated` | The generation phases that ran first; absent when none did |

`summary` holds `created` and `placeholders`; `next_actions` holds the `opentide validate --file` command.

## Source

`src/opentide/cli/commands/new.py`, `src/opentide/cli/services/new.py`
