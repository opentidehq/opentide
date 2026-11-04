---
title: opentide commands
description: Every command and option, read from the CLI itself, for agents and editors.
---

# opentide commands

`opentide --json commands` prints every visible command, read from the CLI itself, so it never drifts from what the CLI accepts:

```bash
opentide --json commands
```

```json illustrative
{
  "program": "opentide",
  "version": "0.18.0",
  "global_options": [
    {
      "name": "repo",
      "flags": ["--repo"],
      "secondary_flags": [],
      "type": "string",
      "choices": null,
      "default": null,
      "required": false,
      "multiple": false,
      "is_flag": false,
      "envvars": ["OPENTIDE_REPO_ROOT"],
      "help": "Repository root"
    }
  ],
  "commands": [
    {
      "path": "validate query",
      "name": "query",
      "summary": "Check rule queries offline, or on the tenants (--live)",
      "help": "Check rule queries offline with the analysis engine, or on the tenants (--live). …",
      "group": false,
      "runs_alone": true,
      "subcommands": [],
      "deprecated": false,
      "arguments": [],
      "options": [
        {
          "name": "platform",
          "flags": ["--platform"],
          "type": "choice",
          "choices": ["sentinel", "splunk", "crowdstrike", "…"],
          "required": true,
          "…": "…"
        }
      ],
      "example": "opentide validate query --platform sentinel --live",
      "output_schema": {
        "anyOf": [
          { "$ref": "#/$defs/QueryValidationResult" },
          { "$ref": "#/$defs/CommandError" }
        ]
      }
    }
  ],
  "$defs": { "QueryValidationResult": { "…": "…" }, "CommandError": { "…": "…" } },
  "ok": true,
  "status": "completed",
  "message": "58 commands",
  "summary": { "commands": 58, "groups": 15 },
  "…": "envelope keys"
}
```

| Key | Meaning |
|-----|---------|
| `version` | The installed opentide version: key a cached copy of the tree on it. |
| `global_options` | The root options (`--repo`, `--json`, …). `--json`, `--no-color`, `--debug` and `--quiet` may also follow the command. |
| `environment` | `[{name, meaning}]`: every `OPENTIDE_*` variable opentide reads, those behind `--repo`, `--data` and `--proxy` included, plus `NO_COLOR` and the agent-detection variables (`AI_AGENT`, `CLAUDECODE`, …). [Global options](./global-options.md#environment-variables) lists them. |
| `commands` | Flat and depth-first, in `--help` order. `path` is the words to type; a group's `subcommands` are the entries whose path extends it. Hidden commands and options are left out. |
| `runs_alone` | `false` for a group that only prints its help (`opentide mcp`): run one of its subcommands. |
| `options[].type` | `string`, `integer`, `number`, `boolean`, `choice` (with `choices`), `path`, … A `string` the command checks itself lists its values in `choices` too: `validate --type`, `deploy --strategy`, `info`'s section. `share --target` takes the configured targets, so it has none. |
| `options[].envvars` | Environment variables that set the option. |
| `example` | The first example in the command's `--help`. A command whose help has none yet gets a placeholder: the command with its required arguments and options filled in. A placeholder names the command but may not run as it is (`opentide deploy` still needs `--strategy`). |
| `output_schema` | The JSON Schema of the document the command prints with `--json`: its own result, or `CommandError` for a usage error. A group that only prints its help prints a document only for a usage error, such as an unknown subcommand, so its schema is `CommandError`. `null` for `mcp start`, `lsp start` and `serve`, which print JSON-RPC. See [JSON output](./json-output.md#output-schemas). |
| `$defs` | The schemas each `output_schema` refers to. |

Without `--json`, `opentide commands` prints the tree, one command per line with its summary, a subcommand indented under its group, and ends with `✓ 58 commands`. Listing the tree imports every command's module once; it never loads the detection registry.

```bash
opentide commands
```

```text output-of="opentide commands"
validate         Validate objects and queries
  query          Check rule queries offline, or on the tenants (--live)
query            Run a read-only query on platform tenants and show rows
```

## Exit codes

`opentide commands` exits `0`. It takes no options and no arguments of its own; the root options (`--json`, `--repo`, …) apply.

## Source

`src/opentide/cli/commands/introspect.py`.
