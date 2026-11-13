---
title: Configuration models
description: The model of each .opentide/configurations/ file, how its layers merge, its JSON Schema, and how a file is checked.
---

# Configuration models

Every file under `.opentide/configurations/` has one model in opentide's Rust core (`opentide-schema`'s `configuration` module). The command line validates the merged document (bundled file, then your workspace file, then the parent instance) against that model when it reads the file, and the JSON Schema of the file is generated from the same model. There is no second, hand-written schema to drift from the command line.

| File | Model | Schema file |
|------|-------|-------------|
| `paths.toml` | `PathsConfiguration` | `paths.schema.json` |
| `deployment.toml` | `DeploymentConfiguration` | `deployment.schema.json` |
| `visibility.toml` | `VisibilityConfig` (`visibility::1.0`) | `visibility.schema.json` |
| `documentation.toml` | `DocumentationConfiguration` | `documentation.schema.json` |
| `sharing.toml` | `SharingConfiguration`, items `MispIntegration` (`sharing::misp::1.0`) | `sharing.schema.json` |
| `platforms/<id>.toml` | `SentinelConfiguration`, `SplunkConfiguration`, … | `platforms.<id>.schema.json` |
| any other `platforms/*.toml` | `PlatformConfiguration` | `platforms.schema.json` |

`resources.toml` and `lint.toml` have no model here: `lint.toml` is checked by `opentide lint`'s own loader. `global.toml`, `schema.toml` and a `systems/` folder are not read: every command refuses them with `retired_configuration_file`, naming what replaces each.

Unknown keys are rejected everywhere except a top-level `sharing.toml` array that names a connector opentide does not know (`[[opencti]]`), which is skipped with an `unknown_connector` warning.

A `$NAME` placeholder is a valid value for any tenant `setup` key; the models check the file as written, and the variable is read when the tenant loads. An error never repeats the offending value, since `setup` tables hold credentials.

## Declared datasets

A `visibility.toml` log source (`VisibilityLogSource`) is one dataset, and its `name` is that dataset: the KQL table for `sentinel` and `defender_for_endpoint`, the sourcetype for `splunk`, the index pattern for `elastic` . It takes `name`, `description`, `system`, `tenants`, `assets`, `references` and `columns`, a mapping of column name to a column (`type` from the system's column types, optional `description`).

Each violation is an issue on the key at fault: an empty `name` or a name declared twice for one `system` (`schema_validation`, `("logsources", "1", "name")`), a column type outside the system's set (`("logsources", "0", "columns", "Actor_s", "type")`), `columns` on a system with no type set, and an unknown key (`unknown_key`). The 0.20.0 keys (`tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views`, `ecs`) fail as `schema_validation` on that key, with a message that says what to do instead.

The analysis engine reads the same keys from the file's text, so nothing is generated in between: `opentide validate`, `lint`, the TUI and the language server read the workspace's `visibility.toml` for the query checks. `*` in a name matches any run of characters.

## The JSON Schemas

The schemas are generated from the models: the language server offers them for hover and completion in `.opentide/configurations/*.toml` in every editor host. There is one per file kind and a router that maps each file name (`deployment.toml`, `platforms/sentinel.toml`, `platforms/*.toml`, `sharing.toml`, …) to its schema and says how layers merge: `deep` (scalars replace, tables merge, arrays replace) or, for `sharing.toml`, `by-name`. Field descriptions are the hover text; enums (`strategy`, tenant `strategies`, documentation `flavor`, `max_tlp`, object families) are JSON Schema enums. The enriched `visibility.1.0.schema.json` that `opentide generate schemas` writes into `.opentide/schemas/` is instance-specific.

## Checking one file

`opentide validate --check configuration` (or `Workspace.validate(check="configuration")`) checks every file, and the language server checks the buffer you edit, with the same codes, field paths and severities that `validate` reports for objects. A client file is a partial override, so it is merged onto the layers before it (the bundled file by default) and required keys apply to that merge, never to the file alone.

```python
from opentide import Workspace

validation = Workspace.open(".").validate(check="configuration")
codes = [issue["code"] for issue in validation.report["issues"]]
```

| Code | Severity | Raised for |
|------|----------|------------|
| `missing_field` | error | A required key is missing from the merged document |
| `unknown_key` | error | A key the model does not declare |
| `schema_validation` | error | A value of the wrong type or outside its enum |
| `promotion_target_unknown` | error | `promotion.promotion_target` is not a `[[statuses]]` name |
| `asset_unknown` | warning | A visibility log source or detector names an undeclared asset |
| `config_parse` | error | The text is not valid TOML |
| `not_a_configuration_file` | warning | The path is not a file opentide reads, or has no model (`resources.toml`, `lint.toml`) |

A `[[responders]]` entry that does not match its model is a warning: the loader keeps an entry that has a name and skips one that has none. A platform file is checked with the model of the platform its file name names (`platforms/splunk.toml` is Splunk's). A platform plugin's file is open: only `[platform]`, `[[modifiers]]` and the tenant `name`, `strategies`, `manual` and `ssl` are checked. A path under `configurations/sharing/` returns `sharing_directory`, and one under `.opentide/schemas/` is not a configuration file.

`sharing.toml` field paths point into the checked file: `("misp", "<index>", "<key>")`, with the block name in `context.block`. A finding on a block the file does not hold (it comes from an earlier layer) has an empty path, and `context.layer` / `context.index` say where it is. `sharing.toml` returns the `sharing-config` codes of the [sharing spec](/docs/specifications/specs/sharing/): `missing_field`, `duplicate_name`, `name_invalid`, `unknown_key`, `max_tlp_unknown`, `organisation_uuid_invalid`, `object_type_unknown`, `sharing_directory`, `rule_status_unknown` (errors), and `api_key_literal`, `unknown_connector` (warnings). `api_key` must be `${NAME}` with an uppercase name; a literal key is a warning, and the warning names the block, never the key.

## Source

`crates/opentide-schema/src/configuration/`, `crates/opentide-schema/src/generate/configuration.rs`
