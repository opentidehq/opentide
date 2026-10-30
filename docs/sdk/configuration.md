---
title: Configuration models
description: Pydantic models of each .opentide/configurations/ file, their JSON Schema export, and the per-file issue helper editors use.
---

# Configuration models

Every file under `.opentide/configurations/` has one Pydantic model in `opentide.models.configuration`. The CLI validates the merged document (bundled file, then your workspace file, then the parent instance) against that model when it reads the file, and the JSON Schema of the file is `model_json_schema()` of the same model. There is no second, hand-written schema to drift from the CLI.

| File | Model | Schema file |
|------|-------|-------------|
| `paths.toml`, legacy `global.toml` | `PathsConfiguration` | `paths.schema.json` |
| `deployment.toml` | `DeploymentConfiguration` | `deployment.schema.json` |
| `schema.toml` | `SchemaConfiguration` | `schema.schema.json` |
| `visibility.toml` | `VisibilityConfig` (`visibility::1.0`) | `visibility.schema.json` |
| `documentation.toml` | `DocumentationConfiguration` | `documentation.schema.json` |
| `sharing.toml` | `SharingConfiguration`, items `MispIntegration` (`sharing::misp::1.0`) | `sharing.schema.json` |
| `platforms/<id>.toml` | `SentinelConfiguration`, `SplunkConfiguration`, … | `platforms.<id>.schema.json` |
| any other `platforms/*.toml` | `PlatformConfiguration` | `platforms.schema.json` |

`resources.toml` and `lint.toml` have no model here: `lint.toml` is checked by `opentide lint`'s own loader.

Unknown keys are rejected everywhere except the retired `[vocabulary]` table of `schema.toml` and a top-level `sharing.toml` array that names a connector opentide does not know (`[[opencti]]`), which is skipped with an `unknown_connector` warning.

A `$NAME` placeholder is a valid value for any tenant `setup` key; the models check the file as written, and the variable is read when the tenant loads. An error never repeats the offending value, since `setup` tables hold credentials.

```python
from opentide.models.configuration import configuration_model_for

model = configuration_model_for(".opentide/configurations/platforms/sentinel.toml")
model.model_validate({"platform": {"enabled": True}})
```

## Declared datasets

A `visibility.toml` log source may name the datasets it fills: `tables` (`sentinel`, `defender_for_endpoint`), `indexes`, `sourcetypes` and `macros` (`splunk`), `indices`, `data_views` and `ecs` (`elastic`). `VisibilityLogSource` rejects a field its `system` does not read, and an empty name, as a `schema_validation` issue on that field (`("logsources", "0", "tables")`). `opentide.models.visibility.DATASET_FIELDS` maps each system to its fields.

The analysis engine reads the same fields from the file's text, so nothing is generated in between. `opentide.analysis.install_workspace_visibility(root)` hands it `root/.opentide/configurations/visibility.toml` for the query checks (`opentide validate`, `lint` and the TUI call it); `opentide._native.install_visibility(text)` takes the text directly, and `install_catalog(..., visibility=text)` installs it with the Tide catalogs. `*` in a name matches any run of characters.

## Exporting the JSON Schemas

```python
from pathlib import Path

from opentide.generation.configuration_schemas import (
    export_configuration_schemas,
    generate_configuration_schema,
)

schema = generate_configuration_schema("deployment.toml")
export_configuration_schemas(Path("catalogs/configuration"))
```

The same export runs from the command line:

```bash
python -m opentide.generation.configuration_schemas catalogs/configuration
```

It writes one schema per file kind and `configurations.router.json`, which maps each file name (`deployment.toml`, `platforms/sentinel.toml`, `platforms/*.toml`, `sharing.toml`, …) to its schema and says how layers merge: `deep` (scalars replace, tables merge, arrays replace) or, for `sharing.toml`, `by-name`. Field descriptions are the hover text; enums (`strategy`, tenant `strategies`, documentation `flavor`, `max_tlp`, object families) are JSON Schema enums. These schemas are instance-independent; the enriched `visibility.1.0.schema.json` that `opentide generate schemas` writes into `.opentide/schemas/` is unchanged.

## Checking one file

`configuration_file_issues` returns `ValidationIssue` records (`code`, `field_path`, `severity`, `message`) for one file, the same shape `validate` reports for objects. A client file is a partial override, so it is merged onto the layers before it (the bundled file by default) and required keys apply to that merge, never to the file alone.

```python
from opentide.validation.configuration import configuration_file_issues, configuration_text_issues

issues = configuration_file_issues("deployment.toml", {"promotion": {"promotion_target": "LIVE"}})
# [ValidationIssue(code="promotion_target_unknown", field_path=("promotion", "promotion_target"), ...)]

issues = configuration_text_issues("sharing.toml", buffer_text, status_names={"PRODUCTION"})
```

| Code | Severity | Raised for |
|------|----------|------------|
| `missing_field` | error | A required key is missing from the merged document |
| `unknown_key` | error | A key the model does not declare |
| `schema_validation` | error | A value of the wrong type or outside its enum |
| `promotion_target_unknown` | error | `promotion.promotion_target` is not a `[[statuses]]` name |
| `asset_unknown` | warning | A visibility log source or detector names an undeclared asset |
| `identifier_mismatch` | error | `[platform] identifier` differs from the file name stem |
| `config_parse` | error | The text is not valid TOML |
| `not_a_configuration_file` | warning | The path is not a file opentide reads, or has no model (`resources.toml`, `lint.toml`) |

A `[[responders]]` entry that does not match its model is a warning: the loader keeps an entry that has a name and skips one that has none. A platform file is checked with the model of the platform the loader files it under (`[platform] identifier`, then `[tide] identifier`, then the file name). A platform plugin's file is open: only `[platform]`, `[[modifiers]]` and the tenant `name`, `strategies`, `manual` and `ssl` are checked. A path under `configurations/sharing/` returns `sharing_directory`, and one under `.opentide/schemas/` is not a configuration file.

`sharing.toml` field paths point into the checked file: `("misp", "<index>", "<key>")`, with the block name in `context.block`. A finding on a block the file does not hold (it comes from an earlier layer) has an empty path, and `context.layer` / `context.index` say where it is. `sharing.toml` returns the `sharing-config` codes of the [sharing spec](/docs/specifications/specs/sharing/): `missing_field`, `duplicate_name`, `name_invalid`, `unknown_key`, `max_tlp_unknown`, `organisation_uuid_invalid`, `object_type_unknown`, `sharing_directory`, `rule_status_unknown` (errors), and `api_key_literal`, `unknown_connector` (warnings). `api_key` must be `${NAME}` with an uppercase name; a literal key is a warning, and the warning names the block, never the key.

| Argument | Default | Purpose |
|----------|---------|---------|
| `earlier_layers` | the bundled file | Layers the file overrides; pass the workspace file when checking a parent instance |
| `later_layers` | none | Layers that override the file |
| `status_names` | the workspace's statuses, read from an absolute path; else the bundled ones | Merged `deployment.toml` status names, for `sharing.toml` `rule_statuses` |
| `sharing_directory` | `False` | Report `sharing_directory` when `configurations/sharing/` exists |
| `partial` | `False` | Skip required-key checks, for a layer checked without the layers it overrides |

## Source

`src/opentide/models/configuration/`, `src/opentide/generation/configuration_schemas.py`, `src/opentide/validation/configuration.py`
