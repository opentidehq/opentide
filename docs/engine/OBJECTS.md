# Tide objects

OpenTide LSP owns Tide diagnostics. Disable Red Hat YAML / yamlls on `objects/**`.

There is **no YAML formatter**. The LSP does not rename object `name`.

## Types

| schema | refs |
| --- | --- |
| `rule::1.0` | `detection_model` → objective UUID (optional; not schema-required) |
| `objective::1.0` | `objective.threats[]` → threat UUIDs |
| `threat::1.0` | `threat.impact` / `threat.leverage` are non-empty lists. `threat.chaining[].vector` / `relation` are not schema properties in 0.5.0 |

## Diagnostic codes (CLI-compatible)

Pydantic stays CLI authority. LSP emits the same `{code, field_path, severity}`:

- `schema_validation`
- `vocab_unknown`
- `invalid_uuid`
- `duplicate_id`
- `invalid_ref`
- `chaining_relation_unknown`
- `deprecated_field`
- `filename_slug`
- `missing_author`
- `missing_organisation`

Query extras (engine may add these inside `query: |`):

- `kql_control_command_unsupported`
- `kql_unknown_operator`
- `kql_unknown_function`
- `kql_unknown_table`
- `kql_render_not_valid`
- `kql_parse_error`
- `spl_unknown_command`
- `spl_parse_error`
- `crowdstrike_unsupported` (never faked)
- `defender_output_columns`

## Catalogs

Snapshot from `opentide generate schemas` into `catalogs/tide/`. A workspace file `.opentide/lsp/catalogs/generated/deprecations.json` (same shape as the bundled catalog) adds `deprecated_field` warnings on top of `catalogs/tide/generated/deprecations.json`.

Snippets come from the same templates `opentide generate` writes (`catalogs/tide/templates/`).

## UUID graph

- `textDocument/definition` and `references` on UUIDs
- Completions = names + UUIDs of the target type
- `workspace/symbol` by name / uuid / schema
- `duplicate_id` across the workspace
