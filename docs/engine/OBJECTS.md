# Tide objects

opentide LSP owns Tide diagnostics. Disable Red Hat YAML / yamlls on `objects/**`.

There is **no YAML formatter**. The LSP does not rename object `name`.

## Types

| schema | refs |
| --- | --- |
| `rule::1.0`, `rule::1.1` | `detection_model` → objective UUID (optional; not schema-required). The field catalog is built from the newest revision, and `metadata.schema` offers both |
| `objective::1.0` | `objective.threats[]` → threat UUIDs |
| `threat::1.0` | `threat.impact` / `threat.leverage` are non-empty lists. `threat.chaining[].vector` / `relation` are not schema properties in 0.16.1 |

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
- `kql_deprecated_function`
- `kql_unknown_table`
- `kql_render_not_valid`
- `kql_parse_error`
- `kql_where_not_first`
- `kql_unscoped_search`
- `kql_unscoped_union`
- `kql_wildcard_table`
- `kql_join_summarize_before_project`
- `spl_unknown_command`
- `spl_parse_error`
- `spl_wildcard`
- `spl_leading_not`
- `spl_subsearch_truncation`
- `crowdstrike_unsupported` (never faked)
- `defender_output_columns`

## Catalogs

Snapshot from `opentide generate schemas` into `catalogs/tide/`. That is the fallback: a workspace that ran `opentide generate schemas` has its own catalogs under `.opentide/lsp/catalogs/generated/`, in the same shapes, and they replace the bundled ones when the server starts (`initialize`), in `opentide-lsp analyze`, and in the `opentide` CLI:

- `fields.json` replaces `catalogs/tide/generated/fields.json`: hover, completion and the enum checks follow the workspace's schemas, custom vocabulary included.
- `deprecations.json` adds `deprecated_field` warnings on top of `catalogs/tide/generated/deprecations.json`.

A file that does not parse is reported on stderr, and the bundled catalogs are used. Hosts embedding the engine call `opentide_analysis::install_catalog`.

Snippets come from the same templates `opentide generate` writes (`catalogs/tide/templates/`).

## UUID graph

- `textDocument/definition` and `references` on UUIDs
- Completions = names + UUIDs of the target type
- `workspace/symbol` by name / uuid / schema
- `duplicate_id` across the workspace
