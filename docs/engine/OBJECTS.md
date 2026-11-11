---
title: "Tide objects"
description: "How the language server checks Tide objects: validate's findings from opentide-workspace, and the query and block checks it adds."
---

# Tide objects

opentide LSP owns Tide diagnostics. Disable Red Hat YAML / yamlls on `objects/**`.

There is **no YAML formatter**. The LSP does not rename object `name`.

## Object checks: `validate`'s

The language server reports what `opentide validate` reports on an open
object (UC-2.6, [#821](https://github.com/opentidehq/opentide/issues/821)):
`opentide-workspace` loads the document's root once, with the editor's
buffers in place of their files, and runs `validate` (the queries check off:
the editor's own analysis below covers the queries) on the root's open
objects. Each finding keeps its code, severity, message and field path; its
range is `validate`'s 1-based line and code-point columns (end exclusive)
converted to LSP's 0-based lines and UTF-16 columns, and a finding without a
line is at the start of the file. A fix of one edit (a vocabulary or
reference typo) is the quick fix's suggestion. `cargo xtask lsp parity
--corpus faults` holds the two equal on every fault kind `validate` reports.

Every code, its meaning and its place are `validate`'s
([diagnostics](../cli/diagnostics.md)): `schema_validation`, `vocab_unknown`,
`invalid_uuid`, `missing_uuid`, `yaml_parse`, `duplicate_id`, `invalid_ref`,
`chaining_relation_unknown`, `deprecated_field`, `platform_not_enabled`,
`nested_object_file` and the others. A document outside every workspace
folder is checked in the workspace its `objects/` folder belongs to. One in
no `objects/` folder and outside every root (an unsaved buffer, a text sent
with `opentide/analyze`, a file `opentide-lsp analyze` finds no workspace
around) is checked as a file of its family's folder in a workspace of its
own, with the objects a browser host supplied: a reference to an object
neither holds is `invalid_ref`. While the configuration does not resolve, objects are not checked and
the editor says why once.

`filename_slug`, `missing_author`, `missing_organisation` and
`recommended_field_missing` are retired (KG-03, KG-05): `opentide lint`'s
`filename_mismatch` and `metadata_recommended` report those problems, and
the editor shows them once `lint::lint_file` is wired in
([#905](https://github.com/opentidehq/opentide/pull/905)). `lint.toml` no
longer changes what the language server reports.

Query extras (the engines add these inside an injected query, and on a raw query file):

- `kql_control_command_unsupported`
- `kql_unknown_operator`
- `kql_unknown_function`
- `kql_deprecated_function`
- `kql_deprecated_operator`
- `kql_unknown_table`
- `kql_render_not_valid`
- `kql_parse_error`
- `kql_where_not_first`
- `kql_unscoped_search`
- `kql_unscoped_union`
- `kql_wildcard_table`
- `kql_join_summarize_before_project`
- `kql_table_not_declared`
- `kql_unknown_column`
- `kql_type_mismatch`
- `spl_unknown_command`
- `spl_parse_error`
- `spl_wildcard`
- `spl_leading_not`
- `spl_subsearch_truncation`
- `spl_unknown_datamodel` (error: a near miss of a CIM data model or dataset, with a suggestion)
- `spl_unknown_datamodel_field` (error: a near miss of a CIM dataset field, `Processes.proces_name`, with a suggestion)
- `spl_dataset_not_declared` (warning: an index, sourcetype or base-search macro the workspace's Splunk log sources do not declare, when they declare that kind)
- `ecs_type_mismatch`, `ecs_unknown_field` (Elastic queries whose indices all hold ECS documents; `docs/engine/LANGUAGE.md`, Elastic indices and ECS)
- `elastic_dataset_not_declared` (`configurations.elastic.index`, `threat.index`, `data_view_id`, and ES|QL `FROM`, when the workspace declares Elastic datasets)
- `spl_search_operator`
- `spl_empty_command`
- `spl_empty_stage`
- `spl_command_without_pipe`
- `config_check_failed` (warning, `opentide-config` only: the host's configuration checker failed; [ARCHITECTURE.md](ARCHITECTURE.md#configuration-toml))
- `defender_output_columns`

A query `opentide new` left as a placeholder gets none of the diagnostics inside it, as `opentide validate` skips it (`opentide lint` reports it as a `placeholders` finding): its first line, or the line above it, ends in `# opentide:placeholder`, and that first line is still `...` (`query: |  # opentide:placeholder` over `...`, or `query: ...  # opentide:placeholder`). The rule is opentide's (`is_placeholder_query` in `opentide.validation.queries`) and holds for every query language (`crates/opentide-tide/src/placeholder.rs`). A query written under a marker left behind is checked. The block's own findings are not the query's: `elastic_dataset_not_declared` on `index`, `threat.index` or `data_view_id`, and `falco_unknown_source` on `configurations.sysdig.source`, stay editor (and `opentide lint`) findings, and `analyze_queries` does not attach them to a placeholder query, which `opentide validate` skips.

Severity of the KQL and SPL extras:

| Severity | KQL and SPL codes |
| --- | --- |
| warning | `kql_where_not_first`, `kql_unscoped_search`, `kql_unscoped_union`, `kql_wildcard_table`, `kql_join_summarize_before_project`, `kql_render_not_valid`, `kql_deprecated_function`, `kql_deprecated_operator`, `kql_table_not_declared`, `spl_wildcard`, `spl_leading_not`, `spl_subsearch_truncation`, `spl_dataset_not_declared`, `spl_empty_stage` |
| error | `kql_control_command_unsupported`, `kql_unknown_operator`, `kql_unknown_function`, `kql_parse_error`, `kql_unknown_column`, `kql_type_mismatch`, `spl_parse_error`, `spl_unknown_datamodel`, `spl_unknown_datamodel_field`, `spl_command_without_pipe` |
| either | `kql_unknown_table`: warning under `sentinel`, error under `defender_for_endpoint`. `spl_unknown_command`: warning, error within one edit of a known command ([spl/commands.md](spl/commands.md)). `spl_search_operator`: error, `=~` warning. `spl_empty_command`: by form ([spl/search-syntax.md](spl/search-syntax.md)) |

Slow-query rules: [kql/DESIGN.md](kql/DESIGN.md#slow-query-warnings), [spl/search-syntax.md](spl/search-syntax.md#wildcards), [spl/DESIGN.md](spl/DESIGN.md#truncated-shapes). Columns and declared tables: [kql/columns.md](kql/columns.md).

## Catalogs

Snapshot from `opentide generate schemas` into `data/catalogs/tide/`: what the engine uses when no host hands it others. The language server generates the same catalogs (`fields.json`, `deprecations.json`) from `opentide-schema` for each root, from the models and the root's resolved configuration, on a thread of its own once the root's workspace has loaded, and hands them to the engine (#926): hover, completion and highlighting follow the workspace's configuration. Until they are ready, the root uses the catalogs for the bundled configuration. The copy `opentide generate schemas` writes to `.opentide/lsp/catalogs/generated/` is not read. Hosts embedding the engine call `opentide_analysis::install_catalog`, `opentide_analysis::set_default_catalog` puts the host's own catalogs where the bundled ones would be used, and `opentide_analysis::bundled_catalog` returns the bundled catalogs so a host can check they match its own models.

Snippets come from the same templates `opentide generate` writes (`data/catalogs/tide/templates/`).

## UUID graph

- `textDocument/definition` and `references` on UUIDs
- Completions = names + UUIDs of the target type
- `workspace/symbol` by name / uuid / schema family
- `duplicate_id` across the workspace
- Inlay hints, symbol ranges and the other structure providers: [EDITORS.md](EDITORS.md#structure-providers)
