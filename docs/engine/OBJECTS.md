# Tide objects

opentide LSP owns Tide diagnostics. Disable Red Hat YAML / yamlls on `objects/**`.

There is **no YAML formatter**. The LSP does not rename object `name`.

## Types

| schema | refs |
| --- | --- |
| `rule::1.0`, `rule::1.1` | `detection_model` → the UUID of an objective, or of a signal an objective declares (`objective.signals.<i>.uuid`), as `opentide validate` accepts both (optional; not schema-required). Each revision has its own fields: an object is checked against the revision its `metadata.schema` names (required fields, keys the revision does not define, enums). A revision the catalog does not know takes the newest one's fields, without the unknown-key check. `metadata.schema` offers both |
| `objective::1.0` | `objective.threats[]` → threat UUIDs |
| `threat::1.0` | `threat.impact` / `threat.leverage` are non-empty lists. `threat.chaining[].vector` / `relation` are not schema properties |

The vocabulary fields of `threat` (`impact`, `leverage`, `severity`,
`viability`) are checked against the catalog's field shape. A list field
written as one YAML string (`impact: High`) is `schema_validation`: "{path}
must be a YAML list of {name} vocabulary names, not a single string". The
diagnostic's `suggestion` is `- {text}`. A list shorter than the field's
`min_items` is also `schema_validation`. Unknown names inside the list are
`vocab_unknown`. Each diagnostic's range is the field's key.

## Diagnostic codes (CLI-compatible)

Pydantic stays CLI authority. LSP emits the same `{code, field_path, severity}`:

- `schema_validation`
- `vocab_unknown`
- `invalid_uuid`
- `duplicate_id`
- `invalid_ref` — error on the reference field when the UUID names nothing in the workspace: a rule's `detection_model` that is neither an indexed objective nor a signal one declares, an objective's `objective.threats` entry, or a threat's `threat.chaining.<i>.vector` that is not an indexed threat.
- `chaining_relation_unknown`
- `deprecated_field`
- `filename_slug` — warning on the `name` value. A non-empty file stem must equal the stem `[filenames] style` derives from the name, or start with `{stem}-`. With `style = "slug"` (the default) that is `slugify(name)`: ASCII alphanumerics lowercased, each run of other characters one `-`, and `-` trimmed from both ends (`Sentinel KQL Rule` → `sentinel-kql-rule`). With `style = "name"` it is the name less `<>:"\/|?*`, control characters, the spaces and dots around it and a trailing `.debug`, as `opentide lint` derives it. `style = "none"` compares no stem. The file stem is the file name less `.yaml` (or `.yml`) and a `.debug` infix, as opentide's `object_stem` reads it. Suggestion text is `{stem}.yaml`, or `{stem}.debug.yaml` for a debug file. A document that is not a file (`untitled:Untitled-1`) gets neither filename check.
- `filename_pattern` — warning on the `name` value when the file stem does not match `[filenames] pattern` (the whole stem less a `.debug` infix, as `re.fullmatch` matches it). A pattern the Rust `regex` crate cannot compile (look-around, backreferences) is not checked here; `opentide lint` still checks it.
- `missing_author` — warning on the `metadata` key when `metadata` has no `author` and `[metadata] required` names it (the default does).
- `missing_organisation` — warning on the `metadata` key when `metadata` has no `organisation` and `[metadata] required` names it (the default does).

### `lint.toml`

The four checks above follow the root's `.opentide/configurations/lint.toml` as `opentide lint` does ([#214](https://github.com/opentidehq/language-server/issues/214)), so the editor and the CLI agree:

| `lint.toml` | Decides |
| --- | --- |
| `[filenames] enabled = false` | no `filename_slug` or `filename_pattern` |
| `[filenames] style`, `pattern`, and `[filenames.threats]`, `[filenames.objectives]`, `[filenames.rules]` (a key a kind leaves unset comes from `[filenames]`) | `filename_slug`, `filename_pattern` |
| `[metadata] enabled = false` | no `missing_author` or `missing_organisation` |
| `[metadata] required` | which of `missing_author` and `missing_organisation` apply |
| `[filenames] severity`, `[metadata] severity` (`error`, `warning`, `info`) | the findings' severity |

Without a `lint.toml` the defaults are `opentide lint`'s: slug filenames, no pattern, `author` and `organisation` required. Other keys `required` names (`reviewed`) have no engine finding. The language server reads the file of the document's root: the editor's buffer while it is open, else the file on disk, else the root's `lint.toml` among the documents a browser host supplies; editing it re-checks open documents. Another host installs it with `opentide_analysis::install_lint`. The host checks the file itself (`opentide-config`); a value of the wrong type keeps its default here. `testdata/conformance/lint-toml` is a workspace with its own conventions and `opentide-lint.json` what `opentide lint` reports for it (`scripts/opentide_lint_findings.py` records it); `crates/opentide-analysis/tests/lint_settings.rs` checks the engine reports the same.

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
- `ecs_type_mismatch`, `ecs_unknown_field` (Elastic queries whose indices all hold ECS documents; `docs/LANGUAGE.md`, Elastic indices and ECS)
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

Snapshot from `opentide generate schemas` into `catalogs/tide/`. That is the fallback: a workspace that ran `opentide generate schemas` has its own catalogs under `.opentide/lsp/catalogs/generated/`, in the same shapes, and they replace the bundled ones when the server starts (`initialize`), in `opentide-lsp analyze`, and in the `opentide` CLI:

- `fields.json` replaces `catalogs/tide/generated/fields.json`: hover, completion and the enum checks follow the workspace's schemas, custom vocabulary included.
- `deprecations.json` adds `deprecated_field` warnings on top of `catalogs/tide/generated/deprecations.json`.

A file that does not parse is reported on stderr, and the bundled catalogs are used. Hosts embedding the engine call `opentide_analysis::install_catalog`, `opentide_analysis::set_default_catalog` puts the host's own catalogs where the bundled ones would be used, and `opentide_analysis::bundled_catalog` returns the bundled catalogs so a host can check they match its own models.

Snippets come from the same templates `opentide generate` writes (`catalogs/tide/templates/`).

## UUID graph

- `textDocument/definition` and `references` on UUIDs
- Completions = names + UUIDs of the target type
- `workspace/symbol` by name / uuid / schema family
- `duplicate_id` across the workspace
- Inlay hints, symbol ranges and the other structure providers: [EDITORS.md](EDITORS.md#structure-providers)
