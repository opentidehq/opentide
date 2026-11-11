# Architecture

opentide LSP is an I/O-free Rust engine plus thin hosts.

```
editors / @opentide/lsp-client / WASM worker
                │
         opentide-lsp  (stdio JSON-RPC, CLI analyze/highlight)
                │
         opentide-analysis  (WorkspaceHost)
          /        |         \
    opentide-{kql,spl}  opentide-{esql,eql,kuery,lucene}  opentide-tide
          \        |         /
            opentide-syntax + opentide-highlight
                      |
               opentide-core
```

## Layers

- **Grammars** (`grammars/tree-sitter-opentide-{kql,spl,esql,eql,kuery,lucene}`) vendored `parser.c`. CI regenerates and fails on drift.
- **Catalogs** (`catalogs/`) compiled into the engine with `include_str!`. Workspace override path: `.opentide/lsp/catalogs/`.
- **HighlightSpec** (`highlights/spec.toml`) is frozen. Capture rename = major. Generated tmLanguage / Monaco / Helix maps are CI-checked.
- **Injection**: block-scalar indent is stripped for analysis; tokens are remapped onto YAML coordinates.

## Injection table

| Field path | Language |
| --- | --- |
| `configurations.sentinel.query` | KQL |
| `configurations.defender_for_endpoint.query` | KQL |
| `configurations.splunk.query` | SPL |
| `configurations.splunk.search` (legacy) | SPL |
| `configurations.elastic.query` with `type: esql` | ES\|QL |
| `configurations.elastic.query` with `type: eql` | EQL |
| `configurations.elastic.query` with `type: query`, `threshold`, `new_terms`, or `threat_match` | `language: kuery` (default) → Kibana KQL; `language: lucene` → Lucene |
| `configurations.elastic.threat.query` | `threat.language` (`kuery` default, or `lucene`) |
| `configurations.elastic.query` with `type: machine_learning` | none |
| `configurations.carbon_black_cloud.query` | Lucene (Carbon Black dialect) |
| `configurations.graylog.query` | Lucene (Graylog dialect); the block's constraint codes, `aggregation.condition` grammar included, are `crates/opentide-tide/src/graylog.rs` |
| `configurations.sysdig.condition` | Falco condition, with the block's `macros` and `lists` in scope and the fields of its `source` (`syscall` default); a fragment that starts with `and`/`or` when the block sets `append_to_rule` |
| `configurations.sysdig.macros[].condition` | Falco condition, same scope |
| `configurations.sysdig.output` | Falco output template, read as libsinsp's formatter reads it: `%field` and `%transformer(...)` tokens compiled for the `source` |
| `configurations.sysdig.exceptions` | Not a query: Falco's exception rules (operators, counts, fields) and the text Falco writes from them, compiled with the condition (`opentide_falco::exceptions`, reported on the YAML keys) |
| `response.procedure.searches[].query` with `system: elastic` | `language` on the entry (`esql`, `eql`, `kuery`, `lucene`); none when omitted (specifications#58) |
| `response.procedure.searches[].query` with `system: sentinel`, `defender_for_endpoint`, `splunk`, `carbon_black_cloud`, `graylog` or `crowdstrike` | that platform's language and profile, whatever the order of the entry's keys; any other `system` (`Sentinel`, `Splunk ES`) is free text and is not analysed |
| `configurations.splunk.actions.notable.drilldown.search` | none: a `$token$` template, not the rule's query |
| `configurations.crowdstrike.query` | CQL, with the Next-Gen SIEM correlation-rule checks ([CQL.md](CQL.md)) |
| `configurations.harfanglab.yara.signature`, `configurations.bitdefender.yara.signature` | YARA, under that platform's profile ([YARA.md](YARA.md)); a YAML alias is `yara_signature_alias` and is not analysed |
| `configurations.harfanglab.yara.strings` + `.condition` + `.imports` | YARA: one injection spanning several scalars. The text analysed is the rule deploy assembles (`compile_yara_deployment`): `import` lines, `rule <name> {`, generated meta, and each body's lines indented after `strip()`. The bodies and the module names map back byte for byte; the generated text is marked synthetic (`InjectionPart`), gets no token, and a finding there is reported by the block's constraint codes instead (`crates/opentide-tide/src/yara.rs`) |
| `description` / `procedure.analysis` / `recommendation` / other `markdown = true` fields | Markdown (HighlightSpec `markdown.*`) |

A key is a query only at these paths, read from the YAML structure (`crates/opentide-tide/src/injection.rs`): a `query:` or `search:` anywhere else is not one. Each query is reported at its own path, list items by index (`response.procedure.searches.0.query`), with its platform (`InjectedQuery::platform`, `QueryReport::platform`), since a hunt's path does not name it. The text analysed is the scalar's value, as a YAML loader reads it: block scalars of either style with any chomping or indentation indicator (`|`, `>-`, `|2`), plain scalars over several lines, and single- or double-quoted scalars with their escapes. Every byte of the value maps back to the source byte it comes from, so a diagnostic in a folded or quoted query lands on its line and column in the file.

Tide object intelligence is generated by opentide itself: [`scripts/sync_opentide_schemas.py`](../scripts/sync_opentide_schemas.py) runs opentide's generator (`opentide.generation.lsp_catalog`, the one `opentide generate schemas` uses for workspace catalogs), so the two never differ. The LSP loads [`catalogs/tide/generated/fields.json`](../catalogs/tide/generated/fields.json), keyed by schema id (`rule::1.0`, `rule::1.1`) and YAML path, and resolves each object through its `metadata.schema`. JSON Schema supplies titles, types, required, enums, consts, and which objects are closed (`additionalProperties: false`). Pydantic `tide.template.multiline` / `hide` supply markdown and hidden flags the schema emitter drops, and `TideModel.__legacy_keys__` the legacy spellings a model's validator accepts (`legacy`). Capture rename in HighlightSpec is a **major**; adding `markdown.*` / `macro` is a minor (`0.2.0`).

Every field row in `fields.json` has the capture `tide.property`, so a
schema key keeps one color however deeply it nests, list items included
(`- purpose:`). opentide's generator sets it; a test in
`crates/opentide-highlight/src/lib.rs` fails if any row differs.
`tide.keyword` stays in HighlightSpec and no row uses it. Values keep their
own captures (markdown, enums as `constant`, UUIDs as `tide.uuid`, injected
queries). A key with no field row is `property`. LSP semantic tokens map
`tide.property` → `property`. JSON `highlight()` still emits `tide.property`.

## Diagnostics

**Elastic stack version.** ES|QL availability is checked against the lowest `setup.version` declared across a rule block's target tenants in `.opentide/configurations/platforms/elastic.toml` (the block's `tenants`, or every tenant). A target without a version, or no configuration, means the 8.19 floor (specifications#59). A declared 9.4+ or Serverless target also drops `esql_metadata_id`, because Kibana adds `METADATA _id` itself there.

Pydantic remains CLI authority. The LSP emits the same `{code, field_path, severity}` with real ranges. The engine may add **extra** query diagnostics inside `query: |`.

## Configuration TOML

`.opentide/configurations/**/*.toml` is `opentide-config` (#158). opentide decides what is wrong with these files. The engine only says where:

- **The host checks.** A host installs a checker with `opentide_analysis::set_configuration_checker`. `opentide lsp start` installs opentide's `configuration_text_issues`, the check `opentide validate` runs. It merges the buffer onto the bundled file and the parent instance, checks the models, and runs the checks a schema cannot state (`rule_status_unknown`, `promotion_target_unknown`, `asset_unknown`, `identifier_mismatch`, the `sharing-config` codes). The engine calls the checker with the buffer's path, its text and the other open configuration buffers (`ConfigRequest`). It gets back `{code, field_path, severity, message}` (`ConfigIssue`).
- **The engine places.** `toml_edit` spans turn each `field_path` into a range:
  - a path that exists: its last key, or an array-of-tables entry's `[[header]]`;
  - a path that exists only in part (a missing key): the deepest key or header that exists, and the message names the path (`misp[1].url: Field required`);
  - an empty path, or one held by another layer: the first line;
  - `config_parse`: where `toml_edit` stops parsing.

  A checker that fails gives one `config_check_failed` warning.
- **The host's schemas** (`install_configuration_schemas`: the router and one JSON Schema per file, as opentide's `generate_configuration_schemas()` returns them) give hover and completion. Hover shows title, type, description, allowed values and default, never the buffer's value. Completion offers the keys a table may still take, table names in a header, and allowed values after `=`. A walker reads the schema (`$ref`, `anyOf`, `items`, `additionalProperties`); it does not validate.
- **Without a host**, as in `opentide-lsp` on its own or WASM, there is no checker and no schema. A configuration file then gets no diagnostics, no hover and no completion. The engine never guesses what opentide would say.
- **No highlighting.** The editor's TOML grammar stays: no semantic tokens for `opentide-config`, no HighlightSpec captures, no TOML grammar here.

## Hosts

- Native: `opentide-lsp --stdio` or `--listen 127.0.0.1:2087`
- Web: `wasm32-unknown-unknown`: the language server itself (`LanguageServer`, `opentide_lsp::MessageSession` one JSON-RPC message at a time, served in a Web Worker by `@opentide/lsp-worker`), and `highlight(language_id, bytes)` — do **not** mix WASI + wasm-bindgen in one artifact. With no filesystem, the client supplies the workspace on `initialize` (`initializationOptions.workspace`)
- vscode.dev: `wasm32-wasip1` of the same binary
- TypeScript: `createOpentideClient({ transport: "stdio" | "worker" | "wasi" })`

## Structure providers

`initialize` advertises document symbols, workspace symbols, document
highlight, code actions, folding, selection range, inlay hints, document
links, code lenses, and pull and workspace diagnostics (for a client that
pulls). Behavior, the visibility.toml fixes, and the quickfix range
pitfall: [EDITORS.md](EDITORS.md#structure-providers).

## Custom RPCs

- `opentide/analyze`, `opentide/highlight`, `opentide/compiledKql`, `opentide/compiledSpl` and `opentide/fs/read`: thin wrappers over `opentide_analysis` (`analyze`, `highlight`, `compiled_kql`, `compiled_spl`) and the session's document store. Params and results: [EDITORS.md](EDITORS.md#custom-rpcs).
- `opentide/catalog` and the notification `opentide/catalogChanged` (#198): the workspace index (each object's identity, its name's range and the UUIDs its body names, with their ranges) for catalogue and graph views. `index_object` finds the references once per text and keeps them in `IndexedObject::refs` (`opentide_tide::object_refs`); `find_refs` and the reference lens read them instead of walking every body. The host compares a digest of each root's catalog at the end of a batch whose index changed and notifies a client that has asked for it. Shapes: [EDITORS.md](EDITORS.md#custom-rpcs).

## Development

Use `cargo test --workspace`. Release tags are `v0.x.y`, independent of the `opentide` Python package.
