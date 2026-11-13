# Changelog

Notable changes to the opentide language server, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0, a minor version may change diagnostics and settings.

Each version's first paragraph is its summary: the GitHub Release and [opentide.org/releases](https://opentide.org/releases/language-server/) show it above the change lists. How to write a version: [`.agents/skills/engine-release-notes/SKILL.md`](../.agents/skills/engine-release-notes/SKILL.md). Versions before 0.5.0 were tagged after the fact, each on the commit where that stretch of work ended. The crates still said 0.1.0 then, so a binary built from those tags reports 0.1.0, and none of them was published to crates.io.

## [Unreleased]

### Upgrade

- If you build an `opentide_workspace::validate::Options` with a struct literal, set its new `compile_check` field: `Some(&opentide_compile::validate::Compilers)` to compile rules as `opentide validate` does, or `None`.
- If you build an `opentide_analysis::QueryReport` with a struct literal, set its new `placeholder` field (`false` for a query you checked).
- If you called `opentide_analysis::install_configuration_schemas`, build an `opentide_analysis::ConfigurationSchemas` (`ConfigurationSchemas::parse(router, &schemas)`) and pass it to `configuration_hover` and `configuration_completions`.
- If your client reads `capabilities.experimental.opentide.catalog`, accept `models`: the server generates its Tide field catalogs and no longer reports `workspace` or `bundled`.
- If you called `opentide_lsp::server::install_workspace_catalog` or read `opentide_lsp::WORKSPACE_CATALOGS`, drop it: the server installs the catalogs it generates for each root.
- If you pinned an `opentide-lsp-*-unknown-linux-musl` binary, build `opentide-lsp` with `cargo install opentide-lsp` instead: no musl binary ships.
- If you pass or read the YAML values of `opentide-tide` (`IndexedObject::body`, `IndexedObject::from_body`, `index_value`, `object_refs`, `TideObject`), use `Arc<opentide_core::node::Node>` where you used `serde_yaml::Value`, and read a document with `opentide_core::node::load` (or `TideObject::parse`) where you called `serde_yaml::from_str`.

- If you build the engine crates from source, use Rust 1.95 or later: `rust-version` is 1.95, which the YARA parser crates (`yara-x-parser`, `yara-x-fmt`) need.

### Breaking

- **`opentide-tide` reads Tide YAML with `opentide_core::node`, and its YAML values are node trees** ([opentide#850](https://github.com/opentidehq/opentide/issues/850)). `IndexedObject::body` is an `Arc<Node>`, `index_value` and `IndexedObject::from_body` take one, `object_refs` takes a `&Node`, and `TideObject` (no longer `serde::Deserialize`) is read with `TideObject::parse` or `TideObject::from_node`. `serde_yaml` is no longer a dependency of any crate: the engine's Tide findings, outline, links, lens and index read the documents `validate` reads, on the same loader. On every corpus of the repository (`crates/testdata`, the `tide_corpus` workspaces, `tests/fixtures`, the golden cases' workspaces, the fuzz seeds) the findings, their ranges, the outline, links, lens, inlay hints, hover and completion are the same. Where the parsers disagreed: a document the loader refuses (a tag outside the core schema, a repeated key, a key that is a collection, an integer past 64 bits) has no query findings, symbols or index entry, as a YAML syntax error had none; a document nested past serde_yaml's 128 levels (and within the loader's 512) is analysed; and the language server checks a standalone buffer the loader refuses as an object of the family its `schema:` line names, so `validate` reports its `yaml_parse`.

- **Configuration hover and completion take their schemas as an argument** ([opentide#926](https://github.com/opentidehq/opentide/issues/926)). `configuration_hover` and `configuration_completions` take a `ConfigurationSchemas`; `install_configuration_schemas` and `has_configuration_schemas` are gone. `opentide-lsp` generates the schemas from `opentide-schema` in every host, so `configurationSchemas` is always `true`.

- **`opentide-lsp` generates its Tide field catalogs from the models** ([opentide#926](https://github.com/opentidehq/opentide/issues/926)). Each root's `fields.json` and `deprecations.json` come from `opentide-schema` and the root's resolved configuration, on a thread of their own, and are handed to the engine; `.opentide/lsp/catalogs/generated/` is not read or watched, `install_workspace_catalog` and `WORKSPACE_CATALOGS` are gone, and `catalog` is `models` (or `host`, for a host that supplies its own).

- **No musl `opentide-lsp` binary** ([opentide#840](https://github.com/opentidehq/opentide/issues/840)). The `x86_64` and `aarch64` `unknown-linux-musl` builds no longer ship; on Alpine and other musl distributions, build `opentide-lsp` with `cargo install`. glibc Linux, macOS and Windows keep their binaries.

- **`opentide_analysis::QueryReport` has a public `placeholder` field** ([opentide#820](https://github.com/opentidehq/opentide/issues/820)). `analyze_queries` says which query is still the stand-in `opentide new` wrote, so a host need not read the file again to skip it. A struct literal of `QueryReport` without the field no longer compiles.

### Added

- **`opentide_workspace::validate::CompileCheck` and `opentide_compile::validate::Compilers`: `validate`'s compile check** ([opentide#817](https://github.com/opentidehq/opentide/issues/817)). `Options::compile_check` takes the platforms' offline compilers, which sit above `opentide-workspace`; with them the `schema` check compiles each rule a deploy would compile once nothing else failed and reports `compile_missing_field`, `compile_invalid_value`, `compile_empty_block`, `compile_invalid_rule` or `compile_failed` at the key at fault, as `opentide validate` does. `opentide::Workspace::validate` passes them with the `compile` feature.

- **`opentide`'s `analysis`, `plugins`, `python` and `stubs` features, and `cli::main_with_version`: every binding wraps the facade alone** ([opentide#836](https://github.com/opentidehq/opentide/issues/836)). `analysis` adds `opentide::analysis` (`analyze_query`, `highlight`, `legend`, `VERSION` and their types: one query checked, or a text highlighted, without a workspace); `plugins` adds `opentide::plugins` (`set_host`, `configurations`, and the connectors' traits a platform plugin implements); `python` adds `opentide::python` (`register`, `models`: the Tide models as Python classes), and `stubs` its PyO3 introspection data; `connectors::Json` names a `Row`'s values; `cli::main_with_version` runs the command line reporting the caller's version. `opentide-analysis` gains `legend()`. The Python binding (`opentide-native`) and the browser build (`opentide-wasm`) now depend on `opentide` and no other workspace crate, as `opentide-node` does, and `cargo xtask check-layers` fails a binding that depends on any other workspace crate (`may_depend_on` in `xtask/layers.toml`). `opentide-cli`, `opentide-lsp`, `opentide-connectors` and `opentide-analysis` say they are internal in their descriptions, READMEs and crate docs.

- **`opentide::Workspace::validate_with_platforms`, `opentide_workspace::state::stores_ids` and `opentide_compile::plan::enabled_with`: platform plugins in validate, deployment state and the deploy plan** ([opentide#835](https://github.com/opentidehq/opentide/issues/835)). `validate_with_platforms` runs `validate` with a `validate::PlatformConfigurations` (now re-exported with `PlatformFinding`) that checks the plugins' blocks; `validate` is unchanged. A deployment state shard may hold a platform plugin's ids: `stores_ids` accepts the four built-in platforms that keep ids and any identifier no built-in platform has, and the shard readers, `validate`'s state check and `plan::action` (a plugin's change is a `create` or an `update`) follow it. `dry_run::Request` gains `plugins`, the plugins a plan may include when the configuration enables them (`enabled_with`).

- **`opentide`'s `connectors` feature: tenant operations through the facade** ([opentide#836](https://github.com/opentidehq/opentide/issues/836)). `Workspace::tenants`, `connectors::{TenantConfig, ConnectOptions, Connection, Canceller, Capabilities}`, `Connection::{open, query, validate_query, deploy, canceller, capabilities}` (async, on tokio), `connectors::{block_on, platforms, capabilities}`, the re-exported query and deploy types of `opentide-connectors` (`QueryRequest`, `QueryOutcome`, `TimeWindow`, `LiveCheck`, `DeployRequest`, `DeployOutcome`, `Operation`, ...) and `jiff::Timestamp`, and `Error::Connector` with its codes. `opentide-connectors` gains `http_settings(platform, timeout)` (each platform's client settings) and `tenant::configured(config, platform)` (a configuration's tenants as setup tables), which the facade calls.

- **`opentide::Workspace::rules`, `objectives` and `threats`** ([opentide#837](https://github.com/opentidehq/opentide/issues/837)). Each returns its family's rows of the catalogue (`catalog::ObjectRow`), in the order the index met them: what the Python SDK's `Workspace.rules()` returns.

- **`opentide-node`: the napi-rs binding of the facade, compiled into the npm package `@opentide/opentide`** ([opentide#838](https://github.com/opentidehq/opentide/issues/838)). It exports `Workspace` (`open`, `fromFiles`, `root`, `validate`, `lint`, `info`, `catalog`, `coverage`, `deployPlan`), `runJson(argv)`, `main(argv)` and `VERSION`, with TypeScript declarations napi-derive generates (`bindings/node/index.d.ts`, checked against each build in CI). The crate is not published; it copies the workspace's lints with `unsafe_code = "deny"`, for napi-derive's registration, and writes no `unsafe`. `cargo xtask golden check --runner node` runs the golden cases through the package's `opentide` bin.

- **`opentide`, the facade crate: the Rust SDK** ([opentide#836](https://github.com/opentidehq/opentide/issues/836)). The only crate of the workspace with a stability promise (ADR 0005): `Workspace` (`open`, `from_files`, `root`, `validate`, `lint`, `info`, `catalog`, `coverage`, `deploy_plan`), `Options`, `ValidateOptions`, `LintOptions`, `DeployPlanOptions`, `Strategy`, `DeployPlan`, `Document` (a JSON document with its key order), `Error` (`#[non_exhaustive]`, `Error::code`), and curated re-exports in `opentide::{models, validate, lint, catalog}`. Features `schema`, `workspace` and `compile` (default), `queries`, `cli` (`cli::main`, `cli::exit`, `cli::run_json` and the `opentide` binary) and `lsp` (`lsp::run_stdio`, `lsp::serve`, `lsp::MessageSession`). `missing_docs` holds, the examples `validate`, `catalog` and `deploy_plan` run with the tests, and CI's `facade` job runs every feature, rustdoc as docs.rs builds it and `cargo semver-checks`. `publish = false` until the crates it wraps are published.

- **The language server reports lint's `filename_mismatch` and `metadata_recommended`** ([opentide#926](https://github.com/opentidehq/opentide/issues/926)). Open objects, and closed ones for a client that pulls, get them as `opentide lint` reports them with the root's `lint.toml`; `filename_mismatch`'s suggestion is the file name, which the rename quick fix uses. `opentide_workspace::Workspace::editor_lint` runs them over the workspace's own parse, and `cargo xtask lsp parity` compares them too.

- **`opentide_tide::index_value`** ([opentide#926](https://github.com/opentidehq/opentide/issues/926)) indexes an object a host has already parsed. The server's index (hover, completion, references, `opentide/catalog`, `opentide/catalogChanged`) reads the parse `opentide-workspace` made of each file instead of a second serde_yaml parse.

- **`opentide_schema::node::load_keeping_repeated_keys`** ([opentide#928](https://github.com/opentidehq/opentide/issues/928)). It and `load_bytes_keeping_repeated_keys` read a document as `load` does but keep every entry of a mapping that repeats a key, in the order written, for a tool that edits values over their spans (`migrate vocab-scope`); `load` still refuses a repeated key.

- **`LineStarts` and `opentide_tide::is_placeholder_query`** ([opentide#820](https://github.com/opentidehq/opentide/issues/820)). `opentide_analysis::LineStarts` converts the engine's LSP ranges to the CLI's 1-based code-point positions for every host, the Python binding included, and `is_placeholder_query`, now public, tells the stand-in query `opentide new` writes from a real one.

- **`opentide_core::suggest`: one "did you mean" rule for the engine** ([#812](https://github.com/opentidehq/opentide/issues/812)). The same word without case, whitespace, `-` or `_` wins outright; otherwise the candidate with the fewest edits (strsim's optimal string alignment distance: a transposition is one edit), within a third of the value's length and of the words that hold the part that differs, so two edits side by side or two characters cut from a long name are found (`SecurityEve` → `SecurityEvent`) while a phrase that shares words with a choice is not a typo of it (`Big incident` is not `Minor incident`). It uses an edit distance rather than a port of Python's `difflib`: an edit distance suggests what a typo meant, where a ratio of shared letters also suggests unrelated words.

- **`opentide_core::falco` and `opentide_core::duration`: Falco's terms and the Elastic duration grammar, written once** ([#810](https://github.com/opentidehq/opentide/issues/810)). Falco's operators, modifiers, priorities and keywords, the macro and list name rule, `resolve_list`, and the list expansion `sysdig_list_in_value` is judged on, and the Elastic `d`/`h`/`m`/`s` and ISO 8601 duration grammar, are shared by `opentide-tide` (the language server's Sysdig findings and `eql_maxspan_*` advisories) and `opentide-schema` (the model `opentide validate` checks), so the editor and the CLI judge a block by the same rules. `duration_millis` keeps its signature and results.

- **Each release carries CycloneDX SBOMs** ([#843](https://github.com/opentidehq/opentide/issues/843)). `opentide-lsp.cdx.json` (the binaries and the WASI build), `opentide-wasm.cdx.json` (the browser build, with the wasi-libc it links), `opentide-lsp-client.cdx.json` and `opentide-lsp-worker.cdx.json` (the npm packages) are release assets, listed in `SHA256SUMS` and checked against the CycloneDX 1.5 schema before they ship. The other assets keep their names.

### Changed

- **language-server 0.12.1 to 0.16.1 are in these crates, without their Tide block checks** ([opentide#790](https://github.com/opentidehq/opentide/issues/790)). The YARA (`opentide-yara`), YARA-L (`opentide-yaral`) and Exabeam Query Language (`opentide-exabeam`) engines, the Lucene Graylog dialect (`--platform graylog`), their codes, grammars, catalogs and highlighting, and `.yar`/`.yara`, `.yaral`/`.yl2` and `.exabeam` files with rename, formatting and signature help came in with their history (`docs/engine/IMPORT.md`). The checks, completion and hover of `configurations.{harfanglab,bitdefender,graylog,exabeam,google_secops}` blocks and of Exabeam, Graylog and Google SecOps hunts were written on `serde_yaml`, which these crates no longer use (#850): they are not in this release, and come back on `opentide_core::node`. 0.16.1's information severity for `missing_author`, `missing_organisation` and `recommended_field_missing` does not apply: these crates retired those codes for `opentide lint`'s `metadata_recommended` and `filename_mismatch` (#926).

- **The YAML node tree is `opentide_core::node`** ([opentide#850](https://github.com/opentidehq/opentide/issues/850)). The loader (`load`, `load_bytes`, `load_keeping_repeated_keys`, `Document`, `Node`, `Value`, `LoadError`, `Locator`, `Span`) moved down from `opentide-schema` to `opentide-core`, so `opentide-tide` (published) reads YAML with it; `opentide_schema::node` re-exports it with the writer, `to_yaml`, and every path through it keeps working. `opentide-core` depends on `saphyr` and `saphyr-parser` 0.3, which `opentide-schema` no longer names.

- **The engine crates are internal: depend on `opentide`** ([opentide#836](https://github.com/opentidehq/opentide/issues/836)). Every component crate's README (`COMPONENT.md`), description and crate documentation, and `opentide-analysis`'s, say so: their APIs change with the engine at the same version and carry no stability promise, which only the `opentide` crate gives.

- **The language server reports what `opentide validate` reports** ([opentide#821](https://github.com/opentidehq/opentide/issues/821)). `opentide-lsp` loads each root with `opentide-workspace`, keeps it current through its invalidation API (an edit, a watched file, `opentide/didChangeWorkspace`), and publishes `validate`'s findings with UTF-16 ranges; `opentide-tide`'s object checks (schema, vocabularies, UUIDs, references, chaining, deprecated fields, file names, metadata) are gone, and with them `filename_slug`, `filename_pattern`, `missing_author`, `missing_organisation` and `recommended_field_missing` from `codes::ALL`, the `lint.toml` settings (`install_lint`, `LintSettings`) and the deprecations overlay. Configuration buffers are checked natively with `opentide-schema` in every host, the bare binary and WebAssembly included: `set_configuration_checker` and `ConfigRequest` are gone, `place_configuration_issues` places a host's findings, and `configurationChecks` is always `true`. `opentide-lsp` and `opentide-wasm` are `publish = false` while `opentide-workspace` and `opentide-schema` are; their binaries and builds still ship as release assets. On start-up the server loads a folder's workspace on a thread of its own as soon as the folder is known, and indexes the object files for hover, completion and the catalog in parallel on the first request that reads them rather than before the first diagnostics: an Elastic rule's first diagnostics index only the objects its advisories read (the objective `detection_model` names and its threats). `opentide-workspace`'s `validate` with a `--file` selection resolves each object folder once instead of every object's path, and `validate::objects::warm_up` parses the vocabularies an object revision's fields name ahead of the first check. A Tide document outside every root and `objects/` folder (an `untitled:` buffer, an `opentide/analyze` text, `opentide-lsp analyze` on a file no workspace holds) is validated as a file of its family's folder in the virtual root, with what the host supplied; every path the server hands the workspace (a root, a buffer, a watched file) is resolved as the workspace resolves its own, so a folder named through a symbolic link, macOS's `/var` or a Windows short name keeps its buffers checked.

- **Every engine crate suggests through `opentide_core::suggest`** ([opentide#790](https://github.com/opentidehq/opentide/issues/790)). The hand-written edit distances of `opentide-cql`, `opentide-ecs`, `opentide-eql`, `opentide-esql`, `opentide-falco`, `opentide-kql`, `opentide-lucene`, `opentide-spl` and `opentide-tide` are gone: suggestions come from `suggest::closest` (or `closest_within` where a crate keeps a tighter bound: one edit for CrowdStrike events, two for a `detection_model` UUID, wherever they are), and a check that reports only near misses keeps its threshold, measured with strsim, and picks among them with the new `suggest::best`. A name far from every choice no longer gets an unrelated suggestion; codes, severities and ranges are unchanged. `Vocab::suggest` follows the same rule. `spl_unknown_command`, an error when the name is one typo from a command, suggests the best of those commands (`tsast` → `stats`).

- **Releases come from opentidehq/opentide, at opentide's version** ([opentide#801](https://github.com/opentidehq/opentide/issues/801), [opentide#840](https://github.com/opentidehq/opentide/issues/840)). The engine moved there with its history, and releases with opentide: its assets keep their names (`highlights-vX.Y.Z.zip`, `opentide-wasm-web-vX.Y.Z.zip`, `opentide-lsp-vX.Y.Z-<target>`, the licences and `SHA256SUMS`) on opentide's GitHub Release, so an editor that pins them changes the URL to `https://github.com/opentidehq/opentide/releases/download/vX.Y.Z/<asset>`. Their build provenance is signed by `opentidehq/opentide/.github/workflows/publish.yml`: verify with `gh attestation verify <asset> --repo opentidehq/opentide` and the identity in `crates/opentide-lsp/README.md`. Releases up to 0.12.0 stay on opentidehq/language-server.

### Fixed

- **"Apply suggestion" keeps a pipe stage's arguments** ([opentide#887](https://github.com/opentidehq/opentide/issues/887)). `kql_unknown_operator` and `spl_unknown_command` cover the whole pipe stage, and the quick fix (and `source.fixAll.opentide`) replaced it all with the suggestion: `index=main | stast count by host` became `index=main | stats`. The edit now replaces only the word the stage starts with (`index=main | stats count by host`); the diagnostics' ranges do not change.

- **`sysdig_list_in_value` sees a value through the block's lists** ([#810](https://github.com/opentidehq/opentide/issues/810)). An exception value that names a block list is that list's items, and a list naming an earlier list is that list's items too, as Falco's loader expands them; an item holding another block list's name inside it (`items: ['x l0']`) is now reported, as `opentide validate` reports it, where the editor said nothing.

### Security

- **`unsafe-libyaml` (RUSTSEC-2024-0449, unmaintained) is out of the dependency tree** ([opentide#850](https://github.com/opentidehq/opentide/issues/850)). It came in through `serde_yaml` 0.9, archived, which `opentide-tide` and `opentide-lsp` read Tide YAML with; neither crate depends on it now, and `deny.toml` no longer excepts the advisory. It was never a vulnerability report: nothing to upgrade for.

## [0.16.1] - 2026-11-13

Missing optional fields such as `author` are information, not warnings. Exabeam activity types, subjects and outcomes are checked against the CIM.

### Upgrade

- To keep a missing `author` or `organisation` as a warning, set `severity = "warning"` under `[metadata]` in `.opentide/configurations/lint.toml`. For a rule's missing `configurations` or `response`, set it under `[recommended]`; that table needs opentide 0.28.1 or later, since older ones reject an unknown table.

### Breaking

- **A missing optional field is information, not a warning.** `missing_author`, `missing_organisation` and `recommended_field_missing` (a rule without `configurations` or `response`) now default to information, so editors stop warning about fields `opentide validate` does not require. A host or CI that counts warnings no longer counts them. `opentide lint` already reports a missing author or organisation as a note, and reports `configurations` and `response` the same way from 0.28.1 ([#249](https://github.com/opentidehq/language-server/issues/249)).

### Added

- **lint.toml `[recommended]`.** `enabled` and `severity` decide `recommended_field_missing`, as `[metadata]` decides `missing_author` and `missing_organisation` ([#249](https://github.com/opentidehq/language-server/issues/249)).
- **API: `opentide_core::Diagnostic::information` and `Diagnostic::with_severity`**, next to `error`, `warning` and `with_field_path`.
- **Exabeam `activity_type`, `subject` and `outcome` values are checked against the CIM.** A value Exabeam's Common Information Model does not list is the warning `exabeam_unknown_value`, with a near miss or the subject's activity types: `activity_type:"network-connection"` suggests `network-session`, `network-traffic` and the rest. Wildcards, functions such as `WLD` and `RGX`, values between slashes, `null`, empty values, unquoted numbers and IP addresses, `@field`s and earlier `AS` names are never reported. When an `activity_type` is a subject (`activity_type:"dns"`), or a `subject` an activity type, the message says so.

## [0.16.0] - 2026-11-12

Google Security Operations support: YARA-L 2.0 rules, searches and `configurations.google_secops` blocks are checked, completed and highlighted as you type.

### Added

- **`.yaral` and `.yl2` files are YARA-L 2.0, language id `yaral`.** Google Security Operations rules and searches are checked offline as yara-l-1.0 1.1 defines them; keywords are case-insensitive in any mix (`and`, `AND`, `aNd`), and Google's own examples for each form are fixtures (`testdata/conformance/google-yaral/`); Google publishes no compiler, so `verifyRuleText` in a tenant stays the live check. `docs/YARAL.md` maps each code to Google's page, and `opentide explain` describes it.
  - Errors: `yaral_parse_error`, `yaral_section_*`, `yaral_meta_duplicate`, `yaral_reserved_identifier`, `yaral_undefined_variable`, `yaral_multi_event_match`, `yaral_match_*`, `yaral_condition_shape`, `yaral_outcome_*`, `yaral_unknown_function`, `yaral_function_unavailable`, `yaral_unknown_udm_field`, `yaral_enum_value`, `yaral_type`, `yaral_regex`, `yaral_export_value` (in a rule, a `write_row` value that is not an outcome variable; in a search, a `match` variable), `yaral_window_bound` (`window_start`/`window_end` without a window, or in `events`), and the other limits of the spec
  - Warnings: `yaral_deprecated_field`, `yaral_unfiltered_event`, `yaral_leading_wildcard_regex`, `yaral_reference_list_deprecated`, `yaral_string_escape` (an escape Google does not document, which its own rules use)
- **Field paths and calls are checked against Google's UDM and function list.** Every event, entity (`graph`) and detection (`detection`) field with its type and enum values, and every function with its arity and where it is available (rules or search), generated from Google's pages: all 22 `metrics.*` functions with their `filter:` expressions and `*` grouping values, `math.round` with one or two arguments, and the `window.*` functions in searches too. Reference lists, data tables and map keys are never reported unknown.
- **Google SecOps blocks (`configurations.google_secops`) are checked as the one rule deploy assembles.** `setup`, `events`, `outcome`, `condition` and `export` are one YARA-L rule with `match` and `options` rendered from YAML, each finding on its own line in the YAML; the block's codes are reported at the spec's field paths.
  - Errors: `google_secops_rule_name`, `google_secops_severity`, `google_secops_run_frequency`, `google_secops_schedule`, `google_secops_meta_key`, and `yaral_section_header`, `yaral_section_empty`, `yaral_section_alias`, `yaral_match_shape` on the YAML
  - Warnings: `google_secops_risk_score_missing`, `google_secops_rule_id_literal`, `google_secops_live_frequency_unavailable`
- **Google SecOps hunts are YARA-L searches.** `response.procedure.searches[].query` with `system: google_secops` is checked under the `search` profile: bare UDM paths, grouped fields (`ip`, `hostname`, ...), `raw = /.../`, `labels["k"]`, `dedup`, `order`, `limit`, `select`, `unselect`, multi-stage `stage` blocks and `cross join`. A stage reading only earlier stages needs no `events`, `meta` is ignored, and match windows are bound as Google documents for search (hop and sliding to 48h, tumbling to 30d, 48h with a join).
- **YARA-L editing: hover, completion and signature help.** Hover shows a UDM field's type, description and enum values, and a function's signature and availability; completion offers UDM fields after `$e.`, enum values after `metadata.event_type =`, and a namespace's functions after `strings.`.
- **YARA-L is highlighted.** Semantic tokens use the existing HighlightSpec captures; `highlights/generated/yaral.tmLanguage.json` (`source.yaral`) is the TextMate grammar, the Tide grammar embeds a Google SecOps block's section texts as `meta.embedded.block.yaral`, and the Neovim, Helix, Zed and `@opentide/lsp-client` samples map `.yaral` and `.yl2` to `yaral`.
- **API: `opentide_core::LanguageId::Yaral`** and the `opentide-yaral` crate.
- **The Tide catalog knows `configurations.google_secops`.** Regenerated with opentide's generator from the opentide branch that adds the block, so editors complete and validate its keys and nested `match`, `options` and `schedule` objects.

## [0.15.0] - 2026-11-12

Exabeam support: Exabeam queries and `configurations.exabeam` correlation rules are checked and highlighted as you type.

### Added

- **`.exabeam` files are the Exabeam Query Language, language id `exabeam`.** The search language of Exabeam's New-Scale SIEM, which Exabeam's guides call "EQL" (`eql` stays Elastic's), is checked as the specification exabeam-1.0 defines it: the filter and the advanced operators (`SELECT`, `WHERE`, `GROUP-BY`, `ORDER-BY`, `LIMIT`, pipes, `FOREACH`, the aggregations, `RGX_EXTRACT`), every `exabeam_*` error and warning of the spec, and `RGX` patterns as RE2 reads them. A `.exabeam` file is a search. `opentide explain` describes each code; `docs/EXABEAM.md` lists them with the conformance results ([specifications RFC 0018](https://github.com/opentidehq/specifications/blob/main/rfcs/0018-exabeam-platform.md)) ([#243](https://github.com/opentidehq/language-server/pull/243)).
- **Exabeam correlation rules and hunts are checked.** `configurations.exabeam.sequences[].query` is analysed under the spec's `rule` profile, where the advanced operators are `exabeam_advanced_in_rule`, and hunts with `system: exabeam` under `search`; `analyze_query` with `platform: exabeam` is the `rule` profile. On Exabeam's 2,371 published correlation rules the engine agrees with the specification's reference checker on every rule: 75 of the 2,294 Sigma conversions have errors, and none of Exabeam's 77 own rules ([#243](https://github.com/opentidehq/language-server/pull/243)).
- **Exabeam fields come from Exabeam's Common Information Model.** Hover and completion know its 1,130 fields, subjects, activity types and outcomes (`catalogs/exabeam/`, `scripts/sync_exabeam_catalog.py`). A field it lacks is the warning `exabeam_unknown_field` (never for `c_` and `m_` fields or an earlier `AS` name), and an unquoted number on a string field (`event_code:4625`) the warning `exabeam_string_field_number` ([#243](https://github.com/opentidehq/language-server/pull/243)).
- **The `configurations.exabeam` block is checked as exabeam-1.0 says.** Its constraint codes and advisories are reported on their fields, from the YAML itself, and the bundled Tide catalog, regenerated from the opentide that models the block, knows `configurations.exabeam` (its keys, `status`, and the threshold and outcome values) ([#243](https://github.com/opentidehq/language-server/pull/243)):
  - Errors: `exabeam_sequences`, `exabeam_correlation`, `exabeam_threshold_function`, `exabeam_threshold_operator`, `exabeam_threshold_value`, `exabeam_group_by`, `exabeam_duration`, `exabeam_severity`, `exabeam_outcome`, `exabeam_email`, `exabeam_schedule`, `exabeam_name_length`, `exabeam_context_table_trigger`, and `exabeam_name_duplicate` across the workspace
  - Warnings: `exabeam_outcome_silent`, `exabeam_correlation_window`
- **Exabeam queries are highlighted.** Semantic tokens follow the spec's highlight table with the existing captures; `highlights/generated/exabeam.tmLanguage.json` (`source.exabeam`) is the TextMate grammar, and the Neovim, Helix, Zed and `@opentide/lsp-client` samples map `.exabeam` to `exabeam` ([#243](https://github.com/opentidehq/language-server/pull/243)).

## [0.14.0] - 2026-11-12

Graylog support: Graylog queries and `configurations.graylog` blocks are checked as you type.

### Added

- **Graylog queries are checked in a Graylog dialect of Lucene.** `configurations.graylog.query`, hunts with `system: graylog` and `opentide-lsp analyze --platform graylog` get Elastic's Lucene checks without the ECS and Kibana KQL advice, plus graylog-1.1's seven codes. Hover and completion offer Graylog's message fields and `_exists_` (`docs/LANGUAGE.md`) ([#242](https://github.com/opentidehq/language-server/pull/242)).
  - Errors: `graylog_leading_wildcard` (opentide drops it for a tenant that allows leading wildcards), `graylog_regex_unsupported`, `graylog_open_range` (a `*` range bound, which Graylog's validator refuses)
  - Warnings: `graylog_regex_operator`, `graylog_regex_quote`, `graylog_double_backslash`, `graylog_analyzed_field`
- **The bundled Tide catalog knows the `configurations.graylog` block.** It is regenerated from opentide's Graylog models, so `opentide-lsp` run on its own and `opentide validate` agree on Graylog blocks, and the Tide TextMate grammar highlights their keys ([#242](https://github.com/opentidehq/language-server/pull/242)).
- **Graylog blocks (`configurations.graylog`) are checked as graylog-1.0 says.** The block's constraint codes and `graylog_overlapping_window` (warning) are reported on their fields, so the editor and `opentide validate` agree; `aggregation.condition` gets completion and hover for Graylog's 12 aggregation functions. `graylog_all_streams` and `graylog_title_duplicate` stay opentide's ([#242](https://github.com/opentidehq/language-server/pull/242)).
  - Errors: `graylog_query_blank`, `graylog_list_shape`, `graylog_schedule` (a Quartz cron as Graylog reads it, an IANA `timezone`), `graylog_event_limit`, `graylog_aggregation` (the condition grammar, nesting at most 32 deep), `graylog_event_field`, `graylog_event_key`, `graylog_priority`, `graylog_field_name`
  - `opentide_tide::graylog::compile_condition` compiles a condition into Graylog's series and condition tree

## [0.13.0] - 2026-11-11

YARA support: `.yar` files and the YARA in HarfangLab and Bitdefender rules are checked as you type. Bitdefender GravityZone rules are checked too.

### Upgrade

- If you build the engine crates or `opentide-lsp` from source, use Rust 1.95 or later: `rust-version` is 1.95, which the YARA parser crates need ([#165](https://github.com/opentidehq/language-server/issues/165)).

### Added

- **`.yar` and `.yara` files are YARA, language id `yara`.** `opentide explain` knows every code of the YARA language spec and its HarfangLab and Bitdefender profiles, listed in `docs/YARA.md`, and describes each as yara-1.0 1.3 defines it: `yara_rule_identifier_conflict` is a rule named like a keyword or matching an earlier rule wildcard, not one named like an imported module, which is `yara_x_incompatible` ([#165](https://github.com/opentidehq/language-server/issues/165)).
- **YARA signatures are checked as libyara 4.5 compiles them.** Every error and warning of the YARA language spec is reported: undefined and unreferenced strings, unknown and unimported modules, module members and function arguments against a catalogue of the 13 modules, types, regular expressions, hex strings, string modifiers and numeric limits, and libyara's own warnings (slow strings, `entrypoint`, suspicious expressions). What only YARA-X refuses is the warning `yara_x_incompatible`, and YARA-X-only syntax is an error that names the feature. `docs/YARA.md` maps each code to its libyara source ([#165](https://github.com/opentidehq/language-server/issues/165)).
- **YARA in HarfangLab and Bitdefender blocks is checked.** `configurations.harfanglab.yara.signature` and `configurations.bitdefender.yara.signature` are analysed under each platform's profile, and HarfangLab's `strings`, `condition` and `imports` as the one rule deploy assembles, each finding at the line it is written. The block's codes are reported: `harfanglab_rule_kind`, `harfanglab_yara_form`, `harfanglab_yara_section_header`, `harfanglab_yara_import`, `harfanglab_yara_rule_name` and `yara_signature_alias` ([#165](https://github.com/opentidehq/language-server/issues/165)).
- **YARA editing: hover, completion, signature help, outline, folding, go to definition, references, rename and formatting.** Hover and completion know every member of the 13 modules; definition, references and rename follow strings within a rule and rules across a signature, and a rename in a HarfangLab block edits `strings` and `condition` together. `.yar` files format with `yara-x-fmt`. The server advertises `renameProvider` (with `prepareRename`) and `documentFormattingProvider` ([#165](https://github.com/opentidehq/language-server/issues/165)).
- **YARA is highlighted.** Semantic tokens colour rules, tags, meta keys, strings and their counts and offsets, modules and their functions; `highlights/generated/yara.tmLanguage.json` (`source.opentide.yara`) is the TextMate grammar, and the Neovim, Helix, Zed and `@opentide/lsp-client` samples map `.yar` and `.yara` to `yara` ([#165](https://github.com/opentidehq/language-server/issues/165)).
- **HarfangLab's decomposed YARA is checked as deploy writes it, and no finding is lost.** The rule is assembled with every meta line `compile_yara_deployment` writes, so a `"` in a value deploy writes raw (`references`, `tags`, `arch`, `context`, `os`) or a context HarfangLab does not know is reported on that value. A condition or strings cut short (`$a and`, an unclosed hex string, `condition: ""`) is an error in its field, where it was silently dropped. A `rule` inside a comment is not a section header. Tags, contexts and imports are read as deploy's YAML loader reads them: comments in a flow list, a plain item over two lines, an empty item and a block-scalar item. Any identifier but a string's past libyara's 128 characters, a module used above its `import`, `.len()` (YARA-X only) and invariant comparisons (`1 == 1`, `filesize < 0`) are reported, and a rule named like an imported module is `yara_x_incompatible`, as libyara accepts it. A module predicate YARA-X types as boolean (`pe.is_dll()`) is no longer a non-boolean condition; where YARA-X needs a number (arithmetic, an ordering, `!=`, a float comparison, an offset, an index, a range bound, a quantifier, an enumeration among integers, a function argument no YARA-X overload takes a boolean for) one is `yara_x_incompatible`. A finding on an expression covers it as written, from the module of a method call (`pe.is_dll() == 1`), with its parentheses. A loop variable an enclosing loop already binds, or one a loop names twice (`for any k, k in …`), is `yara_undefined_identifier`, as libyara refuses it. An integer compared with a boolean, or a non-boolean operand of `and`, `or`, `not` or a `for` body, is `yara_suspicious_expression`; the operand of `defined` is not. A module field called as a function (`pe.number_of_sections(0)`) and a module function used without a call (`pe.imphash`) are `yara_undefined_identifier`, as libyara refuses them. A jump bound of 2^63 or more is refused as libyara refuses it, and `pe.signatures[0].valid_on(0)` is no longer an undefined identifier ([#165](https://github.com/opentidehq/language-server/issues/165)).
- **YARA verdicts are held to libyara and YARA-X.** 1,762 cases from both projects' own test suites, 50 public rule files from ReversingLabs and signature-base with a broken twin each, and a CI oracle against `yara-python` 4.5.4 and the `yara-x` 1.23.0 wheel: an error exactly where libyara refuses, and `yara_x_incompatible` exactly where YARA-X refuses what libyara compiles. Four known differences are listed in `docs/YARA.md`. Neither reference ships ([#165](https://github.com/opentidehq/language-server/issues/165)).
- **Bitdefender GravityZone rules (`configurations.bitdefender`) are checked as bitdefender-1.0 says.** The block's constraint codes and advisories are reported on their fields, so the editor and `opentide validate` agree; `bitdefender_name_duplicate` stays a workspace check in opentide ([#226](https://github.com/opentidehq/language-server/issues/226)).
  - Errors: `bitdefender_rule_kind`, `bitdefender_target`, `bitdefender_criterion_shape`, `bitdefender_criterion_relation`, `bitdefender_criterion_value`, `bitdefender_criteria_combination`, `bitdefender_action_scope`, `bitdefender_targets_shape`, `bitdefender_severity` (`bitdefender_yara_ascii` and `bitdefender_yara_size` come from the YARA checks above)
  - `bitdefender_criterion_field`: an error on `process`, `file`, `connection` and `registry`, a warning on the XDR targets
  - Warnings: `bitdefender_registry_full_hive`, `bitdefender_contains_no_wildcard`, `bitdefender_severity_collapsed`
  - Completion and hover for `detection.target`, each target's criteria fields, the relations `is`, `contains` and `any`, enumerated values, and `actions`, from GravityZone's criteria catalogue (`catalogs/bitdefender/criteria.toml`, `scripts/sync_bitdefender_criteria.py`)

### Changed

- **The bundled Tide catalog knows `configurations.harfanglab.yara.signature` and the `configurations.bitdefender` block.** It is regenerated from opentide's models, so `opentide-lsp` run on its own and `opentide validate` agree on HarfangLab and Bitdefender blocks, and the Tide TextMate grammar highlights their keys ([#236](https://github.com/opentidehq/language-server/pull/236), [#239](https://github.com/opentidehq/language-server/pull/239)).

### Fixed

- **A large injected query no longer takes time in the square of its size.** Every semantic token and finding of a query in a Tide object, and every symbol of a `.yar` file, was positioned by scanning the text from its start: a rule with a 1 MB YARA signature took about 280 s to analyse and now takes about 1 s, with the same output. KQL, SPL, Falco and every other injected language share the path ([#238](https://github.com/opentidehq/language-server/pull/238)).

## [0.12.1] - 2026-11-09

Fixes a false unknown-key warning on a Splunk block's `advanced` table.

### Fixed

- **`configurations.splunk.advanced` is a field again.** The Tide catalog follows opentide, which accepts again the table of raw `savedsearches.conf` keys (a custom alert action's `action.<name>.param.*`) that opentide 0.21.0 refused, so `opentide-lsp` run on its own no longer reports it as an unknown key. As in opentide 0.20.1, it is accepted, not completed.

## [0.12.0] - 2026-11-08

CrowdStrike queries are checked: the CrowdStrike Query Language (CQL) of Falcon LogScale and Next-Gen SIEM is a language, with diagnostics, hover, completion and highlighting for correlation rules, hunts and `.cql` files.

### Upgrade

- If you match or suppress `crowdstrike_unsupported`, match the `cql_*` codes instead (`docs/CQL.md`).

### Breaking

- **CrowdStrike queries are checked as CQL, and `crowdstrike_unsupported` is gone.** `configurations.crowdstrike.query` and hunts with `system: crowdstrike` used to get one `crowdstrike_unsupported` warning; they now get the `cql_*` diagnostics below, so a query LogScale would refuse is an error where it was not before. `docs/CQL.md` has the language and every code ([#221](https://github.com/opentidehq/language-server/pull/221)).

### Added

- **The CrowdStrike Query Language (CQL), Falcon LogScale's and Next-Gen SIEM's, is a language: id `cql`, files `*.cql`.** It follows CrowdStrike's published grammar and function reference (`docs/CQL.md`): 2,786 of the 2,812 blocks labelled CQL in CrowdStrike's public content parse, and 475 of the 490 queries on its function pages are clean (the rest are templates and documentation typos).
  - Errors: `cql_parse_error`, `cql_unknown_function`, `cql_removed_function`, `cql_unknown_parameter`, `cql_duplicate_parameter`, `cql_unnamed_argument`, `cql_missing_parameter`, `cql_parameter_value`, `cql_regex_flag`, `cql_free_text_after_aggregate`, `cql_event_function_after_aggregate`, `cql_assignment_as`, `cql_link_outside_correlate`, `cql_correlate_placement` (`correlate()` where its reference forbids it), `cql_match_guard`
  - In a correlation rule (`configurations.crowdstrike.query`, or `analyze_query` with `platform: crowdstrike`), `cql_correlate_aggregate`: `correlate()` with another aggregate
  - Warnings: `cql_deprecated_function`, `cql_string_escape`, `cql_unknown_event` (a `#event_simpleName` no Falcon event has, with a near match), `cql_regex_group_under_or`
  - A field, saved search, lookup file or repository is never reported unknown: they live in the tenant
  - Hover, completion and signature help for the 196 functions, their parameters and allowed values, LogScale, Falcon and CPS fields and tags, and 395 Falcon events (`catalogs/cql/`, `scripts/sync_cql_catalog.py`)
  - Highlighting: `highlights/generated/cql.tmLanguage.json`, scope `source.opentide.cql` (Cassandra's CQL extensions own `source.cql`), and the CrowdStrike block's query as an embedded region of Tide YAML
  - Editors: the Helix, Neovim and Zed samples and `@opentide/lsp-client` map `*.cql` to `cql`

### Fixed

- **A huge `Content-Length` no longer crashes the server.** `serve`, `--stdio` and `--listen` allocated the length a header named before the body arrived (`lsp-server` sizes its buffer first), so one header could exhaust memory and abort; the body is read as it arrives, and a length longer than the input ends the session with the short-body error it always gave ([#843](https://github.com/opentidehq/opentide/issues/843), found by the new `framing` fuzz target).

## [0.11.0] - 2026-11-06

Filename and metadata warnings now follow the workspace's `lint.toml` as `opentide lint` does, a `detection_model` naming a signal is no longer an `invalid_ref`, and hover and findings point at the exact value they are about.

### Added

- **`opentide/didChangeWorkspace` updates the workspace a host supplied on `initialize`.** A host with no filesystem, such as a browser worker, sends it when files change outside the editor, without a restart; the server re-indexes, re-checks open documents and sends `opentide/catalogChanged` for a catalog the client got that changed. `docs/EDITORS.md` (Custom RPCs) has the shape.
  - `documents` and `objects`: added or changed
  - `removed`: the URIs of files that are gone
  - `visibility`: the text of `visibility.toml`, or `null` when it is gone
  - `capabilities.experimental.opentide.workspaceUpdates` is `true`, so a client can tell this server from an older one
  - `@opentide/lsp-client`: `OpentideClient.updateWorkspace(change)` sends it
- **`filename_pattern` reports a file name `[filenames] pattern` does not match.** A warning on the `name` value, as `opentide lint` reports it; a pattern the Rust `regex` crate cannot compile is left to `opentide lint` ([#214](https://github.com/opentidehq/language-server/issues/214)).
- **Hosts install a root's `lint.toml` with `opentide_analysis::install_lint`.** For a host other than `opentide-lsp`, which reads the file itself; `opentide_analysis::check_lint` parses one without installing it ([#214](https://github.com/opentidehq/language-server/issues/214)).

### Changed

- **A supplied document belongs to the folder that holds it.** With several workspace folders, each supplied file is in its own folder's root only, as a file on disk is; supplied files used to be in every root's index. `docs/EDITORS.md` (TypeScript client) has the rules.
  - A reference to an object only another folder supplied is an `invalid_ref`, as the CLI reports it
  - Each root's `opentide/catalog` lists its own objects
  - An object supplied with no `uri`, or outside every folder, is still every root's
  - A root's `.opentide/configurations/visibility.toml` among the supplied documents declares its datasets, in place of the `visibility` the host supplies for every root
- **Reference findings are on the value, not its key.** `invalid_ref` is on the UUID it is about in these fields, and `filename_slug` on the `name` value ([#215](https://github.com/opentidehq/language-server/issues/215)).
  - `detection_model`
  - each `objective.threats` entry, on its own UUID, where all of them shared the `threats` key
  - a `threat.chaining` `vector`

### Fixed

- **A `detection_model` naming a signal is not an `invalid_ref`.** A rule may implement a signal an indexed objective declares, as `opentide validate` accepts; the message says `is not an indexed objective or signal`, and the suggestion is a UUID within two edits of the value, never the first indexed objective ([#213](https://github.com/opentidehq/language-server/issues/213)).
- **The `invalid_ref` quick fix keeps the YAML valid.** It replaces the UUID, where it used to replace the key with one (`<uuid>: <old uuid>`) ([#215](https://github.com/opentidehq/language-server/issues/215)).
- **The `filename_slug` fix renames the file, not the object.** Its suggestion is a `RenameFile` beside the file, for a client that applies one, a `file:` document and a name no other file has; it is never a text edit, and `source.fixAll.opentide` leaves it out ([#215](https://github.com/opentidehq/language-server/issues/215)).
- **Filename and metadata warnings follow `lint.toml`.** `filename_slug`, `missing_author` and `missing_organisation` read the root's `.opentide/configurations/lint.toml` as `opentide lint` does, so a repository with its own naming, or no `organisation` requirement, no longer carries a warning on every object ([OBJECTS.md](../docs/engine/OBJECTS.md#linttoml), [#214](https://github.com/opentidehq/language-server/issues/214)).
  - `[filenames] enabled`, `style` (`slug`, `name`, `none`) and the `[filenames.<kind>]` tables
  - `[metadata] enabled` and `required`
  - each check's `severity`
  - the open buffer, else the file on disk, else a supplied document; editing it re-checks open documents
  - `opentide-lsp analyze` reads the workspace's file too
- **Debug fixtures and unsaved buffers get no false filename warning.** `x.debug.yaml` is compared without its `.debug` infix, and its suggestion keeps it; an `untitled:` document gets no `filename_slug` or `filename_pattern` ([#214](https://github.com/opentidehq/language-server/issues/214)).

## [0.10.0] - 2026-11-04

Editors get the workspace index for their catalogue, graph and search views, following unsaved edits on the desktop and in the browser, and placeholder queries from `opentide new` are no longer reported as errors.

### Upgrade

- If your editor includes the ES|QL grammar by scope, include `source.opentide.esql`.

### Breaking

- **The ES|QL grammar's scope is `source.opentide.esql`.** It was `source.esql`, the scope of Elastic's ES|QL extension, so an editor that loaded both grammars kept only one ([#195](https://github.com/opentidehq/language-server/issues/195)). The other grammars keep `source.<id>` and HighlightSpec captures are unchanged; `docs/EDITORS.md` says why.

### Added

- **`opentide/catalog` and `opentide/catalogChanged` serve the workspace index.** `opentide/catalog {root?}` gives catalogue, graph and search views every object with its references, from the engine's index, so they follow unsaved edits and work in the browser build ([#198](https://github.com/opentidehq/language-server/issues/198)). `docs/EDITORS.md` (Custom RPCs) has the shapes.
  - Objects: `uuid`, `object_type`, `schema`, `name`, `uri`, the name's `range`, `refs`
  - Refs: each value of `detection_model`, `objective.threats`, a signal's `uuid` and `parent`, and `threat.chaining.<i>.vector`, with its `field_path` and `range`
  - A dangling or non-UUID value (a typo, `TODO`) is a ref whose `uuid` no object carries, as `invalid_ref` reports it
  - `opentide/catalogChanged {root}` follows a change of a root's objects, names or references, once the client has asked for that root
  - API: `IndexedObject::{refs, schema, name_range}`, `IndexedObject::from_body`, `opentide_tide::object_refs`
- **`DOCUMENT_SELECTOR` and `LANGUAGES` include `opentide-config`.** A client built from `@opentide/lsp-client`'s selector sends configuration TOML (`**/.opentide/configurations/**/*.toml`) to `opentide lsp start` ([#197](https://github.com/opentidehq/language-server/issues/197)). The client's `analyze` and `highlight` refuse it: only a host checks it.
- **`WEB_DOCUMENT_SELECTOR` selects documents on vscode.dev and github.dev.** It is `DOCUMENT_SELECTOR` with no scheme, since documents there are not `file:` URIs; `DOCUMENT_SELECTOR` keeps `scheme: "file"` for the desktop ([#197](https://github.com/opentidehq/language-server/issues/197)).
- **Each GitHub Release carries `SHA256SUMS` and build provenance attestations.** They cover every asset, and `sha256sum -c SHA256SUMS` and `gh attestation verify <asset> --repo opentidehq/language-server --cert-identity-regex …` check a download; README.md gives the identity ([#196](https://github.com/opentidehq/language-server/issues/196)). A release's assets are never uploaded again, so their digests stay the ones consumers pinned.

### Fixed

- **Placeholder queries that `opentide new` leaves are not checked.** A rule `opentide new` created no longer opens with a `kql_parse_error`, `eql_parse_error`, `esql_unknown_command` or `falco_parse_error` on its `...` query, which `opentide validate` skips as `opentide lint`'s `placeholders` finding ([#207](https://github.com/opentidehq/language-server/issues/207)). The rule is opentide's, for every query language:
  - A placeholder's first line is still `...`, and that line or the one above it (`query: |`) ends in `# opentide:placeholder`
  - `...` without the marker, or a query written under a leftover marker, is checked as before
  - API: `analyze_queries` still reports a placeholder, with no diagnostics
- **Folders deleted, created or moved under `objects/` are re-read.** Their objects leave or join the workspace index, and `invalid_ref` and `opentide/catalogChanged` follow; a deleted folder, which a client reports as one event (VS Code drops its files' events), stayed indexed until the server restarted. The server asks to watch `**/objects` and `**/objects/**` instead of `**/*.{yaml,yml}`.
- **`documentSelector: DOCUMENT_SELECTOR` compiles in vscode-languageclient's `LanguageClientOptions`.** `@opentide/lsp-client`'s `DOCUMENT_SELECTOR` and `WEB_DOCUMENT_SELECTOR` are plain arrays, not `ReadonlyArray`s, which TypeScript does not assign to vscode-languageclient's mutable `DocumentSelector` (TS2322).
- **A workspace folder removed with `workspace/didChangeWorkspaceFolders` stops being a root.** `workspace/diagnostic` and `workspace/symbol` stop covering it, and an open document of that folder reads the `.opentide/` or `objects/` root around it, as one opened outside every folder does.
- **Locations in workspaces not on disk use each document's URI.** On vscode.dev and github.dev (`vscode-vfs://github/org/repo`) and for `untitled:` documents, a location in another document was `file:///vscode-vfs://…`, which the editor could not open, in:
  - `textDocument/definition` and `textDocument/references`
  - `workspace/symbol`
  - document links
  - a `duplicate_id`'s related information

## [0.9.1] - 2026-11-03

`opentide-lsp` on its own reports the unknown keys and platform `schema` values that `opentide validate` reports, as the bundled Tide catalog follows opentide's removal of its CoreTIDE compatibility.

### Changed

- **The bundled Tide catalog follows opentide's removal of CoreTIDE compatibility.** `opentide-lsp` on its own reports what `opentide validate` reports ([opentidehq/opentide#745](https://github.com/opentidehq/opentide/pull/745)):
  - Unknown keys, where they were accepted spellings or deprecations: a Splunk block's splunk::2.x keys (`search`, `cron_schedule`, `advanced`, `security_domain`), a rule's `meta:`, an objective's root `composition`
  - Each platform block's `schema` offers and accepts only its registered `platform::<platform>::1.0`

## [0.9.0] - 2026-11-03

The server runs in a browser Web Worker, and a rebuilt protocol host keeps up with typing and gives each workspace folder its own objects. Editors get an outline, links, lenses and configuration TOML checked by opentide.

### Upgrade

- If you call `opentide_analysis::hover` or `signature_help`, or a language crate's `hover`, pass the byte offset `opentide_core::position_to_offset` gives for the editor's position.
- If your client shows code lenses, register the `opentide.showReferences` command, which the `N rules use this objective` lens runs with `[uri, position, locations]`.

### Breaking

- **`opentide_analysis::hover` and `signature_help` take a byte offset.** They, and each language crate's `hover`, take a `usize` offset as `completions` already did, never an LSP position ([#185](https://github.com/opentidehq/language-server/issues/185)). A byte-order mark at the start counts as bytes.

### Added

#### Protocol host

- **`initialize` says who runs the server.** `capabilities.experimental.opentide` is `{ host, engine, catalog, configurationChecks, configurationSchemas }`, and `opentide-lsp --version --json` prints the same object without starting a session ([#172](https://github.com/opentidehq/language-server/issues/172)).
  - API: `opentide_lsp::set_host_info` names the host
- **Each workspace folder has its own objects, `visibility.toml` and catalogs.** The server reads `workspaceFolders` (else `rootUri`) and follows `workspace/didChangeWorkspaceFolders` ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - One folder causes no `invalid_ref` or `duplicate_id` in another
  - A client that sent only `workspaceFolders` no longer gets a false `invalid_ref` on every rule
  - A document outside every folder belongs to its `.opentide/` or `objects/` ancestor
- **Catalog and `visibility.toml` loads and failures reach the editor's log.** They are `window/logMessage`, and a broken file on disk is shown once per session ([#185](https://github.com/opentidehq/language-server/issues/185)).

#### Browser build

- **The language server runs in a browser Web Worker.** The browser build (`opentide-wasm`) carries the `opentide-lsp` server `--stdio` runs, driven one JSON-RPC message at a time, so a browser editor gets the same diagnostics, hover, completion, code actions and semantic tokens as a native one ([#14](https://github.com/opentidehq/language-server/issues/14)). It still imports nothing but wasm-bindgen's glue.
  - Exports: `LanguageServer`, `version()`
  - API: `opentide_lsp::MessageSession`, the protocol loop with one message to a batch, the same lifecycle and the same answers to a malformed message
- **`@opentide/lsp-worker` serves the server inside a Web Worker.** `serveLanguageServer(port, server)` passes one JSON-RPC message per `postMessage` each way (JSON text, no `Content-Length` header), as `@codemirror/lsp-client`'s `Transport` sends them.
  - `loadLanguageServer` loads the server; it and `loadHighlightModule` take the glue as a URL or as the module a bundler already imported
  - Messages that arrive while the module loads wait for it
  - A module that fails to load answers every request with the reason, so a client's `initialize` fails at once
- **The `worker` transport talks JSON-RPC to the server worker.** `createOpentideClient({ transport: "worker", worker })` speaks to that worker as `stdio` does to the process, so `analyze` works there and gives the CLI's diagnostics. A loaded `module` still highlights in the same thread.
- **A host with no filesystem supplies its workspace on `initialize`.** It goes in `initializationOptions.workspace`, which `createOpentideClient` sends from its `workspace` option.
  - `documents`: object files, indexed as if on disk
  - `objects`: `{ uuid, schema, name }` of objects known by their metadata alone, so a `detection_model` or threat reference to one is not an `invalid_ref`
  - `visibility`: the text of `visibility.toml`
  - An object the client also opens is itself, not a `duplicate_id` of its metadata
- **`@opentide/lsp-client` and `@opentide/lsp-worker` ship as JavaScript with declarations.** Each package's `exports` point at `dist/`, and a pack holds only those files and the licences ([#167](https://github.com/opentidehq/language-server/issues/167)). A release publishes both to npm at its version, with npm trusted publishing, once the repository enables it.

#### Editor features

- **A Tide object's document symbols are an outline tree.** The tree holds the object, each top-level section, each `configurations.<platform>` block and each query with its language ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - API: `opentide_tide::outline`
- **ATT&CK ids and object UUIDs are document links.** Technique and tactic ids (`T1059.001`, `TA0002`) link to attack.mitre.org, and the UUID of another object links to its file ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - API: `opentide_tide::{document_links, attack_url}`
- **Objectives and threats show how many rules use them.** A lens on the UUID says `N rules use this objective` and runs `opentide.showReferences` with `[uri, position, locations]`, which the client registers ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - API: `opentide_tide::reference_lens`
- **`source.fixAll.opentide` applies every suggestion at once.** When the client asks for source actions, every suggestion of the document comes as one edit ([#185](https://github.com/opentidehq/language-server/issues/185)).
- **Inlay hint labels lead to the object they name.** Ctrl-click on a hint opens the object ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - API: `TideInlay` carries the object's `uuid` and `path`
- **`workspace/diagnostic` reports object files nobody has open.** A client that pulls gets the findings of every closed object file, `duplicate_id` and `invalid_ref` among them ([#185](https://github.com/opentidehq/language-server/issues/185)).
- **Diagnostics carry a docs link, tags, related information and version.** Each is for a client that reads it ([#185](https://github.com/opentidehq/language-server/issues/185)):
  - `codeDescription.href`: the code's section of opentide's diagnostics reference
  - The `Deprecated` tag on deprecations
  - `relatedInformation`: the other file of a `duplicate_id`
  - The document `version` on a published set
- **Queries in Tide YAML are embedded regions of their grammar.** The Tide TextMate grammar marks each query whose path fixes its language as `meta.embedded.block.<id>`; Elastic queries, whose language follows sibling keys, are left to semantic tokens ([#171](https://github.com/opentidehq/language-server/issues/171)).
  - KQL: `configurations.{sentinel,defender_for_endpoint}.query`
  - SPL: `configurations.splunk.{query,search}`
  - Lucene: `configurations.carbon_black_cloud.query`
  - Falco: `configurations.sysdig.condition`
  - The highlights zip ships `generated/package-contributions.json` with the `embeddedLanguages` map
  - HighlightSpec is 0.3.0; no capture changed

#### Configuration TOML

- **Configuration TOML is a language, `opentide-config`, checked by opentide.** `.opentide/configurations/**/*.toml`, `visibility.toml` included, is `opentide-config` whatever id the editor sends ([#158](https://github.com/opentidehq/language-server/issues/158)). `opentide lsp start` installs opentide's own check, so the editor reports what `opentide validate` reports ([opentidehq/opentide#730](https://github.com/opentidehq/opentide/issues/730)).
  - Each finding sits on the key its `field_path` names, or on the block's `[[header]]` when the key is missing, and the message names the path
  - Editing one configuration file re-checks the others that are open, so a status added to `deployment.toml` clears `sharing.toml`
  - A checker that fails gives one `config_check_failed` warning
  - `opentide-lsp` on its own has no checker, so it reports nothing for these files
  - There is no TOML highlighting: the editor's TOML grammar stays
  - The editor samples associate the glob and start `opentide lsp start` for it
- **Configuration TOML has hover and completion from the host's schemas.** Hover shows a key's title, type, description, allowed values and default, never the value; completion offers the keys a table may still take, table names and allowed values ([#158](https://github.com/opentidehq/language-server/issues/158)). `opentide-lsp` on its own has no schemas, so it offers neither.
- **Hosts plug configuration checks and schemas into the engine's API.** The engine does not check these files itself: it places what the host's checker finds and reads the host's schemas ([#158](https://github.com/opentidehq/language-server/issues/158)).
  - `opentide_analysis::set_configuration_checker`, `install_configuration_schemas`
  - `opentide_analysis::config`: `ConfigRequest`, `ConfigIssue`, `configuration_diagnostics`, `configuration_hover`, `configuration_completions`, `configuration_path`
  - `LanguageId::Config`, `Severity::parse`, `opentide_lsp::serve`

#### Carbon Black

- **`cbc_unknown_field` warns on a misspelt Carbon Black field.** A field within two edits of a catalog field gets the warning, with that field as the suggestion (`process_nmae` → `process_name`), in `configurations.carbon_black_cloud.query` and `system: carbon_black_cloud` hunts ([#162](https://github.com/opentidehq/language-server/issues/162)). The upper-case regexp hint still fires on every field, tokenized or not.
  - API: `opentide_lucene::carbon_black`, `codes::CBC_UNKNOWN_FIELD`
- **Hover and completion know Carbon Black's process search fields.** `catalogs/carbon_black/fields.toml` lists 76, with their types, descriptions and the values a few allow, each attested by Carbon Black's Python SDK or pySigma's Carbon Black pipeline ([#162](https://github.com/opentidehq/language-server/issues/162)). Completion offers them, or a field's values after `field:`, and no longer offers ECS fields there: they are Elastic's.
  - API: `opentide_lucene::{hover_dialect, completions_dialect}`
- **`opentide-lsp analyze --platform` picks a query file's dialect or schema.** `--platform carbon_black_cloud` checks a raw `.lucene` file in the Carbon Black dialect, and `--platform defender_for_endpoint` checks KQL against the Defender schema ([#162](https://github.com/opentidehq/language-server/issues/162)).

### Changed

- **The protocol host runs on `lsp-server` 0.10 and `lsp-types` 0.97.** It is the stack rust-analyzer uses, with no async runtime, and each method is a typed handler ([#90](https://github.com/opentidehq/language-server/issues/90), [#185](https://github.com/opentidehq/language-server/issues/185)).
  - Params that do not deserialize get `InvalidParams` (-32602)
  - A request with `"id": null` gets `InvalidRequest` (-32600) with `id: null`, where it got `MethodNotFound`
  - The capabilities are built from the client's
  - `positionEncoding` is advertised as `utf-16`
  - On native targets, stdio and `--listen` read on a thread of their own; `serve` and wasip1 read on the caller's

### Fixed

#### Protocol host

- **Edits after a multi-byte character no longer crash the server.** An incremental edit after `日本`, `é` or an emoji read the editor's UTF-16 column as a byte offset and sliced inside the character ([#178](https://github.com/opentidehq/language-server/issues/178)).
- **The server follows the LSP lifecycle** ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - Before `initialize`: a request gets `ServerNotInitialized`, and a notification is dropped
  - After `shutdown`: a request gets `InvalidRequest`, and nothing is published
  - A second `initialize` gets `InvalidRequest`
  - `opentide-lsp --stdio` exits 0 after `shutdown`, and 1 when the client exits or closes the stream without it
  - API: `serve_with_status` and `run_stdio_status` return whether the session ended cleanly; `serve` and `run_stdio` are unchanged
- **Bad frames and failing handlers no longer end the session** ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - A body that is not JSON, or not a message (a batch, for example), gets `-32700` or `-32600` with `id: null`
  - `content-length` is accepted in any case, a message without `jsonrpc` is answered, and `"id": null` is echoed
  - A handler that panics fails its own request with `InternalError`, where the server exited with 101
- **VS Code no longer shows every diagnostic twice.** The server pushed diagnostics and offered them for pulling; a client that pulls (`textDocument.diagnostic`) and can be asked to pull again (`workspace.diagnostics.refreshSupport`) only pulls, and any other client gets them pushed ([#185](https://github.com/opentidehq/language-server/issues/185)). Pulled items carry the same `data` (field path, suggestion) as pushed ones.
- **The server keeps up with typing.** Each document state is analysed once, where a VS Code keystroke ran about ten analyses, and twenty queued edits are analysed and published once ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - Publish, pull, semantic tokens, code actions, symbols, lenses and links share one analysis
  - Messages that arrive while a request runs are handled as one batch
  - A request the batch cancels gets `RequestCanceled`
  - A request for a document a later edit in the batch changes gets `ContentModified`: semantic tokens, code actions, inlay hints, pulled diagnostics, lenses, links
- **The server asks clients to refresh when workspace files change.** After `visibility.toml`, a configuration file, a catalog or an object on disk changes, a client that can refresh gets `workspace/{semanticTokens,inlayHint,codeLens}/refresh`, and one that pulls `workspace/diagnostic/refresh` ([#185](https://github.com/opentidehq/language-server/issues/185)).
- **The server follows what the client can do** ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - Hover and completion documentation is plain text for a client that renders no Markdown
  - A space opens no completion list in Tide YAML
  - An edit whose version is not newer than the document's is ignored

#### Editor features

- **Definition, references and document highlight work after an emoji.** They found no UUID after a multi-byte character on the line; highlight and workspace-symbol ranges and selection-range line ends are in UTF-16 too ([#185](https://github.com/opentidehq/language-server/issues/185)). A closed file's workspace symbol points at its `name`, not at `0:0`.
- **After an emoji, completion and hover use the right column.** Completion and KQL hover counted characters, not the UTF-16 units the editor counts ([#178](https://github.com/opentidehq/language-server/issues/178)). So did SPL hover ([#185](https://github.com/opentidehq/language-server/issues/185)).
- **Definition and references find no UUID past a line's end.**
- **`completionItem/resolve` returns the client's item with documentation added.** It returned another item, without the `textEdit` and `filterText`, so VS Code, which resolves the focused item before inserting it, appended a dotted ES|QL or Kibana field (`process.parent.name`) after the typed prefix ([#185](https://github.com/opentidehq/language-server/issues/185)).
- **Resolved completion documents a Tide value from its own field.** `completionItem/resolve` reads the field from the item's `data`, not the first field with that value ([#185](https://github.com/opentidehq/language-server/issues/185)).
- **Code actions follow the request.** Quick fixes are built from the diagnostics the client sends back (their `data`), name the diagnostic and are preferred, and `context.only` is honoured ([#185](https://github.com/opentidehq/language-server/issues/185)). The fix that creates `visibility.toml` is offered only to a client that can create files.
- **Completion and hover work right after an injected query.** With the cursor after the query's last character, where it sits while the author types, they found no query, in every language.

#### Workspace files

- **Non-Tide YAML is no longer analysed as a Tide object.** Editors send every YAML file as `yaml`, so `.github/workflows/ci.yml` got `schema_validation` and `.pre-commit-config.yaml` got `filename_slug` ([#185](https://github.com/opentidehq/language-server/issues/185)). A YAML document is read when:
  - the editor names it `opentide-yaml`
  - it is under an `objects/` folder
  - its `metadata` names a Tide schema (`schema: rule::1.0`), which covers object folders that `paths.toml` moves
- **A `.toml` file outside `.opentide/configurations/` is no longer read.** The server analysed `Cargo.toml` or `pyproject.toml` as Tide YAML when an editor sent it.
- **The server reads only `<root>/objects`.** A root without `objects/` had every YAML file under it read on each request, so `/tmp` gave false `duplicate_id` errors ([#185](https://github.com/opentidehq/language-server/issues/185)). Symlinked directories are not entered, so a link back up the tree no longer indexes each object many times, and `opentide-lsp analyze` shares the walk.
- **The server watches configuration TOML, generated catalogs and object YAML.** A referenced objective deleted on disk is an `invalid_ref` in the open rule at once ([#185](https://github.com/opentidehq/language-server/issues/185)).
- **Object files are read and indexed once, not per request.** Hover on a 1,000-object workspace takes under 1 ms instead of a 73 ms median ([#181](https://github.com/opentidehq/language-server/issues/181)).
  - A file changed on disk is read again when the client's file watcher reports it, or when the editor closes it
  - The server asks to watch `**/*.{yaml,yml}`
  - Without a file watcher, each request re-reads the files and re-indexes only those whose text changed
  - API: `WorkspaceHost::indexed_objects` lets any host hand the engine an index it keeps
- **Windows: `file:` URIs and walked paths name the same file.** `file:///c%3A/Users/u/det` is `c:\Users\u\det` and `file://server/share/r.yaml` is the UNC path `\\server\share\r.yaml`, where the server gave `c:/Users/...` and dropped the UNC host ([#185](https://github.com/opentidehq/language-server/issues/185)).
  - API: `opentide_lsp::uri::{uri_to_path, path_to_uri}`
- **Windows: a file is not its own `duplicate_id` in `analyze`.** `opentide-lsp analyze` reported one when the file's path mixed `/` and `\`; the language server never did.

#### Query languages

- **SPL analysis no longer hangs on some broken queries.** In an error-recovered tree, the "never closed" message and the previous-token lookup could loop forever, freezing the language server ([#179](https://github.com/opentidehq/language-server/issues/179)).
- **EQL: a backslash before a multi-byte character no longer panics.** The invalid-escape error covers the whole escaped character (`"D:\\日本"`, `"x\\é"`) and names it, not its first byte ([#180](https://github.com/opentidehq/language-server/issues/180)). A wrong span anywhere gives a short range, never a crash.
  - API: `opentide_core::offset_to_position` and `LineIndex::position` count an offset inside a character from its start instead of panicking
- **Signature help and completion no longer panic on wide characters.** In EQL and ES|QL signature help, and in the language server's completion, a character wider than one byte before the name being typed (`wehrEÖndsWith(`, `= Öabs(`, `where éAccount`) caused a panic ([#182](https://github.com/opentidehq/language-server/issues/182)).
- **Query analysis is much faster.** Each highlight query is compiled once per process, not on every analysis, where it cost more than the analysis itself: SPL takes 0.14 ms per query instead of 9.6, and KQL 4 ms instead of 16 ([#181](https://github.com/opentidehq/language-server/issues/181)).

## [0.8.0] - 2026-11-03

Sysdig Secure rules are checked as Falco loads them: a `configurations.sysdig` block's condition, macros, exceptions and output, with Falco highlighting, hover and completion. Sentinel's `alert.techniques` takes ATT&CK v18 ids.

### Added

- **Falco rule conditions get highlighting, hover and completion.** Falco is the language of Sysdig Secure's `configurations.sysdig` block (sysdig-1.0, [RFC 0014](https://github.com/opentidehq/specifications/blob/main/rfcs/0014-sysdig-falco-platform.md), [opentide#143](https://github.com/opentidehq/opentide/issues/143)).
  - Language id: `falco` (`.falco`)
  - Engine crate: `opentide-falco`
  - Highlighting: `falco.tmLanguage.json` and `highlights/queries/falco/`, with no HighlightSpec capture added
- **A Sysdig block is checked as Falco loads it.** `configurations.sysdig.condition`, `macros[].condition`, `output` and `exceptions` are checked with the block's own `macros` and `lists` and the fields of its `source`. Verdicts follow libsinsp's filter parser and compiler and Falco's rule loader, and match `falco --validate` of Falco 0.45.2 except where `docs/FALCO.md`, the conformance matrix, says.
- **What Falco refuses is an error.** `falco_unknown_field` is a field of a catalogued source the catalogue does not know, in the condition, `val()`, transformers, exception fields or the output, and `falco_parse_error` includes an empty condition.
  - `falco_parse_error`, `falco_unknown_field`, `falco_field_argument`
  - `falco_operator_type`, `falco_value_type`, `falco_invalid_regex`
  - `falco_transformer`, `falco_rhs_field`
  - `falco_unknown_event`, `falco_misplaced_list`, `falco_append_condition`
  - `falco_output_syntax`, `falco_exception`
- **What depends on the agent or tenant is a warning.** An undefined macro or list, or a tuning of a rule the Falco default rules lack, may be one Sysdig manages, so the engine warns where Falco OSS refuses it. Advice is a warning too.
  - `falco_unknown_macro`, `falco_unknown_list`, `falco_unknown_rule`
  - `falco_unknown_source`, `falco_newer_syntax`
  - `falco_regex_simple`, `falco_field_as_value`, `falco_transformer_as_value`
  - `falco_deprecated_field`, `falco_unsafe_na_check`, `falco_no_evttype`
- **Sysdig block constraints are reported on their fields.** The engine reports them natively, as opentide names them.
  - `sysdig_rule_shape`, `sysdig_tuning_keys`, `sysdig_priority`, `sysdig_source`
  - `sysdig_exception_shape`, `sysdig_list_in_value`
  - `sysdig_definition_name`, `sysdig_definition_duplicate`
  - `sysdig_definition_order`, for macros
  - `sysdig_list_self_reference` (warning): a list naming itself
- **Field, event and default-rule catalogues come from Falco's own sources.** They are libsinsp's field tables with their types and flags, the driver's event and syscall tables, the plugin READMEs (k8saudit, cloudtrail, okta, github, gcpaudit, json, k8smeta, container) and the Falco default rules' macros and lists.
- **Macros, lists and tunings resolve as Falco loads them.** Block lists follow Falco's load order; default macros, lists and rules come from the first file that defines them (stable, incubating, then sandbox), and hover shows differing later ones. A tuning is judged on the default rule's condition with it appended (`falco_no_evttype`).
- **Falco completion follows the cursor.** Items are filtered by the word typed and carry a `textEdit` over the whole dotted prefix (`proc.ex`), also right after the end of a scalar.
  - at a check: fields, block macros and default macros
  - after a field: the operators, with modifiers, its type accepts
  - after an operator: the values of `evt.type`, `evt.dir`, `fd.type`, `fd.l4proto` and `evt.category`
  - inside `in (`, `pmatch (`, `intersects (` and modified operators' lists: block, then default lists
  - after `%` in the output: fields

### Changed

- **`configurations.sentinel.alert.techniques` takes ATT&CK v18 ids.** Microsoft Sentinel is aligned to ATT&CK 18, so the bundled Tide catalog gives the field the ATT&CK 18.1 techniques rather than ATT&CK 20.0's, and another value, such as `T1685` (ATT&CK v19), is `vocab_unknown` ([opentidehq/opentide#686](https://github.com/opentidehq/opentide/issues/686), specifications `platform-sentinel` 1.2). A rule's own `techniques` and the objective and threat ATT&CK fields are unchanged.
- **The bundled Tide catalog lists `configurations.sysdig`.** The block is `platform::sysdig::1.0`, regenerated from opentide with [opentidehq/opentide#733](https://github.com/opentidehq/opentide/issues/733) and [opentidehq/opentide#732](https://github.com/opentidehq/opentide/issues/732) together.

## [0.7.1] - 2026-11-03

Declared datasets carry their columns: in the corrected `visibility::1.0`, a log source's `name` is its table, sourcetype or index pattern, and the columns it lists feed the query checks, hover and completion.

### Upgrade

- If your `visibility.toml` uses the opentide 0.20.0 keys, write one `[[logsources]]` entry per table, sourcetype or index pattern, with it as the `name`: those keys declare nothing.

### Breaking

- **`visibility.toml` follows the corrected `visibility::1.0`.** A log source's `name` is its dataset: the KQL table for `sentinel` and `defender_for_endpoint`, the sourcetype for `splunk`, the index pattern for `elastic` ([#146](https://github.com/opentidehq/language-server/issues/146), [specifications#63](https://github.com/opentidehq/specifications/issues/63)). Once a workspace has a log source for a platform, an undeclared table, sourcetype or index pattern of that platform is reported.
  - the opentide 0.20.0 keys `tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views` and `ecs` declare nothing
  - Splunk indexes and macros, and Elastic data views, are no longer declarable
  - `ecs = true` no longer makes an index ECS: ECS checks run on `logs-*` data streams
- **The declared-dataset API takes no dataset kind.**
  - `DatasetKind` has `Tables`, `Sourcetypes` and `Indices` only, with `DatasetKind::of_system`
  - `DeclaredDatasets::status`, `names` and `declares` take no kind, and neither does the function `declare_dataset`
  - `DeclaredDatasets::from_names` takes `(platform, names)`
  - `opentide_ecs::data_view_not_declared` is gone

### Added

- **A log source may list its dataset's columns.** `[logsources.columns]` is keyed by column name, each `{ type, description }`; columns on a name with `*` apply to every dataset it matches, merged with an exact entry's, which wins on a same-named column ([#146](https://github.com/opentidehq/language-server/issues/146)). `docs/kql/columns.md` has the details.
  - KQL: a declared table with columns is checked like a documented one (`kql_unknown_column`, `kql_type_mismatch`)
  - KQL: they extend a catalog table's columns, replacing a same-named one's type and description
  - Elastic: fields are mapped for their index pattern, so a declared field is not `ecs_unknown_field` and its type is checked for `ecs_type_mismatch`
  - hover and completion show them, Splunk fields included
  - API: `DeclaredDatasets::sources`; `Catalog::for_workspace` and `opentide_ecs::with_declared_fields` apply them

### Changed

- **The declare-it quick fix appends a `[[logsources]]` entry.** Titled `Add a [[logsources]] entry declaring 'X' to visibility.toml`, it writes `name`, an empty `description` and `system`, and never edits an existing entry.
- **The bundled Tide catalog takes the current ATT&CK group labels.** `threat.actors.name` says `[Enterprise] APT28` where it said `[Mobile] APT28`; the values `threat::1.0` accepts are unchanged, as it still pins `actors::1.1`.

### Fixed

- **KQL `project-away`, `project-keep` and `project-reorder` accept column patterns.** `*`, `User*` and `*Id` are globs over the input columns, as in Kusto, not a `kql_parse_error`, so Sentinel's threat-intelligence idiom `| project-reorder *, IsActive, ...` parses ([#148](https://github.com/opentidehq/language-server/issues/148)). A pattern is never `kql_unknown_column`; `docs/kql/columns.md` says what each operator keeps.
- **A document starting with a UTF-8 byte-order mark is analysed.** Its YAML failed to parse, so no query was checked and the object was missing from the workspace index ([#150](https://github.com/opentidehq/language-server/issues/150)). The engine, server and CLI drop the mark, and positions are those of the text after it; a `visibility.toml` starting with one parses too.
  - engine: `opentide_tide::analyze`, `analyze_queries`, `extract_injections`, `index_object`, hover and completion
  - server: open documents and workspace files
  - CLI: `analyze` and `highlight`
  - API: `opentide_core::strip_bom` and `strip_bom_at`
- **Under declared tables, an unknown table is `kql_unknown_table` again.** It takes the profile's severity (a warning under `sentinel`, an error under `defender_for_endpoint`) and a message naming the declaration (`declare it for sentinel in visibility.toml`); only a catalog table the workspace does not declare is `kql_table_not_declared` ([#147](https://github.com/opentidehq/language-server/issues/147)). Defender's error gets the declare-it quick fix.
- **An undeclared lower-case KQL table is no longer silently accepted.** Once a workspace declares tables for the platform, names are checked whatever their case; without declarations, a lower-case name is checked only when it ends in `_CL`, as others may be workspace functions ([#149](https://github.com/opentidehq/language-server/issues/149)).
  - never tables: `let` bindings and tabular parameters
  - never tables: functions the engine knows (`_GetWatchlist`)
  - never tables: ASIM parsers, including names in their form (`_Im_*`, `im*`)
  - checked like any other: a name starting with `_`

## [0.7.0] - 2026-11-02

Queries are checked against the tables and columns they read: every Azure Monitor Logs, Defender XDR and ASIM table for KQL, the whole CIM for SPL, ECS for Elastic, and the datasets a workspace's `visibility.toml` declares.

### Added

#### KQL

- **The `sentinel` profile knows every Azure Monitor Logs table.** It knows all 943 with their columns, the Defender XDR tables the Defender XDR connector streams into a workspace, and the ASIM parsers and ingest-time `ASim*Logs` tables, so `NTANetAnalytics` or `DeviceProcessEvents` is no longer unknown ([#113](https://github.com/opentidehq/language-server/issues/113)). Attribution is in `NOTICE`.
- **KQL tracks columns through a query.** At every operator the engine knows the columns, their types and the operator that made each one, through `let`, `union`, `join`, `summarize` and the other column operators, and hover on a column shows its type and that operator ([#112](https://github.com/opentidehq/language-server/issues/112)). API: `opentide_kql::columns`; `docs/kql/columns.md` has the details.
- **`kql_unknown_column` (error) for a misspelt or missing column.** It reports a near miss of a documented column (`DstPortNumbr` suggests `DstPortNumber`), a name that is not a column after `project`, `summarize`, `distinct` or `count`, and one `project-away` or `project-rename` removed ([#113](https://github.com/opentidehq/language-server/issues/113)). Below an unknown source, `evaluate` or an unmodelled operator, nothing is reported.
- **`kql_type_mismatch` (error) for an operator a column's type lacks.** Kusto does not define `EventID has "46"`, `TimeGenerated > "2024-01-01"` or `Account between ("a" .. "b")` for those columns' documented types. Equality is not checked: Kusto accepts `EventID == "4688"`.
- **KQL hover and completion show a column's description.** It is the first sentence of the Azure Monitor Logs reference's description; in a `union` or `join`, hover describes a column from its own side's table, and on an ASIM column shows its class and schema with the schema's documentation link ([#139](https://github.com/opentidehq/language-server/issues/139)).
- **KQL function calls take named arguments.** `_Im_NetworkSession(starttime=ago(1d), dstportnumber=22)` parses (part of [#109](https://github.com/opentidehq/language-server/issues/109) A3), and ASIM parser parameters get signature help.
- **`kql_deprecated_operator` (warning) for legacy operator spellings.** `containscs`, `notcontains` and `notcontainscs`, which Kusto still parses, suggest `contains_cs`, `!contains` and `!contains_cs` ([#125](https://github.com/opentidehq/language-server/issues/125)).
- **A `defender_for_endpoint` hunt is checked against Defender's tables.** Each query knows its platform as a `configurations` key, the block's for a rule query and the entry's `system` for a hunt, and the platform picks the KQL profile and Lucene dialect for hover, completion and diagnostics.
  - API: `InjectedQuery::platform` and `QueryReport::platform`
  - API: `opentide_tide::hunt_query_language` maps a hunt's `system` (and Elastic `language`) to its language

#### SPL

- **SPL knows every CIM data model, dataset and field.** After `tstats ... from datamodel=`, `| datamodel`, `| from datamodel:` or `| pivot`, a near miss is an error: `spl_unknown_datamodel_field` for a field (`Processes.proces_name` suggests `Processes.process_name`), `spl_unknown_datamodel` for a data model or dataset ([#115](https://github.com/opentidehq/language-server/issues/115)). Completion offers lineage-prefixed fields and CIM's expected values; fields a site adds, and fields after `drop_dm_object_name`, are not checked.
- **Codes for SPL that Splunk accepts but that does nothing.** `spl_parse_error` means Splunk's own parser rejects the query, and a form it accepts that does nothing, returns nothing or searches for literal words has a code of its own ([#135](https://github.com/opentidehq/language-server/issues/135)). Each was checked against Splunk 10.6.1; `docs/spl/search-syntax.md` lists them.
  - `spl_empty_command`: a command with no arguments; a warning, or an error for `stats` and `| inputlookup`; `head`, `spath`, `fillnull` and `tojson` have defaults and are not reported
  - `spl_empty_stage` (warning): a trailing `|`, which Splunk ignores
  - `spl_command_without_pipe` (error): a query starting with a command but no `|`, which the fix adds; a command word followed by one term or none (`tstats`, `delete user`) is not reported, nor is `search ...`
- **`spl_search_operator` (error) for search comparisons that never match.** `==`, `<>`, `=>`, `=<` or `!~` in a search clause never matches in Splunk, so a detection that uses one never fires; the quick fix rewrites `==`, `<>`, `=>` and `=<` to `=`, `!=`, `>=` and `<=` ([#136](https://github.com/opentidehq/language-server/issues/136)). `=~` is a warning; `docs/spl/search-syntax.md` lists the clauses checked.
- **SPL knows the Machine Learning Toolkit commands.** `fit`, `apply`, `score`, `summary`, `listmodels` and `deletemodel` are in the catalog, marked `app = "MLTK"`, with hover and completion ([#123](https://github.com/opentidehq/language-server/issues/123)).

#### Elastic

- **Elastic queries over ECS indices are checked against ECS.** Where every index a query reads holds ECS documents (`logs-*` data streams, or indices a log source marks `ecs = true`), ES|QL, EQL, Kibana KQL and Lucene fields are checked ([#116](https://github.com/opentidehq/language-server/issues/116)).
  - `ecs_type_mismatch` (error): what Elasticsearch rejects, such as a wildcard on an `ip` field
  - `ecs_unknown_field` (warning): a near miss under an ECS field set, `process.nmae` for `process.name`

#### Declared datasets

- **`visibility.toml` declares a workspace's own datasets.** Each log source names tables, indexes, sourcetypes, macros, index patterns or data views, and a declared table is known ([#114](https://github.com/opentidehq/language-server/issues/114), [opentide#695](https://github.com/opentidehq/opentide/issues/695)). The server reads `.opentide/configurations/visibility.toml` at start-up and on every change, in the editor or on disk (it registers a file watcher), and checks every open document again.
  - `*` in a declared name matches any run of characters
  - text that is not TOML yet keeps the declarations in use
  - API: `opentide_analysis::Catalog.visibility`, `install_visibility` and `opentide_core::datasets`
- **Undeclared datasets warn once the platform has declarations.** Each warning has a code action that declares the dataset in `visibility.toml`, and a workspace that declares nothing sees no change.
  - `kql_table_not_declared`: a table the workspace does not declare ([#114](https://github.com/opentidehq/language-server/issues/114))
  - `spl_dataset_not_declared`: an undeclared `index=`, `sourcetype=` or base-search macro ([#115](https://github.com/opentidehq/language-server/issues/115))
  - `elastic_dataset_not_declared`: a rule's `index`, `threat.index`, `data_view_id` or ES|QL `FROM` no declaration covers, also in `analyze_queries` ([#116](https://github.com/opentidehq/language-server/issues/116))
- **`opentide_core::codes` has the codes for the dataset tiers.**
  - KQL: `kql_table_not_declared`, `kql_unknown_column`, `kql_type_mismatch`
  - SPL: `spl_unknown_datamodel`, `spl_unknown_datamodel_field`, `spl_dataset_not_declared`
  - Elastic: `ecs_type_mismatch`, `ecs_unknown_field`, `elastic_dataset_not_declared`

### Changed

- **Under `sentinel`, an unknown table is a `kql_unknown_table` warning.** The engine cannot see a workspace's tables, so a custom `_CL` or connector table failed every `opentide validate` since opentide 0.19.0 ([#111](https://github.com/opentidehq/language-server/issues/111), part of [#110](https://github.com/opentidehq/language-server/issues/110)). The message suggests declaring it in `visibility.toml`, a misspelt known table (`SigninLog`) keeps its suggestion, and `defender_for_endpoint` still reports an error.
  - API: `opentide_kql::Catalog` has a `profile` field, and its `TableRow` a `documented` one
- **A `union` leg is checked like a pipeline's source.** Under `union isfuzzy=true` it is not.
- **The SPL grammar accepts what Splunk's parser accepts.** A query that does not start with `|` is search terms, as Splunk runs it, while a word after a `|` is still a command, so a leading `tstats count ...` is no longer `spl_unknown_command` or `spl_parse_error` ([#135](https://github.com/opentidehq/language-server/issues/135)). `| | stats` and `| index=a` stay syntax errors, and these parse:
  - `where`, `search`, `fields`, `eventstats`, `streamstats`, `sistats`, `stats` and `lookup` with no arguments
  - `| inputlookup` with no table, as the first command
  - a trailing `|`
- **SPL searches parse comparison operators as Splunk does.** In a base search, `search`, a subsearch and `inputlookup ... where`, `==`, `<>`, `=>`, `=<` and `!~` parse with or without a term on either side and get `spl_search_operator`, a lint rather than a syntax error ([#136](https://github.com/opentidehq/language-server/issues/136)). `tstats ... where` still rejects them, as Splunk does.
- **A `|` inside `TERM(` or `(` ends the SPL stage.** As in Splunk, `TERM(x|y)` runs the command `y)`; a `|` inside quotes, comments, macros or a subsearch's `[ ]` does not ([#136](https://github.com/opentidehq/language-server/issues/136)).
- **`spl_unknown_command` is a warning, unless one edit from a command.** An app on the search head can add commands (DECRYPT2's `decrypt`, MISP42's `mispsearch`), and `opentide validate` failed on searches that run ([#123](https://github.com/opentidehq/language-server/issues/123)). A near miss (`statz`) stays an error with its suggestion, and `stast` suggests `stats`, not `stash`: an adjacent swap counts less than one edit.

### Fixed

#### Tide queries

- **Queries come from the YAML structure, not lines saying `query:`.** A Splunk notable's drilldown search (`configurations.splunk.actions.notable.drilldown.search`, a `$token$` template) is no longer analysed as the rule's `configurations.splunk.search`, nor is a `query:` or `search:` nested anywhere else under a platform block ([#118](https://github.com/opentidehq/language-server/issues/118)).
- **Each response hunt is analysed in its `system`'s language.** Whatever the order of its keys, a hunt in `response.procedure.searches[]` is reported at its own path (`response.procedure.searches.0.query`), not as the rule's `configurations.<system>.query`; a `system` that is not a platform identifier (`Sentinel`, `Splunk ES`) is free text and is not analysed ([#118](https://github.com/opentidehq/language-server/issues/118)).
- **Folded and multi-line queries are analysed as their YAML value.** A folded (`>`, `>-`) or indentation-indicated (`|2`) block scalar, and a plain scalar below its key or over several lines, are analysed as the value, not as the text `>-` ([#118](https://github.com/opentidehq/language-server/issues/118)). Diagnostics map back through the folding to their line and column.
- **A quoted query is analysed as its value.** `query: "SecurityEvent\n| take 1\n"`, as `yaml.safe_dump` writes one, or a single-quoted query over several lines has its escapes decoded and lines folded instead of being analysed as source text ([#105](https://github.com/opentidehq/language-server/issues/105)).

#### KQL

- **`kql_join_summarize_before_project` no longer fires for `summarize`.** `summarize` returns only the columns it names, and projecting before `arg_max(T, *)` would change its result ([#109](https://github.com/opentidehq/language-server/issues/109) B3). A `join` warns only on a wide input: an earlier `summarize`, `distinct` or `count`, or a `let` ending in `project`, `summarize` or `distinct`, narrows it; the code keeps its name.
- **`kql_where_not_first` skips a `where` on a column the source lacks.** That covers a column a `join` brought in from its right side or an earlier operator made ([#109](https://github.com/opentidehq/language-server/issues/109) B2), and a pipeline that starts from a `let` is not a table reference.
- **KQL typed literals such as `datetime(...)` parse as literals.** `datetime(2024-01-01 10:00:00)`, `timespan(1d)`, `time(0s)`, `long(null)`, `double(0)`, `guid(...)` and the other `bool`, `int`, `real` and `decimal` forms were `kql_unknown_function`, and a date with a space or a `T` also a `kql_parse_error` ([#125](https://github.com/opentidehq/language-server/issues/125), [#109](https://github.com/opentidehq/language-server/issues/109)). As in Kusto, the value runs to `)` on the same line.
- **KQL forms Kusto accepts parse.** Their columns are tracked too (part of [#109](https://github.com/opentidehq/language-server/issues/109) A3).
  - a doubled quote in a verbatim string: `@'it''s'`
  - `.[...]` access on a dynamic value: `d.["a.b"]`, `d.[0].n`
  - quoted identifiers wherever a column is read or named: `['c']`, `["Display Name"]`
  - `parse-where`, which makes the same columns as `parse`
  - `distinct` with named expressions and `*`: `distinct b = tolower(a)`, `distinct *`
- **`externaldata` parses wherever a tabular expression may start.** That is a `let` value, a pipeline source and inside `in ((...))`; without its URI list it is still a syntax error ([#125](https://github.com/opentidehq/language-server/issues/125)).
- **A tabular parameter is a table inside its function body.** With `(T:(x:string))` or `(T:(*))`, `T | where ...` was `kql_unknown_table 'T'` ([#125](https://github.com/opentidehq/language-server/issues/125)).
- **`union` takes calls as legs, and `containscs` parses.** A call such as `g("a")` in `union isfuzzy=true g("a"), g("b")` is a leg ([#125](https://github.com/opentidehq/language-server/issues/125)).
- **KQL operators with their own syntax parse.** Each was a `kql_parse_error` ([#125](https://github.com/opentidehq/language-server/issues/125)):
  - `range x from 1 to 3 step 1`, also as a source
  - `project-reorder x asc` and `top-nested 3 of x by count()`
  - `fork (take 1) (take 2)` and `facet by x`
  - `sample-distinct 1 of x` and `partition by x (take 1)`
  - `scan ... with (step s: x == 1;)`

#### SPL

- **SPL search clauses from deployed detections parse.** The base search, `search`, `tstats ... where` and subsearches no longer report `spl_parse_error` on these forms, while upper-case `AND`, `OR` and `NOT` stay reserved ([#120](https://github.com/opentidehq/language-server/issues/120)):
  - `TERM()` and `CASE()` contents, raw, even without the `)`
  - `tstats ... by PREFIX(src=)` and `by _time span=1h` (`PREFIX(src=)` is still an error as a `where` term)
  - a quoted field (`"a.b"=x`) or one holding `-` or `{}`
  - values such as `earliest=-1h@h`, `latest=now()` and `host=S-RC*`
  - `IN` with a space-separated list
  - a search that starts with a quoted phrase or `NOT`
- **SPL `eval` and `where` expressions from deployed detections parse.** They no longer report `spl_parse_error` on these, and `*` stays multiplication ([#121](https://github.com/opentidehq/language-server/issues/121)):
  - `.` concatenates, as in `a."-".b`
  - `true()`, `false()`, lower-case `like` and `!` for negation
  - an assignment to a quoted (`"a.b"=`) or dynamic (`{f}=`) field
  - `foreach` templates as names: `<<FIELD>>`, `r<<MATCHSTR>>`
  - a subsearch or a `$token$` for a value
- **SPL command arguments from deployed detections parse.** A known command is never a syntax error because its arguments are not modelled, while `rename a as`, `stats values(` and `lookup t` with no field still are ([#122](https://github.com/opentidehq/language-server/issues/122)).
  - case-insensitive keywords: `rename a as b`, `stats ... BY`
  - field names with `-`, `{}`, `@` and `$`: `a{}.b`, `t-include.csv`
  - globs and doubled or trailing commas: `values(*) as *`, `rename DNS.* as *`
  - one rule for `stats`, `eventstats`, `streamstats`, `chart`, `timechart`, `geostats` and the `si` forms, reused by `tstats`
  - a macro for a field, table or aggregate, and a quoted name for a by-field
- **An SPL comment may span lines.** It may also open with more than three backticks; a second line was reported as `unknown SPL command`.
- **SPL commands Splunk rejects without arguments are syntax errors again.** `append`, `top`, `rare`, `transaction`, `bin`, `geostats` and 42 other catalogued commands (`xyseries`, `regex`, `iplocation`, `rest`, `metadata`, ...) were accepted with none, and `geostats` with a `by` clause and no aggregate is an error too ([#135](https://github.com/opentidehq/language-server/issues/135)).
- **SPL syntax errors point at the bad token.** Every error ran from the query's first line to its end; `spl_parse_error` marks the first bad token of each error region (`SPL syntax error: unexpected '.'`), an unclosed `(` or `[`, or a missing token, at most five per query ([#119](https://github.com/opentidehq/language-server/issues/119)). Unbalanced parentheses say so, on the parenthesis.
- **`spl_unknown_command` is reported only in command position.** That is after a `|` or first in the query or a subsearch, outside an error region; a word error recovery stranded, such as `dest` in `| lookup t-x.csv key AS dest OUTPUT c AS m`, was reported as an unknown command ([#119](https://github.com/opentidehq/language-server/issues/119)).
- **`spl_wildcard` and `spl_leading_not` look only at the base search.** They describe the cost of reading the index, so a later `| search NOT outcome="Failure"` is no longer flagged, and `field=*`, the existence check, is never `spl_wildcard`, though a bare `*` term still is ([#124](https://github.com/opentidehq/language-server/issues/124)). A leading or mid-token wildcard is flagged only when no `index=`, `sourcetype=`, `source=`, `host=`, `TERM()`, `PREFIX()` or macro narrows the read.

## [0.6.0] - 2026-10-29

A host API lets opentide compile the engine into its Python package, each Tide object is checked against the schema revision it names, and `@opentide/lsp-client` works on stdio, a browser worker and WASI.

### Upgrade

- If you use `@opentide/lsp-client`'s `worker` transport, pass the `opentide-wasm` module you load with `@opentide/lsp-worker` as `module`.

### Breaking

- **The `worker` transport takes `module` instead of reading a global.** `@opentide/lsp-client`'s `worker` transport calls the `opentide-wasm` module it is given ([#14](https://github.com/opentidehq/language-server/issues/14)).

### Added

#### Hosts and crates

- **`opentide-analysis` has a host API for the `opentide` Python package.** opentide drives the engine through it ([opentide#332](https://github.com/opentidehq/opentide/issues/332), [#16](https://github.com/opentidehq/language-server/issues/16)).
  - `analyze_queries`: every query of a Tide object, finding or not, with language, YAML path, place, diagnostics
  - `analyze_query`: one query with its platform's profile (Defender KQL, Carbon Black Lucene, an ES|QL stack)
  - `install_catalog`: a workspace's Tide field and deprecation catalogs in place of the bundled ones
  - `analyze_with_index`: one workspace index across files
  - `VERSION`
- **Hosts control and inspect the engine's Tide catalogs.** A host that generates them from its own models, as opentide does, is never behind the snapshot compiled in, even after `initialize` finds no workspace catalog, and can tell whether the engine it bundles matches its models.
  - `opentide_analysis::set_default_catalog`: replaces the bundled catalogs process-wide while no workspace catalog is installed ([opentide#677](https://github.com/opentidehq/opentide/issues/677))
  - `opentide_lsp::use_host_catalogs()`: keeps `initialize` from replacing them with a committed workspace copy
  - `opentide_analysis::bundled_catalog()`: the compiled-in catalogs, as their files hold them ([#99](https://github.com/opentidehq/language-server/issues/99))
- **`opentide-analysis` re-exports every type its functions use.** A host, such as the `opentide` Python package or an editor, depends on it alone, and its crates.io page shows a usage example.
- **`opentide-lsp` is also a library.** `opentide_lsp::run_stdio` serves the protocol from a host's own process.
- **`opentide_core::codes::ALL` lists every diagnostic code.** `codes::describe` gives each one a sentence, for hosts that explain a code (`opentide explain`).
- **`cargo binstall opentide-lsp` installs the release binary.** It downloads the binary for the target instead of compiling the workspace.

#### Tide objects

- **Each Tide object is checked against its schema revision.** The revision its `metadata.schema` names sets the required fields, so a `rule::1.1` without `description` is reported, and a key the revision does not define is a `schema_validation` error, except legacy spellings opentide accepts ([#98](https://github.com/opentidehq/language-server/issues/98)). Catalogs keyed by family, from an older `opentide generate schemas`, still load.
- **Every catalog field with an enum is checked (`vocab_unknown`).** The check covered a hand-picked few, which left out `response.alert_severity`, `objective.type`, `objective.composition.strategy` and the signals' fields ([#98](https://github.com/opentidehq/language-server/issues/98)).
- **`recommended_field_missing` (warning) for a field the templates ask for.** It reports a missing field `opentide validate` does not require, such as a rule's `configurations` and `response`: the catalog's `required` follows what validation requires, and such fields are `recommended`.
- **The server reads the workspace's generated field catalog.** `.opentide/lsp/catalogs/generated/fields.json`, which `opentide generate schemas` writes, is read with `deprecations.json`, by `opentide-lsp analyze` too, so hover, completion and vocabulary checks follow the workspace's schemas, custom vocabulary included. A catalog that does not parse is reported on stderr, and the bundled one is used.

### Changed

- **The bundled Tide catalogs come from opentide 0.18.0's own generator.** `opentide.generation.lsp_catalog`, which `opentide generate schemas` also runs, generates them instead of a copy of it ([#100](https://github.com/opentidehq/language-server/issues/100)), and hover shows the field descriptions 0.18.0 added.
- **The other library crates point to `opentide-analysis` on crates.io.** Their pages say they are engine components.
- **The workspace deprecation overlay is process-wide.** A host that analyzes on several threads sees the one it installed; it was per thread.

### Fixed

#### Tide objects and queries

- **A rule's `severity: High` is no longer `vocab_unknown`.** Without a generated workspace catalog, the bundled one, from opentide 0.16.1, checked a rule's severity against the threat severity scale; opentide 0.18.0's takes `alert_severity` values.
- **The shape check reads YAML as opentide does.**
  - a `<<` merge key fills the fields it merges instead of being an unknown key
  - a key that is not a string (`1: x`) is not a field
  - a bad enum value in a later list item is reported there, once per item
  - a quoted, non-ASCII or flow-mapping unknown key is placed on its key, not the file's top
- **A quoted query key is still a query.** `"query": |` or `'sentinel':` left the query unchecked.
- **Positions after non-ASCII text in a block-scalar query are correct.** A diagnostic after `é` or an accented comment in a `query: |` pointed too far right and could spill onto the next line, as did semantic tokens and hover. An injected query's span starts at its text, not at its first line's indentation.
- **An indentation-indicated query block no longer panics.** That is a `query: |2` whose later line is indented less than the first and holds a multi-byte character.
- **A KQL query may start with `search` or `find`.** `search "mimikatz"`, `search in (SecurityEvent) "x"` and `find in (T) where ...` were a `kql_parse_error`; only `T | search ...` parsed.

#### Workspaces and clients

- **Workspace paths with a space or a drive letter work.** `rootUri` and document URIs are percent-decoded, and `file:///c%3A/...` becomes `c:/...`, so the server finds the workspace's objects and catalogs; the locations it returns are percent-encoded.
- **One unreadable workspace file no longer drops the object index.** A file that was not UTF-8 or not readable made the stdio server report every reference to another object as `invalid_ref`, and `analyze` on a Tide object fail; that file is left out and the rest of the workspace resolves.
- **`opentide-lsp analyze` on a query file ignores the directories around it.** Outside a workspace, a `.kql`, `.spl`, `.esql`, `.eql`, `.kuery` or `.lucene` file walked its grandparent directory, so one YAML file there that was not UTF-8 failed the command.
- **`@opentide/lsp-client` works on all three transports.** `analyze` returned no diagnostics, `wasi` did nothing and `legend()` lacked `markdown.*` and `macro` ([#14](https://github.com/opentidehq/language-server/issues/14)). A transport that cannot answer rejects, as does an unknown language id.
  - `stdio`: keeps one `opentide-lsp --stdio` running and calls `opentide/analyze` and `opentide/highlight`
  - `worker`: calls the `opentide-wasm` module
  - `wasi`: runs the `wasm32-wasip1` CLI under `node:wasi`, passed as `wasi`

## [0.5.0] - 2026-10-26

ES|QL, EQL, Kibana KQL and Lucene rules get the same editing support as KQL and SPL, and the server installs from crates.io with `cargo install opentide-lsp`.

### Added

- **ES|QL, EQL, Kibana KQL and Lucene get editing support.** Kibana KQL is `kuery`; each has a grammar, with highlighting, diagnostics, hover, completion, signature help, and injection into Tide rule queries ([#88](https://github.com/opentidehq/language-server/pull/88)).
- **An Elastic Common Schema field catalog for the Elastic engines.**
- **Every crate is published to crates.io.** `cargo install opentide-lsp` installs the server.
- **GitHub Releases carry one binary per target, named for it.**

### Changed

- **Every crate's version is the release version.** The internal crates are pinned to it.

### Removed

- **This repository no longer builds a Python wheel.** The Python bindings, and the `opentide` command that wraps the server, live in [opentidehq/opentide](https://github.com/opentidehq/opentide).

## [0.4.0] - 2026-10-23

KQL and SPL close the grammar and catalog gaps that a comparison with Microsoft's Kusto.Language and Splunk's own parser found.

### Added

- **KQL parses named aggregates, `mv-expand`, `make-series`, tabular `let` and more.** Multi-value lists, `between`, dynamic literals, member and index access, `mv-apply`, `evaluate`, `datatable`, operator options, tabular functions, `materialize` and `toscalar` parse too; every Sentinel rule in the corpus parses.
- **The KQL catalog adds 32 functions and 17 plugins.** They come from Microsoft Learn, and 15 deprecated aliases warn `kql_deprecated_function`.
- **SPL parses multiple aggregations, leading macros and boolean groups.** `tstats where` in search syntax and field lists parse too, and SPL knows searchbnf aliases and `Risk.All_Risk`.

### Changed

- **Tide catalogs are generated from opentide 0.16.1** ([#75](https://github.com/opentidehq/language-server/pull/75)).
- **The project is spelled opentide, and Opentide in class names** ([#74](https://github.com/opentidehq/language-server/pull/74)).

### Fixed

- **KQL `evaluate` plugins are checked against the plugin catalog.**
- **KQL `let`-bound names are no longer flagged as unknown.**
- **SPL `dedup` requires a field.**

## [0.3.0] - 2026-09-29

KQL and SPL signatures follow Microsoft Learn and the Splunk Search Reference, and slow query shapes warn, with vendor citations.

### Added

- **Slow KQL and SPL query shapes warn, with vendor citations.** They are a late `where`, unscoped `search` or `union`, wildcard tables, `join` or `summarize` before `project`, leading and mid-token wildcards, and truncating subsearches ([#61](https://github.com/opentidehq/language-server/pull/61)).
- **SPL completion, hover and signature help from Search Reference arguments** ([#60](https://github.com/opentidehq/language-server/pull/60)).
- **Standalone `.kql` and `.spl` files are first-class documents** ([#59](https://github.com/opentidehq/language-server/pull/59)).
- **Tide lists and public KQL and SPL faults are validated** ([#53](https://github.com/opentidehq/language-server/pull/53)).

### Changed

- **KQL signatures and operator options follow Microsoft Learn's syntax.** Each item's syntax comes with its parameter docs ([#62](https://github.com/opentidehq/language-server/pull/62)).

### Fixed

- **Tide YAML keys keep one color at every nesting depth** ([#58](https://github.com/opentidehq/language-server/pull/58)).

## [0.2.0] - 2026-09-24

Tide hover, completion and highlighting come from opentide 0.5.0's schema export, and deprecated fields warn.

### Added

- **Tide fields resolve by schema family and YAML path.** They are generated from opentide 0.5.0.
- **Deprecated Tide fields warn, with a workspace overlay.** The overlay lives at `.opentide/lsp/catalogs/`.
- **KQL columns, SPL macros and CIM models, signature help.** The KQL columns are Sentinel's and Defender's, and SPL also covers `tstats`.
- **Markdown is highlighted inside Tide description, analysis and recommendation blocks.**
- **Six LSP features, from folding to document highlights.**
  - folding
  - selection ranges
  - workspace symbols
  - code actions
  - inlay hints
  - document highlights
- **GitHub Releases carry the highlights zip and native binaries.**

### Fixed

- **Every incremental edit applies.**
- **Closing a document clears its diagnostics.**
- **SPL `tstats` `as` and `where` are highlighted.**

## [0.1.0] - 2026-09-16

The first working server serves KQL, SPL and Tide YAML over stdio and WASM, with the highlighting spec every editor shares.

### Added

- **I/O-free KQL and SPL engines on vendored tree-sitter grammars.** Their catalogs come from Microsoft Learn and the Splunk Search Reference.
- **Tide YAML with the UUID graph.** KQL and SPL are injected into rule queries.
- **A frozen HighlightSpec with generated editor maps.** Semantic tokens use the standard LSP legend.
- **Stdio and WASM hosts, with Zed, Helix and Neovim samples.**

[0.16.1]: https://github.com/opentidehq/language-server/compare/v0.16.0...v0.16.1
[0.16.0]: https://github.com/opentidehq/language-server/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/opentidehq/language-server/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/opentidehq/language-server/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/opentidehq/language-server/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/opentidehq/language-server/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/opentidehq/language-server/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/opentidehq/language-server/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/opentidehq/language-server/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/opentidehq/language-server/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/opentidehq/language-server/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/opentidehq/language-server/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/opentidehq/language-server/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/opentidehq/language-server/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/opentidehq/language-server/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/opentidehq/language-server/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/opentidehq/language-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/opentidehq/language-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/opentidehq/language-server/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/opentidehq/language-server/releases/tag/v0.1.0
