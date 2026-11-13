# Changelog

All notable changes to the `opentide` package are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Version numbers come from git tags via hatch-vcs.

## [Unreleased]

opentide's command line, MCP server, language server, `opentide tui` and `opentide serve` run on one Rust core: a far smaller install, commands that start in milliseconds, and SDKs for Python, Rust and Node.js. These notes are for opentide 1.0.0, released first as release candidates (`1.0.0rc1` on PyPI, `1.0.0-rc.1` on crates.io, and so on) until the final 1.0.0; breaking changes may still land between candidates, before the final 1.0.0.

### Upgrade

- If you install opentide on Alpine Linux or another musl distribution, install a Rust toolchain first: no musllinux wheel ships, so `pip install opentide` builds from the sdist. If you pinned an `opentide-lsp-*-unknown-linux-musl` binary, build `opentide-lsp` with `cargo install opentide-lsp` instead.
- If your code imports a library that came with opentide's install (`requests`, `rich`, `typer`, `pyyaml`, a vendor SDK, …), add it to your own dependencies: opentide installs `pydantic` alone.
- Run `opentide validate` and fix what it refuses: Tide objects are read as YAML 1.2 and field types as declared, so `enabled: yes`, `"42"` in an integer field, a merge key (`<<: *base`) or an unquoted `created: 20260101` no longer pass.
- If you deploy to CrowdStrike, run `opentide validate query --platform crowdstrike` and fix the `cql_*` errors it reports, so `opentide validate` keeps passing in CI.
- If the `[filenames] pattern` of your `lint.toml` uses look-around or back-references, rewrite it without them: it is read as a Rust regular expression.
- If your CI deploys on a pull or merge request from a shallow checkout, fetch the base branch too (`fetch-depth: 0` in GitHub Actions): opentide reads it from the checkout and no longer fetches `origin`.
- If you installed shell completion with an earlier opentide, run `opentide --install-completion` again to replace the script: an earlier one asks the Python command line, and now prints that it is out of date on each Tab press.
- If your editor setup, a suppression list or a SARIF baseline names `filename_slug`, name `filename_mismatch` instead, and set the file name convention you want in `[filenames]` of `lint.toml` (`opentide explain filename_slug`).
- If it names `missing_author`, `missing_organisation` or `recommended_field_missing`, name `metadata_recommended` instead, and list the keys you recommend in `[metadata] required` of `lint.toml` (`author` and `organisation` when it says nothing).
- If it matches the editor's `filename_pattern`, run `opentide lint --check filenames` for it: `opentide lint` still reports it, as `[filenames] pattern` in `lint.toml` decides.
- If you edit a committed `.opentide/lsp/catalogs/generated/fields.json` to change what the editor offers, change the workspace's configuration instead.
- If you host the language server from Python through `opentide._native` (`serve_stdio`, `install_catalog`, `install_configuration_schemas`, …), run `opentide lsp start` instead: the server generates its catalogs and schemas and checks configuration files itself.
- If an MCP client reads `metaschemas`, `definitions` or `subschemas` from `opentide://index`, read the editor schemas from `opentide://schemas/{object_type}` instead.
- If your SDK code imports a Tide model from `opentide.models` (`DetectionRule`, `ThreatVector`, `SentinelConfig`, …), catch `opentide.models.ValidationError` (a `ValueError`) where you caught `pydantic.ValidationError`, test `isinstance(rule, (DetectionRule, DetectionRule_v1_1))` where you tested `DetectionRule`, and read `rule.file` as a `str` ([Models](docs/sdk/models.md)).
- If it calls `Opentide.initialise()` (or `from opentide import Opentide`) and reads `Opentide.Rules`, `Objectives` or `Threats`, open the workspace with `opentide.Workspace.open(".")` and call `rules()`, `objectives()` and `threats()` instead; `Opentide.Index` and the catalogue helpers are `ws.info()`, `ws.catalog()` and `ws.coverage(technique)`, and `Opentide.Platforms` is `ws.tenants(platform)` with `opentide.Connection` ([migration](docs/sdk/migration.md)).
- If it calls `opentide.validation.session.run_validation` or `ValidationScope.full()` / `.narrow()`, call `Workspace.validate()`, with `files`, `uuids` and `types` for a narrowed scope; a rule's `validate()` is `ws.validate(uuids=[uuid])`.
- If it writes documentation with `opentide.documentation.write_all`, `write_rules`, `write_objectives`, `write_threats` or `run`, or renders one object with `render_rule`, `render_objective` or `render_threat`, call `Workspace.run_json(["generate", "docs"])` (or `["generate", "docs", "rules"]`, ...).
- If it deploys with `rule.deploy(platform, dry_run=True)`, call `ws.deploy_plan(uuids=[uuid], platform=platform, strategies=[...])`; a real deploy is `ws.run_json(["deploy", ...])`, or `await opentide.Connection.open(tenant).deploy(...)` for one compiled rule. `rule.validate_query(platform)` and `rule.run_query(platform)` are `Connection.validate_query` and `Connection.query`, and `opentide.analysis.check_query` checks a query offline.
- If it imports anything else of the package (`opentide.cli`, `opentide.core`, `opentide.platforms`, `opentide.deployment`, `opentide.validation`, `opentide.loading`, `opentide.registry`, `opentide.generation`, `opentide.query`, `opentide.mcp_server`, the Pydantic machinery `TideModel`, `TideField`, `TideRegistry`, the result models `ValidationResult` and `DeploymentResult`, or `opentide.models.delegation`), call `Workspace.run_json([...])` for the command's `--json` document, or use the Rust classes of `opentide.models` for a Tide object. A platform plugin that uses only `opentide.plugins` needs no change.

### Breaking

- **Every command needs opentide's compiled core: the Python implementation is removed** ([#841](https://github.com/opentidehq/opentide/issues/841)). `opentide` and `python -m opentide` hand their arguments to the Rust core compiled into the package, in the same process. When it does not load, they print `error: The opentide analysis engine does not load: …` with the reinstall command on stderr and exit `1`, where 0.28.0 still answered the commands that do not need the engine.
- **`pip install opentide` installs `pydantic` alone** ([#841](https://github.com/opentidehq/opentide/issues/841)). The Python implementation's libraries are no longer installed with it (`typer`, `rich`, `textual`, `questionary`, `structlog`, `ruamel.yaml`, `pyyaml`, `orjson`, `tomli-w`, `dulwich`, `platformdirs`, `requests`, `mcp`, `pymisp`, `azure-identity`, `azure-monitor-query`, `splunk-sdk`, `carbon-black-cloud-sdk`, `boto3`, …): a fresh virtual environment holds six packages. `pydantic` stays for the plugin API's `configuration_model`. Code that imported one of the others through opentide's install declares it itself.
- **The deprecated SDK entry points are removed, with no shims** ([#841](https://github.com/opentidehq/opentide/issues/841)): `Opentide.initialise()` and the registry (`from opentide import Opentide`, `OpenTide`, `Opentide.Rules`, `Objectives`, `Threats`, `Index`, `Platforms`, `render_rule`, `validate_rule`), `opentide.validation.session.run_validation` and `ValidationScope`, and the documentation writers (`opentide.documentation.write_all`, `write_rules`, `write_objectives`, `write_threats`, `run`, `render_rule`, `render_objective`, `render_threat`). Each has an `opentide.Workspace` equivalent (Upgrade; [migration](docs/sdk/migration.md)).
- **opentide's undocumented internals are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)). The package keeps the console script, the SDK (`opentide.Workspace`, `run_json`, `Connection`, `TenantConfig`, `OpentideError`), `opentide.models`, the plugin API (`opentide.plugins`), `opentide.analysis` (`check_query`, `highlight`, `describe`, `engine_codes`, `engine_versions`, `EngineUnavailableError`) and the native binding; a plugin that uses only `opentide.plugins` keeps working. Gone:
  - `opentide.cli`, `opentide.core`, `opentide.platforms`, `opentide.deployment`, `opentide.states`, `opentide.validation`, `opentide.loading`, `opentide.registry`, `opentide.indexing`;
  - `opentide.generation`, `opentide.documentation`, `opentide.export`, `opentide.extraction`, `opentide.ci`, `opentide.sharing`, `opentide.query`, `opentide.mcp_server`, `opentide.vocabulary`, `opentide.mutation`, `opentide.vulnerability_lookup`, and the Python modules of `opentide.schemas` (its bundled data stays);
  - in `opentide.models`: the Pydantic machinery (`TideModel`, `TideField`, `TideRegistry`), the result models and constants (`ValidationResult`, `DeploymentResult`, `RULE`, `CORE_OBJECT_TYPES`, `EnumRegistry`, `SchemaVersion`, …), the submodules it aliased (`opentide.models.results`, `.configuration`, …) and `opentide.models.delegation`;
  - `opentide.analysis.check_queries` and the catalog helpers;
  - the `opentide.platforms` entry points of the built-in platforms.
- **`opentide.models` holds the Tide models as Rust classes, and imports in about 8 ms** ([#815](https://github.com/opentidehq/opentide/issues/815)). `from opentide.models import DetectionRule` (and `opentide.models.rule`, `.objective`, `.threat`, `.metadata`, `.platform`, `.platform_configs`, `.response`) gives the frozen class compiled into opentide, with `model_validate`, `model_dump`, `model_copy`, `model_json_schema`, equality, hashing, `repr` and pickling ([Models](docs/sdk/models.md)); importing it no longer loads Pydantic (about 200 ms). `model_validate` raises `opentide.models.ValidationError`, not Pydantic's; `DetectionRule_v1_1` is no longer a subclass of `DetectionRule`; `model_copy(update=...)` validates the copy; `model_json_schema()` is the schema the CLI generates, not Pydantic's.
- **`opentide validate` checks CrowdStrike queries, and fails a rule whose query Next-Gen SIEM would refuse** ([#790](https://github.com/opentidehq/opentide/issues/790)). `validate`, `validate query`, `lint` and MCP `validate_query` check `configurations.crowdstrike.query` and hunts with `system: crowdstrike` as CQL, as the editor has since 0.24.0: `validate` reports their `cql_*` errors, `lint` their `cql_*` warnings, and the SARIF rule catalogue lists the codes. `validate query --platform crowdstrike` checks offline where it reported `supported: false` and exited `1`; `--live` still reports `supported: false`, since opentide calls no CrowdStrike query check ([Platforms](docs/usage/concepts/platforms.md#crowdstrike-the-offline-cql-checks)).
  - **`crowdstrike_unsupported` is retired; it stays explainable.** `opentide explain`, MCP `explain`, the SARIF rule catalogue (tagged `retired`) and [Diagnostic codes](docs/cli/diagnostics.md#crowdstrike_unsupported) keep its page, which names the `cql_*` codes that report the problem now.
- **Tide objects and configuration files are read as their specifications say** ([#808](https://github.com/opentidehq/opentide/issues/808), [#809](https://github.com/opentidehq/opentide/issues/809), [#810](https://github.com/opentidehq/opentide/issues/810), [#811](https://github.com/opentidehq/opentide/issues/811)). A file 0.28.0 accepted can fail `validate`, and every other command reads it the same way:
  - **Tide objects are read as YAML 1.2**: only `true` and `false` are booleans (`enabled: yes` is the string `yes`), a date is the text written, a merge key (`<<: *base`) is an ordinary key, `017` is 17 and `1_000` a string, and a repeated key is compared by type and value ([YAML](crates/opentide-schema/YAML.md)).
  - **Field types are checked as declared**: a quoted number in an integer field is `int_type` and a quoted `"true"` in a boolean field `bool_type`, where Pydantic coerced them.
  - **`created` and `modified` are text**: `created: 20260101`, `true` or `null` is `schema_validation`, where Pydantic turned it into `'20260101'`, `'True'` or `'None'`; `2026-01-01` reads as before.
  - **A public reference number must be written as an integer**: a `references.public` key such as `abc`, `' 12 '`, `1.5` or `true` is `schema_validation` at the key, where 0.28.0 crashed on it or rewrote it.
  - **Sentinel durations are checked when the rule is validated**: `frequency: hourly`, a duration longer than 999999999 days or one written in other digits than ASCII's is `schema_validation` on the field, where it failed only at compile, or crashed deploy.
  - **Configuration files are read as TOML 1.0**: an integer past 64 bits is `config_parse`, and a `[filenames] pattern` in `lint.toml` with look-around or back-references is refused, with the reason.
- **The editor no longer reports `filename_slug`, `filename_pattern` or the metadata codes** ([#821](https://github.com/opentidehq/opentide/issues/821), [#926](https://github.com/opentidehq/opentide/issues/926)). `opentide lsp start`, the `opentide-lsp` binary and the browser build take an object's findings from `validate` itself, with the same codes, severities, messages and field paths, and add `lint`'s file name and metadata findings, which `opentide tui` counts beside each object (`! 1`); a quick fix is the edit `validate --fix` would write. The retired codes stay explainable.
  - **One rule names object files, in the editor and in CI**: the editor reports `lint`'s `filename_mismatch` (the slug of the name, or `<slug>-<uuid8>` when another object has the same name) and offers to rename the file, where `filename_slug` accepted `name-v2.yaml`; `filename_pattern` is `opentide lint`'s alone.
  - **Metadata recommendations have one code, in the editor and in CI**: `metadata_recommended`, one per object from `[metadata] required` in `lint.toml`, replaces `missing_author`, `missing_organisation` and `recommended_field_missing` (2,200 warnings on a clean 1,100-object workspace).
  - **The editor checks `metadata.reviewed` as `validate` does**: a word, a datetime without an offset or an impossible date is the field's `schema_validation`; a review date in the future stays accepted.
- **The language server builds its catalogs and schemas itself** ([#926](https://github.com/opentidehq/opentide/issues/926)). `opentide lsp start`, `opentide-lsp` and the browser build generate each folder's field catalogs and configuration schemas from the models and the workspace's configuration: a committed `.opentide/lsp/catalogs/generated/fields.json` is no longer read, and `initialize` reports `catalog: "models"`. `opentide._native`'s host functions are removed: `serve_stdio`, `install_catalog`, `set_default_catalog`, `use_host_catalogs`, `install_lint`, `install_visibility`, `set_configuration_checker`, `install_configuration_schemas`, `set_host_info`, `bundled_catalog`, `catalog_version`, `catalog_is_workspace` and `dataset_status`.
- **`opentide://index` leaves out the Python package's schema sources and data folders** ([#841](https://github.com/opentidehq/opentide/issues/841)). `metaschemas`, `definitions` and `subschemas` are gone (the editor schemas are at `opentide://schemas/{object_type}`), and so are `paths.vocabularies`, `resources`, `log_sources`, `platform_configs`, `platform_templates`, `configurations`, `core` and `raw`, which named folders of the Python package. Everything else in it is unchanged.
- **`deploy` on a pull or merge request reads its base from the checkout** ([#823](https://github.com/opentidehq/opentide/issues/823)). When the request's merge commit is not in the checkout, 0.28.0 fetched `origin` before reading `origin/<branch>`; opentide fetches nothing, so the CI job checks out both branches (`fetch-depth: 0` in GitHub Actions).
- **No musl builds: no musllinux wheel, and no musl `opentide-lsp` binary** ([#840](https://github.com/opentidehq/opentide/issues/840)). On Alpine and other musl distributions, `pip install opentide` builds from the sdist, which needs a Rust toolchain; `opentide-lsp` builds with `cargo install`. glibc Linux, macOS and Windows keep their wheels and binaries.

### Added

- **The Python SDK: `opentide.Workspace` over the Rust core** ([#837](https://github.com/opentidehq/opentide/issues/837)). `Workspace.open(path)` (or `from_files(root, files)` for a workspace in memory) reads every object once; `validate`, `lint`, `info`, `rules`, `objectives`, `threats`, `catalog`, `coverage` and `deploy_plan` then return the command line's `--json` data, keys in its order, and `run_json(argv)` runs any command in the process for its document. It releases the GIL while it runs and raises `opentide.OpentideError` with a stable `code` (`io_error`, `configuration_invalid`, `usage_invalid_choice`, `no_json_document`). `import opentide` still loads neither the SDK nor the engine: about 1 ms ([Workspace](docs/sdk/workspace.md)).
- **The Python SDK queries, checks and deploys on tenants, with `async` methods** ([#837](https://github.com/opentidehq/opentide/issues/837)). `Workspace.tenants(platform)` lists a workspace's tenants, and `opentide.Connection.open(tenant)` builds that tenant's client, with its own TLS, CA bundle, proxy, timeout and credentials ([Workspace](docs/sdk/workspace.md#tenant-operations)). `await connection.query(text)`, `validate_query` and `deploy(rule_id, operation, body)` return a `QueryResult`, a `LiveCheck` and a `DeployOutcome`, without the GIL while `asyncio` awaits them; cancelling the task, or `connection.canceller()`, stops one.
  - A failure raises `OpentideError` with the connectors' stable `code` (`tenant_refused`, `tenant_unreachable`, `credential_unset`, `operation_unsupported`, ...) and the vendor's words in `detail`.
  - A platform that cannot do an operation says so, never fakes it.
  - `TenantConfig`, `platforms()` and `capabilities(platform)` describe tenants and connectors in code.
- **The Rust SDK: the `opentide` crate** ([#836](https://github.com/opentidehq/opentide/issues/836)). opentide's Rust API, and the only opentide crate with a stability promise ([Rust SDK](docs/sdk/rust.md)): `Workspace::open` (or `Workspace::from_files` for a workspace in memory), `validate` and `lint` with their options and reports (each finding the one `Diagnostic`), `info`, `catalog` and `coverage`, `deploy_plan` (`deploy --dry-run`, nothing sent), and the Tide models (`opentide::models`). Features: `schema`, `workspace` and `compile` by default; `queries` (the offline query engines), `cli` (`cli::main`, `cli::run_json` and the `opentide` binary) and `lsp` (the language server) on request. Errors are one `#[non_exhaustive]` `opentide::Error`, each variant with a stable code. It publishes to crates.io with the engine crates it wraps, at opentide's version.
  - **A queries check without the engines reports `engine_unavailable`**: a build without the `queries` feature never skips the check; `validate` reports one `engine_unavailable` error and `lint` fails with that code.
- **The Rust SDK queries, checks and deploys on tenants: the `connectors` feature** ([#836](https://github.com/opentidehq/opentide/issues/836)). `Workspace::tenants(platform)` lists a workspace's tenants, and an `opentide::connectors::Connection` reaches one with its own TLS, CA bundle, proxy, timeout and credentials ([Rust SDK](docs/sdk/rust.md#query-check-and-deploy-on-tenants)): `query`, `validate_query` and `deploy` are `async` on tokio, `connectors::block_on` runs one from synchronous code, and a `Canceller` stops one. A failure is `opentide::Error::Connector`, with the connectors' stable code and the vendor's words in `detail`.
- **opentide for Node.js: the `@opentide/opentide` package, the SDK and the `opentide` command** ([#838](https://github.com/opentidehq/opentide/issues/838)). One npm package is both, as on PyPI, and runs the same Rust core in Node's process ([TypeScript SDK](docs/sdk/typescript.md)): `Workspace.open` (or `Workspace.fromFiles`), `validate`, `lint`, `info`, `rules`, `objectives`, `threats`, `catalog`, `coverage` and `deployPlan`; `runJson(argv)` for one command's `--json` document; and the `opentide` bin (`npx @opentide/opentide`). A failed call throws an `Error` whose `code` is a stable code, and TypeScript declarations ship with it. Its six native packages (`@opentide/opentide-<platform>`: glibc Linux, macOS and Windows, x64 and arm64) publish with every release.
  - **The three SDKs give the same documents, byte for byte** ([#839](https://github.com/opentidehq/opentide/issues/839)), on Linux, macOS and Windows, but for notation: JavaScript reads the command tree's `120.0` (`query --timeout`'s default) as `120`. The tenant operations (`query`, `validate_query`, `deploy` and their failures) are compared too, against stand-in SentinelOne and HarfangLab tenants on loopback.
- **The Node SDK queries, checks and deploys on tenants, with promises** ([#838](https://github.com/opentidehq/opentide/issues/838)). `ws.tenants(platform)` and `Connection.open(tenant, { environment, proxy, timeout })` work as in Python ([TypeScript SDK](docs/sdk/typescript.md#tenant-operations)): `connection.query(text, options)`, `validateQuery` and `deploy(ruleId, operation, body)` resolve to a `QueryResult`, a `LiveCheck` and a `DeployOutcome` on the Rust core's own threads, so Node's event loop keeps running. `start` and `end` take a `Date` or an RFC 3339 string; an `AbortSignal` in the options (`{ signal }`, the fourth argument of `deploy`) stops that one operation, and `connection.canceller()` stops all of a connection's (`interrupted`). A failure rejects with an `Error` carrying the connectors' stable `code` and the vendor's words in `detail`.
- **One release publishes opentide everywhere, at one version** ([#840](https://github.com/opentidehq/opentide/issues/840)). Each version reaches PyPI, crates.io (`cargo install opentide --features cli`) and npm (`npx @opentide/opentide`), and its GitHub Release carries `opentide` and `opentide-lsp` binaries for Linux, macOS and Windows with `opentide-installer.sh` and `opentide-installer.ps1`. Every artifact has a CycloneDX SBOM and a GitHub build provenance attestation; `SHA256SUMS` lists every asset. Until the final 1.0.0, release candidates are published as pre-releases on PyPI (`1.0.0rcN`: `pip install --pre opentide`) and crates.io (`1.0.0-rc.N`), with a GitHub pre-release; npm gets releases only.
- **Platform plugins: a package adds a detection platform with `opentide.plugins.PlatformPlugin`** ([#835](https://github.com/opentidehq/opentide/issues/835)). A plugin registered in the `opentide.platforms` entry-point group deploys (`opentide deploy --platform <id>`), checks a rule's query live (`validate query --live`) and runs queries (`opentide query`) as the built-in platforms do, with `--strategy`, `--dry-run` and its ids in deployment state. `validate` and `Workspace.validate` check each rule's `configurations.<id>` block with the plugin's model ([Platforms API](docs/sdk/platforms.md#platform-plugins)).
  - `query --rule` and `--file` do not read a plugin's block: they are a usage error (`usage_invalid_value`, exit `2`), so give the query as `QUERY` or `--query-file`.
  - The npm package and the standalone binary cannot load plugins; `validate` says so for each enabled platform that is not built in.
- **Configuration files are checked, with hover and completion, in every editor host** ([#821](https://github.com/opentidehq/opentide/issues/821), [#926](https://github.com/opentidehq/opentide/issues/926)). The `opentide-lsp` binary, its WASI build and the browser build check `.opentide/configurations/**/*.toml` with the checks `opentide validate` runs, and answer hover and completion there from the schemas the models generate, as `opentide lsp start` does; `configurationChecks` is always `true`.
- **Graylog event definitions deploy from opentide, on the Rust core** ([#970](https://github.com/opentidehq/opentide/pull/970)). A `configurations.graylog` block (`platform::graylog::1.0`) is one Filter & Aggregation event definition: a query in Graylog's search syntax, and optionally an aggregation condition (`count() >= 3 OR card(parent_image_lc) >= 2`), streams and notifications by tenant alias, a schedule (an interval, or a Quartz cron in an IANA time zone), event fields, an event key, a summary and remediation steps. Deploy reads the server version once per tenant (`GET /api/system`) and builds every request for Graylog 6.3, 7.0, 7.1 or 7.2, checks the query with `POST /api/search/validate` before every save but a disablement, and keeps the 24-hex definition id in `.opentide/states/deployment/`; a create that gets no answer is never sent again, and says which title and tag to find the definition by (`graylog_create_unconfirmed`). `opentide query --platform graylog` searches messages read-only (`POST /api/search/messages`), where `--index` names stream aliases, and `validate query --platform graylog --live` asks each tenant for a verdict over the block's window.
  - **`validate` checks Graylog blocks.** It reports every `graylog_*` constraint code of the specification (the query, the list fields, the schedule and its Quartz cron, the event limit, the aggregation condition grammar, nesting at most 32 deep, the event fields and key, the priority, the group-by field names), each at the `field_path` the specification fixes for it, and warns, as `lint` does, on a filter whose window overlaps its interval (`graylog_overlapping_window`) and on a definition no tenant gives a stream (`graylog_all_streams`).

### Deprecated

- **`model_fields`, `model_construct`, `model_rebuild` and `model_post_init` warn on the Tide models** ([#815](https://github.com/opentidehq/opentide/issues/815)). Pydantic's methods stay on the Rust classes with a `DeprecationWarning`, and go in a later minor release: read `__tide_fields__` for the fields, and call `model_validate` where you called `model_construct`. `model_rebuild` and `model_post_init` need nothing in their place: a Rust class is complete when compiled.

### Changed

#### The Rust core
- **The command line, MCP server, language server, `opentide tui` and `opentide serve` run on one Rust core** ([#790](https://github.com/opentidehq/opentide/issues/790), [#841](https://github.com/opentidehq/opentide/issues/841)). Every command keeps its options, `--json` documents, files, exit codes and `failure.code`s; each difference from the Python implementation was compared and approved, and is listed in this section. The npm package's `opentide` and `cargo install opentide --features cli` run the same program ([The implementation](docs/cli/json-output.md#the-implementation)).
  - **A crash names the build**: the crash log and the issue link say `build: rust (<target>)` where they said `python:`, and a panic reads `error[internal]: panic: <message>`.
- **Commands start in about 20 ms, and large workspaces are several times faster.** `opentide --version` takes 20 ms or less and `explain` 30 ms or less, where Typer loaded first; `validate` checks a 1,100-object workspace in 0.43 s in 50 MiB, and `generate docs` writes that workspace's pages in 0.5 s, where the Python implementation took 11.6 s.
- **`opentide mcp start` serves the same tools and resources from the Rust core** ([#829](https://github.com/opentidehq/opentide/issues/829), [#841](https://github.com/opentidehq/opentide/issues/841)). Its name, instructions, capabilities, tools, schemas, resources and answers are the Python server's, and it no longer needs the `mcp` package, so `setup mcp` always reports `mcp_available: true` ([opentide mcp start](docs/cli/mcp.md#mcp-start)).
  - **A missing or mistyped argument is refused in opentide's words**: `Error executing tool search: argument query is required`, `argument live must be a boolean (true or false), not 'sometimes'`, where the Python server quoted Pydantic's validation error; a configuration that does not parse is refused saying why.
- **`opentide serve` keeps its protocol, and reads JSON strictly** ([#830](https://github.com/opentidehq/opentide/issues/830)). Its messages, documents and warm workspaces are unchanged ([opentide serve](docs/cli/serve.md)), but for:
  - **A message JSON does not allow is a parse error**: `NaN`, `Infinity`, a lone surrogate (`"\ud800"`) or nesting deeper than 128 levels answers `-32700`.
  - **Request ids are compared as written**: a cancel for `1.0` or `true` no longer reaches the run `1`.
  - **A SIGTERM or SIGHUP the server was started ignoring (`nohup`) stops it**; `serve` exits `143` on SIGTERM.
  - **`duration_ms` is `0`** in the documents the host writes itself (a cancelled or refused run, a run in a missing directory, help text).
- **`opentide tui` is a new terminal UI, with the same tabs, keys and object page** ([#951](https://github.com/opentidehq/opentide/issues/951), [#841](https://github.com/opentidehq/opentide/issues/841)). It has the Catalogue, Coverage, Results, Visibility, Configuration and Chains tabs, the keys (`v`, `g`, `d`, `r`, `y`, `f`, `n`, `p`, `1`–`6`, `q`, `ctrl+p`) and what the language server and the last validate run report in place; it shows no credential value, and deploys from it are dry runs ([opentide tui](docs/cli/tui.md)). Where it differs from the Textual UI:
  - **The keyboard does what the mouse did**: `n` and `p` write a finding's message and hover on the status line, `f` follows a reference, `u` opens the page's *Not set* list, `/` types into the Visibility filter, and `Enter` folds a branch of the tree (`▼`, `▶`).
  - **No toasts**: what a run returned, and the wait for a running command, are said on the status line.
  - **The Results tab shows what the command prints at a terminal**, wrapped to the tab.
  - **`opentide tui` refuses where the UI cannot open**: `usage_tui_needs_tty`, exit `2`, in `json`, `agent` and `plain` mode or without a terminal, naming the setting that made the run plain, with `help: set OPENTIDE_OUTPUT=human to open it anyway`.
  - **The Configuration tab shows `sharing.toml`'s problems** ([#790](https://github.com/opentidehq/opentide/issues/790)): what `opentide validate --check sharing-config` reports, so a `sharing.toml` that is not valid TOML, not UTF-8 text, or names an unknown TLP shows an error there. A parse error says where (`line 4, column 14`), never what the line holds.
- **The analysis engine is built from opentide's own source** ([#800](https://github.com/opentidehq/opentide/issues/800), [#840](https://github.com/opentidehq/opentide/issues/840)). Its crates moved here from opentidehq/language-server with their history. Its assets (`highlights-vX.Y.Z.zip`, `opentide-wasm-web-vX.Y.Z.zip`, `THIRD-PARTY-LICENSES.html` and the `opentide-lsp` binaries) keep their names on opentide's GitHub Release `vX.Y.Z`, attested by `publish.yml` ([verify a download](crates/opentide-lsp/README.md#releases)), and the wheel and sdist ship `NOTICE`, the notices of the data the engine embeds.
- **`doctor` no longer checks Python** ([#841](https://github.com/opentidehq/opentide/issues/841), [#977](https://github.com/opentidehq/opentide/issues/977)). The `python_version` and `platform_sdk` rows are gone from its checklist, its JSON `checks` and its summary counts; `lsp_catalog` reports the catalog compiled into opentide and writes nothing to the user cache directory, and `analysis_engine` names the engine compiled in.
- **A vocabulary entry whose version cannot be trusted is left out** ([#812](https://github.com/opentidehq/opentide/issues/812)). In a data root's `*.vocab.toml` (`OPENTIDE_DATA_ROOT`), a `version` or `removed` written as a TOML number (`version = 1.10` reads as 1.1: write `"1.10"`), and an entry whose `removed` is not later than its `version`, is skipped with its reason. The bundled vocabularies are unaffected.

#### At a terminal
- **`--help` is laid out by clap** ([#841](https://github.com/opentidehq/opentide/issues/841)). The help says what 0.28.0's said (the usage line, the about text, each option, argument and command with its description, default and environment variable, the examples), as an indented list with one option per paragraph, where Typer drew boxed panels in two columns. The root lists its commands under the same headings, a flag pair is one option (`--staging, --no-staging`), and an environment variable is named (`[env: OPENTIDE_PROXY]`), never its value.
  - **"Did you mean" ranks by Jaro similarity**, after the same first rules (case and separators, known aliases, a unique prefix): a typo far from every choice can get a different suggestion, or none.
  - **An invalid choice is worded as every other one**: `setup ci githb` reads `Invalid value for 'ci_platform': 'githb' is not one of 'github', 'gitlab', 'azure'.`, with `help: did you mean 'github'?` and `failure.suggestion`.
- **Shell completion runs on the Rust command line, and completes the workspace's values** ([#841](https://github.com/opentidehq/opentide/issues/841), [#790](https://github.com/opentidehq/opentide/issues/790)). `--show-completion` and `--install-completion` take the shell as the word after them, or complete for the shell they run in, as before; `--install-completion` writes the script where it did (`~/.bash_completions/opentide.sh`, `~/.zfunc/_opentide`, `~/.config/fish/completions/opentide.fish`, PowerShell's `$PROFILE`) and adds the line that loads it once. The script is `clap_complete`'s registration: each Tab press runs `opentide` with `_OPENTIDE_COMPLETE` set, which answers from the command tree (commands, options, choices) and from the workspace, as the Python CLI did: object UUIDs for `--uuid` with each object's name, object files for `--file`, ATT&CK ids for `--technique`, enabled platforms first for `--platform`, tenants for `query --tenant`, and diagnostic codes for `explain`. A completion reads only the configuration and the first lines of each object file, never loads the catalogue, and answers in a few milliseconds for a catalogue of hundreds of objects. `_OPENTIDE_COMPLETE=bash opentide` prints the same script, to load it at each start instead (`source <(_OPENTIDE_COMPLETE=bash opentide)`). PowerShell's execution policy is left as it is.
- **Progress is one checklist row per step, printed when the step ends.** The spinners and live regions are gone: a step's row prints once its work is done (in milliseconds for most), `validate`'s `Validating objects` line is drawn once, and `validate --watch` redraws with plain cursor movements.
- **Log lines are plain, name no tenant, and JSON ones have no `logger`.** At a terminal a log line is one unstyled line, not wrapped; with `--json` it is a JSON object with the event's fields, `event`, `level` and `timestamp`, `error` where it said `critical`. Every log line writes a tenant's name or host as `***` (the result document still names it), and the warnings that named the Python implementation's own steps are gone.
- **Code frames and outcome lines render the same on every terminal** ([#826](https://github.com/opentidehq/opentide/issues/826)). `explain <code>` renders its page with the same renderers: headings on the left margin, code blocks indented, paragraphs wrapped at words.
  - Frames, glyphs and outcome lines stay in Unicode on every stream: no ASCII fallbacks for `PYTHONIOENCODING=ascii` or a cp1252 pipe.
  - Terminal widths come from `unicode-width`, and wide text wraps by cells: some emoji or East Asian characters move an underline by a cell.
  - Unprintable characters in quoted values are escaped as `\u{a0}`, where Python's `repr` wrote `\xa0`.
  - An underline covers a tab inside its span as the terminal expands it.
  - Control characters from a file print as control pictures (`␛`, `␡`), so a file cannot move the cursor or start a CI workflow command.
- **Prompts at a terminal are drawn by opentide.** The `setup`, `setup repo`, `setup mcp` and `setup skills` wizards ask the same questions with the same defaults on stderr (arrow keys and Enter for a choice, Space for a checkbox), `setup ci` asks one `Y/n` line, and `opentide new` asks for a name and platforms; Ctrl-C at a question stops the run (`error: interrupted`, exit `130`).
- **`info` draws its tables' header with light lines.** The header row's side lines are `│` like the rows', where they were `┃`, and a table wider than the terminal may come out a few cells narrower.

#### Findings and messages
- **"Did you mean" suggests what a typo meant, not a word that shares letters** ([#812](https://github.com/opentidehq/opentide/issues/812)). A vocabulary value is suggested when it has the same spelling once case, spaces, `-` and `_` are ignored, or is a few edits away (a third of the length at most, a swapped pair counting as one): `clearr` suggests `clear`, while `severity: Big incident` gets no suggestion (it was `Substantial incident`).
  - **The query engines suggest by the same rule**: KQL, SPL, ES|QL, EQL, CQL, Falco, Carbon Black and ECS no longer suggest an unrelated name (`WHR` no longer suggests `MMR`), and pick the same choice on every run (`stas` suggests `stash`); codes, severities and ranges do not change.
  - **A Sentinel ATT&CK id is read as an id is meant**: `t1059.001` suggests `T1059.001`, and `t1086` gets the retired-id hint (`use T1059.001`).
- **Every file with an invalid UUID is reported** ([#817](https://github.com/opentidehq/opentide/issues/817)). Five files sharing `not-a-uuid` give five `invalid_uuid` and four `duplicate_id`, where 0.28.0 gave one `invalid_uuid`; a copy left in `*.debug.yaml` scratch output is no longer a duplicate.
- **Findings point at the key or value they are about** ([#808](https://github.com/opentidehq/opentide/issues/808)). A value written `null` or `~` has a `yaml_line`, a value left empty points at its key, a key that is not a string is found, and a one-line collection inside a list is spanned whole.
- **An unknown schema revision is checked against the newest revision of its family** ([#813](https://github.com/opentidehq/opentide/issues/813)). An object whose `metadata.schema` names an unknown revision of its family (`rule::7.0`) still fails with the same code, and the error says which revision checked it, followed by that revision's other findings, as the editor already reported.
  - **An unknown schema identifier is quoted the same way whatever it holds**: `schema: true` is `'true'` (it was `'True'`), and a list or a mapping is `'[...]'` or `'{...}'`.
- **An impossible `reviewed` date is explained by the date library** ([#809](https://github.com/opentidehq/opentide/issues/809)). `'2026-02-30'` is still refused, in jiff's words; a year 0000 or an offset that leaves the years 0001 to 9999 is refused too, where 0.28.0 crashed on the offset.
- **A hunt's findings name the platform it runs on** ([#696](https://github.com/opentidehq/opentide/issues/696)). A finding in `response.procedure.searches[N].query` carries its `system` (`splunk`, `elastic`, ...) as `context.platform`, where it was `null`.
- **YAML, TOML and file errors are in the Rust readers' words** ([#811](https://github.com/opentidehq/opentide/issues/811), [#816](https://github.com/opentidehq/opentide/issues/816), [#946](https://github.com/opentidehq/opentide/issues/946)). Codes, files and exit codes are unchanged; the text differs:
  - `yaml_parse` names the YAML 1.2 parser's problem at the line where the construct starts, on one line;
  - `config_parse` quotes `toml_edit`, and a TOML date stays as written;
  - a file that cannot be read says `Permission denied (os error 13)`;
  - a `paths.toml` its model refuses fails the `docs`, `exports`, `explorer` or `inflight` step as `paths.toml: paths.core: Extra inputs are not permitted`;
  - a `--file` rule that does not validate is quoted without Pydantic's input value and documentation link.
- **`lint` and `validate --fix` treat a few edge cases differently** ([#818](https://github.com/opentidehq/opentide/issues/818)):
  - `--fix --dry-run`'s diff may show a change against the other copy of an identical line;
  - lines are counted where YAML breaks them, not also at form feeds, `\x85` and U+2028;
  - file names that differ only in case are compared in Unicode lower case (`ß` and `ss` are two names);
  - `--watch` wakes on the file system's events.
- **The editor schemas read differently, and accept the same files** ([#900](https://github.com/opentidehq/opentide/issues/900)). `generate schemas` and `setup vscode` write schemas that accept and refuse every object and configuration file as before:
  - keys in alphabetical order, without generated `title`s;
  - an optional field is `"type": ["string", "null"]`, and its `enum` lists `null`;
  - `metadata` and `references` refer to their definition (`$ref`), and each document declares `$schema` (draft 2020-12);
  - a dropdown title-cases by English rules (`Command and Control`, `It's`);
  - `objective.signals.data.logsources` offers the log sources `visibility.toml` declares.
- **The editor reads a Tide object's YAML as `opentide validate` does** ([#850](https://github.com/opentidehq/opentide/issues/850)):
  - an object `validate` cannot load (a tag such as `!Ref`, a key written twice, an integer past 64 bits) shows its `yaml_parse` error and no query findings, outline or highlighting;
  - an object nested more than 128 levels deep gets its query findings;
  - an unsaved object whose YAML does not load is checked as an object of the family its `schema:` line names.

#### Deploy, query and sharing
- **Tenants are reached through opentide's own connectors, not the vendor SDKs** ([#832](https://github.com/opentidehq/opentide/issues/832), [#833](https://github.com/opentidehq/opentide/issues/833), [#834](https://github.com/opentidehq/opentide/issues/834), [#979](https://github.com/opentidehq/opentide/issues/979)). `deploy`, `query`, `validate query --live`, `share`, `generate extract`, `setup skills` and `doctor` make the requests `azure-identity`, `azure-monitor-query`, `splunk-sdk`, `carbon-black-cloud-sdk`, PyMISP and `requests` made, through the proxy and CA bundles the environment names, and trust the system's certificate store too. A tenant that cannot be reached is described in the HTTP client's words. Beside that:
  - a CrowdStrike update the tenant refuses says "Was not able to update rule";
  - a Sysdig error whose `message` is not a string is quoted as JSON;
  - a `#` inside a word of a HarfangLab telemetry query is part of the word;
  - a Defender sign-in answered `200` without JSON is an authentication failure.
- **`deploy` previews and sends rules in a few other formats** ([#823](https://github.com/opentidehq/opentide/issues/823), [#895](https://github.com/opentidehq/opentide/issues/895)). Every request body is the one 0.28.0 sent, but for:
  - **A dry run's preview leaves out unset fields**: a block with no request body to show is written from its model without the `null` of every optional field it does not set, and a block its model refuses is shown as written.
  - **Unset variables are named in plan order**: "a real deploy would need $A, $B and $C" lists them platform by platform, then tenant by tenant.
  - **Splunk's risk objects are compact JSON**: `action.risk.param._risk` is written without spaces after `,` and `:`.
  - **HarfangLab's Sigma YAML quotes with double quotes**: a title with `: ` is written `"..."` where it was `'...'`; the rule reads the same.
- **`--changed` reads the repository without the `git` program** ([#834](https://github.com/opentidehq/opentide/issues/834), [#915](https://github.com/opentidehq/opentide/issues/915)). `lint --changed`, `generate docs --changed`, `share push --changed` and `deploy`'s change set read git with gitoxide: the files `git diff` and `git ls-files --others --exclude-standard` report, compared through git's clean filters (`core.autocrlf`, `.gitattributes`, filter drivers), so an untracked file an exclude file ignores is not a change.
- **Status promotion stops a deploy it cannot rewrite, before writing anything** ([#841](https://github.com/opentidehq/opentide/issues/841), [#979](https://github.com/opentidehq/opentide/issues/979)). No promotion target, a platform key that is not a string, promoted text that does not read back, or a rule file that is not YAML or not a mapping fails the run with exit `1`, naming `--skip-promotion`. A rule file that does not parse, or promoted text that does not read back (a target such as `LIVE}` written into a flow mapping), is named with the YAML 1.2 reader's words and place, on one line (`misplaced bracket`, `in "<unicode string>", line 13, column 27`), where PyYAML quoted the line with a caret under it.

#### Files opentide writes
- **`generate extract` and `opentide new` quote YAML by other rules, with the same data** ([#834](https://github.com/opentidehq/opentide/issues/834), [#933](https://github.com/opentidehq/opentide/issues/933)). A rule extracted again shows these lines as changed in a diff:
  - `generate extract elastic` and `sentinel` double-quote a value that needs quoting (`"2026-01-01"`, `"1"`, `""`), where they single-quoted it;
  - `generate extract elastic` writes non-ASCII text as UTF-8 (`résumé`), where it escaped it, and keeps a long one-line string on one line, where it folded it at 80 columns;
  - `opentide new` quotes a name by YAML 1.2's rule: `1e3` and `0o17` are quoted, `1_000` is not.
- **`setup ci` writes its pipeline with LF line endings on every OS** ([#916](https://github.com/opentidehq/opentide/issues/916)), Windows included, where it wrote CRLF there.

### Fixed

- **A HarfangLab deploy sends its rules** ([#895](https://github.com/opentidehq/opentide/issues/895)). 0.28.0's HarfangLab client read its settings as `Systems.HarfangLab`, a name the configuration registry has no entry for, so every HarfangLab deploy and telemetry search failed with `AttributeError: HarfangLab` before it sent anything. Both reach the tenant.
- **Defender rules keep `odata_type` in their text** ([#895](https://github.com/opentidehq/opentide/issues/895)). `odata_type` was replaced with `@odata.type` across the whole request body, so a rule whose query or description held `odata_type` (a KQL column such as `RawEventData.odata_type`) was sent changed; only the response actions' and impacted assets' keys are written that way.
- **A Sysdig rule that cannot compile is reported as Sysdig's** ([#823](https://github.com/opentidehq/opentide/issues/823)). `deploy --dry-run` described it as "Sentinel cannot compile this rule"; it names Sysdig, as `validate` does.
- **Changed rule files are read in path order** ([#823](https://github.com/opentidehq/opentide/issues/823)). A plan of changed rules listed them in an order that changed from run to run.
- **A credential whose variable is unset is refused before any request** ([#979](https://github.com/opentidehq/opentide/issues/979)). `deploy` sent the literal `$NAME` to the platform.
- **`setup` keeps comments, layout and line endings in the files it edits** ([#743](https://github.com/opentidehq/opentide/issues/743)). `setup mcp` merges opentide's server into `.vscode/mcp.json`, `.cursor/mcp.json`, `.mcp.json` or `opentide.mcp.json` in place, as `setup vscode` edits `.vscode/extensions.json` and `settings.json` and `setup skills --plugin` edits `.claude/settings.json`: comments, trailing commas, CRLF and a byte-order mark stay. `setup platforms` keeps a platform file's CRLF line endings.
- **Status promotion keeps a rule file's permissions** ([#987](https://github.com/opentidehq/opentide/issues/987)). A promoted rule committed as 0644 came back 0600, so the group and other users could no longer read it; it keeps its permission bits (Windows has none to keep).
- **`setup ci --promotion` refuses a `deployment.toml` it cannot read.** A file that is not UTF-8 is `usage_invalid_value` (exit `2`), left as it is, where it stopped on an internal error.
- **An object whose `uuid` is a list or a mapping is reported** ([#816](https://github.com/opentidehq/opentide/issues/816)) as `missing_uuid` (`object YAML uuid is a sequence, not text`), where `validate` crashed.
- **`validate --fix` fixes the first line of a file that starts with a byte-order mark** ([#818](https://github.com/opentidehq/opentide/issues/818)), which it left out.
- **A `reviewed` time with one, two, four or five fractional digits is accepted on Python 3.10** ([#815](https://github.com/opentidehq/opentide/issues/815)). `'2026-09-01T15:04:05.25-05:30'` failed with `Invalid isoformat string` on Python 3.10 and passed on 3.11 and later; every Python reads it now.
- **The editor's "Apply suggestion" keeps a pipe stage's arguments** ([#887](https://github.com/opentidehq/opentide/issues/887)). For an unknown KQL operator or SPL command, `index=main | stast count by host` became `index=main | stats`; the fix replaces the operator or command alone.
- **MCP tool descriptions are the same on Python 3.10 to 3.12 as on 3.13 and later** ([#829](https://github.com/opentidehq/opentide/issues/829)). Every line after the first kept four spaces of indentation on 3.10 to 3.12.
- **MCP `validate_query` suggests a live check only where there is one.** For a Sysdig or CrowdStrike query, its `next_actions` name the finding's `explain` page, not `validate_query` with `live: true`, which those platforms refuse.
- **A huge `Content-Length` no longer crashes `opentide lsp start`** ([#843](https://github.com/opentidehq/opentide/issues/843)). A message header alone could make the server allocate the length it named and exhaust memory; the body is read as it arrives.

## [0.23.0] — 2026-11-06

`opentide tui` shows each object as a page with its findings in place, and gains Visibility, Configuration and Chains tabs. Coverage counts the techniques rules inherit, and `generate explorer` can export visibility, opt-in.

### Added

- **`opentide generate explorer --include-visibility` exports visibility for the explorer** ([explorer#85](https://github.com/opentidehq/explorer/issues/85)). The explorer had no data about telemetry. With the flag, `generate explorer` also writes `.opentide/exports/explorer.visibility.json`: each log source `visibility.toml` declares, its columns, the rules whose queries read it and the objectives and rules that use it through a signal, the datasets rules read that no log source declares, and per-system counts, with a TLP marking (`--visibility-tlp`, `amber` by default, a usage error without `--include-visibility`) for the explorer to show. An inventory of what an organisation can see is sensitive, so the export is off by default, and a run without the flag removes the file an earlier run wrote. See [Visibility export](docs/cli/generate.md#visibility-export).
- **A Visibility tab in `opentide tui`** ([#776](https://github.com/opentidehq/opentide/issues/776)). `visibility.toml` could only be read as TOML, often more than a thousand lines. Tab `4` shows its log sources as a table with system, column count, the rules that use each and what needs attention, filtered by name or `system:`, and drills into the highlighted one: its columns with types and descriptions, the rules whose queries read it, and the objectives and rules that use it through a signal. Tiles count log sources per system and how many declare columns, and flag log sources without columns, log sources nothing uses, and datasets rules read that no log source declares. The datasets each query reads come from the analysis engine. See [Visibility](docs/cli/tui.md#visibility).
- **A Configuration tab in `opentide tui`** ([#776](https://github.com/opentidehq/opentide/issues/776)). Tab `5` shows `deployment.toml`, `lint.toml`, `documentation.toml`, `sharing.toml` and each `platforms/*.toml` by section: each setting's effective value, whether the workspace sets it or it is the bundled default, and what it does, the configuration checks' findings in place, and the options nothing sets with their descriptions. A platform reads as a card: enabled or not, and each tenant's strategies, credentials and the rules a deploy reaches it with. `t` shows the raw file. No credential value is shown anywhere, the raw file included: a credential reads as its variable name and whether it is set, or as hidden, and a file that is not valid TOML, or whose redaction cannot be proven, has no raw view. See [Configuration](docs/cli/tui.md#configuration).
- **A Chains tab in `opentide tui`** ([#776](https://github.com/opentidehq/opentide/issues/776)). `threat.chaining` had no view: following it meant reading UUIDs. Tab `6` draws the chain around the selected threat: sequence links left to right as attack flow, each threat a box with the rules under it (red when none) and how many of its techniques rules cover, own or inherited; supporting and atomicity links beside it, labelled and coloured by relation; a link written from both ends shown once. `+` and `-` change how many hops it shows, `l` the relations, `c` centres it on the highlighted threat and `Enter` opens that threat in the Catalogue. See [Chains](docs/cli/tui.md#chains).
- **`opentide tui` shows an object as a page** ([#776](https://github.com/opentidehq/opentide/issues/776)). The detail pane showed the YAML file. It now shows the object read by its schema revision: a header with version, dates and a TLP badge with what it means; an *Overview* of the top-level values and a section per block, each field under its title; vocabulary values with their meaning and severities as badges; the name of each objective, signal or threat a UUID names, which `f` (or a click) opens; queries in their own panel, coloured in their language; and a collapsed *Not set (N)* listing the optional fields the revision allows and the object leaves out, with their descriptions. `y` shows the file. See [The object page](docs/cli/tui.md#the-object-page).
- **`opentide tui` shows each finding in place** ([language-server#215](https://github.com/opentidehq/language-server/issues/215)). Findings were listed above the file, away from the lines they describe. Each one is now shown under its line, with its code, message and help, the line's gutter marked `✗`, `!` or `·`, and its span underlined over a tint of its severity. Hovering a span shows its frame and what an editor's hover shows there; `n` and `p` move to the next and previous finding from the keyboard, scroll to it and put it on the status line with the hover. The block above the file counts the findings (`✗ 1  ! 2  on lines 8, 28`). A long line wraps with its underline on its own text. The Python binding has `Workspace.hover(path, text, line, column)`, the language server's hover for a position. See [Findings in place](docs/cli/tui.md#findings-in-place).

### Changed

- **The analysis engine is [language-server 0.11.0](https://github.com/opentidehq/language-server/releases/tag/v0.11.0)** ([language-server#213](https://github.com/opentidehq/language-server/issues/213), [#214](https://github.com/opentidehq/language-server/issues/214), [#215](https://github.com/opentidehq/language-server/issues/215)). `opentide tui`, `opentide lsp start` and the offline query checks now report `filename_slug`, `missing_author` and `missing_organisation` as `.opentide/configurations/lint.toml` decides, as `opentide lint` does, with a new `filename_pattern` warning for a name `[filenames] pattern` does not match; a `detection_model` naming a signal is no longer an `invalid_ref`; and reference findings sit on the UUID they are about.

### Fixed

- **Coverage counts the techniques a rule inherits** ([#775](https://github.com/opentidehq/opentide/issues/775)). `opentide info coverage`, the MCP `coverage` tool and the TUI's Coverage tab read only a rule's own `techniques`, so a rule that takes its techniques from its objective, directly or through one of its signals, counted for nothing, and every such technique showed as a gap (`0 rules`, `covered: false`). They now use the walk `info catalog` reports as inherited techniques, from one shared resolver, so the four agree. `info coverage` adds `own`, `inherited` and `matched_techniques` and prints `3 rules (1 own, 2 inherited)`; MCP `coverage` adds `own_rules`, `inherited_rules` and `own_matrix`; the Coverage tab shows `3  1 own · 2 inherited`, and `Enter` opens a rule that lists the technique first. See [Coverage lookup](docs/cli/info.md#coverage-lookup).

## [0.22.0] — 2026-11-04

Minor release. The opentide VS Code extension ([`opentidehq.opentide`](https://marketplace.visualstudio.com/items?itemName=opentidehq.opentide)) ships its first release with it, and builds its catalogue, graph, relations and deploy-plan views on two new commands: `opentide --json info catalog`, the catalogue and its relationships in one document, and `opentide serve`, CLI commands from one warm process. `setup vscode` recommends the extension and stops mapping opentide's schemas for the YAML extension. `pip install opentide` no longer installs pandas or numpy, and Windows on Arm installs a wheel. `deploy --uuid` and `--file`, `setup --plan`, progress events and each platform's tenants in `info` are new. A minor because it adds commands, changes the files `setup vscode` and `generate snippets` write, changes the `end_column` of a query finding over several lines, and drops two dependencies: run `opentide setup vscode --settings --no-generate` and `opentide generate snippets`, and add pandas or numpy to your own requirements if your code imports them.

### Added

- **A wheel for Windows on Arm** (`cp310-abi3-win_arm64`, [#748](https://github.com/opentidehq/opentide/issues/748)). `pip install opentide` on Windows on Arm compiled opentide from its sdist, which needs Rust; it now installs a wheel with the engine compiled in, and a release is refused without one. cryptography, which the Azure SDK needs, publishes no Windows on Arm wheel after 46.0.3, so install with `pip install --only-binary cryptography opentide`, which takes 46.0.3's wheel. Use CPython 3.11 or later: on 3.10, pydantic-core, orjson, rpds-py and cffi have no Windows on Arm wheel, and pip compiles them. See [Installation](docs/usage/installation.md#windows-and-powershell).
- **Every `validate`, `validate query` and `lint` finding carries `end_line`** ([#755](https://github.com/opentidehq/opentide/issues/755)), the one-based line its span ends on: `line` for a span on one line, the real end of a query finding over several lines of a block scalar (an unterminated ES|QL string). A span the engine ends at column 1 of the next line, whose last character is a line break, ends on its own line. `end_column` is on `end_line`. SARIF regions carry `endLine`, and a GitHub annotation of such a finding has `endLine` and no `endColumn`. `opentide --json commands` names the key in each output schema.
- **`opentide --json info catalog`: the catalogue and its relationships in one document** ([#749](https://github.com/opentidehq/opentide/issues/749)). `info` listed UUIDs only. The `catalog` section adds:
  - `objects`: one row per threat, objective and rule, with its path and the line of `name:`, metadata, platform blocks with their status strategy, deployment-state bindings, own and inherited techniques, tactics and actors. A file that did not load keeps its row, with a `load_error` (`code`, `message`, `line`).
  - `edges`: `covers`, `implements`, `parent`, `chains` (with its `relation`), `technique` and `logsource`, each with the field that holds it, and `missing: true` for a reference to no object.
  - `signals`, and `attack`: the Enterprise ATT&CK matrix from the bundled vocabulary (tactics in order, techniques with their names, parents and sub-techniques).

  It is built in one pass over the registry: a 500-rule workspace answers in about 1.3 s. Without `--json` it prints a short summary. See [The catalogue](docs/cli/info.md#the-catalogue).
- **`opentide --json info` lists each platform's tenants** ([#754](https://github.com/opentidehq/opentide/issues/754)). Each `platforms[]` entry, also under `info --platform <id>`, gains `tenants[]`: `name`, `description`, `strategies`, `manual` and `variables`, each `$VAR` the tenant's setup references with whether it is set. A value is never printed. See [Tenants](docs/cli/info.md#tenants).
- **`opentide deploy --uuid` and `--file` select the rules a run reads** ([#753](https://github.com/opentidehq/opentide/issues/753)). Both are repeatable and replace the git-diff default, so `opentide --json deploy --dry-run --strategy PREVIEW --uuid <rule>` plans and renders only that rule. Combined with `--all`, either is a usage error (exit `2`, `usage_error`); a value that selects no rule fails the run, naming it in `unmatched`, after any usage error such as an unknown `--strategy`. See [Selecting rules](docs/cli/deploy.md#selecting-rules).
- **Progress events for editors and scripts** ([#756](https://github.com/opentidehq/opentide/issues/756)). With `OPENTIDE_PROGRESS=json`, long commands write one JSON object per line on stderr as they go: `{"event": "progress", "step": …, "done": …, "total": …}` for each `generate` phase, each batch of objects `validate` checks, the queries `validate query` checks and each platform of `deploy --dry-run`, and `{"event": "tenant", …}` with the status, rows and time of each tenant `query` reaches. Each line is ASCII JSON, so a Windows console's code page cannot break it. Stdout is unchanged: still exactly one document. See [Progress events](docs/cli/json-output.md#progress-events).
- **`opentide serve`: CLI commands in one warm process, for editors** ([#750](https://github.com/opentidehq/opentide/issues/750)). JSON-RPC 2.0 on stdio, one message per line. A `run {argv, cwd?, env?}` request answers with exactly the document `opentide --json <argv>` prints and its exit code, without starting Python and rebuilding the registry each time: at 500 rules a repeat `validate --file` answers in about 0.3 s instead of 1.6 s. Each run names its workspace (`--repo`, `cwd`, then `OPENTIDE_REPO_ROOT`), so one server serves a multi-root window. `invalidate {paths}` drops the registry kept for the workspaces those paths affect, `$/cancelRequest` stops a run as Ctrl-C does (exit `130`, the new failure code `interrupted`), a crash answers `internal` and the server keeps serving, and progress events arrive as `progress` notifications. A run reads an empty stdin, never the requests (`query -` exits `2`), and SIGTERM or SIGHUP cancels the running command so its cleanup runs. `initialize` returns the version and a digest of `opentide --json commands`. See [opentide serve](docs/cli/serve.md).
- **`opentide setup --plan`, and the whole wizard as one command** ([#751](https://github.com/opentidehq/opentide/issues/751)). `--plan` on `setup` and on every subcommand lists, per step, each file it would write or remove (`create`, `merge`, `delete` or `skip`) and its warnings, and writes nothing: setup runs its steps in a temporary copy of the repository and compares the files, so `setup --plan` then `setup --yes` with the same flags writes exactly the files the plan listed. New flags on `setup` answer the wizard's remaining questions: `--mcp vscode|cursor|claude-code|generic` and `--skills claude-code|cursor|github-copilot|generic` (both repeatable), `--plugin`, `--hooks` and `--env`. See [Plan before you write](docs/cli/setup.md#plan-before-you-write).

### Changed

- **The engine is [language-server 0.10.0](https://github.com/opentidehq/language-server/releases/tag/v0.10.0), from crates.io.** A query `opentide new` left as a placeholder (`...` under `# opentide:placeholder`) is no longer reported as a parse error in the editor, which `opentide validate` already skipped; a folder deleted, created or moved under `objects/` is read again; `opentide lsp start` answers `opentide/catalog` and sends `opentide/catalogChanged`, the workspace index the VS Code extension's Relations view reads; and a location in a workspace that is not on disk (vscode.dev, github.dev) is that document's own URI.
- **`pip install opentide` no longer installs pandas or numpy** ([#747](https://github.com/opentidehq/opentide/issues/747)). They were most of the size of every install, for one code path: deploy and `deploy --dry-run` flattened a platform's tenant modifiers with `pandas.json_normalize`. They now use opentide's own function, which gives the keys pandas gave, so every deployed configuration is unchanged; a `[[modifiers]]` entry with an empty `modifications` table, which failed with `IndexError`, now changes nothing. `boto3` stays: the Carbon Black SDK imports it when it loads.
- **`opentide setup vscode` sets up the opentide VS Code extension** ([#752](https://github.com/opentidehq/opentide/issues/752)). The extension (`opentidehq.opentide`) gives object files the language `opentide-yaml`, and its language server checks them.
  - **Snippets** have `scope: "yaml,opentide-yaml"`, so `tide-rule`, `tide-sentinel` and the others complete in the extension's object files as well as in plain YAML. Run `opentide generate snippets` to rewrite them.
  - **`setup vscode`** recommends `opentidehq.opentide` in `.vscode/extensions.json` instead of `redhat.vscode-yaml`, and writes no `yaml.schemas`: a YAML extension mapped to opentide's schemas reported every problem a second time. It removes the router mapping and the per-folder revision mappings earlier releases wrote to `.vscode/settings.json`, keeping every other setting and `yaml.schemas` entry, and no longer creates that file. The object folders those mappings name are read from the configuration of the repository it sets up, also when `-C` names one from another directory. An existing `redhat.vscode-yaml` recommendation is kept.
  - **`doctor`'s `vscode_settings`** passes when `.vscode/extensions.json` recommends the extension, is skipped when it lists the extension under `unwantedRecommendations`, and warns when `settings.json` still maps objects to opentide's schemas.
  - **MCP.** The extension provides the opentide MCP server to VS Code. When the extension is recommended, `setup mcp --vscode` and `setup vscode --mcp` say so (`"extension_mcp": true` and a `detail` note), since `.vscode/mcp.json` then serves teammates without it, and `doctor`'s `mcp_config` passes without that file.

  **Upgrade:** run `opentide setup vscode --settings --no-generate` to drop the old `yaml.schemas` entry, and install the recommended extension.
- **A query finding over several lines now ends where it ends** ([#755](https://github.com/opentidehq/opentide/issues/755)). Its `end_column` was one past its first character, on its first line, so a reader could not tell the span spanned lines; it is now the column after its last character, on the new `end_line`. A one-line finding is unchanged. The code frame still underlines the first line.

### Fixed

- **`deploy`, `validate query --changed` and `lint --changed` in a repository with no commit yet failed with `b'HEAD'`.** Right after `git init` and `opentide setup`, `HEAD` names a branch with no commit, and Dulwich raises `KeyError(b"HEAD")`, whose text is the key's repr; the run exited `1` with `{"failure": {"code": "command_failed", "message": "b'HEAD'"}}`. Outside CI the changed files are the last commit's, and there is none, so nothing has changed: `deploy` without `--all`, `--uuid` or `--file` reports `skipped` with exit `0`, `validate query --changed` checks no rule and `lint --changed` lints no file, each with a warning that `HEAD` names no commit yet and what to do instead (commit the files, pass `--all`, or drop `--changed`). In CI, where the run's commit must be in the checkout, the run still fails with exit `1` and a readable message (on a push whose diff base is read from `HEAD`: `The git repository at <path> has no commits yet`). A git ref or object the checkout does not hold is named in a sentence (`Could not find git ref origin/main`), never as a bytes repr, by every command that reads the diff.
- **A tenant setup value written `${VAR}` now resolves on every platform, and `doctor` names the variable.** Only Elastic's `api_key` and Sysdig's `api_token` accepted the braced form, though the CI/CD guide shows it: elsewhere opentide looked up a variable named `{VAR}`, deploy and `--live` refused the tenant as unset, and `doctor`'s `credentials` check warned about `{VAR}`. A setup value that only starts with `$` (a secret such as `$uP3r-S3cret!`) is now a literal: it is no longer looked up, logged as a missing variable (its text in the log line), refused by a live client as an unset credential, or counted by `doctor`, which also stops reporting `$` values nested in lists or tables, since they were never resolved. When a variable of exactly that name is set (`$AZ-SECRET` and a variable `AZ-SECRET`), it is still read, as 0.21.0 read it, with a warning to rename it. The live query job `setup ci` generates guards the same names: it missed a `${VAR}` and read a literal such as `$ABC-123x` as the variable `ABC`, so it skipped (exit 2) a check whose credentials were all set; re-run `opentide setup ci <provider> --yes`.
- **`info` counts a file whose UUID another file also uses as a load error.** The index keeps one object per UUID, so the file it replaced was in no count and no listing; `opentide validate` reported `duplicate_id`, `info` said `0 load errors`. It is now in `parse_error_count` and `summary.load_errors`, sets `status` to `issues` (`--strict` fails), and has a catalogue row with a `duplicate_id` `load_error`, whose `uuid` is `null` (the message names it), so no two rows share a `uuid`.
- **Interrupting `opentide generate` no longer leaves an empty schema that breaks every later command.** Each schema, the router, the visibility schema and the language server's catalogs were written in place, so Ctrl-C between opening and writing one left it zero-length, and every `validate`, `lint` and `generate` then failed with `internal` (`JSONDecodeError`) until it was regenerated by hand. They are now written to a temporary file and renamed over the old one, and a schema artifact that cannot be parsed is skipped with a `could_not_read_schema_artifact` warning naming it, which `opentide generate schemas` or `opentide generate` then rewrites.
- **`setup skills --cursor` and `--claude-code` keep the files you added to a skill's folder.** Each run deleted `.cursor/skills/<slug>/` and `.claude/skills/<slug>/` and copied the skill afresh, so team notes or any other file the skill does not ship were lost. The skill's own files are now copied over the folder, and a file it does not ship is kept, with a warning naming it. A link in the folder at a path the skill ships is replaced by the skill's file, as before, never written through, and a skill folder that links out of the repository is left as it is, with a warning.
- **`setup skills --claude-code` no longer deletes the skills when `.claude/skills` links to `.agents/skills`.** That layout made the copy's source and destination the same folder: the folder was removed, the skill just written with it, and the copy then failed with `internal`. A destination that is the skill's own folder is now left as it is.
- **`setup vscode` reads a `.vscode/settings.json` saved with a byte-order mark, and leaves one it cannot parse as it is.** VS Code's "UTF-8 with BOM", common on Windows, made `setup vscode` (and `setup --vscode-setup`) exit 1 with `internal` before writing the extension recommendation or the snippets. A BOM is now read, by `doctor`'s `vscode_settings` and `mcp_config` checks too, which reported such a `settings.json`, `extensions.json` or `.vscode/mcp.json` as not valid JSON; a `settings.json` or `extensions.json` that does not parse is left unchanged, with a warning saying what to do by hand, and the other steps run.
- **`setup vscode` keeps the comments, layout and line endings of `.vscode/settings.json` and `extensions.json`.** Both were rewritten with `json.dumps`, so every comment went and CRLF became LF, a whole-file diff, and `extensions.json` was rewritten on every run, VS Code's own template comment included, even when it already recommended the extension. Setup now changes only the entry it removes or the id it adds, and keeps the comments beside them (one after the previous entry's comma, before the next entry, or in an array or object that holds nothing else), writes nothing when the extension is already recommended (or listed as unwanted), and leaves a commented file it cannot edit that way unchanged, with a warning.

### Install

```bash
pip install opentide==0.22.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.21.0] — 2026-11-03

Minor release. Sysdig Secure and Falco become the ninth platform, with Falco conditions checked offline. Migrating CoreTIDE content is not a supported path, and what suggested otherwise is removed: `global.toml`, `schema.toml` and `systems/` fail every command, and the splunk::2.x keys, a rule's `meta:` and an objective's root `composition` are unknown keys. Rule pages show each platform block's own status and severity, one slow query no longer marks a tenant unreachable, and the generated GitLab pipeline is built as data. A minor because it changes what input is accepted, removes `migrate objects` and `export playbook-map`, and changes the generated pipelines: run `opentide validate --strict`, which names each retired file and key, and re-run `opentide setup ci <provider> --yes`.

### Added

- **`opentide setup ci --lint-changed` gates lint on the object files each run changed.** The generated pipelines gated on `opentide lint --strict` over every file, which no inherited catalogue passes on its first day (in one migration, 428 objects without `author` and 132 query style warnings). With `--lint-changed` the validate job runs `opentide lint --strict --changed`, over the diff the run's deploy reads, and checks out full history (and installs `git` on GitLab); `opentide validate --strict` still checks every file. `--lint-all`, the default, keeps the current gate. See [setup ci](docs/cli/setup.md).
- **The editor checks configuration files** ([#730](https://github.com/opentidehq/opentide/issues/730), [language-server#158](https://github.com/opentidehq/language-server/issues/158)). `opentide lsp start` checks each open TOML file under `.opentide/configurations/` with the models and checks `opentide validate` runs, as you type, and puts each finding on the key it names.
  - The file is merged onto the bundled file and the parent instance first, so a partial override is not reported for keys it inherits.
  - An open `deployment.toml`, saved or not, decides the statuses `sharing.toml` may name.
  - Hover shows a key's title, type, description, allowed values and default, never its value. Completion offers keys and allowed values from the files' JSON Schema.
  - Your editor's TOML grammar keeps highlighting. Turn other TOML language servers off for `.opentide/configurations/**`.

  `opentide.validation.configuration.configuration_buffer_issues(path, text, open_buffers)` is the check the editor runs. See [Configuration files](docs/cli/lsp.md#configuration-files).
- **A faster, fuller language server** ([language-server#185](https://github.com/opentidehq/language-server/issues/185)). `opentide lsp start` runs the rebuilt engine host.
  - Each keystroke is analysed once, and queued edits are handled together. A keystroke in a 500-object workspace answers in half the time.
  - Each workspace folder is a workspace of its own.
  - Objects get an outline of their sections, platform blocks and queries.
  - ATT&CK ids and object UUIDs are links, and an objective or threat counts the rules that use it.
  - Quick fixes can be applied all at once.
  - Diagnostics link to their section of the [diagnostics reference](docs/cli/diagnostics.md).
  - `initialize` names opentide as the host (`capabilities.experimental.opentide.host`), so an editor can tell it from the `opentide-lsp` binary ([language-server#172](https://github.com/opentidehq/language-server/issues/172)).
- **Carbon Black Cloud field checks** ([language-server#162](https://github.com/opentidehq/language-server/issues/162)).
  - `opentide validate` and the editor report `cbc_unknown_field` (warning) for a field in `configurations.carbon_black_cloud.query` that is one or two letters away from a Carbon Black process search field, and suggest it (`process_nmae` → `process_name`).
  - In the editor, hover documents Carbon Black fields, and completion offers them instead of Elastic's ECS fields.
  - Completion and hover also work with the cursor right after a query's last character, in every query language.
- **Sysdig Secure and Falco: a ninth platform, `sysdig` (`platform::sysdig::1.0`)** ([#143](https://github.com/opentidehq/opentide/issues/143), [RFC 0014](https://github.com/opentidehq/specifications/blob/main/rfcs/0014-sysdig-falco-platform.md)). Runtime detection for Linux hosts, containers, Kubernetes audit logs and cloud audit trails had no platform: teams kept Falco rules as raw YAML beside their catalogue. A `configurations.sysdig` block is a Falco rule: a `condition`, its `exceptions`, and the `macros` and `lists` only that rule uses, or a tuning of an existing rule (`append_to_rule`). Deploy derives the Falco `desc`, `priority` (from `response.alert_severity`), MITRE and maturity `tags` and a default `output` per event source, and expands the block's own macros and lists into the condition and the exception values by the algorithm of Falco's rule loader (lists flattened with the lists before them, then Falco's `resolve_list` pass for each list in block order with its delimiters and blanks, so a list naming a later list still expands, as in Falco 0.45.2; macros in check positions in parentheses), so Sysdig receives what Falco would compile and two rules never overwrite each other's definitions on a tenant. Exceptions are checked as Falco's `validate_exception_info` checks them: any Falco operator or a modified operator (`startswith oneof`) in the tuple form, `in`, `pmatch`, `intersects` or a modified operator in the single-field form, comparisons trimmed. Deploy creates the rule through the Sysdig Secure runtime API, as every platform is configured over its API, and adds it to the runtime policies the tenant in `platforms/sysdig.toml` or the block names (`policies`; a missing policy fails the rule, and deploy never creates one), with Sysdig's rule id kept in `.opentide/states/deployment/`. `minimum_engine_version` is sent as Sysdig's `minimumEngineVersion`. `DISABLEMENT` removes the rule from its policies (Sysdig has no rule-level switch); `DELETION` deletes it. `validate` reports the block's constraint codes (`sysdig_rule_shape`, `sysdig_tuning_keys`, `sysdig_exception_shape`, `sysdig_definition_order` for a macro that uses itself or a later block macro, which Falco refuses as an undefined macro, `sysdig_list_in_value` for a block list name where Falco's expansion would not make a value list, ...); `validate query --platform sysdig --live` reports `supported: false` (Sysdig has no rule preview); `deploy --dry-run` shows the API body. `opentide setup --sysdig` enables it. `opentide lint` reports the engine's advisory `sysdig_list_self_reference` (a block list that names itself keeps its own name in the deployed condition, as in Falco); it never fails validation.
- **`[skip deploy]` and the `skip-deploy` label keep a catalogue-wide change from deploying.** Nothing guarded a migration, bulk rename or reformat that touches every rule file: its merge request staging-deployed every `PREVIEW` rule and live-checked every query, and its merge promoted every `PREVIEW` rule to `PRODUCTION` and redeployed the catalogue. The pipelines `opentide setup ci` writes now leave out the live query checks, the staging and production deploys and the share when the pushed commit's message, the pull or merge request title, or (GitHub and GitLab) a `skip-deploy` label says so; on Azure each skipped job's first step reads the built commit's message (a pull request's source commit) and stops it with exit 0, because Azure fills `Build.SourceVersionMessage` only inside a running step, so a job or stage `condition:` could not read it. Validation, `lint`, `generate`, docs and inflight shards still run. On GitLab the jobs are left out with `when: never` and the needs on them are optional, so the pipeline still starts. Regenerate with `opentide setup ci <github|gitlab|azure> --yes`. See [Skipping deploys for a catalogue-wide change](docs/usage/workflows/ci-cd.md#skipping-deploys-for-a-catalogue-wide-change).
- **Generated GitLab write-backs can push over SSH, or to any URL.** The production, `after_script` and inflight pushes went to `https://gitlab-ci-token:${CI_JOB_TOKEN}@…`, which needs job-token push access and a CA the job image trusts; the runner rewrites `origin` itself, so a project's `insteadOf` to an SSH URL had no effect. The jobs now push to the CI/CD variable `OPENTIDE_PUSH_URL` when it is set, falling back to the job-token URL. With the File variables `OPENTIDE_PUSH_SSH_KEY` and `OPENTIDE_PUSH_SSH_KNOWN_HOSTS` they install `openssh-client`, push with that key under strict host-key checking, and sign their commits with it; a key without known hosts fails the job before it pushes, and the key is never printed. Regenerate with `opentide setup ci gitlab --yes`. See [GitLab write-back credentials](docs/usage/workflows/ci-cd.md#gitlab-write-back-credentials).
- **`opentide lint --changed` and `--file`: strict lint can gate an inherited catalogue.** `lint --strict` fails on any finding, notes included, and lint read the whole catalogue, so a gate on it failed every run of a catalogue that inherited objects without `author` or with query style warnings (428 and 132 in one migration) until all of them were fixed. `--changed` lints only the object files the run changed, read from the diff `deploy` and `validate query --changed` read (the pull or merge request, the push, or outside CI the last commit), and `--file` (repeatable) only the files it names, matched as `validate --file` matches them. Both narrow every check, `queries` included; the filenames check still reads the whole folder, so a stem another file holds is still a collision, and a narrowed run reports on a file what a full run would. A `--file` target that selects no object file fails with exit `1` and is listed under `unmatched`; `--changed` with `--file` exits `2`; no changed object file passes. `opentide lint --strict --changed` gates new work while the backlog is cleared. See [Linting what changed](docs/cli/lint.md#linting-what-changed).
- **Falco conditions are checked offline.** The analysis engine gains a Falco language (opentidehq/language-server): `opentide validate`, `validate query --platform sysdig`, `lint`, `opentide lsp` and MCP `validate_query` parse a Sysdig block's `condition`, its macros' conditions and its `output` with the block's `source`. A syntax error fails validation (`falco_parse_error`); an unknown field, macro, list or event type is a warning, with a suggestion where one is close, because plugins add fields and Sysdig manages macros. Fields come from the Falco and plugin references; the Falco default rules' macros and lists are known by name. A `.falco` file is a query file.

### Changed

- **Generated pipelines pin opentide once, in `OPENTIDE_VERSION`.** The release was a literal in every job's `pip install`, so moving a pipeline to another release meant editing each job. `opentide setup ci <github|gitlab|azure>` now sets the pipeline variable `OPENTIDE_VERSION` (GitHub workflow `env`, GitLab and Azure `variables`) and every job runs `pip install "opentide==$OPENTIDE_VERSION"`. On GitLab a project or group CI/CD variable of that name overrides the file's. See [CI/CD](docs/usage/workflows/ci-cd.md#scaffold-with-setup).
- **The generated GitLab deploy jobs record deployments.** `deploy_staging` and `deploy_production` had no `environment:`, so GitLab kept no deployment history, listed no environment and counted no deployment in its DORA metrics. `deploy_production` now deploys to `production` (`deployment_tier: production`) and `deploy_staging` to `staging/mr-$CI_MERGE_REQUEST_IID`, one environment per merge request so GitLab's "Prevent outdated deployment jobs" never fails one merge request's staging job because another deployed after it. Set the `opentide-production` resource group's process mode to `oldest_first` so production deploys run in pipeline order; see [Production write-back](docs/usage/workflows/ci-cd.md#production-write-back). Regenerate with `opentide setup ci gitlab --yes`.
- **`opentide lsp start` exits with the protocol's code.** It exits `0` after the editor's `shutdown` and `exit`, and `1` when the editor exits or closes stdin without `shutdown`; it used to exit `0` either way. The engine pin moves to language-server's fixes ([#185](https://github.com/opentidehq/language-server/issues/185)):
  - the server no longer crashes after an edit next to `日本` or an emoji, and no longer hangs on some broken SPL queries;
  - an EQL escape before a non-ASCII character no longer panics;
  - analysis is much faster (highlight queries compiled once, the workspace indexed once);
  - YAML that is not a Tide object, such as `.github/workflows/ci.yml`, is no longer checked;
  - VS Code no longer shows each diagnostic twice;
  - a malformed message or a failing handler no longer ends the session.
- **The analysis engine is language-server [0.9.1](https://github.com/opentidehq/language-server/releases/tag/v0.9.1)**, from crates.io, in place of a git revision: the rebuilt server host, the configuration checker hook, Carbon Black field checks, the Falco language for Sysdig rules (checked against real `falco --validate`), and the Tide catalog with `configurations.sysdig` and Sentinel's ATT&CK v18 techniques. That catalog follows the CoreTIDE-compat removal ([opentidehq/language-server#194](https://github.com/opentidehq/language-server/pull/194)), so `opentide-lsp` run on its own reports the splunk::2.x keys, `meta:` and an objective's root `composition` as unknown keys, as `opentide validate` does. An opentide release can build from it again (`scripts/build/check_engine_pin.py --release`).
- **`configurations.sentinel.alert.techniques` takes ATT&CK v18 ids, the version Microsoft Sentinel is aligned to** ([#686](https://github.com/opentidehq/opentide/issues/686)). The field accepted any string. It now accepts every technique and sub-technique of the ATT&CK 18.1 Enterprise, Mobile and ICS matrices that is not revoked or deprecated (898 ids; 18.0 has the same), from a list bundled for the Sentinel block alone (`data/sentinel/attack-v18.json`, generated from MITRE's STIX data by `scripts/build/sync_sentinel_attack.py`). The `att&ck` vocabulary, which threats, objectives and a rule's own `techniques` use, still follows ATT&CK 20.0 and is unchanged. Any other value fails validation with `sentinel_attack_technique`, whose message names what to use instead: the v18 ids a newer id replaced (`T1685`: use `T1562`, `T1562.001` or `T1562.006`), that a newer id has no v18 equivalent, the v18 id that replaced an id ATT&CK retired before v18 (`T1086`: use `T1059.001`), or the near-miss of a typo. Revocations are followed through every hop, and the newer ids come from the release the `att&ck` vocabulary was built from, read from its `source_version`. Editors complete and check the v18 ids after `opentide generate schemas`. **Upgrade:** a Sentinel block whose `alert.techniques` lists an id newer than ATT&CK v18 replaces it with the v18 id the message names, or removes it. See [A technique fails only under the Sentinel block](docs/usage/troubleshooting.md#a-technique-fails-only-under-configurationssentinelalerttechniques).
- **A platform block's `schema` must be the identifier its platform registers** (`platform::splunk::1.0`), or be left out. Nothing read the identifier, so `schema: splunk::2.1`, another platform's identifier or any string validated, and three conventions disagreed: the templates (`platform::splunk::1.0`), the editor schema's defaults and patterns (`splunk::3.0`, `sentinel::2.4`, ...), and the published JSON Schema, which constrained nothing. `validate` now reports any other value (`schema_validation`: `unknown platform schema 'splunk::2.1': this block's schema is 'platform::splunk::1.0'`), and the editor schema offers the registered identifier as an enum. `opentide generate extract sentinel` and `extract defender` write `platform::sentinel::1.0` and `platform::defender_for_endpoint::1.0`, where they wrote `sentinel::2.1` and `defender_for_endpoint::2.0`. **Upgrade:** set each block's `schema` to `platform::<platform>::1.0`, or remove it.
- **`opentide generate templates` writes each enabled platform's block template to `.opentide/templates/platforms/<platform>.template.yaml`**, and `generate snippets` reads it there. It wrote `<display name> Template.yaml` into the installed package (`opentide/schemas/data/platform_templates/MDR Systems Deployment/Templates/`), which fails on a read-only install and, because the name came from `[platform] name`, made snippets look for a file the package did not ship once a workspace renamed its platform. The bundled templates are named `<platform>.template.yaml` and are kept in step with the models by the test suite.

### Fixed

- **Rule pages and the rules index no longer present `STAGING` and `Informational` as every rule's status and severity.** `DetectionRule.status` defaulted to `STAGING` and `severity` to `Informational`, and `generate docs` rendered them whether or not a rule stated them: in one 525-rule catalogue every page said `STAGING` / `Informational` for rules in `PRODUCTION` with Medium to Critical alerts. A rule-level `status` is read by no command, and promotion moves the platform blocks' statuses, so even an authored one drifted at the first promotion. Both now default to `None`. A page's Status table has a row per platform block (`Status (sentinel)`), and its severity is `response.alert_severity`, else an authored `severity`, else no row; the index shows the blocks' statuses and that severity. `DetectionRule.platform_statuses` and `displayed_severity` expose them. MCP `deploy_rule` reports the block's `status` for the platform, and `search` filters and reports rules by their blocks' statuses, where both read the rule-level one (`search` also stops reading a CoreTIDE `title`).
- **Promotion rewrites only `configurations.<platform>.status`, keeping the file's line endings.** It edited text: every `status:` line after the first line containing the word `configurations` (in a description too), replacing any status name as a substring, so a nested `status` key, a comment and a `PRE-STAGING` status changed as well, and a CRLF file came back LF. It now replaces the exact characters of each block's own `status` scalar, checks that the result differs from the original by those values only, keeps a byte-order mark and CRLF, and writes the file atomically. Every changed rule is planned before any is written, so a rule that cannot be promoted fails the run, naming its file, with nothing half-promoted for the write-back to commit; a block `status` written as a YAML anchor, alias or through a merge key (`<<`) is left as it is, with a `rule_not_promoted` warning naming the file.
- **One slow query no longer ends a `validate query --live` run as "Cannot reach the tenant".** The live check ran each tenant's rules inside one handler that turned any timeout into `TenantUnreachableError`, so a query slower than the 120-second check timeout failed the platform and left every later rule unchecked: a run of 403 Splunk rules stopped after 17 minutes with `Cannot reach splunk tenant 'Default' at <host>:443: The read operation timed out`, though the other rules were valid. A read timeout (the tenant took the request and sent nothing back in time), a gateway's or proxy's HTTP 502, 503 or 504 page, or a SentinelOne PowerQuery still running at the deadline now fails only that rule's check, with the timeout and how to raise it, and the run goes on; `--json` lists those checks under `timed_out` (`code` `query_check_timeout`, with `check_timeout` and `advice`), the message counts them, the exit code is `1`, and `failure.code` is `query_check_timeout` when they are the only failures. A tenant is reported unreachable at once for a refused connection, a DNS, TLS or proxy failure or a connect timeout, and after three queries in a row with no answer, which its message says. A tenant reached through `requests` (every platform but Splunk) that answered no request at all is reported unreachable at the end of its rules even with fewer than three: urllib3 reports a TLS handshake that never completes, behind a proxy or a load balancer, as a read timeout. This also holds where the timeout was wrapped: Azure's `ServiceResponseTimeoutError` (Sentinel), a read timeout `requests` reports as a `ConnectionError` after the Elastic client's retries, Carbon Black's `TimeoutError`. `opentide query` reports a read timeout as `did not answer the query within <N>s` rather than `Cannot reach`. See [Slow queries and timeouts](docs/cli/validate.md#slow-queries-and-timeouts).
- **`validate query --live` takes `--check-timeout SECONDS`, or `OPENTIDE_QUERY_CHECK_TIMEOUT`.** The 120-second check timeout was fixed, and Splunk's and Elastic's live checks did not use it at all: Splunk waited the transport's own 120 seconds whatever `opentide query --timeout` said, and Elastic its client's 30. Every platform's check now waits the configured time, Elastic included; a value that is not a positive number exits `2` (`usage_invalid_value`) before any query is sent, and `--check-timeout` without `--live` exits `2` (`usage_error`). Carbon Black Cloud requests had no timeout at all (the SDK sends none unless given one), so a tenant that never answered held the run forever; they now take the check's, or 120 seconds for deploy. `opentide query --timeout` also refuses `nan` and `inf`.
- **Splunk's gateway page is reported as a gateway timeout, not as a wrong url or port.** An HTML page answering a Splunk request was always read as the wrong port (`Check the tenant's url and port`) and ended the run as an unreachable tenant, even when a gateway in front of Splunk sent it for one slow request while every other request to the same address succeeded. The message now carries the HTTP status (`answered with an HTML page (HTTP 504), not its REST API`); for a 502, 503 or 504, or a page after a request of 30 seconds or more, it names a gateway or proxy timing out, and that query's check fails alone. A non-JSON gateway answer to Splunk's parser fails the same way instead of reading as Splunk refusing the query. Defender, SentinelOne, Elastic, CrowdStrike and HarfangLab report an answer that is not JSON with its status and page title, and the gateway reading for those statuses, where a `200` page raised `JSONDecodeError` and ended the run (Defender, HarfangLab, Elastic's rule preview and data view) or read as `returned no query id` (SentinelOne, CrowdStrike).
- **The generated GitLab validate job no longer fails on GitLab Runner 18.9 after both gate commands passed.** `artifacts:reports:codequality` listed one file per command (`validate.codequality.json`, `lint.codequality.json`), and the runner uploads a Code Quality report as a single file: `failed to copy content to form: only one file can be sent as raw`. The job now declares one report, `opentide-reports/codequality.json`, which its `after_script` merges from the two with `python -m opentide.ci.codequality`. `after_script` runs after a failed command too, so the merge request still shows the findings; a report that is missing, empty or cut short by a crash is skipped with a note, so the merged file is always valid. No other GitLab job declares a report. Regenerate with `opentide setup ci gitlab --yes`. See [CI/CD](docs/usage/workflows/ci-cd.md#annotations-summaries-and-reports).
- **The generated `document` job keeps the pages it renders.** It ran `opentide generate docs --output docs` on every default-branch pipeline (about three minutes on GitLab) and declared no artifact, so the pages were lost with the runner. GitLab, GitHub and Azure now keep them as the `opentide-docs` artifact. Regenerate with `opentide setup ci <github|gitlab|azure> --yes`. See [Documentation in CI](docs/usage/workflows/ci-cd.md#documentation-in-ci).
- **A `rules:` added to a generated GitLab query job no longer stops every pipeline from being created.** `generate` needed each `validate_query_*` job without `optional: true`, so a query job its rules left out made GitLab refuse the pipeline (`'generate' job needs 'validate_query_sentinel' job, but it was not added to the pipeline`); the share job needed `deploy_production` the same way. Every need of a job that has `rules` is now optional; a job that is in the pipeline is still waited for and must still succeed. Tests now check, for every combination of generator options and every kind of pipeline, that each `needs` target exists and that each pipeline GitLab creates can start. Regenerate with `opentide setup ci gitlab --yes`.
- **`opentide lint --fix` no longer turns a debug fixture into a live rule.** The catalogue skips `*.debug.yaml` and `*.debug.yml`, but lint's `filenames` check, which reads them, took `Path.stem` as the stem: `0005 - MDR Deployment Testing MDE.debug.yaml` was compared as `… MDE.debug`, and `--fix` renamed it `MDR TESTING - MDE 1000.yaml`, so the fixture joined the catalogue and the next push's deploy diff. The stem of an object file is now the name without its whole suffix, `.debug` included, in lint's comparison, rename, `pattern` check and collision detection and in `opentide new`'s: the fixture becomes `MDR TESTING - MDE 1000.debug.yaml`. Under `style = "name"` a trailing `.debug` in an object's name is dropped from its expected stem, so no rename can move a file into or out of the catalogue. A fixture and the object of the same name are two files and no longer collide. See [Filename convention](docs/cli/lint.md#filename-convention).
- **`opentide doctor` accepts the `yaml.schemas` object glob in a list, and `setup vscode` keeps a list's other globs.** `vscode_settings` compared the router mapping with the string `"objects/**/*.yaml"`, so `["objects/**/*.yaml"]`, which the YAML extension accepts as the same mapping, warned, and so did a list that also maps the workspace's own folders. `setup vscode`'s merge replaced such a list with the bare string and dropped those globs. Both now read the value as a string or a list: doctor passes when it holds the object glob (with or without `./`), and the merge keeps a list as it is, appending the object glob when it is missing. See [vscode_settings](docs/cli/diagnostics.md#vscode_settings).
- **`spl_unknown_command` no longer asks to declare a search-head app's command.** The engine's message ended "if an app on the search head provides it, declare it", but no configuration (`visibility.toml`, `platforms/splunk.toml`) declares a command, so a catalogue using `decrypt` or `mispsearch` was told to do something it could not. The CLI's message (`validate`, `validate query`, `lint`, `tui`, MCP `validate_query`) now says that an app may provide it and that opentide cannot declare app commands yet, and `opentide explain spl_unknown_command` says what to do instead: fix a typo, which stays an error with `did you mean 'stats'?` as its help (it read `try: stats`), or accept the warning, which `validate` passes. A setting to declare app commands needs the analysis engine to accept them. See [spl_unknown_command](docs/cli/diagnostics.md#spl_unknown_command).
- **`opentide setup repo` adds opentide's ignore lines to an existing `.gitignore`.** On a repository that already had a `.gitignore` the command skipped the file whole, so `.opentide/states/sharing.jsonl` (the sharing cache), `.opentide/exports/*.export.json` and `opentide-reports/` (CI findings reports) were left committable. It now appends the ones the file lacks, as `setup env` appends `.env`, and lists them in `--json` under `gitignore_added`; a rerun adds nothing, and the Python lines a new file starts with (`build/`, `dist/`) are not added to an existing one. Both commands now keep the file's line endings and byte-order mark: `setup env` turned a CRLF `.gitignore` into LF lines. See [setup repo](docs/cli/setup.md#setup-repo).
- **Platform files no longer crash `validate`, schema generation or the editor's catalog** ([#736](https://github.com/opentidehq/opentide/issues/736)).
  - **Plugin platform files.** A third-party `platforms/<id>.toml` (a plugin's platform) crashed `opentide validate` with `KeyError`. opentide has no rule block for such a platform, so `validate`, `generate schemas` and the editor's catalog now skip it. The configuration check still checks the file against `platforms.schema.json`.
  - **`[tide]` tables.** CoreTIDE's `[tide]` identity table is no longer read for a platform's name, identifier or `enabled`. It made catalog generation fail with `KeyError: 'name'` when a workspace enabled a platform there, and `opentide lsp start` then fell back to stale catalogs. It is now an `unknown_key` in the configuration check, like any other unknown table: move its keys to `[platform]`.
- **Sentinel deploy sends ATT&CK sub-techniques in `subTechniques`** ([#686](https://github.com/opentidehq/opentide/issues/686)). Deploy reduced every technique to its parent, so a rule whose objective maps `T1556.009` was deployed as `T1556` and the sub-technique was lost, with no warning. The ARM body now carries the parents in `techniques` and the sub-technique ids in `subTechniques` (`"techniques": ["T1556"]`, `"subTechniques": ["T1556.009"]`), as Microsoft's own solution packager splits them; `tactics` are unchanged. A sub-technique the objective resolves that is newer than ATT&CK v18, the version Sentinel is aligned to (`T1027.018`), is left out of `subTechniques` with a `dropping_sub_technique_newer_than_sentinel_attack` warning; its v18 parent is still sent in `techniques`, as before. A sub-technique in `configurations.sentinel.alert.techniques`, which ARM rejected (`The technique 'T1098.003' is invalid`), is split the same way. The API publishes no list or pattern for `subTechniques`; the ids `alert.techniques` may hold are now Sentinel's ATT&CK v18 (see Changed). `opentide generate extract sentinel` no longer drops a rule's `subTechniques`: it lists each sub-technique in `alert.techniques` in place of its parent. See [deploy](docs/cli/deploy.md).

### Breaking

- **Rust is opentide's only engine: the Python implementation, and `OPENTIDE_ENGINE`, are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)). Every command, `opentide serve`, `opentide mcp start`, `opentide tui` and `opentide lsp start` run on the Rust core compiled into the package; the console script (`opentide._cli:main`) hands it the arguments in process. `OPENTIDE_ENGINE` is no longer read: `python` no longer runs the Python command line, MCP server or Textual UI, and `compare` no longer runs both implementations. The `engine_not_ported` and `engine_mismatch` failure codes, exit code `70` and their `opentide explain` pages are gone, and `opentide --json commands` no longer lists the variable. When the compiled core does not load, the console script prints `error: The opentide analysis engine does not load: …` with the reinstall command on stderr and exits `1`, where the Python command line answered the commands that do not need it.
- **The deprecated SDK entry points are removed, with no shims** ([#841](https://github.com/opentidehq/opentide/issues/841)): `Opentide.initialise()` and the registry (`from opentide import Opentide`, `OpenTide`, `Opentide.Rules`, `Objectives`, `Threats`, `Index`, `Platforms`, `render_rule`, `validate_rule`), `opentide.validation.session.run_validation` and `ValidationScope`, and the documentation writers (`opentide.documentation.write_all`, `write_rules`, `write_objectives`, `write_threats`, `run`, `render_rule`, `render_objective`, `render_threat`). Each has an `opentide.Workspace` equivalent (Upgrade; [migration](docs/sdk/migration.md)).
- **opentide's undocumented internals are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)): `opentide.cli` (and its services), `opentide.core`, `opentide.platforms`, `opentide.deployment`, `opentide.states`, `opentide.validation`, `opentide.loading`, `opentide.registry`, `opentide.indexing`, `opentide.generation`, `opentide.documentation`, `opentide.export`, `opentide.extraction`, `opentide.ci`, `opentide.sharing`, `opentide.query`, `opentide.mcp_server`, `opentide.vocabulary`, `opentide.mutation`, `opentide.schemas` (its Python modules; the bundled data stays) and `opentide.vulnerability_lookup`. `opentide.models` keeps the Rust classes alone: the Pydantic package behind it (`opentide._models`), the Pydantic machinery (`TideModel`, `TideField`, `TideRegistry`), the result models and constants (`ValidationResult`, `DeploymentResult`, `RULE`, `CORE_OBJECT_TYPES`, `EnumRegistry`, `SchemaVersion`, …), the submodules it aliased (`opentide.models.results`, `.configuration`, …) and `opentide.models.delegation` are gone. `opentide.analysis` keeps `check_query`, `highlight`, `describe`, `engine_codes`, `engine_versions` and `EngineUnavailableError`; `check_queries` and the catalog helpers are gone. The package keeps the console script, the SDK (`opentide.Workspace`, `run_json`, `Connection`, `OpentideError`), `opentide.models`, the plugin API (`opentide.plugins`) and the native binding; a plugin that uses only `opentide.plugins` keeps working. The built-in platforms no longer register `opentide.platforms` entry points.
- **opentide no longer depends on the Python implementation's libraries** ([#841](https://github.com/opentidehq/opentide/issues/841)): `typer`, `rich`, `textual`, `questionary`, `structlog`, `ruamel.yaml`, `pyyaml`, `orjson`, `tomli-w`, `dulwich`, `platformdirs`, `requests`, `mcp`, `pymisp`, `azure-identity`, `azure-monitor-query`, `splunk-sdk`, `carbon-black-cloud-sdk` and `boto3` are no longer installed with it. `pydantic` stays, for the plugin API's `configuration_model`. Code that imported one of them through opentide's install declares it itself.
- **`opentide query --rule` and `--file` on a platform plugin are a usage error** ([#835](https://github.com/opentidehq/opentide/issues/835)): `usage_invalid_value`, exit `2`, naming the option, where they were refused as not ported. A plugin's block is the plugin's to read: give its query as `QUERY` or `--query-file`.
- **A status promotion that cannot rewrite the push fails the deploy** ([#841](https://github.com/opentidehq/opentide/issues/841)): no promotion target, a platform key that is not a string, or promoted text that does not read back fails the run before anything is written (exit `1`, `--skip-promotion` named), where it was refused as not ported (`engine_not_ported`, exit `2`).
- **Migrating CoreTIDE content to opentide is not a supported path.** The pieces that suggested otherwise accepted CoreTIDE files half-way, read them and ignored them, or kept CoreTIDE names alive. They are removed, and each now fails with a message that names what replaces it. A workspace created by `opentide setup` is not affected by any of them.
- **`opentide migrate objects` is removed**, with the migration guide and prompt (`docs/usage/migration/`) and the "Migrating from submodule CI" section of the CI/CD guide. It moved CoreTIDE folders (`Configurations/`, `Objects/*`, `Models Library/*`, `.opentide/framework/*`) but not their content, which opentide never read. `opentide migrate vocab-scope`, which upgrades opentide objects from 0.13, and `opentide deploy migrate-state` stay; [`opentide migrate`](docs/cli/migrate.md) now documents `vocab-scope`.
- **`global.toml`, `schema.toml` and a `systems/` folder under `.opentide/configurations/` fail every command** with `retired_configuration_file`, naming what replaces each (`paths.toml`; nothing; `platforms/<platform>.toml`). They were loaded and then ignored, so a workspace believed it was configured by settings that had no effect: `schema.toml`'s `[templates]` defaults never reached a template, its `[vocabulary]` table was dropped. The bundled `global.toml` and `schema.toml` are gone, and `paths.toml` is the only layout: `[paths.tide]`, `[paths.core]`, `[paths.framework]`, `[indexes]`, `[exports]`, `[json_schemas]`, `[templates]`, `[config_json_schemas]`, `[config_metaschemas]` and `[recomposition]` are unknown keys. `opentide explain retired_configuration_file` describes the finding.
- **A platform file is identified by its file name only.** `[platform] identifier`, `subschema` and `flags`, and the `[tide]` table, are unknown keys, and the `identifier_mismatch` finding is gone. Splunk's `[setup]`, `[secrets]`, `[defaults]` and table-form `[modifiers]`, and Carbon Black's `[setup]`, `[secrets]` and `[validation]`, which configured a platform without `[[tenants]]`, are unknown keys too: declare `[[tenants]]` with `[tenants.setup]`.
- **A Splunk block takes the `platform::splunk::1.0` layout only.** The `splunk::2.x` keys (`search`, `cron_schedule`, flat `throttling`, `threshold`, `notable`, `risk`, `email`, `scheduling.frequency`, `scheduling.cron`, `scheduling.custom_time`, `scheduling.lookback`) and the hidden `advanced` table of raw `savedsearches.conf` keys are unknown keys, like every other unknown key, where they were rewritten onto the current layout before validation.
- **An objective's root `composition` is an unknown key.** It was accepted and dropped; the composition is `objective.composition`. A rule's `meta:`, offered by the editor schema as a deprecated spelling of `metadata:` that validation refused, is gone from the schema too, and `metadata` is required there as validation requires it.
- **`opentide export playbook-map` is removed**, with the `openpyxl` dependency it alone used. It read root `status`, `title`, `meta.author` and `tags.playbook` from rules, fields `rule::1.0` does not have, so it exported nothing.
- **CoreTIDE names leave the Python API**: `opentide.platforms.plugins.DeployTide` (now `EnabledPlatforms`) and its `PlatformsRegistry`, `PluginTide`, `DeployEngine`, `DeployMDR`, `ValidateQuery` and `PluginEnginesLoader` aliases; `opentide.deployment.TideRepo` (use `GitRepository`); `opentide.deployment.DetectionSystems` (use `DetectionPlatforms`); `opentide.core.errors.TideErrors` (use `Errors`). `opentide.platforms.registry.PlatformsRegistry`, the registry behind `Opentide.Platforms`, is unchanged. `[debug] proxy_enabled` in `deployment.toml`, kept as "ignored" so a CoreTIDE file would load, is an unknown key, as `[proxy]` already is. The bundled authoring skills no longer mention `Schemas/Templates`, `Configurations/systems` or `mdr::2.1`.

### Install

```bash
pip install opentide==0.21.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.20.1] — 2026-11-03

Patch release. A `visibility.toml` log source is one dataset, named by its `name` and declaring its columns, and the query checks read them ([language-server 0.7.1](https://github.com/opentidehq/language-server/releases/tag/v0.7.1)); `lint` checks files that start with a UTF-8 byte-order mark, MCP `validate_query` reads `visibility.toml`, and `lint.toml` sets the filename convention per object kind. A patch by maintainer decision, although the release-management rule makes a change to accepted input a minor: the 0.20.0 `visibility.toml` dataset lists were a defect of `visibility::1.0`, shipped the same day, and are corrected in place. After upgrading, a workspace that used the 0.20.0 dataset lists (`tables`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views`, `ecs`), which now fail validation with a message that says what to do, rewrites `visibility.toml` with one `[[logsources]]` per table, sourcetype or index pattern, named after it, and updates the signals' `data.logsources` references to the new names ([Upgrading from 0.20.0](docs/usage/configuration.md#upgrading-from-0200)). Everything else needs nothing.

### Added

- **`lint.toml` sets the filename convention per object kind** ([#721](https://github.com/opentidehq/opentide/issues/721)). `[filenames] style` and `pattern` applied to every kind, so a catalogue whose rules keep their name as the file stem (`[SEN][Identity]Some rule[TenantA].yaml`) while threats and objectives use slugs had to fall back to `style = "none"` and one pattern for both shapes. `[filenames.threats]`, `[filenames.objectives]` and `[filenames.rules]` now take `style` and `pattern` for that kind; a key a kind's table leaves unset comes from `[filenames]`, and a kind without a table follows `[filenames]` as before. `lint` compares, renames under `--fix` and pattern-checks each file by its own kind's convention, and `opentide new <kind>` names the file by its kind's `style` (its pattern warning names the table the pattern came from). A table for another kind, or a key other than `style` and `pattern` in a kind's table, exits `2` naming it. Without a kind table nothing changes. See [A convention per object kind](docs/cli/lint.md#a-convention-per-object-kind).

### Changed

- **ATT&CK 20.0 group labels.** 32 ATT&CK groups in the actors vocabulary take their current label (`[Enterprise] APT28` where it said `[Mobile] APT28`) in generated docs and editor schemas. `threat::1.0` still pins `actors::1.1` and accepts the same values; the 60 actors added at `actors::1.2` wait for a new threat revision.
- **The analysis engine is [language-server 0.7.1](https://github.com/opentidehq/language-server/releases/tag/v0.7.1), from crates.io** (`opentide-analysis`, `opentide-lsp`), which reads `visibility::1.0` as corrected in place: a log source's `name` is its dataset, and its `columns` are known to the query checks ([opentidehq/language-server#146](https://github.com/opentidehq/language-server/issues/146), [#147](https://github.com/opentidehq/language-server/issues/147), [#148](https://github.com/opentidehq/language-server/issues/148), [#149](https://github.com/opentidehq/language-server/issues/149), [#150](https://github.com/opentidehq/language-server/issues/150)). What the query checks (`validate`, `validate query`, `lint`, `tui`, MCP `validate_query`) and the language server do differently: a KQL table declared with `columns` is checked like a documented table, so a near miss of a declared column is `kql_unknown_column` and an operator its declared type does not support is `kql_type_mismatch`, and hover and completion show the declared columns; an unknown table keeps its profile's severity once a log source is declared, so a typo in a Defender table name fails `validate` again (`kql_unknown_table`, an error under `defender_for_endpoint`, a warning under `sentinel`); once a workspace declares tables for a platform, a table name is checked whatever its case, so an undeclared lower-case name is no longer silently accepted; column patterns in `project-reorder`, `project-away` and `project-keep` (`Device*`) parse; and an object file the language server opens, or a `visibility.toml`, that starts with a UTF-8 byte-order mark is analysed like the same file without it. The `opentide._native.dataset_status` binding takes `(platform, name)`: a log source's system decides what kind of dataset its name is, so the `kind` argument is gone.

### Fixed

- **`opentide lint` checks the queries of an object file that starts with a UTF-8 byte-order mark** ([#719](https://github.com/opentidehq/opentide/issues/719)). `lint` read object files as `utf-8`, so the BOM reached the engine, which found no query in the file: none of that rule's queries was analysed, and `lint` reported nothing for it while `validate` did. Object and query files are now read as `utf-8-sig` wherever opentide hands their text to the engine or parses them (`lint`, `validate`, `validate query`, `tui`, code frames, `opentide query --query-file`), so a BOM changes no finding. A query file (`.kql`, `.spl`, ...) that starts with one no longer has its line-1 findings one column off.
- **MCP `validate_query` knows the datasets the workspace's `visibility.toml` declares** ([#720](https://github.com/opentidehq/opentide/issues/720)). The offline check ran the engine without the workspace's declarations, so an agent got other findings than `opentide validate query` and `lint` on the same query: a declared custom table was unknown (an error under `defender_for_endpoint`), and a table it did not declare was not reported. The tool now hands the engine `.opentide/configurations/visibility.toml` before each check, read afresh on every call so an edit applies at once; a server started as an Agent Plugin with no workspace declares nothing. See [validate_query](docs/mcp/tools.md#validate_query).
- **A `visibility.toml` log source is one dataset, named by its `name`, with its columns: `visibility::1.0` is corrected in place** ([#718](https://github.com/opentidehq/opentide/issues/718), [opentidehq/specifications#63](https://github.com/opentidehq/specifications/issues/63)). 0.20.0 let one log source list datasets (`tables = ["A", "B"]`, `indexes`, `sourcetypes`, `macros`, `indices`, `data_views`, `ecs`), so a workspace that declared its tables had to invent groups for them ("Custom tables"), signals then named those groups in `data.logsources`, and a dataset had nowhere to declare its columns. A log source's `name` is now its dataset: the KQL table (`sentinel`, `defender_for_endpoint`), the sourcetype (`splunk`), the index pattern (`elastic`); Splunk indexes and macros and Elastic data views are no longer declarable. It takes `name`, `description`, `system`, `tenants`, `assets`, `references` and `columns`, a table keyed by column name whose values set `type` (from the system's type set) and an optional `description`. Names are unique per `system`. The 0.20.0 keys fail validation (`schema_validation` on the key) with a message that says what to do instead. A name two systems declare is offered once to signals and describes both, where the first one used to hide the other. The bundled `visibility.toml` declares no log source (it held a placeholder) and shows one commented example per platform, one with columns; the `*_not_declared` explain pages say what the engine does: the warning is for a name no log source declares once the system has one, including a table the engine knows. The schema identifier stays `visibility::1.0`. The query checks read the new shape and the declared columns with language-server 0.7.1 (see Changed). **Upgrade:** a workspace that declared datasets in 0.20.0 rewrites `visibility.toml` with one `[[logsources]]` per table, sourcetype or index pattern, named after it, removes `indexes`, `macros`, `data_views` and `ecs`, and updates the signals' `data.logsources` references to the new names. See [Upgrading from 0.20.0](docs/usage/configuration.md#upgrading-from-0200).

### Install

```bash
pip install opentide==0.20.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.20.0] — 2026-11-02

Minor release: `validate` compiles every rule a deploy would compile, the query checks know the documented tables and their columns (language-server 0.7.0), a workspace's `visibility.toml` declares its own datasets, and `lint.toml` sets the filename convention. It is a minor because `validate` can now fail a rule that passed under 0.19.0, and because `validate query --live` drops the `VALIDATION_*` environment flags and the `validation_exit_code` / `exit_on_validation_errors` helpers. After upgrading:

- **Run `opentide validate`.** A rule the Sentinel or Elastic compiler cannot build (a Sentinel rule without `grouping.alert`, say) fails it where only its deploy failed before, and a query with a near miss of a documented column (`kql_unknown_column`), a type Kusto does not accept (`kql_type_mismatch`) or a near miss of a CIM field (`spl_unknown_datamodel_field`) is an error. `--queries warn` reports the queries as warnings while you fix them.
- **Scripts that read `VALIDATION_ERROR_RAISED` or `VALIDATION_WARNING_RAISED`, or call `validation_exit_code`, read the exit code instead** (or `report_outcome(report)` from Python). `--json` and the exit codes are unchanged.
- **Optionally, declare your own tables, indexes and index patterns** in `visibility.toml`, so the query checks know them.

### Added

- **The MCP server finds your detection repository when an Agent Plugin starts it** ([#431](https://github.com/opentidehq/opentide/issues/431)). An Agent Plugins 1.0 client (VS Code, Cursor, GitHub Copilot) starts a plugin's server in the plugin's directory, so the [opentidehq/skills](https://github.com/opentidehq/skills) plugin's `opentide mcp start` served the skills package as an empty catalogue. Started in a directory whose `plugin.json` is an Agent Plugins manifest, the server now serves `OPENTIDE_REPO_ROOT` or `OPENTIDE_TIDE_WORKSPACE` when it names a workspace, the plugin directory when it is one, or else the host's project directory (`CLAUDE_PROJECT_DIR`, then `PWD`). With none, the catalogue tools and resources fail with `workspace_not_found` and say how to name the repository; `explain` and offline `validate_query` still answer. A server started anywhere else resolves its workspace as before. See [Agent Plugins](docs/mcp/configuration.md#agent-plugins).
- **`opentide setup skills --plugin` installs the opentidehq/skills Agent Plugin for a project's Claude Code users** ([#431](https://github.com/opentidehq/opentide/issues/431)). It adds the `opentide` marketplace (`extraKnownMarketplaces`, GitHub `opentidehq/skills`) and enables `opentide@opentide` (`enabledPlugins`) in `.claude/settings.json`, keeping every other setting, so Claude Code offers the skills and the MCP server to whoever opens the project. With `--claude-code`, `CLAUDE.md` is written but the skills are not copied to `.claude/skills/`, which would load each one twice; on its own, `--plugin` downloads nothing. A settings file that is not a JSON object is left unchanged, with a warning. JSON output has `plugin`, and `advice` names the install step of the agents that install plugins from their own menu (Cursor, VS Code, Copilot CLI). See [The Agent Plugin](docs/cli/setup.md#the-agent-plugin).
- **`opentide setup mcp --generic` writes an Agent Plugins 1.0.0 `mcp.json`** (`$schema`, `type: "stdio"`), which validates against `https://agent-plugins.org/schemas/1.0.0/mcp.schema.json`, so a plugin can ship it unchanged. Merging into an existing `opentide.mcp.json` keeps its own `$schema`.
- **A `visibility.toml` log source names the datasets it fills, so a custom table or index is known to the query checks** ([#695](https://github.com/opentidehq/opentide/issues/695), part of [opentidehq/language-server#110](https://github.com/opentidehq/language-server/issues/110)). The engine knew only the tables it ships, so a workspace's own tables (`MyApp_CL`), Splunk indexes and Elastic index patterns were unknown to it. A log source now takes, according to its `system`, `tables` (`sentinel`, `defender_for_endpoint`), `indexes`, `sourcetypes` and `macros` (`splunk`), or `indices`, `data_views` and `ecs` (`elastic`, `ecs = true` marking its indices as following the Elastic Common Schema). Names may hold `*` (`*_CL`, `logs-azure.*`). A field that does not fit its log source's `system`, or an empty name, fails validation (`schema_validation` on that field), so a Splunk index can never make a Sentinel table known. Every field is optional: a workspace that names none is checked as before, and the engine's warnings about an undeclared name (`kql_table_not_declared`, `spl_dataset_not_declared`, `elastic_dataset_not_declared`) are opt-in per platform and kind. Nothing is generated: the engine reads `.opentide/configurations/visibility.toml` itself. `opentide validate`, `opentide validate query`, `opentide lint` and `opentide tui` hand it the file on every run, and the language server (`opentide lsp start`, or `opentide-lsp` on its own) reads it at start-up and again whenever it changes, in the editor before it is saved or on disk, and checks the open documents again. A quick fix on an undeclared name adds it to its platform's log source. The bundled `visibility.toml` shows one commented example per platform, and the `visibility::1.0` schema carries the new fields. See [The datasets a log source fills](docs/usage/configuration.md#the-datasets-a-log-source-fills).
- **`opentide lint` reports the engine's ECS findings** (`ecs_unknown_field`, `ecs_type_mismatch`) and its undeclared-dataset warnings with the other query warnings, instead of dropping a code with no language prefix; each has an `opentide explain` page.
- **`lint.toml` can set the filename convention** ([#699](https://github.com/opentidehq/opentide/issues/699)). The `filenames` check had one rule, a stem equal to `slugify(name)`, so a catalogue with its own naming (for example `[SEN][AWS]Some rule[TenantA+TenantB].yaml`) could only turn the check off, and lost its nested-file, unparsable-file and missing-name findings with it. `[filenames]` takes two new keys. `style` is `"slug"` (the default: `slugify(name)`, as before), `"name"` (the stem is the name less the characters a file name cannot hold, with the same `--fix` rename, `-{uuid[:8]}` collision suffix and idempotence) or `"none"` (the stem is not compared with the name). `pattern` is a regular expression the whole stem must match; a stem that misses it is a new `filename_pattern` finding with the check's severity, no `expected` and the pattern in `help`, and `--fix` leaves it. `opentide new` names the file it scaffolds by `style`, and warns when the file misses `pattern`. An unknown `style` or a `pattern` that is not a string or does not compile exits `2` naming the key. Without either key nothing changes. `generate docs` still names pages `slugify(name)`, so with `style = "name"` an object file and its page no longer share a stem. See [opentide lint](docs/cli/lint.md#filename-convention); `opentide explain filename_pattern` describes the finding.
- **`opentide validate` fails a rule a platform compiler cannot build, so a rule that validates deploys** ([#660](https://github.com/opentidehq/opentide/issues/660)). A Sentinel rule without `grouping.alert`, or without `scheduling.frequency` and not NRT, passed `validate` and was first reported by `deploy --dry-run` as `✗ would fail`. The `schema` check now compiles each rule a deploy would compile (its status deploys and its platform is enabled) with the dry run's own offline compiler, Sentinel's or Elastic's, and reports the same code, message and help (`compile_missing_field`, `compile_invalid_value`, `compile_empty_block`, `compile_failed`) at the key at fault, or the block that should hold it. A `DESIGN` or `REMOVED` rule is not compiled, and rules are compiled only once the run has no other error, so one cause is reported once. A workspace whose rules deploy sees no change; one with such a rule now fails `validate` (exit `1`) where only its deploy failed before. See [What a platform compiler needs](docs/cli/validate.md#what-a-platform-compiler-needs).

### Changed

- **The analysis engine is [language-server 0.7.0](https://github.com/opentidehq/language-server/releases/tag/v0.7.0), from crates.io**, with table and column knowledge (`opentide-analysis`, `opentide-lsp`; [opentidehq/language-server#134](https://github.com/opentidehq/language-server/pull/134)). What the queries check sees:
  - Under the `sentinel` profile `kql_unknown_table` is a warning, not an error, as a Sentinel workspace holds tables no catalog lists; it stays an error under Defender's advanced hunting schema. The Azure Monitor Logs tables (`NTANetAnalytics`, `SentinelHealth`, ...), the Defender XDR tables and the ASIM parsers are known under `sentinel`, so `validate` no longer fails on them.
  - `kql_unknown_column` (error): a near miss of a documented column (`_Im_NetworkSession | where DstPortNumbr == 22` suggests `DstPortNumber`), or a name that is not a column after `project`, `summarize` or `distinct`. `kql_type_mismatch` (error): an operator Kusto does not define for a column's type (`EventID has "46"`).
  - `spl_unknown_datamodel_field` and `spl_unknown_datamodel` (errors) on a near miss of a CIM field, data model or dataset; `ecs_type_mismatch` (error) and `ecs_unknown_field` (warning) on Elastic queries over ECS indices.
  - `_Im_NetworkSession(starttime=ago(1d))` and other named arguments parse.
  - KQL forms Kusto accepts no longer fail `validate`: a doubled quote in a verbatim string (`@"{""a""}"`), `.[...]` access on a dynamic value (`d.["a.b"]`), quoted identifiers (`where ['c'] > 0`, `project ["Display Name"] = ...`), `parse-where`, and `distinct` with named expressions or `*` ([opentidehq/language-server#142](https://github.com/opentidehq/language-server/pull/142)).
  - `opentide lint` no longer reports `kql_join_summarize_before_project` for a `summarize`, which already returns only the columns it names.
  - In editors (`opentide lsp start`) and `opentide tui`, KQL hover and completion show a column's description from the Azure Monitor Logs reference ([opentidehq/language-server#140](https://github.com/opentidehq/language-server/pull/140)).
- **`validate query --live` runs on the `opentide query` runners, and the `VALIDATION_ERROR_RAISED` / `VALIDATION_WARNING_RAISED` environment flags are gone** ([#673](https://github.com/opentidehq/opentide/issues/673)). Each platform's live check is now its runner's: a search for one row over the last minute (Sentinel, Defender, SentinelOne), Splunk's `search/parser` and Carbon Black's `search_validation` (no search runs), and for Elastic the Kibana preview of the compiled rule, as before. No check saves a search or creates a rule. Each query is checked as deploy sends it, so a Sentinel or Defender rule's tenant exclusions are now in the checked query, and one client serves every rule of a tenant (Defender signed in once per rule before). Validators return a verdict per rule, query and tenant instead of setting process-wide flags, so `DetectionRule.validate_query` no longer saves and restores the environment, and `validate`, `validate query` and `share` grade their runs from what they found. The `--json` document, the human output and the exit codes are unchanged, with three exceptions: an unreachable Sentinel workspace is now reported like every other platform's tenant (`tenant`, `host`, exit `1`) rather than as rejected queries; a Sentinel credential the tenant refuses fails the run as `Query validation for sentinel failed: …` rather than as rejected queries (exit `1` either way); and a SentinelOne answer that is neither a success nor a `400` is now that query's rejection rather than a failed run. `opentide.cli.exit_codes.validation_outcome` takes the run's findings (`failed=`, `warned=`) and `report_outcome(report)` grades a `ValidationReport`; `validation_exit_code` and `exit_on_validation_errors` are removed. See [`--live`](docs/cli/validate.md#--live).

### Fixed

- **Deploy errors no longer say "MDR"** ([#617](https://github.com/opentidehq/opentide/issues/617)). The last messages that still used the retired term now name the key at fault: a Splunk rule without its block fails with `The rule has no configurations.splunk block` (or `... configurations.splunk.query`), and a SentinelOne rule the console no longer has points at its entry in `.opentide/states/deployment/`, where vendor ids live since 0.15.0, instead of "the MDR file".
- **`opentide doctor` no longer reports fresh templates as stale in a workspace that sets `[metadata].required` in `lint.toml`.** `generate templates` renders those metadata keys as live keys, but the `templates_fresh` check rendered the default `author` and `organisation`, so a workspace whose `[metadata].required` differs from the default was told to regenerate templates it had just generated. The check now renders with the workspace's `[metadata].required`. A `lint.toml` that parses but holds a value opentide rejects (an unknown `[metadata].required` key, say) is reported by `templates_fresh` as a warning naming the key, where the check used to report stale templates for the wrong reason. A `lint.toml` that is not valid TOML is still reported by `configuration`.

## [0.19.0] — 2026-10-29

Minor release: the language server and its query engine are compiled into opentide, so `validate` checks every rule query offline, `lint` checks query style, `opentide lsp start` serves editors, and `opentide query` runs a query on a tenant. It is a minor because `validate` now fails on a query the platform would reject, `validate query` without `--live` checks instead of refusing, and wheels are built per platform.

The language server and its query engine ship with `pip install opentide` ([#332](https://github.com/opentidehq/opentide/issues/332)). There is no `opentide[lsp]` extra and no second package: the Rust engine from [opentidehq/language-server](https://github.com/opentidehq/language-server) is compiled into opentide itself, so each opentide wheel is built for its platform. After upgrading:

- **`opentide validate` checks every rule query.** The new `queries` check is one of the defaults, so a query the platform would reject now fails `validate` (exit `1`). `--queries warn` reports those queries as warnings instead (the run passes unless `--strict`) while you fix them; `--queries off` validates everything but the queries.
- **Read `opentide validate query` again.** Without `--live` it now checks every rule query offline (exit `1` on an error) instead of refusing with exit `2`. A script that relied on the refusal, or on `--platform` being required without `--live`, changes behaviour; `--live` is unchanged.
- **Run `opentide generate schemas`** to write the language server's catalogs, then point your editor at `opentide lsp start`.

### Added

- **`opentide deploy` reports each rule as it is sent, and counts every run, failed ones too** ([#675](https://github.com/opentidehq/opentide/issues/675)). A real run printed nothing between the plan and one summary line, so a Sentinel deploy of about 90 rules sat for two minutes and a CI log looked hung; when the platform rejected one rule the log showed a traceback and nothing about the rules before or after it. Each platform's deployer now reports every rule it sends (`opentide.core.deploy_events`), and the CLI prints one append-only line per rule as it finishes, with no spinner and no carriage return when stdout is not a terminal: `[ 3/91] ✓ deployed  <rule>  0.9s`, `✗ failed` followed by the platform's own message and HTTP status, and `· skipped` for a rule the engine left out. A run that stops early prints every rule it never reached as `not attempted after a failure`, and a platform it never reached as a skipped step. On a terminal the live row names the rule being sent. The run ends with the platform's counts (`✗ sentinel · 2 deployed, 1 failed, 88 not attempted · 14s`) and an outcome line that always carries `failed` and `not attempted` and the elapsed time, whether the run passed or failed, and exits `1` on a failure with `failure.code` `issues_found`. With `--json`, the document gains `results` (one entry per rule and tenant with `id`, `name`, `platform`, `tenant`, `action`, `status`, `seconds`, `error` and `reason`) and `summary` counts every action, `failed`, `skipped` and `not_attempted`; stdout stays one document. A dry run now ends with `dry run, nothing sent`.
- **Verbs by intent** ([#685](https://github.com/opentidehq/opentide/issues/685)): `validate` answers "does it deploy?", `lint` "is it clean?", `lsp` serves editors.
  - **`opentide validate` checks queries by default.** Its `queries` check reads every query an object carries and reports the analysis engine's errors (a query the platform would reject) with their codes, positions and `opentide explain` pages; `summary.queries` counts the queries and the outcome line says it (`✓ 6 objects valid · 4 queries · 1.2s`). `--check queries` runs it alone. `--queries error|warn|off` sets how a rejected query is reported: an error (the default), a warning with `context.reported_as_warning` and a frame note (passes unless `--strict`), or not at all. `--queries` with another `--check`, or `--check queries --queries off`, exits `2`. A failed run's `check again` step keeps the mode. MCP `validation_report` takes the same `queries` argument.
  - **`opentide lint` checks query style** (its new `queries` check, on by default in `lint.toml`): the engine's warnings and notes, such as slow query shapes (`kql_where_not_first`, `spl_wildcard`) and Elastic block settings that miss events (`lookback_zero`, `risk_band`), as code frames.
  - **`opentide validate query --file` takes query files** (`.kql`, `.spl`, `.esql`, `.eql`, `.kuery`, `.lucene`, in any case): one query in that language, checked offline, with the `--platform` profile when one is given.
  - A query still holding the `...` stand-in `opentide new` wrote, under its `# opentide:placeholder` marker, is left to lint's `placeholders` check, so a draft rule still validates.
- **CI fails when the engine's bundled catalog is stale** ([#679](https://github.com/opentidehq/opentide/issues/679)). `scripts/build/check_engine_catalog.py` (in `scripts/ci-local.sh` and the lint job) compares the catalog opentide's models generate with the one in the pinned engine and names the fields that differ, so a model or vocabulary change reaches the language server before a release instead of after.
- **opentide checks objects with its own catalog** ([#677](https://github.com/opentidehq/opentide/issues/677)). `opentide lsp start` and `opentide tui` generate the language server's catalog from this opentide's models and the workspace's configuration, cached under the user cache directory (`OPENTIDE_CACHE_DIR`), instead of using a committed `.opentide/lsp/catalogs/` from an older opentide or the engine's snapshot. The catalog `source` reads `opentide`; the committed copy stays for editors that run `opentide-lsp` on its own, and `opentide doctor` (`lsp_catalog`) says when it is stale or when generation fails.
- **The language server checks each object against its own revision** ([#676](https://github.com/opentidehq/opentide/issues/676)). The catalog `opentide generate schemas` writes has the fields of every revision (`rule::1.0` and `rule::1.1` each), not only the newest, with required fields and the objects that take no other key. So editors and `opentide tui` report what `opentide validate` reports: a `rule::1.1` without `description`, a `rule::1.0` carrying `metadata.reviewed`. Run `opentide generate schemas` to refresh a workspace's catalog. `python -m opentide.generation.lsp_catalog --out DIR [--check]` writes or checks the catalogs, and language-server generates its bundled ones with it.
- **`opentide validate query` checks queries offline.** The analysis engine parses each rule query in its platform's language, with the platform's profile: KQL with Sentinel or Defender tables, SPL, ES|QL (against the block's tenants' `setup.version`), EQL, Kibana KQL, Lucene, and Carbon Black's Lucene dialect. No tenant, no credentials. It is the default; `--live` is the tenant check. `--platform` is optional offline (every platform the engine parses), `--changed`, `--file` and `--uuid` narrow it, and `--queries warn` reports a rejected query as a warning (failing only under `--strict`). It reports the queries a platform would reject; their style is `opentide lint`'s. Findings print as code frames at their place in the rule file, with CI annotations, and the document lists every query checked (`queries`) and finding (`diagnostics`). SentinelOne's S1QL is checked on the tenant only; CrowdStrike and HarfangLab are never validated.
- **`opentide lsp start`** serves the language server protocol on stdio for editors: diagnostics, hover, completion, signature help, definitions, references and semantic highlighting for Tide objects and the queries inside them, and for `.kql`, `.spl`, `.esql`, `.eql`, `.kuery` and `.lucene` files. `--stdio` is accepted for editors that pass it. [Configuring an editor](docs/cli/lsp.md#configuring-an-editor) has Neovim and Helix samples.
- **Query findings are highlighted.** At a terminal, the source lines of a query finding's code frame are coloured as the editor colours them (keywords, functions, tables, strings, comments), by the same engine; plain output, CI logs and `--json` are unchanged.
- **`opentide tui` shows the language server.** Each object's file is coloured by the language server (Tide keys, UUIDs, vocabulary values, and the query inside a rule in its own language), and the detail pane shows what the language server reports for it, refreshed at every load, beside the last validate run; a finding both report is shown once. The tree marks objects with findings before any validate run, the finding's span is underlined in the file, and the Results tab colours the query lines of its code frames. See [The language server](docs/cli/tui.md#the-language-server).
- **`opentide generate schemas` writes the language server's catalogs** to `.opentide/lsp/catalogs/generated/` (`fields.json`, `deprecations.json`) from the workspace's models, so hover, completion and vocabulary checks follow its configuration; the catalog compiled into the engine is the fallback.
- **MCP `validate_query` checks its `query` offline** in the platform's language, with `language` and `stack` for Elastic, and returns `valid`, `errors`, `warnings` and `diagnostics` with positions in the query. `live: true` is unchanged.
- **`opentide explain` pages for every engine code** (`kql_unknown_table`, `spl_parse_error`, `esql_unavailable`, ...), from the engine's own descriptions, and for `engine_unavailable`, `analysis_engine` and `lsp_catalog`.
- **`opentide doctor` checks the engine** (`analysis_engine`: it imports, and its versions) and the language-server catalogs (`lsp_catalog`: present, parseable, from this opentide version).
- **`opentide query` runs a read-only query on a platform's tenants and returns the rows** ([#665](https://github.com/opentidehq/opentide/issues/665)). Trying a detection against real telemetry meant copying it into the Sentinel, Defender, Splunk or Kibana console: `validate query --live` only says whether a query runs. `opentide query --platform <p> '<query>'` sends the query over a window (`--since 24h` by default, or `--from`/`--to`) to the tenant `--tenant` names, several, or `--tenant all`, and prints at most `--limit` rows per tenant (100 by default) as a table, `--format jsonl` or `csv`, or the `--json` envelope with one `results` entry per tenant. `--rule <uuid>` or `--file <rule.yaml>` runs the query that rule deploys. Every platform has a runner: Sentinel (Log Analytics), Defender (Graph advanced hunting), Splunk (one-shot search), SentinelOne (PowerQuery), Carbon Black Cloud (process search), CrowdStrike (Next-Gen SIEM, needs `NGSIEM: Read`), HarfangLab (telemetry source and field filters) and Elastic (ES|QL, EQL and Lucene on Elasticsearch; KQL through a rule preview, whose rows are the preview's alerts). No search or rule is saved on a tenant. A Sentinel or Defender rule query carries the tenant's exclusions, as deploy compiles them. With several tenants and no `--tenant` the command exits `2` and lists them; a tenant that refuses the query fails the run with exit `1` while the others still return rows. See [opentide query](docs/cli/query.md).
- **MCP `run_query` runs the query** instead of returning a stub. It refuses until `live: true`, and its next action is the live call; then it returns the `opentide --json query` payload. It takes `tenant` (names, comma-separated, or `all`), `rule`, `since`, `limit`, `language` and `index`. The `stub` and `rows` keys of the old answer are gone.
- **`DetectionRule.run_query(platform, tenants=..., since=..., limit=...)`** runs a rule's query from Python, and `opentide.query.run_query` runs any query.
- **`opentide info` and `opentide://platforms` report `can_query`** for each platform.

### Changed

- **The engine is [language-server 0.6.0](https://github.com/opentidehq/language-server/releases/tag/v0.6.0), from crates.io** instead of a git revision, so the sdist builds from published crates. Among its fixes: one workspace YAML file that is not UTF-8, or cannot be read, no longer drops the whole object index, which made `opentide lsp` report every reference to another object as `invalid_ref`.
- **A real `opentide deploy` prints the plan's header and tally before it sends anything**, where only `--dry-run` printed the plan. The outcome line of a pass reads `✓ Deployed 91 rules to 1 tenant · 91 created or updated · 0 failed, 0 not attempted · 1m56s`, and a run that failed on a rule reads `✗ Deployment failed · 2 created or updated, 1 failed, 88 not attempted · 14s` instead of `error: Deployment to sentinel failed: HttpResponseError: …` followed by the exception text; an error before any rule is sent (a tenant's credentials, say) keeps that message. Elastic's per-rule failures are now attributed to the rule they happened on.
- **A bare `opentide validate query` runs the offline check** instead of exiting `2` and naming `--live`. `--platform` is required only with `--live`. `--strategy` and `--wide` choose tenants, so they now need `--live` (exit `2` without it). `opentide validate --strict query` and `opentide validate --queries warn query` hand the option to `query`, which takes it now.
- **MCP `validate_query` without `live`** returns the offline check rather than a refusal (`valid` is `true` or `false` instead of `null`); it still refuses, with `valid: null`, a SentinelOne query and an empty one.
- **opentide wheels are per platform**: one wheel per platform serves CPython 3.10 and later on Linux (x86_64 and arm64, glibc and musl), macOS (Intel and Apple silicon) and Windows x64. Elsewhere, including free-threaded Python, pip builds opentide from its sdist, which compiles the engine and needs a Rust toolchain. A missing engine fails the commands that need it (`engine_unavailable`); it never skips them.
- **`opentide validate` names Elastic advisories by the codes of the platform specification** ([#637](https://github.com/opentidehq/opentide/issues/637)). The editor already used `lookback_zero`, `lookback_long`, `threshold_lookback`, `esql_metadata_id`, `eql_maxspan_window`, `eql_maxspan_lookback`, `risk_band` and `technique_not_enterprise`, while the CLI logged event names of its own, two of which (`elastic_lookback_long_warning`, `elastic_eql_maxspan_window_warning`) covered two conditions each. The log event is now the code, repeated as `code`, and `legacy_event` holds the old name for log consumers; it goes in the release after next. The three look-back codes are now independent: a `threshold` rule with a look-back over `1h` raises `lookback_long` and `threshold_lookback`, where only the first was reported before. The `technique_not_enterprise` warning that `deploy` logs when it leaves a Mobile or ICS technique out of `threat` is renamed the same way. See [opentide validate](docs/cli/validate.md#elastic-live-validation-and-deploy).

## [0.18.0] — 2026-10-27

Minor release: configuration files are now validated, rule `severity` moves to the alert labels, and new commands arrive (`new`, `doctor`, `tui`, `explain`, `commands`, `info vocab`, `validate --fix` and `--watch`). It is a minor because files that loaded under 0.17.2 can now fail, and because the CLI's human and JSON output changed. After upgrading:

- **Run `opentide validate`.** An unknown key or a wrong type in `.opentide/configurations/` now fails every command that reads the file and names the file and the key. Two cases seen while preparing this release: a Splunk tenant's `schedule_offset = "5"` must be the number `5`, and a `documentation.toml` that `opentide migrate` carried over from CoreTIDE must drop `skip_vocabularies`, `model_cover_pages` and `[titles]`. A rule whose top-level `severity` is an incident-scale value (`Substantial incident`) must use an alert label (`High`).
- **Regenerate CI** with `opentide setup ci <github|gitlab|azure> --yes`. The pipeline then keeps SARIF and Code Quality reports, and a pipeline written with `--sharing` shares a rule after the production deploy has promoted it.
- **Run `opentide generate`** to refresh schemas and templates, and `opentide setup skills` to refresh agent instruction files.
- **Move a pin of `mcp` 1.x** to `mcp>=2.3,<3`. `opentide mcp start` needs `mcp` 2.x.

Every configuration file under `.opentide/configurations/` in the configuration specification now has a Pydantic model (`lint.toml` keeps its own loader), and the CLI validates the merged file against it when it reads the file (#374). A misspelt or unknown key that was silently ignored now fails the command that reads the file, naming the file and the key: `deployment.toml is invalid: promotion.enabeld: unknown key`. `opentide validate` runs the same check by default (`configuration`), so run it after upgrading to find any.

### Added

- **Configuration models and JSON Schema export.** `opentide.models.configuration` holds one model per file: `paths.toml` (and legacy `global.toml`), `deployment.toml`, `schema.toml`, `visibility.toml`, `documentation.toml`, `sharing.toml` (items are `sharing::misp::1.0`) and each `platforms/<id>.toml`. `opentide.generation.configuration_schemas.export_configuration_schemas(dir)`, or `python -m opentide.generation.configuration_schemas <dir>`, writes the JSON Schema of each file (`model_json_schema()`, with a description on every field) and `configurations.router.json`, which maps a file name to its schema. They are for editors and the language server; `.opentide/schemas/` is unchanged.
- **`validate` check `configuration`**, on by default: every merged configuration file the CLI reads is checked against its model, so a file `deploy` or `generate docs` would refuse fails `validate` first. Issues carry `context.file` and a `field_path` into the file.
- **`opentide.validation.configuration.configuration_file_issues`** returns `{code, field_path, severity}` issues for one configuration file, merged onto the layers before it so that a partial override is not reported for keys it inherits. It returns every `sharing-config` code, and `promotion_target_unknown`, `asset_unknown` and `identifier_mismatch` for the checks a schema cannot state.
- **Elastic tenants declare their stack version** ([#661](https://github.com/opentidehq/opentide/issues/661)). `[tenants.setup] version` in `platforms/elastic.toml` takes `MAJOR.MINOR` (`8.19`, `9.5`) or `serverless`, as the Elastic platform specification defines ([specifications#61](https://github.com/opentidehq/specifications/pull/61)); any other value is a `schema_validation` error. The language server already reads it to check ES|QL against the lowest version a rule targets; without this key the configuration check reported it as `unknown_key`.
- **`opentide info vocab <name>` reports a vocabulary's contract revisions** ([#523](https://github.com/opentidehq/opentide/issues/523)). A vocabulary file declares no top-level `version`, so nothing read back which revision a field validates against. The command lists each revision the `[[keys]]` lifecycle defines with the keys it introduces, removes and admits; each object schema field pinned to the vocabulary in `data/pins/`, with its revision, the keys it admits and whether the field is `scoped` (authored `<stage>::<key>`); whether the vocabulary is staged and its stage ids; and its entry and removed-key counts. `opentide info vocab` lists every vocabulary. An unknown name exits `2` as a usage error, lists the available ones and suggests the closest. A key whose `version` or `removed` does not parse exits `1` naming the vocabulary and key. `--json` returns the same data under `vocabulary` / `vocabularies`.
- **`opentide lint` reads `lint.toml`** ([#489](https://github.com/opentidehq/opentide/issues/489)). opentide ships the defaults, and `.opentide/configurations/lint.toml` overrides them like any other configuration file. `[metadata].required` lists the `metadata` keys the metadata check demands (default `["author", "organisation"]`, so an unconfigured repository sees the same findings as before). Each check takes `enabled` and `severity` (`error`, `warning` or `info`, replacing the severity of every finding of that check). `--check` still wins: it runs a check that `lint.toml` disables. Each object is asked only for the `required` keys its schema accepts, so `reviewed` (rule::1.1 only) is not demanded of threats, objectives or rule::1.0 rules. A `required` entry that is not a metadata key, an unknown table or key, or a bad `severity`/`enabled` fails the command with exit `2` and names the key. `run_lint` takes an optional `config`.
- **`opentide tui`**, a terminal UI: the catalogue as a tree (threats → objectives → rules, with counts), each object's YAML with the diagnostics from the last validate run, coverage by ATT&CK technique, and `validate`, `generate` and `deploy --dry-run` from the command palette (`ctrl+p`) or a key, with their results printed as the commands print them. It runs only at an interactive terminal; under `--json`, in a pipe, in CI or under a coding agent it exits `2` with `failure.code` `usage_tui_needs_tty`. See [opentide tui](docs/cli/tui.md). It needs [Textual](https://textual.textualize.io/), now a dependency of `opentide` (there are no extras); it loads only when the UI opens (not for `opentide tui --help` or a walk of the command tree), so start-up is unchanged. The header shows the tagline only where it fits whole, a long name ends in `…` and gives way before its counts (the detail pane shows it in full), and the tree never scrolls sideways.
- **`opentide new threat|objective|rule`** scaffolds an object from the generated template with a fresh UUID, today's date, the git author and the catalogue's organisation. Every value nobody chose ends in `# opentide:placeholder`; the file validates at once, and `opentide lint` reports each marker by key (`surface[0]` for a list item, with its column) until it is replaced. A rule keeps the commented blocks of its own platforms only, and holds what each platform's deploy needs (Sentinel's schedule and grouping), so after moving its status to a `PREVIEW` one, `deploy --dry-run` compiles it.
- **`opentide doctor`** checks the installation, the workspace and its integrations in one checklist, with a code, a status and a fix per check, paths relative to the current directory, and `○` for a skipped check. It exits `1` when a check fails.
- **`opentide validate --fix`** applies every fix whose `safe` is `true` (a vocabulary value that differs from a valid one only in case, spaces, `-` or `_`, such as `tlp: Clear`), validates again and prints what is left: `✓ Fixed 2 values in 2 files · 3 objects valid · 0.9s`. Only the replaced value changes in each file; comments, quoting, key order and line endings stay as they were. A fix that is not safe is never applied. `--fix --dry-run` prints the edits as a unified diff and changes nothing. With `--json`, the document gains `fixed` (`[{path, line, code, before, after}]`; `would_fix` and `diff` under `--dry-run`) and `summary.fixed`. A plain `validate` counts what `--fix` would fix in `summary.fixable` and in its outcome line (`2 fixable with --fix`), and its next step is `opentide validate --fix`.
- **`opentide validate --watch`** validates again each time an object file is saved (it checks modification times every 0.5 s), in a view redrawn in place in a terminal, or one outcome line per run in plain output. A save that keeps the file's UUIDs re-checks that file; an added or removed file, or a changed reference, re-checks everything. Ctrl-C exits `0`. It is refused with exit `2` and `failure.code` `usage_watch_needs_tty` under `--json`, a coding agent or `OPENTIDE_OUTPUT=agent`.
- **`opentide explain <code>`** prints what a diagnostic code means, an example, and how to fix it; `opentide explain` lists every code, and `--json` returns the page. [Diagnostic codes](docs/cli/diagnostics.md) collects the pages.
- **Diagnostic fields on every finding.** Each entry of `validate`'s `report.issues` and `report.warnings`, and of `lint`'s `findings`, gains `path` (workspace-relative), `line` (one-based), `column` and `end_column` (best effort), `help`, `fix` (`{ "safe", "edits" }`: a replacement for a suggested value, `safe` only when the two differ in case, spaces, `-` or `_` and hold no digit) and `explain`. Lint findings also gain `code` and `field_path`. Existing keys are unchanged: `yaml_line` stays zero-based and `file_path` absolute. `summary` carries the counts behind the outcome line.
- **Each command's output schema.** Every command in `opentide --json commands` carries `output_schema`, the JSON Schema of the document it prints with `--json`, and the document gains `$defs`, the schemas they refer to. They are generated from typed result models (`opentide.cli.ui.results`). See [Output schemas](docs/cli/json-output.md#output-schemas).
- **`opentide commands`** lists every command with its arguments, options (types, choices, defaults, environment variables) and an example to paste. `opentide --json commands` gives an agent the whole tree in one document, with the installed `version` and every `OPENTIDE_*` environment variable it reads (`OPENTIDE_LINKS`, `OPENTIDE_LOG_JSON`, `OPENTIDE_VALIDATE_WORKERS`, … as well as the ones behind `--repo`, `--data` and `--proxy`); see [Command tree for agents](docs/cli/index.md#command-tree-for-agents).
- **MCP findings carry the same diagnostic fields.** `validation_report` issues and warnings, and `validate_rule` issues, gain `path`, `line`, `column`, `end_column`, `help`, `fix` and `explain`. `validate_rule`, `validation_report` and a refused `validate_query` gain `next_actions`, each `{tool, arguments, command, reason}`: a result with errors points at `explain` for the first error code, then at the same validation again. Existing keys are unchanged.
- **MCP `explain` tool**: the `opentide explain` page for a code, or every code when `code` is empty.
- **Agent instruction files teach the JSON contract.** `opentide setup skills` writes `AGENTS.md`, `CLAUDE.md` and `.github/copilot-instructions.md` that tell an agent to run `opentide --json …`, branch on the exit code and `failure.code`, apply each finding's `fix`, follow `next_actions` and read `opentide explain`, in a search, draft, validate, dry-run loop where people own merges. The bundled skills say the same. Their Quick start deploy line is now `opentide deploy --dry-run --strategy PREVIEW --all`: the old `opentide deploy --dry-run` exits `2`, because a run needs a strategy. Re-run `opentide setup skills` to refresh files written by an earlier version.
- **An `explain` page for every failure code**, not only for findings: `opentide explain issues_found`, `usage_unknown_command`, `share_partial`, `api_key_unset`, … say what the code means and what to do.
- **CI annotations and job summaries.** In GitHub Actions, each `validate` and `lint` finding is an `::error`, `::warning` or `::notice` annotation on the line it is about, and the outcome and a table of findings go to the job summary; `deploy` adds its plan and `validate query` the queries sent per tenant. Azure Pipelines gets `##vso[task.logissue]` lines and a summary attached with `##vso[task.uploadsummary]`. GitLab CI gets the summary in `opentide-reports/summary.md`. Nothing is written under `--json`. See [CI/CD](docs/usage/workflows/ci-cd.md#annotations-summaries-and-reports).
- **`--format sarif` and `--format codequality`** on `validate` and `lint` write the findings as SARIF 2.1.0 (for GitHub code scanning; rules from the `opentide explain` pages) or as GitLab Code Quality JSON, to `--output` or to stdout. `--output` without one of these formats exits `2`. `opentide setup` adds `opentide-reports/` to the `.gitignore` it writes.
- **`opentide setup ci` keeps the reports.** The validate job writes them under `opentide-reports/`: GitHub uploads the SARIF as an artifact and, on a public repository, sends it to code scanning from a new `code_scanning` job that holds only `security-events: write`; GitLab reads the Code Quality reports and keeps the summary of each job; Azure publishes the SARIF as `CodeAnalysisLogs`. Regenerate the pipeline with `opentide setup ci <github|gitlab|azure> --yes`.
- `share push --changed --since COMMIT` diffs from a commit SHA or ref of your choosing to `HEAD`, also outside CI. Use it once to share rules promoted before this fix.

### Changed

- **Unknown keys and wrong types in configuration files are errors.** The exceptions are the retired `[vocabulary]` table of `schema.toml`, which is accepted and ignored, and a `sharing.toml` array naming an unknown connector, which is skipped with a warning. A `$NAME` placeholder is still valid for any tenant `setup` key. Error messages never repeat a value. A malformed `[[responders]]` entry is still skipped with a warning rather than failing the file.
- **`documentation.toml` values are checked.** `[diagrams] relations_direction` outside `upstream`, `downstream` and `both` failed over to `both`; it now fails to load.
- **`opentide generate schemas` writes `visibility.1.0.schema.json` as `model_json_schema()` of `VisibilityConfig`,** the same document the configuration export writes, instead of a second, enriched schema source.
- **Platform plugins own their file.** A third-party platform's `platforms/<id>.toml` is not validated; only the eight built-in platforms are.
- **A migrated CoreTIDE `global.toml` is not validated** when `paths.toml` is present (it always ships), since the resolver does not read it.
- **sharing.toml:** `api_key` must be `${NAME}` with an uppercase name, as sharing 1.0 specifies; `${misp_key}` is now a literal and reported as `api_key_literal`. `organisation_uuid` accepts uppercase hex. The warning for an unknown top-level array is `unknown_connector` (was `unknown_integration`). `api_key` is matched as written, so `" ${KEY} "` is a literal. A present but empty `name` is `name_invalid`, and a value of the wrong type takes its key's code (`object_types = "rule"` is `object_type_unknown`), as the specification's checker reports them. A duplicate name or an unknown top-level key no longer hides the other blocks' findings, and every block a duplicate involves is reported.
- **The MCP server runs on `mcp` 2.x.** `mcp` 2.x turned `mcp.server.fastmcp` into a stub that raises `ModuleNotFoundError` and moved the server class to `mcp.server.mcpserver.MCPServer`. `opentide mcp start` now uses `MCPServer`, and the base dependency moves from `mcp>=1.28.1,<2` to `mcp>=2.3,<3`. The server now reports opentide's version in `serverInfo.version`, which `mcp` 2.x would otherwise leave empty. **If your environment pins `mcp` 1.x alongside opentide** (a constraints file, a lock, or a `pip install 'mcp<2'`), upgrade that pin: `pip install 'mcp>=2.3,<3'`. With `mcp` 1.x installed, `opentide mcp start` exits with that instruction on stderr instead of a traceback; the rest of the CLI is unaffected ([#581](https://github.com/opentidehq/opentide/issues/581)).
- Under `mcp` 2.x the stdio transport drops a line that is not JSON-RPC (such as an LSP-style `Content-Length:` header) without answering it; 1.x sent an error notification. The JSON body after the header is still answered.
- **Generated templates uncomment the metadata keys lint requires.** `opentide setup` and `opentide generate templates` wrote `author` and `organisation` commented out, as optional, and `opentide lint` then flagged every object made from them. Templates and VS Code snippets now write each `[metadata].required` key live (`author:` and an `organisation:` block with `uuid:` and `name:` by default), so a new object shows what lint asks for. Fill them in, or delete the block: an empty `organisation` fails `validate`. Run `opentide generate templates snippets` to pick this up; a workspace that sets `required` gets templates that follow it.
- **The deploy "no rule to deploy" warning** is also an annotation on Azure Pipelines, as it was on GitHub Actions.
- **Findings print as code frames.** `validate` and `lint` print each finding as `severity[code]: message`, the path with `:line:column`, the line from the file with the value underlined, and a `help:` line, grouped by file. This replaces the "Validation issues" panel and lint's `[check/severity] path: message` lines. The outcome line counts them: `✓ 3 objects valid · 0.9s`, `✗ 2 errors in 1 file · 3 objects checked · 0.9s`, `✓ 3 files clean`, `! 2 findings in 1 file`. `info` ends with `✓ 1 rule · 1 threat · 1 objective · 0 load errors`, and `info --strict` now says why it exits `1`. The JSON `message` of each command is unchanged.
- **One finding per cause.** A dangling reference (`detection_model`, `objective.threats`, `threat.chaining[].vector`) is reported as `invalid_ref` only; the `vocab_unknown` it also raised is gone, in `validate` and in the MCP `validate_rule` and `validation_report` tools alike. A value repeated in a list is reported at each place it is written. `invalid_ref` issues carry the value in `context.value`.
- **`checks.schema.status` counts `config_enum_unknown` and `external_id_shape`.** Both already failed the run; the `schema` entry of `checks` said `passed`.
- **YAML errors name the line and column**, not `in "<unicode string>", line 8, column 8` over four lines: `did not find expected ',' or ']' at line 9, column 9 (while parsing a flow sequence that starts at line 8, column 8)`. `validate` reports an unreadable object file once, as its `yaml_parse` finding, instead of also logging it.
- **A value in the wrong case is a safe fix.** `tlp: AMBER`, `tlp: Clear` and `severity: localised_incident` now get `help: did you mean 'amber'?` and a `safe` fix (they had no suggestion at all); suggestions compare values without case. The MCP tools' `suggestion` follows.
- **`validate` checks each platform block's `status`** against the `[[statuses]]` your deployment configuration declares, as deploy does by exact name. `status: design` was accepted by `validate` and refused by `deploy`; it is now a `config_enum_unknown` error with a safe fix to `DESIGN`. A status no block declares is an error too. A configuration that declares no statuses leaves the field free.
- **A missing field points at where it belongs**: `error[schema_validation]: missing required field 'description'`, framed at the top of the file (or at the key of the mapping it belongs in), instead of `description: Field required` with no line. Vocabulary findings read `'clearr' is not a TLP value`. The JSON `message` of each issue is unchanged.
- **A failed `validate` says what to run next**: `→ opentide explain <code>` for the first finding, then `→ opentide validate`, in `next_actions` too, as the MCP `validation_report` does.
- **A TOML typo in `.opentide/configurations/` is your error, not a crash.** `validate`, `info`, `deploy` and every other command print a `config_parse` frame at the file, line and column, and exit `1` with `failure.code` `config_parse`; the JSON document carries the diagnostic under `diagnostics`.
- **An object file whose YAML is a list or a single value** reads `expected a mapping at the top of the file, found a list`, framed where the document starts. `deploy` stopped on it with `list indices must be integers or slices, not str`; it now exits `1` with `failure.code` `yaml_parse` and the frame.
- **`info` counts an unreadable object file without also logging it**, and log lines name such files relative to the current directory. A `generate` failure no longer quotes a raw event name (`uuid_does_not_exist_in_the_index_of_tide_objects`).
- **`lint --fix` counts what is left**: `✓ 3 files clean · 1 fixed`, not `! 1 finding in 1 file · 1 fixed`. When warnings and notes are both left, the outcome splits them: `! 15 findings in 4 files · 2 warnings, 13 notes`.
- **Code frames fit a narrow terminal.** On a terminal, a message or a note wraps at a space (or after a `/`), and a long location keeps its first folder, file name and position around `…`, so the terminal never breaks a word. Piped output is unchanged. An empty catalogue's outcome names its directory relative to the current one.
- **`failure.code` is `issues_found`** when `validate` fails on its findings, and for `lint --strict` and `info --strict`; it was `command_failed`. `info` reports `status: issues` when an object file failed to load.
- **Usage errors a command detects exit `2`, not `1`.** An unknown `info` section, an unknown `generate` phase, an invalid `validate --type`, a `share --target` that names no configured block, `info coverage` without `--technique`, `generate docs --changed` combined with a scope, and a `setup` prompt with no terminal (or under `--json`) now exit `2`, as [exit codes](docs/cli/exit-codes.md) already promised. A pipeline that tested for `1` on these should test for non-zero, or read `failure.code` from `--json`. A `share --target` naming a block that exists but is disabled still exits `1`.
- **One JSON document for every `--json` run, usage errors included.** `opentide --json valdate` prints a document with `failure.code` `usage_unknown_command` and `failure.suggestion` `validate`, and exits `2`; it used to print a Rich panel on stderr. Every document gains `schema_version`, `command`, `duration_ms`, `exit_code`, `summary`, `next_actions` and `failure`. Existing keys are unchanged; `error` is still a string. See [JSON output](docs/cli/json-output.md).
- **`--json` prints one compact line unless stdout is a terminal.** In a pipe, a file, CI or an agent's shell the document is one line, about a third smaller (a `validate` run with three errors: 2,750 bytes instead of 4,232); at a terminal it stays indented. `OPENTIDE_JSON_INDENT=0` or `2` chooses either way. Each document ends in exactly one newline; it used to end in two. A script that parsed the JSON is unaffected; one that matched indented text, such as `grep '"ok": true'`, should parse it (`jq .ok`) or set `OPENTIDE_JSON_INDENT=2`.
- **`opentide --json setup skills show <name>` for an unknown skill carries `status` (`failed`) and `message`**, like every other document. Its other keys are unchanged.
- **Every failure document carries `error`, and usage errors name the input at fault.** `error` is set on every non-zero exit, `--json validate` with issues included. `deploy --strategy PREVEW` names `--strategy` and suggests `PREVIEW`; a suggestion ignores case and `-`/`_`, so `validate --type RULE`, `info RULES` and `VALIDATE` suggest `rule`, `rules` and `validate`. `next_actions` commands in a document read `opentide --json …`. `opentide --json mcp` (a group with no subcommand) is a `usage_error` document instead of the help screen. Typer's multi-line `Choose from:` list is one line: `Missing option '--platform': choose from sentinel, splunk, …`.
- **`validate query` without `--live` and `rules unreviewed --older-than 9x` exit `2`** (`usage_missing_option`, `usage_invalid_value`) instead of `1`.
- **No colour in plain and agent output, on a terminal too**, unless `FORCE_COLOR` or `PY_COLORS` asks for it: CI logs (`CI=true`), `OPENTIDE_OUTPUT=plain` and coding agents get no colour escapes.
- **No `UnicodeEncodeError` on an ASCII stream.** With `PYTHONIOENCODING=ascii`, `·` prints as `-` and `…` as `...`, and a `--json` document escapes non-ASCII characters.
- Splunk schedule and time-range errors no longer start with `[FATAL]`.
- **`--json`, `--no-color`, `--debug` and the new `--quiet` work after the command.** `opentide validate --json` is the same as `opentide --json validate`.
- **Human output follows one grammar.** Warnings print first (`warning: …`), then one outcome line (`✓ Validation passed`, `! Catalogue lint found issues`, `Skipped: …`), then at most three next steps (`→ opentide lint --fix`). An ordinary failure is an `error:` line on stderr instead of a `FATAL` panel. Plain output (pipes, CI, `NO_COLOR`) is never wrapped, so paths stay on one line. Scripts that matched `OK `, `ISSUES `, `SKIPPED `, `WARNING ` or `FATAL:` should use `--json`.
- **`--debug` reads `OPENTIDE_DEBUG`.** `DEBUG` is still read when it is a boolean (`1`, `true`, `0`, ...). `DEBUG='*'`, which Node tooling exports, made every command exit `2`; it is now ignored. opentide no longer exports `DEBUG` to the processes it starts; it exports `OPENTIDE_DEBUG=1`.
- **`--json` logs `WARNING` and above on stderr**, like every other mode, instead of `INFO`; `--debug` shows everything. Log lines carry one level label (`warning: Tenant targets failed · system: sentinel`) instead of two.
- **Coding agents and `OPENTIDE_OUTPUT`.** Under a coding agent (`AI_AGENT`, `CLAUDECODE`, `CURSOR_AGENT`, ...) `setup` never prompts: it exits `2` and names the flags to pass. A failure ends with a tip to add `--json`. `OPENTIDE_OUTPUT=json|agent|plain|human` chooses the output mode.
- **The MCP server describes itself as spec-driven development for agentic detection engineering.** Its `instructions` give agents the workflow (search, draft, `validation_report` until clean, dry-run `deploy_rule`; people merge and deploy), and each tool's description says what it returns and what to call next.
- **`opentide setup skills discover` ends with an outcome line**, `✓ 31 skills available · 2 installed · opentidehq/skills@main`, instead of `Source: …`, and cuts each description at a word boundary with `…` rather than mid-word. The bundled rule skill and its catalogue entry name `rule::1.1`, the schema `opentide new rule` writes, instead of `rule::1.0`. Every `setup skills` option has help text, and `opentide --json setup skills` names the target flags it needs instead of a `--skill` option that does not exist.
- **The MCP server's stderr logs `WARNING` and above by default**, like `--json`; `--debug` (or `OPENTIDE_DEBUG=1`) shows everything.
- **`opentide mcp start` keeps stdout for JSON-RPC alone.** A `print`, a console line or a child process writing to stdout while a tool runs lands on stderr instead of corrupting a frame.
- **An unexpected error prints `error[internal]` and writes a redacted crash log.** It used to print a Rich traceback on every run, which repeated a token or a proxy password in the exception message as it was. Now stderr gets `error[internal]: <Type>: <message>`, the crash log's path and a link to a pre-filled GitHub issue (version, Python, OS and command name only); the traceback prints only with `--debug`. The log goes to `$XDG_STATE_HOME/opentide/` (`~/Library/Logs/opentide` on macOS, `%LOCALAPPDATA%\opentide\logs` on Windows), never into the repository, with credentials, secret values and tenant names and hosts removed; the last ten are kept. Under `--json` the document has `failure.code` `internal` and `failure.crash_log`. Exit code `1`, as before. Ctrl-C exits `130` with one `error: interrupted` line. See [Troubleshooting](docs/usage/troubleshooting.md#opentide-stops-with-errorinternal).
- **Faster start.** `opentide --version` answers before Typer, Rich or the detection registry load: about 30 ms instead of about 1 s. `opentide --help` and shell completion list the commands without importing them (about 0.3 s instead of 1 s); a command's module loads when it runs. `import opentide` no longer loads the registry; `from opentide import Opentide` still works and loads it then. Output, help text and JSON are unchanged.
- **Long runs show their steps.** `generate` (every phase and subcommand), `validate query`, and the promotion and deploy steps of `deploy` print one line per finished step in a pipe or in CI (`✓ schemas · 6 files · 2.6s · .opentide/schemas/`) and a live checklist with a spinner at a terminal. They replace the `== Section ==` headers, which engine modules no longer print. `--quiet` and `--json` show no steps; the JSON document carries them under `steps`.
- **Shell completion completes values, and installs with an outcome line.** Tab after `--uuid`, `--file`, `--type`, `--technique`, `--platform` (enabled platforms first) or `--strategy` offers values from the workspace, with names and titles beside them. Completing a value never loads the command or the engine (about 0.2 s, the same as a command name). `opentide --install-completion` prints `✓ Installed zsh completion in ~/.zfunc/_opentide` and the command that loads it; `--install-completion zsh` and `--show-completion zsh` take the shell named after them, and any other word is a usage error naming the shells. `opentide completion` points at both options.
- **Long runs show progress in the tab or taskbar** (OSC 9;4) in Windows Terminal, WezTerm, kitty, Ghostty 1.2 or later and iTerm2 3.6.6 or later, cleared on exit and on Ctrl-C. `OPENTIDE_PROGRESS=0` turns it off, `OPENTIDE_PROGRESS=1` sends it to any terminal.
- **Outcome lines carry counts.** `✓ Generated 21 files in 5.8s · 6 phases`, `✓ Imported 14 rules from sentinel · 2 skipped`, `✓ Shared 4 objects to misp-prod · 3 new, 1 updated`, `! 5 rules unreviewed for 90 days` (`Skipped: No rules yet` on an empty catalogue), `✓ 12 queries valid on 2 tenants` (`validate query --live`), `Would move 3 folders · pass --apply to migrate`, `Would share …` (dry runs take no `✓`), `✓ Moved 6 vendor ids to .opentide/states/deployment/ · …`. The JSON `message` reads the same, and `summary` holds the numbers. Scripts that matched `Full generation pipeline completed`, `Deployment completed`, `Setup complete`, `Share finished: …` or `Listed N unreviewed rules` should read `ok`, `status` and `summary` from `--json`.
- **`deploy --dry-run` prints a plan**: each rule on each tenant with `+ create`, `~ update`, `- disable` or `× delete`, then `Plan: 1 to create, 0 to update, 0 to disable, 0 to delete`; the platforms and tenants it covers are on the plan's header. A rule that would fail to deploy prints above the tally as `error[compile_missing_field]: configurations.sentinel.grouping is missing`, its file and a `help:` line, instead of a raw Python error such as `AttributeError: 'NoneType' object has no attribute 'alert_severity'` (an empty `response:` block); `--json` lists them under `diagnostics`. The tally never takes `error:`; the exit code carries the failure. A dry run reports an unset `$VARIABLE` as `warning: a real deploy would need $…`, not as an error. Sentinel, Splunk, Elastic, Carbon Black and HarfangLab write a rule by its UUID, so their rows say `create or update` rather than guess. A real run ends with `✓ Deployed 3 rules to 2 tenants · 1 created, 2 updated · 12.4s`. `--json` adds `changes` (one entry per rule and tenant) and the tally in `summary`.
- **`setup` has a welcome, a summary and next steps.** The interactive wizard opens with the opentide logo and the tagline, prompts in the brand style, and refuses an empty repository name on the row below the field. The setup plan it confirms names each choice as the prompts did (`GitHub Actions`, `VS Code`, `none`) and the folder relative to where you are; setting up the current folder ends with `✓ Created … here`. Ctrl-C prints one line. Without a terminal, or under a coding agent, every `setup` command exits `2` naming its flags (`--platform, --ci`). Every `setup` command lists what it wrote, prints its warnings once before the outcome line (`✓ Created Tutorial Detections in ./tutorial-detections`, `✓ Wrote .github/workflows/opentide.yml`) and numbers the next steps. The "no default branch" warning is no longer printed twice.
- **A bare `opentide` at a terminal shows a home screen**: the icon, the tagline, the workspace and its git state, catalogue counts, schema health, enabled platforms, and up to three next steps. The workspace shows relative to the current directory (`.` at its root), and a narrow terminal drops the step descriptions rather than wrap them. In a pipe, in CI, under an agent or with `NO_COLOR` it prints the help, as before.
- **Help is grouped and shorter.** `opentide --help` lists commands under Author, Ship, Workspace, and Agents and integrations, carries the tagline instead of "DetectionOps Engine", and every command's help ends with examples. Summaries are at most 60 characters. `--platform` shows `PLATFORM` and lists its values instead of eight names run together, and `--proxy` no longer shows a stray backslash. Every option has help text, examples are single-spaced, and help ends with one newline. `info` lists each platform as `enabled · deploy, validate` instead of `enabled=True [deploy, validate]`.
- **"MDR" is gone from what people read.** `TideMDRDataModelErrors` is now `TideRuleDataModelErrors`; the old name still works in `except` clauses, and error messages carry the new one. VS Code platform snippets are titled `Platform configuration : Microsoft Sentinel Template` instead of `MDR Systems Deployment : …`; their prefixes (`tide-sentinel`, …) are unchanged. Log events say `rule` (`rule_skipped_for_strategy`, `rule_promoted`, …, was `mdr_…`), generated docs head the section `Signal rule coverage`, and the ATT&CK Navigator legend reads `Rule Only - Needs to be checked`. Configuration keys (`mdr_test_uuids`) are unchanged; the `MDR Alert Severity` vocabulary keeps the name the specifications repository gives it.
- **A rule's `severity` uses the alert labels, `Informational` to `Critical`.** Rule `severity` was pinned to `severity::1.0`, the Threat Severity incident scale (*Localised incident* … *National cyber emergency*). That contradicted the rule spec, its examples and opentide's own default, `Informational`, which therefore failed validation. Rules now use `alert_severity::1.0`, the same labels as `response.alert_severity`; threats keep the incident scale ([specifications#60](https://github.com/opentidehq/specifications/pull/60)). **Action:** a rule whose top-level `severity` is an incident-scale value now fails `validate`. Replace it with an alert label (for example `Substantial incident` → `High`), then run `opentide generate` to refresh schemas and templates.
- **The docs flavor adapts to where the docs are read.** Without `--flavor`, `generate docs` uses the CI platform running the job (`GITHUB_ACTIONS`, `GITLAB_CI`, `TF_BUILD`), then the host of the repository's `origin` remote (Azure DevOps over HTTPS or SSH included), so a local run renders what CI would, then `[flavor] default` (CommonMark `generic`). Any CI that sets only `CI` (Jenkins, CircleCI) used to get the GitLab flavor; it now follows the remote or the default.
- opentide describes itself as "spec-driven development for agentic detection engineering" instead of "DetectionOps engine", in the PyPI description, the README and the documentation.
- The bundled skill pack `detection-ops` is now `detection-workflow`, and its skill is named `opentide-detection-workflow` instead of `opentide-detection-ops`. Its platform table now lists Elastic. `copy_skill_pack("detection-ops", …)` still copies it. `opentide setup skills` never installed this pack, so repositories set up with it have nothing to change; for copies made by hand, see [Client migration](https://opentide.org/docs/usage/migration/#skill-pack-detection-ops-renamed).
- **Completing an option or subcommand name loads no engine module.** `opentide validate --<TAB>`, `opentide setup <TAB>` and the rest answer in about 0.3 s instead of 0.6 s, and `opentide validate --help` takes 0.33 s instead of 0.6 s: commands import their services when they run, not when they load.
- **`opentide tui` prints results as the commands do**: `validate`'s code frames and counted outcome line, and a dry run's plan view, with next steps as a person types them.
- **A deploy dry run prints a rule it cannot compile as a code frame** (`error[compile_…]`, `╭─▶ path`, `╰─ help:`), like `validate` and `lint`; an object file it cannot read is reported once, as that frame or as one warning, never also as a log line.
- **MCP `validation_report` and `validate_rule` re-run with `--fix`** when a finding has a safe fix: the last `next_actions` step is `opentide --json validate --fix …`.
- **`opentide explain` covers every code**: the 16 `doctor` checks, the `compile_*` codes, `placeholder`, `internal`, and the `new`, `doctor` and `tui` failure codes.
- **A crash under `--json` prints compact JSON in a pipe** and honours `OPENTIDE_JSON_INDENT`, like every other document.

### Deprecated

- `opentide.core.logging.print_banner()` (also `opentide.cli.print_banner`) warns with a `DeprecationWarning`, draws the new icon and returns it with the tagline as text. It will be removed in a later release.

### Removed

- `coretide-logo.png` from the repository root.

### Fixed

- **A rule without platform blocks failed every deploy.** `opentide new rule` without `--platform` writes `configurations:` holding only a comment, which validates; `deploy` (and the status promotion of a `RELEASE` run) then stopped on it with `'NoneType' object is not iterable`, deploying none of the other rules. A rule whose `configurations` is empty or absent is now skipped, like a rule for a platform the workspace has not enabled.
- **Object files in subfolders were still indexed, validated, documented and shared.** Workspace 1.3 defines an object as a YAML file placed directly in its family folder; `objects/rules/team/x.yaml` is not one. `deploy` and `share push --changed` already skipped such files, but the registry walked every subfolder, so `validate`, `lint`, docs, exports, `rules unreviewed` and a full `share push` treated them as objects, and a full push could publish a file `deploy` refused. One helper now defines the catalogue as the `.yaml`/`.yml` files directly in each configured object folder, for all of them. A file in a subfolder is reported once as a `nested_object_file` warning naming its path (in `validate`'s report, `lint`'s findings and the `warnings` of `share`, docs and exports), and `--file` naming it fails with `scope_no_match`. `validate --strict` fails on that warning: move the file up into its folder. Suffixes match as `deploy` spells them (`.yaml`, `.yml`), so `r.YAML` is not an object anywhere ([#584](https://github.com/opentidehq/opentide/issues/584)).
- **A rule promoted by the production deploy was not shared until it changed again** ([#590](https://github.com/opentidehq/opentide/issues/590)). The generated share job ran beside the production deploy on the triggering commit, before promotion rewrote block statuses, so the rule was `skipped_status`; the `[skip ci]` write-back that promoted it was in no later `--changed` diff. The share job now runs after the production job (GitHub `needs: [generate, deploy_production]`, GitLab stage `share` after `deploy`, Azure stage `Share` with `dependsOn: [Generate, Deploy]`) and checks out the default branch's tip. It runs after a failed or no-op deploy too, but not after a failed generate or a cancel; GitLab, which cannot express that, runs it `when: always` behind `opentide validate --strict`.
- `share push --changed` diffs from the triggering push's baseline (the triggering commit's first parent, or GitLab's `CI_COMMIT_BEFORE_SHA`) to the checkout's `HEAD`, so on the tip it covers both the push and the promotion write-back. In a checkout of the triggering commit nothing changes.
- **A signal's authored `parent` was overwritten by its objective.** `objective-1.0` defines `signals[].parent` as a parent *signal* UUID, but indexing (and the inflight overlay) replaced it with the UUID of the objective the signal is defined in. The indexed signal now keeps `parent` as written and records the objective as `owner`. Coverage and relation walks (`parents`/`childs`, documentation coverage graphs, explorer export, preflight) follow `owner` for the objective → signal hop. Code reading `Opentide.Signals[uuid]["parent"]` for the objective should read `owner`; `SignalRecord.parent_uuid`/`parent_name` are now `owner_uuid`/`owner_name`.
- **Two signals sharing a UUID: the index kept the last one.** It now keeps the first definition, including for a UUID repeated within one objective; `opentide validate` reports the clash as `duplicate_id` on the signal.
- **An inflight preview kept signals its objective no longer defined.** When a shard replaced an objective, signals the shard had removed stayed in the index under that objective, and a signal moved to another objective in the same change stayed on the old one. The overlay now re-indexes the signals of every objective it replaces.
- **An empty Elastic duration passed validate and crashed compile.** `""` for `scheduling.interval`, `suppression.duration` or `new_terms.history_window_start` skipped the duration check; it now reports `duration` at validate time, as `scheduling.lookback` already did. A threshold rule's empty `suppression.duration` reports `duration` too (a missing one is still `suppression_shape`). A `scheduling` that is not an object is reported as a `scheduling` shape error instead of `duration` ([#589](https://github.com/opentidehq/opentide/issues/589)).
- **Elastic durations accepted non-ASCII digits.** `５m` or `PT١H` parsed as five minutes and one hour; Elastic durations now take ASCII digits `0-9` only and report `duration` otherwise ([#589](https://github.com/opentidehq/opentide/issues/589)).
- **An Elastic tenant `api_key` only had to start with `$`.** `$`, `$1KEY` or `$ELASTIC KEY` loaded and never resolved. The key must be `$VAR` or `${VAR}`; anything else, a literal key included, fails the config load. `${VAR}` now resolves like `$VAR` ([#589](https://github.com/opentidehq/opentide/issues/589)).
- **Object files a person can save by mistake no longer crash a command.** An empty or comment-only object file, a file saved as Latin-1, an impossible date (`created: 2026-13-45`) and a list where `detection_model` belongs ended in `error[internal]` from `validate`, `lint`, `info`, `deploy --dry-run`, `rules unreviewed` or `share preview`. They are `yaml_parse` (`found an empty file`, `the file is not UTF-8 text (byte 0xe9 at offset 9); save it as UTF-8`, `'2026-13-45' is not a valid date`) or `schema_validation` findings.
- **A read-only workspace is a failure line, not a crash.** `validate --fix` lists the file it could not write; `opentide new` exits `1` with the new `failure.code` `path_not_writable` and points at `opentide explain path_not_writable`.
- **A `--repo` that does not exist exits `2`** (`usage_invalid_value`) instead of passing as an empty catalogue, which turned a CI job with a typo green; it points at `opentide --help`. `setup` may still name a folder it is about to create.
- **`deploy` counts the rules a status kept out** (`Skipped: No rule has a status PREVIEW deploys · 4 rules in DESIGN`, with the statuses that would deploy as `help:`, or a `note:` under a plan's tally) instead of one `warning: Rule skipped for strategy · system: … deployed_by: no run` log line per platform block. JSON gains `skipped` and `summary.skipped`; the log lines remain under `--debug`.
- **A rule that would fail to compile is not planned as a create.** Its row reads `✗ would fail`, the tally counts it apart (`1 would fail`), and JSON marks the change `"fails": true` and counts `summary.fail`. Compile frames quote names (`'response'`) instead of printing Markdown code spans.
- **A misspelled `enabled` key in a platform file is named** (`sentinel.toml sets 'enabeld' in [platform], not 'enabled'`) instead of the warning sending you to `opentide setup platforms`.
- **`validate` is 3-4 times faster on a large catalogue** (306 objects: 8-12 s → 2-3 s): an object with no finding is no longer parsed again to place findings it does not have. A transient `Validating objects` spinner shows meanwhile at a terminal.
- **A duplicate UUID is framed at the value**: `UUID … is also used by 'Other rule'`, the frame under the UUID, an `also:` note with the other file's line and column, and help that does not guess which file is the copy.
- **Every frame ends in a step to take**: a YAML syntax error, a missing field and a disabled platform's block had none. A file that does not parse gets the step that fits it (an empty file, an impossible date, a file that is not UTF-8), and one step only.
- **`generate` reports an object that does not validate in one line** (`'LSASS access on splunk' does not validate: description: field required; opentide validate shows each finding`) instead of Pydantic's report with the internal model name and an errors.pydantic.dev link.
- **`share preview` and `share targets` print plan rows**, by object name, with the actions a preview would take (`+ create`, `○ skip` and a short reason such as `status not shared`) instead of a table of raw records that said `created` for a dry run; with no target configured they say which file to write.
- **The crash help line is a short, clickable link** at a terminal instead of an 800-character pre-filled URL.
- **Outside a workspace**, `validate`, `lint` and `deploy --dry-run` end with `→ opentide setup`; a bare `opentide` prints the help and exits `0` in every mode; the home screen suggests `opentide new threat` for an empty catalogue instead of a deploy.
- **Help screens**: `PLATFORM`, `PROVIDER` and `CHECK` metavars instead of choice lists broken mid-word, no reStructuredText backticks, and summaries without trailing periods. `--platform defender` suggests `defender_for_endpoint` and `--format gitlab` suggests `codequality`.
- **Warning, error, help, outcome and next-step lines, plan and share rows, `opentide explain` and doctor checks wider than the terminal wrap between words**, continued under their text like a code frame's message, instead of the terminal breaking `$SPLUNK_TOKEN` or `Permission denied` mid-word at 100 columns. A path wider than the row is never split, and a pipe or CI log keeps one line.
- **Smaller wording fixes**: the setup warning outside a git repository says how to start one; `new` prints one line for the optional metadata it left out, and the wizard says the organisation goes in the README; deprecations are `warning:` lines; `info` prints label and value columns instead of a boxed Key/Value table; `lint` with notes alone ends on `✓ 6 notes in 6 files`; more than three unset variables are counted; the TUI's status line says the counted outcome; the agent `tip:` comes after the next steps; `setup skills discover` lists slugs and `show` prints a skill once with its install step; the `new rule` platform prompt has one key hint; an underline label that would pass the terminal edge moves below it, and the `--watch` view wraps frames as `validate` does.
- **`invalid_uuid`, `missing_uuid` and `duplicate_id` frames end in a step to take** (`╰─ help: replace it with a UUID v4: …`); they had no help line.
- **`opentide lint` prints a placeholder's help line** in its code frame, and `opentide explain placeholder` has a page.
- **`opentide --json commands` lists `OPENTIDE_PROGRESS`** under `environment`.
- **Elastic ES|QL and EQL checks read past comments and strings** ([#616](https://github.com/opentidehq/opentide/issues/616)). The ES|QL pre-flight now takes its index sources from the `FROM`/`TS` command alone: a comment before `FROM`, a leading `SET …;`, a `FROM` subquery, or an index pattern containing `metadata` (`logs-metadata-*`) no longer makes it check the wrong indices. The validation warnings changed with it: `METADATA _id` written only in a comment or string no longer counts, `INLINE STATS` no longer makes a query aggregating (as in Kibana), `sequence` in a string no longer makes an EQL query a sequence, and `maxspan=500ms` is 500 milliseconds, not 500 minutes.
- **`ssl = false` was ignored on Elastic when a CA bundle is exported.** With `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` set, as on many corporate hosts and CI runners, `requests` replaces a session's `verify` with the bundle for every request that does not pass its own (psf/requests#3829). Elastic set verification only on its session, so `deploy` and `validate query --live` against a self-signed Kibana failed with `CERTIFICATE_VERIFY_FAILED`; Defender's Graph API fallback and Sentinel's ARM calls had the same gap. Every platform's HTTP session now keeps the tenant's `ssl` for every request; with `ssl = true` an exported bundle is still used.
- **`share retract --type` and `--file` retracted every shared object.** Retract added every UUID in the sharing ledger to its candidates and only `--uuid` narrowed them, so `share retract --type rule --delete --yes` also deleted the threat and objective events. An object still in the repository is now retracted only when the filters select it; a deleted object is matched by `--type` against the schema its ledger line recorded, and never by `--file`.
- **`share push --publish` left an unchanged event unpublished.** After a push without publish, a later `push --publish` saw the same content hash, reported `unchanged`, exited `0` and never published. Push now publishes a matched event that is still unpublished when the run asks for it and reports `updated`; `push --dry-run --publish` predicts the same.
- **Two objects whose names slugify alike shared one docs page.** `Sentinel KQL Rule` and `Sentinel-KQL rule`, or any two names with no ASCII letters (both `object.md`), wrote the same file and both index rows linked to it. The second object's page now gets a `-<uuid[:8]>` suffix; existing page names change only on a collision.
- **`generate docs --changed` deleted pages of objects that still exist, and renames left stale pages.** A moved but unstaged YAML file, or a deleted rule replaced by one with the same name, had its new page unlinked; a renamed object's old page was never removed, and pages under a renamed objective kept linking it. Every docs run now removes the generated pages no object writes any more, leaving `README.md` and hand-written files alone, and `--changed` rewrites the pages that link to a renamed object.
- **Elastic platform configurations were missing from rule pages.** The section walked a hard-coded platform list written before Elastic existed.
- **A `|` or a newline in a name broke Markdown tables.** Rule, signal and author values shifted the columns of the metadata, coverage and index tables. Table cells are now escaped.
- **Signal links on GitHub pages did not jump to the signal.** The anchor collapsed punctuation (`#process-cmd-exe-spawn`) where GitHub ids the heading `process---cmdexe-spawn`. GitHub pages now use GitHub's anchor rule.
- **`generate extract sentinel` wrote unparsable YAML** for rules that group incidents by entities or details, alert titles starting with `{{Column}}`, names containing `"` or `\`, and descriptions or queries whose first line is indented. Values are now written as proper YAML scalars, and each file is parsed before it is written.
- **Imported Defender rules targeted the tenant `PandoraStores`,** a name from the original author's environment. The tenant the rule was listed from is now written.
- **Imported rules with the same display name overwrote each other** on Sentinel and Defender. The second file name now gets the first eight characters of the rule's UUID.
- **A Defender detection deployed to several tenants imported as one file per tenant, all with the same UUID.** It is now one rule whose `tenants` lists every tenant it was found in; a warning names tenants whose copy differs.
- **`generate extract defender` read only the first page of rules and could hang.** The listing now follows `@odata.nextLink`, times out after 60 s per page, and an HTTP error names the tenant and status instead of raising `KeyError`.
- **Imported Elastic rules were marked TLP:CLEAR.** Enabled rules import as PRODUCTION, which `share push` shares by default, so an organisation's private detections would have been published as TLP:CLEAR. They now import as `amber`, as Sentinel's do.
- **Splunk retirements never removed anything.** The request handler built `urllib` requests without a method, so splunklib's DELETE went out as a GET; Splunk answered with the saved search and the run reported it deleted. A lookup that failed for any reason (401, TLS, a refused connection) was also read as "already absent". DELETE is sent as DELETE, and only a missing saved search counts as absent.
- **A Splunk deploy answered with a gateway redirect counted as success.** A `307` on the update request was logged and returned as success; it now fails the deploy.
- **Splunk and Carbon Black deployed every tenant with the first tenant's settings** (Splunk actions, scheduling, skew and offset; the Carbon Black watchlist). Each tenant now uses its own.
- **Carbon Black updates appended a second IOC and retirements removed nothing.** `remove_iocs_by_id` was given a string, which the SDK read as a set of characters. A shared report is now deleted only when no other rule's IOC remains in it.
- **Defender, SentinelOne, CrowdStrike, HarfangLab and Splunk calls had no timeout,** so a tenant that accepted the connection and never answered hung the job until the runner killed it. Every platform session now times out.
- **Defender's minimal-configuration retry posted to the wrong endpoint** and could never succeed; it now retries where the rule is created, and an error body that is not JSON no longer hides the HTTP status.
- **CrowdStrike rejected the `US-GOV-1` API domain** because of a stray colon in the match.
- **SentinelOne sent `cool_off` as the raw string** (`"30m"`) instead of minutes.
- **KQL `let` values with a backslash or quote broke the Sentinel and Defender query** (`C:\Windows\Temp\` escaped the closing quote). String values are now escaped.
- **HarfangLab Sigma rules with `:` or quotes in a title or value were invalid YAML, and a value like `yes` became a boolean.** The rule is now serialised with a YAML dumper.
- **Deploys could ship another open pull request's unreviewed query.** Every registry build applied the inflight preview shards, so deploy and `validate --strict` read a shard of the same or higher version instead of the committed file. Only preview output applies shards now: `generate docs`, the docs SDK's `write_all` and the explorer export.
- **Pull request runs deployed and validated rules the target branch changed.** The diff ran from the merge base to the merge commit GitHub, Azure and GitLab merged-results build; it now starts at the merge commit's first parent. A `pull_request_target` run saw none of the request's changes. Both are fixed; a `pull_request_target` run takes the request's base and head commits from the event payload, so a pull request from a fork no longer needs its branch on `origin`.
- **A push of several commits deployed only the last commit's rules** on GitHub; the diff now starts at the push's `before`.
- **`setup ci github --explorer-pages` could cancel queued production deploys:** `concurrency: group: pages` sat on the whole workflow and Pages permissions on every job. Both are now on the `deploy-explorer` job.
- **Rules saved as `.yml` were never validated** and failed deploy with `KeyError: '<uuid>'`. The registry indexes `.yml` objects.
- **A platform modifier applied when only some of its conditions held** (`tenants` replaced the `status` result, and a `flags` condition was skipped for rules without flags). All set conditions must now hold.
- **`setup hooks` could corrupt an existing `.pre-commit-config.yaml`** in the `pre-commit sample-config` layout or with a top-level key after `repos:`. The hook is inserted after the last repo, and the file is written only if it still parses.
- **Hook scripts were written with CRLF on Windows,** which Git Bash refuses; they are written with LF and re-running setup repairs a broken one.
- **Options typed before a subcommand were silently dropped:** `opentide share --dry-run push` really pushed and `opentide deploy --dry-run migrate-state` rewrote files. They are passed to the subcommand or refused.
- **`DEBUG=*` (the Node convention) made every command exit 2.** `DEBUG` is now read leniently.
- **`setup mcp` overwrote `.mcp.json` and `setup skills` overwrote `AGENTS.md`, `CLAUDE.md` and Copilot instructions.** MCP configs are merged; existing agent entrypoints are kept with a warning.
- **A `TypeError` inside a deployer surfaced as an unrelated "unexpected keyword argument 'deployment'" traceback** with no JSON result. The legacy retry is gone; a platform failure is a failed result naming it.
- **`migrate vocab-scope --apply` rewrote every line ending,** and **`migrate objects` reported success while leaving `Configurations/` behind.** Line endings are kept, and every skipped path is a warning (exit 1 under `--apply`).
- **`setup skills --install X` without a target ignored `--install`, `--all` and `--name`;** **`lint --fix` could not fix a case-only filename on macOS/Windows;** **`rules unreviewed` crashed on one unreadable rule;** **`generate docs --rules --threats` generated only rules;** **`setup --json --no-promotion` reported no platforms;** **`setup skills --all` made one GitHub API call per skill.** All fixed.
- **`validate` crashed on a `threat:` or `objective:` block whose keys are all commented out,** and on a YAML parse error recorded without an object type. Both are now reported as issues.
- **A Defender block without `scope` passed validation, then broke loading of every rule.**
- **The `uuid-format` check accepted any UUID** (v1, v5, nil, braced, unhyphenated). It now requires a hyphenated version-4 UUID.
- **An unreachable CVE lookup passed silently, even with `--strict`.** It is now a `cve_lookup_unavailable` warning.
- **A small YAML file of nested aliases took seconds to minutes to validate, and a recursive alias crashed `validate`.** Parsing is linear and a recursive alias is a YAML error.
- **The MCP `validate_rule` and `validation_report` tools validated the workspace as it was when the server started,** and one rule that failed to load broke `validate_rule` for all. They now reload and look rules up individually.
- **`validate_all_objects(objects_index)` and `DetectionRule.validate_query` in the SDK ignored their input / always returned `ok=True`.**
- **`DetectionRule.validate_query()` in the SDK raised `TypeError` or checked nothing.** It called the platform validator without run strategies, which most validators require; without them no tenant is targeted. It now validates this rule object (an edited or unregistered rule used to be looked up again by UUID) against the strategies the CLI uses by default.
- **A Carbon Black org without any watchlist failed with `AttributeError`** instead of the "nonexistent Watchlist" error that names the watchlist to create.
- **Defender's deployer rejected rule objects and its validator an empty selection** (SDK callers). Both now accept rules as objects or UUIDs, like the other platforms.
- **A rule without a `configurations` block failed deep in a deployer with `'NoneType' object has no attribute …`.** The error now names the rule.
- **Generated schemas:** the visibility configuration schema rejected every valid configuration; a misspelled rule tenant passed and deployed nowhere (tenants are now an enum of the configured ones); a Splunk rule from the shipped template was flagged for missing `scheduling`; `metadata.tlp` ignored its vocabulary pin; a scoped vocabulary entry without stages crashed generation.
- **ATT&CK groups present in several domains kept the Mobile entry** (`G0007` read `[Mobile] APT28`); the generator now keeps the Enterprise one. The bundled vocabulary is regenerated upstream in `opentidehq/specifications`.

### Install

```bash
pip install opentide==0.18.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.17.2] — 2026-10-22

Patch release. Nothing to regenerate. A `uv` install resolves a current boto3 again (python-dateutil 3.0.0 had sent it back to a 2014 release that cannot import). A Splunk tenant reached through a proxy that answers with its own HTML page now fails with a message naming the proxy and the `NO_PROXY` value to set, instead of `xml.etree.ElementTree.ParseError: mismatched tag`. If your pipeline replaces opentide's Splunk handler with `verify=not ssl_enabled`, delete that step and list the Splunk host in `NO_PROXY` and `no_proxy`: the patch works only by skipping the proxy, and with `ssl = false` it turns certificate verification on.

### Fixed

- **A proxy's HTML page read as a Splunk TLS failure.** When `HTTPS_PROXY` or `OPENTIDE_PROXY` sends an internal Splunk tenant through a TLS-inspecting proxy, the proxy answers with its own page. With `ssl = false` the proxy's certificate is accepted, and splunklib failed to parse the page as XML with `ParseError: mismatched tag`, which read as a certificate fault; 0.17.1's notes repeated that reading. Splunk's REST API never answers with HTML, so the client now raises `SplunkAnsweredHtmlError` (a `ConnectionError`; `validate query --live` reports it as the tenant's result). The message names the address, the page title and the proxy (without credentials), and gives the `NO_PROXY` entry to add. Without a proxy it points at the port: 8089 is the REST API, 8000 Splunk Web.
- Each Splunk connection logs `splunk_tenant_route` with `via` set to the proxy it goes through, or `direct`.
- **A `uv` install of opentide could not import the Carbon Black SDK.** python-dateutil 3.0.0 came out on 21 October. botocore caps it below 3, and `uv`'s resolver chose dateutil 3 and walked boto3 back to `0.0.3`, whose botocore fails on `from six.moves import configparser`. Carbon Black deploys and live query checks, and anything importing `cbc_sdk`, failed. opentide now requires `boto3>=1.35`, so the resolver keeps a current boto3 and caps python-dateutil. `pip` was not affected. Until you upgrade, `uv pip install opentide==0.17.1 'boto3>=1.35'` works around it.
- The troubleshooting entry for 0.17.0's `ssl = false` bug said that it often failed with an XML `ParseError`. It failed with `CERTIFICATE_VERIFY_FAILED`; a `ParseError` means an HTML answer.

### Install

```bash
pip install opentide==0.17.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.17.1] — 2026-10-21

Patch release. Nothing to regenerate. A tenant's `ssl` now decides certificate verification for every call opentide makes to that tenant, on every platform. Splunk deploys and live query checks work again against a tenant with `ssl = false` (a self-signed certificate), and Splunk rules with a `trigger` block deploy. If your pipeline patches the installed `opentide/platforms/splunk/client.py` or `deployer.py` with `sed` to work around either bug, delete those steps: after upgrading their patterns match nothing. A patch, not a minor: each fix restores what the configuration already documented, and the stricter `ssl` check only refuses values that never worked.

### Fixed

- **A Splunk tenant with `ssl = false` still verified the certificate.** The tenant's `ssl` reached the HTTP handler through the `TIDE_SPLUNK_SSL_ENABLED` environment variable, which held the string `"False"`, and the handler tested the string, which is true. Against a Splunk with a self-signed certificate, every `deploy` and `validate query --live` failed on the TLS handshake, often reported as an XML `ParseError`. Each connection now carries its own tenant's `ssl`, so two tenants with different settings in one run each get their own. `TIDE_SPLUNK_SSL_ENABLED` is no longer read or written. `TIDE_SPLUNK_PLUGIN_ALLOW_HTTP_ERRORS` is gone the same way: once a live query check had set it, a later deploy in the same process stopped raising on HTTP errors.
- **Splunk rules with a `trigger` block failed to deploy** with `HTTP 400 Bad Request -- Argument "quantity" is not supported by this handler.` The deployer sent the `savedsearches.conf` names `counttype`, `relation` and `quantity`, which the `saved/searches` REST endpoint refuses. `trigger.condition`, `comparator` and `threshold` now deploy as `alert_type`, `alert_comparator` and `alert_threshold`, the names the bundled `splunk.toml` defaults already used.
- **Defender for Endpoint and Sentinel ignored `ssl = false` for part of their traffic.** Defender requested its Entra ID token, and deployed through the Graph API fallback for a custom detection, with verification always on. Sentinel's Entra ID token request (deploy and live query check) always verified too. Behind a TLS-inspecting proxy that is what failed first. Both now apply the tenant's `ssl` to every request, the token request included.
- **An unset `ssl = "$VAR"` failed with an unrelated error.** On every platform but Splunk, the literal `$VAR` reached the HTTP client as the path of a CA bundle, and the call failed with `Could not find a suitable TLS CA certificate bundle`. Every platform now refuses it before the first request and names the tenant and the variable: `crowdstrike tenant 'Primary' setup: ssl is unset ($CROWDSTRIKE_SSL)`.
- **A refused Splunk request lost Splunk's reason.** The handler read the error body into the log, then gave splunklib an empty one, so the raised error read `HTTP 400 Bad Request -- b''`. The error now carries Splunk's message.
- **A tenant's `ssl` must be a boolean.** `ssl = "$SPLUNK_SSL"` resolves to the variable's text, and the text `false` verified the certificate too. `true`/`false`, `yes`/`no`, `on`/`off` and `1`/`0` (any case) now read as booleans on every platform. Any other value fails to load and names the tenant: `splunk tenant 'Primary' setup: ssl must be true or false, got 'sometimes'`.
- Carbon Black no longer logs `ssl_has_been_set_to` with the first tenant's value, which read as if it applied to every tenant; each tenant's `ssl` is passed to the SDK, as before.

### Install

```bash
pip install opentide==0.17.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.17.0] — 2026-10-20

Minor release with **breaking changes**: deployment plans are removed. A deploy now names the status strategy it carries out, and a tenant lists the strategies it accepts. Three things need action after upgrading; each old setting fails with a message naming its replacement.
- **Replace `--plan` and unset `DEPLOYMENT_PLAN`.** `--plan STAGING` becomes `--strategy PREVIEW`, `--plan PRODUCTION` becomes `--strategy RELEASE`, and `--plan FULL` (or no plan) becomes `--strategy PREVIEW --strategy RELEASE --all`.
- **Replace each tenant's `deployment` key** in `.opentide/configurations/platforms/*.toml`: `"STAGING"` becomes `strategies = ["PREVIEW"]`, `"PRODUCTION"` becomes `strategies = ["RELEASE"]`, `"ALWAYS"` is removed, and `"MANUAL"` becomes `manual = true`.
- **Regenerate generated pipelines** with `opentide setup ci <github|gitlab|azure> --yes`. Deploy jobs then pass `--strategy`, live query validation checks only the rules each run changed, and GitLab merge request pipelines start at all.

Run `opentide generate` to refresh the editor schemas' objective and signal labels; the vocabulary warnings stop either way.

### Breaking

- **Rust is opentide's only engine: the Python implementation, and `OPENTIDE_ENGINE`, are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)). Every command, `opentide serve`, `opentide mcp start`, `opentide tui` and `opentide lsp start` run on the Rust core compiled into the package; the console script (`opentide._cli:main`) hands it the arguments in process. `OPENTIDE_ENGINE` is no longer read: `python` no longer runs the Python command line, MCP server or Textual UI, and `compare` no longer runs both implementations. The `engine_not_ported` and `engine_mismatch` failure codes, exit code `70` and their `opentide explain` pages are gone, and `opentide --json commands` no longer lists the variable. When the compiled core does not load, the console script prints `error: The opentide analysis engine does not load: …` with the reinstall command on stderr and exits `1`, where the Python command line answered the commands that do not need it.
- **The deprecated SDK entry points are removed, with no shims** ([#841](https://github.com/opentidehq/opentide/issues/841)): `Opentide.initialise()` and the registry (`from opentide import Opentide`, `OpenTide`, `Opentide.Rules`, `Objectives`, `Threats`, `Index`, `Platforms`, `render_rule`, `validate_rule`), `opentide.validation.session.run_validation` and `ValidationScope`, and the documentation writers (`opentide.documentation.write_all`, `write_rules`, `write_objectives`, `write_threats`, `run`, `render_rule`, `render_objective`, `render_threat`). Each has an `opentide.Workspace` equivalent (Upgrade; [migration](docs/sdk/migration.md)).
- **opentide's undocumented internals are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)): `opentide.cli` (and its services), `opentide.core`, `opentide.platforms`, `opentide.deployment`, `opentide.states`, `opentide.validation`, `opentide.loading`, `opentide.registry`, `opentide.indexing`, `opentide.generation`, `opentide.documentation`, `opentide.export`, `opentide.extraction`, `opentide.ci`, `opentide.sharing`, `opentide.query`, `opentide.mcp_server`, `opentide.vocabulary`, `opentide.mutation`, `opentide.schemas` (its Python modules; the bundled data stays) and `opentide.vulnerability_lookup`. `opentide.models` keeps the Rust classes alone: the Pydantic package behind it (`opentide._models`), the Pydantic machinery (`TideModel`, `TideField`, `TideRegistry`), the result models and constants (`ValidationResult`, `DeploymentResult`, `RULE`, `CORE_OBJECT_TYPES`, `EnumRegistry`, `SchemaVersion`, …), the submodules it aliased (`opentide.models.results`, `.configuration`, …) and `opentide.models.delegation` are gone. `opentide.analysis` keeps `check_query`, `highlight`, `describe`, `engine_codes`, `engine_versions` and `EngineUnavailableError`; `check_queries` and the catalog helpers are gone. The package keeps the console script, the SDK (`opentide.Workspace`, `run_json`, `Connection`, `OpentideError`), `opentide.models`, the plugin API (`opentide.plugins`) and the native binding; a plugin that uses only `opentide.plugins` keeps working. The built-in platforms no longer register `opentide.platforms` entry points.
- **opentide no longer depends on the Python implementation's libraries** ([#841](https://github.com/opentidehq/opentide/issues/841)): `typer`, `rich`, `textual`, `questionary`, `structlog`, `ruamel.yaml`, `pyyaml`, `orjson`, `tomli-w`, `dulwich`, `platformdirs`, `requests`, `mcp`, `pymisp`, `azure-identity`, `azure-monitor-query`, `splunk-sdk`, `carbon-black-cloud-sdk` and `boto3` are no longer installed with it. `pydantic` stays, for the plugin API's `configuration_model`. Code that imported one of them through opentide's install declares it itself.
- **`opentide query --rule` and `--file` on a platform plugin are a usage error** ([#835](https://github.com/opentidehq/opentide/issues/835)): `usage_invalid_value`, exit `2`, naming the option, where they were refused as not ported. A plugin's block is the plugin's to read: give its query as `QUERY` or `--query-file`.
- **A status promotion that cannot rewrite the push fails the deploy** ([#841](https://github.com/opentidehq/opentide/issues/841)): no promotion target, a platform key that is not a string, or promoted text that does not read back fails the run before anything is written (exit `1`, `--skip-promotion` named), where it was refused as not ported (`engine_not_ported`, exit `2`).
- **`opentide deploy --strategy` replaces `--plan`.** A run deploys the rule files it changed whose status maps to its strategy, to the tenants that accept that strategy. `--strategy PREVIEW` deploys rules whose status maps to `PREVIEW` or `UNIVERSAL`. `--strategy RELEASE` deploys rules mapping to `RELEASE` or `UNIVERSAL`, and disables or deletes those mapping to `DISABLEMENT` or `DELETION`. The option is required and repeatable, and takes only `PREVIEW` and `RELEASE`. A status name such as `STAGING` is refused with the strategy it maps to in your configuration. Plans named a pipeline with the same words as two default statuses, which read as if `STAGING` and `PRODUCTION` were canonical statuses. They are not: they are two of the default statuses, and only the strategy a status maps to decides anything.
- **Which rule files a deploy reads follows the CI context.** In a pull or merge request pipeline, deploy reads the files changed since the merge base. In any other CI run, it reads those the push changed. Outside CI, it reads those the last commit changed; it used to read every rule file. `--all` reads every rule file. Without `--all`, rules that map to `DISABLEMENT` or `DELETION` are included (`--drop-deprecated` leaves them out); with `--all` they are left out (`--keep-deprecated` includes them).
- **Tenants declare `strategies`** (`PREVIEW`, `RELEASE`, or both when omitted) and optionally `manual = true` (only rules that list the tenant). The `deployment` key fails to load and names the replacement line.
- **`--plan` and `DEPLOYMENT_PLAN` are removed.** `--plan`, or `deploy` and `validate query --live` with `DEPLOYMENT_PLAN` set, exits `2` and names the `--strategy` to pass. Generated inflight jobs no longer export `DEPLOYMENT_PLAN`.
- **`validate query --live` checks each rule on the tenants a deploy sends it to.** Before, a run without `--plan` reached every tenant. Now a `PREVIEW` rule is not checked on a tenant that only accepts `RELEASE`; the pull request that moves it to a `RELEASE` status checks it there. `--strategy` narrows the check. `--json` reports `strategies` instead of `plan`.
- **SDK and deployer API.** `DeploymentStrategy` is removed. Deployers and validators take `strategies` (a tuple of `StatusStrategy`) instead of `deployment_plan`. `rule.deploy(platform, dry_run=False, *, strategies=None)` deploys a rule by the runs its own status needs when `strategies` is omitted.
- The `mdr_skipped_for_plan` log event is now `rule_skipped_for_strategy`, with the rule's `strategy`, the run's `run_strategies`, and `deployed_by`. `adding_tenant` and `skipping_tenant` name the rule strategy, the tenant's strategies and the run's.

### Added

- **[Statuses, strategies and tenants](https://opentide.org/docs/usage/concepts/statuses-and-strategies/)**: a page on how a status maps to a strategy, which runs deploy which strategies, which tenants accept them, and how promotion interacts. It includes worked examples and a migration table from plans.
- **`deploy --dry-run --json` lists the tenants** each platform's rules would reach (`tenants`), and every deploy result names its `strategies`.
- **`opentide validate query --changed`** checks only the rule files a deploy of the same run reads: the pull or merge request's diff, the push's, or outside CI the last commit's. `--json` reports `"scope": "changed"`.
- **`opentide validate query --file` and `--uuid`** (repeatable) check only the selected rules. A target that selects no rule file directly in the rules folder fails with exit `1` and is listed under `unmatched`, before any query is sent. `--json` reports `"scope": "selected"`.
- **`OPENTIDE_PROXY`** sets the global `--proxy` when the flag is omitted, so a CI/CD variable can send opentide's platform calls through a proxy without editing the generated pipeline. Hosts in `NO_PROXY` are still reached directly, with or without `--proxy`: one deploy reaches a cloud tenant through the proxy and an internal Splunk directly, with no per-platform job.

### Changed

- Generated pipelines run `opentide deploy --strategy PREVIEW` in the pull or merge request job and `opentide deploy --strategy RELEASE` in the default-branch job. The job ids (`deploy_staging`, `deploy_production`) are unchanged. The CI/CD guide's hand-written pipelines match; they used to run `DEPLOYMENT_PLAN: staging` on pushes to `main`, which has no pull request to diff.
- The CI/CD guide covers pipelines behind a proxy or a private CA: which proxy variables `pip`, `apt-get`, `git` and opentide read (set both spellings), `NO_PROXY` for internal tenants, and the CA bundle variables to use instead of `GIT_SSL_NO_VERIFY`. The global options page lists `--proxy`.
- `--wide` is documented as what it does: ignore the strategy filter, not widen the output.

### Fixed

- **Generated pipelines checked every rule's query on every run.** The live query step ran `opentide validate query --platform <p> --live` with no scope, so a pull request that edited one rule sent the whole catalogue to the tenant; a catalogue of a few hundred Splunk rules took most of an hour. It now passes `--changed`, and the jobs that run it fetch full history (GitHub `fetch-depth: 0`, GitLab `GIT_DEPTH: "0"`, Azure `fetchDepth: 0`).
- **Generated GitLab pipelines could not start a merge request pipeline.** A GitLab job with no `rules` defaults to `except: merge_requests`, so the merge request pipeline held only `deploy_staging` and `inflight_shards`, whose `needs: generate` named a job that was not added: GitLab refused the pipeline, the staging deploy and the inflight shards never ran, and every push to the branch also ran a branch pipeline. The file now sets `workflow:rules` for merge request and default-branch pipelines, so every job runs in a merge request pipeline and one push starts one pipeline. A push to a branch that has no merge request yet starts no pipeline; open a (draft) merge request to validate it, as GitHub validates pull requests.
- **`opentide generate` logged a vocabulary warning per objective.** The editor schemas describe each objective with its priority, and looked that value up in the `criticality` vocabulary for an icon: `High` logged `Vocab parameter not found` (no vocabulary defines `icon`) and `Critical` logged `Vocab identifier not found` (an objective's `priority` is free text, commonly an `alert_severity` value, not a `criticality` one). The description prints the value as authored, labelled **Priority** for an objective, **Severity** for a signal and **Criticality** for a threat, with no lookup. Regenerate schemas with `opentide generate` to update the labels.
- `--proxy` (and now `OPENTIDE_PROXY`) also sets the lowercase `http_proxy` and `https_proxy`. Python's HTTP clients prefer the lowercase spelling, so an inherited `http_proxy` used to win over the flag.
- A GitHub pull request diff from a fork, whose head branch is not on origin, takes the request's base from the merge ref's two parents instead of failing with `Could not find git ref origin/<branch>`. This applies to `deploy` and `validate query --changed`.
- A GitLab push diff with no previous tip (`CI_COMMIT_BEFORE_SHA` all zeros, as on a branch's first push, a manual run or a schedule) diffs from HEAD's first parent, as on GitHub and Azure, instead of failing with `No Source Commit Found`.

### Install

```bash
pip install opentide==0.17.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup ci <github|gitlab|azure> --yes
opentide validate --strict
```

## [0.16.1] — 2026-10-20

Patch release. Nothing to regenerate and nothing to do after upgrading: the SDK class is renamed `Opentide` with the old spelling kept as a deprecated alias.

### Changed

- **The SDK class names lose their second capital.** `Opentide` (the registry singleton) and `OpentideRegistry` replace `OpenTide` and `OpenTideRegistry`. `from opentide import OpenTide`, `opentide.core.OpenTide` and `opentide.core.registry.OpenTide` / `OpenTideRegistry` still import and return the same objects, and raise a `DeprecationWarning`; the old spelling goes in a later release. Docs and snippets use `Opentide`.
- The project is spelled `opentide`, lowercase, across the CLI help, docs, generated pipelines (`name: opentide`, `opentidehq` as the GitHub owner) and the MCP server name (`opentide`, was `OpenTide`). The `OPENTIDE_*` environment variables and the Elastic rule tag `OpenTide` are unchanged.

### Fixed

- `opentide setup skills` accepts the catalogue manifest's `source` in any letter case. GitHub names are case-insensitive, and a manifest that spelled itself `OpenTideHQ/skills` logged `Skills manifest source rejected` on every run, although the fallback installed the same catalogue.

### Install

```bash
pip install opentide==0.16.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.16.0] — 2026-10-19

Minor release: `pip install opentide` is the only install, and two things need action after upgrading.
- **Regenerate generated pipelines** with `opentide setup ci <provider> --yes`. They now take tenant configuration from the default branch before credentialed jobs (security), and an install with no extras validates every platform live.
- **Regenerate schemas** with `opentide generate schemas`: technique pins move to `att&ck::1.2` (ATT&CK 20.0), and techniques added since ATT&CK v17 validate again.

It is a minor because `generate` and `validate` now fail on input they used to accept (a phase that logs an error, a missing or unknown `metadata.schema`), and lint and generate output change.

### Security

- **Generated pipelines no longer let a pull request choose where platform credentials go.** Live query validation and the staging deploy hold platform secrets and send them to the tenant URLs and `$VAR` references in `.opentide/configurations`. On a pull request that directory came from the pull request itself, so a configuration-only change could send a credential to any host. The generated GitHub, GitLab and Azure pipelines now replace `.opentide/configurations` with the default branch's copy, in the same step, right before those commands. A platform the default branch has no tenant for yet skips its live query step with a note and exits `0`, so the pull request that adds the first tenant can pass. Regenerate existing pipelines with `opentide setup ci <github|gitlab|azure> --yes` ([#565](https://github.com/opentidehq/opentide/pull/565)).

### Added

- `opentide --version` / `-V` prints `opentide <version>` and exits before the workspace is resolved, so CI jobs can log which opentide they installed ([#187](https://github.com/opentidehq/opentide/issues/187)).
- `opentide setup platforms --elastic` ([#414](https://github.com/opentidehq/opentide/issues/414)).
- `opentide lint` findings carry the object's `uuid`, a `severity` (`error` for an unparseable or unnamed object, `warning` for a filename slug mismatch, `info` for missing recommended metadata) and a zero-based `yaml_line` like `validate`'s, so they can be sorted, joined to their object and opened at the right line. The human line reads `[check/severity] path[:line]: message`. The JSON change is additive and `--strict` exit codes are unchanged ([#488](https://github.com/opentidehq/opentide/issues/488)).

### Changed

- **`pip install opentide` is the only install: every optional extra is removed.** The vendor SDKs (`azure-identity`, `azure-monitor-query`, `splunk-sdk`, `pandas`, `openpyxl`, `carbon-black-cloud-sdk`) are base dependencies, so live query validation, deploy and the importers work for every platform on a stock install. Generated CI pipelines install exactly `opentide==<version>`, so through 0.15.0 the pipeline's `validate query --live` for Sentinel failed with `Live query validation for sentinel needs a vendor SDK: No module named 'azure'` and staging and production never deployed. The `sentinel`, `splunk`, `carbon-black`, `crowdstrike`, `cli`, `mcp` and `dev` extras no longer exist: pip and uv warn about the unknown extra and install opentide with everything, so an existing `pip install 'opentide[sentinel]'` keeps working. Contributors use `uv sync --group dev` ([#576](https://github.com/opentidehq/opentide/issues/576)).
- **Sentinel deploys through the ARM `alertRules` REST API directly**, with an `azure-identity` token, instead of `azure-mgmt-securityinsight`. That SDK has published only pre-releases since 2.0, and uv refuses a transitive pre-release, so it could not become a base dependency without breaking `uv tool install opentide` and `uvx opentide`. The request body, the API version (`2025-10-01-preview`, the only one that accepts `NRT` rules) and the dry-run preview are unchanged: the bodies of the 0.15.0 deployer were captured and are asserted byte-for-byte. An ARM error now fails the rule with `SentinelApiError`, naming the HTTP status, the ARM error code and its message. `deploy --dry-run` always previews the compiled ARM body; the fallback to the configuration block when the SDK was missing is gone ([#576](https://github.com/opentidehq/opentide/issues/576)).
- When a vendor SDK will not import, `validate query --live` and `generate extract` report an incomplete install and advise `pip install --force-reinstall opentide`, instead of naming an extra ([#576](https://github.com/opentidehq/opentide/issues/576)).
- **Technique pins move to `att&ck::1.2` (ATT&CK 20.0).** Run `opentide generate schemas` so the editor offers the new IDs. Elastic threat arrays follow the ATT&CK v19 split of Defense Evasion: TA0005 is now Stealth and TA0112 Defense Impairment is new, and the legacy Defense Evasion stage of revoked keys maps to Stealth. Sentinel tactics are mapped onto the ARM `AttackTactic` enum: Stealth, Defense Impairment and the ICS Evasion tactic deploy as `DefenseEvasion`, and a stage with no Sentinel tactic is dropped with a `dropping_attack_stage_without_sentinel_tactic` warning. Tactics for every other technique are unchanged ([#568](https://github.com/opentidehq/opentide/issues/568)).
- **`generate` fails when a phase raises or logs an error.** Before, a phase that logged an error, for example after skipping an object file it could not parse, still exited `0`. The run now stops at that phase and exits `1`; the result names the phase in `phase` and at the start of `message`, keeps the exception type, and ends with the UUID of the object being rendered when one object caused it (`exports: KeyError: 'mitre_attack' while rendering <uuid>`, where 0.15.0 printed only `'mitre_attack'`). With `--json`, `generate docs` and `generate exports` and their subcommands print one result document instead of a traceback. A phase that logged errors and then raised reports both, and an error logged again when a phase reloads the registry counts once. A malformed object file fails the first phase that loads the registry, so the editor refresh `generate schemas templates vocabs snippets` now stops at `schemas`; run `opentide validate` to list every broken object at once. The documentation SDK (`opentide.documentation.run`, `write_all`) raises `ObjectGenerationError` around a per-object failure, with the original exception as its cause ([#579](https://github.com/opentidehq/opentide/issues/579)).
- **`opentide validate` warns `platform_not_enabled`** when a rule has a block for a platform the workspace has not enabled, for example an imported Splunk rule in a Sentinel-only repository. One warning per block, at `configurations.<platform>`, naming the `opentide setup platforms` flag. It does not fail `--strict`, the commit hook or CI; malformed blocks and unknown platform keys still fail. Such blocks still do not deploy ([#413](https://github.com/opentidehq/opentide/issues/413), [#410](https://github.com/opentidehq/opentide/issues/410)).
- **A missing or unknown `metadata.schema` is no longer checked against the newest revision of its object type** (versioning 1.1). Without `metadata.schema`, `opentide validate` fails the `schema` check with a new `schema_missing` issue at that field. An unregistered identifier, or one that names another object type (a rule declaring `threat::1.0`), fails with `schema_validation`. Both are reported at `metadata.schema` with its line, and a `metadata` that is not a mapping is a shape error at `metadata`. `load_rule_from_dict` and `Opentide.Rules` raise `SchemaMissingError` or the new `SchemaIdentifierError` (a `LookupError`) instead of defaulting to `rule::1.0`, so a rule declaring another family's schema now stops registry load instead of loading as `rule::1.0` ([#582](https://github.com/opentidehq/opentide/issues/582)).
- Signal `effort` is no longer pinned to the `efforts` vocabulary: it is an integer score from 1 to 10 (specifications#42). The unused `threat::2.1` pin table is removed, and an `objective::1.1` table is bundled, unused until opentide ships that revision ([#111](https://github.com/opentidehq/opentide/issues/111)).
- The MalAPI vocabulary scraper is no longer part of the package: `opentide.extraction.malapi` scraped malapi.io on import and needed an undeclared BeautifulSoup dependency. It is now the maintainer script `scripts/vocabulary/generate_malapi.py` ([#539](https://github.com/opentidehq/opentide/issues/539)).
- Docs: a rule's `detection_model` names the objective it implements, or one signal defined under that objective. Both are referenceable by design (specifications#48).

### Fixed

- **ATT&CK techniques added since v17 validate again.** 0.13.0 ([#504](https://github.com/opentidehq/opentide/pull/504)) re-synced the bundled `att&ck` vocabulary from a specifications copy that was still ATT&CK v17, while every schema pinned `att&ck::1.1`, so T1685–T1690, T1059.013 and the other v18 and v19 techniques failed validation. ATT&CK 19.2 is restored as `att&ck::1.1` (the 60 keys 0.9.0–0.12.1 shipped) and ATT&CK 20.0 is added as `att&ck::1.2` (19 keys, including T1696–T1701). The 27 IDs MITRE has since revoked (T1562.*, T1070.001/.002, T1656, …) still validate under `att&ck::1.x`. `att&ck.groups`, `mitigations` and `datasources` are refreshed from the same releases, and the generator names enterprise sub-techniques `Parent: Sub` again ([#568](https://github.com/opentidehq/opentide/issues/568)).
- `Opentide.validate_rule()` and `validate_raw_payload()` check a rule against the revision its `metadata.schema` names, so a valid `rule::1.1` rule with `metadata.reviewed` no longer fails as `rule::1.0` ([#582](https://github.com/opentidehq/opentide/issues/582)).
- `opentide share push` matches a block's `rule_statuses` against the status of the rule's enabled platform blocks, which deploy uses and promotion rewrites, instead of the root `status`, which promotion leaves at `STAGING`. The root `status` is used only when no enabled block has one. In generated pipelines the share job still runs before the production deploy promotes, so a rule promoted by that deploy is shared the next time a push selects it ([#583](https://github.com/opentidehq/opentide/issues/583), follow-up [#590](https://github.com/opentidehq/opentide/issues/590)).
- `opentide generate extract sentinel` imports near-real-time rules. ARM lists them as kind `NRT`, and the importer compared the kind with `nrt`, so every NRT rule was skipped as an unsupported kind ([#577](https://github.com/opentidehq/opentide/issues/577)).
- **Elastic deploy and live validation work again.** The planner dumps each rule with `exclude_none=False` and reloads it, and the Elastic block's checks tested key *presence*, so the dumped `null` keys raised `filter_shape`, `type_block` and `index_list` and every Elastic deploy and `validate query --live` failed before reaching Kibana. Optional fields set to `null` are now treated as absent. A raw filter that also carries a top-level `negate` is still rejected as mixing the two filter shapes ([#557](https://github.com/opentidehq/opentide/issues/557), [#561](https://github.com/opentidehq/opentide/pull/561)).
- Elastic `kill-process` and `suspend-process` response actions without a `field` compile to Kibana's default `config` (`{field: process.entity_id, overwrite: true}`). Kibana requires `config` for both, so such a rule — including any rule `extract elastic` wrote for a default-field action — failed deploy and preview with HTTP 400 ([#558](https://github.com/opentidehq/opentide/issues/558), [#562](https://github.com/opentidehq/opentide/pull/562)).
- `opentide generate extract elastic` no longer writes `negate: null` on `threat_match` mapping entries when Kibana omits `negate`; an explicit `false` is kept ([#559](https://github.com/opentidehq/opentide/issues/559), [#563](https://github.com/opentidehq/opentide/pull/563)).
- Sentinel and Elastic accept compound shorthand durations (`1h10m`, `1d2h`, `2m30s`; units in `d`, `h`, `m`, `s` order, each at most once, lower case) as used by the official Azure-Sentinel rules, alongside single-unit shorthand and ISO 8601. Sentinel shorthand also accepts seconds. An upper-case shorthand unit (`1M`) is rejected, as in 0.15.0 ([#560](https://github.com/opentidehq/opentide/issues/560), [#564](https://github.com/opentidehq/opentide/pull/564)).
- `ElasticClient.find_managed` pages through every managed rule instead of stopping at the first 1,000, and raises `requests.HTTPError` when a page fails rather than returning the rules collected so far ([#566](https://github.com/opentidehq/opentide/issues/566), [#569](https://github.com/opentidehq/opentide/pull/569)).
- Splunk correlation searches carry the rule's own `techniques` together with the techniques inherited from its objective, de-duplicated in order, and compiling a rule that is not in the catalogue index (SDK, MCP `deploy_rule`) no longer crashes or logs a CRITICAL lookup failure ([#567](https://github.com/opentidehq/opentide/issues/567), [#570](https://github.com/opentidehq/opentide/pull/570)).
- Follow-ups to those fixes: an Elastic raw filter that also carries a top-level `negate` is rejected again as mixing filter shapes, as RFC 0007 requires; a Splunk compile of a rule outside the catalogue no longer logs a CRITICAL lookup failure; Sentinel shorthand durations are case-sensitive again, as in 0.15.0, and accept seconds (`2m30s`); out-of-order and repeated units are rejected on Sentinel and Elastic.
- `validate query --live` and the MCP `validate_query` tool report a tenant they cannot reach (a refused connection, DNS, TLS, timeout or proxy failure) as a failed check with exit `1`, naming the `tenant` and `host`. Splunk, SentinelOne, Elastic, Carbon Black Cloud and Defender for Endpoint used to crash with a `URLError` or `requests` traceback and print nothing on stdout. The new `TenantUnreachableError` is an `Errors.TenantConnectionError`.
- The default `opentide validate` no longer crashes with `AttributeError` on an object whose `metadata` is not a mapping.
- `opentide generate exports navigator` writes the ATT&CK Navigator layer in a fixed order: techniques by ID, and each comment lists threats, then rules, by name. Renaming or moving object files no longer reshuffles the whole file. Expect a one-time reorder diff the first time you regenerate the layer ([#521](https://github.com/opentidehq/opentide/issues/521)).
- `opentide migrate objects --apply` on macOS and Windows (case-insensitive filesystems) renames the legacy `Objects/` folder to `objects/` after the moves. Before, the migrated folders stayed inside `Objects/` and a Linux checkout found no objects. `--json` lists the rename under `case_renamed`, and the command explains how to make git record the new folder case. Re-running it repairs a repository an earlier release left in `Objects/` ([#522](https://github.com/opentidehq/opentide/issues/522)).
- The `AGENTS.md` and `CLAUDE.md` that `opentide setup skills` writes name `opentide mcp start`, not the `opentide-mcp` command removed in 0.12.0 ([#460](https://github.com/opentidehq/opentide/issues/460)).
- Importing a platform client, deployer or validator no longer builds the whole registry index: `DebugEnvironment` reads its debug deployment settings on access instead of at import ([#539](https://github.com/opentidehq/opentide/issues/539)).
- The advice printed when deploy or live `validate query` skips a disabled platform names a flag that exists (`--defender-for-endpoint`, `--sentinel-one`, `--carbon-black-cloud`), and so does the Defender import advice ([#414](https://github.com/opentidehq/opentide/issues/414)).
- opentide's own CI checks the bundled vocabulary pins against the specifications. The drift gate never ran before, because it filtered changed paths with `rg`, which GitHub-hosted runners do not ship ([#111](https://github.com/opentidehq/opentide/issues/111)).
- `data/specifications.lock.json` no longer lists `responders.vocab.toml`, which was removed in #512.
- The PyPI publish workflow warns, naming the cause, when the website was not notified of a release ([#540](https://github.com/opentidehq/opentide/issues/540)).

### Install

```bash
pip install opentide==0.16.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide setup ci <github|gitlab|azure> --yes
opentide generate schemas
opentide validate --strict
```

## [0.15.0] — 2026-10-16

Minor release: two things need action after upgrading.
- **Vendor rule ids move out of rule YAML into committed deployment state shards** (RFC 0010, [specs/deployment-state.md](https://github.com/opentidehq/specifications/blob/main/specs/deployment-state.md)). Run `opentide deploy migrate-state` and commit its output before the next deploy.
- **Generated pipelines must be regenerated** with `opentide setup ci <provider> --yes`. They now retire rules, deploy from the default branch's newest deployment state, queue production deploys on GitLab and Azure, and persist deploy write-backs.

Elastic Security is also now a supported platform, with an `opentide extract elastic` importer. Nothing to do unless you use it.

### Breaking

- **Rust is opentide's only engine: the Python implementation, and `OPENTIDE_ENGINE`, are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)). Every command, `opentide serve`, `opentide mcp start`, `opentide tui` and `opentide lsp start` run on the Rust core compiled into the package; the console script (`opentide._cli:main`) hands it the arguments in process. `OPENTIDE_ENGINE` is no longer read: `python` no longer runs the Python command line, MCP server or Textual UI, and `compare` no longer runs both implementations. The `engine_not_ported` and `engine_mismatch` failure codes, exit code `70` and their `opentide explain` pages are gone, and `opentide --json commands` no longer lists the variable. When the compiled core does not load, the console script prints `error: The opentide analysis engine does not load: …` with the reinstall command on stderr and exits `1`, where the Python command line answered the commands that do not need it.
- **The deprecated SDK entry points are removed, with no shims** ([#841](https://github.com/opentidehq/opentide/issues/841)): `Opentide.initialise()` and the registry (`from opentide import Opentide`, `OpenTide`, `Opentide.Rules`, `Objectives`, `Threats`, `Index`, `Platforms`, `render_rule`, `validate_rule`), `opentide.validation.session.run_validation` and `ValidationScope`, and the documentation writers (`opentide.documentation.write_all`, `write_rules`, `write_objectives`, `write_threats`, `run`, `render_rule`, `render_objective`, `render_threat`). Each has an `opentide.Workspace` equivalent (Upgrade; [migration](docs/sdk/migration.md)).
- **opentide's undocumented internals are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)): `opentide.cli` (and its services), `opentide.core`, `opentide.platforms`, `opentide.deployment`, `opentide.states`, `opentide.validation`, `opentide.loading`, `opentide.registry`, `opentide.indexing`, `opentide.generation`, `opentide.documentation`, `opentide.export`, `opentide.extraction`, `opentide.ci`, `opentide.sharing`, `opentide.query`, `opentide.mcp_server`, `opentide.vocabulary`, `opentide.mutation`, `opentide.schemas` (its Python modules; the bundled data stays) and `opentide.vulnerability_lookup`. `opentide.models` keeps the Rust classes alone: the Pydantic package behind it (`opentide._models`), the Pydantic machinery (`TideModel`, `TideField`, `TideRegistry`), the result models and constants (`ValidationResult`, `DeploymentResult`, `RULE`, `CORE_OBJECT_TYPES`, `EnumRegistry`, `SchemaVersion`, …), the submodules it aliased (`opentide.models.results`, `.configuration`, …) and `opentide.models.delegation` are gone. `opentide.analysis` keeps `check_query`, `highlight`, `describe`, `engine_codes`, `engine_versions` and `EngineUnavailableError`; `check_queries` and the catalog helpers are gone. The package keeps the console script, the SDK (`opentide.Workspace`, `run_json`, `Connection`, `OpentideError`), `opentide.models`, the plugin API (`opentide.plugins`) and the native binding; a plugin that uses only `opentide.plugins` keeps working. The built-in platforms no longer register `opentide.platforms` entry points.
- **opentide no longer depends on the Python implementation's libraries** ([#841](https://github.com/opentidehq/opentide/issues/841)): `typer`, `rich`, `textual`, `questionary`, `structlog`, `ruamel.yaml`, `pyyaml`, `orjson`, `tomli-w`, `dulwich`, `platformdirs`, `requests`, `mcp`, `pymisp`, `azure-identity`, `azure-monitor-query`, `splunk-sdk`, `carbon-black-cloud-sdk` and `boto3` are no longer installed with it. `pydantic` stays, for the plugin API's `configuration_model`. Code that imported one of them through opentide's install declares it itself.
- **`opentide query --rule` and `--file` on a platform plugin are a usage error** ([#835](https://github.com/opentidehq/opentide/issues/835)): `usage_invalid_value`, exit `2`, naming the option, where they were refused as not ported. A plugin's block is the plugin's to read: give its query as `QUERY` or `--query-file`.
- **A status promotion that cannot rewrite the push fails the deploy** ([#841](https://github.com/opentidehq/opentide/issues/841)): no promotion target, a platform key that is not a string, or promoted text that does not read back fails the run before anything is written (exit `1`, `--skip-promotion` named), where it was refused as not ported (`engine_not_ported`, exit `2`).
- `rule_id`, `rule_id_bundle` and `rule_id::<tenant>` are removed from the Defender for Endpoint, SentinelOne, CrowdStrike, HarfangLab and Carbon Black blocks. Vendor ids for Defender, SentinelOne and CrowdStrike now live in `.opentide/states/deployment/<uuid>.json` (`deployment.state::1.0`), one committed shard per rule.
  - `opentide validate` fails a rule that still carries any of those keys with `external_id_in_rule`.
  - `opentide deploy` refuses it for **every** platform before any HTTP call.
  - There is no fallback read of the YAML. A deploy with neither the key nor a shard would create a second remote rule, so migrate first.
  - Upgrade: in `.gitignore`, replace `.opentide/states/` with `.opentide/states/sharing.jsonl`. Then run `opentide deploy migrate-state` and `opentide validate --strict`, and commit the stripped rules together with `.opentide/states/deployment/` ([#396](https://github.com/opentidehq/opentide/issues/396)).
- Deploy no longer writes ids into rule files. A create records the returned id in the shard, and logs it as `external_id_recorded` at warning level so the CI log keeps it. `DELETION` or `DISABLEMENT` without an entry is the warning `external_id_missing`: nothing is called and the run does not fail, since nothing is known to exist on that tenant. A create is refused with `deployment_state_ignored` while git ignores the shard directory. `opentide.deployment.ExternalIdHelper` is removed ([#396](https://github.com/opentidehq/opentide/issues/396)).
- In CI, a deploy whose plan is not `PRODUCTION` (the pull-request staging job, or a `FULL`, `ALWAYS` or `MANUAL` run) refuses to create a Defender for Endpoint, SentinelOne or CrowdStrike rule with `deployment_state_unpersisted`, before any vendor call, because only the production job commits the shards. Updates and deletes of bound rules still run, and local runs may still create. A pipeline that commits `.opentide/states/deployment/` itself can pass `opentide deploy --persist-state-externally`. Before, every staging rerun created another untracked remote rule ([#554](https://github.com/opentidehq/opentide/issues/554)).
- Shards are read in canonical form only: a file name that is not the lowercase canonical uuid, an `object_uuid` that is not exactly the file name, or a second file naming the same rule is `deployment_state_uuid_mismatch`, and a tenant key with surrounding spaces is `deployment_state_shape`. The rule is refused rather than read as having no id ([#396](https://github.com/opentidehq/opentide/issues/396)).

### Added

- **Elastic Security platform** (`elastic`, `platform::elastic::1.0`, [RFC 0007](https://github.com/opentidehq/specifications/blob/main/rfcs/0007-elastic-security-platform.md); [#386](https://github.com/opentidehq/opentide/issues/386)–[#390](https://github.com/opentidehq/opentide/issues/390)). A rule compiles to a Kibana detection engine body whose `rule_id` is its `metadata.uuid`, so Elastic keeps no deployment state shard. Deploy creates, updates, disables and deletes rules; a type change is a delete then a create; remote fields the rule does not set (`actions`, `exceptions_list` and others) are kept; prebuilt rules are never modified. `validate query --platform elastic --live` previews each rule through Kibana `rules/preview` and runs the Elasticsearch pre-flight (ES|QL `LIMIT 0`, then `_field_caps` on aggregation, timestamp and indicator-match fields); the same pre-flight runs before every deploy. A 401 or 403 fails the tenant, any other error fails only that rule. There is no offline syntax check. Tenants live in `.opentide/configurations/platforms/elastic.toml`, with the API key as an `$ENV` reference.
- `opentide generate extract elastic` imports the detection rules of one Kibana space (`--space`) as `platform::elastic::1.0` rules. Disabled rules import as `DISABLED`, prebuilt rules are converted to custom rules with derived UUIDs only with `--include-prebuilt`, and a rule that would not load is skipped and reported rather than written.
- `opentide deploy migrate-state` moves existing Defender, SentinelOne and CrowdStrike ids into shards. It writes the shard before stripping the lines, preserves comments and layout, reports `external_id_conflict` and `external_id_shape`, refuses a gitignored destination, and is idempotent. Keys on every other platform (Sentinel, Splunk, HarfangLab, Carbon Black Cloud) are removed without being stored and reported as `external_id_unused` with platform, tenant, value and file. It exits `0` on success, on a clean second run and on `external_id_unused` warnings only, and `1` when any rule fails or the destination is ignored ([#396](https://github.com/opentidehq/opentide/issues/396)).
- `opentide deploy --persist-state-externally` ([#554](https://github.com/opentidehq/opentide/issues/554)).
- Full-workspace `opentide validate` checks every shard under `.opentide/states/deployment/`, including orphans whose rule was deleted ([#396](https://github.com/opentidehq/opentide/issues/396)).
- MCP `deployment_status` returns `external_ids` from the shard ([#396](https://github.com/opentidehq/opentide/issues/396)).
- `opentide validate --file` is repeatable ([#548](https://github.com/opentidehq/opentide/issues/548)).
- `validate query --live` JSON reports `plan`, `queries_validated` and `queries_per_tenant` ([#547](https://github.com/opentidehq/opentide/issues/547)).

### Changed

- `opentide setup repo` ignores `.opentide/states/sharing.jsonl` instead of the whole `.opentide/states/` directory ([#396](https://github.com/opentidehq/opentide/issues/396)).
- `opentide validate --file` fails with `scope_no_match` when any one `--file` target matches no object, and names that target in `context.targets`. Before, a run with several targets passed as long as one of them matched, so a mistyped or quoted path was never validated. A script that passes a `--file` for a file that may not exist now exits `1`.
- `opentide deploy --plan PRODUCTION` now includes `DISABLED` and `REMOVED` rules, so they are disabled or deleted as [specs/deployment.md](https://github.com/opentidehq/specifications/blob/main/specs/deployment.md) defines. Before, the `--keep-deprecated` default dropped them before the `PRODUCTION` allow-list was consulted, and a retirement never reached the platform. `--drop-deprecated` restores the old behaviour ([#548](https://github.com/opentidehq/opentide/issues/548)).
- The generated production job (GitHub, GitLab, Azure) commits promoted rule statuses and `.opentide/states/deployment/` back to the default branch with `[skip ci]` ([#548](https://github.com/opentidehq/opentide/issues/548)):
  - Before the dry-run it replaces the checkout's `.opentide/states/deployment/` with the default branch tip's, so a merge made before an earlier run's write-back landed updates the rule that run created instead of creating it again.
  - Production jobs are queued on GitLab (`resource_group: opentide-production`) and Azure (`lockBehavior: sequential`, which takes effect once an Exclusive lock check is added to a resource the stage uses). GitHub deliberately has no `concurrency` group: it cancels pending runs, and a cancelled diff-scoped deploy would silently never deploy its rules. Overlapping GitHub runs that create the same rule fail loudly with `deployment_state_conflict`.
  - The write-back runs whenever the deploy started: after a deploy that failed part way, was cancelled or timed out (GitHub `always()`, Azure `always()`, GitLab `after_script` on cancel; GitLab skips `after_script` on a timeout), so ids from the creates that succeeded are never lost.
  - Rule files are committed only when `opentide validate --strict` passes on exactly those files, read NUL-delimited so no file name is C-quoted.
  - If a concurrent merge conflicts with the rule files, this run's shard changes are replayed per tenant onto the new tip and pushed alone, and the job fails. Bindings other runs recorded and shards either run deleted are preserved.
  - Any failure that leaves the state commit off the default branch (push rejected every time, a failed fetch or replay) prints the state diff and pushes the commit to `refs/opentide/deployment-state/<commit>`.
- `opentide setup vscode` maps `objects/**/*.yaml` to `.opentide/schemas/opentide.schema.json`, so `rule::1.0` and `rule::1.1` rules validate side by side. A merge removes the per-folder revision mappings earlier releases wrote ([#550](https://github.com/opentidehq/opentide/issues/550)).
- `opentide validate` rejects a quoted or boolean signal `effort` (for example `"3"`), as the editor schema does ([#552](https://github.com/opentidehq/opentide/issues/552)).
- The `sentinel` extra requires `azure-mgmt-securityinsight>=2.0.0b2`; the lock uses 2.0.0b4 ([#545](https://github.com/opentidehq/opentide/issues/545)).
- The router no longer lists `visibility::1.0`, which is configuration rather than an object ([#550](https://github.com/opentidehq/opentide/issues/550)).

### Fixed

- **Sentinel deploy:**
  - Rules with `alert.dynamic_properties` deploy. The `sentinel` extra resolved `azure-mgmt-securityinsight` 1.0.0, which has no `AlertPropertyMapping`, so every such rule failed with `AttributeError`. Both the `SecurityInsights` and `SecurityInsightsMgmtClient` client names now work ([#545](https://github.com/opentidehq/opentide/issues/545)).
  - Rules accept ISO 8601 durations (`PT1H`, `P1D`) as the platform spec documents; before, only the `1h` shorthand parsed ([#545](https://github.com/opentidehq/opentide/issues/545)).
  - A rule without `entities` no longer sends an empty `entityMappings`, which ARM rejected with 400 ([#549](https://github.com/opentidehq/opentide/issues/549)).
  - A missing `grouping` or `grouping.alert` fails with an error naming the rule and `configurations.sentinel.grouping.alert`, in deploy and in `--dry-run`, instead of an `AttributeError` ([#549](https://github.com/opentidehq/opentide/issues/549)).
- `deploy --dry-run` no longer hides Sentinel compile errors. It previously fell back to the configuration block and reported `completed`. It now shows the ARM request a deploy would send, and a rule that would fail is listed as `failed` with its `error`; the run exits `1` ([#545](https://github.com/opentidehq/opentide/issues/545)).
- The `PRODUCTION` plan on GitHub Actions and Azure Pipelines diffs against HEAD's first parent. Before, on a merge commit the diff was taken against the merged branch's head, so the rules the merge changed were not deployed, and pull-request jobs on the merge ref reported `skipped` ([#546](https://github.com/opentidehq/opentide/issues/546)).
- `validate query --live` with no `--plan` checks every tenant a rule can reach, `STAGING` and `PRODUCTION` alike. `MANUAL` tenants are checked only when listed, and `deploy` targets are unchanged. If the rules reach no configured tenant at all, the run reports `skipped` with exit `2` instead of `passed`. An explicit `--plan` that only narrows every rule out (a staging-only rule under `--plan PRODUCTION`) is an ordinary `skipped` with exit `0` ([#547](https://github.com/opentidehq/opentide/issues/547)).
- `opentide.schema.json` applies exactly one revision schema per object, selected by `metadata.schema`. It offers the registered identifiers as completions and resolves its references to the files next to it. Before, its `oneOf` could never be satisfied ("Matches multiple schemas"), and its `$id` sent references to a remote URL ([#550](https://github.com/opentidehq/opentide/issues/550)).
- `rule.1.1.schema.json` includes `metadata.reviewed` and accepts the same date and datetime forms as `opentide validate` ([#551](https://github.com/opentidehq/opentide/issues/551)).
- Signal `effort` is typed as an integer in `objective.1.0.schema.json`; the efforts names had made every authored value invalid in the editor ([#552](https://github.com/opentidehq/opentide/issues/552)).
- CrowdStrike rules deploy as `active`, and disabled rules as `inactive`; the status was inverted. Compiling any CrowdStrike rule had also raised `AttributeError` ([#553](https://github.com/opentidehq/opentide/issues/553)).
- A rule refused with `external_id_in_rule` fails the deploy on every path: with `--platform`, with `--skip-unconfigured`, and when the Sentinel or Splunk deployer is called directly (SDK, MCP `deploy_rule`). MCP `deploy_rule` returns `status: failed` with an `error` when the deployer refused or failed the rule; it used to report a plain `deploy`. Error and warning flags no longer leak from one deploy to the next in a long-lived process.
- The commented `[[tenants]]` example in every bundled platform template loads when uncommented. The retired `proxy` key is gone, and the HarfangLab `type` and SentinelOne `url`/`account_id` placeholders are valid TOML.

### Install

```bash
pip install opentide==0.15.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide deploy migrate-state
opentide validate --strict
```

## [0.14.2] — 2026-10-14

Patch on 0.14.1. Nothing to do after upgrading, but upgrade promptly if you run `opentide setup skills`: it could be made to install skill content from a repository other than the pinned catalogue. A patch rather than a minor because no input contract, generated artefact, exit code or command surface changes — the installer refuses inputs that no legitimate catalogue produces, and a normal install behaves exactly as before.

### Fixed

- `opentide setup skills` can no longer be steered outside the pinned `opentidehq/skills` catalogue. The installer interpolated the catalogue manifest's `ref`, the skill `slug`, and each tree path straight into `raw.githubusercontent.com` and `api.github.com` URLs without rejecting `..`. GitHub normalises dot segments server-side, so a manifest ref of `../../../attacker/payload/main` resolved to a **different public repository** and its `SKILL.md` files were installed into `.agents/skills/` on a developer or agent machine — unreviewed instructions, delivered by the tool whose whole promise is that the catalogue is pinned. The same gap existed on the write side: a tree entry such as `skills/<slug>/../../.git/hooks/pre-commit` escaped the staging directory, which turns a catalogue listing into arbitrary file write, a git hook being the obvious target. Containment is now checked at four points — the ref, the slug, each repository path, and the fully-assembled URL after dot-segment removal (host, scheme, prefix, query, and absence of credentials or a fragment all re-verified) — and the destination of every written file is confirmed to resolve inside the skill tree. A rejected manifest ref falls back to `main` rather than being used, and a rejected slug or path aborts the install instead of writing a partial tree ([#483](https://github.com/opentidehq/opentide/pull/483)).

### Changed

- Runtime dependencies moved up: `pydantic` 2.13.5 → 2.14.0, `orjson` 3.12.0 → 3.13.0, `dulwich` 1.2.15 → 1.2.17, `typer` 0.27.2 → 0.27.3. No API, schema or output change — the full matrix (Python 3.10–3.14), the CLI E2E shards and the Windows smoke job are green on each ([#502](https://github.com/opentidehq/opentide/pull/502), [#500](https://github.com/opentidehq/opentide/pull/500), [#501](https://github.com/opentidehq/opentide/pull/501), [#498](https://github.com/opentidehq/opentide/pull/498)).

### Install

```bash
pip install opentide==0.14.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.14.1] — 2026-10-14

Patch on 0.14.0. Nothing to do after upgrading. Documentation and export generation are dramatically faster again — a 265-object corpus that took **722s** on 0.14.0 now completes in **under a second**, and the generated output is byte-identical, so no regeneration is required. Field extraction for ATT&CK techniques, threat actors and platform configurations is now derived from the Pydantic models rather than a hardcoded key list. A patch rather than a minor because no input contract, generated artefact, exit code or command surface changes; the one behaviour change is an undeclared legacy key that no model ever described, noted under Changed.

### Fixed

- The vocabulary index is no longer rebuilt on every access. `Opentide.Vocabularies.Index` was a `@property` calling `VocabularyLoader.load_index()` on each read, and `generation.framework.VOCAB_INDEX` is a `_LazyMapping` whose `_data()` re-read that property for every `[]`, `in`, `.get`, iteration and `len` — so a single `get_vocab_entry()` call rebuilt all 35 vocabularies, `actors` and its ~1,249 entries included. A full-corpus run made **169 million** `_build_entry` calls and re-validated the same vocabulary models **172 million** times. `generate docs` goes from **722s to 1.44s** on a 265-object corpus and `generate exports` from 152s to 0.61s; generated documentation is byte-identical to the same corpus generated under 0.14.0, verified file by file. `_LazyMapping`'s own docstring already promised the cost was "paid once per process" — nothing tested it, so the claim and the code had diverged indefinitely ([#510](https://github.com/opentidehq/opentide/issues/510)).
- The threat chaining graph is no longer recomputed on every access. `Opentide.Models.chaining` rebuilt the whole graph per read and `generation.framework.CHAINING_INDEX` re-read it per lookup — the same defect shape as the vocabulary index, measured at **4,273** `compute_chains` calls on a 265-object corpus. It is now memoised against the registry snapshot's identity, mirroring `FlatIndex` two properties above it in the same class, whose metaclass already clears that cache whenever the registry reloads. Worth **3.82s → 0.91s** on top of the vocabulary fix, output byte-identical ([#510](https://github.com/opentidehq/opentide/issues/510)).

### Changed

- ATT&CK techniques, threat actors and platform configurations are extracted by deriving the field locations **from the Pydantic models** instead of scanning hardcoded key tuples. The previous `_TECHNIQUE_KEYS = ("techniques", "mitre_attack", "attack")` was wrong on two counts: `attack` was declared by **no model at all**, and the tuple conflated field names with model types — every key was tried in every section, so a rule was scanned for `mitre_attack` and a threat for `techniques`, fields those models do not have. Each role-bearing field now carries a `FieldRole` marker on the model that declares it, and the search paths are built per model by walking `model_fields`, selected by the body's `metadata.schema`. A renamed or added role-bearing field is picked up by tagging the model, with no edit to the extractor, and every registered revision of a model is covered. **Behaviour change:** the undocumented tolerance for a nested `tags` mapping carrying techniques is gone. No model declares that shape — the only model-declared `tags` is a `list[str]` on platform configuration, which is not a technique holder — and no object in the reference catalogue uses it. If you hold pre-0.9 objects that carry techniques under a `tags:` mapping, catalogue search and `opentide info` will stop reporting those techniques until the values are moved to the field the object's model declares.

### Install

```bash
pip install opentide==0.14.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.14.0] — 2026-10-14

Minor on 0.13.0. Two things need action after upgrading. `objective.signals[].entities` values are now stage-scoped (`Hostname` → `Host::Hostname`), and `opentide migrate vocab-scope` re-prefixes them for you. `response.responders` becomes a configuration enum you declare in `deployment.toml`, so a value that no instance could make valid under 0.13.0 now validates. Documentation and export generation are dramatically faster — a corpus that previously exceeded a one-hour CI timeout now completes.

### Breaking

- **Rust is opentide's only engine: the Python implementation, and `OPENTIDE_ENGINE`, are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)). Every command, `opentide serve`, `opentide mcp start`, `opentide tui` and `opentide lsp start` run on the Rust core compiled into the package; the console script (`opentide._cli:main`) hands it the arguments in process. `OPENTIDE_ENGINE` is no longer read: `python` no longer runs the Python command line, MCP server or Textual UI, and `compare` no longer runs both implementations. The `engine_not_ported` and `engine_mismatch` failure codes, exit code `70` and their `opentide explain` pages are gone, and `opentide --json commands` no longer lists the variable. When the compiled core does not load, the console script prints `error: The opentide analysis engine does not load: …` with the reinstall command on stderr and exits `1`, where the Python command line answered the commands that do not need it.
- **The deprecated SDK entry points are removed, with no shims** ([#841](https://github.com/opentidehq/opentide/issues/841)): `Opentide.initialise()` and the registry (`from opentide import Opentide`, `OpenTide`, `Opentide.Rules`, `Objectives`, `Threats`, `Index`, `Platforms`, `render_rule`, `validate_rule`), `opentide.validation.session.run_validation` and `ValidationScope`, and the documentation writers (`opentide.documentation.write_all`, `write_rules`, `write_objectives`, `write_threats`, `run`, `render_rule`, `render_objective`, `render_threat`). Each has an `opentide.Workspace` equivalent (Upgrade; [migration](docs/sdk/migration.md)).
- **opentide's undocumented internals are removed** ([#841](https://github.com/opentidehq/opentide/issues/841)): `opentide.cli` (and its services), `opentide.core`, `opentide.platforms`, `opentide.deployment`, `opentide.states`, `opentide.validation`, `opentide.loading`, `opentide.registry`, `opentide.indexing`, `opentide.generation`, `opentide.documentation`, `opentide.export`, `opentide.extraction`, `opentide.ci`, `opentide.sharing`, `opentide.query`, `opentide.mcp_server`, `opentide.vocabulary`, `opentide.mutation`, `opentide.schemas` (its Python modules; the bundled data stays) and `opentide.vulnerability_lookup`. `opentide.models` keeps the Rust classes alone: the Pydantic package behind it (`opentide._models`), the Pydantic machinery (`TideModel`, `TideField`, `TideRegistry`), the result models and constants (`ValidationResult`, `DeploymentResult`, `RULE`, `CORE_OBJECT_TYPES`, `EnumRegistry`, `SchemaVersion`, …), the submodules it aliased (`opentide.models.results`, `.configuration`, …) and `opentide.models.delegation` are gone. `opentide.analysis` keeps `check_query`, `highlight`, `describe`, `engine_codes`, `engine_versions` and `EngineUnavailableError`; `check_queries` and the catalog helpers are gone. The package keeps the console script, the SDK (`opentide.Workspace`, `run_json`, `Connection`, `OpentideError`), `opentide.models`, the plugin API (`opentide.plugins`) and the native binding; a plugin that uses only `opentide.plugins` keeps working. The built-in platforms no longer register `opentide.platforms` entry points.
- **opentide no longer depends on the Python implementation's libraries** ([#841](https://github.com/opentidehq/opentide/issues/841)): `typer`, `rich`, `textual`, `questionary`, `structlog`, `ruamel.yaml`, `pyyaml`, `orjson`, `tomli-w`, `dulwich`, `platformdirs`, `requests`, `mcp`, `pymisp`, `azure-identity`, `azure-monitor-query`, `splunk-sdk`, `carbon-black-cloud-sdk` and `boto3` are no longer installed with it. `pydantic` stays, for the plugin API's `configuration_model`. Code that imported one of them through opentide's install declares it itself.
- **`opentide query --rule` and `--file` on a platform plugin are a usage error** ([#835](https://github.com/opentidehq/opentide/issues/835)): `usage_invalid_value`, exit `2`, naming the option, where they were refused as not ported. A plugin's block is the plugin's to read: give its query as `QUERY` or `--query-file`.
- **A status promotion that cannot rewrite the push fails the deploy** ([#841](https://github.com/opentidehq/opentide/issues/841)): no promotion target, a platform key that is not a string, or promoted text that does not read back fails the run before anything is written (exit `1`, `--skip-promotion` named), where it was refused as not ported (`engine_not_ported`, exit `2`).
- `objective.signals[].entities` entries are stage-scoped: an authored value is `<stage>::<key>`. Seven of the 28 entity keys are defined under two stages (`Account`, `User`, `Authentication`, `Token`, `Permissions`, `Email` and `API Call`), so a bare key name could not say whether a signal keyed on a **host** account or a **cloud** account — different telemetry, a different data contract, often a different platform. The enum carried 28 values where the vocabulary defines 35, and now carries all 35. Stage identifiers are capitalised to `Host`, `Network` and `Cloud`, matching the convention `threat.surface` already uses. Vocabulary entry keys are unchanged — the prefix is applied at resolve time — so the `signal.entities::1.0` pin is unaffected. Migrate with `opentide migrate vocab-scope --apply`, then `opentide generate schemas templates vocabs snippets` ([#509](https://github.com/opentidehq/opentide/issues/509), [RFC 0005](https://github.com/opentidehq/specifications/blob/main/rfcs/0005-scoped-signal-entities.md)).
- `response.responders` is a **configuration enum**, not a vocabulary. The shipped `responders` vocabulary had `keys = []` while both rule revisions pinned the field to it, so every authored value failed validation and no instance could clear it — vocabularies are canonical and not locally extensible. One corpus reported 483 unclearable findings from two values. The alert handling team is per-organisation, so an instance now declares its teams in a `[[responders]]` block in `deployment.toml`; the generated schema offers them in the editor with their descriptions, and `validate` rejects anything else. Declaring **none** leaves the field unconstrained, so a fresh install carries no constraint it cannot satisfy. `[deployment] default_responders` supplies the team for a rule that names none — a key that shipped in the configuration template and in the spec but **was read by no code**, so the documented fallback never happened. The `responders` vocabulary file is removed ([#507](https://github.com/opentidehq/opentide/issues/507)).

### Changed

- `mcp` is a base dependency, so a bare `pip install opentide` ships a working MCP server. It previously lived in an optional `[mcp]` extra, so a plain install omitted it and `opentide mcp` told the user to install an extra before the command would run — a requirement for a first-class CLI command. The `[mcp]` extra is kept as an empty alias, so an existing `pip install opentide[mcp]`, or an editor configuration naming it, keeps resolving. The now-redundant pin is dropped from the `dev` extra and the `dev` dependency group, leaving `mcp` declared in exactly one place ([#526](https://github.com/opentidehq/opentide/issues/526)).

### Added

- `opentide migrate vocab-scope` re-prefixes authored values for every stage-scoped field. It applies only mechanical outcomes — a key defined under exactly one stage, and a stage whose casing drifted — and reports a key defined under several stages with its candidates rather than guessing, exiting 2 while anything is left for a human. Values are located by path through the document rather than by leaf key name, so a Sentinel platform block that also carries a key called `entities` is never touched, and each value is replaced over the exact span its scalar occupies, so comments, block scalars, quoting style and flow sequences survive.

- `opentide generate --help` names the four positional phases (`schemas`, `templates`, `vocabs`, `snippets`). Typer renders the sub-app's help string rather than the callback docstring, which already named them, so the only place the list appeared was an error string you had to trigger deliberately — while naming the cheap phases is the documented remedy for a stale editor schema after a contract change.
- `generate` reports what each phase costs, and names the slowest. A run that overran a CI job timeout previously emitted no phase boundary and no timing, so a killed job gave no way to tell whether it was 10% or 90% through. Timing is recorded even when a phase raises, which is the case that needed it ([#510](https://github.com/opentidehq/opentide/issues/510)).

### Fixed

- Documentation and export generation no longer rescan the whole catalogue for every object. `childs()` walked every model on every call while all of its callers are per-object — the table exporter per row, the documentation catalogue per signal, and `relations_downstream()` recursively at every level — so cost grew with the square of the corpus. It is now a reverse index built once per catalogue generation: **68× faster** on a 1497-object corpus. This is the root cause behind both a `generate docs` phase that exceeded a one-hour CI job timeout and a `generate exports` phase measured at 395s ([#510](https://github.com/opentidehq/opentide/issues/510)).
- `childs()` matched a model id against reference values with a substring test, so a short non-UUID id matched a longer one that merely contained it — `o-1` matched a signal referencing `o-186`, returning 113 spurious children. Relations are now compared by equality. UUID-shaped ids could not trigger this; any other id scheme could.
- `validate` and `generate` no longer disagree on the same vocabulary value. `get_vocab_entry()` stripped the stage prefix unconditionally before lookup while `is_valid()` checked the raw value first, so the two paths could resolve one value differently. Both now go through one helper that tries the raw value first. Three `Security::*` surface keys resolved to a different entry under the stripping path and three more missed entirely; those keys are reachable now ([#508](https://github.com/opentidehq/opentide/issues/508)).
- `check_status` resolved a deployment status by its configured *name* rather than by the strategy it maps to, so a renamed status silently took the wrong branch. It now resolves the strategy, and raises typed errors instead of a bare `Exception` ([#506](https://github.com/opentidehq/opentide/issues/506)).
- `opentide mcp start` and `opentide setup mcp` no longer advise an install that cannot help. Both told a user with an unimportable `mcp` to run `pip install 'opentide[mcp]'`, but that extra is now an empty alias, so following the advice installed nothing and left the user where they started. They now name the real remedy, `pip install 'mcp>=1.28.1,<2'`, and distinguish an incomplete environment from an incompatible `mcp` 2.x. The wheel gate that was meant to cover this could only ever skip once `mcp` became a base dependency; it now proves the stronger claim, that a **bare** wheel install answers a stdio `initialize` ([#526](https://github.com/opentidehq/opentide/issues/526)).
- The documentation no longer advertises a release it does not install. Four pages named 0.12.1 as the latest release beside their own `pip install 'opentide==0.14.0'` block — the defect [#406](https://github.com/opentidehq/opentide/issues/406) closed at 0.8.0, regressed silently through 0.13.0 because the release tests covered the release *commands* and nothing covered the version *claims*. Every claim, pin and PyPI link outside the historical release log is now checked against the newest `CHANGELOG.md` entry on every run.
- The test suite no longer operates on the repository under test. Git tests ran `git` with `cwd=` set to a temporary repository but inherited the environment, and `GIT_DIR` overrides `cwd` — so when `git push` exported `GIT_DIR` to its hooks and a hook ran the suite, the fixtures committed and checked out branches **in the real repository**, producing a commit that deleted 890 files. The environment is now sanitised for every test, with a collection-time guard so the hazard cannot return silently ([#513](https://github.com/opentidehq/opentide/issues/513)).

### Install

```bash
pip install opentide==0.14.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide migrate vocab-scope --apply
opentide generate schemas templates vocabs snippets
opentide validate --strict
```

## [0.13.0] — 2026-10-12

Minor on 0.12.1. `threat.surface` values are now stage-scoped (`Windows::Desktop` → `OS::Windows::Desktop`), platform configuration blocks require `status`, `opentide --json validate` emits one document shape and drops its legacy `errors` map, and the local `[vocabulary]` extension block is removed. Re-run `opentide setup ci` — generated pipelines deployed to the staging tenant and pushed to your default branch from any pull request. Regenerate with `opentide generate schemas templates vocabs snippets`.

### Changed

- `threat.surface` entries are stage-scoped: an authored value is `<stage>::<key>`. The vocabulary groups keys under 8 stages and defines the same key under two of them, so a bare key name was ambiguous and five values were unreachable (`VPN`, `VPN::OpenVPN`, `VPN::WireGuard`, `Wireless` and `Industrial` are each both `Infrastructure` and `Protocol`). The enum carried 895 values where the vocabulary defines 900, and now carries all 900. Vocabulary entry keys are unchanged — the prefix is applied at resolve time.
- `configurations.<platform>.status` is required. A rule omitting it previously passed `validate`, failed the published JSON Schema, and crashed the deployer; validation now reports `status: Field required` with the field path. Platform templates emit `status:` live rather than commented.
- `opentide --json validate` and `opentide --json validate --check <x>` return the same document. The report is always at `report` and `checks` maps each check that ran to its verdict; `--check` narrows `checks` and adds `check` rather than relocating the report to `issues`. The duplicate legacy `errors` map is removed — read `report.issues`.
- The `[vocabulary]` extension block in `schema.toml` no longer injects vocabulary entries and has been removed from the shipped template. Vocabularies are canonical in the specifications repository and are not locally extensible.

### Fixed

- Generated CI gated staging deployment and default-branch pushes on pull-request *events* rather than the pull request's *target branch*, so a pull request between two feature branches deployed detections to a live staging tenant and committed to the default branch. Six jobs across the GitLab, GitHub and Azure renderers now require the target to be the default branch. Re-run `opentide setup ci`.
- `threat.actors.name` is pinned to `actors::1.1`. 220 threat-actor galaxy clusters were present in the bundled vocabulary but invisible behind the `actors::1.0` pin, so a correctly-authored MISP cluster UUID was reported as an unknown vocabulary value. The actors enum goes from 1029 to 1249 values; `actors::1.0` keys are unaffected.
- `opentide setup skills --install opentide-detection-rule` no longer fails as an unknown slug. Three of the four wheel-bundled authoring skills were missing from the discovery catalogue while remaining in the default starter set, so the CLI installed a slug it refused to name.
- The weekly vocabulary refresh workflow had never completed a run: its opentide pull-request step was not gated on the App credential the specifications step already required, so it fell back to `GITHUB_TOKEN`, force-pushed the branch, then failed at `gh pr create`, leaving an updated branch with no pull request. It now fails fast before any mutation and names the missing secrets.
- `platform_loader` reported a missing `status` as a type error (`None is not a valid string`) instead of `Field required`.

### Install

```bash
pip install opentide==0.13.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide generate schemas templates vocabs snippets
opentide validate --strict
```

## [0.12.1] — 2026-10-09

Patch on 0.12.0. A missing credential is logged once, not once per object. Re-run `opentide setup ci` so a live query job guards only the `$VAR` names in that platform file and exits 2 when one of them is unset.

### Fixed

- `fetch_config_envvar` reports each unset configuration variable once per process. The live check still ends on the FATAL panel that names those variables.
- Generated CI no longer treats every `$VAR` in the bundled platform sample as required. The guard reads the enabled platform file, ignores comments and literals, and exits 2 on a skip. Exit 0 means the tenant check ran.

### Install

```bash
pip install opentide==0.12.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.12.0] — 2026-10-09

Minor on 0.11.0. The `opentide-mcp` console script is gone. The stdio server is `opentide mcp start`. Regenerate editor config with `opentide setup mcp`. Re-run `opentide setup ci` so a live query job runs only when every required credential variable is set. Regenerate schemas with `opentide generate` so object lists such as `threat.chaining` are not given a string vocabulary enum.

### Removed

- The `opentide-mcp` console script. The stdio server is `opentide mcp start`. There is no alias ([#460](https://github.com/opentidehq/opentide/issues/460)).

### Changed

- `opentide setup mcp` writes `command: opentide` and `args: ["mcp", "start"]`. `opentide mcp` with no subcommand prints help and exits. The editor owns stop and reload ([#460](https://github.com/opentidehq/opentide/issues/460)).

### Fixed

- Splunk `[[modifiers]]` loads as an array of tables. A config `ValueError` during engine load is no longer reported only as a missing `declare` ([#466](https://github.com/opentidehq/opentide/issues/466)).
- Generated schemas no longer put a string vocabulary enum on `threat.chaining` items or on the array node. `list[str]` vocabulary fields still get `items.enum` ([#468](https://github.com/opentidehq/opentide/issues/468)).
- Stage-prefix suggestions strip using the field name, including when the caller passes `surface::1.0`. MISP actor UUIDs still get no suggestion ([#467](https://github.com/opentidehq/opentide/issues/467)).
- A retired `[tenants.setup] proxy` key fails the live query check with a message naming `opentide --proxy`. That retirement covers platform tenant config, not only `[cve].proxy` ([#469](https://github.com/opentidehq/opentide/issues/469)).
- `--live` fails when a credential is still an unsubstituted `$VARIABLE`. Generated CI runs that job only when every required credential variable is set ([#471](https://github.com/opentidehq/opentide/issues/471)).
- Validate findings for vocabulary and cross-object checks record `yaml_line`, including list indexes such as `actors[0]`. Lint findings are unchanged ([#470](https://github.com/opentidehq/opentide/issues/470)).

### Install

```bash
pip install opentide==0.12.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.11.0] — 2026-10-07

Minor on 0.10.0. Bare `validate query` no longer scans. `--live` is the tenant check. Regenerate CI with `opentide setup ci` so generated pipelines pass `--live` and pin this release. Regenerate schemas with `opentide generate` so optional vocabulary lists include `items.enum`.

### Added

- `opentide generate` accepts `schemas`, `templates`, `vocabs`, and `snippets` together and runs them in that order. `docs`, `exports`, `extract`, and `inflight` stay subcommands ([#455](https://github.com/opentidehq/opentide/issues/455)).
- The bundled actors vocabulary matches the specifications snapshot refreshed from the live MISP galaxy ([specifications#34](https://github.com/opentidehq/specifications/issues/34)).

### Changed

- Bare `opentide validate query` refuses and names `--live`. It does not scan query text. `--live` checks the tenant. A missing SDK or plan fails that check. CrowdStrike and HarfangLab stay `supported: false` ([#456](https://github.com/opentidehq/opentide/issues/456)).
- Generated GitHub, GitLab, and Azure pipelines pass `--live` and skip a platform when every credential variable for that platform is empty ([#456](https://github.com/opentidehq/opentide/issues/456)).
- MCP `validate_query` refuses unless `live` is true. `live: true` checks the catalogue rules for the platform against the tenant ([#456](https://github.com/opentidehq/opentide/issues/456)).
- Generated schemas stamp `items.enum` on optional vocabulary lists and on each branch of a string-or-list union ([#450](https://github.com/opentidehq/opentide/issues/450)).

### Fixed

- Validation findings print `file:line` when `yaml_line` is set ([#451](https://github.com/opentidehq/opentide/issues/451)).
- `validate --check` returns only that check's issues. Parse findings belong to the schema check ([#452](https://github.com/opentidehq/opentide/issues/452)).
- Unknown `sharing.toml` keys name `[[misp]]` ([#453](https://github.com/opentidehq/opentide/issues/453)).
- Surface suggestions try the exact de-prefixed key before difflib ([#454](https://github.com/opentidehq/opentide/issues/454)).

### Install

```bash
pip install opentide==0.11.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.10.0] — 2026-10-06

Minor on 0.9.0. Upgrade, rename technique lists to `mitre_attack`, and regenerate schemas with `opentide generate`. Regenerate CI with `opentide setup ci` so the install pin is exact. A root `composition` block is still accepted and is no longer required.

### Added

- `opentide --proxy http://[user:pass@]host:port` sets `HTTP_PROXY` and `HTTPS_PROXY` for that process. A passed flag wins over the existing environment. Omitting the flag leaves the environment as it is.
- `python -m opentide` and `python -m opentide.mcp_server` start the CLI and the MCP server.
- `opentide info` prints how many object files failed to load. `--strict` exits non-zero when that count is not zero.
- `opentide migrate objects` moves `Models Library/Threat Vector Models`, `Models Library/Detection Objectives`, and `Models Library/Managed Detection Rules`, and object folders named in `Configurations/global.toml`.

### Changed

- Threat and objective technique lists are `mitre_attack`, pinned to `att&ck::1.1`. `att&ck` and `attack` are not accepted. Actor values stay scoped (`att&ck::G0007`).
- `objective.composition` is required. A root `composition` block is accepted and ignored. Templates emit the block once, under `objective`.
- `signals[].data.logsources` come from workspace `visibility.toml`. The `datasources` pin on that field is gone.
- Signal `severity` uses `alert_severity::1.0` (`Informational` through `Critical`). Threat `severity` stays the incident vocabulary.
- `detection_model` accepts an objective UUID or a signal UUID.
- `VisibilityAsset.custom_details` accepts strings, booleans, and numbers.
- Sentinel generated schema no longer requires `grouping` or `entities`.
- `surface` and `signal.entities` descriptions say stages group keys. Authored values are not prefixed with the stage id.
- `opentide setup ci` installs `opentide==<installed version>`.

### Fixed

- Vocabulary extensions are looked up by field name, so a `schema.toml` extension applies during validation.
- `opentide lint` reports an unreadable file instead of crashing.
- `opentide setup vscode` accepts JSONC comments and trailing commas, and names the file when the JSON is still invalid.
- Duplicate YAML keys are rejected with the key and line.
- An unreadable object file is logged separately from malformed YAML.
- Legacy `tvm`, `dom`, `mdr`, and `cdm` object types in `Configurations/global.toml` raise an error that names the rename and tells you to delete that file.
- Unknown vocabulary values that are a UUID or `misp::<uuid>` do not get a "did you mean" suggestion.
- A leftover `[proxy]`, `[cve].proxy`, or tenant `setup.proxy` key is an error that names `--proxy`.

### Install

```bash
pip install opentide==0.10.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.9.0] — 2026-10-05

Minor on 0.8.2. Upgrade and regenerate schemas with `opentide generate` so `rule::1.1` can record `metadata.reviewed` and technique and logsource checks use `att&ck::1.1` and `datasources::1.1`. `opentide rules unreviewed` lists rules with no review, or a review older than the window. It does not require regenerating CI.

### Added

- `rule::1.1` accepts optional `metadata.reviewed` (ISO 8601 date or datetime). `rule::1.0`, threats, and objectives still reject the field. Validate, deploy, share, and template generation do not write it. `opentide rules unreviewed --older-than 90d` (also `12h`, `30m`, or a bare positive day count) lists `rule::1.0` as `schema`, a `rule::1.1` with no review as `absent`, and a review strictly earlier than now minus the window as `stale`. A review equal to the window boundary is fresh. Exit code is 0 when the window parses, including when rules are listed ([#437](https://github.com/opentidehq/opentide/issues/437), [#438](https://github.com/opentidehq/opentide/pull/438), [specifications#29](https://github.com/opentidehq/specifications/pull/29)).

### Changed

- Technique pins are `att&ck::1.1` on threats, objectives, `rule::1.0`, and `rule::1.1`. Objective logsources pin `datasources::1.1`. Bundled ATT&CK, groups, datasources, and mitigations match upstream 19.2 ([#392](https://github.com/opentidehq/opentide/issues/392), [#445](https://github.com/opentidehq/opentide/pull/445)).
- Production dependencies: `orjson` 3.12.0 ([#443](https://github.com/opentidehq/opentide/pull/443)) and `azure-identity` 1.26.0 ([#444](https://github.com/opentidehq/opentide/pull/444)). The `mcp` extra stays below 2 and is 1.30.0 ([#442](https://github.com/opentidehq/opentide/pull/442)). Transitive `oauthlib` 4.0.0, `urllib3` 2.8.0, and `virtualenv` 21.14.5 ([#435](https://github.com/opentidehq/opentide/pull/435)).

### Fixed

- CrowdStrike auth no longer logs the token response. Defender no longer logs the bearer token or a client-secret prefix. `--json` and the MCP server emit those logs to stderr, so a CI reader could reuse the credential ([#441](https://github.com/opentidehq/opentide/pull/441)).
- `share push` publishes a retracted object again. A matching content hash skips the push only when the ledger line is `synced`. Preview no longer reports an update that push then skips ([#385](https://github.com/opentidehq/opentide/pull/385)).
- Deploy commit loading records the immediate parent. Walking every ancestor raised `RecursionError` on a history deeper than the Python recursion limit and aborted the diff ([#369](https://github.com/opentidehq/opentide/pull/369)).

### Install

```bash
pip install opentide==0.9.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.8.2] — 2026-10-02

Patch on 0.8.1. Upgrade for a memoised object index and vocabulary files that keep dotted keys quoted. It does not change accepted input, CLI output, or exit codes, and it does not require regenerating CI.

### Changed

- `Opentide.Models.FlatIndex` is memoised for the current registry snapshot. Clearing `IndexManager._cache` drops that memo with the snapshot, so a rebuilt index cannot return the previous object map ([#436](https://github.com/opentidehq/opentide/pull/436)).
- `run_extract` and `run_extract_import` forward keyword arguments to the extraction runner. The CLI passes none, so an existing `run()` still works. Unexpected keywords raise `TypeError` with the module name ([#436](https://github.com/opentidehq/opentide/pull/436)).

### Fixed

- Vocabulary writers quote dotted list keys (`"tide.vocab.stages"`) instead of emitting a bare dotted key that TOML reads as nested tables. An entry that already stores stages under the nested table is still read ([#436](https://github.com/opentidehq/opentide/pull/436)).

### Install

```bash
pip install opentide==0.8.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.8.1] — 2026-10-01

Patch on 0.8.0. Upgrade and regenerate GitLab CI with `opentide setup ci gitlab` so query validation gates generate and deploy, and the inflight shell matches ShellCheck. This restores the documented gate that GitHub and Azure already enforced. It does not change accepted input, CLI output, or exit codes.

### Fixed

- Generated GitLab pipelines start `generate` only after object validation and every `validate query` job. A failed query check no longer starts deploy. Regenerate with `opentide setup ci gitlab` ([#429](https://github.com/opentidehq/opentide/issues/429)).
- Inflight shell quotes `$CI_DEFAULT_BRANCH` and exits if `cd` into the worktree fails. A document job with no commands is omitted, instead of an empty `script` GitLab rejects. `gitlab-ci-verify` (ShellCheck) and glint both accept the file ([#430](https://github.com/opentidehq/opentide/issues/430)).

### Install

```bash
pip install opentide==0.8.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.8.0] — 2026-09-30

Minor on 0.7.0. Upgrade and regenerate CI with `opentide setup ci` so validation and lint are strict, deploy skips a plan whose platforms have no tenants, and an Azure pipeline has a pool. An object file with no `uuid` now fails validation. `get_chaining` returns the threat, objective, and rule lineage.

### Added

- `opentide deploy --skip-unconfigured` exits 0 when every platform in the plan has no `[[tenants]]` block. A plan that mixes configured and unconfigured platforms still fails with `Cannot deploy:` ([#408](https://github.com/opentidehq/opentide/issues/408)).
- Generated GitHub deploy jobs map each credential named in the bundled platform files from `secrets`. GitLab and Azure read the same names from the project variable store. There is no `OPENTIDE_SECRETS` variable ([#408](https://github.com/opentidehq/opentide/issues/408)).

### Changed

- Generated catalogue gates are `opentide validate --strict` and `opentide lint --strict` ([#409](https://github.com/opentidehq/opentide/issues/409)).
- Azure pipelines set `pool.vmImage` to `ubuntu-latest` and trigger on every branch, so a topic-branch push still validates. `pr:` stays for Azure Pipelines hosted on GitHub or Bitbucket. Azure Repos Git ignores `pr:`; add a build validation policy on the default branch so `Build.Reason` is `PullRequest`. Staging deploy stays gated on that reason. The YAML cannot create the policy ([#398](https://github.com/opentidehq/opentide/issues/398)).
- `lint` prints `ISSUES` when findings exist. The exit code stays 0 unless `--strict`. JSON keeps `"ok": true`.
- MCP `get_chaining` returns the threat → objective → rule lineage reached through `objective.threats`, `rule.detection_model`, and threat-to-threat links. When `threat.chaining` is non-empty, `graph` stays that relation map and `lineage` lists the related objects. `Opentide.Models.chaining` is still the threat-to-threat map only ([#407](https://github.com/opentidehq/opentide/issues/407)).

### Fixed

- An object YAML file with no `uuid` fails validation. The schema check reports `missing_uuid`. An empty catalogue still exits 0 ([#397](https://github.com/opentidehq/opentide/issues/397)).
- `deploy --plan STAGING` on a detached pull-request checkout fetches `origin` by name. It no longer dies with `list index out of range` ([#402](https://github.com/opentidehq/opentide/issues/402), [#415](https://github.com/opentidehq/opentide/issues/415)).
- The generated inflight prune job creates `.opentide/inflight` before `git add`, so a repository that never committed that directory no longer exits 128 ([#403](https://github.com/opentidehq/opentide/issues/403)).
- `setup skills` downloads every file under `skills/<slug>/` and renders `AGENTS.md` from the package template. `opentide-detection-rule`, `opentide-detection-objective`, `opentide-threat-vector`, and `detection-engineering` are installed from the package and describe `rule::1.0`, `objective::1.0`, and `threat::1.0` ([#399](https://github.com/opentidehq/opentide/issues/399), [#405](https://github.com/opentidehq/opentide/issues/405)).
- `setup repo` writes `.gitkeep` in empty scaffold directories and does not create `.github/workflows` itself. The README lists one `opentide deploy --platform <name> --dry-run` per enabled platform. `--name`, `--org`, or `--description` on an existing `README.md` keeps the file and warns ([#400](https://github.com/opentidehq/opentide/issues/400), [#404](https://github.com/opentidehq/opentide/issues/404)).
- `generate docs` writes `rules/README.md`, `objectives/README.md`, and `threats/README.md` when the folder has no objects ([#401](https://github.com/opentidehq/opentide/issues/401)).
- The docs home and installation page name **0.8.0** as the latest release ([#406](https://github.com/opentidehq/opentide/issues/406)).

### Install

```bash
pip install opentide==0.8.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.7.0] — 2026-09-29

Minor on 0.6.4. Upgrade to publish Tide objects to MISP, or to regenerate CI so a GitHub production job compares `github.ref` to a literal ref. Sharing is a new command. The share stage stays off until `opentide setup ci` is run with `--sharing`.

### Added

- `opentide share` publishes a threat, objective, or rule to MISP as one Event. `push`, `preview`, `status`, `retract`, and `targets` share `.opentide/configurations/sharing.toml`. `preview` and `status` do not contact the destination. An API key is never printed ([#184](https://github.com/opentidehq/opentide/issues/184), [#371](https://github.com/opentidehq/opentide/issues/371)).
- `sharing.toml` merges `[[misp]]` blocks by `name`. `opentide validate --check sharing-config` reports the sharing checker codes. The check is off unless requested, and it runs for `opentide share push` ([#370](https://github.com/opentidehq/opentide/issues/370)).
- Successful shares are recorded in `.opentide/states/sharing.jsonl`. A skip or a failure leaves that file unchanged. Setup gitignores `.opentide/states/` ([#373](https://github.com/opentidehq/opentide/issues/373)).
- The MISP connector wraps PyMISP. One Tide object is one Event, the object YAML is copied verbatim, and the Event UUID is assigned by MISP ([#372](https://github.com/opentidehq/opentide/issues/372)).
- `opentide setup` and `opentide setup ci` take `--sharing` / `--no-sharing`, default off. When selected, GitHub, GitLab, and Azure run `opentide share push --changed` after generate on a push to the default branch. Deploy still depends only on generate ([#375](https://github.com/opentidehq/opentide/issues/375)).

### Changed

- A regenerated GitHub workflow compares `github.ref` with `'refs/heads/<branch>'`. `format()` with only the format string is not a valid Actions expression.
- `opentide share preview` does not require the API key. `push` and `retract` still do.

### Fixed

- A create that fails after the remote lookup no longer deletes the matching ledger line.
- Importing the CLI no longer imports PyMISP, so usage errors and `--json` stay free of the `pymisp loaded properly` line.

### Install

```bash
pip install opentide==0.7.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.4] — 2026-09-28

Patch on 0.6.3. Upgrade if `generate` printed an empty error for a missing detection model, a GitHub production deploy never ran, setup rewrote a README or platform comments, or MCP `deploy_rule` crashed. Regenerate a GitHub, GitLab, or Azure workflow with `opentide setup ci` so production deploy and the checkout depth match this release.

### Fixed

- `generate` exits `1` with one JSON document whose `message` names the missing UUID and `detection_model`. 0.6.3 printed empty stdout and a traceback that ended in a bare `Exception`. A catalogue that contains the objective still completes, and `generate inflight` on the broken tree still exits `0` ([#352](https://github.com/opentidehq/opentide/issues/352)).
- MCP `deploy_rule` returns a structured failure for an unknown platform and for a platform with no tenants, instead of `KeyError` or `TypeError`. `deployment_status` reports `deployed: false` when the authoring config has no `external_id` and no tenants ([#345](https://github.com/opentidehq/opentide/issues/345)).
- `--json setup` quotes the path it would write. A target of `.` no longer reads as `..` ([#346](https://github.com/opentidehq/opentide/issues/346)).
- Explorer pages are offered only for GitHub. GitLab and Azure exit `0` and warn that Explorer pages were not written, instead of writing no job and no warning ([#347](https://github.com/opentidehq/opentide/issues/347)).
- A generated GitHub production deploy needs `generate`, so a push to the default branch still deploys when the pull-request staging job is skipped. GitHub, GitLab, and Azure deploy jobs fetch full history. A missing parent commit is named instead of a bare SHA ([#348](https://github.com/opentidehq/opentide/issues/348)).
- `setup --yes --ci none` scaffolds the repository and writes no pipeline. `setup ci none` is rejected. CI-only flags without `github`, `gitlab`, or `azure` are named in warnings ([#349](https://github.com/opentidehq/opentide/issues/349)).
- Re-running setup keeps an edited `README.md`, `.gitignore`, and comments in an existing platform toml. The first scaffold still creates those files. `setup ci` still replaces the workflow ([#350](https://github.com/opentidehq/opentide/issues/350)).
- `lint --fix` rewrites a metadata finding onto the path it just renamed. A second `--fix` does not rename that file again ([#353](https://github.com/opentidehq/opentide/issues/353)).
- Usage and CLI pages no longer tell the reader to run a command that exits `2` ([#354](https://github.com/opentidehq/opentide/issues/354)).

### Install

```bash
pip install opentide==0.6.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.3] — 2026-09-24

Patch on 0.6.2. Upgrade if a CI diff plan still crashed after 0.6.2: a missing tip SHA died on `encode`, Azure `STAGING` died on `KeyError` or a fetch of a missing `origin`, a ref that is not on `origin` died on `Invalid object name`, or `DEBUG`, `MANUAL`, or `ALWAYS` died on `KeyError`. Each still exits `1`, with the sentence for that case. `FULL` is unchanged.

### Fixed

- A CI diff plan whose tip SHA is unset exits `1` and names the variable: `CI_COMMIT_SHA`, `GITHUB_SHA`, or `BUILD_SOURCEVERSION` is required to compute the changed rules. 0.6.2 reached `repo.commit(None)` and died with `'NoneType' object has no attribute 'encode'` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- Azure `STAGING` without `SYSTEM_PULLREQUEST_SOURCEBRANCH` or `SYSTEM_PULLREQUEST_TARGETBRANCHNAME` exits `1` with `Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and SYSTEM_PULLREQUEST_TARGETBRANCHNAME | Ensure this is running in a Pull Request pipeline`. 0.6.2 fetched `origin` first, so a checkout with no remote died with `No git repository was found at origin`, and a checkout that had one died with `KeyError while compiling the deployment plan`. The variables are read before the fetch ([#339](https://github.com/opentidehq/opentide/issues/339)).
- GitHub or Azure `STAGING` whose pull-request ref is not on `origin` exits `1` with `Could not find git ref origin/<name>`. 0.6.2 died with `Invalid object name` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- `DEBUG`, `MANUAL`, and `ALWAYS` under CI exit `1` with `Deployment plan <NAME> is not a CI diff plan. Use STAGING, PRODUCTION, or FULL.` `ALWAYS` was an alias of `FULL` because both enum values were the same string, so `--plan ALWAYS` took the full-redeploy path. It is now its own plan. `FULL` still does not compute a git diff ([#339](https://github.com/opentidehq/opentide/issues/339)).
- A GitLab merged-result pipeline reads the second parent only when that commit has more than one parent. A one-parent `CI_COMMIT_BEFORE_SHA` keeps `CI_COMMIT_SHA` as the tip and exits `0` when both SHAs are in the checkout. 0.6.2 died with `list index out of range` ([#339](https://github.com/opentidehq/opentide/issues/339)).

### Tests

- Each skipped arm is checked for human and JSON output on GitLab, GitHub, and Azure, including Azure `STAGING` with no `origin` remote. The messages are the sentences above, and the output does not contain `lookup_ref`, `encode`, `list index out of range`, `KeyError while compiling the deployment plan`, or `Invalid object name` ([#339](https://github.com/opentidehq/opentide/issues/339)).
- A one-parent merged-result commit exits `0`. The 0.6.2 GitLab base and GitHub pull-request-ref checks still pass ([#333](https://github.com/opentidehq/opentide/issues/333), [#334](https://github.com/opentidehq/opentide/issues/334), [#339](https://github.com/opentidehq/opentide/issues/339)).

### Install

```bash
pip install opentide==0.6.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.2] — 2026-09-24

Patch on 0.6.1. Upgrade if a GitLab `STAGING` or `PRODUCTION` plan crashed with `'Repo' object has no attribute 'lookup_ref'`, or a GitHub `STAGING` plan asked for Azure pull-request variables and then `KeyError`. Both still exit `1`. GitLab reports `No Source Commit Found`. GitHub names `GITHUB_HEAD_REF` and `GITHUB_BASE_REF`.

### Fixed

- GitLab `STAGING` and `PRODUCTION` with an unset or unknown base SHA exit `1` with `No Source Commit Found`. 0.6.1 walked `origin/main` through Dulwich `Repo.lookup_ref`, which does not exist, so the command died with `FATAL: 'Repo' object has no attribute 'lookup_ref'` and never reached that message. The same command still succeeds when both SHAs are in the checkout ([#333](https://github.com/opentidehq/opentide/issues/333)).
- GitHub Actions `STAGING` without `GITHUB_HEAD_REF` and `GITHUB_BASE_REF` exits `1` with `Expected to find GITHUB_HEAD_REF and GITHUB_BASE_REF | Ensure this is running in a Pull Request pipeline`. 0.6.1 fetched `origin` first, logged Azure `SYSTEM_PULLREQUEST_SOURCEBRANCH` and `SYSTEM_PULLREQUEST_TARGETBRANCHNAME`, then raised a bare `KeyError`, which deploy printed as `KeyError while compiling the deployment plan`. The Azure branch still cites the Azure names it reads ([#334](https://github.com/opentidehq/opentide/issues/334)).

### Tests

- A GitLab diff plan with an unset or unknown base, for `STAGING` and `PRODUCTION` and for human and JSON output, exits `1` with `No Source Commit Found` and does not mention `lookup_ref`. The same command exits `0` when both SHAs are in the checkout, including when `origin/main` exists and still does not contain the base ([#333](https://github.com/opentidehq/opentide/issues/333)).
- GitHub `STAGING` with an `origin` remote and neither pull-request ref set exits `1` with the GitHub variable sentence, in human and JSON output, and does not mention `SYSTEM_PULLREQUEST` or `KeyError` ([#334](https://github.com/opentidehq/opentide/issues/334)).

### Install

```bash
pip install opentide==0.6.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.1] — 2026-09-23

Patch on 0.6.0. Upgrade if a CI `STAGING` or `PRODUCTION` plan skipped a changed rule file that sits directly in `objects/rules/`: 0.6.0 left that file out of the plan, and 0.6.1 deploys it. A file in a subdirectory of `objects/rules/` is still not deployed. The missing-checkout failure is still exit `1`, with a different message.

### Changed

- CI `STAGING` and `PRODUCTION` plans include a changed rule file that sits directly in `objects/rules/`. 0.6.0 matched the git diff against an absolute rules path, so a repo-relative entry such as `objects/rules/rule.yaml` was left out and the plan deployed nothing for that change. A file under `objects/rules/<subfolder>/` stays out of the plan; the existing warning names it ([#318](https://github.com/opentidehq/opentide/issues/318)).

### Fixed

- `deploy --plan STAGING` or `PRODUCTION` with `GITHUB_ACTIONS`, `CI`, or `TF_BUILD` set and no git checkout exits `1` and names the directory it searched, and points at `--plan FULL`. 0.6.0 exited `1` with `FATAL: No git repository was found at None`. `FULL` still does not need a checkout. A directory that has `.git` is still opened ([#310](https://github.com/opentidehq/opentide/issues/310)).
- `opentide setup --path .` from a subdirectory of a git checkout scaffolds that directory. 0.6.0 treated the discovered git root as `--repo` and wrote the scaffold there. An explicit `--repo` still replaces `.` when it is not the working directory ([#324](https://github.com/opentidehq/opentide/issues/324)).
- `opentide setup --no-promotion` and `--promotion-target` write `[promotion]` in `.opentide/configurations/deployment.toml` without `--ci`. 0.6.0 applied those flags only when the same command generated a CI pipeline. Omitting them still keeps the repository's setting, and an explicit flag that disagrees with an existing table still exits `2` before anything is written ([#325](https://github.com/opentidehq/opentide/issues/325)).

### Tests

- CI diff selection keeps a top-level `.yaml` or `.yml` (repo-relative or absolute) in the plan and a file under `objects/rules/<subfolder>/` in the skipped list, and rejects lookalike paths such as `objects/rules-archive/` ([#318](https://github.com/opentidehq/opentide/issues/318)).
- The missing-checkout failure is checked for all three CI markers, both diff plans, human and JSON output, a `FULL` plan, and a real `git init` checkout. The CI overlay clears `GITHUB_WORKSPACE` and the other platform variables, so a GitHub-hosted run does not open the checkout the job itself is in ([#310](https://github.com/opentidehq/opentide/issues/310)).
- `setup --path .` from a subdirectory of a git checkout writes `.opentide` there, and an explicit `--repo` still selects the git root ([#324](https://github.com/opentidehq/opentide/issues/324)).
- A plain `setup` applies or refuses `--no-promotion` and `--promotion-target` before any file is written ([#325](https://github.com/opentidehq/opentide/issues/325)).

### Install

```bash
pip install opentide==0.6.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.6.0] — 2026-09-23

Minor on 0.5.0. Upgrade if a command checked the wrong directory, hid what `--json` already showed, or crashed on a repository that was not finished yet. A few JSON fields and exit results change, so read **Changed** before upgrading a pipeline.

### Changed

- SDK: the registry index has a `file_paths` map from UUID to the file each object was read from; `files` still holds bare file names. `ValidationScope.matches_file()` matches a path target only through the object's own path, and the `ValidationScope.path_basenames` field is removed ([#297](https://github.com/opentidehq/opentide/issues/297)).
- `opentide --json setup mcp --generic` returns its copy-the-file instruction as `advice` instead of `note`, so human output prints it too. Scripts that read `note` should read `advice` ([#292](https://github.com/opentidehq/opentide/issues/292)).
- `opentide validate` reports the directory it read objects from as `workspace` in `--json` output. A full run that finds no objects still passes with exit `0`, `--strict` included, but its message names that directory (`Validation passed, but no detection objects were found under …`) instead of a bare `Validation passed` ([#294](https://github.com/opentidehq/opentide/issues/294)).

### Fixed

- In the SDK, `rule.metadata.schema` returns the schema identifier (`"rule::1.0"`), as `docs/sdk/models.md` shows. It returned Pydantic's deprecated `BaseModel.schema` method, so the documented line printed a bound method; the same held for `.schema` on platform blocks (`rule.configurations.sentinel.schema`). `schema_id` / `platform_schema` stay the canonical fields, and validation, `model_dump(by_alias=True)` and generated JSON Schemas still use the `schema` key ([#298](https://github.com/opentidehq/opentide/issues/298)).
- `opentide setup --ci <github|gitlab|azure>` accepts `--default-branch`, like `setup ci`. Without the flag, a repository with no `origin/HEAD` now gets its checked-out branch, ahead of `init.defaultBranch` and `main`: a repository whose only branch was `trunk` got a pipeline that fetched from, pushed to, and deployed on `main`. Both forms warn when the pipeline falls back to a `main` branch the repository does not have, or targets the checked-out branch while other local branches exist ([#288](https://github.com/opentidehq/opentide/issues/288)).
- `opentide setup` prints the warnings of its steps. The one-shot `setup --ci <provider>` showed none of the CI step's `WARNING` lines that `setup ci <provider>` prints for the same condition, such as GitLab ignoring `--default-branch`; with `--json` they now also appear in the top-level `warnings`, not only under `steps[].warnings` ([#308](https://github.com/opentidehq/opentide/issues/308)).
- `validate --file` with a repo-relative or absolute path validates only that file when object folders have subfolders. The index kept only each object's file name, so `--file objects/rules/x.yaml` also validated `objects/rules/other/x.yaml` and reported its issues against `objects/rules/x.yaml`, while `--file objects/rules/other/x.yaml` matched nothing. A path no longer falls back to its file name, a bare file name still matches that name in every subfolder, and every issue names the file of the object it concerns — in the CLI, MCP `validation_report`, and `--check cve` ([#297](https://github.com/opentidehq/opentide/issues/297)).
- The duplicate-ID check reads object files in subfolders, as indexing does. A UUID duplicated in a file under `objects/rules/<subfolder>/` passed a full `validate` ([#297](https://github.com/opentidehq/opentide/issues/297)).
- SDK: `rule.file` on `Opentide.Rules[...]` and `Opentide.Models.Rules[...]` points at the rule's own file in subfolders. It was rebuilt as `<rules folder>/<file name>`, so a rule in `objects/rules/other/x.yaml` got `objects/rules/x.yaml` — another rule's file, or none ([#297](https://github.com/opentidehq/opentide/issues/297)).
- Human output no longer drops bracketed text. Rich read it as markup, so the `info` platform rows lost `[deploy, validate]`, the `validate` issues panel lost each `[error]` tag, and `generate extract sentinel` told you to `install opentide` without `[sentinel]` — `--no-color` included, while `--json` was correct. Help text that named `opentide[sentinel]` or `[deprecated]` lost it the same way ([#292](https://github.com/opentidehq/opentide/issues/292)).
- Human output prints a result's `advice` and `detail` as indented lines under its message, as `--json` carries them: `validate query --live` without the vendor SDK names the extra to install, and a live run on a disabled platform says how to enable it ([#292](https://github.com/opentidehq/opentide/issues/292)).
- Human `opentide lint` lists each finding as `[check] path: message` above its summary line. It used to print only `OK Catalogue lint found issues`, so without `--json` there was no way to see what to fix ([#292](https://github.com/opentidehq/opentide/issues/292)).
- `opentide info rules`, `info threats`, `info objectives`, and `info coverage --technique …` print the section asked for — UUID and name per object, the platforms each rule configures, the technique and its rule count — instead of the plain `info` summary ([#293](https://github.com/opentidehq/opentide/issues/293)).
- `generate docs` writes an actor's Source cell as its vocabulary stage (`att&ck`) instead of the Python tuple `('att&ck',)`. Documentation cells join any collection of values the same way, and a cell with no value shows `-` ([#296](https://github.com/opentidehq/opentide/issues/296)).
- `opentide info` and `Opentide.initialise()` no longer build a client for every installed platform, so a repo that does not use Splunk no longer logs `The frequency scheduling setting was not correct set` twice. Clients are built only when a command deploys to or validates against their platform. A Splunk setup without `frequency_scheduling` no longer warns and keeps the mode it deployed with before: `random` for a `[[tenants]]` entry, `current` for a legacy `[setup]` table. An invalid value logs one `frequency_scheduling_is_not_valid` warning that names the value ([#295](https://github.com/opentidehq/opentide/issues/295)).
- Commands run from inside a detection workspace find it. Root discovery walked up for `.git` only, so from `objects/rules` in a scaffold outside git, or anywhere in a workspace kept below a larger checkout (`monorepo/detections/`), the root was the current directory or the checkout: `info` counted no objects, configured platforms showed as disabled, and `validate --strict` passed having checked nothing. The CLI, SDK, and MCP server now stop at the nearest directory holding `.opentide/` or `objects/`, never above the enclosing git checkout, and fall back to the git top level as before. `--repo`, `OPENTIDE_REPO_ROOT`, and `OPENTIDE_TIDE_WORKSPACE` still take precedence, and `generate docs --changed` finds a nested workspace's changes from the cwd alone ([#294](https://github.com/opentidehq/opentide/issues/294)).
- `deploy` in a workspace without `objects/rules/` (an empty directory, or a fresh clone before the first rule is committed) no longer exits `1` with `FATAL: [Errno 2] No such file or directory`. It reports `skipped` with exit `0` and contacts no platform, as `validate`, `lint`, `info`, and `generate` already did. The same applies to `validate query --live`, and to a rules folder holding only `.gitkeep` or a subfolder, which failed with `'NoneType' object is not subscriptable` and `[Errno 21] Is a directory`. A skipped deploy now returns the same JSON keys as one that planned rules: `dry_run`, an empty `plan` and `deployed`, and `payloads` on `--dry-run` ([#300](https://github.com/opentidehq/opentide/issues/300)).
- `deploy` no longer skips rule files in subfolders of `objects/rules/` silently. Deploy still reads only the files directly in `objects/rules/` ([#312](https://github.com/opentidehq/opentide/issues/312)), but every plan now warns once and names the skipped files: a `WARNING` line in human output, and the result's `warnings` with `--json`. The list shows five names and then `+N more`. In CI, where `STAGING` and `PRODUCTION` plan from the git diff, only changed files are named. A repository whose rules all sit in subfolders reports `skipped` with the warning ([#300](https://github.com/opentidehq/opentide/issues/300)).
- The `deploy` reference, troubleshooting, and tutorial pages match the commands they document: a dry-run prints `== MDR Deployment ==` and `OK Deployment completed` (the plan and payloads only with `--json`). The tutorial scaffold leaves `[[tenants]]` commented out, so that dry-run's JSON leaves `deployed` empty and warns that a real deploy would stop. `deploy metadata` exits `2` with `FATAL: Metadata deployment is not implemented for splunk` rather than logging intent, and the tutorial's T1059 coverage query lists the rule alone, not an objective ([#299](https://github.com/opentidehq/opentide/issues/299)).
- `deploy` and `validate query --live` no longer crash with a bare `Exception` when an enabled platform has rules but no `[[tenants]]` entry. Both exit `1` with the platform and the file to edit, before any engine loads. `deploy --dry-run` still previews payloads, leaves that platform out of `deployed`, and warns that a real deploy would stop ([#314](https://github.com/opentidehq/opentide/issues/314)).
- `opentide setup`, `setup --ci <provider>` and `setup ci <provider>` now apply `--no-promotion` and `--promotion-target <STATUS>`. Both flags were accepted and ignored: no generated pipeline has a promotion job, and `opentide deploy` promotes as the merged `deployment.toml` says, so `--promotion-target STAGING` still promoted rules to `PRODUCTION`. Setup now writes those values to the `[promotion]` table of `.opentide/configurations/deployment.toml`, keeping the rest of an existing file, and lists the file in its result. Omitting the flags keeps the repository's setting. A target that is not a status of the repository, or an explicit flag that disagrees with an existing `[promotion]` table, exits with code 2 before anything is written. An explicit value equal to the bundled default writes nothing when the repository has no `[promotion]` table. The never-rendered promotion jobs are removed from the GitHub, GitLab and Azure renderers; generated pipelines are unchanged ([#307](https://github.com/opentidehq/opentide/issues/307)).
- `vocab-upstream.yml` no longer puts `secrets` in a step `if`, which GitHub's workflow parser rejected, so the vocabulary drift gate never ran ([#287](https://github.com/opentidehq/opentide/issues/287)).
- `publish-pypi.yml` can be retried after a PyPI 5xx: an upload that already succeeded is skipped, and the job checks that the release files are on PyPI before it finishes ([#289](https://github.com/opentidehq/opentide/issues/289)).

### Tests

- A parity test fails when a `setup ci` option is missing from the one-shot `setup --ci`, declared with a different default, or not passed on to CI generation ([#288](https://github.com/opentidehq/opentide/issues/288)).
- A human-vs-JSON parity test runs a matrix of commands on the tutorial workspace with and without `--json` and requires every top-level prose string in the payload, plus its warnings, issue severities, findings, platform capabilities, and section items, to appear verbatim in the human output. A unit guard sends markup-like text through every emit helper and checks that every help string renders its brackets ([#292](https://github.com/opentidehq/opentide/issues/292), [#293](https://github.com/opentidehq/opentide/issues/293)).
- A console-script E2E runs `info`, `validate --strict`, `lint --strict`, `generate docs`, and `generate` from the root of a scaffold, from `objects/rules` and `.opentide/configurations/platforms` inside it, and from a workspace nested in a parent git checkout, with no `OPENTIDE_*` variables set, and requires the same workspace, counts, and output location from each ([#294](https://github.com/opentidehq/opentide/issues/294)).
- A `text` or `json` fence in `docs/` tagged `output-of="opentide …"` (plus `exit=N` for a command meant to fail) is run against a repository scaffolded as in the tutorial, with deployers stubbed. Its lines or JSON values and its exit code must match the live command, the command must be printed on the same page, and a failing sample's section must say which code it exits with ([#299](https://github.com/opentidehq/opentide/issues/299)).
- A sample of a failure the finished tutorial does not produce names the repository edit it needs, `state=dangling-reference` or `state=unterminated-string`, so the `exit-codes` failure envelope and the `validate` offline-syntax finding are checked like any other sample ([#299](https://github.com/opentidehq/opentide/issues/299)).
- Pairing is no longer opt-in for CLI output. A `text`, `json`, or unlabelled fence under `docs/cli/` or `docs/usage/` that holds an `"ok"` / `"status"` key, or a line starting `OK `, `SKIPPED `, `WARNING `, `DEPRECATED `, `FATAL`, or `== … ==`, fails the golden test unless it carries `output-of=` or is marked `illustrative` ([#299](https://github.com/opentidehq/opentide/issues/299)).
- Every platform is deployed and live-query-validated from a `setup repo` scaffold whose tenant example is still commented out. A real deploy must fail before an engine import; a dry run must not list the platform as deployed ([#314](https://github.com/opentidehq/opentide/issues/314)).

### Install

```bash
pip install opentide==0.6.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

If you generated CI with `opentide setup ci`, regenerate it so `--default-branch` matches the branch you deploy from: `opentide setup ci <github|gitlab|azure> --yes`.

## [0.5.0] — 2026-09-23

Minor on 0.4.0. Upgrade if your threats follow `threat::1.0` and list their `impact` / `leverage` names: 0.4.0 rejected every such threat with `Input should be a valid string` ([#189](https://github.com/opentidehq/opentide/issues/189)). It is a minor rather than a patch because a threat written the way 0.4.0 required (`impact: Data Breach`) now fails validation until it becomes a one-item list — read **Changed** before upgrading a pipeline.

### Changed

- `threat.impact` and `threat.leverage` must be non-empty YAML lists of vocabulary names, as `threat::1.0` specifies. A single string (`impact: Data Breach`), which 0.4.0 required, now fails validation with `must be a YAML list of impact vocabulary names`; rewrite it as a one-item list. Several names joined with `;` fail too, as the whole value or as one list item: give each name its own item and keep all of them ([#189](https://github.com/opentidehq/opentide/issues/189)).
- In the SDK `ThreatBody.impact` and `ThreatBody.leverage` are `list[str]`. Generated threat templates, editor schemas (`type: array`, `minItems: 1`), and the explorer bundle carry both fields as lists ([#189](https://github.com/opentidehq/opentide/issues/189)).

### Fixed

- A threat written to the `threat::1.0` spec (`impact: [Data Breach, Identity Theft]`) no longer fails with `Input should be a valid string`, and `validate` no longer suggests a single vocabulary name for a `;`-joined value, which would drop the other names ([#189](https://github.com/opentidehq/opentide/issues/189)).

### Tests

- The 14 `threat-*.yaml` conformance fixtures from [opentidehq/specifications](https://github.com/opentidehq/specifications) are vendored under `tests/fixtures/specifications/threat-1.0/` and run through `opentide validate --file` in the E2E suite. The valid fixture must pass, each invalid one must fail on the field it breaks, and a guard test fails when upstream adds a fixture without an expectation ([#189](https://github.com/opentidehq/opentide/issues/189)).

### Install

```bash
pip install opentide==0.5.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Rewrite each `impact: Data Breach` as a one-item list (same for `leverage`), then run `opentide generate` so new threats start from the list template. If your CI patches the installed model to accept lists, drop that step.

## [0.4.0] — 2026-09-22

Minor on the public 0.3.0 beta. Upgrade if a first-run command crashed, printed a traceback, or quietly did nothing: this release fixes the first-user bugs filed against 0.3.0 ([#239](https://github.com/opentidehq/opentide/issues/239)–[#258](https://github.com/opentidehq/opentide/issues/258), [#202](https://github.com/opentidehq/opentide/issues/202), [#233](https://github.com/opentidehq/opentide/issues/233)) and the test-harness gaps that let them ship ([#259](https://github.com/opentidehq/opentide/issues/259)). It is a minor rather than a patch because several fixes change output that scripts can depend on — read **Changed** before upgrading a pipeline. If you generated GitHub CI with `opentide setup ci`, regenerate it — see **Security**.

### Security

- The inflight job written by `opentide setup ci github` checked out the pull request head and ran `git push origin HEAD:<default branch>`. Whenever the pull request was up to date with the default branch, that push fast-forwarded the default branch to the pull request, landing its unreviewed changes. Generated GitHub, GitLab, and Azure inflight jobs now commit only `.opentide/inflight/` shards, on a separate worktree of the default branch, and push that. Regenerate existing pipelines with `opentide setup ci <github|gitlab|azure> --yes` ([#244](https://github.com/opentidehq/opentide/issues/244)).

### Changed

- `opentide validate query` is an offline syntax check (KQL, SPL, S1QL, Lucene) by default and needs no platform SDK, credentials, or network. It follows each dialect's quoting and escaping: KQL multi-line strings (```` ``` ```` and `~~~`), S1QL `||` (with an operand on each side), and Lucene backslash escapes, mixed range ends, and `/regex/` terms. The previous tenant round-trip is `validate query --live`, which names the extra to install when the SDK is missing. JSON output reports `mode: offline-syntax` or `mode: live` ([#239](https://github.com/opentidehq/opentide/issues/239)).
- `validate query` for CrowdStrike and HarfangLab returns the normal `ok` / `status` envelope with `supported: false` instead of a bare payload ([#247](https://github.com/opentidehq/opentide/issues/247)).
- `query` is required and must not be blank on Splunk and Carbon Black configurations, as on the other query platforms. A rule with `query: ""` now fails validation instead of deploying nothing ([#233](https://github.com/opentidehq/opentide/issues/233)). See [Upgrading to 0.4.0](https://opentide.org/docs/usage/concepts/platforms/#upgrading-to-040).
- `opentide --json setup` without `--yes` refuses to start the interactive wizard and exits non-zero with one JSON error ([#255](https://github.com/opentidehq/opentide/issues/255)).
- MCP `search` always returns a list (a UUID lookup included, which also honours the other filters and ignores case; `get_chaining` resolves UUIDs the same way and returns the graph for them), `platform=` matches the configuration key exactly, and `coverage` for a parent technique includes sub-technique rules and reports `matched_techniques` ([#252](https://github.com/opentidehq/opentide/issues/252), [#253](https://github.com/opentidehq/opentide/issues/253)).
- MCP `opentide://vocabularies` returns an index (`metadata`, `entry_count`, `uri`) instead of every entry; read `opentide://vocabularies/{name}` for entries ([#254](https://github.com/opentidehq/opentide/issues/254)).
- MCP `run_query` is an explicit stub (`stub: true`, `rows: null`, no `results` key) rather than a successful empty result ([#258](https://github.com/opentidehq/opentide/issues/258)).
- `mcp` is pinned `<2` and the unused `fastmcp` dependency is gone. `opentide[sentinel]` declares the Azure packages the Sentinel validator and deployer import ([#256](https://github.com/opentidehq/opentide/issues/256), [#239](https://github.com/opentidehq/opentide/issues/239)).
- The positional `PATH` on `setup` subcommands is deprecated in favour of `--path` / `-C`. Giving both is a usage error ([#248](https://github.com/opentidehq/opentide/issues/248)).

### Fixed

- `deploy metadata` and `generate inflight prune` no longer run their parent command first — a live deploy, or a second JSON document on stdout ([#243](https://github.com/opentidehq/opentide/issues/243)).
- `opentide info coverage --technique T1059` works in either argument order ([#257](https://github.com/opentidehq/opentide/issues/257)).
- Every `setup` subcommand accepts `--path` / `-C` and `--yes` / `-y`. Given before the subcommand (`opentide setup --path DIR --yes env`) they apply to it; other `setup` options in that position are refused instead of silently ignored, and a subcommand's `--help` after them still shows its help ([#248](https://github.com/opentidehq/opentide/issues/248)).
- `validate --file objects/rules/x.yaml` honours the directory; a path target no longer matches a same-named file elsewhere. The ID-uniqueness check and the MCP `validation_report` tool resolve the same targets against the workspace, so a duplicate UUID is reported and an MCP server started outside the repository still finds the file ([#240](https://github.com/opentidehq/opentide/issues/240)).
- Unparseable object YAML is reported as a `yaml_parse` validation issue instead of a traceback, including files the indexer skips ([#250](https://github.com/opentidehq/opentide/issues/250)).
- `generate docs --changed` reports a structured failure in a repository without commits instead of a traceback. `generate docs --changed` and `generate inflight` find the baseline on `development`, `main`, or `master` (upstream, remote, or local), or whatever `origin/HEAD` names, count untracked object YAML, keep non-ASCII file names, and work when the workspace is nested inside the checkout. A pushed feature branch (`git push -u`, or an `actions/checkout` job) is compared with the default branch rather than its own remote copy, which hid every committed change ([#241](https://github.com/opentidehq/opentide/issues/241), [#251](https://github.com/opentidehq/opentide/issues/251)).
- `generate extract sentinel|defender` fail with a reportable error that names the missing extra, tenant, or key instead of `ModuleNotFoundError` / `KeyError` at import ([#242](https://github.com/opentidehq/opentide/issues/242)).
- `opentide generate explorer` is registered and writes `explorer.bundle.json` / `explorer.search.json`; the GitHub CI template calls it instead of the nonexistent `opentide explorer build` ([#202](https://github.com/opentidehq/opentide/issues/202)).
- A Sentinel-only `validate query` or deploy loads only the Sentinel engine: no missing-validator warnings for other vendors and no `ERROR` for platforms the repository disabled. An engine that fails to load is reported instead of a traceback ([#246](https://github.com/opentidehq/opentide/issues/246)).
- `setup ci gitlab` inflight jobs use `${CI_JOB_TOKEN}` / `${CI_SERVER_HOST}` and a commit message GitLab can parse; `setup ci azure` inflight jobs actually commit and push (`set -e` script, `persistCredentials: true`, no cross-stage `dependsOn`); GitLab jobs that run `git` install it on the `python:*-slim` image. GitHub and Azure jobs target the repository's default branch (`setup ci --default-branch`, else `origin/HEAD`) instead of assuming `main`, and inflight jobs retry when another job publishes first and keep the shards other pull requests publish while they run ([#244](https://github.com/opentidehq/opentide/issues/244)).
- The pre-commit hook validates the worktree being committed rather than an exported `OPENTIDE_REPO_ROOT`, and `--repo` overrides an exported workspace ([#249](https://github.com/opentidehq/opentide/issues/249)). A workspace nested below the Git root is validated at its own path, several workspaces in one repository share the hook instead of the last `setup hooks` run replacing the others, and a hook whose workspace was moved or deleted fails instead of passing every commit. Setup no longer installs into a user-wide `core.hooksPath`, where the hook would fail commits in every other repository, and no longer crashes on Windows when the hooks directory is on another drive.
- `--no-color`, `NO_COLOR`, `FORCE_COLOR=0`, and `PY_COLORS=0` keep every line free of ANSI escapes, including Typer help and usage errors on CI runners that force colour. Importing `opentide.ci` no longer changes a host application's Typer colour settings ([#282](https://github.com/opentidehq/opentide/pull/282)).
- MCP `coverage` and actor search read `rule.techniques` and `threat.actors`, not only `tags.*` ([#252](https://github.com/opentidehq/opentide/issues/252)).
- MCP `opentide://schemas/{object_type}` resolves `rule` / `rule::1.0` instead of returning `{}`, `opentide://templates/{object_type}` accepts the same forms for the current schema version, and vocabularies are JSON rather than Pydantic `repr()` strings ([#254](https://github.com/opentidehq/opentide/issues/254)).
- MCP `validate_query` returns real findings instead of `valid: true` for any string ([#245](https://github.com/opentidehq/opentide/issues/245)).
- `opentide-mcp` from a plain `pip install opentide` prints the install line for the `mcp` extra instead of a traceback, and `opentide setup mcp` warns when the extra is missing ([#256](https://github.com/opentidehq/opentide/issues/256)).
- `splunk::2.x` rules map `search`, `cron_schedule`, and flat throttling / notable / risk / email fields the same way in `validate` and `deploy`, and a migrated `cron_schedule` deploys as a scheduled search ([#233](https://github.com/opentidehq/opentide/issues/233)).
- Tutorial, quickstart, and CLI reference samples match live output ([#247](https://github.com/opentidehq/opentide/issues/247)).

### Tests

The CI harness now exercises the paths a first user takes, so these bugs fail CI if they return ([#259](https://github.com/opentidehq/opentide/issues/259)): interactive setup on a real PTY ([#260](https://github.com/opentidehq/opentide/issues/260)); `validate query` against the real validators ([#261](https://github.com/opentidehq/opentide/issues/261)); the wheel job runs `opentide-mcp` with and without the extra ([#262](https://github.com/opentidehq/opentide/issues/262)); a Typer argv matrix ([#263](https://github.com/opentidehq/opentide/issues/263)); unmocked MCP tests plus a stdio JSON-RPC client ([#264](https://github.com/opentidehq/opentide/issues/264)); hook tests that run `git commit` ([#265](https://github.com/opentidehq/opentide/issues/265)); unmocked `generate extract` / `generate explorer` ([#266](https://github.com/opentidehq/opentide/issues/266)); repo-relative `validate --file` ([#267](https://github.com/opentidehq/opentide/issues/267)); git-baseline e2e for HEAD-less and non-`main` repositories ([#268](https://github.com/opentidehq/opentide/issues/268)); assertions on GitLab and Azure job scripts ([#269](https://github.com/opentidehq/opentide/issues/269)); and every documented `opentide` command resolved against the live CLI, with read-only samples executed as golden tests ([#270](https://github.com/opentidehq/opentide/issues/270)).

### Not in this release

- [#189](https://github.com/opentidehq/opentide/issues/189) (`ThreatBody.impact` / `leverage` as `list[str]`) waits on [opentidehq/specifications#12](https://github.com/opentidehq/specifications/issues/12).

### Install

```bash
pip install opentide==0.4.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

Regenerate generated CI and hooks to pick up the fixed templates: `opentide setup ci <github|gitlab|azure> --yes` and `opentide setup hooks --yes`.

## [0.3.0] — 2026-09-21

Minor maintenance release on the public 0.2.1 beta. Upgrade for current runtime and toolchain floors (cryptography 50.x, typer 0.27) and a clean GitHub Code Quality pass.

### Changed

- Recreated stale Dependabot uv upgrades on current trunk ([#235](https://github.com/opentidehq/opentide/pull/235)): cryptography **50.0.1** (CVE-2026-69247), dulwich **1.2.15**, typer **0.27.2** (extra `all` was removed in 0.27; rich/shellingham/colorama are default deps), syrupy **5.5.3** (stay on 5.x), ruff **0.16.8**, ty **0.0.82** (dev extra only; `typing_extensions` stays a runtime dependency).
- Cleared GitHub Code Quality findings from the CodeQL `python-code-quality` suite ([#236](https://github.com/opentidehq/opentide/pull/236)).

### Install

```bash
pip install opentide==0.3.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.2.1] — 2026-09-18

Patch on the public 0.2.0 beta. Upgrade if you validate `threat.cve` identifiers or generate threat documentation that should link to CIRCL Vulnerability-Lookup.

### Added

- CVE validation and generated threat CVE tables use [CIRCL Vulnerability-Lookup](https://vulnerability.circl.lu) instead of scraping NVD through `mitrecve`. `opentide validate --check cve` looks up CVE, GHSA, and GCVE identifiers (`GET /api/vulnerability/{id}`); unknown IDs return empty JSON. Generated docs link to `https://vulnerability.circl.lu/vuln/{id}` and can enrich published date, severity, and aliases ([#109](https://github.com/opentidehq/opentide/issues/109)).
- `threat.cve` is a first-class optional list on the threat body, so schema validation accepts CVE identifiers. GNA 0 GCVE ids (`GCVE-0-YEAR-N`) map to the reserved CVE key.

### Changed

- Bundled `documentation.toml` `[cve]` defaults to Vulnerability-Lookup (`base_url` / `default_db_link`). Legacy NVD link prefixes are remapped. The CVE check stays **opt-in** (`--check cve`) so default `opentide validate` stays offline.

### Install

```bash
pip install opentide==0.2.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.2.0] — 2026-09-18

Minor on the public 0.1.8 beta. Upgrade if you generate templates or VS Code snippets — optional YAML now hugs `#` to each key, spacers stay blank, and rule `configurations` are commented platform stubs rather than `{}`.

### Changed

- `opentide generate templates` walks Pydantic `FieldInfo` instead of the JSON Schema `gen_template` walker. Optional sections are commented YAML blocks (`#` hugs each key; nested optionals are not commented again; spacer blanks stay blank), placeholders are typed (no `null`), nested bodies come from nested models, and rule `configurations` are commented platform stubs rather than `{}` ([#223](https://github.com/opentidehq/opentide/issues/223)).
- VS Code snippet conversion treats commented nested keys as mapping children, so `configurations:` with only `#sentinel:` stubs is not turned into a tabstop.

### Install

```bash
pip install opentide==0.2.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.8] — 2026-09-16

Patch on the public 0.1.7 beta. Upgrade if first-time `setup` / `generate` logged missing object folders as errors, dumped YAML `null`, attached live children under `#key:` parents, skipped platform TOML from `setup repo --platform`, emitted Title-Case UUID documentation paths, or looked up `objective.priority` in `criticality::1.0`.

### Added

- VS Code snippets use `tide-threat` / `tide-objective` / `tide-rule` / `tide-<platform>` prefixes, `scope: yaml`, descriptions, and tabstops on empty scalars. Missing core or enabled-platform templates fail loud ([#194](https://github.com/opentidehq/opentide/issues/194)).
- `opentide setup vscode --mcp` writes `.vscode/mcp.json` through the existing MCP helper. Parent `--vscode-setup` still does not imply MCP ([#193](https://github.com/opentidehq/opentide/issues/193)).

### Fixed

- Absent `objects/{threats,objectives,rules}` folders log at **debug**, once per path. Paths that exist but are not a directory still log at **error** ([#212](https://github.com/opentidehq/opentide/issues/212)).
- Optional template subtrees dumped as `#key:` now comment nested children, so `uuid` / `name` no longer attach to the previous mapping ([#209](https://github.com/opentidehq/opentide/issues/209)).
- Generated templates skip `default: None` (no YAML `null`) and restore typed placeholders ([#210](https://github.com/opentidehq/opentide/issues/210)).
- `opentide setup repo --platform` writes and enables `.opentide/configurations/platforms/*.toml`, so `generate` emits `#sentinel:` (and other) configuration stubs ([#211](https://github.com/opentidehq/opentide/issues/211)).
- Objective documentation renders `priority` as the author string. It is not looked up in `criticality::1.0` ([#204](https://github.com/opentidehq/opentide/issues/204)).
- GitHub/generic docs use lowercase `docs/{rules,objectives,threats}/<slug>.md`. UUID permalinks stay GitLab-only ([#203](https://github.com/opentidehq/opentide/issues/203)).

### Install

```bash
pip install opentide==0.1.8
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.7] — 2026-09-16

Patch on the public 0.1.6 beta. Upgrade if VS Code YAML reported "Matches multiple schemas", generated templates hid required nested fields, `setup vscode` skipped snippets or crashed on a missing path, JSON validate stamped every check failed, or `invalid_ref` pointed at parent objects.

### Fixed

- `invalid_ref` is attributed to the leaf UUID field. JSON `validate` reports per-check `status` (`uuid`, `metadata`, `schema`, `vocab`, `query`, `references`). Vocabulary names skip YAML list indices ([#186](https://github.com/opentidehq/opentide/issues/186)).
- VS Code `yaml.schemas` maps each object folder recursively (`objects/threats/**/*.yaml`) instead of the `opentide.schema.json` router glob, so nested files keep editor association ([#185](https://github.com/opentidehq/opentide/issues/185)).
- MCP templates use `servers` for VS Code 1.102+ / Cursor, host-specific `OPENTIDE_REPO_ROOT` (`${workspaceFolder}` vs `${CLAUDE_PROJECT_DIR}`), `.vscode/extensions.json`, and `AGENTS.md` ([#188](https://github.com/opentidehq/opentide/issues/188)).
- Template `$ref` / `$defs` expansion inlines nested object bodies. Nested `required` lists are no longer inherited from the parent, so required nested fields stay uncommented ([#191](https://github.com/opentidehq/opentide/issues/191)).
- `opentide setup vscode` generates templates and schemas before writing snippets, and fails if snippets were requested but could not be written ([#192](https://github.com/opentidehq/opentide/issues/192)).
- `opentide setup vscode` creates a missing target directory before generate, so `chdir` no longer raises `FileNotFoundError` ([#200](https://github.com/opentidehq/opentide/pull/200)).

### Install

```bash
pip install opentide==0.1.7
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.6] — 2026-09-15

Patch on the public 0.1.5 beta. Upgrade if `opentide generate` crashed on unquoted YAML dates, or if interactive `opentide setup` crashed after choosing a CI provider.

### Fixed

- Unquoted `YYYY-MM-DD` values in `metadata.created` / `modified` no longer crash `opentide generate` with `TypeError: Object of type date is not JSON serializable`. The YAML loader stringifies timestamps so export JSON matches the schema's string dates ([#178](https://github.com/opentidehq/opentide/issues/178)).
- Interactive `opentide setup` no longer raises `ValueError: validate must be callable` on the CI workflow features checkbox. Optional Questionary checkboxes omit `validate` ([#177](https://github.com/opentidehq/opentide/issues/177)).

### Install

```bash
pip install opentide==0.1.6
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.5] — 2026-09-13

Patch on the public 0.1.4 beta. Upgrade if you regenerate ATT&CK or MISP vocabularies, or if you run the weekly ingest workflow.

### Added

- Weekly (and `workflow_dispatch`) ingest for MITRE ATT&CK STIX and MISP threat actors. Vocabularies merge with per-key RFC 0003 versions; schema pins for techniques, actors, and datasources bump in the same PRs. `uv run python scripts/vocabulary/sync_upstream.py --check|--apply`.

### Fixed

- ATT&CK groups are catalog-only (`att&ck.groups`); live objects pin them via `threat.actors.name` → `actors::*`. Ingest no longer reports pin bumps for vocabs that no pin file references (`att&ck.groups`, `mitigations`).
- Weekly ingest fetches `chore/vocab-upstream` before `git push --force-with-lease` so later cycles can update the specifications branch.

### Install

```bash
pip install opentide==0.1.5
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.4] — 2026-09-13

Patch on the public 0.1.3 beta. Upgrade if `opentide generate` crashed with `'str' object has no attribute 'get'` on `threat.actors`, or if you authored actors as vocabulary ID strings.

### Fixed

- `threat.actors` is a list of objects (`name` is a scoped actors-vocabulary ID such as `att&ck::G0006`; optional `sighting` and `references`), matching CoreTide. Generated JSON Schema no longer teaches `list[str]`. `opentide generate` no longer crashes calling `.get` on a string ([#172](https://github.com/opentidehq/opentide/issues/172)).
- Nested vocabulary fields (for example threat leverage / viability and objective composition) are validated against the pinned vocabs instead of being skipped.
- Explorer export uses timezone-aware UTC so the package imports on Python 3.10.

### Install

```bash
pip install opentide==0.1.4
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.3] — 2026-09-11

Patch on the public 0.1.2 beta. Upgrade if you ran `setup ci`, `deploy` / `validate query` locally, followed the tutorial, or installed without Azure/pandas extras.

### Fixed

- `opentide setup ci` emits parseable GitHub, GitLab, and Azure YAML. `textwrap.dedent` no longer strips indentation from already-indented step blocks ([#163](https://github.com/opentidehq/opentide/issues/163)).
- `opentide deploy` and `validate query` no longer crash locally when `DEPLOYMENT_PLAN` is unset. Unset or blank env defaults to `FULL`; illegal names fail with a clear error. Local debug compiles from the rules folder; PRODUCTION promotion is skipped for `--dry-run` and LocalDebug ([#164](https://github.com/opentidehq/opentide/issues/164)).
- Tutorial objects validate and lint: required `metadata.created` / `modified`, severity vocabulary, filenames matching `slugify(name)`, nested organisation and author. `setup` scaffolds `docs/Rules`, `docs/Objectives`, and `docs/Threats`. Templates emit `YYYY-MM-DD` dates. `generate docs` joins relative docs paths against the repository root ([#165](https://github.com/opentidehq/opentide/issues/165)).
- `opentide info` reports `can_deploy: true` after a base `pip install` (no Azure/pandas extras). Platforms lazy-load optional SDKs; `requests` is a core dependency. Tenant `[platform]` identity is not parsed as a detection-rule schema. Coverage counts top-level `techniques`. `generate extract` runs the installed package modules ([#166](https://github.com/opentidehq/opentide/issues/166)).

### Install

```bash
pip install opentide==0.1.3
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.2] — 2026-09-11

Patch on the public 0.1.1 beta. Upgrade if you scaffold new detection repos, generate on an empty catalogue, or install agent skills.

### Added

- Generated GitHub, GitLab, and Azure pipelines from `opentide setup ci` now set `OPENTIDE_REPO_ROOT` for every job (`github.workspace`, `$CI_PROJECT_DIR`, `$(Build.SourcesDirectory)`) ([#51](https://github.com/opentidehq/opentide/issues/51)).
- `opentide setup env` writes `.env.example` with `OPENTIDE_REPO_ROOT` and adds `.env` to `.gitignore` ([#48](https://github.com/opentidehq/opentide/issues/48)).
- `opentide setup hooks` writes a local pre-commit hook that runs `opentide validate --strict` and installs it into `.git/hooks` when the path is a Git repository ([#49](https://github.com/opentidehq/opentide/issues/49)).
- `opentide lint` reports filename slug mismatches (`slugify(name)`) and missing recommended metadata. `--fix` renames files; `--strict` is the CI gate ([#108](https://github.com/opentidehq/opentide/issues/108)).
- `opentide migrate objects` dry-runs (default) or applies (`--apply`) moves from CoreTide `Configurations/` and `Objects/` paths into `.opentide/configurations/` and `objects/` ([#100](https://github.com/opentidehq/opentide/issues/100)).

### Changed

- `opentide setup skills` discovers the catalogue from the live [opentidehq/skills](https://github.com/opentidehq/skills) `manifest.json` and installs skill trees from that repository. The wheel no longer ships a stale catalogue snapshot or starter `SKILL.md` files. If GitHub is unreachable, discover / show / install fail with an actionable error instead of installing outdated copies ([#152](https://github.com/opentidehq/opentide/issues/152)).

### Fixed

- `opentide generate` on a freshly scaffolded repository no longer crashes in snippet generation (`AttributeError: SimpleNamespace has no attribute 'subschemas'`). Platform templates are resolved from `platform_templates` (with a legacy `subschemas` alias), missing template files are skipped, and an empty object catalogue is treated as a valid export rather than an error ([#153](https://github.com/opentidehq/opentide/issues/153)).

### Install

```bash
pip install opentide==0.1.2
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.1] — 2026-09-11

Patch for the public 0.1.0 wheel. Upgrade if you installed from PyPI and hit `UnicodeDecodeError` on `validate` / `generate`, or if `opentide setup skills discover` started an install wizard.

### Fixed

- `opentide generate` and `opentide validate` no longer crash with `UnicodeDecodeError` when pip has compiled `__pycache__` next to bundled configuration TOMLs. Nested configuration directories load `*.toml` only (same class of fix as [#150](https://github.com/opentidehq/opentide/pull/150)).
- `opentide setup skills discover` and `show` are parsed as subcommands. A positional PATH on the skills group was consuming those names (and prompting for an install).
- Starter skill install (`opentide-detection-rule`, `detection-engineering`) falls back to the packaged skill trees when GitHub is unreachable.

### Install

```bash
pip install opentide==0.1.1
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

## [0.1.0] — 2026-09-09

First public release of the DetectionOps engine as a **PyPI package**. This is a beta (`Development Status :: 4 - Beta`), not a 1.0. The old engine and companion repos are archived; pinned CoreTide submodules still resolve.

### Added

- Install with `pip install opentide` (Python 3.10–3.14). One wheel: CLI (`opentide`), MCP server (`opentide-mcp`), SDK (`from opentide import Opentide`), and seven platform adapters.
- `opentide setup` scaffolds a detection repository, CI (GitHub, GitLab, Azure DevOps), MCP client config, and agent skills.
- `opentide validate`, `generate`, `deploy`, and `document` as the operator surface. `--strict` is the CI gate.
- Query syntax validation on five platforms: Sentinel, Defender for Endpoint, Splunk, SentinelOne, Carbon Black Cloud. CrowdStrike and HarfangLab **deploy only** — the CLI and MCP report `supported: false` and do not fake a pass.
- Object model: threat → objective → rule, generated JSON Schema from the models, vocabularies as versioned TOML.
- Public companion repos: [specifications](https://github.com/opentidehq/specifications), [library](https://github.com/opentidehq/library), [explorer](https://github.com/opentidehq/explorer), [skills](https://github.com/opentidehq/skills). Docs: [opentide.org](https://opentide.org).

### Changed

- The engine is no longer consumed as a git submodule. Pin a package version instead of a SHA.
- Platform flags use `--platform` (not `--system`).

### Migration

There is no `opentide migrate`. Drop the CoreTide submodule, depend on this package, replace `Orchestration/` scripts with the CLI, set `OPENTIDE_REPO_ROOT`, run `opentide validate --strict`. Guide: [Usage → Migration](https://opentide.org/docs/usage/migration/).

### Stabilization

For four weeks after this release, work is bugs, docs, deployers, agent setup, and migration questions — not new platforms.

### Install

```bash
pip install opentide==0.1.0
export OPENTIDE_REPO_ROOT=/path/to/detection-repo
opentide validate --strict
```

[Unreleased]: https://github.com/opentidehq/opentide/compare/v0.23.0...HEAD
[0.23.0]: https://github.com/opentidehq/opentide/releases/tag/v0.23.0
[0.22.0]: https://github.com/opentidehq/opentide/releases/tag/v0.22.0
[0.21.0]: https://github.com/opentidehq/opentide/releases/tag/v0.21.0
[0.20.1]: https://github.com/opentidehq/opentide/releases/tag/v0.20.1
[0.20.0]: https://github.com/opentidehq/opentide/releases/tag/v0.20.0
[0.19.0]: https://github.com/opentidehq/opentide/releases/tag/v0.19.0
[0.18.0]: https://github.com/opentidehq/opentide/releases/tag/v0.18.0
[0.17.2]: https://github.com/opentidehq/opentide/releases/tag/v0.17.2
[0.17.1]: https://github.com/opentidehq/opentide/releases/tag/v0.17.1
[0.17.0]: https://github.com/opentidehq/opentide/releases/tag/v0.17.0
[0.16.1]: https://github.com/opentidehq/opentide/releases/tag/v0.16.1
[0.16.0]: https://github.com/opentidehq/opentide/releases/tag/v0.16.0
[0.15.0]: https://github.com/opentidehq/opentide/releases/tag/v0.15.0
[0.14.2]: https://github.com/opentidehq/opentide/releases/tag/v0.14.2
[0.14.1]: https://github.com/opentidehq/opentide/releases/tag/v0.14.1
[0.14.0]: https://github.com/opentidehq/opentide/releases/tag/v0.14.0
[0.13.0]: https://github.com/opentidehq/opentide/releases/tag/v0.13.0
[0.12.1]: https://github.com/opentidehq/opentide/releases/tag/v0.12.1
[0.12.0]: https://github.com/opentidehq/opentide/releases/tag/v0.12.0
[0.11.0]: https://github.com/opentidehq/opentide/releases/tag/v0.11.0
[0.10.0]: https://github.com/opentidehq/opentide/releases/tag/v0.10.0
[0.9.0]: https://github.com/opentidehq/opentide/releases/tag/v0.9.0
[0.8.2]: https://github.com/opentidehq/opentide/releases/tag/v0.8.2
[0.8.1]: https://github.com/opentidehq/opentide/releases/tag/v0.8.1
[0.8.0]: https://github.com/opentidehq/opentide/releases/tag/v0.8.0
[0.7.0]: https://github.com/opentidehq/opentide/releases/tag/v0.7.0
[0.6.4]: https://github.com/opentidehq/opentide/releases/tag/v0.6.4
[0.6.3]: https://github.com/opentidehq/opentide/releases/tag/v0.6.3
[0.6.2]: https://github.com/opentidehq/opentide/releases/tag/v0.6.2
[0.6.1]: https://github.com/opentidehq/opentide/releases/tag/v0.6.1
[0.6.0]: https://github.com/opentidehq/opentide/releases/tag/v0.6.0
[0.5.0]: https://github.com/opentidehq/opentide/releases/tag/v0.5.0
[0.4.0]: https://github.com/opentidehq/opentide/releases/tag/v0.4.0
[0.3.0]: https://github.com/opentidehq/opentide/releases/tag/v0.3.0
[0.2.1]: https://github.com/opentidehq/opentide/releases/tag/v0.2.1
[0.2.0]: https://github.com/opentidehq/opentide/releases/tag/v0.2.0
[0.1.8]: https://github.com/opentidehq/opentide/releases/tag/v0.1.8
[0.1.7]: https://github.com/opentidehq/opentide/releases/tag/v0.1.7
[0.1.6]: https://github.com/opentidehq/opentide/releases/tag/v0.1.6
[0.1.5]: https://github.com/opentidehq/opentide/releases/tag/v0.1.5
[0.1.4]: https://github.com/opentidehq/opentide/releases/tag/v0.1.4
[0.1.3]: https://github.com/opentidehq/opentide/releases/tag/v0.1.3
[0.1.2]: https://github.com/opentidehq/opentide/releases/tag/v0.1.2
[0.1.1]: https://github.com/opentidehq/opentide/releases/tag/v0.1.1
[0.1.0]: https://github.com/opentidehq/opentide/releases/tag/v0.1.0
