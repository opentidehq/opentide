# Oracles

CI-only checks that compare the opentide engine with the parser each query language is defined by. They answer one question: where does our engine disagree with Microsoft or Splunk, and is every disagreement known?

| Language | Reference | Runs as | Job |
| --- | --- | --- | --- |
| KQL | Microsoft Kusto.Language 12.4.1 (`KustoCode.Parse`, `GlobalState.Default`) | `kusto/`, a NuGet-locked .NET 10 console tool | `oracle.yml` → Kusto.Language |
| SPL | Splunk Enterprise 10.6.1 `search/parser` REST endpoint, `searchbnf.conf` | `splunk/splunk:10.6.1` service container | `oracle.yml` → Splunk |
| ES\|QL | `@elastic/esql` 4.33.0 (`Parser.parseErrors`) | `elastic/esql.cjs`, npm-locked in `elastic/package-lock.json` | `oracle.yml` → Elastic and Lucene |
| EQL | Elasticsearch `EqlBase.g4` at `2c85bbdf`, generated with antlr-ng 1.0.10 (the grammar has no actions) | `elastic/eql.mjs` | `oracle.yml` → Elastic and Lucene |
| Kibana KQL (`kuery`) | Kibana `grammar.peggy` at `ea2712af`, compiled with peggy 5.1.1 | `elastic/kuery.cjs` | `oracle.yml` → Elastic and Lucene |
| Lucene | Lucene 10.5.2 `QueryParser` (the version Elasticsearch pins), leading wildcards on | `elastic/LuceneOracle.java` | `oracle.yml` → Elastic and Lucene |
| Lucene, Graylog | Graylog 7.2.2 and 6.3.5 `POST /api/search/validate` (`status` OK, WARNING or ERROR) | `graylog/probes.py`, with `OPENTIDE_GRAYLOG_URLS` (comma-separated base URLs), `OPENTIDE_GRAYLOG_USER` and `OPENTIDE_GRAYLOG_PASSWORD`; it records `testdata/oracles/graylog/expected.tsv` (`--write`) or compares with it | locally; `crates/opentide-lucene/tests/graylog_verdicts.rs` holds the Graylog dialect to the recorded verdicts in `cargo test`, with its exceptions listed there |
| Lucene, Carbon Black Cloud | A Carbon Black Cloud tenant's `processes/search_validation` (`valid`, `invalid_message`, `error_offset`), as cbc_sdk's `validate_process_query` calls it | `oracle.py carbon_black`, with `OPENTIDE_CBC_URL`, `OPENTIDE_CBC_ORG_KEY` and `OPENTIDE_CBC_TOKEN` (`<api secret>/<api id>`, `org.search.events` READ) | `oracle.yml` → Carbon Black Cloud, weekly and on demand; it skips without the secrets and never runs on a pull request |
| Falco | `falco --validate`: Falco 0.45.2 (libs 0.26.1), `falcosecurity/falco:0.45.2`, with the three default rules files of `falcosecurity/rules@e7b066bf` loaded | `falco/oracle.py`, one Falco process per case in one container | `oracle.yml` → Falco 0.45.2; see [Falco](#falco) |
| CQL (CrowdStrike) | None in CI. CQL is closed source: there is no parser to port, LogScale self-hosted needs a licence key and Kafka, and Community Edition sign-up closed in 2024. A tenant is the only reference: LogScale's GraphQL `validateQuery` (diagnostics without positions), or a Next-Gen SIEM query job that fails with HTTP 400 | — | the engine follows CrowdStrike's published grammar and function reference, measured on 2,846 public queries; see [docs/engine/CQL.md](../../../docs/engine/CQL.md) |
| Exabeam Query Language | None in CI. Exabeam's search language is closed source: Exabeam publishes no grammar and no parser, and the only reference is a tenant's Search API (`POST /search/v2/events`, which `opentide validate query --live` calls). The specification's reference checker (`scripts/engine/exabeam_language.py` in opentidehq/specifications) stands in: its verdicts on every conformance query are recorded in `crates/testdata/conformance/exabeam/reference.json` (`scripts/engine/sync_exabeam_conformance.py`) and held by `cargo test` | — | measured on Exabeam's 2,371 published correlation rules, which may not be redistributed; see [docs/engine/EXABEAM.md](../../../docs/engine/EXABEAM.md) |
| YARA | libyara 4.5.4 (`yara-python` 4.5.4: `yara.compile`, warnings by `error_on_warning`) and YARA-X 1.23.0 (the `yara-x` wheel: `Compiler.add_source`, `build`) | `yara/oracle.py`, each verdict in a child process with 2 GB and 20 s | `oracle.yml` → libyara and YARA-X; see [YARA](#yara) |
| YARA-L (Google SecOps) | None offline. Google publishes no grammar, compiler or reference parser for YARA-L; the only reference is a tenant's `verifyRuleText` (Chronicle API v1, `POST <endpoint>/v1/projects/<p>/locations/<l>/instances/<i>:verifyRuleText`, permission `chronicle.rules.verifyRuleText`), which compiles a rule without creating it | — | none yet; see [YARA-L](#yara-l). The engine follows yara-l-1.0 and Google's pages, measured on chronicle/detection-rules' 410 community rules ([docs/engine/YARAL.md](../../../docs/engine/YARAL.md)) |
| Tide YAML | Pydantic models of this repository's `opentide` package (`src/opentide`) | `scripts/engine/pydantic_object_issues.py` | `ci.yml`, job `engine` (`cargo test`, `tide_corpus.rs`) |
| EQL, ES\|QL, Lucene | A live Elasticsearch (8.19 and 9.x release images) | `elasticsearch/`, a throwaway container | `oracle.yml` (8.19.23 and 9.5.5), and locally for the other lines; see [Live Elasticsearch](#live-elasticsearch) |

Tide YAML already has its oracle: `tide_corpus.rs` runs the opentide CLI's Pydantic models and requires the LSP to report every issue they find. Configuration TOML gets the same treatment in `#68`. The Elastic references are fetched at CI time: the npm packages from `elastic/package-lock.json` (`npm ci --ignore-scripts`), and `EqlBase.g4`, `grammar.peggy`, and the Lucene jars by URL with a pinned SHA-256 (`FETCH` in `oracle.py`), cached in `elastic/.cache/`. None of them is committed. CQL and the Exabeam Query Language have none (their rows above say why). Later languages (S1QL, Sigma) get an oracle when they get an engine; see `.agents/skills/add-language/SKILL.md`.

## What is compared

`oracle.py` gathers every query in the corpus:

- `crates/testdata/corpus/<lang>/*` (fixture tag line removed, as `corpus_gate.rs` does)
- `crates/testdata/conformance/external/<lang>/*`, including the `.broken.` twins
- `crates/testdata/conformance/perf/*`
- `crates/testdata/conformance/columns/*` (KQL: one column or type error each)
- `crates/testdata/oracles/<lang>/*`, one probe per form real detections use
- every `configurations.{sentinel,defender_for_endpoint,splunk}` query in a Tide rule under `crates/testdata/` (and the legacy `configurations.splunk.search`), and every `response.procedure.searches[]` query whose `system` is one of those platforms, as YAML loads them (folded, quoted). A drilldown search is not a query
- Elastic: `configurations.elastic.query` and `threat.query` in the language their `type` and `language` select, `response.procedure.searches[]` entries with `system: elastic` and a `language`, the verdict tables `crates/testdata/conformance/external/{lucene-queryparser,kuery-opensearch-dashboards}/cases.tsv`, and, when `OPENTIDE_DETECTION_RULES` names an `elastic/detection-rules` checkout (CI pins one), every rule and single-language hunt in it

Each query runs through `opentide-lsp analyze` and through the reference.

Carbon Black Cloud (`carbon_black`) gathers its own corpus: `crates/testdata/conformance/external/lucene-carbon-black/*` with the twins, the probes in `crates/testdata/oracles/carbon_black/`, and every `configurations.carbon_black_cloud.query` and `system: carbon_black_cloud` hunt in a Tide rule under `crates/testdata/`, with its lines joined as deploy joins them. Ours runs `opentide-lsp analyze --platform carbon_black_cloud` and rejects a query on an error-severity syntax code or a `cbc_unknown_field`; the tenant rejects it when `valid` is false. Disagreements go in `[[carbon_black]]` entries of `exceptions.toml`.

**Verdicts.** Ours rejects a query when it reports `kql_parse_error` or `kql_unknown_operator` (`spl_parse_error` or `spl_unknown_command` for SPL, at any severity: an unknown command is a warning because an app may provide it, but Splunk without that app rejects it; for the Elastic languages, an error-severity syntax code from `REJECT` in `oracle.py`, which leaves out checks Elasticsearch makes after parsing). The reference rejects it when it reports an error. A query where they differ must be listed by path in `crates/testdata/oracles/exceptions.toml`. A `.broken.` fixture the reference accepts always fails: its injected fault breaks nothing. A probe in `crates/testdata/oracles/<lang>/` is a valid detection form, so any error-severity diagnostic from ours on it fails too (an unknown table or function there is a false positive).

**KQL columns and types.** `KustoOracle semantic` analyzes every KQL query against a database `oracle.py` builds from the engine's own catalogs (the Azure Monitor tables, the hand-written columns, the standard Log Analytics columns, the ASIM parsers). Every `kql_unknown_column` and `kql_type_mismatch` ours reports must be an error Kusto.Language reports too: the name it does not know, or KS106/KS107 for an operator it does not define for the types. Each fixture in `crates/testdata/conformance/columns/` must make ours report one, so the check is never vacuous. The reverse is not compared: ours stays silent on purpose wherever a column may exist that the catalog does not list (`docs/engine/kql/columns.md`).

**Names.** KQL: `data/catalogs/kql/core/functions.toml` and `evaluate-plugins.toml` against the functions, aggregates and plugins in Kusto.Language's `GlobalState.Default`, plus any name ours flags `kql_unknown_function` that Kusto.Language knows. SPL: `data/catalogs/spl/commands.toml` against the `*-command` stanzas and aliases in `searchbnf.conf`, plus any name ours flags `spl_unknown_command` that Splunk knows. Every disagreeing name must be listed.

A listed path or name that no longer disagrees fails as stale, so the exceptions file is the exact ledger of known gaps. Fix a gap and delete its entry in the same change. When a check fails, the output ends with the unlisted items as TOML to start from.

## Splunk setup

The parser expands macros and resolves data models, so `oracle.py` defines them in the container first:

- macros from `splunk/macros.toml`. ESCU macros are copied from `splunk/security_content` (Apache-2.0); CIM helpers are one-line stand-ins. Any `` `<detection>_filter` `` macro is defined as `search *`, which is what ESCU generates.
- data models built from `data/catalogs/spl/datamodels.toml`, one dataset per entry with its fields. A data model the catalog lacks is a real disagreement.

Text that does not start with `|` is sent as `search <text>`, which is how Splunk runs authored SPL (`docs/engine/spl/README.md`). The engine sees the authored text unchanged.

## Running locally

Both are optional. `scripts/engine/ci-oracle.sh` skips a language whose reference is missing unless `OPENTIDE_ORACLE_REQUIRED=1`.

```bash
# KQL: needs the .NET 10 SDK, cargo and PyYAML
bash scripts/engine/ci-oracle.sh kql

# SPL: needs Docker. Starting the container accepts the Splunk General Terms.
eval "$(bash scripts/engine/oracles/splunk/start.sh)"
bash scripts/engine/ci-oracle.sh spl
```

## Live Elasticsearch

The Elastic oracles in `elastic/` (Elasticsearch's EQL grammar, `@elastic/esql`, Kibana's kuery grammar, Lucene's classic query parser) answer "does it parse". Most of what the EQL and ES|QL engines check happens after parsing: the Verifier's argument types, field-to-field comparisons rejected when a filter becomes a query, the per-release grammar of each 8.19 and 9.x line, `runs` and `until` rules, the expression-depth guard, regular expressions compiled on a shard, and what `query_string` throws with `lenient` on or off. Only a running cluster answers those, so this is a third kind of reference: a release image of Elasticsearch, started on this machine.

```bash
eval "$(bash scripts/engine/oracles/elasticsearch/start.sh 9.3.0)"      # any tag of the official image
python3 scripts/engine/oracles/elasticsearch/run.py --language eql DIR    # or esql, lucene
python3 scripts/engine/oracles/elasticsearch/probes.py                    # the recorded probes
python3 scripts/engine/oracles/elasticsearch/esql_catalog.py              # data/catalogs/esql versions vs this release
```

`start.sh` pulls `mirror.gcr.io/library/elasticsearch:<tag>`, falling back to Docker Hub and then `docker.elastic.co` when a registry refuses after its retries (set `ES_IMAGE` to use one registry only), binds 127.0.0.1 only, runs single-node with security off, a basic licence (EQL and ES|QL are basic features), a 1 GB heap, ML off and disk watermarks off. Set `ES_PORT` to run two releases side by side.

**Fixture.** `run.py` waits for cluster health yellow, then creates `opentide-ecs` (alias `o`) mapped from `data/catalogs/ecs/fields.json`, so the Verifier sees real ECS types, and an empty `opentide-unmapped` (alias `u`) for files named `*.unmapped.*`. `object` and `nested` entries are not mapped themselves (a nested parent's children become plain object fields), and `match_only_text` children of keyword fields become multi-fields, as in ECS. `--extra-mapping` adds `{"field": "type"}` pairs.

**Requests.** EQL: `POST o/_eql/search` with `size: 1`. `size: 0` lets the planner answer with an empty result before it translates the filter, which hides the field-to-field comparison error; the index holds no documents, so `size: 1` costs nothing. ES|QL: `POST /_query`. Every `FROM` / `TS` source list is rewritten to the alias in place: the pattern list is blanked to spaces and its first characters become `o` (keeping a `cluster:` prefix and a `::selector`), so every line and column Elasticsearch reports matches the authored text. `x.esql.params.json` beside a file is sent as `params`. Lucene: a `query_string` search with `size: 0`, `default_field: *`, `allow_leading_wildcard: true`, and `lenient: false`; a fourth column repeats the verdict with `lenient: true`, which is how detection rules run (`--lucene-verdict strict|lenient` prints one verdict in the three-column format).

**Verdicts.** `OK`, or `ERR` with Elasticsearch's error type and reason. A problem that exists only because the fixture is not a real cluster is `OK` with an `unverified:` note: `Unknown column [x]` where `x` is not mapped in the fixture, `No matches found for pattern` that matches no mapped field, an unknown index, enrich policy, lookup index, or inference endpoint, and the cross-cluster licence check, and a command that needs a licence above basic (`CHANGE_POINT`). `Unknown column [x]` for a mapped `x` is an error: the query itself dropped the column (`KEEP`, `STATS`, a misspelt `EVAL` name). Parse errors (`parsing_exception`), every other Verifier problem, and errors raised while a shard builds the query (`query_shard_exception`, the EQL comparison-against-fields error) are `ERR`. Both Verifiers stop after unresolved names, so an `unverified` query may hide a type error behind them. Lucene has no such note but the same blind spot: `query_string` builds nothing, so checks nothing (not even a regexp), for a field the index does not map. A `circuit_breaking_exception` is the fixture's 1 GB heap, so it is `unverified` too; `--skip-larger` keeps a huge query (9.3.0 runs out of heap on a 250 KB SigmaHQ Lucene query) from killing the node.

`--assume-unmapped` retries such a query: EQL marks the unmapped fields optional (`?field`, null), ES|QL maps them as `keyword` in a side index, and Lucene maps every unmapped `field:` as `keyword` before it runs. Problems that name an assumed field stay `unverified`; the note starts with `assumed:` either way. Use it for corpora written against non-ECS fields (SigmaHQ conversions), not for probes.

**Probes.** `crates/testdata/oracles/elasticsearch/<topic>/` holds one minimal query per file for each behaviour the engines encode from Elasticsearch's source (EQL argument types and field comparisons, `runs`, `until`, comments, regex, depth; ES|QL syntax gates; Lucene fuzziness, regexp, and leniency). `expected.tsv` records each probe's verdict per release line (recorded on 8.19.23, 9.0.8, 9.1.10, 9.2.8, 9.3.8, 9.4.8, and 9.5.5; 9.3.0 differs on the EQL and ES|QL expression-depth probes, which it accepts); `probes.py` fails when the running release disagrees and `--update` records a new line. `esql_catalog.py` sends one query per command, function, alias, and cast in `data/catalogs/esql/` and prints every name whose `versions` list disagrees with the release. `crates/opentide-analysis/tests/live_elasticsearch_probes.rs` holds the engines to `expected.tsv` without a cluster: a probe every release rejects needs an error, one every release accepts must have none, and one only some releases accept needs a non-error diagnostic. Its `EXCEPTIONS` list (mapping-dependent probes, 9.6-only syntax) must stay exact. `scripts/engine/sync_esql_catalog.py` folds live catalog findings into `versions` (`LIVE_FUNCTION_RELEASES`, and no `date` cast on 9.0).

Nothing from this reference is shipped or vendored; the image is pulled at run time.

## Not shipped

Kusto.Language, Splunk, Splunk SDKs, the Elastic and Lucene references, the `yara-x` compiler crate and `yara-python` never enter a release artifact. `ci-oracle.sh` fails if a shipped manifest depends on one, and the engine release (`.github/workflows/engine-release-build.yml`, also run as ci.yml's dry run in its full set and on a pull request that changes the release's inputs) runs `scripts/engine/license-scan.sh` over every artifact (unpacking zips and `.crate` files) before it attaches or publishes them.

## Falco

`falco/oracle.py` runs every case through the real Falco and through the engine, and compares them. A case is one Falco rule: a condition, its output, exceptions, the macros and lists it defines, or a tuning (`append_to_rule`). It becomes a Falco rules file (its lists and macros as real `- list:` / `- macro:` items, so Falco resolves them itself, then the rule or an `override: append` of a default rule) and an opentide rule with the same `configurations.sysdig` block, which `opentide-lsp analyze` checks. Falco validates each file with the three default rules files loaded first (`falco_rules.yaml`, `falco-incubating_rules.yaml`, `falco-sandbox_rules.yaml`), in its own process: a load failure carries over to the files after it in one run.

A case agrees when Falco loads it exactly when the engine reports no error (`falco_*` or the block's `sysdig_*` constraint codes), and when Falco's `LOAD_NO_EVTTYPE` matches the engine's `falco_no_evttype`. The corpora are `crates/testdata/oracles/falco/cases.yaml`, one or more cases per row of `docs/engine/FALCO.md`, and the conditions of the Falco default rules (`crates/testdata/conformance/external/falco/syscall/`) with their broken twins.

Two differences are documented, and the oracle counts them apart: Falco OSS refuses a macro or list it does not define (`Undefined macro`), and an append to a rule it does not have; on a Sysdig tenant either may be one Sysdig manages, so the engine warns (`falco_unknown_macro`, `falco_unknown_list`, `falco_unknown_rule`). Nothing else is allowed to differ. A case may also list `engine_warnings` it requires (`sysdig_list_self_reference` on a list naming itself), which Falco has no code for.

Pins: Falco `0.45.2` (the `falcosecurity/falco` image), rules `falcosecurity/rules@e7b066bfbc8d81226ca5fa3e95ffd4dee38a2428`. Bump both in `oracle.yml` and here together. Plugin sources (`k8s_audit`, `aws_cloudtrail`, ...) are not compared: the image ships only the container plugin.

```bash
python scripts/engine/oracles/falco/oracle.py --rules ../falcosecurity-rules --docker falcosecurity/falco:0.45.2 --report report.json
```

## YARA

`yara/oracle.py` makes two checks, with the pins `yara-python==4.5.4` and `yara-x==1.23.0` (it refuses other versions):

1. Every verdict recorded in `crates/testdata/conformance/yara/cases.json` (1,762 cases from YARA-X's `lib/src/tests/mod.rs` and compiler `errors`/`warnings` suites, and libyara's `tests/test-rules.c`, written by `scripts/engine/sync_yara_conformance.py`) is what the live engines say. `crates/opentide-yara/tests/conformance.rs` holds the engine to those verdicts in every `cargo test`, so the oracle only keeps them honest.
2. Every YARA file of the repository (`crates/testdata/corpus/yara`, `crates/testdata/conformance/external/yara` with its `.broken.` twins, YARA-X's parser suite in `crates/testdata/conformance/yara-x/parser`) goes through `opentide-lsp analyze --language yara` and both references.

A file agrees when the engine reports an error exactly when libyara refuses it (`yara_empty_signature` aside: libyara compiles a file of private rules), and reports `yara_x_incompatible` (or `yara_entrypoint_deprecated`) exactly when libyara compiles it and YARA-X refuses it. A disagreement fails unless a `[[yara]]` entry of `crates/testdata/oracles/exceptions.toml` lists it, with `check` naming the verdict that differs (`libyara`, `yara_x` or `both`); `conformance.rs` reads the entries whose paths are `cases.json#<origin>`. A listed path that agrees fails too. The four entries are an unterminated `/*` (libyara drops the rest of the text silently), a case libyara runs out of memory on, YARA-X's regexp size limit, and libyara's test-only `tests` module.

Neither package ships: `scripts/engine/ci-oracle.sh` refuses the `yara-x` compiler crate (and its `wasmtime`) or `yara-python` in a shipped manifest, and `scripts/engine/license-scan.sh` in a release artifact. The engine parses with `yara-x-parser`, which is not the compiler.

```bash
pip install yara-python==4.5.4 yara-x==1.23.0
cargo build -p opentide-lsp
python3 scripts/engine/oracles/yara/oracle.py --report report.json
```

## YARA-L

There is no offline reference. Google SecOps compiles YARA-L only in a tenant, and its documentation has no grammar. The checks the engine makes are the ones yara-l-1.0 derives from Google's pages; Google's community rules (chronicle/detection-rules, `crates/testdata/conformance/external/yaral/`) stand in for verdicts: a rule Google publishes is taken to compile, and each `.broken.` twin carries a fault Google's pages say the compiler refuses.

An opt-in tenant job is the planned reference, as the Carbon Black Cloud job is: a `yaral` mode in `oracle.py`, run weekly and on demand by `oracle.yml` only when a sandbox tenant's secrets are set, never on a pull request. It would send each rule of the corpus (the community rules, their twins, the `rule` fixtures under `crates/testdata/corpus/yaral/`, and every Google SecOps block of a Tide rule under `crates/testdata/`, assembled as deploy assembles it) to `verifyRuleText` and compare: the tenant rejects a rule when the response has no `success: true` or holds a diagnostic with `severity: ERROR`; ours rejects it on an error-severity `yaral_*` code. Every disagreement would be a `[[yaral]]` entry of `exceptions.toml`. Searches would go through `validateQuery`. The job needs, as secrets of the workflow and never in the repository: `OPENTIDE_SECOPS_ENDPOINT` (`https://<location>-chronicle.googleapis.com`), `OPENTIDE_SECOPS_INSTANCE` (`projects/<project>/locations/<location>/instances/<customer id>`), and a service-account key with only `chronicle.rules.verifyRuleText` (and `chronicle.events.validateQuery`) on a sandbox instance. A tenant resolves reference lists and data tables, which the offline check cannot: the job's rules must use none, or the sandbox must define them. No credential is shipped, and the job is not wired yet.
