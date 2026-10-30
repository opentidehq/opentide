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
| Tide YAML | Pydantic models in the pinned `opentide` package | `scripts/pydantic_object_issues.py` | `ci.yml` (`cargo test`, `tide_corpus.rs`) |
| EQL, ES\|QL, Lucene | A live Elasticsearch (8.19 and 9.x release images) | `elasticsearch/`, a throwaway container | `oracle.yml` (8.19.23 and 9.5.5), and locally for the other lines; see [Live Elasticsearch](#live-elasticsearch) |

Tide YAML already has its oracle: `tide_corpus.rs` runs the opentide CLI's Pydantic models and requires the LSP to report every issue they find. Configuration TOML gets the same treatment in `#68`. The Elastic references are fetched at CI time: the npm packages from `elastic/package-lock.json` (`npm ci --ignore-scripts`), and `EqlBase.g4`, `grammar.peggy`, and the Lucene jars by URL with a pinned SHA-256 (`FETCH` in `oracle.py`), cached in `elastic/.cache/`. None of them is committed. Later languages (S1QL, Sigma, YARA) get an oracle when they get an engine; see `skills/add-language/SKILL.md`.

## What is compared

`oracle.py` gathers every query in the corpus:

- `testdata/corpus/<lang>/*` (fixture tag line removed, as `corpus_gate.rs` does)
- `testdata/conformance/external/<lang>/*`, including the `.broken.` twins
- `testdata/conformance/perf/*`
- `testdata/oracles/<lang>/*`, one probe per form real detections use
- every `configurations.{sentinel,defender_for_endpoint,splunk}` query in a Tide rule under `testdata/` (and the legacy `configurations.splunk.search`), and every `response.procedure.searches[]` query whose `system` is one of those platforms, as YAML loads them (folded, quoted). A drilldown search is not a query
- Elastic: `configurations.elastic.query` and `threat.query` in the language their `type` and `language` select, `response.procedure.searches[]` entries with `system: elastic` and a `language`, the verdict tables `testdata/conformance/external/{lucene-queryparser,kuery-opensearch-dashboards}/cases.tsv`, and, when `OPENTIDE_DETECTION_RULES` names an `elastic/detection-rules` checkout (CI pins one), every rule and single-language hunt in it

Each query runs through `opentide-lsp analyze` and through the reference.

**Verdicts.** Ours rejects a query when it reports `kql_parse_error` or `kql_unknown_operator` (`spl_parse_error` or `spl_unknown_command` for SPL, at any severity: an unknown command is a warning because an app may provide it, but Splunk without that app rejects it; for the Elastic languages, an error-severity syntax code from `REJECT` in `oracle.py`, which leaves out checks Elasticsearch makes after parsing). The reference rejects it when it reports an error. A query where they differ must be listed by path in `testdata/oracles/exceptions.toml`. A `.broken.` fixture the reference accepts always fails: its injected fault breaks nothing. A probe in `testdata/oracles/<lang>/` is a valid detection form, so any error-severity diagnostic from ours on it fails too (an unknown table or function there is a false positive).

**Names.** KQL: `catalogs/kql/core/functions.toml` and `evaluate-plugins.toml` against the functions, aggregates and plugins in Kusto.Language's `GlobalState.Default`, plus any name ours flags `kql_unknown_function` that Kusto.Language knows. SPL: `catalogs/spl/commands.toml` against the `*-command` stanzas and aliases in `searchbnf.conf`, plus any name ours flags `spl_unknown_command` that Splunk knows. Every disagreeing name must be listed.

A listed path or name that no longer disagrees fails as stale, so the exceptions file is the exact ledger of known gaps. Fix a gap and delete its entry in the same change. When a check fails, the output ends with the unlisted items as TOML to start from.

## Splunk setup

The parser expands macros and resolves data models, so `oracle.py` defines them in the container first:

- macros from `splunk/macros.toml`. ESCU macros are copied from `splunk/security_content` (Apache-2.0); CIM helpers are one-line stand-ins. Any `` `<detection>_filter` `` macro is defined as `search *`, which is what ESCU generates.
- data models built from `catalogs/spl/datamodels.toml`, one dataset per entry with its fields. A data model the catalog lacks is a real disagreement.

Text that does not start with `|` is sent as `search <text>`, which is how Splunk runs authored SPL (`docs/spl/README.md`). The engine sees the authored text unchanged.

## Running locally

Both are optional. `scripts/ci-oracle.sh` skips a language whose reference is missing unless `OPENTIDE_ORACLE_REQUIRED=1`.

```bash
# KQL: needs the .NET 10 SDK, cargo and PyYAML
bash scripts/ci-oracle.sh kql

# SPL: needs Docker. Starting the container accepts the Splunk General Terms.
eval "$(bash scripts/oracles/splunk/start.sh)"
bash scripts/ci-oracle.sh spl
```

## Live Elasticsearch

The Elastic oracles in `elastic/` (Elasticsearch's EQL grammar, `@elastic/esql`, Kibana's kuery grammar, Lucene's classic query parser) answer "does it parse". Most of what the EQL and ES|QL engines check happens after parsing: the Verifier's argument types, field-to-field comparisons rejected when a filter becomes a query, the per-release grammar of each 8.19 and 9.x line, `runs` and `until` rules, the expression-depth guard, regular expressions compiled on a shard, and what `query_string` throws with `lenient` on or off. Only a running cluster answers those, so this is a third kind of reference: a release image of Elasticsearch, started on this machine.

```bash
eval "$(bash scripts/oracles/elasticsearch/start.sh 9.3.0)"      # any tag of the official image
python3 scripts/oracles/elasticsearch/run.py --language eql DIR    # or esql, lucene
python3 scripts/oracles/elasticsearch/probes.py                    # the recorded probes
python3 scripts/oracles/elasticsearch/esql_catalog.py              # catalogs/esql versions vs this release
```

`start.sh` pulls `mirror.gcr.io/library/elasticsearch:<tag>` (set `ES_IMAGE` for another registry), binds 127.0.0.1 only, runs single-node with security off, a basic licence (EQL and ES|QL are basic features), a 1 GB heap, ML off and disk watermarks off. Set `ES_PORT` to run two releases side by side.

**Fixture.** `run.py` waits for cluster health yellow, then creates `opentide-ecs` (alias `o`) mapped from `catalogs/ecs/fields.json`, so the Verifier sees real ECS types, and an empty `opentide-unmapped` (alias `u`) for files named `*.unmapped.*`. `object` and `nested` entries are not mapped themselves (a nested parent's children become plain object fields), and `match_only_text` children of keyword fields become multi-fields, as in ECS. `--extra-mapping` adds `{"field": "type"}` pairs.

**Requests.** EQL: `POST o/_eql/search` with `size: 1`. `size: 0` lets the planner answer with an empty result before it translates the filter, which hides the field-to-field comparison error; the index holds no documents, so `size: 1` costs nothing. ES|QL: `POST /_query`. Every `FROM` / `TS` source list is rewritten to the alias in place: the pattern list is blanked to spaces and its first characters become `o` (keeping a `cluster:` prefix and a `::selector`), so every line and column Elasticsearch reports matches the authored text. `x.esql.params.json` beside a file is sent as `params`. Lucene: a `query_string` search with `size: 0`, `default_field: *`, `allow_leading_wildcard: true`, and `lenient: false`; a fourth column repeats the verdict with `lenient: true`, which is how detection rules run (`--lucene-verdict strict|lenient` prints one verdict in the three-column format).

**Verdicts.** `OK`, or `ERR` with Elasticsearch's error type and reason. A problem that exists only because the fixture is not a real cluster is `OK` with an `unverified:` note: `Unknown column [x]` where `x` is not mapped in the fixture, `No matches found for pattern` that matches no mapped field, an unknown index, enrich policy, lookup index, or inference endpoint, and the cross-cluster licence check, and a command that needs a licence above basic (`CHANGE_POINT`). `Unknown column [x]` for a mapped `x` is an error: the query itself dropped the column (`KEEP`, `STATS`, a misspelt `EVAL` name). Parse errors (`parsing_exception`), every other Verifier problem, and errors raised while a shard builds the query (`query_shard_exception`, the EQL comparison-against-fields error) are `ERR`. Both Verifiers stop after unresolved names, so an `unverified` query may hide a type error behind them. Lucene has no such note but the same blind spot: `query_string` builds nothing, so checks nothing (not even a regexp), for a field the index does not map. A `circuit_breaking_exception` is the fixture's 1 GB heap, so it is `unverified` too; `--skip-larger` keeps a huge query (9.3.0 runs out of heap on a 250 KB SigmaHQ Lucene query) from killing the node.

`--assume-unmapped` retries such a query: EQL marks the unmapped fields optional (`?field`, null), ES|QL maps them as `keyword` in a side index, and Lucene maps every unmapped `field:` as `keyword` before it runs. Problems that name an assumed field stay `unverified`; the note starts with `assumed:` either way. Use it for corpora written against non-ECS fields (SigmaHQ conversions), not for probes.

**Probes.** `testdata/oracles/elasticsearch/<topic>/` holds one minimal query per file for each behaviour the engines encode from Elasticsearch's source (EQL argument types and field comparisons, `runs`, `until`, comments, regex, depth; ES|QL syntax gates; Lucene fuzziness, regexp, and leniency). `expected.tsv` records each probe's verdict per release line (recorded on 8.19.23, 9.0.8, 9.1.10, 9.2.8, 9.3.8, 9.4.8, and 9.5.5; 9.3.0 differs on the EQL and ES|QL expression-depth probes, which it accepts); `probes.py` fails when the running release disagrees and `--update` records a new line. `esql_catalog.py` sends one query per command, function, alias, and cast in `catalogs/esql/` and prints every name whose `versions` list disagrees with the release. `crates/opentide-analysis/tests/live_elasticsearch_probes.rs` holds the engines to `expected.tsv` without a cluster: a probe every release rejects needs an error, one every release accepts must have none, and one only some releases accept needs a non-error diagnostic. Its `EXCEPTIONS` list (mapping-dependent probes, 9.6-only syntax) must stay exact. `scripts/sync_esql_catalog.py` folds live catalog findings into `versions` (`LIVE_FUNCTION_RELEASES`, and no `date` cast on 9.0).

Nothing from this reference is shipped or vendored; the image is pulled at run time.

## Not shipped

Kusto.Language, Splunk, Splunk SDKs, and the Elastic and Lucene references never enter a release artifact. `ci-oracle.sh` fails if a shipped manifest depends on one, and `release.yml` runs `scripts/license-scan.sh` over every artifact (unpacking zips and `.crate` files) before it attaches or publishes them.
