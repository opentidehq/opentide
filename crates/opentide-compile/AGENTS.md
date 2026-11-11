# opentide-compile — agent guide

Deploy compile and plan (plan §4, UC-3.1, #823): what `opentide deploy` would send, computed
locally, byte for byte what the Python CLI (the oracle, opentide 0.23.0) sends.

| Module | What | Oracle |
|--------|------|--------|
| `strategy.rs` | `StatusStrategy` runs, `deploys`, `parse_strategies` and its messages, the `[[statuses]]` of `deployment.toml`, the removed `DEPLOYMENT_PLAN` | `models/deployment_enums.py`, `deployment/utils.py` `check_status` |
| `sentinel.rs` | The `alertRules` PUT body for one tenant | `platforms/sentinel/deployer.py` `compile_deployment` |
| `elastic.rs` | The Detection Engine rule body, its ATT&CK `threat` | `platforms/elastic/compile.py`, `attack.py` |
| `sysdig.rs` | The `/api/secure/rules` body: the Falco rule a block deploys, its macros and lists expanded as Falco's loader expands them (`opentide_core::falco`, opentide-schema's `falco_text`), derived name, desc, priority, output and tags | `platforms/sysdig/compile.py`, `expansion.py` |
| `defender.rs`, `sentinel_one.rs`, `crowdstrike.rs` | The rule a deploy creates (`POST`), updates or deletes on one tenant, by the id the deployment state records (`deploy.rs` `action`) | `platforms/<platform>/deployer.py` and `client.py` |
| `splunk.rs` | The saved search's create and two updates: schedule, trigger, actions, `[[modifiers]]`, the tenant's actions and Enterprise Security; `Clock` is the random or current minute and hour a frequency runs at | `platforms/splunk/deployer.py`, `client.py` |
| `harfanglab.rs` | The Sigma rule (YAML by serde-saphyr) or YARA file for a tenant of its `type`, or the delete | `platforms/harfanglab/deployer.py`, `client.py` |
| `carbon_black.rs` | The watchlist report a deploy creates when the org holds none of its title (what else it does depends on the org) | `platforms/carbon_black/deployer.py`, the Carbon Black SDK's `Report` |
| `deploy.rs` | What those six share: `Write` (method, URL, body), `Action`, tenant settings | `deployment/external_ids.py` |
| `preview.rs` | A dry run's payload entries; `compile_offline`; `compile_tenant` (any platform, one tenant); `config_dump`, the block serialised from opentide-schema's model where the oracle prints `model_dump` | `deployment/preview.py` |
| `plan.rs` | Rule selection by strategy (`make_deploy_plan`), tenants (`tenants_resolver`), create or update from deployment state, the tally, unset variables | `deployment/utils.py`, `planning.py`, `platforms/enabled.py`, `cli/services/deploy_plan.py` |
| `dry_run.rs` | `deploy --dry-run`'s result payload, in the oracle's key order; `--uuid`/`--file` selection (#753) | `cli/services/deploy.py` |
| `git.rs` | The git baseline: the run's changed files through gitoxide's crates (`gix-discover` finds the checkout, `gix-ref`, `gix-odb`, `gix-diff`, `gix-revision` for rev-specs and the merge base), CI diff sources; `generate docs --changed`'s work tree as `git diff` and `git ls-files --others --exclude-standard` read it (`gix-index`, `gix-worktree`'s exclude and attribute stack, `gix-filter`'s clean filters) | `deployment/git_repo.py`, `deployment/ci.py` |
| `kql.rs`, `duration.rs`, `attack.rs` | Exclusions and `let` statements; Sentinel and Elastic durations; techniques a rule inherits, `att&ck` entries | `platforms/kql.py`, `sentinel/client.py`, `elastic/durations.py`, `generation/framework.py` |
| `generate/` | Generation (UC-3.2, #824; UC-3.2c, #916): `exports.rs` the Navigator layer, objects table and revisions snapshot; `explorer.rs` the explorer's bundle and search index; `visibility.rs` the telemetry report `--include-visibility` adds (the datasets the queries read are the host's, from the query engines); `inflight.rs` the inflight preview shards, their overlay on the index, change metadata and prune; `relations.rs` parents and children; `json_text.rs` JSON files as `json.dumps` lays them out (indented, or one line), ASCII only; `files.rs` parallel writes (rayon), removals and the written-file count by modification time and size; `docs/` (UC-3.2b, #915) the documentation pages: `catalog.rs` the objects in their models and the relations walk (active rules, coverage and chaining graphs), `render.rs` each section's data, `templates/*.md.j2` the minijinja templates that lay the pages out, `flavor.rs` the four Markdown flavours, `mermaid.rs` diagrams (labels wrapped by textwrap), `cve.rs` CVE links, `inflight.rs` the inflight preview overlay, `changed.rs` `--changed` | `export/`, `generation/framework.py`, `cli/services/generation.py`, `cli/services/visibility.py`, `documentation/`, `indexing/inflight*.py` |
| `ci/` | `setup ci`'s pipelines (UC-3.2c, #916): minijinja templates per provider (`templates/`, `[[ ]]` for a value since GitHub writes `${{ }}`), the shell the jobs run as macros of `scripts.sh.j2`, and the commands and gates they share. `tests/setup_ci.rs` compares each with a pipeline `tests/ci/oracle.py` recorded from the Python CLI, as data then as text | `ci/` |
| `json.rs` | `Json`: an ordered JSON value, so a body keeps the oracle's key order without `serde_json`'s `preserve_order` (a workspace-wide feature) | |

## Place

domain, tier 1 (`xtask/layers.toml`), beside `opentide-analysis`: it reads the index
`opentide-workspace` loads and the vocabularies and configuration of `opentide-schema`.

## Invariants

- The caller loads the workspace. Reads go through `opentide-workspace`'s `FileSystem`
  (`plan::local_scope`, `plan::state_id`, `dry_run`), except `git.rs`, which reads the
  repository through gitoxide (`gix-config` for the `origin` remote, a branch's upstream and
  the work tree's filters; `generate docs --changed` runs a configured `filter.<driver>.clean`
  program on an object file, as `git diff` does) and the CI event file, and `generate/docs` reads the inflight shards and, for the pages no
  object writes any more, the docs folders. Nothing reaches the network. Only
  `generate/files.rs` writes: rendering is pure (a phase returns its `Output`s), and the
  command line writes them with `files::write_all`.
- A generated file the oracle writes is byte for byte the oracle's on every recorded fixture
  (`tests/generate_exports.rs` reads the golden recordings); a machine-read JSON export matches
  as bytes, not only as data.
- gitoxide's crates, never the `gix` facade: its object cache (clru) brings a second `hashbrown`,
  which `deny.toml` bans.
- A body's key order is the oracle's: build it with `json::Object` (an `IndexMap`) in the order
  the oracle's dict is built. The oracle compiles Elastic from the model dump, so nested models'
  keys follow the model's field order whatever the file's order (`elastic::model_order`).
- A rule a platform cannot compile is a `CompileError` with the oracle's `code`, reason and hint,
  never a panic.
- `cargo xtask payloads diff --against python --corpus all` compares every body of every rule of
  every corpus with the oracle's, on every platform; a difference is a bug or an entry of
  `tests/golden/payloads/APPROVED.toml` (moved to `tests/golden/APPROVED_DIFFS.toml` when deploy
  runs on the Rust command line): one difference (`[[diff]]`), or a class of the model-dump
  previews (`[[dump]]`: `nulls`, `order`), which serde writes and Pydantic's `model_dump` did not.
- A request body is the oracle's byte for byte as JSON. A text inside it that another format
  serialises (Splunk's risk JSON, HarfangLab's Sigma YAML) is the crate's natural output
  (serde_json, serde-saphyr), never a port of `json.dumps` or PyYAML; its difference is approved.
- What a deploy reads that is not the rule (a Splunk schedule's random or current minute, Carbon
  Black's report timestamp, the id the deployment state records) is an input, never read here.

## Test

```bash
cargo nextest run -p opentide-compile
cargo nextest run -p opentide-cli generate_goldens         # every recorded generate case, in-process
cargo nextest run -p opentide-compile generate_docs         # every page of the tide corpus, generic and GitHub
cargo xtask payloads diff --against python --corpus all   # every body, every corpus
cargo xtask payloads plan                                  # the dry run's plan against the recordings
cargo xtask payloads git --against python                  # a scripted git history
```

`tests/golden/payloads/APPROVED.toml` holds the intended differences of all three.
