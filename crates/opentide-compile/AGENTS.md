# opentide-compile — agent guide

Deploy compile and plan (plan §4, UC-3.1, #823): what `opentide deploy` would send, computed
locally, byte for byte what the recorded corpus holds (taken from opentide 0.23.0, retired in #1142).

| Module | What |
|---|---|
| `strategy.rs` | `StatusStrategy` runs, `deploys`, `parse_strategies` and its messages, the `[[statuses]]` of `deployment.toml`, the removed `DEPLOYMENT_PLAN` |
| `sentinel.rs` | The `alertRules` PUT body for one tenant |
| `elastic.rs` | The Detection Engine rule body, its ATT&CK `threat` |
| `sysdig.rs` | The `/api/secure/rules` body: the Falco rule a block deploys, its macros and lists expanded as Falco's loader expands them (`opentide_core::falco`, opentide-schema's `falco_text`), derived name, desc, priority, output and tags |
| `defender.rs`, `sentinel_one.rs`, `crowdstrike.rs` | The rule a deploy creates (`POST`), updates or deletes on one tenant, by the id the deployment state records (`deploy.rs` `action`) |
| `splunk.rs` | The saved search's create and two updates: schedule, trigger, actions, `[[modifiers]]`, the tenant's actions and Enterprise Security; `Clock` is the random or current minute and hour a frequency runs at |
| `harfanglab.rs` | The Sigma rule (YAML by serde-saphyr) or YARA file, by the rule's own kind (`Kind`, `request_body`), or the delete |
| `carbon_black.rs` | The watchlist report a deploy creates when the org holds none of its title (what else it does depends on the org) |
| `deploy.rs` | What those six share: `Write` (method, URL, body), `Action`, tenant settings |
| `preview.rs` | A dry run's payload entries (the writes a tenant receives, with `<send-time:…>`, `<tenant-read:…>` and `<tenant:…>` placeholders, for the platforms whose body is built from the tenant); `compile_offline`; `compile_tenant` (any platform, one tenant); `config_dump`, the block serialised from opentide-schema's model where opentide 0.23.0 printed `model_dump` |
| `compiler.rs` | `Compiler`: the one compile entry point per platform that the dry run (`preview.rs`) and the deploy (`opentide-cli`'s `deploy_send.rs`) both call, so a dry run shows what a deploy sends (#1952). Every platform |
| `plan.rs` | Rule selection by strategy (`make_deploy_plan`; with `log`, its warnings as it logs them), tenants (`tenants_resolver`), create or update from deployment state, the tally, unset variables; `git.rs` also answers whether git ignores the deployment state (`state_ignore`, `deployment_state_ignore`) |
| `modifiers.rs` | A platform's `[[modifiers]]` applied to a rule's block for one tenant: conditions, `prefix::`/`suffix::`, dotted keys, the model's top-level keys only (`validate query --live` checks the block as modified) |
| `dry_run.rs` | `deploy --dry-run`'s result payload, in the recorded key order; `--uuid`/`--file` selection (#753) |
| `promotion.rs` | The status promotion of a RELEASE deploy on a push: `[promotion]`, the blocks a rule promotes, each block `status` replaced over its own characters and the result read back (`promote_block_statuses`); the host reads and writes the files |
| `git.rs` | The git baseline: the run's changed files through gitoxide's crates (`gix-discover` finds the checkout, `gix-ref`, `gix-odb`, `gix-diff`, `gix-revision` for rev-specs and the merge base), CI diff sources; `share push --changed`'s push diff up to HEAD (`changed_through_head`, its base and `--since` read as Dulwich read them); `generate docs --changed`'s work tree as `git diff` and `git ls-files --others --exclude-standard` read it (`gix-index`, `gix-worktree`'s exclude and attribute stack, `gix-filter`'s clean filters) |
| `kql.rs`, `duration.rs`, `attack.rs` | Exclusions and `let` statements; Sentinel and Elastic durations; techniques a rule inherits, `att&ck` entries |
| `generate/` | Generation (UC-3.2, #824; UC-3.2c, #916): `exports.rs` the Navigator layer, objects table and revisions snapshot; `explorer.rs` the explorer's bundle and search index; `visibility.rs` the telemetry report `--include-visibility` adds (the datasets the queries read are the host's, from the query engines); `inflight.rs` the inflight preview shards, their overlay on the index, change metadata and prune; `relations.rs` parents and children; `json_text.rs` JSON files as serde_json writes them (pretty at an indent; one line is `Json::to_compact`), UTF-8; `files.rs` parallel writes (rayon), removals and the record of the files a phase wrote and removed; `docs/` (UC-3.2b, #915) the documentation pages: `catalog.rs` the objects in their models and the relations walk (active rules, coverage and chaining graphs), `render.rs` each section's data, `templates/*.md.j2` the minijinja templates that lay the pages out, `flavor.rs` the four Markdown flavours, `mermaid.rs` diagrams (labels wrapped by textwrap), `cve.rs` CVE links, `inflight.rs` the inflight preview overlay, `changed.rs` `--changed` |
| `ci/` | `setup ci`'s pipelines (UC-3.2c, #916): minijinja templates per provider (`templates/`, `[[ ]]` for a value since GitHub writes `${{ }}`), the shell the jobs run as macros of `scripts.sh.j2`, and the commands and gates they share. `tests/setup_ci.rs` compares each with a pipeline `tests/ci/record.py` recorded from opentide 0.23.0, as data then as text |
| `json.rs` | `Json`: an ordered JSON value, so a body keeps the request's key order without `serde_json`'s `preserve_order` (a workspace-wide feature) |

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
- A generated file is held byte for byte by the CLI's `generate` snapshots (the Python CLI's
  recordings were retired, #1142); a machine-read JSON export changes as bytes only on purpose.
- gitoxide's crates, never the `gix` facade: its object cache (clru) brings a second `hashbrown`,
  which `deny.toml` bans.
- A body's key order is the one the request has always had: build it with `json::Object` (an
  `IndexMap`) in that order. Elastic is compiled from the model dump, so nested models'
  keys follow the model's field order whatever the file's order (`elastic::model_order`).
- A rule a platform cannot compile is a `CompileError` with the recorded `code`, reason and hint,
  never a panic.
- `tests/payload_corpus.rs` holds every body of the compile corpus (`tests/golden/payloads/`) to
  what was recorded for it (`recorded.json`); a difference is a bug or an entry of
  `tests/golden/payloads/APPROVED.toml`: one difference (`[[diff]]`), a class of the previews
  (`[[dump]]`: `nulls`, `order` and `wrapped` for Elastic, `request` for the platforms whose dry run
  shows the tenant's writes, #1712), or a class of the tenants' writes the recording's probe recorded
  otherwise (`[[writes]]`: Splunk's `search`, Carbon Black's `watchlist`).
  The recorder, `cargo xtask payloads`, was retired with the Python CLI (#1142).
- A request body is the recorded one, byte for byte as JSON. A text inside it that another format
  serialises (Splunk's risk JSON, HarfangLab's Sigma YAML) is the crate's natural output
  (serde_json, serde-saphyr), never a port of `json.dumps` or PyYAML; its difference is approved.
- What a deploy reads that is not the rule (a Splunk schedule's random or current minute, Carbon
  Black's report timestamp, the id the deployment state records) is an input, never read here. A
  dry run passes none for the first two, and the writes show `<send-time:NAME>` in their place.

## Test

```bash
cargo nextest run -p opentide-compile
cargo nextest run -p opentide-cli --test cli_snapshots generate   # every generate case, as snapshots
cargo nextest run -p opentide-compile generate_docs         # every page of the tide corpus, generic and GitHub
cargo nextest run -p opentide-compile --test payload_corpus        # every body of the compile corpus
```

`tests/golden/payloads/APPROVED.toml` holds the intended differences.
