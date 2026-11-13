# Vocabulary ingest

`cargo xtask vocab ingest` ([`xtask/src/vocab/ingest/`](../../xtask/src/vocab/ingest/))
fetches the canonical upstream sources and regenerates the canonical
`{field}.vocab.toml` files under `specifications/vocabularies/`. It is the Rust
port (UC-6.3) of the Python package's `opentide.vocabulary` and of the scripts
that were in this directory, removed with the Python implementation (UC-6.2,
[#841](https://github.com/opentidehq/opentide/issues/841)), and it writes the
same files byte for byte from the same inputs ([below](#the-port-and-the-python-ingest)).

It writes into specifications, then syncs the bundled copy in
`src/opentide/data/vocabulary/` and `data/specifications.lock.json`
(`cargo xtask vocab sync`).

By default it expects a sibling clone at `../specifications`. Override with
`--specifications DIR` or:

```bash
export OPENTIDE_SPECIFICATIONS_ROOT="/absolute/path/to/specifications"
```

The STIX bundles are downloaded into `--stix-dir DIR`, else
`$OPENTIDE_ATTACK_STIX_DIR`, else a scratch directory that goes when the run
ends. CI keeps them in a scratch directory of the runner:

```bash
export OPENTIDE_ATTACK_STIX_DIR="/tmp/attack-stix"
```

## Automated ingest (ATT&CK + MISP)

Weekly GitHub Actions (`.github/workflows/vocab-upstream.yml`) plus:

```bash
# Dry-run: exit 1 when vocabularies would change
cargo xtask vocab ingest --check

# Fetch latest ATT&CK STIX + MISP galaxy, merge, sync bundle
cargo xtask vocab ingest --apply

# Reuse bundles already on disk (DIR holds enterprise-attack.json, mobile-attack.json,
# ics-attack.json and the fetch's manifest.json); a MISP galaxy from a file
cargo xtask vocab ingest --check --no-fetch --stix-dir DIR --misp-url file:///path/threat-actor.json
```

It downloads with `curl` (HTTPS only): the latest release of
[`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data)
through GitHub's API, its three bundles, and the MISP galaxy named by
`misp.galaxies.threat_actors` in
[`src/opentide/data/configurations/resources.toml`](../../src/opentide/data/configurations/resources.toml)
(or `--misp-url`). `--now TIMESTAMP` writes that time where the run would read
the clock (`generated_at`, and `source_fetched_at` without a fetch manifest),
for a reproducible run.

`--apply` writes:

1. `specifications/vocabularies/{att&ck,att&ck.groups,mitigations,datasources,actors}.vocab.toml`
2. The opentide bundle + `data/specifications.lock.json`

It never writes a schema pin. New keys open the next minor contract (for example
`actors::1.2`), and the run reports it as an unpinned contract for the vocab
fields schema pin files reference (`att&ck`, `actors`, `datasources`). A shipped
revision keeps the contracts it pins, so a new key stays unreachable until a new
schema revision (`threat::1.1`) pins its contract: that revision is a deliberate
specifications and opentide change ([versioning](https://github.com/opentidehq/specifications/blob/main/specs/versioning.md),
RFC 0003), never an ingest side effect. `att&ck.groups` and `mitigations` are
catalog vocabs with no schema pin: ATT&CK groups still version-gate objects
through `threat.actors.name` → `actors::*` (STIX intrusion-sets merge into `actors`).
Keys that disappear from upstream keep their `version` and get `removed` at the
next major, so existing schema revisions still accept them. The ingest PRs are
the review gate — nothing auto-merges.

Merge order: specifications PR first (canonical vocabs), then the opentide
companion PR (bundle, lockfile).

### Per-key bump rules (RFC 0003)

| Upstream change | Key metadata | Contract |
|-----------------|--------------|----------|
| New id | `version` = next minor for this cycle | opens that minor, unpinned |
| Description/name/link only | keep `version` | none |
| Id gone | `removed` = next major | none |
| First fill of an empty file | `version = "1.0"` | none (pins already `::1.0`) |

## The port and the Python ingest

The files are written in the layout `tomli_w` 1.2.0 gave the Python ingest
(`ingest/tomli.rs`): the header's keys first, its tables after, then one
`[[keys]]` table per key, keys in their merge order, four-space array indents.
The values keep Python's semantics where they decide an output byte: tables
keep insertion order, JSON is read in document order, `==` and truthiness are
Python's (`ingest/value.rs`).

The proof (UC-6.3) ran both on the same inputs: the Python ingest from
`ca32f5558d95fd77d5550084ee0f9d0681397fdc` (the last commit that has it, in a
worktree of its own, its clock fixed and its bundle sync left out) and
`cargo xtask vocab ingest --apply --no-fetch --now ...`, each on its own copy of
the specifications vocabularies, with the same ATT&CK bundles and the same MISP
galaxy file. Every file of `vocabularies/` and the printed summary were
identical in each case:

| Case | Vocabularies | ATT&CK | What it exercises |
|------|--------------|--------|-------------------|
| A | specifications `main` (ATT&CK 20.0) | 20.1 | a weekly run: 163 techniques updated |
| B | specifications `main` | 18.1 | 65 techniques and 6 groups removed, a new contract (`att&ck::1.3`) |
| C | specifications at `7c3d742` (the first per-key versions) | 20.1 | additions to every vocabulary, 280 new actors |
| D | specifications at `7c3d742` | 18.1 | the same, from another release |
| E | A's output | 20.1 | a second run: nothing to write |
| F | `main`, three vocabularies emptied of keys | 20.1 | the first fill (`1.0`, no contract) |

## Not ported

- **MalAPI** (`generate_malapi.py`): it scraped [malapi.io](https://malapi.io)'s
  HTML, one page per API at about one page a minute, and merged the result into
  `malapi.vocab.toml` with the rules above. It ran by hand, never in CI. A port
  needs an HTML parser crate, which the workspace does not have; until then it
  runs from `ca32f5558d95fd77d5550084ee0f9d0681397fdc`:

  ```bash
  git worktree add --detach ../malapi ca32f5558d95fd77d5550084ee0f9d0681397fdc
  cd ../malapi && uv sync --group dev
  uv run --with beautifulsoup4 --with lxml python scripts/vocabulary/generate_malapi.py
  ```

  Then sync the bundle from this checkout with `cargo xtask vocab sync`.
- **`migrate_yaml_to_toml.py`**: the one-shot YAML to TOML migration, done;
  no YAML vocabulary is left.

## Keying model

| `key` | Index field | When |
|-------|-------------|------|
| `name` (default) | `name` | Simple enums, datasources (duplicate MITRE ids) |
| `id` | `id` | ATT&CK techniques, groups, NIST, indicators, actors |

Optional `id` on name-keyed entries is kept as reference metadata only.
