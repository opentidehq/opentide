# Corpora

The inputs that make the verifier near-perfect (plan §5.3; UC-0.6, #804): a deterministic heavy
workspace for performance and scale, a fault catalogue in which every diagnostic code has a fault
kind that triggers it, and the process for adding real-world repositories. The tooling is
`cargo xtask corpus` (`xtask/src/corpus/`); the oracle is the Python CLI at the frozen tag,
opentide 0.23.0.

| File | What it is | Written by |
|------|------------|------------|
| [`faults.toml`](faults.toml) | The fault catalogue: kinds, their targets, mutations and expected codes; codes no workspace can produce, with the evidence | hand, reviewed; expectations adjusted to what the oracle reports |
| [`codes.toml`](codes.toml) | The codes in scope: `VALIDATION_CODES`, `LINT_CODES`, the configuration check's codes, the analysis engine's codes, and the compile check's codes (its `compile_*` explain pages); `out_of_scope` lists the other 52 `opentide explain` codes (usage errors, failure codes, doctor checks, sharing and deploy outcomes), which no workspace finding carries | `cargo xtask corpus codes --engine python --write` |
| [`COVERAGE.md`](COVERAGE.md) | Every code in scope mapped to its fault kinds | `cargo xtask corpus coverage --write` |
| [`KNOWN_GAPS.md`](KNOWN_GAPS.md) | Faults the oracle misses or reports surprisingly; each has a fault kind; UC-2.2 decides each | hand |
| [`INTAKE.md`](INTAKE.md) | How a shared real-world repository joins the corpora | hand |
| [`oracle.in`](oracle.in), [`oracle-requirements.txt`](oracle-requirements.txt) | The oracle and its dependencies, every wheel hash-pinned | `uv pip compile` (command in the file's header) |

## The oracle

```bash
uv venv --python 3.12 /tmp/oracle
uv pip install --python /tmp/oracle/bin/python --require-hashes -r tests/corpora/oracle-requirements.txt
export OPENTIDE_ORACLE=/tmp/oracle/bin/opentide      # or pass --oracle to each command
```

Never the working tree's `opentide`: the commands check that the oracle prints
`opentide 0.23.0` (the `oracle` key of `faults.toml`). The Linux x86_64 wheel's SHA-256 is
`de12c30f53327c4790fff5996c20b7d14508b4fd96ac73c81db20a02993211bc`, as PyPI publishes it.

`--repo` is a global option of 0.23.0: `opentide --json --repo DIR validate`, not
`opentide --json validate --repo DIR` (a usage error, exit 2).

## The heavy workspace

```bash
cargo xtask corpus generate --seed 20261107 --out /tmp/heavy        # 300 threats, 300 objectives, 500 rules
cargo xtask corpus generate --seed 20261107 --scale 10 --out /tmp/x10
cargo xtask corpus generate --seed 1 --threats 30 --objectives 30 --rules 50 --out /tmp/small
cargo xtask corpus generate --seed 1 --threats 30 --objectives 30 --rules 50 --digest
cargo xtask corpus clean --engine python --repo /tmp/heavy           # validate and lint: zero findings
```

- **Deterministic by seed.** The generator has its own SplitMix64 and YAML emitter, reads no clock,
  environment or file, and forks one random stream per family. `xtask/tests/corpus_generate.rs`
  records the digest (FNV-1a over every path and byte) of four configurations; a change that
  alters the output records the new digests in the same commit and says why, because UC-0.5's
  goldens and UC-0.8's baselines are made from it.
- **Contents.** All nine platforms (every rule has one primary platform in rotation, two thirds a
  second, some a third); `rule::1.0` and `rule::1.1` (with `reviewed`); objectives with one to three
  signals, some with a `parent`; threats with chaining relations, actors (ATT&CK groups, sightings),
  kill chain and references; rules implementing an objective or a signal; responses with
  responders (declared in `deployment.toml`), playbooks and hunt queries; per-platform variants
  (Sentinel scheduled and NRT, Elastic KQL, EQL, Lucene, ES|QL and threshold, HarfangLab Sigma
  and YARA, SentinelOne single-event and correlation, Sysdig lists and macros, Splunk notables,
  Defender process and network queries); `visibility.toml` log sources for every queried table.
- **Configuration.** All nine platforms enabled; Sentinel, Defender, Splunk, Elastic and Sysdig
  have tenants (Sentinel and Elastic two, PREVIEW and RELEASE), which rules list in `tenants`. Every
  credential is a `$VARIABLE` reference and every host is on a reserved example domain: the
  generator writes no secret, real or fake-looking.
- **`paths.toml` variants** (`--layout`): `standard` (none, the default folders), `explicit` (the
  default: a `paths.toml` that restates the default folders), `custom` (objects under
  `detection/`, docs under `documentation/`). See `KNOWN_GAPS.md` KG-07: `opentide lint` ignores
  `paths.toml`.
- **Clean.** Seed 1 (30/30/50) and seed 20261107 (300/300/500) have zero findings in the
  oracle's `validate` and `lint`; the `Corpus` workflow checks the heavy one.

Consumers: `xtask golden` (UC-0.5) records the small workspace (seed 1, 30/30/50) and the fault
workspace as fixtures; `xtask bench` (UC-0.8) generates seed 20261107 with `--scale`. The library
API is `xtask::corpus::generate::{generate, Options, Counts, Layout}` and
`xtask::corpus::cli::write_workspace`.

## The fault catalogue

```bash
cargo xtask corpus faults --check --engine python            # every kind, against the oracle
cargo xtask corpus faults --check --engine python --only uuid-invalid-rule --keep /tmp/faults
cargo xtask corpus faults --out /tmp/faults-ws                # one workspace, every kind applied
cargo xtask corpus coverage --check
```

`--check` generates the base workspace (`[base]`), checks it has no finding under every command
the kinds use, then gives each kind its own copy: it selects the targets, applies the mutation,
runs the oracle (reading `report`, `findings`, a failure's `diagnostics`, and `deploy
migrate-state`'s `errors`) and requires
**exactly** the expected codes (no other code, none missing), each
finding with the expected severity, and (unless `per_target = false`) a finding on every target
file. `--out` writes the combined fault workspace, a fixture for UC-0.5's goldens: the `[combined]`
counts, every kind not marked `isolated` applied once (twice for a cross-file kind) to files no
other kind touches, and `DIR.faults.json` beside it listing each kind's files, command and codes.
The expectations hold per kind in isolation; in the combined workspace kinds interact (the compile
check, KG-10, stays silent), so it is recorded, not checked against them. Sharing kinds and kinds
that change how the whole workspace loads are `isolated`.

A configuration file is one file (`deployment.toml`, `visibility.toml`, `sharing.toml`): kinds
aimed at one (`target.path`) put five faulty entries in it and pin the oracle's number of
findings with `counts` (five, or one where the oracle reports a code once per file, such as
`unknown_connector` or `config_parse`); every other kind takes at least five files.

A kind:

```toml
[[kind]]
id = "uuid-invalid-rule"          # unique, kebab-case
class = "single"                  # single | combination (two faults in one file) | cross-file
codes = ["invalid_uuid"]          # exactly what the oracle reports; [] only for a known gap it is silent on
severity = "error"                # or { invalid_uuid = "error", other = "warning" }
command = ["validate"]            # after `opentide --json --repo DIR`; ["lint"], ["validate", "--check", "cve"]
target = { family = "rule", platform = "sentinel", tags = ["rule::1.1"], without = [], skip = 0 }
count = 5                         # at least 5 files, unless the target is a single file
ops = [{ op = "set", path = "metadata.uuid", value = "not-a-uuid-{n}" }]
per_target = true                 # every target carries a finding (both codes, for a combination)
counts = { invalid_uuid = 5 }     # exact numbers of findings, when they matter
covers = ["sysdig_source"]        # codes proven by an expected finding's message naming them
baseline = true                   # the clean base is checked under this command too
env = { HTTPS_PROXY = "http://127.0.0.1:9" }   # for the oracle (a dead proxy: lookups fail alike)
isolated = false                  # left out of the combined workspace
gap = "KG-01"                     # its KNOWN_GAPS.md entry
note = "why"
```

Targets select by family (`threat`, `objective`, `rule`, `config`), platform, and the tags the
generator puts on each file (`rule::1.1`, `reviewed`, `hunt`, `sentinel:nrt`, `elastic:eql`,
`harfanglab:yara`, `chaining`, `actors`, `config:deployment.toml`, `tenants`, ...: see
`xtask/src/corpus/generate.rs`). The operations are `set` (a TOML `value`, or `raw` for a YAML
scalar written verbatim), `delete`, `append`, `copy_from_partner` (pairs the targets and copies a
value from the second of each pair into the first: duplicates), `replace`, `append_text`, `write`,
`copy_path` (a value from the same file), `rename`, `copy`, `delete_file` and `add_file`. Strings expand `{n}` (the target's position),
`{uuid}`, `{platform}`, `{dir}`, `{stem}` and `{name}`. TOML files are edited as tables (and
re-serialised), YAML objects as trees, text operations on the rendered file.

### Adding or changing a kind

1. Write the kind with the codes you expect.
2. Run it alone: `cargo xtask corpus faults --check --engine python --only <id> --keep /tmp/f`.
3. When the oracle reports something else, the oracle is the truth: adjust `codes` and
   `severity` to what it reports. When that is surprising (a fault it misses, a code it should not
   report, a severity that disagrees with the code's page), add a `KNOWN_GAPS.md` entry and link
   it with `gap`.
4. `cargo xtask corpus coverage --write` and commit `COVERAGE.md`.

A code that no workspace mutation makes the commands the runner uses offline report (`validate`,
`lint`, `deploy migrate-state`; the language server's own codes, a lookup that needs the network)
gets an `[[unreachable]]` entry with the evidence instead; `COVERAGE.md` lists it as "no fault
kind".
