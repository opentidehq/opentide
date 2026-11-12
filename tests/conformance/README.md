# Cross-SDK conformance

The Rust, Python and Node SDKs are one implementation, the `opentide` facade crate, behind three
bindings (UC-5.4, #839). This suite proves it: every operation of [`manifest.json`](manifest.json)
runs on every corpus through each SDK, and the documents must be byte-identical.

```bash
uv sync --group dev                                    # the Python SDK (opentide._native)
(cd bindings/node && npm ci && OPENTIDE_VERSION=<workspace version> node build.mjs --profile develop)
cargo xtask conformance --runners rust,python,node     # 0: identical
cargo xtask conformance --diverge python               # the suite's own test: 0 when caught
```

`<workspace version>` is `version` in the root `Cargo.toml`, the version the Rust and Python
builds report; the npm package's own is `0.0.0` until the release sets it (UC-5.5), and
`run_json(["commands"])` would differ at `/version`.

## What runs

| Piece | Where |
|-------|-------|
| The manifest: corpora and operations | [`manifest.json`](manifest.json) |
| The comparator, the corpora's layout, the runners' commands | `cargo xtask conformance` ([`xtask/src/conformance/`](../../xtask/src/conformance/)) |
| The Rust runner | [`crates/opentide/tests/conformance.rs`](../../crates/opentide/tests/conformance.rs) (`cargo test -p opentide --features cli --profile develop --test conformance`) |
| The Python runner | [`test_python_runner.py`](test_python_runner.py) (pytest under `uv run`) |
| The Node runner | [`bindings/node/test/conformance.test.mjs`](../../bindings/node/test/conformance.test.mjs) (`node --test`) |

`cargo xtask conformance` lays the corpora out under `<target>/conformance/corpora/`, writes
`plan.json` (each workspace's name and folder, and the operations), runs each runner with
`OPENTIDE_CONFORMANCE_PLAN` and `OPENTIDE_CONFORMANCE_OUT`, then compares
`documents/<runner>/<corpus>/<operation>.json` with the first runner's (the reference). The first
difference in each document is reported by its JSON pointer: a value first, then the order of an
object's keys, then the bytes. `report.json` holds every mismatch. A run that passes removes the
corpora and documents unless `--keep`.

Each runner also runs on its own, in its suite (`cargo test -p opentide --all-features`, `pytest
tests/`, `npm test`): every operation on the tide corpus under a temporary folder, plus a test of
the divergence flag.

## Corpora

| Name | Kind | What |
|------|------|------|
| `tide_corpus` | `tide_corpus` | `tests/fixtures/tide_corpus/current` in today's layout |
| `heavy` | `heavy` | The heavy workspace, seed 20261107 (300 threats, 300 objectives, 500 rules) |
| `faults` | `faults` | The combined fault workspace (`cargo xtask corpus faults --out`) |
| `configuration` | `configuration_faults` | Each configuration fault kind (`xtask/src/corpus/configuration.rs`) applied alone to the fault catalogue's base workspace: `configuration/<kind>`, one workspace each; some stop `Workspace.open` |

## How a runner builds a document

The same in the three runners; a difference anywhere else is a difference between the SDKs.

- **Open.** `Workspace.open(root)` (`open: "disk"`, the default), or `Workspace.from_files(root,
  files)` (`open: "files"`) with every file under the workspace, by its path with `/`, as UTF-8
  text without newline translation. A workspace that does not open gives every operation on it
  the document `{"error": {"code", "message"}}`, the facade's `Error::code` and message.
- **Operations.** `options` use the facade's names (`keep_deprecated`); the Node runner passes
  them in the Node API's (`keepDeprecated`). Validate's document is `{checks, report, summary,
  failed, warned, exit_code}`, lint's `{path, checks, findings, status, message, exit_code,
  failure_code, summary, outcome, unmatched, warnings, next_actions}`, deploy plan's `{document,
  summary, ok}`; the Node API's camelCase members (`exitCode`) are written by these names. The
  other calls' results are written as they come. A call that throws or raises gives the error
  document.
- **`run_json`.** Run from the workspace's folder, with `--repo <root>` first unless `repo:
  false`, so that relative paths are the same in every runner.
- **Normalised.** Three members, where a document has them, are written as `null`: `/duration_ms`
  (`run_json`'s envelope), `/evaluated_at` (`rules unreviewed`) and `/report/stats/wall_ms`
  (validate): a run's own clock, the values two runs of one operation differ in. Nothing else is
  changed.
- **Written** with two-space indentation, keys in their order, UTF-8 as is and a final newline:
  `json.dumps(indent=2, ensure_ascii=False)`, `JSON.stringify(document, null, 2)`, and
  `opentide_compare::json::write(Indented)`, which agree byte for byte on these documents.

The runners run in one environment: xtask clears the CI providers' variables, the coding agents'
and every `OPENTIDE_*` variable, which change what a command writes; the Python runner runs
without the suite's conftest (`--confcutdir tests/conformance`), which changes the environment.

## The divergence check

`OPENTIDE_CONFORMANCE_DIVERGE` is test-only: the runner it is set for writes each validate
document with its keys sorted, as a binding that went through a sorted map (a
`serde_json::Value`) would hand it back. The data stays the same, so only a comparison of the
bytes and key order catches it. `cargo xtask conformance --diverge <runner>` sets it for that
runner and passes only when the comparator reports a difference in that runner's documents and
no other's. CI runs it after the real comparison.

## Adding to it

- An operation: add it to `manifest.json`, with each runner's handling if it is a new `call`.
- A corpus kind: `lay_out` in `xtask/src/conformance/cli.rs`, and the kinds `Manifest::parse`
  accepts.
- A difference is fixed in the binding that is wrong, never by normalising it away here.

## Known differences

[`known_differences.json`](known_differences.json) lists the differences no binding can remove,
each one value at one JSON pointer of one runner's document, with both values, its reason and its
issue. A document is accepted when every difference in its data is listed there; a difference in
key order or layout never is. An entry a run could have needed and did not is stale and fails
the run. Today there is one: JavaScript has one number type, so the Node SDK's `runJson(['commands'])`
reads `query --timeout`'s default, `120.0`, as `120`.
