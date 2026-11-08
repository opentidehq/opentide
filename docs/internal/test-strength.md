---
title: Test strength
description: How strong the verifier is — Rust line coverage per crate with its gates, weekly mutation testing with its baseline, and the parity dashboard (UC-X.2).
---

# Test strength

> Status: **implemented** by UC-X.2 ([#844](https://github.com/opentidehq/opentide/issues/844)),
> plan [§5.4 "Strength"](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#54-layered-tests). Three measures: coverage gates per
> crate, mutation testing, and the [parity dashboard](./parity.md).

Coverage says which code the tests run; mutation testing says whether they would notice that code
changing; the parity dashboard says how far each command has come against the Python oracle.

## Coverage gates

| | |
|---|---|
| Workflow | [`.github/workflows/coverage.yml`](https://github.com/opentidehq/opentide/blob/development/.github/workflows/coverage.yml), job **Rust coverage gates**, on every pull request and push to `development` |
| Policy | [`xtask/coverage.toml`](https://github.com/opentidehq/opentide/blob/development/xtask/coverage.toml) |
| Check | `cargo xtask coverage gate --report target/coverage.json` |
| Python | unchanged: 85% (`fail_under` in `pyproject.toml`), ci.yml's `test` job on Python 3.14 |

One instrumented build ([cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)) is measured by
two suites: every Rust test of the workspace (`cargo nextest run --workspace --profile ci`), and the
Python tests that call the PyO3 binding `opentide._native`, whose functions only Python calls. The
gate sums each workspace member's lines (every file under its directory) and compares the sum with
its gate:

| Crate | Gate | State |
|-------|-----:|-------|
| `opentide-schema` | 90% | pending: applies when UC-1.1 ([#807](https://github.com/opentidehq/opentide/issues/807)) adds the crate |
| `opentide-workspace` | 90% | pending: UC-2.1 ([#816](https://github.com/opentidehq/opentide/issues/816)) |
| `opentide-compile` | 90% | pending: UC-3.1 ([#823](https://github.com/opentidehq/opentide/issues/823)) |
| `opentide-cli` | 90% | pending: UC-3.3 ([#825](https://github.com/opentidehq/opentide/issues/825)) |
| every other member | 80% | enforced |

A pending gate needs no follow-up: it applies as soon as the crate is a workspace member, so the
change that creates the crate must already meet 90%. Rules the gate enforces on its own policy: no
entry below the default (the gate never loosens), no entry for a crate that is neither a member nor
names the work item that creates it, and no exclude list (a member none of whose lines were
measured fails).

Locally:

```bash
cargo install cargo-llvm-cov --locked && rustup component add llvm-tools-preview
cargo llvm-cov --workspace --fail-under-lines 80          # the Rust tests, the workspace total
cargo llvm-cov --workspace --no-report && \
  cargo llvm-cov report --json --summary-only --output-path target/coverage.json && \
  cargo xtask coverage gate --report target/coverage.json  # per crate, Rust tests only
```

The workflow's step "Instrumented tests" is the full measurement, the binding's Python tests
included; run its commands to reproduce it. Doctests are not measured (cargo-llvm-cov needs nightly
for them).

A child process the tests start counts only when it exits normally: a killed process writes no
profile. The language server's test client therefore ends its server with `exit` and waits for it
(`crates/opentide-lsp/tests/common/mod.rs`); before that change the stdio tests' coverage was lost
and `opentide-lsp` measured 66.8% instead of 91.8%.

## Mutation testing

| | |
|---|---|
| Workflow | [`.github/workflows/mutants.yml`](https://github.com/opentidehq/opentide/blob/development/.github/workflows/mutants.yml), Mondays 02:41 UTC and on demand |
| Policy | [`xtask/mutants.toml`](https://github.com/opentidehq/opentide/blob/development/xtask/mutants.toml) (crates, thresholds) |
| Settings | [`.cargo/mutants.toml`](https://github.com/opentidehq/opentide/blob/development/.cargo/mutants.toml) |
| Baseline | [`xtask/mutants-baseline.toml`](https://github.com/opentidehq/opentide/blob/development/xtask/mutants-baseline.toml), generated |
| Report | `cargo xtask mutants report --outcomes mutants.out/outcomes.json …` |

[cargo-mutants](https://mutants.rs) replaces a function body or an operator, one mutant at a time,
and runs the mutated crate's tests. A mutant is **caught** (a test failed), **missed** (every test
passed: it survived), **timeout** (counted as detected) or **unviable** (it did not build; not
counted). The **score** is detected (caught + timeout) over viable (caught + timeout + missed).

The plan tracks the score of `opentide-schema` and `opentide-workspace`. Until they exist the job
mutates the crates whose code becomes `opentide-workspace`: `opentide-analysis` and
`opentide-tide`. The run is split into eight shards; the `report` job merges them, prints each
crate's score against the baseline in the job summary, and writes a candidate baseline into its
artifact. On the schedule only, the `issues` job (the one job with a write permission, `issues:
write`) opens or updates one issue per crate whose survivors exceed `issue_above`, listing them.

To record a new baseline, take `mutants-baseline.toml` from a full run's `mutants-report` artifact
(or run the report locally with `--write-baseline`) and commit it in a reviewed change, lowering
`issue_above` to the new missed count. Never edit the baseline by hand.

Locally, for a change:

```bash
git diff origin/development... > /tmp/change.diff
cargo mutants -p opentide-analysis --in-diff /tmp/change.diff
```

## Parity dashboard

[`parity.md`](./parity.md) is generated by `cargo xtask parity dashboard` from the goldens
(`tests/golden/`, UC-0.5), the engine state and `compare` results (UC-0.7), the approved-diffs
ledger (`tests/golden/APPROVED_DIFFS.toml`) and the fault catalogue (UC-0.6). The
[`parity`](https://github.com/opentidehq/opentide/blob/development/.github/workflows/parity.yml)
workflow renders it on every pull request and push (job summary) and, on a push to
`development`, commits it when it changed. The page carries no date or commit, so it changes only
when the migration does.
