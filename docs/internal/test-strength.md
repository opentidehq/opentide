---
title: Test strength
description: How strong the verifier is — Rust line coverage per crate with its gates and mutation testing, once, as a time-boxed experiment (UC-X.2, #844); the parity dashboard was retired with the Python implementation (UC-6.2).
---

# Test strength

> Status: **implemented** by UC-X.2; mutation testing ran once, as a time-boxed experiment (below, [#844](https://github.com/opentidehq/opentide/issues/844)),
> plan [§5.4 "Strength"](https://github.com/opentidehq/opentide/blob/docs/unified-core-plan/docs/internal/unified-core.md#54-layered-tests). Three measures: coverage gates per
> crate, mutation testing, and the parity dashboard, retired since (UC-6.2).

Coverage says which code the tests run; mutation testing says whether they would notice that code
changing. The parity dashboard said how far each command had come against the Python oracle.

## Coverage gates

| | |
|---|---|
| Workflow | [`.github/workflows/coverage.yml`](https://github.com/opentidehq/opentide/blob/development/.github/workflows/coverage.yml), job **Rust coverage gates**, in CI's nightly set: nightly and on demand |
| Policy | [`xtask/coverage.toml`](https://github.com/opentidehq/opentide/blob/development/xtask/coverage.toml) |
| Check | `cargo xtask coverage gate --report target/coverage.json` |
| Python | unchanged: 85% (`fail_under` in `pyproject.toml`), ci.yml's `test` job on Python 3.14 |

One instrumented build ([cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)) is measured by
two suites: every Rust test of the workspace (`cargo nextest run --workspace --profile ci`), and the
whole Python suite, unit and end-to-end, since only Python calls the functions of the PyO3 binding
`opentide._native` (directly, or through `opentide.analysis` and the CLI). Only the GitLab lint
tests are left out: they need binaries the job does not install and reach no Rust. The
gate sums each workspace member's lines (every file under its directory) and compares the sum with
its gate:

| Crate | Gate | State |
|-------|-----:|-------|
| `opentide-schema` | 90% | enforced since UC-1.1 ([#807](https://github.com/opentidehq/opentide/issues/807)) added the crate |
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

The workflow's step "Instrumented tests" is the full measurement, the Python suite included; run its commands to reproduce it. Doctests are not measured (cargo-llvm-cov needs nightly
for them).

A child process the tests start counts only when it exits normally: a killed process writes no
profile. The language server's test client therefore ends its server with `exit` and waits for it
(`crates/opentide-lsp/tests/common/mod.rs`); before that change the stdio tests' coverage was lost
and `opentide-lsp` measured 66.8% instead of 91.8%.

## Mutation testing

Mutation testing is not a recurring job here. It ran once, as a time-boxed experiment (#844,
November 2026), to measure how strong the tests of `opentide-schema` and `opentide-workspace` are
and to find the gaps worth a test. This section is that experiment's record; the full list of
surviving mutants is [`mutants-844.txt`](mutants-844.txt).

[cargo-mutants](https://mutants.rs) replaces a function body or an operator, one mutant at a time,
and runs the mutated crate's tests. A mutant is **caught** (a test failed), **missed** (every test
passed: it survived), **timeout** (counted as detected) or **unviable** (it did not build; not
counted). The **score** is detected (caught + timeout) over viable (caught + timeout + missed).

### What ran

| | |
|---|---|
| Tool | cargo-mutants 27.1.0, nextest, the settings of [`.cargo/mutants.toml`](../../.cargo/mutants.toml) |
| Crates | `opentide-schema` and `opentide-workspace`, each with its own tests only |
| Where | GitHub Actions, run 44336903971 (a branch made for it and deleted after), 32 shards |
| Time box | 105 minutes of mutation per shard (`timeout --signal=INT`), 120 per job |
| Mutants | 6,651, 208 a shard (203 in the last). The shards are contiguous slices of the files: 0 to 20 are `opentide-schema`'s (4,368), 22 to 31 `opentide-workspace`'s (2,075), and shard 21 holds the end of one and the start of the other |

**The `opentide-schema` score is partial.** Of the 32 shards, 24 finished. Six (0, 1, 4, 8, 15, 20, all `opentide-schema`) reached the time box
while building a mutant, and two (13, 14) were stopped by a runner shutdown, not the box. Every
shard of `opentide-workspace` finished; 13 of the 21 `opentide-schema`-only shards did, so its score
covers 2,704 of at least 4,368 mutants. The stopped shards' surviving mutants are still in the list below
(cargo-mutants prints each one as it finds it), but their caught and unviable counts are not known. A mutant
takes a build of the crate and a run of its tests, about 30 s on a runner, so 208 mutants a shard
is near the limit of the box.

### Scores

From the 24 shards that finished (a shard prints its counts only when it ends):

| Crate | Mutants tested | Caught | Timeout | Missed | Unviable | Score |
|---|---:|---:|---:|---:|---:|---:|
| `opentide-workspace` (shards 22 to 31: all of it but its part of shard 21) | 2,075 | 1,467 | 10 | 351 | 247 | **80.8%** |
| `opentide-schema` (13 of its 21 whole shards) | 2,704 | 2,011 | 9 | 390 | 294 | **83.8%** |
| Shard 21 (both crates) | 208 | 141 | 4 | 37 | 26 | 79.7% |

Counting every shard's surviving-mutant lines, the finished and the stopped ones: **901 survivors**,
524 in `opentide-schema` and 377 in `opentide-workspace`, and 32 timeouts.

### The survivors, triaged

cargo-mutants runs only the mutated crate's tests. Much of what these crates do is held by the
tests of the crates above them, above all the command line's snapshots (`opentide-cli`'s
`cli_snapshots`), so a survivor here is first a mutant that *this crate's* tests do not hold.

| Kind | Schema | Workspace | Verdict |
|---|---:|---:|---|
| `JsonSchema` implementations | 51 | | Held elsewhere: `cargo xtask codegen --check` compares the generated schemas, not a test of the crate |
| `IntoPyObject` implementations | 8 | | Held elsewhere: the Python suite, through `opentide._native` |
| `Display` and `Debug` implementations | 3 | 5 | Equivalent where only a debug format changes; the rest are in the gap list |
| A whole function body replaced (`vec![]`, `None`, `true`, `""`, `()`) | 158 | 113 | Gap: a function no test of the crate calls with an input that tells |
| Comparisons, `&&`/`\|\|`, `!`, match arms and guards | 234 | 212 | Gap, mostly: a branch no test takes both ways |
| Arithmetic and shifts (`+` to `*`, `-` to `/`, a unary `-` deleted) | 68 | 42 | Gap or equivalent: many are positions and lengths the snapshots hold |
| A struct literal's field deleted | 2 | 5 | Gap: a default no test tells from the value |
| **Total** | **524** | **377** | |

The largest files: `opentide-workspace`'s `validate/mod.rs` (102), `validate/objects.rs` (54),
`fs.rs` (35), `validate/annotate.rs` (26) and `lint/mod.rs` (25); `opentide-schema`'s `python.rs`
(53, the PyO3 surface, held by the Python suite), `harfanglab/yara.rs` (43), `generate/schema.rs`
(38) and `configuration/types.rs` (34).

Fixed in #844: **23 survivors**, each killed by a test that fails with the mutant (checked by a
cargo-mutants run on the functions, and by hand):

- `Context::error_count -> 0` (`opentide-schema`'s `from_node.rs`): with it, a model's
  `mode="after"` validator ran on a model whose fields had already failed, and reported a second
  error. `an_after_validator_waits_for_the_fields`.
- 22 in `opentide-workspace`'s `validate/mod.rs`, the checks a user sees, which only the command
  line's snapshots held (tests in `crates/opentide-workspace/tests/validate.rs`):
  - the cross-rule name checks (`title_duplicates`, `exabeam_names`, `name_duplicates`: Graylog
    titles, Exabeam names, Google SecOps rule names), each finding on its own rule's file;
  - `Check::name` and `Check::parse`, `Validation::exit_code` and `checks_json`;
  - `compile_findings` and `nearest_key_line`: a compiler's refusal at its block, at a key the
    block lacks and at a key it has.

The other survivors are listed in [`mutants-844.txt`](mutants-844.txt); the 819 that are neither
killed here nor held elsewhere are followed by file in
[#1614](https://github.com/opentidehq/opentide/issues/1614), `validate/` and the platform models
first.

### Running it again

By hand, for a crate or for what a change touches (settings in `.cargo/mutants.toml`):

```bash
export CARGO_TARGET_DIR=<a target pool that holds the workspace's build>
cargo mutants -p opentide-workspace --in-place --cap-lints false
git diff origin/development... > /tmp/change.diff
cargo mutants -p opentide-workspace --in-place --cap-lints false --in-diff /tmp/change.diff
```

`--in-place` mutates the checkout (leave it alone until the run ends: cargo-mutants restores each
file) and builds in `CARGO_TARGET_DIR`; `--cap-lints false` keeps the build's own flags. Together they
reuse a warm build; without them, cargo-mutants copies the tree and builds the workspace from
scratch. A whole crate takes hours; `--shard k/n` splits it, `-f <file>` and `-F <regex>` narrow it.

## Parity dashboard (retired)

The dashboard (`cargo xtask parity dashboard`, `docs/internal/parity.md`, the `parity` workflow)
tabled, per command, which engine ran it and how its compare run stood against the Python oracle.
UC-6.2 ([#841](https://github.com/opentidehq/opentide/issues/841)) made the Rust core the only
engine, so every row would have read the same: it was retired with the Python implementation.
What it summarised is CI's `Golden compare` job (`cargo xtask golden check --engine rust`): every
golden case against the oracle's recording, through the approved-diffs ledger. That job, the recordings and the
ledger were retired in turn ([#1142](https://github.com/opentidehq/opentide/issues/1142)): the CLI's
Rust-owned snapshots hold its behaviour.
