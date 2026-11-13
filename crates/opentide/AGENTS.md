# opentide (the facade) — agent guide

The `opentide` crate: the Rust SDK and the only opentide crate with a stability promise (plan §4,
"The facade API"; D-5, [ADR 0005](../../docs/internal/adr/0005-opentide-facade-crate.md);
UC-5.1, #836). Every binding is to wrap it and nothing else (UC-5.2, UC-5.3).

## Place

facade (`xtask/layers.toml`), above the applications: its features reach opentide-cli (`queries`,
`cli`), opentide-lsp (`lsp`) and opentide-connectors (`connectors`). `publish = false` while the engine crates it wraps are
unpublished; `cargo package` leaves it out and the licence scan reads its source (`ci.yml`
`engine-package`, `engine-release.yml`, `scripts/ci-local.sh`). The name on crates.io is held by
`publishing/placeholders/crates/opentide` until then.

## Layout

| Path | What |
| --- | --- |
| `src/lib.rs` | The crate's page: features, errors, the stability policy; the re-exports |
| `src/error.rs` | `Error`: `#[non_exhaustive]`, each variant with a stable code (`Error::code`) |
| `src/document.rs` | `Document`: a JSON document's text (key order kept: `serde_json` sorts keys, and the workspace never turns on `preserve_order`) and its value |
| `src/workspace.rs` | `Workspace` (a newtype over `opentide_workspace::Workspace`): `open`, `from_files`, `validate`, `lint`, `info`, `catalog`, `coverage`; `Options`, `ValidateOptions`, `LintOptions`, `Info` |
| `src/queries.rs` | The queries checks: the engines (`queries` feature, from opentide-cli's `queries`), else a stand-in that reports `engine_unavailable` |
| `src/deploy.rs` | `Workspace::deploy_plan` over `opentide_compile::dry_run`; `Strategy`, `DeployPlanOptions`, `DeployPlan` |
| `src/models.rs`, `catalog.rs`, `validate.rs`, `lint.rs` | Curated re-exports of the internal crates' types |
| `src/cli.rs` | `cli` feature: `main`, `exit`, `run_json`, `VERSION` |
| `src/lsp.rs` | `lsp` feature: `run_stdio`, `serve`, `MessageSession` |
| `src/connectors.rs` | `connectors` feature: `Workspace::tenants`, `TenantConfig`, `ConnectOptions`, `Connection` (`query`, `validate_query`, `deploy`: async, on tokio, over `opentide-connectors`' traits), `Canceller`, `block_on`, `Error::Connector`'s codes |
| `src/bin/opentide.rs` | The `opentide` binary (`required-features = ["cli"]`) |
| `examples/` | `validate`, `catalog`, `deploy_plan`, `query` (`connectors`): the four examples of `docs/sdk/rust.md`; the page shows `query`'s `docs:start`..`docs:end` part verbatim, which `tests/examples.rs` checks |
| `tests/api.rs` | The API on `tests/fixtures/tide_corpus` laid out under a temporary folder |
| `tests/examples.rs` | Each example compiled in (`#[path]`) and run on the corpus |
| `tests/cli.rs` | `cli`: the binary's `--json commands` against the PyPI CLI's recording, through the goldens' comparator and `APPROVED_DIFFS.toml`; `run_json` |
| `tests/lsp.rs` | `lsp`: the lifecycle over frames and one message at a time |
| `tests/connectors.rs` | `connectors`: tenants from a workspace, and query, live check, deploy, cancellation and errors on wiremock stand-in tenants (each connection is given its environment, so no proxy of the process applies) |
| `tests/conformance.rs` | `cli` and `connectors`: the Rust runner of the cross-SDK conformance suite (UC-5.4, `tests/conformance/README.md`); on its own, every operation on the corpus, and the tenant operations on the stand-in tenants of `tests/cassettes/` it starts with `python3` (`$PYTHON`) |

`docs/sdk/rust.md` and `README.md` are doctests too (`#[cfg(doctest)]` items in `lib.rs`).

## Rules

- **Curate, do not leak.** Add a re-export only for a type the API returns or takes. A function
  here wraps one call of an internal crate; logic belongs in the domain crates.
- **Semver.** Every exported item is the API, re-exports included. New options structs and enums
  are `#[non_exhaustive]` with a `Default` and builder methods. A breaking change raises the minor
  version while 0.x and gets a **Breaking** entry in `crates/CHANGELOG.md`. CI's `facade` job runs
  `cargo semver-checks` against the base branch.
- **Docs.** `missing_docs` holds; every public item has a doc comment, and a sample is a doctest.
  `cargo doc -p opentide --all-features --no-deps` with `RUSTDOCFLAGS=-D warnings` is clean.
- **Features.** A build without `queries` never skips a queries check: it reports
  `engine_unavailable`. A feature's tests gate themselves (`#![cfg(feature = "...")]` at the file's
  top), never with a `[[test]]` table: the Python sdist leaves `tests/` out, and a table naming a
  missing file stops its manifest from parsing (`tests/test_package/test_layout.py` checks every
  member). CI's `facade` job runs them all (`--all-features`), and the workspace's run the default
  ones.
- **Async.** The tenant operations (`connectors`) are `async fn`s on tokio, as the plan's facade
  sketch has them (`connectors::deploy(...).await`) and as the connectors are; `block_on` serves a
  synchronous caller. Nothing else in the crate is async, and no other feature pulls in tokio.
- **The binary.** opentide-cli also builds a binary named `opentide`; this crate's is built only
  with `cli`, so a workspace build never builds both, and opentide-cli's is not documented
  (`doc = false`), whose page would take this crate's path (cargo#6313).

## Verify

```bash
cargo test -p opentide
cargo test -p opentide --all-features
RUSTDOCFLAGS="-D warnings" cargo doc -p opentide --all-features --no-deps
cargo run -p opentide --example validate -- <workspace>
cargo semver-checks -p opentide --baseline-rev origin/integration/unified-core
```
