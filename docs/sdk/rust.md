---
title: Rust SDK
description: The opentide crate — open a Tide workspace from Rust, validate and lint it, read its catalogue and coverage, plan a deploy, and run the command line.
---

# Rust SDK

The `opentide` crate is opentide's Rust API, and the only opentide crate with a stability promise. The Python package, the npm packages and the `opentide` binaries are built on the same crates; the `opentide-*` crates it wraps are internal.

## Install

The crate builds from this repository while the engine crates it wraps are not yet on crates.io:

```toml
[dependencies]
opentide = { git = "https://github.com/opentidehq/opentide" }
```

It needs the Rust release `rust-toolchain.toml` names, and builds the query engines' grammars with a C compiler. Once it is published, `cargo add opentide` will do.

The command line, with its `--json commands` tree identical to the PyPI package's:

```bash
cargo install --git https://github.com/opentidehq/opentide opentide --features cli
```

## Features

| Feature | Default | What it adds |
|---------|:-------:|--------------|
| `schema` | yes | `opentide::models`: the Tide models, every revision, schema identifiers |
| `workspace` | yes | `Workspace`: open, `validate`, `lint`, `info`, `catalog`, `coverage` |
| `compile` | yes | `Workspace::deploy_plan` and `opentide::deploy` |
| `queries` | no | The offline query engines (KQL, SPL, ES\|QL, EQL, Kibana KQL, Lucene, Falco, CQL) behind validate's and lint's queries checks |
| `cli` | no | `opentide::cli::main(argv)`, `opentide::cli::run_json(argv)` and the `opentide` binary; implies `compile` and `queries` |
| `lsp` | no | `opentide::lsp`: the language server, on stdio or one message at a time |

Without `queries`, a queries check is never skipped: `validate` reports one `engine_unavailable` error and `lint` fails with that code. Turn the check off (`QueriesMode::Off`) to validate without it. The platform connectors (deploy, live query validation, query runs) will come behind a `connectors` feature.

## Open a workspace

`Workspace::open` takes the repository's folder (the one with `.opentide/` and `objects/`). `Workspace::from_files` opens one held in memory, for an editor's buffers, a browser or a test:

```rust
use opentide::validate::QueriesMode;
use opentide::{ValidateOptions, Workspace};

fn main() -> Result<(), opentide::Error> {
    let ws = Workspace::from_files(
        "/ws",
        [(
            "objects/rules/example.yaml",
            "name: Example\nmetadata:\n  uuid: 11111111-1111-4111-8111-111111111111\n  schema: rule::1.1\n",
        )],
    )?;
    assert_eq!(ws.info().counts.rules, 1);
    let validation = ws.validate(&ValidateOptions::default().queries(QueriesMode::Off));
    for finding in validation.report.issues.iter().chain(&validation.report.warnings) {
        println!("{}: {}", finding.code, finding.message);
    }
    Ok(())
}
```

Opening reads every object file once, in parallel, into one index; each operation then reads the index, so keep the `Workspace` and run as many operations on it as you need.

## Validate a workspace

`validate` runs every check of `opentide validate` and returns what `validate --json` reports: the checks with their status, the report and its counts. Each finding is a `Diagnostic` with its code, severity, file, 1-based line and column, field path, suggestion and fix. The example `crates/opentide/examples/validate.rs` prints them:

```bash
cargo run -p opentide --example validate -- path/to/workspace
```

```rust no_run
use opentide::validate::{Check, QueriesMode};
use opentide::{Options, ValidateOptions, Workspace};

fn main() -> Result<(), opentide::Error> {
    let ws = Workspace::open("path/to/workspace", &Options::default())?;
    let options = ValidateOptions::default()
        .check(Check::Schema)
        .object_type("rule")
        .strict(true)
        .queries(QueriesMode::Off);
    let validation = ws.validate(&options);
    for finding in &validation.report.issues {
        println!(
            "{}:{}: {}",
            finding.path.as_deref().unwrap_or("-"),
            finding.line.unwrap_or(0),
            finding.message
        );
    }
    std::process::exit(validation.exit_code());
}
```

`lint` runs `opentide lint` the same way (`LintOptions`, `LintReport`), without `--fix`.

## Print the catalogue

`info`, `catalog` and `coverage` return the data of `opentide info`, `info catalog` and `info coverage`; each serialises with `serde` to the command line's JSON. `crates/opentide/examples/catalog.rs`:

```bash
cargo run -p opentide --example catalog -- path/to/workspace T1059
```

```rust no_run
use opentide::{Options, Workspace};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ws = Workspace::open("path/to/workspace", &Options::default())?;
    let info = ws.info();
    println!("{} rules, {} load errors", info.counts.rules, info.load_errors);
    let catalogue = ws.catalog();
    println!("{}", serde_json::to_string(&catalogue)?);
    let coverage = ws.coverage("T1059");
    println!("{} rules cover {}", coverage.count, coverage.technique);
    Ok(())
}
```

## Plan a deploy

`deploy_plan` is `opentide deploy --dry-run`: the rules a strategy selects, the tenants each reaches and the request bodies a real run would send. Nothing is sent and nothing is written. The plan is a `Document`: its text keeps the command line's key order, and its value is a `serde_json::Value` to read fields from. `crates/opentide/examples/deploy_plan.rs`:

```bash
cargo run -p opentide --example deploy_plan -- path/to/workspace PREVIEW
```

```rust no_run
use opentide::{DeployPlanOptions, Options, Strategy, Workspace};

fn main() -> Result<(), opentide::Error> {
    let ws = Workspace::open("path/to/workspace", &Options::default())?;
    let plan = ws.deploy_plan(&DeployPlanOptions::new(Strategy::Preview))?;
    for change in plan.document().value()["changes"].as_array().into_iter().flatten() {
        println!("{} {} on {}", change["action"], change["name"], change["platform"]);
    }
    println!("{}", plan.document());
    Ok(())
}
```

## Run the command line

With the `cli` feature, `opentide::cli::run_json` runs one command in the process and returns its `--json` document, and `opentide::cli::main` is the whole program:

```rust ignore
fn main() -> Result<(), opentide::Error> {
    let info = opentide::cli::run_json(["--repo", "path/to/workspace", "info"])?;
    println!("{}", info.value()["counts"]["rules"]);
    Ok(())
}
```

## Errors

Every fallible call returns `opentide::Error`. Its variants each map to a stable code (`Error::code`): `configuration_invalid` or the configuration check's own code, `io_error`, the command line's usage codes, `no_json_document`, `lsp_failed`. Match on the code, not the message. New variants can come in a minor release, so a `match` needs a wildcard arm. Findings about the workspace are not errors: they are `Diagnostic`s in a report.

## Stability

- The crate follows semantic versioning as Cargo reads it. While it is `0.x`, a release that breaks the API raises the minor version (0.12 to 0.13); a patch release never breaks it.
- Every item the crate exports is covered, re-exported types included. The `opentide-*` crates are internal: their APIs change with the engine, at the same version.
- `cargo semver-checks` checks the crate's API in CI against the branch it merges into.
- Structs that may gain a field and enums that may gain a variant are `#[non_exhaustive]`: build options with their constructors and builder methods (`ValidateOptions::default().strict(true)`).
- The JSON documents follow the command line's JSON contract ([JSON output](../cli/json-output.md)), which only grows.
- The minimum supported Rust version is the manifest's `rust-version`; raising it is a minor release.

The API reference is on docs.rs, with every feature: `cargo doc -p opentide --all-features --open` builds it locally.
