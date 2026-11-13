---
title: Rust SDK
description: The opentide crate — open a Tide workspace from Rust, validate and lint it, read its catalogue and coverage, plan a deploy, query and deploy to tenants, and run the command line.
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
| `analysis` | no | `opentide::analysis`: check one query on its own and highlight a text, without a workspace |
| `workspace` | yes | `Workspace`: open, `validate`, `lint`, `info`, `catalog`, `coverage` |
| `compile` | yes | `Workspace::deploy_plan` and `opentide::deploy`, and validate's compile check (a rule a deploy would compile must compile); without it `validate` compiles nothing |
| `queries` | no | The offline query engines (KQL, SPL, ES\|QL, EQL, Kibana KQL, Lucene, Falco, CQL) behind validate's and lint's queries checks |
| `cli` | no | `opentide::cli::main(argv)`, `opentide::cli::main_with_version(argv, version)`, `opentide::cli::run_json(argv)` and the `opentide` binary; implies `compile` and `queries` |
| `lsp` | no | `opentide::lsp`: the language server, on stdio or one message at a time |
| `connectors` | no | `opentide::connectors`: the tenants a workspace configures (`Workspace::tenants`), and on each a query run, a live query check and a rule deploy; async, on tokio; implies `compile` |
| `plugins` | no | `opentide::plugins`: the platform plugin host a binding embeds to add platforms (the connectors' traits, `plugins::set_host`); implies `connectors` |
| `python` | no | `opentide::python`: the Tide models as Python classes, for the Python package's binding; brings PyO3 |
| `stubs` | no | PyO3's introspection data behind `python`, for `cargo xtask stubs` |

Without `queries`, a queries check is never skipped: `validate` reports one `engine_unavailable` error and `lint` fails with that code. Turn the check off (`QueriesMode::Off`) to validate without it.

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

## Query, check and deploy on tenants

With the `connectors` feature, a `Connection` reaches one tenant through the platform connectors that `opentide query`, `opentide validate query --live` and `opentide deploy` run on: one HTTP client per tenant, with that tenant's own TLS, CA bundle, proxy, timeout and retries, and its credentials resolved from the environment (an unset `$NAME` is an error naming the variable, never sent). `Workspace::tenants(platform)` lists the tenants a workspace configures (`[[tenants]]` in `.opentide/configurations/platforms/<platform>.toml`); `TenantConfig::new` describes one in code.

| Operation | Command line | Returns |
|-----------|--------------|---------|
| `Connection::query(&QueryRequest)` | `opentide query` | `QueryOutcome`: columns, rows (at most `limit`), `truncated`, the vendor's warnings |
| `Connection::validate_query(&QueryRequest)` | `opentide validate query --live` | `LiveCheck`: the one-row search's result, and the `errors` that still fail the query |
| `Connection::deploy(&DeployRequest)` | one rule of `opentide deploy` | `DeployOutcome`: the platform's identifier of the rule |

The operations are `async`, as the connectors are: run them on a [tokio](https://tokio.rs) runtime (`connection.query(&request).await`), or from synchronous code with `opentide::connectors::block_on`, which starts a runtime of its own (never call it inside one). A query saves nothing on the tenant. `Connection::canceller()` stops a running operation from elsewhere (the error's code is then `interrupted`), and a search the connector stops waiting for is stopped on the tenant where the API allows it (CrowdStrike). `crates/opentide/examples/query.rs`:

```bash
cargo run -p opentide --features connectors --example query -- path/to/workspace splunk spl 'index=main | head 5'
```

```rust ignore
use std::io::Write;
use std::path::Path;

use opentide::connectors::{self, ConnectOptions, Connection, QueryRequest, TimeWindow, Timestamp};
use opentide::{Options, Workspace};

/// Runs `query`, written in `language` (`spl`, `kql`, `esql`, `powerquery`,
/// ...), on the first tenant the workspace at `path` configures for
/// `platform`, over the last 24 hours, and writes each row to `out` as one
/// JSON line.
pub fn run(
    path: &Path,
    platform: &str,
    language: &str,
    query: &str,
    options: &ConnectOptions,
    out: &mut dyn Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws = Workspace::open(path, &Options::default())?;
    let Some(tenant) = ws.tenants(platform).into_iter().next() else {
        return Err(format!("{} configures no {platform} tenant", path.display()).into());
    };
    let connection = Connection::open(&tenant, options)?;
    let now = Timestamp::now();
    let window = TimeWindow {
        start: now.checked_sub(std::time::Duration::from_secs(24 * 60 * 60))?,
        end: now,
    };
    let mut request = QueryRequest::new(query, language, window);
    request.limit = 10;
    // A synchronous caller runs the async operation on a runtime of its own;
    // in a tokio task, `connection.query(&request).await?` instead.
    let outcome = connectors::block_on(connection.query(&request))??;
    for row in &outcome.rows {
        writeln!(out, "{}", serde_json::to_string(row)?)?;
    }
    if outcome.truncated {
        writeln!(out, "(more than {} rows)", request.limit)?;
    }
    Ok(())
}
```

A platform whose connector cannot do an operation answers `operation_unsupported`, never a faked result: CrowdStrike, HarfangLab and Sysdig cannot check a query live, Sysdig runs no queries, and Elastic and Sysdig rules deploy through `opentide deploy` only (`opentide::connectors::capabilities(platform)` says which). A `DeployRequest` carries one rule's compiled body for one tenant, as `deploy_plan`'s payloads hold it, sent as its bytes; a whole deploy run (the plan, the deployment state, the retirements) is the command line's `deploy` (`cli::run_json`).

Failures are `Error::Connector`, with the platform, the tenant and, when the tenant gave a reason, the vendor's words in `detail`. Messages name a tenant by its address (scheme, host and port), never a path, a query string or a credential, and no `Debug` prints a secret.

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

Every fallible call returns `opentide::Error`. Its variants each map to a stable code (`Error::code`): `configuration_invalid` or the configuration check's own code, `io_error`, the command line's usage codes, `no_json_document`, `lsp_failed`, and with `connectors` `tenant_unreachable`, `tenant_timeout`, `tenant_gateway`, `tenant_answer_invalid`, `tenant_setup_invalid`, `credential_unset`, `authentication_failed`, `tenant_refused`, `query_timed_out`, `connector_crashed`, `interrupted`, `operation_unsupported` and `runtime_unavailable`. Match on the code, not the message. New variants can come in a minor release, so a `match` needs a wildcard arm. Findings about the workspace are not errors: they are `Diagnostic`s in a report.

## Stability

- The crate follows semantic versioning as Cargo reads it. While it is `0.x`, a release that breaks the API raises the minor version (0.12 to 0.13); a patch release never breaks it.
- Every item the crate exports is covered, re-exported types included. The `opentide-*` crates are internal: their APIs change with the engine, at the same version.
- `cargo semver-checks` checks the crate's API in CI against the branch it merges into, until the crate is published on crates.io; from then on, against the last published version.
- Structs that may gain a field and enums that may gain a variant are `#[non_exhaustive]`: build options with their constructors and builder methods (`ValidateOptions::default().strict(true)`).
- The JSON documents follow the command line's JSON contract ([JSON output](../cli/json-output.md)), which only grows.
- The minimum supported Rust version is the manifest's `rust-version`; raising it is a minor release.

The API reference is on docs.rs, with every feature: `cargo doc -p opentide --all-features --open` builds it locally.
