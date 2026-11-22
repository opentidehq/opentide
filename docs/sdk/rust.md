---
title: Rust SDK
description: The opentide crate — open a Tide workspace from Rust, validate and lint it, read its catalogue and coverage, plan a deploy, query and deploy to tenants, and run the command line.
---

# Rust SDK

The `opentide` crate is opentide's Rust API, and the only opentide crate with a stability promise. The Python package, the npm packages and the `opentide` binaries are built on the same crates; the `opentide-*` crates it wraps are internal.

## Install

The `opentide` crate and the engine crates it wraps are on [crates.io](https://crates.io/crates/opentide), and the API is on [docs.rs](https://docs.rs/opentide). Their current version is the 1.0 release candidate, `1.0.0-rc.3`. Cargo does not pick a pre-release for a requirement such as `opentide = "1"`, so name the version:

```bash
cargo add opentide@=1.0.0-rc.3 --features queries
```

```toml
[dependencies]
opentide = { version = "=1.0.0-rc.3", features = ["queries"] }
```

`queries` (the offline query engines) is a default feature of the candidates after 1.0.0-rc.1, so `features = ["queries"]` is redundant there and harmless. 1.0.0-rc.1 itself has it off by default: a program that validates with the default `ValidateOptions` needs the feature, or it fails every workspace with `engine_unavailable`.

It needs the Rust release `rust-toolchain.toml` names (1.95 or later), and a C compiler for the TLS library the `connectors` and `cli` features build. Once 1.0.0 is released, `cargo add opentide` will do. The version is the one `pip install --pre opentide` installs, which PyPI spells `1.0.0rc3`: see [release candidates](../usage/installation.md#release-candidates).

The default features open a workspace, validate and lint its objects (the offline query engines included, `queries`, from the candidate after 1.0.0-rc.1), and plan a deploy. They are the ones `opentide validate` runs on; a build that wants fewer dependencies sets `default-features = false` and names what it needs (the [feature table](#features) says what each adds).

The command line, with its `--json commands` tree identical to the PyPI package's:

```bash
cargo install opentide --version 1.0.0-rc.3 --features cli --locked
```

The language server on its own: `cargo install opentide-lsp --version 1.0.0-rc.3 --locked`, or the binaries and installers of the [GitHub Release](../usage/installation.md#release-candidates).

## Features

| Feature | Default | What it adds |
|---------|:-------:|--------------|
| `schema` | yes | `opentide::models`: the Tide models, every revision, schema identifiers |
| `analysis` | no | `opentide::analysis`: check one query on its own and highlight a text, without a workspace |
| `workspace` | yes | `Workspace`: open, `validate`, `lint`, `info`, `catalog`, `coverage` |
| `compile` | yes | `Workspace::deploy_plan` and `opentide::deploy`, and validate's compile check (a rule a deploy would compile must compile); without it `validate` compiles nothing |
| `queries` | yes | The offline query engines (KQL, SPL, ES\|QL, EQL, Kibana KQL, Lucene, Falco, CQL) behind validate's and lint's queries checks |
| `cli` | no | `opentide::cli::main(argv)`, `opentide::cli::main_with_version(argv, version)`, `opentide::cli::run_json(argv)` and the `opentide` binary; implies `compile` and `queries` |
| `cli-core` | no | The same `opentide::cli` functions without the terminal UI and the `setup` wizard's prompts (`opentide tui` and the questions refuse, as under WASI); implies `compile` and `queries`; `cli` adds the terminal |
| `lsp` | no | `opentide::lsp`: the language server, on stdio or one message at a time |
| `connectors` | no | `opentide::connectors`: the tenants a workspace configures (`Workspace::tenants`), and on each a query run, a live query check and a rule deploy; async, on tokio; implies `compile` |
| `plugins` | no | `opentide::plugins`: the platform plugin host a binding embeds to add platforms (the connectors' traits, `plugins::set_host`); implies `connectors` |
| `python` | no | `opentide::python`: the Tide models as Python classes, for the Python package's binding; brings PyO3 |
| `stubs` | no | PyO3's introspection data behind `python`, for `cargo xtask stubs` |

`queries` is a default feature (from the candidate after 1.0.0-rc.1; in 1.0.0-rc.1 it is off by default and its error message does not name it), because the default `ValidateOptions` run the queries check. Without it (`default-features = false` and no feature that implies it, such as `cli`), a queries check is never skipped: `validate` reports one `engine_unavailable` error and `lint` fails with that code. The error's message names the fix: add `features = ["queries"]` to the dependency, or turn the check off (`QueriesMode::Off`) to validate without it.

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

The example turns the queries check off with `QueriesMode::Off`, which a build without the `queries` feature needs and a default build does not: the default `ValidateOptions` check the queries of the workspace's rules offline, as `opentide validate` does. On a build with `default-features = false`, they report `engine_unavailable` (the message names the feature) and `validation.failed` is `true` for every workspace, until you add `features = ["queries"]`.

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

`deploy_plan` is `opentide deploy --dry-run`: the rules a strategy selects, the tenants each reaches and the requests a real run would send (each rule's `api_request`, as [`deploy --dry-run`](../cli/deploy.md#payloads) shows it). Nothing is sent and nothing is written. The plan is a `Document`: its text keeps the command line's key order, and its value is a `serde_json::Value` to read fields from. `DeployPlanOptions::environment` is where the tenants' `$NAME` credentials are looked up to say which are unset, as `ConnectOptions::environment` names the one a connection reads, and `Workspace::info_in` reports each variable in it; without one, the process's. `crates/opentide/examples/deploy_plan.rs`:

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

With the `connectors` feature, a `Connection` reaches one tenant through the platform connectors that `opentide query`, `opentide validate query --live` and `opentide deploy` run on: one HTTP client per tenant, with that tenant's own TLS, CA bundle, proxy, timeout and retries, and its credentials resolved from the environment, `ConnectOptions::environment` when it names one, Google SecOps's Application Default Credentials too (an unset `$NAME` is an error naming the variable, never sent). TLS roots are the system's store, which the process's `SSL_CERT_FILE` and `SSL_CERT_DIR` replace (read once per process, whatever the options say), plus the CA bundles the options' environment names (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`). `Workspace::tenants(platform)` lists the tenants a workspace configures (`[[tenants]]` in `.opentide/configurations/platforms/<platform>.toml`), and returns `Error::Usage` (`usage_invalid_choice`) for a platform that is neither built in nor a loaded plugin's; `TenantConfig::new` describes one in code. `Connection::query` refuses a `limit` outside 1 to `connectors::MAX_QUERY_LIMIT` (5000) with `usage_invalid_value`.

| Operation | Command line | Returns |
|-----------|--------------|---------|
| `Connection::query(&QueryRequest)` | `opentide query` | `QueryOutcome`: columns, rows (at most `limit`), `truncated`, the vendor's warnings |
| `Connection::validate_query(&QueryRequest)` | `opentide validate query --live` | `LiveCheck`: the one-row search's result, and the `errors` that still fail the query |
| `Connection::deploy(&DeployRequest)` | one rule of `opentide deploy` | `DeployOutcome`: the platform's identifier of the rule, and the warnings the deploy raised |

The operations are `async`, as the connectors are: run them on a [tokio](https://tokio.rs) runtime (`connection.query(&request).await`), or from synchronous code with `opentide::connectors::block_on`, which runs it on the process's one runtime (never call it inside a runtime, nor on a `spawn_blocking` thread of a runtime of yours: there it answers the code `runtime_unavailable`). A query saves nothing on the tenant. `Connection::canceller()` stops a running operation from elsewhere (the error's code is then `interrupted`), and a search the connector stops waiting for is stopped on the tenant where the API allows it (CrowdStrike). `crates/opentide/examples/query.rs`:

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
    let Some(tenant) = ws.tenants(platform)?.into_iter().next() else {
        return Err(format!("{} configures no {platform} tenant", path.display()).into());
    };
    let connection = Connection::open(&tenant, options)?;
    let now = Timestamp::now();
    let window = TimeWindow {
        start: now.checked_sub(std::time::Duration::from_hours(24))?,
        end: now,
    };
    let mut request = QueryRequest::new(query, language, window);
    request.limit = 10;
    // A synchronous caller runs the async operation on the process's runtime;
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

A platform whose connector cannot do an operation answers `operation_unsupported`, never a faked result: CrowdStrike, HarfangLab and Sysdig cannot check a query live, and Sysdig runs no queries (`opentide::connectors::capabilities(platform)` says which). A `DeployRequest` carries one rule's compiled body for one tenant, as `deploy_plan`'s payloads hold it (below for the platforms whose plan lists requests), sent as its bytes: build it with `DeployRequest::new(rule_id, operation, body)`, or `DeployRequest::delete(rule_id)` for a deletion, which takes no body (but on HarfangLab, below), and `.with_policies(..)` for a Sysdig rule's own policies. Sysdig adds a rule to its runtime policies, and takes a disabled or deleted rule out of them: the request's `policies` (`Some`: the plan entry's `policies`, which a block that names its own carries), else the tenant setup's `policies` (`None`), as `opentide deploy` chooses them. A Google SecOps payload from `deploy_plan` carries, beside the rule's `text`, the `run_state` of its status strategy (a PREVIEW rule deploys without alerting), its `run_frequency` and its `sections`, which the deploy sends; a body with the text alone deploys under RELEASE's run state, and a `disable` always disables. Graylog bodies from `deploy_plan` are compiled for Graylog 7.2, and every one carries `tags` (opentide always tags its definitions), which only 7.2 takes. The tenant's version is read first: below 6.3 it is refused; below 7.2, a create, update or disable is refused before any write with the code `graylog_field_unsupported_version`, so through the SDK such a tenant takes deletions only, and `opentide deploy`, which compiles for the tenant's version, deploys the rest. A body that fits is sent in the shape the version takes. A HarfangLab body names the rule's kind, `{"kind": "Sigma" or "YARA", "rule": <the compiled rule>}`, and a delete's names the kind alone (`{"kind": "YARA"}`; an empty one fails): a tenant takes both kinds, and the kind, the rule block's `sigma` or `yara` key, picks the endpoint. A body that names no kind fails the rule with `harfanglab_request_invalid` before any call. `deploy_plan` shows a rule on Defender for Endpoint, SentinelOne, CrowdStrike, HarfangLab, Splunk or Carbon Black Cloud as the requests a deploy sends to the plan entry's `tenant`, each `{"method", "url", "body"}`, with placeholders for values known only at send time ([deploy](../cli/deploy.md#payloads)): for Defender for Endpoint, SentinelOne and CrowdStrike, the body `deploy` takes is the first request's `body`, and for HarfangLab it is `{"kind": ..., "rule": <the first request's body>}`. Splunk's body is the saved search's settings and `search`, under `rule_id`, its name, and Carbon Black's the report's fields (`uuid`, `name`, `description`, `query`, `tags`, `severity`, `watchlist`, `report`): for these two the plan shows what the tenant receives, which `deploy` builds from that body. An Elastic body is `{"payload": <the Kibana rule>, "block": <the rule's elastic block>}`, as `opentide deploy` sends it and `deploy_plan` holds it, compiled for the entry's `tenant` (the first Elastic tenant the plan reaches) as `opentide deploy` compiles it, with that tenant's modifiers and `setup`, so another tenant with other modifiers, `tags`, `index` or `suppression` gets another Kibana rule: the rule is checked against Elasticsearch (the block's sources, else the tenant's `index`), then created, replaced or, when its type changes, created again, so `create` and `update` do the same, and `disable` writes it disabled; the Kibana rule's `rule_id` must be the request's, else the rule fails and nothing is sent; a bare Kibana rule deploys without those checks, which read the block, and says so with the warning `elastic_checks_skipped` (not raised). A tenant whose Graylog version does not revoke access tokens reliably adds the outcome's `graylog_version_vulnerable` warning: `DeployOutcome::warnings` holds what a deploy raised without failing (`code`, the event `opentide deploy` logs, `message`, and `raised`, whether it raises the run's warnings), such as a rule created again because the tenant lost it; `DeployOutcome::events` what it did (`DeployEvent`: a name and its fields, in order; empty for now on every platform but Bitdefender, Sysdig, Exabeam, Graylog, Google SecOps and Elastic, each `*_rule_created` with its `rule_id`, or Graylog's `graylog_definition_created` with its `definition_id`, and the rest). `.at(now)` fixes the time a platform stamps on what it writes (Carbon Black Cloud's report timestamp), and `.refusing_recreate(failure)` fails a rule the tenant lost with that failure instead of creating it again, as `opentide deploy` does when deployment state cannot record the new id. A whole deploy run (the plan, the deployment state, the retirements) is the command line's `deploy` (`cli::run_json`).

Failures are `Error::Connector`, with the platform, the tenant and, when the tenant gave a reason, the vendor's words in `detail`. A failed deploy is `Error::Deploy` (a boxed `DeployFailed`), never a `DeployOutcome`: it adds its `scope` (`FailureScope::Rule`, the tenant's other rules can deploy, or `FailureScope::Tenant`), the HTTP `status` when the tenant gave one, the `fields` that locate it, and `partial`: what the deploy did before failing when you must keep it (a `DeployOutcome` whose `remote_id` is the id the tenant gave the rule, which you record, with the warnings and events raised first; Sysdig's, Exabeam's, Bitdefender's and Google SecOps's for now). SentinelOne's refusals have codes of their own: `sentinel_one_rule_invalid` (400), `sentinel_one_unauthorized` (401, the tenant's), `sentinel_one_rule_not_found` (404), `sentinel_one_request_failed` (any other status), and `deployment_id_invalid` for a stored id that is not a number. `more_failures` lists the rule's further failures, in order (`DeployFailure`s), when the deploy failed more than once, as a Google SecOps rule whose text and then its deployment could not be written can. An interrupted deploy stays `Error::Connector` with the code `interrupted`. A `Deployer` returns a `DeployError` (its `scope`, its `DeployFailure`, and `.with_partial(outcome)` for what it did before failing); `From<ConnectorError>` builds one from a connector error, and `deploying` adapts a future that fails with `ConnectorError`. Messages name a tenant by its address (scheme, host and port), never a path, a query string or a credential, and no `Debug` prints a secret.

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

Every fallible call returns `opentide::Error`. Its variants each map to a stable code (`Error::code`): `configuration_invalid` or the configuration check's own code, `io_error`, the command line's usage codes, `no_json_document`, `lsp_failed`, and with `connectors` `tenant_unreachable`, `tenant_timeout`, `tenant_gateway`, `tenant_answer_invalid`, `tenant_setup_invalid`, `credential_unset`, `authentication_failed`, `tenant_refused`, `query_timed_out`, `connector_crashed`, `interrupted`, `operation_unsupported`, `runtime_unavailable` and, in the WASI build only, `network_unavailable`. Match on the code, not the message. New variants can come in a minor release, so a `match` needs a wildcard arm. Findings about the workspace are not errors: they are `Diagnostic`s in a report.

## Stability

- The crate follows semantic versioning as Cargo reads it. While it is `0.x`, a release that breaks the API raises the minor version (0.12 to 0.13); a patch release never breaks it.
- Every item the crate exports is covered, re-exported types included. The `opentide-*` crates are internal: their APIs change with the engine, at the same version.
- `cargo semver-checks` checks the crate's API in CI against the branch it merges into, until the crate is published on crates.io; from then on, against the last published version.
- Structs that may gain a field and enums that may gain a variant are `#[non_exhaustive]`: build options with their constructors and builder methods (`ValidateOptions::default().strict(true)`).
- The JSON documents follow the command line's JSON contract ([JSON output](../cli/json-output.md)), which only grows.
- The minimum supported Rust version is the manifest's `rust-version`; raising it is a minor release.

The API reference is on docs.rs, with every feature: `cargo doc -p opentide --all-features --open` builds it locally.
