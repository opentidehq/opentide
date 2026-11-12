# opentide

The Rust SDK of [opentide](https://opentide.org), spec-driven development for agentic detection engineering. Open a Tide workspace (threat vectors, detection objectives and detection rules as YAML, with their configuration), validate and lint it, read its catalogue and ATT&CK coverage, plan a deploy to the nine platforms opentide deploys to, and run the `opentide` command line.

```rust
use opentide::validate::QueriesMode;
use opentide::{ValidateOptions, Workspace};

fn main() -> Result<(), opentide::Error> {
    let ws = Workspace::from_files(
        "/ws",
        [(
            "objects/rules/example.yaml",
            "name: Example\nmetadata:\n  uuid: not-a-uuid\n  schema: rule::1.1\n",
        )],
    )?;
    let validation = ws.validate(&ValidateOptions::default().queries(QueriesMode::Off));
    assert!(validation.failed);
    for finding in &validation.report.issues {
        println!("{}: {}", finding.code, finding.message);
    }
    Ok(())
}
```

`Workspace::open(path, &Options::default())` opens one on disk. The examples run on any workspace:

```bash
cargo run -p opentide --example validate -- path/to/workspace
cargo run -p opentide --example catalog -- path/to/workspace T1059
cargo run -p opentide --example deploy_plan -- path/to/workspace PREVIEW
```

| Feature | Default | What it adds |
|---------|:-------:|--------------|
| `schema` | yes | The Tide models (`opentide::models`) |
| `workspace` | yes | `Workspace`: open, validate, lint, info, catalogue, coverage |
| `compile` | yes | `Workspace::deploy_plan` |
| `queries` | no | The offline query engines behind validate's and lint's queries checks |
| `cli` | no | `opentide::cli::{main, run_json}` and the `opentide` binary (`cargo install opentide --features cli`) |
| `lsp` | no | The language server (`opentide::lsp`) |
| `connectors` | no | Tenant operations (`opentide::connectors`): a query run, a live query check and a rule deploy on a workspace's tenants; async, on tokio |

This is the only opentide crate with a stability promise: semantic versioning, checked with `cargo semver-checks`. The `opentide-*` crates it builds on are internal. The documentation is on [docs.rs](https://docs.rs/opentide) and on [opentide.org](https://opentide.org/docs/sdk/rust).

Licensed under the [EUPL-1.2](https://github.com/opentidehq/opentide/blob/development/LICENSE).
