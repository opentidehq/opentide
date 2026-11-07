# Parked: language-server's workflows

These are opentidehq/language-server's GitHub Actions workflows, imported with their history
(#800, `docs/engine/IMPORT.md`). GitHub runs only `.github/workflows/`, so none of them runs here.
UC-0.3 (#801) rebuilds one CI for the repository from them.

| Workflow | Here |
| --- | --- |
| `ci.yml` | Its fmt, clippy, tests and engine checks run in `.github/workflows/ci.yml` (jobs `engine`, `engine-wasm`); the rest (Windows, packaging, grammars, clients, the Elastic sweep, benchmarks) waits for UC-0.3 |
| `release.yml` | Must not run as it is: it triggers on `v*.*.*` tags, which are opentide's release tags here, and would publish the engine crates and npm packages on an opentide release |
| `fuzz.yml` | Nightly cargo-fuzz; waits for UC-0.3 |
| `backfill-releases.yml` | One-off, for language-server's early tags; not needed here |

`oracle.yml` (the vendor-parser oracles) runs from `.github/workflows/oracle.yml`. language-server's
`opentide-canary.yml` is gone: `tests/test_generation/test_bundled_tide_catalog.py` checks the
bundled Tide catalog against this checkout's models.
