# Parked: language-server's release workflows

These are opentidehq/language-server's GitHub Actions workflows that must not run here yet,
imported with their history (#800, `docs/engine/IMPORT.md`). GitHub runs only
`.github/workflows/`. UC-0.3 (#801) brings engine releases back.

| Workflow | Here |
| --- | --- |
| `release.yml` | Must not run as it is: it triggers on `v*.*.*` tags, which are opentide's release tags here, and would publish the engine crates and npm packages on an opentide release (`tests/test_package/test_layout.py` fails if an active workflow publishes them) |
| `backfill-releases.yml` | One-off, for language-server's early tags; not needed here |

The others run from `.github/workflows/`:

| language-server | Here |
| --- | --- |
| `ci.yml` | `engine-ci.yml` (Windows, crate packaging and licence scan, grammar regeneration, TextMate grammars, LSP clients, benchmarks, the Elastic sweep); its rustfmt, clippy, tests, engine checks, WebAssembly builds and npm packages run in `ci.yml`, jobs `engine` and `engine-wasm` |
| `fuzz.yml` | `engine-fuzz.yml`, nightly |
| `oracle.yml` | `oracle.yml`, without its tag trigger |
| `opentide-canary.yml` | gone: `tests/test_generation/test_bundled_tide_catalog.py` checks the bundled Tide catalog against this checkout's models |

## Before engine releases resume here

- `release.yml` needs tags of its own (not `v*.*.*`) and actions pinned by commit. Its paths
  already follow the import (`scripts/engine/`, `data/catalogs/`, `cargo package --exclude
  opentide-native`).
- `fuzz/Cargo.lock` has been stale since language-server 0.7.1: cargo-fuzz re-resolves it on
  each run. Refresh it before anything passes `--locked` there.
- The crates' readmes (`crates/COMPONENT.md`, `crates/opentide-analysis/README.md`,
  `crates/opentide-lsp/README.md`) still link to language-server's releases and changelog.
