# Configuration schemas (test data)

`schemas/` is opentide's export of the configuration TOML schemas, written by
opentide itself:

```bash
uv run --project <opentide checkout> python -m opentide.generation.configuration_schemas crates/testdata/config/schemas
```

The files here came from opentide at `615cbdc` (the `claude/friendly-bardeen-y8tdxm` branch, after CoreTIDE's `[tide]` table was dropped). Only
the tests read them (`crates/opentide-analysis/tests/configuration.rs`): they
exercise the engine's schema walker for hover and completion. The engine
bundles no configuration schema. At run time the host installs its own
(`opentide_analysis::install_configuration_schemas`), generated from the
models it validates with, so these copies going stale changes nothing a user
sees. Do not edit them by hand. Regenerate them when a test needs a newer
schema.
