# OpenTide Copilot Instructions

## Project Identity

**OpenTide** (`opentide`) is the DetectionOps engine for the OpenTide framework — a versioned Python package on PyPI that powers detection-as-code deployment across seven security platforms. It is the successor to [CoreTide](https://github.com/OpenTideHQ/CoreTide), which was historically consumed as a git submodule.

OpenTide is **not** the detection content. Client repositories hold YAML objects (rules, threat vectors, objectives); OpenTide validates, indexes, deploys, and documents that content.

**Programme**: [Project TideKit](https://github.com/OpenTideHQ/CoreTide/issues/60) — tracked phases [#61–#71](https://github.com/OpenTideHQ/CoreTide/issues?q=is%3Aissue+milestone%3A%22Project+TideKit%22). Agents: read [`AGENTS.md`](../AGENTS.md) before implementing a phase.

---

## Architecture Overview

### Target Package Layout (post-Phase 5)

```
src/opentide/
├── core/           # registry.py (OpenTide), index.py, environment.py, loaders/
├── models/         # DetectionRule, ThreatVector, DetectionObjective (Pydantic)
├── platforms/      # Per-platform deployer + validator packages
├── generation/     # schemas, templates, snippets, index builder
├── validation/     # Schema + query validators
├── documentation/  # Wiki generation
├── cli/            # Typer CLI (opentide)
├── mcp_server/     # FastMCP server (opentide-mcp)
└── data/           # Bundled TOML configs, vocabulary, external frameworks
```

### Core Data Flow

```
YAML objects (rules, objectives, threats)
    → Indexing (index_builder → index.json)
    → Generation (JSON Schemas, templates, VS Code snippets)
    → Validation (schema, UUID, query)
    → Deployment (per-platform deployers)
    → Documentation (markdown wiki)
```

### Central Abstraction: OpenTide

`OpenTide` (in `opentide.core.registry`) is the singleton registry — the programmatic entry point:

```python
from opentide import OpenTide

OpenTide.initialise()
rule = OpenTide.Rules[uuid]
rule.deploy("sentinel")
rule.validate()

OpenTide.Platforms.Sentinel.deployer.deploy([uuid])
OpenTide.Platforms.Sentinel.validator.validate([uuid])
```

Key traits:
- Lazy-loaded after `initialise()` — no import-time side effects (post-Phase 4)
- Pydantic models with delegation methods for deploy/validate/document
- Platform-centric access via `OpenTide.Platforms.{Name}`

### Platform Capability Matrix

| Platform | Deploy | Query validate |
|----------|:------:|:--------------:|
| Sentinel | ✅ | ✅ KQL |
| Defender for Endpoint | ✅ | ✅ KQL |
| Splunk | ✅ | ✅ SPL |
| SentinelOne | ✅ | ✅ S1QL |
| Carbon Black Cloud | ✅ | ✅ Lucene |
| CrowdStrike | ✅ | ❌ |
| HarfangLab | ✅ | ❌ |

CrowdStrike and HarfangLab have `.can_validate is False` and `.validator is None`. Never fake query validation for these platforms.

### Plugin Registration

Platforms register via entry points (`opentide.platforms` group) and `declare()`:

```python
def declare():
    OpenTide.Platforms.register(SentinelPlatform)
```

---

## CLI & MCP

```bash
opentide validate --platform sentinel --all
opentide deploy --platform splunk --dry-run
opentide generate
opentide init ./my-detections
```

```json
{ "mcpServers": { "opentide": { "command": "opentide-mcp" } } }
```

MCP exposes detection catalogue resources and content-creation tools (search, validate, deploy). Infrastructure operations (generate, document, mutate) are CLI-only.

---

## Coding Conventions

### Language & Style
- **British English** throughout (favour, behaviour, initialise)
- **snake_case** functions/variables; **CamelCase** classes
- Type hints on all signatures; `Optional[T]` for nullable (3.10 compat)
- Pydantic v2 models: `frozen`, `extra="forbid"`, `populate_by_name`

### Logging & Errors
- Use `log(LEVEL, ...)` from `opentide.core.logs` — never `print()`
- `TideErrors` hierarchy for exceptions — never bare `except:`

### Secrets & Paths
- `$ENV_VAR` placeholders in TOML resolved via environment helpers
- Bundled data: `importlib.resources` / `OPENTIDE_DATA_ROOT`
- Client content root: `OPENTIDE_REPO_ROOT`

### Legacy Compatibility (transition period)
```python
# Deprecated — emits DeprecationWarning
from Engines.modules.tide import DataTide  # shim → OpenTide
```

---

## Agent Workflow

When implementing TideKit work:

1. Pick the lowest unblocked phase from [AGENTS.md](../AGENTS.md)
2. Read the GitHub issue's Agent Execution Contract on [OpenTideHQ/CoreTide](https://github.com/OpenTideHQ/CoreTide/issues)
3. Branch `refactor/tidekit-phase<N>-<slug>` or `feat/tidekit-phase<N>-<slug>` from `development`
4. One phase per PR; conventional commits; `Closes #<issue>` in PR body
5. Run phase verification commands before opening PR

See `.github/instructions/tidekit-phase.instructions.md` and `.github/instructions/testing.instructions.md`.

---

## What NOT to Do

- Do not modify `OpenTide` registry structure without understanding all consumers
- Do not bypass env-var secret resolution patterns
- Do not add platforms without full deployer + TOML config (+ validator if applicable)
- Do not mutate frozen/Pydantic models in place — reload via index refresh
- Do not hard-code platform logic in shared modules — use `platforms/` packages
- Do not bundle multiple TideKit phases in one PR
- Do not claim CrowdStrike/HarfangLab support query syntax validation

---

## Common Tasks

| Task | Entry point | Key modules |
|------|-------------|-------------|
| Generate indexes & schemas | `opentide generate` | `generation/` |
| Validate objects | `opentide validate` | `validation/` |
| Deploy rules | `opentide deploy` | `platforms/*/deployer.py` |
| Generate docs | `opentide document` | `documentation/` |
| Add platform | deployer + config + optional validator | `platforms/`, `data/configurations/platforms/` |
| Run tests | `pytest` | `tests/` — see `docs/TEST_PLAN.md` |
| Migrate client repo | `docs/migration/MIGRATION.md` | — |
