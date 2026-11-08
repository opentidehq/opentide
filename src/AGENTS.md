# src/opentide — Agent Guide: the Python package

The `opentide` package on PyPI: the CLI (Typer), the MCP server, the SDK, the platform clients
and the bundled data. The root [`AGENTS.md`](../AGENTS.md) is the map and holds the ground rules
and the definition of done; this guide covers what is particular to the package. (It sits in
`src/`, not `src/opentide/`, so that it never ships in the wheel.)

The unified-core plan ([#790](https://github.com/opentidehq/opentide/issues/790)) moves this
package's logic into the Rust workspace one command at a time. Until a command's default flips,
the Python implementation here is the oracle the Rust one is compared with: change its
behaviour only on purpose, with a test and a changelog entry.

## Layout

| Path | What |
|------|------|
| `cli/` | The command tree (Typer), output modes, renderers; docs in `docs/cli/` |
| `mcp_server/` | `opentide mcp start`; skill [mcp-server](../.agents/skills/mcp-server/SKILL.md), docs in `docs/mcp/` |
| `models/`, `vocabulary/`, `data/pins/` | The Tide model (Pydantic), vocabularies and schema pins |
| `validation/`, `loading/`, `indexing/`, `registry/`, `core/` | Loading, the index, validation and lint |
| `platforms/` | A module and a package per platform (`client`, `deployer`, `runner`, `validator`, `compile` where it has one); `transport.py` holds `TenantSession`, which the clients build their HTTP session from |
| `deployment/`, `states/`, `sharing/`, `extraction/`, `query/` | Deploy plans and state, MISP sharing, extraction, `opentide query` |
| `generation/`, `documentation/`, `export/`, `ci/` | Generated schemas, docs, exports, CI templates |
| `analysis.py`, `_native.pyi` | The one door to the Rust engine (`opentide._native`, built from `analysis/`) |
| `data/` | Bundled data: vocabularies, pins, configuration and log-source defaults, the `opentide explain` pages (`diagnostics/`), setup templates and skills |

## Rules of the package

- **Logging:** `opentide.core.logging` (structlog + Rich) — no operational `print()` (ruff's
  `T20`). `--json` stdout carries only the JSON document; logs go to stderr.
- **The engine:** Python reaches it only through `src/opentide/analysis.py`. A missing engine is
  `engine_unavailable`, never a skipped check. After a change to the binding, update
  `_native.pyi` ([`analysis/AGENTS.md`](../analysis/AGENTS.md)).
- **Object models, vocabulary or pins:** regenerate the engine's bundled Tide catalog in the same
  change, `uv run python scripts/engine/sync_opentide_schemas.py`;
  `tests/test_generation/test_bundled_tide_catalog.py` fails otherwise. Model field docstrings
  are the editor hovers and are checked against the specifications' field tables.
- **Client repos** are set up with `opentide setup` or `opentide setup ci`.
- **Docs follow the code** in the same PR: the table in
  [docs-maintenance](../.agents/skills/docs-maintenance/SKILL.md) maps each module to its page.

## Platform capability matrix

| Platform | Deploy | Query validate (`--live`) | Offline (engine) | `opentide query` |
|----------|:------:|:--------------:|:----------------:|:----------------:|
| Sentinel | ✅ | ✅ KQL | ✅ KQL | ✅ KQL |
| Defender | ✅ | ✅ KQL | ✅ KQL | ✅ KQL |
| Elastic | ✅ | ✅ Kuery, Lucene, EQL, ES\|QL | ✅ Kuery, Lucene, EQL, ES\|QL | ✅ ES\|QL, EQL, Lucene; Kuery via rule preview |
| Splunk | ✅ | ✅ SPL | ✅ SPL | ✅ SPL |
| SentinelOne | ✅ | ✅ S1QL | ❌ | ✅ PowerQuery |
| Carbon Black | ✅ | ✅ Lucene | ✅ Lucene | ✅ Lucene |
| CrowdStrike | ✅ | ❌ | ❌ | ✅ CQL (Next-Gen SIEM) |
| HarfangLab | ✅ | ❌ | ❌ | ✅ telemetry filters (no `--rule`) |
| Sysdig Secure (Falco) | ✅ | ❌ | ✅ Falco | ❌ |

CrowdStrike, HarfangLab and Sysdig: `can_validate is False` — return `supported: False`, never fake validation.
Sysdig (`src/opentide/platforms/sysdig/`) deploys through the Sysdig Secure runtime API only, with the rule
id in deployment state; block macros and lists are expanded into the condition.
`opentide query` runners live in `src/opentide/platforms/<pkg>/runner.py` (`opentide.query`): they save no
search or rule, and stop an asynchronous search they stop waiting for where the API can (CrowdStrike). Elastic
`kuery` is the one write: its rule preview's alerts, in the preview index.

## Test

```bash
uv run pytest tests/<area> -q --no-cov          # while editing
scripts/ci-local.sh --full                       # before a push: unit + coverage gate + E2E
```

The network, files-the-user-owns and serialisation rules every change here is checked against
are in [review-checklist](../.agents/skills/review-checklist/SKILL.md); test design in
[python-testing-patterns](../.agents/skills/python-testing-patterns/SKILL.md) and
[cli-e2e-testing](../.agents/skills/cli-e2e-testing/SKILL.md).
