# Master Test Plan — Project TideKit

Epic: [#60](https://github.com/OpenTideHQ/CoreTide/issues/60) · Agent guide: [`AGENTS.md`](https://github.com/OpenTideHQ/opentide/blob/development/AGENTS.md)

---

## Summary Matrix

| Phase | Issue | Primary test type | Verification |
|-------|-------|-------------------|--------------|
| 0 | [#61](https://github.com/OpenTideHQ/CoreTide/issues/61) | Smoke + grep | `rg` counts, pipeline scripts |
| 1 | [#62](https://github.com/OpenTideHQ/CoreTide/issues/62) | Import smoke | Shim imports, no circular deps |
| 2 | [#63](https://github.com/OpenTideHQ/CoreTide/issues/63) | Invariant | `OpenTide` + legacy shims, capability flags |
| 3 | [#64](https://github.com/OpenTideHQ/CoreTide/issues/64) | Regression | Schema regen, EnumResolver fixes |
| 4 | [#65](https://github.com/OpenTideHQ/CoreTide/issues/65) | Inventory + diff | `behaviour-inventory.md`, byte diff |
| 5 | [#66](https://github.com/OpenTideHQ/CoreTide/issues/66) | Install smoke | `pip install -e .` |
| 6 | [#67](https://github.com/OpenTideHQ/CoreTide/issues/67) | CLI | Typer CliRunner |
| 7 | [#68](https://github.com/OpenTideHQ/CoreTide/issues/68) | MCP | Tool/resource smoke |
| 8 | [#69](https://github.com/OpenTideHQ/CoreTide/issues/69) | Packaging | `hatch build`, `twine check` |
| 9 | [#71](https://github.com/OpenTideHQ/CoreTide/issues/71) | Full pytest | ≥80% cov, ruff, ty, mkdocs |

---

## Platform Capability Invariants

| Platform | Deploy | Validate |
|----------|:------:|:--------:|
| sentinel | ✅ | ✅ |
| defender_for_endpoint | ✅ | ✅ |
| splunk | ✅ | ✅ |
| sentinel_one | ✅ | ✅ |
| carbon_black_cloud | ✅ | ✅ |
| crowdstrike | ✅ | ❌ |
| harfanglab | ✅ | ❌ |

Tests: `tests/test_platforms/test_capabilities.py` (Phase 9).

---

## Phase Details

### Phase 0 ([#61](https://github.com/OpenTideHQ/CoreTide/issues/61))

- Remove CDM/BDR/lookups; fix `Templates.dom` bug (L1286)
- Verify: zero deprecated refs; all `Orchestration/*.py` import clean
- Future: `test_generation/test_templates_dom_key.py`

### Phase 1 ([#62](https://github.com/OpenTideHQ/CoreTide/issues/62))

- Decompose monoliths; re-export shims only
- Future: `test_core/test_legacy_shims.py`, `test_no_circular_imports.py`

### Phase 2 ([#63](https://github.com/OpenTideHQ/CoreTide/issues/63))

- `DataTide` → `OpenTide`; platform-centric API
- Future: `test_open_tide_registry.py`, `test_platform_access.py`

### Phase 3 ([#64](https://github.com/OpenTideHQ/CoreTide/issues/64))

- Typed vocabularies; fix `json_schemas.py` L241, L752
- Future: `test_vocabulary_loader.py`, `test_enum_resolver_finalise.py`

### Phase 4 ([#65](https://github.com/OpenTideHQ/CoreTide/issues/65))

- **Gating**: commit `docs/migration/behaviour-inventory.md`
- Pydantic models; delegation methods; byte-equivalent schema output
- Future: parametrised `test_behaviour_inventory.py`, `test_delegation.py`

### Phase 5 ([#66](https://github.com/OpenTideHQ/CoreTide/issues/66))

- `src/opentide/` layout; 7 deployers, 5 validators
- Future: `test_package_import.py`, `test_data_paths.py`

### Phase 6 ([#67](https://github.com/OpenTideHQ/CoreTide/issues/67))

- `opentide` CLI; 5-platform query validation only
- Future: `tests/test_cli/test_*.py`

### Phase 7 ([#68](https://github.com/OpenTideHQ/CoreTide/issues/68))

- MCP: 13 resources, 8 tools; `dry_run=True` default
- Future: `tests/test_mcp/test_*.py`

### Phase 8 ([#69](https://github.com/OpenTideHQ/CoreTide/issues/69))

- PyPI publish; migration guide; deprecation shims
- See [`migration/MIGRATION.md`](migration/MIGRATION.md)

### Phase 9 ([#71](https://github.com/OpenTideHQ/CoreTide/issues/71))

```bash
pip install -e ".[dev]"
pytest --cov=opentide --cov-fail-under=80
ruff check src/opentide
uv run ty check src/opentide
mkdocs build --strict
```

Final tree: `tests/{test_core,test_models,test_platforms,test_validation,test_generation,test_cli,test_mcp}/`

---

## Regression Policy

1. Phases 0–8: pipeline + issue verification commands pass before merge.
2. Phase 4+: behaviour inventory is the generator contract.
3. Phase 9+: pytest primary gate; ≥80% core coverage.
4. Capability invariants block merge at any phase.
