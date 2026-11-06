"""#775: every coverage surface counts the techniques a rule inherits.

Rules seldom list techniques: they take their objective's, directly or through
one of its signals. ``info catalog``, ``info coverage``, MCP ``coverage`` and the
TUI's Coverage tab must agree on which rules cover a technique, and on which of
those list it themselves. The workspace is the synthetic tide_corpus plus one
objective that names T1190 and three rules on it: one through the objective, one
through its signal, and a control rule that lists T1190 itself.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import (
    CORPUS_OBJECTIVE_UUID,
    CORPUS_RULE_UUIDS,
    TIDE_CORPUS_ROOT,
    clear_runtime_caches,
)
from tests.test_cli.conftest import assert_json_ok

from opentide.cli.context import CliContext
from opentide.cli.services.tui import load_catalogue
from opentide.cli.tui_app import OpentideTui, coverage_count
from opentide.core.object_fields import technique_covers
from opentide.mcp_server.catalog import coverage_analysis

pytestmark = pytest.mark.cli_e2e

TECHNIQUE = "T1190"
OBJECTIVE = "00000000-0000-4000-8002-000000000775"
SIGNAL = "00000000-0000-4000-8099-000000000775"
VIA_OBJECTIVE = "00000000-0000-4000-8003-000000000775"
VIA_SIGNAL = "00000000-0000-4000-8003-000000000776"
OWN = "00000000-0000-4000-8003-000000000777"

OBJECTIVE_DIR = "Objects/Detection Objectives"
RULE_DIR = "Objects/Detection Rules"

OBJECTIVE_YAML = f"""\
name: Exploitation Objective

metadata:
  uuid: {OBJECTIVE}
  schema: objective::1.0
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear

objective:
  priority: High
  type: Threat
  description: Detect exploitation of public-facing applications
  composition:
    strategy: Combined
    description: One signal
  mitre_attack:
    - {TECHNIQUE}
  signals:
    - name: Web exploitation signal
      uuid: {SIGNAL}
      description: Exploit payloads in web requests
      severity: High
      methodology: Statistical
      entities:
        - Host::Hostname
      data:
        availability: Complete
        requirements: Web server logs
"""


def _rule(uuid: str, name: str, detection_model: str, *, own: bool) -> str:
    """The corpus Sentinel rule, re-pointed; without ``techniques`` unless *own*."""
    text = (
        (TIDE_CORPUS_ROOT / RULE_DIR / "rule-0001-sentinel-kql.yaml")
        .read_text(encoding="utf-8")
        .replace(CORPUS_RULE_UUIDS["sentinel"], uuid)
        .replace("name: Sentinel KQL Rule", f"name: {name}")
        .replace(f"detection_model: {CORPUS_OBJECTIVE_UUID}", f"detection_model: {detection_model}")
    )
    replacement = f"techniques:\n  - {TECHNIQUE}\n" if own else ""
    assert "techniques:\n  - T1059\n" in text
    return text.replace("techniques:\n  - T1059\n", replacement)


@pytest.fixture
def workspace(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    (tide_corpus_repo / OBJECTIVE_DIR / "objective-0775-exploitation.yaml").write_text(
        OBJECTIVE_YAML, encoding="utf-8"
    )
    rules = tide_corpus_repo / RULE_DIR
    for uuid, name, target, own in (
        (VIA_OBJECTIVE, "Via Objective Rule", OBJECTIVE, False),
        (VIA_SIGNAL, "Via Signal Rule", SIGNAL, False),
        (OWN, "Own Technique Rule", OBJECTIVE, True),
    ):
        (rules / f"rule-{uuid[-4:]}.yaml").write_text(
            _rule(uuid, name, target, own=own), encoding="utf-8"
        )
    monkeypatch.delenv("CI", raising=False)  # the TUI's pilot runs in this test
    clear_runtime_caches()
    return tide_corpus_repo


def _catalog_coverage(catalog: dict[str, Any], technique: str) -> tuple[set[str], set[str]]:
    """Rules ``info catalog`` gives *technique* (or a sub-technique) to: (own, inherited)."""
    own: set[str] = set()
    inherited: set[str] = set()
    for row in catalog["objects"]:
        if row["type"] != "rule":
            continue
        if any(technique_covers(technique, t) for t in row["techniques"]["own"]):
            own.add(row["uuid"])
        elif any(technique_covers(technique, t) for t in row["techniques"]["inherited"]):
            inherited.add(row["uuid"])
    return own, inherited


def test_rules_that_inherit_a_technique_count_on_every_surface(
    invoke_cli: Any, workspace: Path
) -> None:
    catalog = assert_json_ok(invoke_cli("info", "catalog"))
    own, inherited = _catalog_coverage(catalog, TECHNIQUE)
    assert own == {OWN}
    assert inherited == {VIA_OBJECTIVE, VIA_SIGNAL}

    coverage = assert_json_ok(invoke_cli("info", "coverage", "--technique", TECHNIQUE))["coverage"]
    assert coverage["count"] == 3
    assert set(coverage["rules"]) == own | inherited
    assert set(coverage["own"]) == own
    assert set(coverage["inherited"]) == inherited

    clear_runtime_caches()
    mcp = coverage_analysis(technique=TECHNIQUE)
    assert mcp["covered"] is True
    assert set(mcp["rules"]) == own | inherited
    assert set(mcp["own_rules"]) == own
    assert set(mcp["inherited_rules"]) == inherited
    matrix = coverage_analysis()
    assert set(matrix["matrix"][TECHNIQUE]) == own | inherited
    assert set(matrix["own_matrix"][TECHNIQUE]) == own

    row = next(
        row
        for row in load_catalogue(CliContext(repo=workspace)).coverage
        if row.technique == TECHNIQUE
    )
    assert set(row.rules) == own | inherited
    assert set(row.own) == own
    assert set(row.inherited) == inherited
    assert row.rules[0] == OWN  # Enter opens a rule that lists the technique first
    assert coverage_count(row).plain == "3  1 own · 2 inherited"


def test_surfaces_agree_on_every_technique(invoke_cli: Any, workspace: Path) -> None:
    """No technique in the catalogue is counted differently by any surface."""
    catalog = assert_json_ok(invoke_cli("info", "catalog"))
    clear_runtime_caches()
    rows = {row.technique: row for row in load_catalogue(CliContext(repo=workspace)).coverage}
    clear_runtime_caches()
    matrix = coverage_analysis()["matrix"]
    assert rows, "the corpus names techniques"
    for technique, row in rows.items():
        own, inherited = _catalog_coverage(catalog, technique)
        assert set(row.rules) == own | inherited, technique
        assert set(row.own) == own, technique
        # The matrix is keyed by exact ID; the lookups also count sub-techniques.
        exact = {
            row["uuid"]
            for row in catalog["objects"]
            if row["type"] == "rule"
            and technique in (*row["techniques"]["own"], *row["techniques"]["inherited"])
        }
        assert set(matrix.get(technique, ())) == exact, technique
        cli = assert_json_ok(invoke_cli("info", "coverage", "--technique", technique))
        assert set(cli["coverage"]["rules"]) == own | inherited, technique


def test_coverage_tab_shows_inherited_rules(workspace: Path) -> None:
    async def main() -> None:
        app = OpentideTui(CliContext(repo=workspace))
        async with app.run_test(size=(160, 40)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.press("2")
            await pilot.pause()
            from textual.widgets import DataTable, TabbedContent

            table = app.query_one("#coverage-table", DataTable)
            cells = [str(cell) for cell in table.get_row(TECHNIQUE)]
            assert cells[0] == TECHNIQUE
            assert cells[1] == "3  1 own · 2 inherited"
            assert "Via Signal Rule" in cells[2]
            table.move_cursor(row=table.get_row_index(TECHNIQUE))
            await pilot.press("enter")
            await pilot.pause()
            assert app.query_one(TabbedContent).active == "catalogue"
            assert app.selected == OWN

    asyncio.run(main())
