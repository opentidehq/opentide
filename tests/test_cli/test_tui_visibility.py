"""#776: the Visibility tab, and the report behind it (shared with the explorer export).

Synthetic fixtures only: the tutorial repository, with a ``visibility.toml``
that declares the table its rule reads (with columns), a log source its signal
names (without columns), and one nothing uses; a second rule reads a table no
log source declares.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from tests.test_cli.test_tui import OBJECTIVE, RULE, RULE_FILE, tutorial_repo  # noqa: F401 -- fixture
from textual.widgets import DataTable, Input, Static, TabbedContent
from textual.worker import WorkerFailed

from opentide.cli.context import CliContext
from opentide.cli.services.tui import load_catalogue
from opentide.cli.services.visibility import VisibilityReport
from opentide.cli.tui_app import OpentideTui
from opentide.cli.tui_tabs.visibility import matches

SECOND_RULE = "00000000-0000-4000-8003-000000000776"

VISIBILITY = """\
[[logsources]]
name = "SecurityEvent"
description = "Windows security events."
system = "sentinel"

[logsources.columns]
EventID = { type = "int", description = "The event's identifier." }
Account = { type = "string" }

[[logsources]]
name = "Windows Security Events"
description = "Security event log of the domain controllers."
system = "splunk"

[[logsources]]
name = "Contoso_Audit_CL"
description = "Administrative audit events."
system = "sentinel"
"""


@pytest.fixture
def visibility_repo(tutorial_repo: Path) -> Iterator[Path]:  # noqa: F811 -- the fixture
    config = tutorial_repo / ".opentide" / "configurations"
    config.mkdir(parents=True, exist_ok=True)
    (config / "visibility.toml").write_text(VISIBILITY, encoding="utf-8")
    objective = tutorial_repo / "objects/objectives/credential-access-objective.yaml"
    objective.write_text(
        objective.read_text(encoding="utf-8").replace(
            "        requirements: Security event logs\n",
            "        requirements: Security event logs\n"
            "        logsources:\n          - Windows Security Events\n",
        ),
        encoding="utf-8",
    )
    rule = (tutorial_repo / RULE_FILE).read_text(encoding="utf-8")
    second = (
        rule.replace(RULE, SECOND_RULE)
        .replace("name: Sentinel KQL Rule", "name: Undeclared Table Rule")
        .replace("SecurityEvent\n", "SigninLogs\n")
    )
    assert "SigninLogs" in second
    (tutorial_repo / "objects/rules/undeclared-table-rule.yaml").write_text(second, encoding="utf-8")
    yield tutorial_repo


def _report(repo: Path) -> VisibilityReport:
    report = load_catalogue(CliContext(repo=repo)).visibility
    assert report is not None
    return report


def test_the_report_joins_log_sources_with_queries_and_signals(visibility_repo: Path) -> None:
    report = _report(visibility_repo)
    assert report.present and report.problem is None and report.reads_unavailable is None
    security = report.find("sentinel", "SecurityEvent")
    assert security is not None
    assert [c.name for c in security.columns] == ["EventID", "Account"]
    assert security.columns[0].type == "int"
    # The engine says which table each query reads.
    assert security.read_by == (RULE,)
    # A signal names this one: the objective uses it, and the rules implementing it.
    windows = report.find("splunk", "Windows Security Events")
    assert windows is not None
    assert windows.objectives == (OBJECTIVE,)
    assert set(windows.signal_rules) == {RULE, SECOND_RULE}
    assert windows.read_by == ()
    unused = report.find("sentinel", "Contoso_Audit_CL")
    assert unused is not None and not unused.used and not unused.columns
    # A table a rule reads that no log source declares.
    [missing] = report.undeclared
    assert (missing.system, missing.name, missing.rules) == ("sentinel", "SigninLogs", (SECOND_RULE,))
    assert missing.system_declares
    assert report.systems["sentinel"] == {"logsources": 2, "with_columns": 1, "used": 1}
    # The workspace's own declarations are in force again afterwards.
    from opentide.analysis import engine

    assert engine().dataset_status("sentinel", "SecurityEvent") == "declared"
    assert engine().dataset_status("sentinel", "SigninLogs") == "undeclared"


def test_without_visibility_toml_the_report_says_so(tutorial_repo: Path) -> None:  # noqa: F811
    report = _report(tutorial_repo)
    assert not report.present
    assert report.logsources == ()


def test_the_search_narrows_by_name_and_system() -> None:
    assert matches("security", "sentinel", "SecurityEvent")
    assert matches("system:sentinel", "sentinel", "SecurityEvent")
    assert not matches("system:splunk", "sentinel", "SecurityEvent")
    assert matches("system:sentinel audit", "sentinel", "Contoso_Audit_CL")
    assert matches("domain", "splunk", "Windows Security Events", "the domain controllers")


def _plain(renderable: Any) -> str:
    buffer = io.StringIO()
    Console(width=160, file=buffer).print(renderable)
    return buffer.getvalue()


def test_the_visibility_tab(visibility_repo: Path) -> None:
    async def main() -> None:
        app = OpentideTui(CliContext(repo=visibility_repo))
        async with app.run_test(size=(160, 48)) as pilot:
            with contextlib.suppress(WorkerFailed):
                await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.press("4")
            await pilot.pause()
            assert app.query_one(TabbedContent).active == "visibility"
            tiles = _plain(app.query_one("#vis-tiles", Static).content)
            assert "2 sentinel" in tiles and "1 with columns · 1 used" in tiles
            assert "1 without columns" not in tiles  # two sources have none
            assert "2 without columns" in tiles
            assert "1 unused" in tiles
            assert "1 read but not declared" in tiles
            table = app.query_one("#vis-table", DataTable)
            keys = [row.value for row in table.rows]
            assert "sentinel:SecurityEvent" in keys
            assert "undeclared:sentinel:SigninLogs" in keys
            # Drill down: the highlighted source's columns and who uses it.
            table.move_cursor(row=table.get_row_index("sentinel:SecurityEvent"))
            await pilot.pause()
            shown = _plain(app.query_one("#vis-detail", Static).content)
            assert "Columns (2)" in shown and "EventID" in shown and "int" in shown
            assert "Read by queries: Sentinel KQL Rule" in shown
            # Filter by system.
            app.query_one("#vis-search", Input).value = "system:splunk"
            await pilot.pause()
            assert [row.value for row in table.rows] == ["splunk:Windows Security Events"]
            shown = _plain(app.query_one("#vis-detail", Static).content)
            assert "Objectives: Credential Access Objective" in shown
            assert "No columns declared" in shown
            # Enter opens a rule that uses it in the catalogue.
            table.focus()
            await pilot.press("enter")
            await pilot.pause()
            assert app.query_one(TabbedContent).active == "catalogue"
            assert app.selected in {RULE, SECOND_RULE}

    asyncio.run(main())
