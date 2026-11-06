"""#776: the Chains tab, and the chaining graph behind it. Synthetic fixtures only."""

from __future__ import annotations

import asyncio
import contextlib
import io
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from tests.test_cli.test_tui import THREAT, tutorial_repo  # noqa: F401 -- the fixture
from textual.widgets import DataTable, Static, TabbedContent
from textual.worker import WorkerFailed

from opentide.cli.context import CliContext
from opentide.cli.services.chains_view import chain_edges, flow_layers, neighbourhood
from opentide.cli.tui_app import OpentideTui

FOLLOW_UP = "00000000-0000-4000-8001-000000000002"
ENABLED = "00000000-0000-4000-8001-000000000003"
LATER = "00000000-0000-4000-8001-000000000004"
MISSING = "00000000-0000-4000-8001-0000000dead0"


def _threat(uuid: str, *links: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "name": uuid[-4:],
        "metadata": {"uuid": uuid, "schema": "threat::1.0"},
        "threat": {
            "chaining": [
                {"relation": relation, "vector": vector, "description": description}
                for relation, vector, description in links
            ]
        },
    }


THREATS = {
    THREAT: _threat(THREAT, ("sequence::preceeds", FOLLOW_UP, "initial access first")),
    FOLLOW_UP: _threat(
        FOLLOW_UP,
        ("sequence::succeeds", THREAT, "after the initial access"),
        ("sequence::preceeds", LATER, ""),
    ),
    ENABLED: _threat(ENABLED, ("support::enabling", THREAT, "credentials make it easier")),
    LATER: _threat(LATER, ("support::synergize", MISSING, "")),
}


def test_inverse_links_are_read_once() -> None:
    edges = chain_edges(THREATS)
    sequence = [e for e in edges if e.stage == "sequence"]
    first = next(e for e in sequence if e.source == THREAT)
    # Written from both ends: one edge, both descriptions.
    assert (first.target, first.label, first.merged) == (FOLLOW_UP, "then", True)
    assert first.descriptions == ("initial access first", "after the initial access")
    assert set(first.relations) == {"sequence::preceeds", "sequence::succeeds"}
    # `ENABLED enabling THREAT` reads as THREAT enables ENABLED.
    [support] = [e for e in edges if e.stage == "support" and e.directed]
    assert (support.source, support.target, support.label) == (THREAT, ENABLED, "enables")
    [both] = [e for e in edges if not e.directed]
    assert both.missing and both.label == "synergizes with"
    assert len(sequence) == 2


def test_sequence_links_read_left_to_right_and_a_cycle_is_cut() -> None:
    edges = chain_edges(THREATS)
    assert flow_layers(THREATS, edges) == ((THREAT,), (FOLLOW_UP,), (LATER,))
    cyclic = chain_edges(
        {
            THREAT: _threat(THREAT, ("sequence::preceeds", FOLLOW_UP, "")),
            FOLLOW_UP: _threat(FOLLOW_UP, ("sequence::preceeds", THREAT, "")),
        }
    )
    layers = flow_layers([THREAT, FOLLOW_UP], cyclic)
    assert sorted(uuid for layer in layers for uuid in layer) == sorted([THREAT, FOLLOW_UP])


def test_the_neighbourhood_grows_by_hops_and_filters_by_relation() -> None:
    edges = chain_edges(THREATS)
    names = {uuid: body["name"] for uuid, body in THREATS.items()}
    one = neighbourhood(THREAT, edges, names, {THREAT: 1}, hops=1)
    assert set(one.nodes) == {THREAT, FOLLOW_UP, ENABLED}
    assert one.hidden == 2  # LATER, then the threat it names that is missing
    assert one.nodes[THREAT].rules == 1 and one.nodes[FOLLOW_UP].rules == 0
    two = neighbourhood(THREAT, edges, names, {}, hops=2)
    assert LATER in two.nodes
    sequence = neighbourhood(THREAT, edges, names, {}, hops=3, stage="sequence")
    assert set(sequence.nodes) == {THREAT, FOLLOW_UP, LATER}
    assert all(edge.stage == "sequence" for edge in sequence.edges)


@pytest.fixture
def chained_repo(tutorial_repo: Path) -> Iterator[Path]:  # noqa: F811 -- the fixture
    threats = tutorial_repo / "objects" / "threats"
    source = (threats / "simulated-actor.yaml").read_text(encoding="utf-8")
    assert "mitre_attack" in source
    for uuid, name, chaining in (
        (FOLLOW_UP, "Follow-up Actor", f"sequence::succeeds\n      vector: {THREAT}"),
        (ENABLED, "Enabled Actor", f"support::enabling\n      vector: {THREAT}"),
        (LATER, "Later Actor", f"sequence::succeeds\n      vector: {FOLLOW_UP}"),
    ):
        text = (
            source.replace(THREAT, uuid)
            .replace("name: Simulated Actor", f"name: {name}")
            .rstrip("\n")
            + f"\n  chaining:\n    - relation: {chaining}\n      description: synthetic link\n"
        )
        (threats / f"{name.lower().replace(' ', '-')}.yaml").write_text(text, encoding="utf-8")
    yield tutorial_repo


def _plain(renderable: Any) -> str:
    buffer = io.StringIO()
    Console(width=200, file=buffer).print(renderable)
    return buffer.getvalue()


def test_the_chains_tab(chained_repo: Path) -> None:
    async def main() -> None:
        app = OpentideTui(CliContext(repo=chained_repo))
        async with app.run_test(size=(180, 50)) as pilot:
            with contextlib.suppress(WorkerFailed):
                await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.catalogue is not None and len(app.catalogue.chains) == 3
            app.select(THREAT)
            await pilot.press("6")
            await pilot.pause()
            assert app.query_one(TabbedContent).active == "chains"
            table = app.query_one("#chain-nodes", DataTable)
            assert next(row.value for row in table.rows) == THREAT
            assert {row.value for row in table.rows} == {THREAT, FOLLOW_UP, ENABLED}
            shown = _plain(app.query_one("#chain-flow", Static).content)
            # The focused threat has the tutorial's rule; its follow-up none.
            assert "Simulated Actor" in shown and "1 rule" in shown
            assert "Follow-up Actor" in shown and "0 rules" in shown
            assert "──▶" in shown
            assert "1/1 techniques" in shown
            described = _plain(app.query_one("#chain-links", Static).content)
            assert "Simulated Actor  ─then─▶  Follow-up Actor" in described
            assert "Simulated Actor  ─enables─▶  Enabled Actor" in described
            assert "synthetic link" in described  # the focused threat's links, described
            await pilot.press("plus")
            await pilot.pause()
            assert LATER in {row.value for row in table.rows}
            await pilot.press("l")  # sequence only
            await pilot.pause()
            assert ENABLED not in {row.value for row in table.rows}
            header = _plain(app.query_one("#chain-header", Static).content)
            assert "relations: sequence" in header
            table.move_cursor(row=table.get_row_index(FOLLOW_UP))
            await pilot.press("c")
            await pilot.pause()
            assert app.query_one("ChainsPane").focus_uuid == FOLLOW_UP
            table.move_cursor(row=table.get_row_index(LATER))
            await pilot.press("enter")
            await pilot.pause()
            assert app.query_one(TabbedContent).active == "catalogue"
            assert app.selected == LATER

    asyncio.run(main())
