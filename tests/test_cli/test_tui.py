"""``opentide tui``: the Textual app, driven by its pilot against the tutorial repository."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import re
import subprocess
import sys
import threading
from collections.abc import Awaitable, Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from rich.text import Text
from tests.test_cli.e2e.helpers import write_tutorial_objects
from textual.pilot import Pilot
from textual.widgets import DataTable, RichLog, Static, TabbedContent, Tree
from textual.worker import WorkerFailed
from typer.testing import CliRunner

from opentide.cli import app as cli_app
from opentide.cli import tui_app
from opentide.cli.commands import tui as tui_command
from opentide.cli.context import CliContext
from opentide.cli.services import tui as tui_service
from opentide.cli.services.tui import (
    ACTIONS,
    Action,
    Catalogue,
    CatalogueEntry,
    Diagnostic,
    load_catalogue,
    run_action,
)
from opentide.cli.tui_app import (
    TAGLINE,
    OpentideTui,
    diagnostic_text,
    empty_state,
    fit_label,
    masthead_brand,
    outcome_text,
    pill,
)
from opentide.core.root import get_data_root

THREAT = "00000000-0000-4000-8001-000000000001"
OBJECTIVE = "00000000-0000-4000-8002-000000000001"
RULE = "00000000-0000-4000-8003-000000000001"
RULE_FILE = "objects/rules/sentinel-kql-rule.yaml"

_SGR = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _SGR.sub("", text)


@pytest.fixture
def tutorial_repo(
    invoke_cli: Callable[..., Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """The repository docs/usage/tutorial.md builds: one threat, objective and rule."""
    from tests.corpus_support import clear_runtime_caches

    repo = tmp_path / "tutorial-detections"
    setup = invoke_cli(
        "setup",
        "--yes",
        "--name",
        "Tutorial Detections",
        "--org",
        "Example Corp",
        "--platform",
        "sentinel",
        "--path",
        str(repo),
        repo=tmp_path,
    )
    assert setup.exit_code == 0, setup.stdout + setup.stderr
    write_tutorial_objects(repo)
    for name in ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"):
        monkeypatch.setenv(name, str(repo))
    monkeypatch.setenv("OPENTIDE_DATA_ROOT", str(get_data_root()))
    monkeypatch.delenv("CI", raising=False)
    clear_runtime_caches()
    yield repo
    clear_runtime_caches()


@pytest.fixture
def stub_deployers(monkeypatch: pytest.MonkeyPatch) -> dict[str, MagicMock]:
    """No platform engine: a dry run only previews, and must never reach a vendor."""
    deployers: dict[str, MagicMock] = {}

    class _StubDeployTide:
        def mdr_for(self, platforms: Any) -> dict[str, MagicMock]:
            return {name: deployers.setdefault(name, MagicMock()) for name in platforms}

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _StubDeployTide)
    return deployers


def _break_tlp(repo: Path) -> None:
    rule = repo / RULE_FILE
    rule.write_text(
        rule.read_text(encoding="utf-8").replace("tlp: clear\n", "tlp: clearr\n"),
        encoding="utf-8",
    )


def _drive(
    repo: Path,
    script: Callable[[OpentideTui, Pilot[None]], Awaitable[None]],
    size: tuple[int, int] = (140, 40),
) -> None:
    """Run the app headless on *repo*, wait for the catalogue, then run *script*."""

    async def main() -> None:
        app = OpentideTui(CliContext(repo=repo))
        async with app.run_test(size=size) as pilot:
            await _settle(app, pilot)
            await script(app, pilot)

    asyncio.run(main())


async def _settle(app: OpentideTui, pilot: Pilot[None]) -> None:
    """Wait for the running worker and the messages it posted."""
    with contextlib.suppress(WorkerFailed):  # the app reports it; the test checks how
        await app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()


def _text(app: OpentideTui, selector: str) -> str:
    """What a Static shows, as plain text, whatever FORCE_COLOR says."""
    buffer = io.StringIO()
    Console(width=200, file=buffer).print(app.query_one(selector, Static).content)
    return _plain(buffer.getvalue())


def _log_text(app: OpentideTui) -> str:
    """The Results tab. RichLog renders only once shown, so this shows it."""
    return "\n".join(strip.text for strip in app.query_one("#log", RichLog).lines)


async def _results(app: OpentideTui, pilot: Pilot[None]) -> str:
    await pilot.press("3")
    await pilot.pause()
    return _log_text(app)


def _labels(node: Any) -> list[str]:
    labels: list[str] = []
    for child in node.children:
        labels.append(str(child.label))
        labels.extend(f"  {label}" for label in _labels(child))
    return labels


# -- the catalogue ----------------------------------------------------------


def test_catalogue_comes_from_the_registry(tutorial_repo: Path) -> None:
    catalogue = load_catalogue(CliContext(repo=tutorial_repo))
    assert [entry.uuid for entry in catalogue.of_kind("threat")] == [THREAT]
    assert [entry.uuid for entry in catalogue.children(THREAT)] == [OBJECTIVE]
    assert [entry.uuid for entry in catalogue.children(OBJECTIVE)] == [RULE]
    rule = catalogue.entries[RULE]
    assert rule.name == "Sentinel KQL Rule"
    assert rule.path is not None and rule.path.name == "sentinel-kql-rule.yaml"
    assert catalogue.unlinked("rule") == []
    assert tui_service.summary_line(catalogue) == "1 threat · 1 objective · 1 rule"
    [row] = catalogue.coverage
    assert (row.technique, row.rules, row.referenced_by) == ("T1059", (RULE,), (THREAT,))


def test_tree_nests_threats_objectives_and_rules_with_counts(tutorial_repo: Path) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        tree = app.query_one("#tree", Tree)
        assert _labels(tree.root) == [
            "Simulated Actor  1 objective · 1 rule",
            "  Credential Access Objective  1 rule",
            "    Sentinel KQL Rule",
        ]
        assert "1 threat · 1 objective · 1 rule" in _text(app, "#summary")
        assert "Spec-driven development for agentic detection engineering" in _text(app, "#brand")
        assert app.theme == "opentide"
        # Blue is a fill, never a text colour.
        variables = app.get_css_variables()
        assert variables["block-cursor-background"].lower() == "#001489"
        for name in ("footer-key-foreground", "text-accent", "border", "accent"):
            assert variables[name].lower() != "#001489", name
        # The first object is shown before anything is selected.
        assert app.selected == THREAT
        assert "Not validated yet" in _text(app, "#diagnostics")

    _drive(tutorial_repo, script)


def test_select_a_rule_run_validate_and_see_its_diagnostic(tutorial_repo: Path) -> None:
    _break_tlp(tutorial_repo)

    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        await pilot.press("down", "down")
        assert app.selected == RULE
        assert "tlp: clearr" in _text(app, "#source")
        await pilot.press("v")
        await _settle(app, pilot)
        detail = _text(app, "#diagnostics")
        assert "error[vocab_unknown]:" in detail
        assert f"╭─▶ {RULE_FILE}:8\n" in detail
        assert "help: did you mean 'clear'?" in detail
        assert "Sentinel KQL Rule  ✗ 1" in _labels(app.query_one("#tree", Tree).root)[-1]
        assert "opentide validate: Validation failed" in _text(app, "#status")
        # The cursor stays on the rule after the tree is rebuilt.
        assert app.selected == RULE
        log = await _results(app, pilot)
        assert "$ opentide validate" in log
        # As `opentide validate` prints it: #641's code frame, with the source
        # line underlined, and the counted outcome line.
        assert "error[vocab_unknown]: 'clearr' is not a TLP value" in log
        assert f"╭─▶ {RULE_FILE}:8:8" in log
        assert "8 │   tlp: clearr" in log
        assert "━━━━━━ not in tlp::1.0" in log
        assert re.search(r"✗ 1 error in 1 file · 3 objects checked · \d+(\.\d+)?m?s", log)
        assert "error: Validation failed" not in log
        # The next steps a person would run, not the --json form.
        assert "→ opentide validate · check again" in log
        assert "--json" not in log
        await pilot.press("1", "up")
        assert "No diagnostics from the last validate run" in _text(app, "#diagnostics")

    _drive(tutorial_repo, script)


def test_a_clean_validate_reports_success(tutorial_repo: Path) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        app.action_run("validate")
        await _settle(app, pilot)
        # The counted line `opentide validate` prints (#641).
        assert re.search(r"✓ 3 objects valid · \d", await _results(app, pilot))
        assert app.validated
        assert app.diagnostics == ()

    _drive(tutorial_repo, script)


def test_a_file_that_failed_to_load_has_its_own_node(tutorial_repo: Path) -> None:
    (tutorial_repo / "objects" / "rules" / "broken.yaml").write_text(
        "name: [unclosed\n", encoding="utf-8"
    )

    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        labels = _labels(app.query_one("#tree", Tree).root)
        assert labels[-2:] == ["Files that failed to load (1)", "  broken.yaml"]
        assert "1 load error" in _text(app, "#summary")
        await pilot.press("down", "down", "down", "down")
        assert app.selected == ("load_error", 0)
        assert "error[yaml_parse]:" in _text(app, "#diagnostics")
        assert "objects/rules/broken.yaml" in _text(app, "#heading")

    _drive(tutorial_repo, script)


def test_unlinked_objects_are_grouped(tutorial_repo: Path) -> None:
    rule = tutorial_repo / RULE_FILE
    rule.write_text(
        rule.read_text(encoding="utf-8").replace(OBJECTIVE, "00000000-0000-4000-8002-00000000ffff"),
        encoding="utf-8",
    )

    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        labels = _labels(app.query_one("#tree", Tree).root)
        assert labels[-2:] == ["Rules without an objective (1)", "  Sentinel KQL Rule"]
        assert labels[1] == "  Credential Access Objective  0 rules"

    _drive(tutorial_repo, script)


def test_coverage_lists_techniques_and_opens_the_rule(tutorial_repo: Path) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        await pilot.press("2")
        assert app.query_one(TabbedContent).active == "coverage"
        table = app.query_one("#coverage-table", DataTable)
        assert [str(cell) for cell in table.get_row_at(0)] == [
            "T1059",
            "1",
            "Sentinel KQL Rule",
            "Simulated Actor",
        ]
        await pilot.press("enter")
        await pilot.pause()
        assert app.query_one(TabbedContent).active == "catalogue"
        assert app.selected == RULE

    _drive(tutorial_repo, script)


def test_palette_offers_the_actions(tutorial_repo: Path) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        titles = [command.title for command in app.get_system_commands(app.screen)]
        assert titles[: len(ACTIONS) + 1] == [
            *(action.command for action in ACTIONS),
            "Reload the catalogue",
        ]
        assert "Quit" in titles

    _drive(tutorial_repo, script)


def test_deploy_dry_run_shows_the_plan(
    tutorial_repo: Path, stub_deployers: dict[str, MagicMock]
) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        await pilot.press("d")
        await _settle(app, pilot)
        log = await _results(app, pilot)
        assert app.query_one(TabbedContent).active == "results"
        assert "$ opentide deploy --dry-run --strategy PREVIEW --all" in log
        # #643's plan view and its tally, as `deploy --dry-run` prints them.
        assert "Deploy plan · strategy PREVIEW · 1 platform, 0 tenants" in log
        assert "+ create or update  Sentinel KQL Rule" in log
        assert "Plan: 0 to create, 0 to update, 1 to create or update" in log
        assert "  sentinel: 1 rule" not in log
        assert "warning: sentinel has no tenants configured" in log

    _drive(tutorial_repo, script)
    for deployer in stub_deployers.values():
        deployer.deploy.assert_not_called()


def test_quit_waits_for_the_running_command(tutorial_repo: Path) -> None:
    """A worker thread cannot be cancelled: q keeps the UI up until it is done."""
    release = threading.Event()

    def slow(ctx: CliContext) -> dict[str, Any]:
        assert release.wait(10)
        return {"message": "Slow command completed"}

    slow_action = Action("slow", "opentide slow", "Takes a while", slow)

    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        app._start("slow", partial(app._run, slow_action), slow_action.command)
        await pilot.press("q")
        await pilot.pause()
        assert app.is_running
        assert "Waiting for opentide slow to finish" in _text(app, "#status")
        # Nothing new starts while it waits.
        await pilot.press("v")
        assert app.running == "opentide slow"
        release.set()
        await _settle(app, pilot)
        assert not app.is_running
        assert app.outcomes[-1].result.message == "Slow command completed"

    _drive(tutorial_repo, script)


def test_quit_with_nothing_running_exits_at_once(tutorial_repo: Path) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        await pilot.press("q")
        await pilot.pause()
        assert not app.is_running

    _drive(tutorial_repo, script)


def test_one_command_at_a_time(tutorial_repo: Path) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        app.running = "generate"
        app.action_run("validate")
        assert not app.workers
        app.running = None
        await pilot.press("r")
        await _settle(app, pilot)
        assert app.running is None
        assert app.catalogue is not None and app.catalogue.count("rule") == 1

    _drive(tutorial_repo, script)


def test_a_worker_that_raises_is_reported(
    tutorial_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        def explode(ctx: CliContext) -> Catalogue:
            raise RuntimeError("index unreadable")

        monkeypatch.setattr(tui_app, "load_catalogue", explode)
        app.action_reload()
        await _settle(app, pilot)
        assert "error[internal]: RuntimeError: index unreadable" in await _results(app, pilot)
        assert app.running is None

    _drive(tutorial_repo, script)


def test_a_failed_reload_keeps_the_outcome(
    tutorial_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        def explode(ctx: CliContext) -> Catalogue:
            raise RuntimeError("index unreadable")

        monkeypatch.setattr(tui_app, "load_catalogue", explode)
        app.action_run("validate")
        await _settle(app, pilot)
        assert app.validated
        log = await _results(app, pilot)
        assert "✓ 3 objects valid · " in log
        # RichLog wraps the line to the tab's width: compare it unwrapped.
        assert (
            "error[internal]: the catalogue could not be read again: RuntimeError: index unreadable"
            in " ".join(line.strip() for line in log.splitlines())
        )
        assert app.catalogue is not None  # the snapshot from before stays on screen
        assert app.running is None

    _drive(tutorial_repo, script)


# -- layout at 100 columns --------------------------------------------------

LONG_RULE = "LSASS memory read by an unsigned process from a user-writable directory"


def _tree_lines(app: OpentideTui) -> list[str]:
    """The tree as drawn: guides and labels, without the padding."""
    tree = app.query_one("#tree", Tree)
    return [tree.render_line(y).text.rstrip() for y in range(len(_labels(tree.root)))]


def test_the_tagline_shows_whole_or_not_at_all() -> None:
    summary = Text("acme-detections · 0 threats · 0 objectives · 0 rules")
    assert masthead_brand(98, summary).plain == "▐ ≋ opentide ▌"
    wide = masthead_brand(200, summary).plain
    assert wide == f"▐ ≋ opentide ▌  {TAGLINE}"
    # Exactly wide enough, and one cell short of it.
    fits = len(wide) + 2 + summary.cell_len
    assert masthead_brand(fits, summary).plain == wide
    assert masthead_brand(fits - 1, summary).plain == "▐ ≋ opentide ▌"


@pytest.mark.parametrize(
    ("label", "width", "tail", "fitted"),
    [
        ("Spec-driven development for agentic", 28, 0, "Spec-driven development for…"),
        # A cut after a space reads the same as one after a letter.
        ("Spec-driven development for agentic", 29, 0, "Spec-driven development for…"),
        ("Credential Access Objective  1 rule", 26, 8, "Credential Access…  1 rule"),
        ("Simulated Actor  0 objectives · 0 rules", 30, 24, "Simul…  0 objectives · 0 rules"),
        ("Short  1 rule", 13, 8, "Short  1 rule"),
        # No room for the name: the whole label is cut.
        ("Name  0 objectives · 0 rules", 10, 24, "Name  0 o…"),
    ],
)
def test_fit_label_cuts_with_an_ellipsis_and_keeps_the_counts(
    label: str, width: int, tail: int, fitted: str
) -> None:
    result = fit_label(Text(label), width, tail)
    assert result.plain == fitted
    assert result.cell_len <= width


def test_fit_label_keeps_the_style_of_the_cell_it_cuts() -> None:
    label = Text("Credential Access Objective")
    label.stylize("reverse")  # as the tree marks the cursor line
    cut = fit_label(label, 10)
    assert cut.plain == "Credentia…"
    assert all(span.style == "reverse" for span in cut.spans)
    assert cut.spans[-1].end == len(cut)


def test_at_100_columns_names_end_in_an_ellipsis_and_nothing_scrolls_sideways(
    tutorial_repo: Path,
) -> None:
    rule = tutorial_repo / RULE_FILE
    rule.write_text(
        rule.read_text(encoding="utf-8").replace(
            "name: Sentinel KQL Rule", f"name: {LONG_RULE}", 1
        ),
        encoding="utf-8",
    )

    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        tree = app.query_one("#tree", Tree)
        width = tree.scrollable_content_region.width
        lines = _tree_lines(app)
        assert all(len(line) <= width for line in lines), lines
        threat, objective, leaf = lines
        # The counts stay whole; the name gives way.
        assert threat.endswith("  1 objective · 1 rule"), threat
        assert objective.endswith("…  1 rule"), objective
        assert leaf.endswith("…") and " …" not in leaf, leaf
        assert LONG_RULE not in leaf
        assert tree.virtual_size.width <= width
        assert not tree.show_horizontal_scrollbar
        # The tagline does not fit beside the counts: it goes, whole.
        brand = _text(app, "#brand").strip()
        assert brand == "▐ ≋ opentide ▌"
        await pilot.press("down", "down")
        assert app.selected == RULE
        # The detail pane shows the full name.
        assert LONG_RULE in " ".join(_text(app, "#heading").split())

    _drive(tutorial_repo, script, size=(100, 30))


def test_an_empty_workspace_names_its_path_relative_to_the_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "acme-detections"
    (repo / "objects").mkdir(parents=True)
    assert empty_state(repo, repo) == "No detection objects in this workspace"
    assert empty_state(repo, tmp_path) == "No detection objects under acme-detections"
    assert empty_state(repo, repo / "objects") == "No detection objects in this workspace"
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert empty_state(repo, elsewhere) == "No detection objects in this workspace"
    monkeypatch.chdir(tmp_path)

    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        [line] = _labels(app.query_one("#tree", Tree).root)
        assert line == "No detection objects under acme-detections"
        assert str(tmp_path) not in line
        assert not app.query_one("#tree", Tree).show_horizontal_scrollbar

    _drive(repo, script, size=(100, 30))


# -- actions and renderers --------------------------------------------------


def test_an_action_that_raises_is_an_internal_failure(tutorial_repo: Path) -> None:
    def explode(ctx: CliContext) -> dict[str, Any]:
        assert ctx.json_output  # services return payloads and print nothing
        raise ValueError("boom")

    action = Action("boom", "opentide boom", "Fails", explode)
    outcome = run_action(CliContext(repo=tutorial_repo), action)
    assert outcome.result.ok is False
    assert outcome.result.failure is not None
    assert outcome.result.failure.code == "internal"
    assert outcome.result.message == "ValueError: boom"
    assert _plain(outcome_text(outcome, tutorial_repo).plain).splitlines() == [
        "$ opentide boom",
        "error: ValueError: boom",
    ]


def test_generate_runs_the_service_the_cli_calls(
    tutorial_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[CliContext] = []

    def fake_generate(ctx: CliContext, **_: Any) -> dict[str, Any]:
        calls.append(ctx)
        return {"message": "Full generation pipeline completed", "phases": ["docs"]}

    monkeypatch.setattr("opentide.cli.services.generation.run_generate", fake_generate)
    outcome = run_action(CliContext(repo=tutorial_repo), tui_service.ACTIONS_BY_NAME["generate"])
    assert [ctx.repo for ctx in calls] == [tutorial_repo]
    assert outcome.result.ok
    assert outcome_text(outcome, tutorial_repo).plain.splitlines()[-1] == (
        "✓ Full generation pipeline completed"
    )


def test_diagnostics_match_by_uuid_or_file(tmp_path: Path) -> None:
    path = tmp_path / "rule.yaml"
    entry = CatalogueEntry(uuid=RULE, kind="rule", name="Rule", path=path)
    by_uuid = Diagnostic.from_issue({"code": "x", "message": "m", "object_uuid": RULE})
    by_file = Diagnostic.from_issue({"code": "x", "message": "m", "file_path": str(path)})
    other = Diagnostic.from_issue({"code": "x", "message": "m", "object_uuid": THREAT})
    nowhere = Diagnostic.from_issue({"code": "x", "message": "m"})
    assert [d.concerns(entry) for d in (by_uuid, by_file, other, nowhere)] == [
        True,
        True,
        False,
        False,
    ]
    assert Diagnostic.from_issue({"code": "x", "message": "m", "yaml_line": 0}).line == 1


def test_help_asks_did_you_mean_only_for_a_value() -> None:
    def help_for(code: str, suggestion: str) -> str | None:
        return Diagnostic.from_issue(
            {"code": code, "message": "m", "suggestion": suggestion}
        ).help_text()

    assert help_for("vocab_unknown", "clear") == "did you mean 'clear'?"
    assert help_for("invalid_ref", THREAT) == f"did you mean '{THREAT}'?"
    advice = "Confirm each identifier on Vulnerability-Lookup (https://vulnerability.circl.lu)."
    assert help_for("invalid_cve", advice) == advice
    diagnostic = Diagnostic.from_issue(
        {"code": "invalid_cve", "message": "m", "suggestion": advice}
    )
    assert _plain(diagnostic_text(diagnostic, Path(".")).plain).splitlines()[-1] == (
        f"  ╰─ help: {advice}"
    )
    assert Diagnostic.from_issue({"code": "x", "message": "m"}).help_text() is None


def test_a_diagnostic_reads_as_the_spec_frame_without_its_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "detections"
    rule = repo / RULE_FILE
    issue = {
        "code": "vocab_unknown",
        "message": "Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry",
        "suggestion": "clear",
        "file_path": str(rule),
        "yaml_line": 7,
        "field_path": ["metadata", "tlp"],
    }
    monkeypatch.chdir(tmp_path)
    framed = _plain(diagnostic_text(Diagnostic.from_issue(issue), repo).plain)
    # Relative to the current directory when the file is inside it.
    assert framed.splitlines() == [
        "error[vocab_unknown]: Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry",
        f"  ╭─▶ detections/{RULE_FILE}:8",
        "  ╰─ help: did you mean 'clear'?",
    ]
    (tmp_path / "elsewhere").mkdir()
    monkeypatch.chdir(tmp_path / "elsewhere")
    # Elsewhere, relative to the workspace; no help closes the location; no
    # line, the field says where.
    bare = Diagnostic.from_issue({**issue, "suggestion": None, "yaml_line": None})
    assert _plain(diagnostic_text(bare, repo).plain).splitlines()[1:] == [
        f"  ╰─▶ {RULE_FILE} · metadata.tlp"
    ]


def test_results_text_carries_no_line_breaks_of_its_own(tutorial_repo: Path) -> None:
    """RichLog wraps to the width of the Results tab; the text must not wrap first."""
    warning = "sentinel has no tenants configured in " + "x/" * 80 + "sentinel.toml"
    action = Action(
        "long", "opentide long", "Long", lambda ctx: {"message": "Done", "warnings": [warning]}
    )
    outcome = run_action(CliContext(repo=tutorial_repo), action)
    assert _plain(outcome_text(outcome, tutorial_repo).plain).splitlines() == [
        "$ opentide long",
        f"warning: {warning}",
        "✓ Done",
    ]


def test_pill_is_white_on_reflex_blue() -> None:
    text = pill()
    assert text.plain == "▐ ≋ opentide ▌"
    middle = text.spans[1].style
    assert str(middle.bgcolor.name) == "#001489"
    assert str(middle.color.name) == "#ffffff"


# -- the command ------------------------------------------------------------


def test_refused_outside_a_terminal(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli_app, ["--repo", str(tmp_path), "tui"])
    assert result.exit_code == 2
    assert _plain(result.stderr).splitlines()[0] == (
        "error: opentide tui needs an interactive terminal; this run is in plain mode"
    )


def test_refused_with_json(tmp_path: Path) -> None:
    result = CliRunner().invoke(cli_app, ["--repo", str(tmp_path), "tui", "--json"])
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["failure"]["code"] == "usage_tui_needs_tty"
    assert payload["command"] == "tui"
    assert [action["command"] for action in payload["next_actions"]] == [
        "opentide --json info",
        "opentide --json validate",
    ]


@pytest.mark.parametrize(
    ("argv", "env", "reason"),
    [
        ([], {"NO_COLOR": "1"}, "NO_COLOR is set"),
        (["--no-color"], {}, "--no-color was passed"),
        ([], {"CI": "true"}, "a CI environment was detected"),
        ([], {"OPENTIDE_OUTPUT": "plain"}, "OPENTIDE_OUTPUT is plain"),
    ],
    ids=["no-color-env", "no-color-flag", "ci", "opentide-output"],
)
def test_at_a_terminal_in_plain_mode_the_refusal_names_the_setting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    env: dict[str, str],
    reason: str,
) -> None:
    monkeypatch.setattr(tui_command, "_interactive", lambda: True)
    for name in ("NO_COLOR", "CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "TERM"):
        monkeypatch.delenv(name, raising=False)
    result = CliRunner().invoke(cli_app, ["--repo", str(tmp_path), *argv, "tui"], env=env)
    assert result.exit_code == 2
    assert _plain(result.stderr).splitlines()[:2] == [
        "error: opentide tui runs only in the human output mode; "
        f"this run is in plain mode because {reason}",
        "  help: set OPENTIDE_OUTPUT=human to open it anyway",
    ]


def test_at_a_terminal_the_json_refusal_carries_the_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tui_command, "_interactive", lambda: True)
    result = CliRunner().invoke(
        cli_app, ["--repo", str(tmp_path), "--json", "tui"], env={"NO_COLOR": "1"}
    )
    payload = json.loads(result.stdout)
    # --json is not a setting a person can be told to drop: the plain wording.
    assert payload["message"] == (
        "opentide tui needs an interactive terminal; this run is in json mode"
    )
    assert "advice" not in payload
    assert payload["failure"]["code"] == "usage_tui_needs_tty"


def test_human_mode_without_a_terminal_on_stdin_is_refused(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli_app, ["--repo", str(tmp_path), "tui"], env={"OPENTIDE_OUTPUT": "human"}
    )
    assert result.exit_code == 2
    assert "stdin or stdout is not one" in _plain(result.stderr)


def test_human_mode_on_a_terminal_runs_the_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started: list[CliContext] = []
    monkeypatch.setattr(tui_command, "_interactive", lambda: True)
    monkeypatch.setattr(OpentideTui, "run", lambda self: started.append(self.cli))
    result = CliRunner().invoke(
        cli_app, ["--repo", str(tmp_path), "tui"], env={"OPENTIDE_OUTPUT": "human"}
    )
    assert result.exit_code == 0, result.output
    assert [ctx.repo for ctx in started] == [tmp_path]


def test_the_service_module_does_not_import_textual() -> None:
    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys\nimport opentide.cli.services.tui\n"
            "raise SystemExit('textual' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr


def _modules_after(code: str) -> set[str]:
    """The modules a fresh interpreter has loaded once *code* ran."""
    done = subprocess.run(
        [sys.executable, "-c", f"{code}\nimport sys\nprint(' '.join(sorted(sys.modules)))"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return set(done.stdout.splitlines()[-1].split())


def _textual(modules: set[str]) -> set[str]:
    return {name for name in modules if name.split(".")[0] == "textual"}


def test_tui_help_does_not_import_textual() -> None:
    """Textual loads when the UI opens, never for the command's help."""
    modules = _modules_after(
        "import contextlib, io\n"
        "from opentide.cli import app\n"
        "with contextlib.redirect_stdout(io.StringIO()), contextlib.suppress(SystemExit):\n"
        "    app(['tui', '--help'])"
    )
    assert "opentide.cli.commands.tui" in modules
    assert not _textual(modules)


def test_walking_the_command_tree_does_not_import_textual() -> None:
    """What introspection does (``opentide commands``, completion): build every command."""
    modules = _modules_after(
        "import typer\n"
        "from typer import _click\n"
        "from opentide.cli import app\n"
        "def walk(command, ctx):\n"
        "    command.get_params(ctx)\n"
        "    for name in getattr(command, 'list_commands', lambda ctx: [])(ctx):\n"
        "        child = command.get_command(ctx, name)\n"
        "        walk(child, _click.Context(child, parent=ctx, info_name=name))\n"
        "group = typer.main.get_command(app)\n"
        "walk(group, _click.Context(group, info_name='opentide'))"
    )
    assert "opentide.cli.commands.tui" in modules
    assert not _textual(modules)
