"""``opentide tui``: the Textual app, driven by its pilot against the tutorial repository."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import re
import subprocess
import sys
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from tests.test_cli.e2e.helpers import write_tutorial_objects
from textual.pilot import Pilot
from textual.widgets import DataTable, RichLog, Static, TabbedContent, Tree
from textual.worker import WorkerFailed
from typer.testing import CliRunner

from opentide.cli import app as cli_app
from opentide.cli.commands import tui as tui_command
from opentide.cli.commands.tui import OpentideTui, outcome_text, pill
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


def _drive(repo: Path, script: Callable[[OpentideTui, Pilot[None]], Awaitable[None]]) -> None:
    """Run the app headless on *repo*, wait for the catalogue, then run *script*."""

    async def main() -> None:
        app = OpentideTui(CliContext(repo=repo))
        async with app.run_test(size=(140, 40)) as pilot:
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
    """What a Static shows, as plain text."""
    console = Console(width=200, file=io.StringIO())
    console.print(app.query_one(selector, Static).content)
    return console.file.getvalue()  # ty: ignore[unresolved-attribute]


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
        assert f"--> {RULE_FILE}:8 · metadata.tlp" in detail
        assert "help: did you mean 'clear'?" in detail
        assert "Sentinel KQL Rule  ✗ 1" in _labels(app.query_one("#tree", Tree).root)[-1]
        assert "opentide validate: Validation failed" in _text(app, "#status")
        # The cursor stays on the rule after the tree is rebuilt.
        assert app.selected == RULE
        log = await _results(app, pilot)
        assert "$ opentide validate" in log
        assert (
            "error[vocab_unknown]: Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry" in log
        )
        assert "error: Validation failed" in log
        await pilot.press("1", "up")
        assert "No diagnostics from the last validate run" in _text(app, "#diagnostics")

    _drive(tutorial_repo, script)


def test_a_clean_validate_reports_success(tutorial_repo: Path) -> None:
    async def script(app: OpentideTui, pilot: Pilot[None]) -> None:
        app.action_run("validate")
        await _settle(app, pilot)
        assert "✓ Validation passed" in await _results(app, pilot)
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
        assert "  sentinel: 1 rule" in log
        assert "✓ Deployment completed" in log
        assert "warning: sentinel has no tenants configured" in log

    _drive(tutorial_repo, script)
    for deployer in stub_deployers.values():
        deployer.deploy.assert_not_called()


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

        monkeypatch.setattr(tui_command, "load_catalogue", explode)
        app.action_reload()
        await _settle(app, pilot)
        assert "error[internal]: RuntimeError: index unreadable" in await _results(app, pilot)
        assert app.running is None

    _drive(tutorial_repo, script)


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


def test_pill_is_white_on_reflex_blue() -> None:
    text = pill()
    assert text.plain == "▐ ≋ opentide ▌"
    middle = text.spans[1].style
    assert str(middle.bgcolor.name) == "#001489"  # ty: ignore[unresolved-attribute]
    assert str(middle.color.name) == "#ffffff"  # ty: ignore[unresolved-attribute]


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
        "opentide info",
        "opentide validate",
    ]


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
            "import sys\nimport opentide.cli.services.tui\nraise SystemExit('textual' in sys.modules)",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
