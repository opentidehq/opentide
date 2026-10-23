"""Brand marks, progress checklist, deploy plan, setup welcome and home screen.

Every renderer is snapshotted at a fixed width, ``human`` with its styles and
``plain`` without, so a change to what people see shows up as a diff.
"""

from __future__ import annotations

import io
import warnings
from pathlib import Path

import pytest
from rich.console import Console

from opentide.cli.ui import brand
from opentide.cli.ui.contract import NextAction
from opentide.cli.ui.home import HomeFacts, gather, home_view, next_steps
from opentide.cli.ui.layout import columns
from opentide.cli.ui.mode import OutputMode, set_mode
from opentide.cli.ui.plan import plan_view
from opentide.cli.ui.progress import Checklist, Step, checklist_table, step_line
from opentide.cli.ui.render import render_next_actions
from opentide.cli.ui.setup import render_summary, setup_outcome, welcome

WIDTH = 100


def _console(mode: OutputMode, *, width: int = WIDTH, encoding: str = "utf-8") -> Console:
    human = mode is OutputMode.HUMAN
    return Console(
        record=True,
        width=width,
        file=io.TextIOWrapper(io.BytesIO(), encoding=encoding),
        force_terminal=human,
        color_system="truecolor" if human else None,
    )


def _text(console: Console, mode: OutputMode) -> str:
    return console.export_text(styles=mode is OutputMode.HUMAN)


MODES = [OutputMode.HUMAN, OutputMode.PLAIN]

# --------------------------------------------------------------------------
# Brand
# --------------------------------------------------------------------------


def test_marks_have_the_documented_sizes() -> None:
    assert {len(row) for row in brand.ICON} == {28} and len(brand.ICON) == 28
    assert {len(row) for row in brand.LOGO} == {80} and len(brand.LOGO) == 20
    assert set("".join(brand.ICON + brand.LOGO)) <= {"B", "W", "."}
    icon = brand.icon().plain.splitlines()
    logo = brand.logo().plain.splitlines()
    assert (len(icon), {len(line) for line in icon}) == (14, {28})
    assert (len(logo), {len(line) for line in logo}) == (10, {80})


def test_blue_is_only_ever_a_fill() -> None:
    """Reflex Blue colours block glyphs and backgrounds, never letters."""
    for text in (brand.icon(), brand.logo(), brand.pill(), brand.header("Next steps")):
        for span in text.spans:
            style = span.style if not isinstance(span.style, str) else None
            if style is None or style.color is None:
                continue
            if style.color.name.lower() == brand.BLUE:
                assert set(text.plain[span.start : span.end]) <= set("▀▄█▐▌ ")


def test_mono_marks_keep_the_shape_without_colour() -> None:
    mono = brand.icon(mono=True)
    assert not mono.spans
    # The glyph is cut out of the disc: blank cells inside the circle.
    assert "█" in mono.plain and " " in mono.plain.splitlines()[7].strip()
    assert "█" in brand.logo(mono=True).plain


def test_marks_draw_only_for_a_person_with_a_capable_encoding() -> None:
    human = _console(OutputMode.HUMAN)
    assert brand.can_draw(human, mode=OutputMode.HUMAN)
    for mode in (OutputMode.PLAIN, OutputMode.AGENT, OutputMode.JSON, OutputMode.MCP):
        assert not brand.can_draw(human, mode=mode)
    ascii_console = _console(OutputMode.HUMAN, encoding="cp1252")
    assert not brand.can_draw(ascii_console, mode=OutputMode.HUMAN)
    assert brand.pill(encoding="ascii").plain == "opentide"
    assert brand.header("Next steps", encoding="ascii").plain == "Next steps"


def test_print_banner_is_deprecated_and_returns_the_new_mark() -> None:
    from opentide.cli import print_banner

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        banner = print_banner()
    assert any(issubclass(item.category, DeprecationWarning) for item in caught)
    assert brand.TAGLINE in banner
    assert "▄" in banner
    assert "DetectionOps" not in banner


# --------------------------------------------------------------------------
# Layout
# --------------------------------------------------------------------------


def test_columns_align_without_trailing_blanks() -> None:
    text = columns([("a", "long value", ""), ("longer", "v", "x")], right=(1,))
    assert text.plain.splitlines() == ["a       long value", "longer           v  x"]


# --------------------------------------------------------------------------
# Progress
# --------------------------------------------------------------------------

_STEPS = [
    Step("docs", count=4, where="docs/", status="ok", seconds=1.21),
    Step("vocabularies", count=0, status="ok", seconds=0.02),
    Step("schemas", count=6, where=".opentide/schemas/", status="ok", seconds=2.2),
    Step("snippets", count=1, where=".vscode/", status="failed", seconds=0.04),
]


@pytest.mark.parametrize("mode", MODES)
def test_generate_checklist_snapshot(mode: OutputMode, snapshot) -> None:
    """``human`` draws the final checklist; ``plain`` prints one line per finished step."""
    console = _console(mode)
    if mode is OutputMode.HUMAN:
        console.print(checklist_table(_STEPS))
    else:
        for step in _STEPS:
            console.print(step_line(step), soft_wrap=True)
    assert _text(console, mode) == snapshot


def test_checklist_prints_one_plain_line_per_step_and_marks_failures() -> None:
    console = _console(OutputMode.PLAIN)
    with pytest.raises(RuntimeError), Checklist(console, mode=OutputMode.PLAIN, quiet=False) as run:
        with run.step("templates", where=".opentide/templates/") as step:
            step.done(4)
        with run.step("schemas"):
            raise RuntimeError("boom")
    lines = console.export_text().splitlines()
    assert lines[0].startswith("✓ templates · 4 files · ")
    assert lines[0].endswith(" · .opentide/templates/")
    assert lines[1].startswith("✗ schemas · ")
    assert [step.status for step in run.steps] == ["ok", "failed"]


@pytest.mark.parametrize("mode", [OutputMode.JSON, OutputMode.MCP])
def test_checklist_is_silent_for_machines(mode: OutputMode) -> None:
    console = _console(OutputMode.PLAIN)
    with Checklist(console, mode=mode, quiet=False) as run, run.step("schemas") as step:
        step.done(3)
    assert console.export_text() == ""
    assert run.steps[0].to_dict()["count"] == 3


def test_checklist_is_silent_under_quiet() -> None:
    console = _console(OutputMode.PLAIN)
    with Checklist(console, mode=OutputMode.PLAIN, quiet=True) as run, run.step("schemas"):
        pass
    assert console.export_text() == ""


def test_checklist_shows_engine_stages_on_the_running_step() -> None:
    from opentide.core.progress import report_stage

    console = _console(OutputMode.PLAIN)
    seen: list[str] = []
    with Checklist(console, mode=OutputMode.PLAIN, quiet=False) as run, run.step("schemas"):
        report_stage("JSON schema assembly")
        assert run.current is not None
        seen.append(run.current.detail)
    assert seen == ["JSON schema assembly"]


def test_human_checklist_leaves_only_the_final_rows() -> None:
    console = _console(OutputMode.PLAIN)  # not a terminal: Live draws no frames
    with Checklist(console, mode=OutputMode.HUMAN, quiet=False) as run:
        with run.step("schemas", where=".opentide/schemas/") as step:
            step.done(6)
    text = console.export_text()
    assert len(text.splitlines()) == 1
    assert "6 files" in text


# --------------------------------------------------------------------------
# Deploy plan
# --------------------------------------------------------------------------

_CHANGES = [
    {
        "platform": "sentinel",
        "tenant": None,
        "uuid": "00000000-0000-4000-8000-000000000001",
        "name": "Sentinel KQL Rule",
        "status": "STAGING",
        "action": "upsert",
    },
    {
        "platform": "defender_for_endpoint",
        "tenant": "prod",
        "uuid": "00000000-0000-4000-8000-000000000002",
        "name": "Defender KQL Rule",
        "status": "PRODUCTION",
        "action": "update",
    },
    {
        "platform": "defender_for_endpoint",
        "tenant": "prod",
        "uuid": "00000000-0000-4000-8000-000000000003",
        "name": "Retired Rule",
        "status": "REMOVED",
        "action": "delete",
    },
]


@pytest.mark.parametrize("mode", MODES)
def test_plan_view_snapshot(mode: OutputMode, snapshot) -> None:
    console = _console(mode)
    console.print(
        plan_view(
            _CHANGES,
            strategies=["PREVIEW", "RELEASE"],
            tenants={"defender_for_endpoint": {"prod": []}},
        )
    )
    assert _text(console, mode) == snapshot


def test_plan_and_deploy_tallies() -> None:
    from opentide.cli.services.deploy_plan import (
        PlannedChange,
        deployed_message,
        plan_message,
        plan_summary,
    )

    changes = [
        PlannedChange(**{**change, "action": change["action"]})  # type: ignore[arg-type]
        for change in _CHANGES
    ]
    platforms = ["sentinel", "defender_for_endpoint"]
    assert plan_message(changes, platforms, 1) == (
        "Plan: 0 to create, 1 to update, 1 to create or update, 0 to disable, 1 to delete"
        " · 2 platforms, 1 tenant"
    )
    assert plan_message(changes[1:], platforms[1:], 1) == (
        "Plan: 0 to create, 1 to update, 0 to disable, 1 to delete · 1 platform, 1 tenant"
    )
    assert plan_summary(changes, platforms, 1)["delete"] == 1
    assert deployed_message(changes[1:2], 12.4) == (
        "Deployed 1 rule to 1 tenant · 1 updated · 12.4s"
    )


def test_plan_outcome_line_has_no_glyph() -> None:
    from opentide.cli.ui.render import outcome_text

    line = outcome_text("plan", "Plan: 1 to create · 1 platform, 0 tenants")
    assert line.plain == "Plan: 1 to create · 1 platform, 0 tenants"


# --------------------------------------------------------------------------
# Setup
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mode", "width"),
    [(OutputMode.HUMAN, WIDTH), (OutputMode.HUMAN, 70), (OutputMode.PLAIN, WIDTH)],
    ids=["human", "human-narrow", "plain"],
)
def test_setup_welcome_snapshot(mode: OutputMode, width: int, snapshot) -> None:
    console = _console(mode, width=width)
    welcome(console, version="0.18.0", mode=mode)
    assert _text(console, mode) == snapshot


_SETUP_RESULT = {
    "path": "/work/tutorial-detections",
    "steps": [
        {
            "step": "repo",
            "name": "Tutorial Detections",
            "scaffolded": True,
            "files": ["README.md", ".gitignore"],
            "platform_files": [".opentide/configurations/platforms/sentinel.toml"],
        },
        {"step": "ci", "files": [".github/workflows/opentide.yml"]},
    ],
}


@pytest.mark.parametrize("mode", MODES)
def test_setup_outcome_snapshot(mode: OutputMode, snapshot, monkeypatch) -> None:
    monkeypatch.chdir("/")
    set_mode(mode)
    console = _console(mode)
    render_summary(console, _SETUP_RESULT)
    message, actions = setup_outcome(_SETUP_RESULT)
    console.print(message)
    render_next_actions(console, actions, numbered=True)
    assert _text(console, mode) == snapshot


def test_setup_outcome_names_a_single_file() -> None:
    message, actions = setup_outcome({"path": "/x", "files": [".github/workflows/opentide.yml"]})
    assert (message, actions) == ("Wrote .github/workflows/opentide.yml", [])
    assert setup_outcome({"status": "skipped"}) == (None, [])


# --------------------------------------------------------------------------
# Home screen
# --------------------------------------------------------------------------

_FACTS = HomeFacts(
    version="0.18.0",
    workspace=Path("/work/detections"),
    git="main, clean",
    catalogue={"rules": 1, "threats": 1, "objectives": 1},
    schemas=True,
    platforms={"sentinel": 0},
)


@pytest.mark.parametrize(
    ("mode", "width"),
    [(OutputMode.HUMAN, WIDTH), (OutputMode.HUMAN, 70), (OutputMode.PLAIN, WIDTH)],
    ids=["human", "human-narrow", "plain"],
)
def test_home_screen_snapshot(mode: OutputMode, width: int, snapshot) -> None:
    set_mode(mode)
    console = _console(mode, width=width)
    console.print(home_view(console, _FACTS))
    assert _text(console, mode) == snapshot


def test_home_next_steps_follow_the_workspace() -> None:
    assert [step.command for step in next_steps(HomeFacts("1", None))] == ["opentide setup"]
    fresh = HomeFacts("1", Path("."), schemas=False, platforms={})
    assert [step.command for step in next_steps(fresh)] == [
        "opentide generate",
        "opentide validate",
        "opentide setup platforms --sentinel",
    ]
    assert len(next_steps(_FACTS)) <= 3
    assert all(isinstance(step, NextAction) for step in next_steps(_FACTS))


def test_gather_reads_counts_from_disk(tmp_path: Path) -> None:
    (tmp_path / ".opentide" / "configurations" / "platforms").mkdir(parents=True)
    (tmp_path / ".opentide" / "configurations" / "platforms" / "sentinel.toml").write_text(
        '[platform]\nenabled = true\n\n[[tenants]]\nname = "prod"\n', encoding="utf-8"
    )
    (tmp_path / "objects" / "rules").mkdir(parents=True)
    (tmp_path / "objects" / "rules" / "a.yaml").write_text("name: a\n", encoding="utf-8")
    facts = gather("1.0", tmp_path)
    assert facts.workspace == tmp_path.resolve()
    assert facts.catalogue == {"rules": 1, "threats": 0, "objectives": 0}
    assert facts.platforms == {"sentinel": 1}
    assert facts.schemas is False
