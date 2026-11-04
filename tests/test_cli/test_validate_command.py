"""``opentide validate --fix`` / ``--watch``: the command's wiring, with the services stubbed.

The end-to-end tests run the same paths on a real workspace, but under
``cli_e2e`` and without coverage. These pin what the command passes to the
services and how it renders what comes back.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.commands import validate as validate_command
from opentide.cli.enums import QueriesMode
from opentide.cli.ui.diagnostics import Diagnostic
from opentide.cli.ui.fixes import FixChange, FixPlan
from opentide.cli.ui.mode import OutputMode
from opentide.cli.ui.watch import WatchRun

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\]8;[^\x1b]*\x1b\\")
_CHANGED = Path("/ws/objects/rules/changed.yaml")


def _invoke(repo: Path, *argv: str) -> Result:
    env = {
        "OPENTIDE_REPO_ROOT": str(repo),
        "OPENTIDE_TIDE_WORKSPACE": str(repo),
        "OPENTIDE_DATA_ROOT": None,
        "NO_COLOR": None,
    }
    return CliRunner().invoke(app, ["--repo", str(repo), *argv], env=env)


def _text(result: Result) -> str:
    return _ANSI.sub("", result.output)


class FakeWatcher:
    """Runs one full and one scoped validation, shows a pass, then gets Ctrl-C."""

    instances: list[FakeWatcher] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        FakeWatcher.instances.append(self)

    def run(self, show: Callable[[WatchRun], None]) -> None:
        validate = self.kwargs["validate"]
        diagnostics, objects = validate(None)
        validate((_CHANGED,))
        show(
            WatchRun(
                number=1,
                diagnostics=tuple(diagnostics),
                found=tuple(diagnostics),
                objects=objects,
                errors=0,
                warnings=0,
                files=0,
                failed=False,
                seconds=0.4,
            )
        )
        raise KeyboardInterrupt


@pytest.fixture
def watch(tmp_path: Path) -> Iterator[list[dict[str, Any]]]:
    """Stub the watcher, the workspace folders and ``run_validate``; yield its calls."""
    FakeWatcher.instances = []
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    calls: list[dict[str, Any]] = []

    def run_validate(_cli: object, **kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {"_diagnostics": [], "_summary": {"objects": 3}}

    folders = {"rule": rules, "threat": tmp_path / "objects" / "missing"}
    with (
        patch.object(validate_command, "Watcher", FakeWatcher),
        patch("opentide.cli.services.validation.run_validate", side_effect=run_validate),
        patch("opentide.registry.paths.resolve_workspace_paths", return_value=folders),
    ):
        yield calls


def test_a_narrowed_watch_passes_its_filters_to_every_full_run(
    tmp_path: Path, watch: list[dict[str, Any]]
) -> None:
    result = _invoke(
        tmp_path,
        "validate",
        "--watch",
        "--strict",
        "--file",
        "objects/rules/a.yaml",
        "--uuid",
        "u-1",
        "--type",
        "rule",
    )
    assert result.exit_code == 0, result.output
    (watcher,) = FakeWatcher.instances
    assert watcher.kwargs["scoped_runs"] is False
    assert watcher.kwargs["strict"] is True
    assert "platform_not_enabled" in watcher.kwargs["strict_exempt"]
    assert watcher.kwargs["roots"] == [tmp_path / "objects" / "rules"]
    full, scoped = watch
    assert full == {
        "check": None,
        "strict": True,
        "files": ["objects/rules/a.yaml"],
        "uuids": ["u-1"],
        "object_types": ["rule"],
        "queries": QueriesMode.error,
    }
    # A pass over changed files validates those files, not the narrowed scope.
    assert scoped == {
        "check": None,
        "strict": True,
        "files": [str(_CHANGED)],
        "uuids": None,
        "object_types": None,
        "queries": QueriesMode.error,
    }
    assert re.search(r"^✓ 3 objects valid · 0\.4s$", _text(result), re.MULTILINE), result.output


def test_a_whole_workspace_watch_may_validate_changed_files_alone(
    tmp_path: Path, watch: list[dict[str, Any]]
) -> None:
    result = _invoke(tmp_path, "validate", "--watch")
    assert result.exit_code == 0, result.output
    (watcher,) = FakeWatcher.instances
    assert watcher.kwargs["scoped_runs"] is True
    assert watcher.kwargs["strict"] is False
    assert [call["files"] for call in watch] == [None, [str(_CHANGED)]]


def test_a_watch_in_a_terminal_draws_the_live_view(
    tmp_path: Path, watch: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with patch.object(validate_command, "get_mode", return_value=OutputMode.HUMAN):
        result = _invoke(tmp_path, "validate", "--watch")
    assert result.exit_code == 0, result.output
    text = _text(result)
    assert "✓ 3 objects valid · 0.4s" in text
    assert re.search(r"watching objects/rules · \d\d:\d\d:\d\d · Ctrl-C to stop", text), text


def test_shown_names_the_folder_that_holds_every_watched_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    shown = validate_command._shown
    assert shown([]) == "nothing: no object folder exists"
    assert shown([tmp_path / "objects" / "rules", tmp_path / "objects" / "threats"]) == "objects"
    assert shown([tmp_path]) == "."
    outside = tmp_path.parent / "elsewhere"
    assert shown([outside / "rules", outside / "threats"]) == outside.as_posix()


def test_watched_folders_are_the_object_folders_that_exist(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    folders = {"rule": rules, "threat": tmp_path / "missing", "_workspace_root": tmp_path}
    with patch("opentide.registry.paths.resolve_workspace_paths", return_value=folders):
        assert validate_command.watched_folders() == [rules]


# --------------------------------------------------------------------------
# --fix rendering
# --------------------------------------------------------------------------


def _change(tmp_path: Path) -> FixChange:
    return FixChange(
        path="objects/rules/rule.yaml",
        file_path=tmp_path / "objects" / "rules" / "rule.yaml",
        line=8,
        column=8,
        code="vocab_unknown",
        before="Clear",
        after="clear",
    )


def _payload(*, failed: bool, **extra: Any) -> dict[str, Any]:
    summary = {"objects": 1, "errors": int(failed), "warnings": 0, "files": int(failed)}
    payload: dict[str, Any] = {
        "report": {"ok": not failed, "issues": []},
        "status": "failed" if failed else "passed",
        "message": "Validation failed" if failed else "Validation passed",
        "_exit_code": int(failed),
        "_summary": summary | extra.pop("summary", {}),
        "_diagnostics": [],
        "_fix_plan": FixPlan(),
    }
    if failed:
        payload["_failure_code"] = "issues_found"
    return payload | extra


def test_a_fix_that_could_not_be_written_says_so(tmp_path: Path) -> None:
    payload = _payload(
        failed=True,
        summary={"fixable": 1, "fixed": 0},
        fixed=[],
        warnings=["Could not write the fix to objects/rules/rule.yaml: Permission denied"],
        _fixed=FixPlan(),
        _unwritten=["objects/rules/rule.yaml: Permission denied"],
        _unwritten_fixes=1,
    )
    with patch("opentide.cli.services.validation.run_validate_fix", return_value=payload):
        result = _invoke(tmp_path, "validate", "--fix")
    assert result.exit_code == 1
    text = _text(result)
    assert (
        "warning: Could not write the fix to objects/rules/rule.yaml: Permission denied\n" in text
    )
    assert re.search(r"✗ 1 error in 1 file · could not write 1 fix · 1 object checked · ", text)
    assert "no safe fix" not in text


def test_quiet_fix_prints_the_outcome_line_alone(tmp_path: Path) -> None:
    change = _change(tmp_path)
    fixed = FixPlan((change,), {change.file_path: (change.path, "a", "b")})
    payload = _payload(
        failed=False, summary={"fixable": 0, "fixed": 1}, fixed=[change.to_dict()], _fixed=fixed
    )
    # The command pops the private keys, so each run gets its own copy.
    with patch(
        "opentide.cli.services.validation.run_validate_fix",
        side_effect=lambda *_, **__: dict(payload),
    ):
        loud = _invoke(tmp_path, "validate", "--fix")
        quiet = _invoke(tmp_path, "--quiet", "validate", "--fix")
    assert "fixed: " in _text(loud)
    assert quiet.exit_code == 0, quiet.output
    assert re.fullmatch(r"✓ Fixed 1 value in 1 file · 1 object valid · \d+\.\ds\n", _text(quiet)), (
        quiet.output
    )


def test_a_dry_run_with_nothing_to_fix_prints_no_diff(tmp_path: Path) -> None:
    payload = _payload(failed=False, summary={"fixable": 0}, would_fix=[], diff="")
    with patch("opentide.cli.services.validation.run_validate_fix", return_value=payload) as run:
        result = _invoke(tmp_path, "validate", "--fix", "--dry-run")
    assert run.call_args.kwargs["dry_run"] is True
    assert result.exit_code == 0, result.output
    assert re.fullmatch(r"✓ 1 object valid · \d+\.\ds\n", _text(result)), result.output


def test_a_dry_run_prints_the_diff_and_frames_only_what_it_would_not_fix(
    tmp_path: Path,
) -> None:
    change = _change(tmp_path)
    plan = FixPlan((change,), {change.file_path: (change.path, "tlp: Clear\n", "tlp: clear\n")})
    fixable = Diagnostic(
        code="vocab_unknown",
        severity="error",
        message="Value 'Clear' is not a valid 'tlp::1.0' vocabulary entry",
        path=change.path,
        file_path=change.file_path,
        line=8,
        column=8,
    )
    left = Diagnostic(code="invalid_ref", severity="error", message="Unknown reference")
    payload = _payload(
        failed=True,
        summary={"fixable": 1},
        would_fix=[change.to_dict()],
        diff=plan.diff(),
        _fix_plan=plan,
        _diagnostics=[fixable, left],
    )
    with patch("opentide.cli.services.validation.run_validate_fix", return_value=payload):
        result = _invoke(tmp_path, "validate", "--fix", "--dry-run")
    assert result.exit_code == 1
    text = _text(result)
    assert "-tlp: Clear\n+tlp: clear\n" in text
    assert "error[invalid_ref]" in text
    assert "error[vocab_unknown]" not in text, "the diff already shows it"
    assert re.search(r"✗ 1 error in 1 file · would fix 1 value in 1 file · 1 object checked", text)


@pytest.mark.parametrize(
    ("argv", "code", "argument"),
    [
        (("validate", "--dry-run"), "usage_error", "--dry-run"),
        (("validate", "--watch", "--fix"), "usage_error", "--watch"),
        # #646 + #648: the watch loop would write no report and say nothing.
        (
            ("validate", "--watch", "--format", "sarif", "--output", "r.sarif"),
            "usage_error",
            "--watch",
        ),
        (("validate", "--watch"), "usage_watch_needs_tty", "--watch"),
    ],
)
def test_combinations_that_cannot_run_exit_2(
    tmp_path: Path, argv: tuple[str, ...], code: str, argument: str
) -> None:
    with patch("opentide.cli.services.validation.run_validate") as run:
        result = _invoke(tmp_path, "--json", *argv)
    run.assert_not_called()
    assert result.exit_code == 2
    failure = json.loads(result.stdout)["failure"]
    assert (failure["code"], failure["argument"]) == (code, argument)


@pytest.mark.parametrize("report", ["sarif", "codequality"])
def test_watch_refuses_a_report_format_and_writes_nothing(tmp_path: Path, report: str) -> None:
    """``--watch --format`` exits 2 before the watch starts, in human output too."""
    output = tmp_path / "report.json"
    with patch("opentide.cli.services.validation.run_validate") as run:
        result = _invoke(
            tmp_path, "validate", "--watch", "--format", report, "--output", str(output)
        )
    run.assert_not_called()
    assert result.exit_code == 2
    assert "--watch cannot be combined with --format" in _text(result)
    assert not output.exists()
