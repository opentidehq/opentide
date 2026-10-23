"""CLI E2E: ``validate --fix``, ``--fix --dry-run`` and ``--watch`` on the tutorial workspace.

Three typos are safe to fix (two ``tlp: clearr``, a quoted ``"Data Breech"``)
and one is not (``criticality: Hihg``, under the similarity bar). Output is
read with ANSI stripped, since CI forces colour.
"""

from __future__ import annotations

import functools
import json
import re
import shutil
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches
from tests.test_cli.e2e.helpers import write_tutorial_objects
from tests.test_cli.e2e.pty_driver import PtySession, clean_env, requires_pty, strip_ansi
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup
from opentide.cli.ui.mode import AGENT_VARIABLES, CI_PROVIDERS
from opentide.cli.ui.watch import Watcher

pytestmark = pytest.mark.cli_e2e

_LEAKY_ENV = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_OUTPUT",
    "DEPLOYMENT_PLAN",
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "NO_COLOR",
    "FORCE_COLOR",
    "AI_AGENT",
    "CLAUDECODE",
)
_RULE = Path("objects/rules/sentinel-kql-rule.yaml")
_THREAT = Path("objects/threats/simulated-actor.yaml")
_ANSI = re.compile(r"\x1b\[[0-9;]*m|\x1b\]8;[^\x1b]*\x1b\\")
_TIME = r"\d+\.\ds"


@pytest.fixture(scope="module")
def _pristine(tmp_path_factory: pytest.TempPathFactory) -> Path:
    repo = tmp_path_factory.mktemp("fix") / "tutorial"
    run_repo_setup(
        RepoSetupOptions(
            path=repo,
            name="Tutorial Detections",
            org="Example Corp",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
    write_tutorial_objects(repo)
    result = CliRunner().invoke(
        app, ["--repo", str(repo), "--json", "generate"], env=dict.fromkeys(_LEAKY_ENV)
    )
    assert result.exit_code == 0, result.output
    return repo


@pytest.fixture
def tutorial(_pristine: Path, tmp_path: Path) -> Iterator[Path]:
    repo = tmp_path / "tutorial"
    shutil.copytree(_pristine, repo)
    yield repo
    clear_runtime_caches()


def _edit(repo: Path, relpath: Path, old: str, new: str) -> None:
    path = repo / relpath
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _typos(repo: Path) -> None:
    """Three safe fixes in two files, and one fix that is not safe."""
    _edit(repo, _RULE, "  tlp: clear\n", "  tlp: clearr\n")
    _edit(repo, _THREAT, "  tlp: clear\n", "  tlp: clearr\n")
    _edit(repo, _THREAT, "    - Data Breach\n", '    - "Data Breech"\n')
    _edit(repo, _THREAT, "criticality: High\n", "criticality: Hihg\n")


def _env(repo: Path) -> dict[str, str | None]:
    return dict.fromkeys(_LEAKY_ENV) | {
        "OPENTIDE_REPO_ROOT": str(repo),
        "OPENTIDE_TIDE_WORKSPACE": str(repo),
    }


def _run(repo: Path, *argv: str, json_output: bool = False, **env: str) -> Result:
    clear_runtime_caches()
    head = ["--repo", str(repo)] + (["--json"] if json_output else [])
    return CliRunner().invoke(app, [*head, *argv], env=_env(repo) | env)


def _text(result: Result) -> str:
    return _ANSI.sub("", result.output)


def _files(repo: Path) -> dict[Path, bytes]:
    return {path: (repo / path).read_bytes() for path in (_RULE, _THREAT)}


def test_validate_points_at_fix_when_safe_fixes_exist(tutorial: Path) -> None:
    _typos(tutorial)
    result = _run(tutorial, "validate")
    assert result.exit_code == 1
    text = _text(result)
    assert re.search(
        rf"✗ 4 errors in 2 files · 3 fixable with --fix · 3 objects checked · {_TIME}\n"
        r"→ opentide validate --fix · apply 3 safe fixes\n",
        text,
    ), text

    payload = json.loads(_run(tutorial, "validate", json_output=True).stdout)
    assert payload["summary"] == {
        "objects": 3,
        "errors": 4,
        "warnings": 0,
        "files": 2,
        "fixable": 3,
    }
    assert payload["next_actions"] == [
        {"command": "opentide validate --fix", "reason": "apply 3 safe fixes"}
    ]
    assert "fixed" not in payload


def test_fix_applies_only_the_safe_fixes_and_keeps_every_other_byte(tutorial: Path) -> None:
    _typos(tutorial)
    before = _files(tutorial)
    result = _run(tutorial, "validate", "--fix")
    assert result.exit_code == 1, result.output
    text = _text(result)
    assert (
        "fixed: objects/rules/sentinel-kql-rule.yaml:8:8 'clearr' → 'clear'\n"
        "fixed: objects/threats/simulated-actor.yaml:9:8 'clearr' → 'clear'\n"
        "fixed: objects/threats/simulated-actor.yaml:18:8 'Data Breech' → 'Data Breach'\n"
    ) in text
    assert "error[vocab_unknown]: Value 'Hihg' is not a valid 'criticality::1.0'" in text
    assert text.count("error[") == 1
    assert re.search(
        rf"✗ 1 error in 1 file · fixed 3 values in 2 files · 3 objects checked · {_TIME}\n", text
    )
    assert "→ opentide validate --fix" not in text

    after = _files(tutorial)
    assert after[_RULE] == before[_RULE].replace(b"  tlp: clearr\n", b"  tlp: clear\n")
    assert after[_THREAT] == (
        before[_THREAT]
        .replace(b"  tlp: clearr\n", b"  tlp: clear\n")
        .replace(b'"Data Breech"', b'"Data Breach"')
    )
    assert b"criticality: Hihg" in after[_THREAT]
    assert b"# the objective from step 4" in after[_RULE]

    # A second run has nothing left to apply and changes nothing.
    again = _run(tutorial, "validate", "--fix")
    assert again.exit_code == 1
    assert re.search(
        rf"✗ 1 error in 1 file · no safe fix to apply · 3 objects checked · {_TIME}\n",
        _text(again),
    )
    assert _files(tutorial) == after
    payload = json.loads(_run(tutorial, "validate", "--fix", json_output=True).stdout)
    assert (payload["fixed"], payload["summary"]["fixed"]) == ([], 0)
    assert _files(tutorial) == after


def test_fix_reports_each_value_in_json(tutorial: Path) -> None:
    _typos(tutorial)
    payload = json.loads(_run(tutorial, "validate", "--fix", json_output=True).stdout)
    assert payload["fixed"] == [
        {
            "path": "objects/rules/sentinel-kql-rule.yaml",
            "line": 8,
            "code": "vocab_unknown",
            "before": "clearr",
            "after": "clear",
        },
        {
            "path": "objects/threats/simulated-actor.yaml",
            "line": 9,
            "code": "vocab_unknown",
            "before": "clearr",
            "after": "clear",
        },
        {
            "path": "objects/threats/simulated-actor.yaml",
            "line": 18,
            "code": "vocab_unknown",
            "before": "Data Breech",
            "after": "Data Breach",
        },
    ]
    assert payload["summary"] == {
        "objects": 3,
        "errors": 1,
        "warnings": 0,
        "files": 1,
        "fixable": 0,
        "fixed": 3,
    }
    (remaining,) = payload["report"]["issues"]
    assert remaining["context"]["value"] == "Hihg"
    assert remaining["fix"]["safe"] is False
    assert payload["next_actions"] == []
    assert payload["exit_code"] == 1
    assert payload["failure"]["code"] == "issues_found"


def test_fix_with_nothing_left_passes(tutorial: Path) -> None:
    _edit(tutorial, _RULE, "  tlp: clear\n", "  tlp: clearr\n")
    result = _run(tutorial, "validate", "--fix")
    assert result.exit_code == 0, result.output
    assert re.search(
        rf"^✓ Fixed 1 value in 1 file · 3 objects valid · {_TIME}$", _text(result), re.M
    )
    clean = _run(tutorial, "validate", "--fix")
    assert re.fullmatch(rf"✓ 3 objects valid · {_TIME}\n", _text(clean))


def test_dry_run_prints_the_diff_and_changes_nothing(tutorial: Path) -> None:
    _typos(tutorial)
    before = _files(tutorial)
    result = _run(tutorial, "validate", "--fix", "--dry-run")
    assert result.exit_code == 1, result.output
    text = _text(result)
    assert (
        "--- a/objects/rules/sentinel-kql-rule.yaml\n"
        "+++ b/objects/rules/sentinel-kql-rule.yaml\n"
        "@@ -5,7 +5,7 @@\n"
        "   version: 1\n"
        "   created: 2026-01-01\n"
        "   modified: 2026-01-02\n"
        "-  tlp: clearr\n"
        "+  tlp: clear\n"
    ) in text
    assert '-    - "Data Breech"\n+    - "Data Breach"\n' in text
    # The diff covers the three it would fix; the frame shows the one it would not.
    assert text.count("error[") == 1
    assert "'Hihg'" in text
    assert re.search(
        rf"✗ 4 errors in 2 files · would fix 3 values in 2 files · 3 objects checked · {_TIME}\n"
        r"→ opentide validate --fix · apply 3 safe fixes\n",
        text,
    ), text
    assert _files(tutorial) == before

    payload = json.loads(_run(tutorial, "validate", "--fix", "--dry-run", json_output=True).stdout)
    assert [entry["after"] for entry in payload["would_fix"]] == ["clear", "clear", "Data Breach"]
    assert payload["diff"].startswith("--- a/objects/rules/sentinel-kql-rule.yaml\n")
    assert "fixed" not in payload["summary"]
    assert payload["summary"]["fixable"] == 3
    assert _files(tutorial) == before


@pytest.mark.parametrize(
    ("argv", "argument"),
    [
        (("validate", "--dry-run"), "--dry-run"),
        (("validate", "--watch", "--fix"), "--watch"),
    ],
)
def test_flag_combinations_that_cannot_work_are_usage_errors(
    tutorial: Path, argv: tuple[str, ...], argument: str
) -> None:
    payload = json.loads(_run(tutorial, *argv, json_output=True).stdout)
    assert payload["exit_code"] == 2
    assert payload["failure"]["code"] == "usage_error"
    assert payload["failure"]["argument"] == argument


def test_watch_is_refused_where_no_terminal_shows_it(tutorial: Path) -> None:
    result = _run(tutorial, "validate", "--watch", json_output=True)
    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["failure"]["code"] == "usage_watch_needs_tty"
    assert payload["failure"]["argument"] == "--watch"
    assert payload["next_actions"] == [{"command": "opentide validate", "reason": "validate once"}]

    agent = _run(tutorial, "validate", "--watch", OPENTIDE_OUTPUT="agent")
    assert agent.exit_code == 2
    assert _text(agent).startswith(
        "error: --watch redraws the terminal until Ctrl-C, so it does not run in agent mode\n"
    )


def test_watch_in_plain_mode_prints_one_outcome_line_per_run(
    tutorial: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _edit(tutorial, _RULE, "  tlp: clear\n", "  tlp: clearr\n")
    naps: list[float] = []

    def sleep(seconds: float) -> None:
        naps.append(seconds)
        if len(naps) == 1:
            # A save: the next poll sees a new size and re-checks the rule alone.
            _edit(tutorial, _RULE, "  tlp: clearr\n", "  tlp: clear\n")
        elif len(naps) == 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(
        "opentide.cli.commands.validate.Watcher", functools.partial(Watcher, sleep=sleep)
    )
    result = _run(tutorial, "validate", "--watch")
    assert result.exit_code == 0, result.output
    lines = [line for line in _text(result).splitlines() if line.startswith(("✓", "✗"))]
    assert len(lines) == 2, result.output
    assert re.fullmatch(
        rf"✗ 1 error in 1 file · 1 fixable with --fix · 3 objects checked · {_TIME}", lines[0]
    )
    assert re.fullmatch(rf"✓ 3 objects valid · {_TIME}", lines[1])
    assert _text(result).count("error[vocab_unknown]") == 1
    assert len(naps) == 3


def test_watch_in_a_terminal_redraws_and_exits_0_on_ctrl_c(tutorial: Path) -> None:
    requires_pty()
    _edit(tutorial, _RULE, "  tlp: clear\n", "  tlp: clearr\n")
    env = clean_env(tutorial)
    for name in (*AGENT_VARIABLES, *(variable for variable, _ in CI_PROVIDERS), "CI"):
        env.pop(name, None)
    for name in ("NO_COLOR", "OPENTIDE_OUTPUT", "FORCE_COLOR", "PY_COLORS"):
        env.pop(name, None)
    session = PtySession(["validate", "--watch"], env=env, cwd=tutorial, timeout=90)
    session.expect("Ctrl-C to stop")
    time.sleep(0.3)
    _edit(tutorial, _RULE, "  tlp: clearr\n", "  tlp: clear\n")
    session.expect("re-checked sentinel-kql-rule.yaml")
    session.child.sendcontrol("c")
    run = session.finish()
    assert run.exit_status == 0, run.clean
    screen = strip_ansi(run.output)
    assert "✗ 1 error in 1 file · 1 fixable with --fix · 3 objects checked" in screen
    assert "✓ 3 objects valid" in screen
    assert "Traceback" not in screen
