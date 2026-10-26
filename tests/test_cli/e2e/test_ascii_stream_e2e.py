"""CLI E2E: the merged commands run on an ASCII stream (``PYTHONIOENCODING=ascii``).

#638 gave every console glyph fallbacks; #642 (``new``, ``doctor``), #643
(``generate``'s checklist, the home screen) and #651 (compact ``--json``) came
later and print through them. A real process per command, in ``human`` mode,
since a pipe would otherwise select ``plain``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.cli_e2e

#: Variables that would change the mode or the encoding of the child process.
_DROP = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_DATA_ROOT",
    "NO_COLOR",
    "FORCE_COLOR",
    "PYTHONUTF8",
    "CLAUDECODE",
    "AI_AGENT",
)


def _run(cwd: Path, *argv: str) -> subprocess.CompletedProcess[bytes]:
    env = {key: value for key, value in os.environ.items() if key not in _DROP}
    env |= {"PYTHONIOENCODING": "ascii", "OPENTIDE_OUTPUT": "human", "COLUMNS": "100"}
    return subprocess.run(
        [sys.executable, "-m", "opentide", *argv],
        capture_output=True,
        cwd=cwd,
        env=env,
        check=False,
        timeout=180,
    )


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("ascii") / "detections"
    root.mkdir()
    done = _run(root, "--json", "setup", "--yes", "--path", str(root))
    assert done.returncode == 0, done.stderr.decode("ascii", "replace")
    return root


def _ascii(done: subprocess.CompletedProcess[bytes]) -> tuple[str, str]:
    # Every byte must be ASCII: decode strictly.
    out, err = done.stdout.decode("ascii"), done.stderr.decode("ascii")
    assert "Traceback" not in err and "error[internal]" not in err, err
    return out, err


@pytest.mark.parametrize(
    ("argv", "expect"),
    [
        (("generate",), "ok Generated"),
        ((), "Spec-driven development for agentic detection engineering"),
        (("new", "threat", "--name", "Ascii Threat"), "ok Created objects/threats/"),
        (("doctor", "--offline"), "o Not checked: --offline - opentide_latest"),
    ],
    ids=["generate", "home", "new", "doctor"],
)
def test_a_command_prints_ascii_fallbacks(
    workspace: Path, argv: tuple[str, ...], expect: str
) -> None:
    done = _run(workspace, *argv)
    out, err = _ascii(done)
    assert done.returncode == 0, out + err
    assert expect in out + err


@pytest.mark.parametrize(
    "argv",
    [("doctor", "--offline"), ("new", "rule", "--name", "Ascii Rule"), ("commands",)],
    ids=["doctor", "new", "commands"],
)
def test_json_is_ascii_and_parses(workspace: Path, argv: tuple[str, ...]) -> None:
    done = _run(workspace, "--json", *argv)
    out, err = _ascii(done)
    assert done.returncode == 0, out + err
    assert json.loads(out)["ok"] is True
