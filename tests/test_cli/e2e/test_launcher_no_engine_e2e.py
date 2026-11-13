"""The console script without its engine (UC-3.8b, #960; UC-6.2, #841).

``opentide`` and ``python -m opentide`` run the command line compiled into the
engine, ``opentide._native``. Where it does not load (a damaged install, a
platform whose wheel's module fails to load), no command can run: the launcher
says so on stderr, with the reinstall advice, and exits 1, with no traceback.
Here a ``sitecustomize`` on ``PYTHONPATH`` makes the engine unimportable in the
process the console script starts.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.cli_smoke

_BLOCK_ENGINE = """
import sys


class _NoEngine:
    def find_spec(self, name, path=None, target=None):
        if name == "opentide._native":
            raise ImportError("the engine does not load (test)")
        return None


sys.meta_path.insert(0, _NoEngine())
"""


def _console_script() -> list[str]:
    folder = Path(sys.executable).parent
    script = folder / ("opentide.exe" if sys.platform == "win32" else "opentide")
    assert script.is_file(), f"{script}: the console script is not installed (uv sync)"
    return [str(script)]


LAUNCHERS = {
    "console-script": _console_script,
    "python-m": lambda: [sys.executable, "-m", "opentide"],
}


@pytest.fixture
def without_engine(tmp_path: Path):
    hook = tmp_path / "hook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text(_BLOCK_ENGINE, encoding="utf-8")

    def run(launcher: str, *argv: str, cwd: Path) -> tuple[int, str, str]:
        env = {
            name: value
            for name, value in os.environ.items()
            if name not in {"OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"}
        }
        env.update({"PYTHONPATH": str(hook), "NO_COLOR": "1"})
        result = subprocess.run(
            [*LAUNCHERS[launcher](), *argv],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=120,
        )
        assert "Traceback" not in result.stderr, result.stderr
        return result.returncode, result.stdout, result.stderr

    return run


@pytest.mark.parametrize("launcher", sorted(LAUNCHERS))
@pytest.mark.parametrize("argv", [["--version"], ["--json", "info"], ["--json", "validate"]])
def test_no_command_runs_without_the_engine(
    without_engine, tide_corpus_repo: Path, launcher: str, argv: list[str]
) -> None:
    code, out, err = without_engine(launcher, *argv, cwd=tide_corpus_repo)
    assert (code, out) == (1, "")
    assert err == (
        "error: The opentide analysis engine does not load: the engine does not load (test)\n"
        "  help: reinstall opentide: pip install --force-reinstall opentide\n"
    )
