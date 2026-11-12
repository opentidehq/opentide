"""The console script without its engine: the Python CLI still answers (UC-3.8b, #960).

``opentide`` and ``python -m opentide`` load the engine, ``opentide._native``,
first. Where it does not load (a damaged install, a platform whose wheel's
module fails to load), the Python CLI answers every run: the commands that
need the engine fail with ``engine_unavailable``, and the others work. Here a
``sitecustomize`` on ``PYTHONPATH`` makes the engine unimportable in the
process the console script starts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from opentide import __version__

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

    def run(launcher: str, *argv: str, cwd: Path, engine: str | None = None) -> tuple[int, str]:
        env = {
            name: value
            for name, value in os.environ.items()
            if name not in {"OPENTIDE_ENGINE", "OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE"}
        }
        env.update({"PYTHONPATH": str(hook), "NO_COLOR": "1"})
        if engine is not None:
            env["OPENTIDE_ENGINE"] = engine
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
        return result.returncode, result.stdout

    return run


@pytest.mark.parametrize("launcher", sorted(LAUNCHERS))
def test_the_python_cli_answers_when_the_engine_does_not_load(
    without_engine, tide_corpus_repo: Path, launcher: str
) -> None:
    for engine in (None, "rust"):
        code, out = without_engine(launcher, "--version", cwd=tide_corpus_repo, engine=engine)
        assert (code, out) == (0, f"opentide {__version__}\n")

    code, out = without_engine(launcher, "--json", "info", cwd=tide_corpus_repo)
    assert code == 0, out
    assert json.loads(out)["ok"] is True

    code, out = without_engine(launcher, "--json", "validate", "query", cwd=tide_corpus_repo)
    assert code == 1, out
    document = json.loads(out)
    assert document["failure"]["code"] == "engine_unavailable"
    assert "the engine does not load (test)" in document["failure"]["message"]


@pytest.mark.parametrize("launcher", sorted(LAUNCHERS))
def test_rust_without_the_engine_is_engine_unavailable(
    without_engine, tide_corpus_repo: Path, launcher: str
) -> None:
    """The Rust command line is compiled into the engine: no engine, no Rust run, no traceback."""
    code, out = without_engine(
        launcher, "--json", "explain", "vocab_unknown", cwd=tide_corpus_repo, engine="rust"
    )
    assert code == 1, out
    assert json.loads(out)["failure"]["code"] == "engine_unavailable"
