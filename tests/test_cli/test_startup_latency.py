"""CLI startup must not build the detection registry until a command needs it."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_IMPORT_SCRIPT = """
from opentide.core.registry import OpenTide
from opentide.cli import app

assert OpenTide.is_initialised is False, "CLI import must not initialise the registry"
assert app is not None
print("IMPORT_OK")
"""

_HELP_SCRIPT = """
import sys
from opentide.core.registry import OpenTide
from opentide.cli import app

assert OpenTide.is_initialised is False
result = app(sys.argv[1:], standalone_mode=False)
assert OpenTide.is_initialised is False, "CLI help must not initialise the registry"
raise SystemExit(result or 0)
"""


def test_cli_import_does_not_initialise_registry() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _IMPORT_SCRIPT],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr
    assert "IMPORT_OK" in result.stdout


def test_cli_help_does_not_initialise_registry() -> None:
    result = subprocess.run(
        [sys.executable, "-c", _HELP_SCRIPT, "--help"],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ},
    )
    assert result.returncode == 0, result.stderr
    assert "validate" in result.stdout


def test_console_script_help_works_without_workspace(tmp_path: Path) -> None:
    """``opentide --help`` must work without a configured workspace."""
    empty = tmp_path / "empty"
    empty.mkdir()
    result = subprocess.run(
        [sys.executable, "-c", "from opentide.cli import main; raise SystemExit(main())", "--help"],
        capture_output=True,
        check=False,
        text=True,
        env={**os.environ, "OPENTIDE_TIDE_WORKSPACE": str(empty)},
    )
    assert result.returncode == 0, result.stderr
    assert "DetectionOps" in result.stdout or "validate" in result.stdout
