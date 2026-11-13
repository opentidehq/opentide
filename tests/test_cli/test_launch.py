"""The console script, ``opentide._cli.main`` (UC-6.2, #841).

It hands its arguments to the Rust command line compiled into the package
(``opentide._native.cli_main``) with the package's version, in this process,
and returns its exit code; when the engine does not load it says so and exits
1. ``python -m opentide`` is the same function.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest

import opentide
from opentide import _cli


class _Native(SimpleNamespace):
    def __init__(self, code: int = 0) -> None:
        super().__init__(calls=[])
        self.code = code

    def cli_main(self, argv: list[str], version: str) -> int:
        self.calls.append((argv, version))
        return self.code


def _with_native(monkeypatch: pytest.MonkeyPatch, native: object) -> None:
    real = importlib.import_module

    def import_module(name: str, package: str | None = None) -> ModuleType:
        if name == "opentide._native":
            if isinstance(native, BaseException):
                raise native
            return native  # ty: ignore[invalid-return-type]  # a stand-in module
        return real(name, package)

    monkeypatch.setattr(importlib, "import_module", import_module)


def test_the_arguments_and_the_version_reach_the_rust_command_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _Native(code=3)
    _with_native(monkeypatch, native)
    assert _cli.main(["--json", "validate"]) == 3
    assert native.calls == [(["--json", "validate"], opentide.__version__)]


def test_without_arguments_it_reads_sys_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    native = _Native()
    _with_native(monkeypatch, native)
    monkeypatch.setattr(sys, "argv", ["opentide", "info", "--json"])
    assert _cli.main() == 0
    assert native.calls == [(["info", "--json"], opentide.__version__)]


def test_an_engine_that_does_not_load_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with_native(monkeypatch, ImportError("cannot load it (test)"))
    assert _cli.main(["--version"]) == _cli.ENGINE_UNAVAILABLE_EXIT == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "error: The opentide analysis engine does not load: cannot load it (test)\n"
        "  help: reinstall opentide: pip install --force-reinstall opentide\n"
    )


def test_python_m_opentide_is_the_console_script() -> None:
    done = subprocess.run(
        [sys.executable, "-m", "opentide", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    assert done.stdout == f"opentide {opentide.__version__}\n"
