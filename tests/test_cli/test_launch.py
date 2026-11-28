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
        super().__init__(calls=[], __version__="9.9.9.dev1")
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
    assert native.calls == [(["--json", "validate"], "9.9.9.dev1")]


def test_without_arguments_it_reads_sys_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    native = _Native()
    _with_native(monkeypatch, native)
    monkeypatch.setattr(sys, "argv", ["opentide", "info", "--json"])
    assert _cli.main() == 0
    assert native.calls == [(["info", "--json"], "9.9.9.dev1")]


def test_the_version_answers_from_the_metadata_without_the_engine(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--version`` checks nothing (#1072): a broken engine is reported by the
    first command, not by it."""
    import opentide

    _with_native(monkeypatch, ImportError("cannot load it (test)"))
    for flag in ("--version", "-V"):
        assert _cli.main([flag]) == 0
        captured = capsys.readouterr()
        assert (captured.out, captured.err) == (f"opentide {opentide.__version__}\n", "")


def test_the_version_without_the_engine_or_metadata_is_the_engines_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With no metadata to read either, ``--version`` reports the engine."""
    import importlib.metadata

    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    _with_native(monkeypatch, ImportError("cannot load it (test)"))
    monkeypatch.setattr(importlib.metadata, "version", missing)
    assert _cli.main(["--version"]) == _cli.ENGINE_UNAVAILABLE_EXIT
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: The opentide analysis engine does not load")


def test_an_engine_that_does_not_load_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _with_native(monkeypatch, ImportError("cannot load it (test)"))
    assert _cli.main(["info"]) == _cli.ENGINE_UNAVAILABLE_EXIT == 1
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


def test_the_engine_carries_the_version_the_package_metadata_does() -> None:
    """The console script passes ``_native.__version__`` (compiled from the
    Cargo version) where ``opentide.__version__`` reads the metadata maturin
    wrote from the same version: both spell it alike (PEP 440)."""
    from importlib.metadata import version

    native = importlib.import_module("opentide._native")
    assert native.__version__ == version("opentide") == opentide.__version__
