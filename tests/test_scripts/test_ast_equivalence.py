"""Tests for scripts/ast_equivalence.py, the behaviour-preservation check for refactors."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

_MODULE = Path(__file__).resolve().parents[2] / "scripts" / "ast_equivalence.py"
_spec = importlib.util.spec_from_file_location("ast_equivalence", _MODULE)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

BEFORE = """\
from typing import Optional
import os


def greet(name: Optional[str] = None) -> str:
    message = "Hello, " + (name or "world") + "! This greeting is long enough to wrap."
    return message
"""

# Reformatted, imports re-sorted, annotation modernised, string split: equivalent.
MECHANICAL = """\
import os


def greet(name: str | None = None) -> str:
    message = (
        "Hello, "
        + (name or "world")
        + "! This greeting is long "
        "enough to wrap."
    )
    return message
"""

# One character of logic changed.
SEMANTIC = BEFORE.replace('"world"', '"World"')


def test_mechanical_changes_are_equivalent() -> None:
    assert _mod.normalised_dump(BEFORE) == _mod.normalised_dump(MECHANICAL)


def test_a_logic_change_is_reported() -> None:
    assert _mod.normalised_dump(BEFORE) != _mod.normalised_dump(SEMANTIC)


def test_a_string_turned_into_a_call_is_reported() -> None:
    """Wrapping the tail of an implicit concatenation in parentheses calls the string."""
    split = 'x = ("a "\n     "b")\n'
    broken = 'x = ("a "(\n     "b"))\n'
    assert _mod.normalised_dump(split) != _mod.normalised_dump(broken)


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test")
    (tmp_path / "mod.py").write_text(BEFORE, encoding="utf-8")
    (tmp_path / "other.py").write_text("VALUE = 1\n", encoding="utf-8")
    git("add", ".")
    git("commit", "-q", "-m", "base")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_main_lists_only_files_whose_logic_changed(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "mod.py").write_text(MECHANICAL, encoding="utf-8")
    assert _mod.main(["HEAD"]) == 0

    (repo / "other.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert _mod.main(["HEAD"]) == 1
    assert capsys.readouterr().out.splitlines() == ["other.py: 2 AST line(s) differ"]
