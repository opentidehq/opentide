"""Tests for leftover template file helpers."""

from __future__ import annotations

from pathlib import Path

from opentide.generation.template_engine import (
    indent_template,
    remove_blanks,
    replace_strings_in_file,
)


def test_replace_strings_in_file(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("key: blank\nother: Comment out\n", encoding="utf-8")
    replace_strings_in_file(path, ["blank"], "filled")
    content = path.read_text(encoding="utf-8")
    assert "filled" in content
    assert "blank" not in content


def test_remove_blanks(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("key: value\n\n\nother: x\n", encoding="utf-8")
    remove_blanks(path)
    assert path.read_text(encoding="utf-8") == "key: value\nother: x\n"


def test_indent_template(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("key: value\n", encoding="utf-8")
    indent_template(path, 4)
    assert path.read_text(encoding="utf-8").startswith("    key:")
