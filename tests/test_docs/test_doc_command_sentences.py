"""Backtick commands in the docs must be invocations that exist (#354)."""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def _text(relative: str) -> str:
    return (_ROOT / relative).read_text(encoding="utf-8")


def test_ci_cd_rerun_names_a_provider() -> None:
    text = _text("docs/usage/workflows/ci-cd.md")
    assert "Re-run `opentide setup ci github --yes`" in text
    assert "Re-run `opentide setup ci`" not in text


def test_migration_table_names_a_provider() -> None:
    text = _text("docs/usage/migration/index.md")
    assert "| (CI pipeline files) | `opentide setup ci github` |" in text
    assert "| (CI pipeline files) | `opentide setup ci` |" not in text


def test_generate_extract_names_a_platform() -> None:
    text = _text("docs/cli/generate.md")
    assert "`opentide generate extract sentinel`" in text
    assert "`opentide generate extract defender`" in text
    assert "Use `opentide generate extract` explicitly" not in text


def test_releases_puts_json_before_validate() -> None:
    text = _text("docs/usage/releases.md")
    assert "`opentide --json validate`" in text
    assert "`validate --json`" not in text
