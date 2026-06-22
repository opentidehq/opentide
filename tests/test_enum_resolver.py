"""Unit tests for EnumResolver bug fixes (Phase 3).

Behavioral coverage of vocabulary resolution lives in ``test_vocabulary.py``.
These tests assert the Phase 3 code fixes remain present without importing the
full Engines stack (which requires repository indexing and optional deps).
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_field_types_string_normalisation_uses_isinstance() -> None:
    source = (ROOT / "Engines/framework/json_schemas.py").read_text()
    assert "type(field_types) is str()" not in source
    assert "isinstance(field_types, str)" in source


def test_finalise_no_self_extend_bug() -> None:
    source = (ROOT / "Engines/framework/json_schemas.py").read_text()
    assert "enum_description.extend(self.enum_description)" not in source
    assert "_hint_descriptions" in source


def test_finalise_builds_hint_descriptions_separately() -> None:
    source = (ROOT / "Engines/framework/json_schemas.py").read_text()
    assert "self._hint_descriptions" in source
    assert "enum_description.extend(self._hint_descriptions)" in source
