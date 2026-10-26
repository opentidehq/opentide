"""``opentide migrate vocab-scope`` file handling; test_vocab_scope covers resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.cli.services.migrate_vocab_scope import (
    SCOPED_FIELDS,
    load_scoped_vocabularies,
    run_migrate_vocab_scope,
)

_THREAT = (
    "name: Test threat\n"
    "# a comment\n"
    "metadata:\n"
    "  uuid: 3f1b8f0e-8a8b-4b8e-9a4e-1c2d3e4f5a6b\n"
    "threat:\n"
    "  surface:\n"
    "    - Windows::Desktop\n"
)


@pytest.mark.parametrize("newline", ["\r\n", "\n"], ids=["crlf", "lf"])
def test_apply_keeps_the_files_line_endings(tmp_path: Path, newline: str) -> None:
    """A file was read in text mode and written back with the platform's newline.

    A CRLF file came back LF, so every line showed as changed, although the
    migration promises the formatting survives.
    """
    path = tmp_path / "objects" / "threats" / "t.yaml"
    path.parent.mkdir(parents=True)
    path.write_bytes(_THREAT.replace("\n", newline).encode("utf-8"))

    report = run_migrate_vocab_scope(
        tmp_path, load_scoped_vocabularies(SCOPED_FIELDS), apply=True, fields=SCOPED_FIELDS
    )

    assert report["changed_files"] == ["objects/threats/t.yaml"]
    expected = _THREAT.replace("Windows::Desktop", "OS::Windows::Desktop")
    assert path.read_bytes() == expected.replace("\n", newline).encode("utf-8")


def test_a_file_that_is_not_utf8_is_reported_not_fatal(tmp_path: Path) -> None:
    threats = tmp_path / "objects" / "threats"
    threats.mkdir(parents=True)
    (threats / "latin1.yaml").write_bytes("name: Menace élevée\n".encode("latin-1"))
    (threats / "t.yaml").write_text(_THREAT, encoding="utf-8")

    report = run_migrate_vocab_scope(
        tmp_path, load_scoped_vocabularies(SCOPED_FIELDS), apply=True, fields=SCOPED_FIELDS
    )

    assert report["changed_files"] == ["objects/threats/t.yaml"]
    assert str(report["failed_files"]["objects/threats/latin1.yaml"]).startswith("unreadable:")
