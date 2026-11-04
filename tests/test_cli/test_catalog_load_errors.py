"""``info catalog``: what a row for a file that did not load reads from its text (#749)."""

from __future__ import annotations

from pathlib import Path

from opentide.cli.services.catalog import _load_error_row

ROOT_UUID = "00000000-0000-4000-8003-0000000000aa"
META_UUID = "00000000-0000-4000-8002-0000000000bb"
SIGNAL_UUID = "00000000-0000-4000-8099-0000000000cc"


def _row(tmp_path: Path, text: str) -> dict[str, object]:
    path = tmp_path / "broken.yaml"
    path.write_text(text, encoding="utf-8")
    return _load_error_row({"path": str(path), "object_type": "rule"}, tmp_path)


def test_a_root_uuid_and_a_quoted_name_with_an_apostrophe(tmp_path: Path) -> None:
    row = _row(
        tmp_path,
        f'name: "O\'Brien rule"  # who wrote it\nuuid: {ROOT_UUID}\nschema: rule::1.0\n'
        "techniques: [T1059\n",
    )
    assert row["uuid"] == ROOT_UUID
    assert row["name"] == "O'Brien rule"
    assert row["schema"] == "rule::1.0"


def test_single_quoted_and_plain_names(tmp_path: Path) -> None:
    assert _row(tmp_path, "name: 'It''s here'\n[\n")["name"] == "It's here"
    assert _row(tmp_path, "name: Plain # comment\n[\n")["name"] == "Plain"
    assert _row(tmp_path, "name: C#-style rule\n[\n")["name"] == "C#-style rule"


def test_signals_before_metadata_do_not_lend_their_uuid(tmp_path: Path) -> None:
    row = _row(
        tmp_path,
        "name: Objective\n"
        "objective:\n"
        "  signals:\n"
        f"    - uuid: {SIGNAL_UUID}\n"
        "      name: first\n"
        "  nested:\n"
        f"    uuid: {SIGNAL_UUID}\n"
        "metadata:\n"
        f"  uuid: '{META_UUID}'\n"
        "  schema: objective::1.0\n"
        "broken: [\n",
    )
    assert row["uuid"] == META_UUID
    assert row["schema"] == "objective::1.0"


def test_no_uuid_reads_as_null(tmp_path: Path) -> None:
    row = _row(tmp_path, "name: Nothing\nmetadata:\n  tlp: clear\n[\n")
    assert row["uuid"] is None
    assert row["name"] == "Nothing"


def test_a_comment_after_metadata_still_opens_the_block(tmp_path: Path) -> None:
    """``metadata:  # comment`` read the comment as the key's value, so the block was not
    metadata and the row lost its uuid and schema."""
    row = _row(
        tmp_path,
        "name: Commented  # x\n"
        "metadata:  # identity\n"
        f"  uuid: {META_UUID}\n"
        "  schema: rule::1.0  # revision\n"
        "broken: [\n",
    )
    assert row["uuid"] == META_UUID
    assert row["schema"] == "rule::1.0"
    assert _row(tmp_path, "name: # no name yet\n[\n")["name"] == "broken"
