"""Verbatim document loading, including the parse failures sharing reports."""

from __future__ import annotations

from opentide.sharing.document import TideDocument, load_document


def test_properties_follow_metadata() -> None:
    document = load_document("name: Named\nmetadata:\n  uuid: abc\n  schema: rule::1.0\n")
    assert document.name == "Named"
    assert document.uuid == "abc"
    assert document.schema_id == "rule::1.0"
    assert document.family == "rule"
    assert document.content_hash
    assert document.parse_error is None


def test_missing_and_unknown_metadata_are_empty() -> None:
    document = load_document("name: 1\nmetadata: []\n")
    assert document.metadata == {}
    assert document.uuid is None
    assert document.schema_id is None
    assert document.family is None
    assert document.name is None


def test_schema_without_a_known_family_is_not_a_share_family() -> None:
    bare = load_document("metadata:\n  schema: rule\n  uuid: ''\n")
    assert bare.schema_id == "rule"
    assert bare.family is None
    assert bare.uuid is None
    unknown = load_document("metadata:\n  schema: playbook::1.0\n")
    assert unknown.family is None
    assert unknown.schema_id == "playbook::1.0"


def test_bytes_and_yaml_failures() -> None:
    broken = load_document(b"\xff")
    assert broken.parse_error == "encoding"
    assert broken.document == ""
    invalid = load_document("a: [\n")
    assert invalid.parse_error == "yaml"
    assert invalid.document.startswith("a:")
    root = load_document("- just\n- a\n- list\n", path=None)
    assert root.parse_error == "root"
    assert isinstance(root, TideDocument)
