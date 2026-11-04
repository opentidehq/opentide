"""In-place JSONC edits for ``.vscode`` files: only the named member or array changes."""

from __future__ import annotations

import json

import pytest

from opentide.cli.services.setup.jsonc_edit import (
    JsoncError,
    JsoncText,
    add_member,
    append_to_array,
    mask,
    members,
    remove_member,
    replace_value,
    root_object,
)
from opentide.cli.services.setup.vscode import _strip_jsonc

NESTED = '{\n  "yaml.schemas": {\n    "a": 1,\n    "b": 2,\n    "c": 3\n  },\n  "x": 1\n}\n'


def _schemas(text: str) -> int:
    return members(mask(text), root_object(mask(text)))[0][0].value_start


def test_mask_blanks_comments_and_keeps_offsets_and_strings() -> None:
    text = '{"u": "http://x", /* c */ "v": 1 // d\n}'
    masked = mask(text)
    assert len(masked) == len(text)
    assert "http://x" in masked
    assert "/*" not in masked and "//" not in masked.replace("http://x", "")
    assert JsoncText(text, False, "\n").has_comments


@pytest.mark.parametrize(
    ("key", "expected"),
    [
        ("a", {"b": 2, "c": 3}),
        ("b", {"a": 1, "c": 3}),
        ("c", {"a": 1, "b": 2}),
    ],
)
def test_remove_member_keeps_the_others(key: str, expected: dict[str, int]) -> None:
    edited = remove_member(NESTED, _schemas(NESTED), key)
    assert json.loads(edited) == {"yaml.schemas": expected, "x": 1}


def test_remove_member_with_a_trailing_comma_and_the_only_member() -> None:
    assert json.loads(_strip_jsonc(remove_member('{"a": 1, "b": 2,}', 0, "b"))) == {"a": 1}
    assert remove_member('{\n  "a": 1\n}\n', 0, "a") == "{\n}\n"
    assert remove_member('{"a": 1}', 0, "missing") == '{"a": 1}'


def test_replace_value_and_add_member() -> None:
    text = '{"a": [1, 2], "b": 3}'
    assert json.loads(replace_value(text, 0, "a", "[1]")) == {"a": [1], "b": 3}
    assert json.loads(add_member("{}", 0, "r", '["x"]', "\n")) == {"r": ["x"]}
    assert json.loads(add_member('{"b": 1}', 0, "r", "[]", "\n")) == {"r": [], "b": 1}


def test_append_to_array_follows_the_layout() -> None:
    assert append_to_array('{"r": []}', 6, '"x"', "\n") == '{"r": ["x"]}'
    assert append_to_array('{"r": ["a",]}', 6, '"x"', "\n") == '{"r": ["a", "x"]}'
    multiline = '{"r": [\r\n    "a"\r\n]}'
    assert append_to_array(multiline, 6, '"x"', "\r\n") == '{"r": [\r\n    "a",\r\n    "x"\r\n]}'


@pytest.mark.parametrize("text", ["[]", '{"a" 1}', '{"a": ', '{"a": "x'])
def test_text_that_is_not_an_object_is_refused(text: str) -> None:
    with pytest.raises(JsoncError):
        members(mask(text), root_object(mask(text)))


def test_decode_and_encode_keep_the_bom_and_newline() -> None:
    raw = b"\xef\xbb\xbf{\r\n}\r\n"
    source = JsoncText.decode(raw)
    assert source.bom and source.newline == "\r\n"
    assert source.encode() == raw
