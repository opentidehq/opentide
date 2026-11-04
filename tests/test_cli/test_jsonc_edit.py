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


def _comments(text: str) -> list[str]:
    """Every comment in *text*, as written, in order."""
    masked = mask(text)
    found: list[str] = []
    index = 0
    while index < len(text):
        if text[index] != masked[index] and text.startswith(("//", "/*"), index):
            end = index
            while end < len(text) and (text[end] != masked[end] or text[end] in "\r\n"):
                if text[end] in "\r\n" and text.startswith("//", index):
                    break
                end += 1
            found.append(text[index:end].strip())
            index = end
            continue
        index += 1
    return found


ROUTER_ENTRY = '".opentide/schemas/opentide.schema.json": "objects/**/*.yaml"'

SETTINGS_CASES = {
    "a comment before the next member": (
        '{\n    "yaml.schemas": {\n        ' + ROUTER_ENTRY + "\n    },\n\n"
        '    // Python settings\n    "python.defaultInterpreterPath": ".venv/bin/python"\n}\n',
        {"python.defaultInterpreterPath": ".venv/bin/python"},
    ),
    "a trailing comment on the previous member": (
        '{\n    "editor.tabSize": 2, // two spaces, team rule\n    "yaml.schemas": {\n'
        "        " + ROUTER_ENTRY + "\n    }\n}\n",
        {"editor.tabSize": 2},
    ),
    "a trailing comma and a comment after it": (
        '{\n    "a": 1,\n    "yaml.schemas": {\n        ' + ROUTER_ENTRY + "\n    }, // end\n}\n",
        {"a": 1},
    ),
    "a schema entry between commented ones": (
        '{\n  "yaml.schemas": {\n    "x.json": "x/*.yaml", // x\n    ' + ROUTER_ENTRY + ",\n"
        '    // y next\n    "y.json": "y/*.yaml"\n  }\n}\n',
        {"yaml.schemas": {"x.json": "x/*.yaml", "y.json": "y/*.yaml"}},
    ),
}


@pytest.mark.parametrize("case", sorted(SETTINGS_CASES))
def test_removing_a_mapping_keeps_every_comment_around_it(tmp_path, case: str) -> None:
    from opentide.cli.services.setup.vscode import write_vscode_settings

    text, expected = SETTINGS_CASES[case]
    (tmp_path / ".vscode").mkdir()
    path = tmp_path / ".vscode" / "settings.json"
    path.write_text(text, encoding="utf-8")
    warnings: list[str] = []
    assert write_vscode_settings(tmp_path, warnings=warnings) == ".vscode/settings.json"
    assert warnings == []
    edited = path.read_text(encoding="utf-8")
    assert json.loads(_strip_jsonc(edited)) == expected
    assert _comments(edited) == _comments(text), edited


EXTENSIONS_CASES = {
    "an object holding only a comment": "{\n  // TODO add recommendations\n}\n",
    "an empty array of commented-out ids": (
        '{\n  "recommendations": [\n    // "redhat.vscode-yaml"\n  ]\n}\n'
    ),
    "a block comment before the first id": (
        '{\n  "recommendations": [\n    /* core */ "ms-python.python"\n  ]\n}\n'
    ),
    "a trailing comment on the last id": (
        '{\n  "recommendations": [\n    "ms-python.python" // python\n  ]\n}\n'
    ),
    "a commented-out id after the last": (
        '{\n  "recommendations": [\n    "ms-python.python",\n    // "redhat.vscode-yaml"\n  ]\n}\n'
    ),
}


@pytest.mark.parametrize("case", sorted(EXTENSIONS_CASES))
def test_adding_the_recommendation_keeps_every_comment(tmp_path, case: str) -> None:
    from opentide.cli.services.setup.vscode import write_vscode_extensions

    text = EXTENSIONS_CASES[case]
    (tmp_path / ".vscode").mkdir()
    path = tmp_path / ".vscode" / "extensions.json"
    path.write_text(text, encoding="utf-8")
    warnings: list[str] = []
    assert write_vscode_extensions(tmp_path, warnings=warnings) == ".vscode/extensions.json"
    assert warnings == []
    edited = path.read_text(encoding="utf-8")
    before = json.loads(_strip_jsonc(text)).get("recommendations", [])
    after = json.loads(_strip_jsonc(edited))["recommendations"]
    assert after == [*before, "opentidehq.opentide"]
    assert _comments(edited) == _comments(text), edited
    if "python" in text:
        # A trailing comment stays on the id it was written beside.
        python_line = next(line for line in edited.splitlines() if "ms-python.python" in line)
        assert ("// python" in python_line) == ("// python" in text)
