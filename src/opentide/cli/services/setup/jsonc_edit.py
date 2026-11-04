"""Edit a VS Code JSONC file in place: its comments, layout and line endings survive.

``settings.json`` and ``extensions.json`` are the user's, and VS Code's own
template for ``extensions.json`` has comments. Rewriting either with
``json.dumps`` dropped every comment and turned CRLF into LF. These helpers
change only the characters of one member or one array, and the caller
re-parses the result before writing it (:func:`opentide.cli.services.setup.vscode`).
"""

from __future__ import annotations

from dataclasses import dataclass

BOM = b"\xef\xbb\xbf"


@dataclass(frozen=True)
class Member:
    """One ``"key": value`` of an object, by its offsets in the text."""

    key: str
    key_start: int
    value_start: int
    value_end: int
    #: Offset of the comma after the value, if one follows.
    comma: int | None


class JsoncError(ValueError):
    """The text is not the JSONC this module can edit."""


@dataclass
class JsoncText:
    """A file's text, and how to write it back as it was: its BOM and newline."""

    text: str
    bom: bool
    newline: str

    @classmethod
    def decode(cls, raw: bytes) -> JsoncText:
        bom = raw.startswith(BOM)
        text = raw[len(BOM) :].decode("utf-8") if bom else raw.decode("utf-8")
        newline = "\r\n" if "\r\n" in text else "\n"
        return cls(text, bom, newline)

    def encode(self) -> bytes:
        data = self.text.encode("utf-8")
        return BOM + data if self.bom else data

    @property
    def has_comments(self) -> bool:
        return mask(self.text) != self.text


def mask(text: str) -> str:
    """*text* with each comment replaced by spaces, newlines kept: same offsets, no comments."""
    out = list(text)
    index = 0
    length = len(text)
    in_string = False
    while index < length:
        char = text[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            index += 1
            continue
        if text.startswith("//", index):
            while index < length and text[index] not in "\r\n":
                out[index] = " "
                index += 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = length if end < 0 else end + 2
            for position in range(index, end):
                if text[position] not in "\r\n":
                    out[position] = " "
            index = end
            continue
        index += 1
    return "".join(out)


def _skip_space(masked: str, index: int) -> int:
    while index < len(masked) and masked[index] in " \t\r\n":
        index += 1
    return index


def _string_end(masked: str, index: int) -> int:
    """Offset after the string starting at *index* (a ``"``)."""
    index += 1
    while index < len(masked):
        char = masked[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index + 1
        index += 1
    raise JsoncError("unterminated string")


def _value_end(masked: str, index: int) -> int:
    """Offset after the value starting at *index*."""
    if index >= len(masked):
        raise JsoncError("missing value")
    char = masked[index]
    if char == '"':
        return _string_end(masked, index)
    if char in "{[":
        closing = "}" if char == "{" else "]"
        index += 1
        while True:
            index = _skip_space(masked, index)
            if index >= len(masked):
                raise JsoncError("unterminated container")
            if masked[index] == closing:
                return index + 1
            if masked[index] == ",":
                index += 1
                continue
            if char == "{":
                if masked[index] != '"':
                    raise JsoncError("object key is not a string")
                index = _skip_space(masked, _string_end(masked, index))
                if index >= len(masked) or masked[index] != ":":
                    raise JsoncError("missing ':'")
                index = _skip_space(masked, index + 1)
            index = _value_end(masked, index)
    end = index
    while end < len(masked) and masked[end] not in " \t\r\n,]}":
        end += 1
    if end == index:
        raise JsoncError(f"unexpected {char!r}")
    return end


def root_object(masked: str) -> int:
    """Offset of the ``{`` that opens the document."""
    index = _skip_space(masked, 0)
    if index >= len(masked) or masked[index] != "{":
        raise JsoncError("the document is not an object")
    return index


def members(masked: str, start: int) -> tuple[list[Member], int]:
    """The members of the object opening at *start*, and the offset of its ``}``."""
    import json

    if masked[start] != "{":
        raise JsoncError("not an object")
    found: list[Member] = []
    index = start + 1
    while True:
        index = _skip_space(masked, index)
        if index >= len(masked):
            raise JsoncError("unterminated object")
        if masked[index] == "}":
            return found, index
        if masked[index] == ",":
            index += 1
            continue
        if masked[index] != '"':
            raise JsoncError("object key is not a string")
        key_end = _string_end(masked, index)
        key = json.loads(masked[index:key_end])
        colon = _skip_space(masked, key_end)
        if colon >= len(masked) or masked[colon] != ":":
            raise JsoncError("missing ':'")
        value_start = _skip_space(masked, colon + 1)
        value_end = _value_end(masked, value_start)
        after = _skip_space(masked, value_end)
        comma = after if after < len(masked) and masked[after] == "," else None
        found.append(Member(str(key), index, value_start, value_end, comma))
        index = after if comma is None else comma + 1


def _cut(text: str, start: int, end: int) -> str:
    """*text* without ``text[start:end]``, and without the line it leaves blank.

    Spaces after the cut go with it. When the line keeps something (a comment
    written after the cut), its indent stays; when nothing is left, the whole
    line goes, its line break included.
    """
    line_start = text.rfind("\n", 0, start) + 1
    alone = not text[line_start:start].strip()
    after = end
    while after < len(text) and text[after] in " \t":
        after += 1
    if after < len(text) and text[after] not in "\r\n":
        return text[:start] + text[after:]
    if not alone:
        return text[:start] + text[after:]
    if text.startswith("\r\n", after):
        after += 2
    elif after < len(text):
        after += 1
    return text[:line_start] + text[after:]


def remove_member(text: str, object_start: int, key: str) -> str:
    """*text* without the member *key* of the object opening at *object_start*.

    Only the member and its own comma go: a comment before the next member, or
    after the previous one's comma, stays where it is.
    """
    masked = mask(text)
    found, _ = members(masked, object_start)
    for position, member in enumerate(found):
        if member.key != key:
            continue
        if member.comma is not None:
            return _cut(text, member.key_start, member.comma + 1)
        if position > 0 and found[position - 1].comma is not None:
            # The last member: the previous one's comma goes too, and nothing else
            # (a comment after that comma is the previous member's).
            previous = found[position - 1].comma
            assert previous is not None
            text = _cut(text, member.key_start, member.value_end)
            return text[:previous] + text[previous + 1 :]
        return _cut(text, member.key_start, member.value_end)
    return text


def _indent_of_first_line(text: str, start: int, end: int, fallback: str) -> str:
    """The indent of the first line between *start* and *end* that holds something."""
    for line in text[start:end].splitlines()[1:]:
        if line.strip():
            return line[: len(line) - len(line.lstrip())]
    return fallback


def replace_value(text: str, object_start: int, key: str, value: str) -> str:
    """*text* with the value of member *key* of the object at *object_start* replaced."""
    masked = mask(text)
    found, _ = members(masked, object_start)
    for member in found:
        if member.key == key:
            return text[: member.value_start] + value + text[member.value_end :]
    return text


def append_to_array(text: str, start: int, item: str, newline: str) -> str:
    """*text* with *item* (JSON text) added at the end of the array opening at *start*.

    Comments stay: in an array that holds only comments the item goes first, and
    on a line that ends in a comment after the last item, the item goes on the
    next line, so the comment stays beside the item it was written for.
    """
    masked = mask(text)
    end = _value_end(masked, start) - 1  # the ]
    last = end - 1
    while last > start and masked[last] in " \t\r\n":
        last -= 1
    if last == start:
        inner = text[start + 1 : end]
        if not inner.strip():
            return text[: start + 1] + item + text[end:]
        # Only comments (a commented-out id): the item goes before them.
        if "\n" not in inner:
            return text[: start + 1] + item + " " + inner.lstrip() + text[end:]
        indent = _indent_of_first_line(text, start, end, "  ")
        return text[: start + 1] + newline + indent + item + text[start + 1 :]
    first = _skip_space(masked, start + 1)
    multiline = "\n" in text[start:first]
    if multiline:
        line_start = text.rfind("\n", 0, first) + 1
        prefix = text[line_start:first]
        # The indent alone: a block comment before the first item is that item's.
        separator = newline + prefix[: len(prefix) - len(prefix.lstrip(" \t"))]
    else:
        separator = " "
    lead = "" if masked[last] == "," else ","
    insert_at = last + 1
    text = text[:insert_at] + lead + text[insert_at:]
    masked = masked[:insert_at] + lead + masked[insert_at:]
    insert_at += len(lead)
    if multiline:
        line_end = insert_at
        while line_end < len(text) and text[line_end] not in "\r\n":
            line_end += 1
        if not masked[insert_at:line_end].strip():
            # Past a comment that ends the last item's line.
            insert_at = line_end
    return text[:insert_at] + separator + item + text[insert_at:]


def add_member(text: str, object_start: int, key: str, value: str, newline: str) -> str:
    """*text* with ``"key": value`` added as the first member of the object at *object_start*."""
    import json

    masked = mask(text)
    found, close = members(masked, object_start)
    member = f"{json.dumps(key)}: {value}"
    if not found:
        inner = text[object_start + 1 : close]
        if not inner.strip():
            return text[: object_start + 1] + newline + "  " + member + newline + text[close:]
        # Only comments: the member goes first, and they stay.
        indent = _indent_of_first_line(text, object_start, close, "  ")
        if "\n" not in inner:
            return text[: object_start + 1] + " " + member + inner + text[close:]
        return text[: object_start + 1] + newline + indent + member + text[object_start + 1 :]
    first = found[0].key_start
    line_start = text.rfind("\n", 0, first) + 1
    indent = text[line_start:first] if not text[line_start:first].strip() else ""
    if "\n" in text[object_start:first]:
        return text[:first] + member + "," + newline + indent + text[first:]
    return text[:first] + member + ", " + text[first:]
