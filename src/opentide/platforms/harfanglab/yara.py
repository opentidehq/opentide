"""The YARA checks of harfanglab-1.0 1.2 and yara-1.0 that need no YARA parser.

``configurations.harfanglab.yara`` is a whole YARA text (``signature``) or the
decomposed ``meta``/``strings``/``condition``/``imports`` that deploy assembles
into one rule. This module holds what the model, ``opentide validate``,
``opentide lint`` and the deployer share: the constraint codes on the block, the
YARA codes on a signature that a scan of its text decides (``yara_include``,
``yara_empty_signature``, ``yara_duplicate_rule``), the rule name deploy derives,
the signature as deploy sends it, and the ``harfanglab_yara_context`` and
``yara_meta_missing`` advisories. A signature is scanned with its comments and
string literals blanked out, so a ``rule`` or ``include`` inside either is not
read as one.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

#: The modules the YARA language knows (yara-1.0, Modules).
YARA_MODULES = frozenset(
    {
        "pe",
        "elf",
        "math",
        "hash",
        "time",
        "dotnet",
        "macho",
        "magic",
        "cuckoo",
        "console",
        "string",
        "lnk",
        "dex",
    }
)

#: libyara 4.5's reserved words: none of them can name a rule.
YARA_KEYWORDS = frozenset(
    {
        "all",
        "and",
        "any",
        "ascii",
        "at",
        "base64",
        "base64wide",
        "condition",
        "contains",
        "defined",
        "endswith",
        "entrypoint",
        "false",
        "filesize",
        "for",
        "fullword",
        "global",
        "icontains",
        "iendswith",
        "iequals",
        "import",
        "in",
        "include",
        "int16",
        "int16be",
        "int32",
        "int32be",
        "int8",
        "int8be",
        "istartswith",
        "matches",
        "meta",
        "nocase",
        "none",
        "not",
        "of",
        "or",
        "private",
        "rule",
        "startswith",
        "strings",
        "them",
        "true",
        "uint16",
        "uint16be",
        "uint32",
        "uint32be",
        "uint8",
        "uint8be",
        "wide",
        "xor",
    }
)

#: The meta ``context`` values the HarfangLab profile expects (harfanglab-1.0, YARA profile).
#: The scan contexts a HarfangLab meta ``context`` joins with commas, without blanks
#: (harfanglab-1.0 1.3, YARA profile): ``file,memory`` and ``file.pe,memory`` are lists.
HARFANGLAB_CONTEXTS = frozenset({"file", "memory", "file.pe", "file.elf", "file.macho"})
_CONTEXTS_TEXT = "a comma-joined list of " + ", ".join(sorted(HARFANGLAB_CONTEXTS))

#: The ``context`` deploy writes for ``file`` in the decomposed form, by ``meta.os``
#: (the deployer's ``OS_TO_FILE_CONTEXT``).
OS_FILE_CONTEXT = {"Windows": "file.pe", "MacOS": "file.macho", "Linux": "file.elf"}

#: libyara's longest identifier (yara-1.0 1.1, Dialect).
MAX_IDENTIFIER = 128

#: The decomposed form's keys; a ``yara`` object with ``signature`` sets none of them.
DECOMPOSED_KEYS = ("meta", "strings", "condition", "imports")

#: The advisories ``opentide lint`` reports on a signature (warnings, never a failure).
ADVISORY_CODES = frozenset({"harfanglab_yara_context", "yara_meta_missing"})

_SECTION_HEADER = re.compile(
    r"^\s*(?:strings\s*:|condition\s*:|(?:(?:private|global)\s+)*rule\s+[A-Za-z_])",
    re.MULTILINE,
)
_INCLUDE = re.compile(r"(?<![\w$#@!])include\s*\"")
_RULE = re.compile(r"(?<![\w$#@!])((?:(?:private|global)\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)")
_META = re.compile(r"(?<![\w$#@!])meta\s*:")
_SECTION_AFTER_META = re.compile(r"(?<![\w$#@!])(?:strings|condition)\s*:")
_CONTEXT = re.compile(r"(?<![\w$#@!])context\s*=\s*")
_ASCII_NAME = re.compile(r"[A-Za-z0-9_]+")


def _blank(text: str) -> str:
    """*text* with comments and the insides of string and regexp literals turned into spaces.

    Offsets and line breaks are kept, so a position in the result is the same
    position in *text*. The quotes of a string and the slashes of a regexp
    stay, so ``include "x"`` still reads as an include.

    It tokenises as libyara's lexer does: outside a string or a comment, every
    ``/`` that does not start ``//`` or ``/*`` opens a regexp (YARA divides
    with ``\\``, never ``/``), wherever it stands: a string's value, the right
    of ``matches``, a module function's argument. The regexp ends at the next
    ``/`` that ``\\`` does not escape; its modifiers are letters and stay.
    """
    out = list(text)
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if char == "/" and not text.startswith(("//", "/*"), index):
            end = index + 1
            while end < size and text[end] not in "/\n":
                end += 2 if text[end] == "\\" else 1
            end = min(end, size)
            out[index + 1 : end] = " " * (end - index - 1)
            index = end + 1
        elif char == "/" and text.startswith("//", index):
            end = text.find("\n", index)
            end = size if end < 0 else end
            out[index:end] = " " * (end - index)
            index = end
        elif char == "/" and text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = size if end < 0 else end + 2
            out[index:end] = [c if c == "\n" else " " for c in text[index:end]]
            index = end
        elif char == '"':
            end = index + 1
            while end < size and text[end] not in '"\n':
                end += 2 if text[end] == "\\" else 1
            end = min(end, size)
            out[index + 1 : end] = " " * (end - index - 1)
            index = end + 1
        else:
            index += 1
    return "".join(out)


@dataclass(frozen=True)
class YaraRuleHeader:
    """One ``rule`` of a signature: its name, modifiers and where its text runs."""

    name: str
    private: bool
    global_: bool
    start: int
    end: int


def rule_headers(signature: str) -> list[YaraRuleHeader]:
    """Each rule a signature declares, in order, with the span of its text."""
    code = _blank(signature)
    matches = list(_RULE.finditer(code))
    headers: list[YaraRuleHeader] = []
    for index, match in enumerate(matches):
        modifiers = match.group(1).split()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(signature)
        headers.append(
            YaraRuleHeader(
                name=match.group(2),
                private="private" in modifiers,
                global_="global" in modifiers,
                start=match.start(),
                end=end,
            )
        )
    return headers


def signature_codes(signature: object) -> set[str]:
    """The yara-1.0 error codes a scan of *signature* decides."""
    if not isinstance(signature, str) or not signature.strip():
        return {"yara_empty_signature"}
    codes: set[str] = set()
    if _INCLUDE.search(_blank(signature)):
        codes.add("yara_include")
    headers = rule_headers(signature)
    if not any(not (header.private or header.global_) for header in headers):
        codes.add("yara_empty_signature")
    names = [header.name for header in headers]
    if len(names) != len(set(names)):
        codes.add("yara_duplicate_rule")
    return codes


def derived_rule_name(name: str) -> str:
    """The YARA rule name deploy derives from the Tide rule ``name`` (decomposed form)."""
    derived = name.lower().replace(" ", "_").replace("-", "_")
    derived = "".join(c if c.isalnum() or c == "_" else "_" for c in derived)
    if derived and derived[0].isdigit():
        derived = f"rule_{derived}"
    return derived


def rule_name_problem(name: str) -> str | None:
    """Why libyara refuses the rule name deploy derives from *name*, or ``None``.

    A keyword, a character other than ASCII letters, digits and ``_``, or more
    than 128 characters (``harfanglab_yara_rule_name``, harfanglab-1.0 1.3).
    """
    derived = derived_rule_name(name)
    if derived in YARA_KEYWORDS:
        return f"the YARA rule name {derived!r} derived from it is a YARA keyword"
    if not _ASCII_NAME.fullmatch(derived):
        others = sorted({c for c in derived if not _ASCII_NAME.fullmatch(c)})
        shown = ", ".join(repr(c) for c in others) or "none"
        return (
            f"the YARA rule name {derived!r} derived from it keeps {shown}; libyara takes only "
            "ASCII letters, digits and _"
        )
    if len(derived) > MAX_IDENTIFIER:
        return (
            f"the YARA rule name derived from it is {len(derived)} characters long; libyara "
            f"takes at most {MAX_IDENTIFIER}"
        )
    return None


def rule_name_refused(name: str) -> bool:
    """Whether libyara refuses the rule name deploy derives (``harfanglab_yara_rule_name``)."""
    return rule_name_problem(name) is not None


def context_accepted(value: str) -> bool:
    """Whether *value* is a comma-joined list, without blanks, of HarfangLab scan contexts."""
    return all(part in HARFANGLAB_CONTEXTS for part in value.split(","))


def decomposed_context(contexts: list[str], os: str) -> str:
    """The meta ``context`` the decomposed form deploys: ``file`` rewritten from ``os``."""
    return ",".join(
        OS_FILE_CONTEXT[os] if context == "file" and os in OS_FILE_CONTEXT else context
        for context in contexts
    )


def deployed_signature(signature: str) -> str:
    """*signature* as deploy sends it: ``\\n`` line endings, and a trailing newline if it has none.

    yara-1.0 allows nothing else: blank lines, at the end or anywhere, are sent as written.
    """
    text = signature.replace("\r\n", "\n").replace("\r", "\n")
    return text if text.endswith("\n") else text + "\n"


def _set(value: object) -> bool:
    return value is not None


def block_codes(block: Mapping[str, Any]) -> set[str]:
    """The constraint and YARA codes a raw ``configurations.harfanglab`` mapping breaks.

    ``harfanglab_yara_rule_name`` needs the Tide rule ``name`` and is the rule's
    check (:func:`rule_name_refused`); ``yara_signature_alias`` needs the YAML
    node graph and is ``opentide validate``'s.
    """
    codes: set[str] = set()
    yara = block.get("yara")
    if _set(block.get("sigma")) and _set(yara):
        codes.add("harfanglab_rule_kind")
    if not isinstance(yara, Mapping):
        return codes
    # A key written in the block chooses its form, even with an empty value:
    # `signature` with `imports: null` is still both forms (harfanglab_yara_form).
    if "signature" in yara:
        if any(key in yara for key in DECOMPOSED_KEYS):
            codes.add("harfanglab_yara_form")
        codes |= signature_codes(yara["signature"])
        return codes
    for key in ("strings", "condition"):
        body = yara.get(key)
        if isinstance(body, str) and _SECTION_HEADER.search(body):
            codes.add("harfanglab_yara_section_header")
    imports = yara.get("imports")
    if isinstance(imports, list) and any(
        not isinstance(module, str) or module not in YARA_MODULES for module in imports
    ):
        codes.add("harfanglab_yara_import")
    return codes


@dataclass(frozen=True)
class YaraAdvisory:
    """A HarfangLab profile warning on a signature, at an offset into it."""

    code: str
    message: str
    offset: int
    #: The YARA rule it is about.
    rule: str = ""


def _meta_span(code: str, header: YaraRuleHeader) -> tuple[int, int] | None:
    meta = _META.search(code, header.start, header.end)
    if meta is None:
        return None
    after = _SECTION_AFTER_META.search(code, meta.end(), header.end)
    return meta.end(), after.start() if after else header.end


def _context_value(
    signature: str, code: str, span: tuple[int, int]
) -> tuple[str | None, str, int] | None:
    """``(string value or None, the value as written, offset of the key)`` of meta ``context``.

    A value that is not a string (``context = 1``, ``context = true``) is ``None``.
    """
    found = _CONTEXT.search(code, *span)
    if found is None:
        return None
    start = found.end()
    if start < len(signature) and signature[start] == '"':
        end = start + 1
        while end < len(signature) and signature[end] not in '"\n':
            end += 2 if signature[end] == "\\" else 1
        return signature[start + 1 : end], signature[start : end + 1], found.start()
    line_end = signature.find("\n", start)
    written = signature[start : len(signature) if line_end < 0 else line_end].strip()
    return None, written, found.start()


def advisories(signature: str) -> Iterator[YaraAdvisory]:
    """``yara_meta_missing`` and ``harfanglab_yara_context`` for each non-private rule."""
    code = _blank(signature)
    for header in rule_headers(signature):
        if header.private:
            continue
        span = _meta_span(code, header)
        found = _context_value(signature, code, span) if span else None
        if found is None:
            yield YaraAdvisory(
                "yara_meta_missing",
                f"YARA rule {header.name!r} has no meta context; HarfangLab expects one",
                header.start,
                header.name,
            )
            continue
        value, written, offset = found
        if value is None:
            yield YaraAdvisory(
                "harfanglab_yara_context",
                f"YARA rule {header.name!r} sets meta context to {written}, not a string; "
                f"HarfangLab expects {_CONTEXTS_TEXT}",
                offset,
                header.name,
            )
        elif not context_accepted(value):
            yield YaraAdvisory(
                "harfanglab_yara_context",
                f"YARA rule {header.name!r} sets meta context {value!r}; "
                f"HarfangLab expects {_CONTEXTS_TEXT}",
                offset,
                header.name,
            )


def decomposed_advisory(contexts: object, os: object) -> tuple[str, str] | None:
    """``(code, message)`` for the ``context`` the decomposed form deploys, or ``None``.

    The advisory applies to the decomposed form on the value deploy writes
    (harfanglab-1.0 1.3); deploy writes no ``context`` for an empty list.
    """
    if not isinstance(contexts, list) or not all(isinstance(item, str) for item in contexts):
        return None  # the schema check's finding
    if not contexts:
        return (
            "yara_meta_missing",
            "meta.context is empty, so deploy writes the YARA rule with no meta context; "
            "HarfangLab expects one",
        )
    written = decomposed_context(contexts, os if isinstance(os, str) else "")
    if context_accepted(written):
        return None
    return (
        "harfanglab_yara_context",
        f"meta.context deploys as context {written!r}; HarfangLab expects {_CONTEXTS_TEXT}",
    )


#: Where a HarfangLab block's signature sits in a rule file.
SIGNATURE_PATH = ("configurations", "harfanglab", "yara", "signature")


def _compose(text: str) -> Any:
    import yaml

    try:
        return yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:  # the file's parse error is reported by the loader
        return None


_MERGE_TAG = "tag:yaml.org,2002:merge"


def _aliased(value: Any, key: Any) -> bool:
    """Whether *value*, written after *key*, is an alias: its node starts where its anchor is.

    YAML defines an anchor before any alias of it, so an alias's node starts
    before the key it is the value of; a value written in place starts after.
    """
    return value.start_mark.index < key.end_mark.index


def _own(node: Any, key: str) -> tuple[Any, Any, bool] | None:
    """``(key node, value, aliased)`` where mapping *node* writes *key* itself, else ``None``.

    A key written twice is the last one, as PyYAML loads it.
    """
    for k, value in reversed(node.value):
        if k.tag != _MERGE_TAG and str(k.value) == key:
            return k, value, _aliased(value, k)
    return None


def _merge_sources(node: Any) -> list[tuple[Any, bool]]:
    """The mappings *node*'s ``<<`` keys merge, in PyYAML's order, each with whether it is aliased.

    A merge value that is an alias is aliased, and so is every mapping of an
    aliased sequence; an element of a sequence written in place is aliased when
    it starts before the sequence does.
    """
    import yaml

    sources: list[tuple[Any, bool]] = []
    for k, value in node.value:
        if k.tag != _MERGE_TAG:
            continue
        if isinstance(value, yaml.SequenceNode):
            sequence_aliased = _aliased(value, k)
            # An item written in place starts after everything written before it in
            # the sequence; an alias starts at its anchor, which is earlier: before
            # the sequence, or inside an earlier item.
            boundary = value.start_mark.index
            for item in value.value:
                sources.append((item, sequence_aliased or item.start_mark.index < boundary))
                boundary = max(boundary, item.end_mark.index)
        else:
            sources.append((value, _aliased(value, k)))
    return sources


def _lookup(node: Any, key: str) -> tuple[Any, Any, bool] | None:
    """``(key node, value, aliased)`` of *key* in mapping *node*, through merge keys as PyYAML
    merges them.

    A key the mapping writes wins over a merged one; among ``<<`` sources the
    first that has the key wins, depth first. *aliased* is whether reaching the
    value went through an alias. Only this one key is looked up, so unrelated
    aliases are never expanded. The walk keeps its own stack, so a merge chain
    of any length is fine, and visits each mapping once, so it is linear.
    """
    import yaml

    if not isinstance(node, yaml.MappingNode):
        return None
    own = _own(node, key)
    if own is not None:
        return own
    visited = {id(node)}
    stack: list[tuple[Iterator[tuple[Any, bool]], bool]] = [(iter(_merge_sources(node)), False)]
    while stack:
        sources, aliased = stack[-1]
        following = next(sources, None)
        if following is None:
            stack.pop()
            continue
        source, via = following
        if not isinstance(source, yaml.MappingNode) or id(source) in visited:
            continue
        visited.add(id(source))
        reached = aliased or via
        own = _own(source, key)
        if own is not None:
            return own[0], own[1], reached or own[2]
        stack.append((iter(_merge_sources(source)), reached))
    return None


def signature_is_aliased(text: str) -> bool:
    """Whether the HarfangLab ``signature`` in *text* is a YAML alias (``yara_signature_alias``).

    ``yaml.safe_load`` gives an alias the same value as its anchor, so whether
    ``signature`` was written in place is only seen in the node graph. The
    signature is aliased when its node, or any mapping on its path
    (``configurations``, ``harfanglab``, ``yara``), or a merge source (``<<:``)
    on that path, is an alias. Only that path is followed, so a file's other
    aliases cost nothing, however deep they nest.
    """
    node = _compose(text)
    aliased = False
    for key in SIGNATURE_PATH:
        found = _lookup(node, key)
        if found is None:
            return False
        _, node, step = found
        aliased = aliased or step
    return aliased


@dataclass(frozen=True)
class SignatureSite:
    """A HarfangLab signature as a rule file writes it."""

    #: The signature's value.
    value: str
    #: The file's text.
    text: str
    #: Where the scalar is written in the file: its first and past-the-last character.
    start: int
    end: int
    #: The scalar style: ``|`` literal, ``>`` folded, ``'``, ``"``, ``""`` plain, or ``?``
    #: when no written scalar holds the value (only its first line is known).
    style: str

    def line_of(self, offset: int) -> int:
        """The 0-based file line of the character at *offset* into the value.

        A literal block maps the value's lines one to one onto the lines after
        its indicator. Folding and quoting join lines and change escapes, so in
        any other style the words at *offset* are found in the written scalar
        (the same occurrence of them), and the scalar's first line is the
        answer only when they are not.
        """
        if self.style == "|":
            return self.text.count("\n", 0, self.start) + 1 + self.value.count("\n", 0, offset)
        if self.style in ("", "'", '"'):
            positions = _flow_positions(self.text, self.start, self.end, self.style)
            if len(positions) == len(self.value) and 0 <= offset < len(positions):
                return self.text.count("\n", 0, positions[offset])
        words = re.findall(r"\S+", self.value[offset:])[:2]
        if words:
            pattern = re.compile(r"\s+".join(re.escape(word) for word in words))
            before = sum(1 for match in pattern.finditer(self.value) if match.start() < offset)
            written = list(pattern.finditer(self.text, self.start, self.end))
            if before < len(written):
                return self.text.count("\n", 0, written[before].start())
        return self.text.count("\n", 0, self.start)


#: How many source characters after ``\\x``, ``\\u`` and ``\\U`` a double-quoted escape reads.
_ESCAPE_DIGITS = {"x": 2, "u": 4, "U": 8}


def _flow_positions(text: str, start: int, end: int, style: str) -> list[int]:
    """For each character of a flow scalar's value, where it is written in *text*.

    *start* and *end* are the scalar's marks; *style* is ``""`` (plain), ``'``
    or ``"``. It follows YAML's flow folding (a line break between words is a
    space, each empty line a ``\\n``, whitespace around a break dropped), a
    double-quoted escape (``\\"``, ``\\n``, ``\\x41``, an escaped line break)
    and a single-quoted ``''``. A list whose length differs from the value's
    means the scalar holds what this does not decode.
    """
    quoted = style in ("'", '"')
    index, stop = start + quoted, end - quoted
    positions: list[int] = []
    pending: list[int] = []  # blanks that a line break after them drops
    while index < stop:
        char = text[index]
        if char in " \t":
            pending.append(index)
            index += 1
            continue
        if char in "\r\n":
            pending = []
            breaks: list[int] = []
            while index < stop and text[index] in "\r\n":
                breaks.append(index)
                index += 2 if text.startswith("\r\n", index) else 1
                while index < stop and text[index] in " \t":
                    index += 1
            # One break folds to a space; each further (empty) line is a \n.
            positions.extend(breaks[:1] if len(breaks) == 1 else breaks[1:])
            continue
        positions.extend(pending)
        pending = []
        following = text[index + 1] if index + 1 < stop else ""
        if style == '"' and char == "\\":
            if following in "\r\n" and following:
                index += 3 if text.startswith("\r\n", index + 1) else 2
                while index < stop and text[index] in " \t":
                    index += 1
                continue
            positions.append(index)
            index += 2 + _ESCAPE_DIGITS.get(following, 0)
            continue
        if style == "'" and char == "'" and following == "'":
            positions.append(index)
            index += 2
            continue
        positions.append(index)
        index += 1
    positions.extend(pending)
    return positions


def _entry_at(text: str, path: tuple[str, ...]) -> tuple[Any, Any] | None:
    """``(key node, value node)`` at *path* in *text*, through merge keys as loaded."""
    node: Any = _compose(text)
    key: Any = None
    for part in path:
        found = _lookup(node, part)
        if found is None:
            return None
        key, node, _ = found
    return key, node


def _node_at(text: str, path: tuple[str, ...]) -> Any:
    """The node at *path* in *text*, through merge keys as the loaded data has it."""
    entry = _entry_at(text, path)
    return entry[1] if entry else None


def _loaded_at(text: str, path: tuple[str, ...]) -> Any:
    """The value at *path* in *text* as ``yaml.safe_load`` gives it, after merges and aliases."""
    import yaml

    try:
        value: Any = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


#: Where the decomposed form's scan contexts and OS sit in a rule file.
CONTEXT_PATH = ("configurations", "harfanglab", "yara", "meta", "context")
OS_PATH = ("configurations", "harfanglab", "yara", "meta", "os")


def decomposed_context_in(text: str) -> tuple[Any, Any, int] | None:
    """``(meta.context, meta.os, 0-based line of meta.context)`` of a decomposed HarfangLab block.

    ``None`` when the file has no ``meta.context`` or its block has a ``signature``.
    """
    yara = _loaded_at(text, SIGNATURE_PATH[:-1])
    if not isinstance(yara, dict) or "signature" in yara:
        return None
    meta = yara.get("meta")
    if not isinstance(meta, dict) or "context" not in meta:
        return None
    # The values are the loaded data's, after merges; the key only places them.
    return meta.get("context"), meta.get("os"), _placed_line(text, CONTEXT_PATH)


def _placed_line(text: str, path: tuple[str, ...]) -> int:
    """The 0-based line of the deepest key of *path* written in place in *text*.

    Past an alias the keys are the anchor's, elsewhere in the file, so the last
    key reached without one places the finding; 0 when *text* writes none.
    """
    node: Any = _compose(text)
    line = 0
    for part in path:
        found = _lookup(node, part)
        if found is None:
            break
        key, node, aliased = found
        if aliased:
            break
        line = key.start_mark.line
    return line


def signature_in(text: str) -> SignatureSite | None:
    """The HarfangLab signature in a rule file's *text*; ``None`` when it has none.

    The value is the one deploy sends: the loaded data's, after merge keys and
    aliases. The node, found through the same merges, only places it in the
    file; when it does not hold that value, its first line stands for it.
    """
    import yaml

    value = _loaded_at(text, SIGNATURE_PATH)
    if not isinstance(value, str):
        return None
    entry = _entry_at(text, SIGNATURE_PATH)
    node = entry[1] if entry else None
    if not isinstance(node, yaml.ScalarNode) or node.value != value:
        # No written scalar holds it: the signature key, else the yara block, stands for it.
        if entry is not None:
            where = entry[0].start_mark.index
        else:
            where = _line_start(text, _placed_line(text, SIGNATURE_PATH))
        return SignatureSite(value=value, text=text, start=where, end=where, style="?")
    return SignatureSite(
        value=value,
        text=text,
        start=node.start_mark.index,
        end=node.end_mark.index,
        style=node.style or "",
    )


def _line_start(text: str, line: int) -> int:
    """The offset of the 0-based *line* in *text*."""
    offset = 0
    for _ in range(line):
        offset = text.index("\n", offset) + 1
    return offset


#: Which advisory a finding is: ``(code, form, YARA rule)``. The form is
#: ``signature`` or ``decomposed``; the rule is a signature rule's name, ``""``
#: in the decomposed form, which assembles one rule.
AdvisoryKey = tuple[str, str, str]


def advisory_keys(text: str) -> set[AdvisoryKey]:
    """The advisories opentide's own check reports on a rule file's *text*, by key."""
    site = signature_in(text)
    if site is not None:
        return {(item.code, "signature", item.rule) for item in advisories(site.value)}
    decomposed = decomposed_context_in(text)
    found = decomposed_advisory(*decomposed[:2]) if decomposed else None
    return {(found[0], "decomposed", "")} if found else set()


def engine_advisory_key(text: str, code: str, line: int) -> AdvisoryKey:
    """The key of an engine *code* reported at 0-based *line* of a rule file's *text*.

    In the signature form the rule is the one whose header is the last at or
    before *line*; a finding before every header has the first rule's.
    """
    site = signature_in(text)
    if site is None:
        return code, "decomposed", ""
    rule = ""
    for header in rule_headers(site.value):
        if site.line_of(header.start) > line and rule:
            break
        rule = header.name
    return code, "signature", rule
