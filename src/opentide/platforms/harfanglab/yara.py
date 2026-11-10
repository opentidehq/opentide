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
HARFANGLAB_CONTEXTS = frozenset(
    {"file", "memory", "file,memory", "file.pe", "file.elf", "file.macho"}
)

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
_CONTEXT = re.compile(r"(?<![\w$#@!])context\s*=\s*\"")
_ASCII_NAME = re.compile(r"[A-Za-z0-9_]+")


def _blank(text: str) -> str:
    """*text* with comments and the insides of string literals turned into spaces.

    Offsets and line breaks are kept, so a position in the result is the same
    position in *text*. The quotes of a string stay, so ``include "x"`` still
    reads as an include.
    """
    out = list(text)
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if char == "/" and text.startswith("//", index):
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


def rule_name_refused(name: str) -> bool:
    """Whether libyara refuses the rule name deploy derives (``harfanglab_yara_rule_name``)."""
    derived = derived_rule_name(name)
    return derived in YARA_KEYWORDS or not _ASCII_NAME.fullmatch(derived)


def deployed_signature(signature: str) -> str:
    """*signature* as deploy sends it: ``\\n`` line endings and one trailing newline."""
    text = signature.replace("\r\n", "\n").replace("\r", "\n")
    return text.rstrip("\n") + "\n"


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
    signature = yara.get("signature")
    if _set(signature):
        if any(_set(yara.get(key)) for key in DECOMPOSED_KEYS):
            codes.add("harfanglab_yara_form")
        codes |= signature_codes(signature)
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


def _meta_span(code: str, header: YaraRuleHeader) -> tuple[int, int] | None:
    meta = _META.search(code, header.start, header.end)
    if meta is None:
        return None
    after = _SECTION_AFTER_META.search(code, meta.end(), header.end)
    return meta.end(), after.start() if after else header.end


def _context_value(signature: str, code: str, span: tuple[int, int]) -> tuple[str, int] | None:
    found = _CONTEXT.search(code, *span)
    if found is None:
        return None
    start = found.end()
    end = start
    while end < len(signature) and signature[end] not in '"\n':
        end += 2 if signature[end] == "\\" else 1
    return signature[start:end], found.start()


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
            )
            continue
        value, offset = found
        if value not in HARFANGLAB_CONTEXTS:
            yield YaraAdvisory(
                "harfanglab_yara_context",
                f"YARA rule {header.name!r} sets meta context {value!r}; HarfangLab's rules use "
                + ", ".join(sorted(HARFANGLAB_CONTEXTS)),
                offset,
            )


#: Where a HarfangLab block's signature sits in a rule file.
SIGNATURE_PATH = ("configurations", "harfanglab", "yara", "signature")


def _compose(text: str) -> Any:
    import yaml

    try:
        return yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError:  # the file's parse error is reported by the loader
        return None


def aliased_paths(text: str) -> list[tuple[str, ...]]:
    """The key paths whose value is a YAML alias of a scalar written earlier in *text*.

    ``yaml.safe_load`` gives an alias the same value as its anchor, so whether
    ``signature`` was written in the block is only seen in the node graph:
    an alias is the anchored node object itself, met a second time.
    """
    import yaml

    root = _compose(text)
    seen: set[int] = set()
    found: list[tuple[str, ...]] = []

    def walk(node: Any, path: tuple[str, ...]) -> None:
        if id(node) in seen:
            if isinstance(node, yaml.ScalarNode):
                found.append(path)
            return
        seen.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                walk(value, (*path, str(key.value)))
        elif isinstance(node, yaml.SequenceNode):
            for index, value in enumerate(node.value):
                walk(value, (*path, str(index)))

    if root is not None:
        walk(root, ())
    return found


def signature_is_aliased(text: str) -> bool:
    """Whether the HarfangLab ``signature`` in *text* is a YAML alias (``yara_signature_alias``)."""
    return SIGNATURE_PATH in aliased_paths(text)


def signature_in(text: str) -> tuple[str, int] | None:
    """The HarfangLab signature in a rule file's *text*, and the 0-based line its text starts on.

    A block scalar (``|``) starts on the line after its indicator; any other
    scalar on the indicator's own line. ``None`` when the file has no signature.
    """
    import yaml

    node = _compose(text)
    for key in SIGNATURE_PATH:
        if not isinstance(node, yaml.MappingNode):
            return None
        node = next((value for k, value in node.value if k.value == key), None)
    if not isinstance(node, yaml.ScalarNode) or node.tag != "tag:yaml.org,2002:str":
        return None
    line = node.start_mark.line
    return str(node.value), line + 1 if node.style == "|" else line
