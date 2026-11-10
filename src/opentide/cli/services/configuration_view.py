"""The workspace's configuration as ``opentide tui`` shows it: read, not as TOML (#776).

Each file (``deployment.toml``, ``lint.toml``, ``documentation.toml``,
``sharing.toml`` and each ``platforms/*.toml``) is shown by section, each
setting with its effective value (the bundled file, the workspace's and the
parent instance merged, as every command reads them), whether the workspace
sets it, and what it does: the description its JSON Schema
(:mod:`opentide.generation.configuration_schemas`) gives, else the bundled
file's comment above it. Options the workspace does not set are listed with
their descriptions too. Platforms read as cards: enabled or not, and each
tenant's strategies, credentials and the rules that reach it.

**No credential value is ever returned.** A value with a ``setup`` table, or a
key that names a secret (``key``, ``token``, ``password``…), anywhere on its
key path is replaced: a ``$NAME`` or ``${NAME}`` reference by its variable
name and whether the environment sets it, as ``opentide doctor`` reports it;
anything else by :data:`HIDDEN`. The raw file is redacted the same way, then
proven redacted (:func:`redact_toml`): a file that does not parse, or whose
redaction cannot be proven, has no raw view.
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

__all__ = [
    "HIDDEN",
    "ConfigFile",
    "ConfigFinding",
    "ConfigurationView",
    "Credential",
    "PlatformCard",
    "Setting",
    "TenantCard",
    "UnsafeRawView",
    "load_configuration_view",
    "redact_toml",
]

#: What a hidden value reads as. Never the value, its length or a part of it.
HIDDEN = "•••• hidden"
#: A key that names a secret: every value at or under it is one.
SECRET_KEY = re.compile(
    r"(secret|token|password|passwd|passphrase|api[_\-\s.]?key|private[_\-\s.]?key|"
    r"credential|auth|^key$|[_\-\s.]key$|cookie|session)",
    re.IGNORECASE,
)
#: The tables whose every value is a credential or tenant secret.
SECRET_TABLES = frozenset({"setup"})
#: ``scheme://user:password@host``: the user part, up to the authority's last ``@``.
_USERINFO = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/?#]*@")
#: Why a raw view is withheld when its redaction cannot be proven.
UNSAFE_RAW = (
    "The raw file cannot be shown safely: a credential in it could not be redacted "
    "with certainty. Its settings are listed in the read view."
)

#: The files the tab shows, in order; platform files follow.
FILES = ("deployment.toml", "lint.toml", "documentation.toml", "sharing.toml")
_MERGED_KEYS = {
    "deployment.toml": "deployment",
    "lint.toml": "lint",
    "documentation.toml": "documentation",
    "sharing.toml": "sharing",
}


@dataclass(frozen=True)
class Setting:
    """One value of a configuration file, as the tab shows it."""

    #: The key path in the file (``tenants.0.setup.api_key``).
    path: str
    key: str
    #: The effective value, shown: redacted when it is a secret.
    shown: str
    #: Whether the workspace's file sets it (else it is the bundled default).
    set_here: bool
    description: str = ""
    secret: bool = False
    #: For a secret that is a ``$NAME`` reference: the variable, and whether it is set.
    variable: str | None = None
    variable_set: bool | None = None


@dataclass(frozen=True)
class ConfigFinding:
    code: str
    severity: str
    message: str
    field_path: tuple[str, ...]


@dataclass(frozen=True)
class ConfigFile:
    """One configuration file."""

    key: str
    #: The workspace's file, when it has one.
    path: Path | None
    settings: tuple[Setting, ...]
    #: ``(path, description)`` of options the schema defines that nothing sets.
    unset: tuple[tuple[str, str], ...] = ()
    findings: tuple[ConfigFinding, ...] = ()
    #: The workspace's file, redacted (:func:`redact_toml`); ``None`` without one,
    #: or when it cannot be shown (:attr:`raw_problem` says why).
    raw: str | None = None
    #: Why the workspace's file has no raw view: never its content.
    raw_problem: str | None = None


@dataclass(frozen=True)
class Credential:
    """One ``setup`` key of a tenant: never its value."""

    key: str
    variable: str | None
    #: Whether the variable is set; ``None`` for a literal (shown as :data:`HIDDEN`).
    is_set: bool | None
    #: A switch (``ssl = true``), which is no credential and is shown.
    flag: bool | None = None


@dataclass(frozen=True)
class TenantCard:
    name: str
    strategies: tuple[str, ...]
    manual: bool
    credentials: tuple[Credential, ...]
    #: Rules a deploy run reaches this tenant with, as ``deploy`` plans them.
    rules: tuple[str, ...]


@dataclass(frozen=True)
class PlatformCard:
    platform: str
    enabled: bool
    tenants: tuple[TenantCard, ...]
    #: Rules with a block for this platform.
    rules: tuple[str, ...]


@dataclass(frozen=True)
class ConfigurationView:
    files: tuple[ConfigFile, ...] = ()
    platforms: tuple[PlatformCard, ...] = ()
    #: Why the configuration could not be read, when it could not.
    problem: str | None = None


class UnsafeRawView(ValueError):
    """Why a file has no raw view: it does not parse, or its redaction was not proven."""


def _is_secret(parts: Sequence[str]) -> bool:
    """Whether a value at *parts* is a secret: any key on the path names one."""
    return any(
        part in SECRET_TABLES or SECRET_KEY.search(part) is not None
        for part in parts
        if not part.isdigit()
    )


def _hide_userinfo(text: str) -> str:
    return _USERINFO.sub(lambda m: f"{m.group(1)}{HIDDEN}@", text)


def _shown(value: Any, parts: Sequence[str], environ: Mapping[str, str]) -> Setting:
    from opentide.core.environment import env_reference

    path = ".".join(parts)
    key = parts[-1] if parts else ""
    # A switch (`ssl = true`) is no credential: it is shown as it is.
    if _is_secret(parts) and not isinstance(value, bool):
        variable = env_reference(value) if isinstance(value, str) else None
        if variable is not None:
            is_set = bool(environ.get(variable))
            return Setting(
                path, key, f"${{{variable}}} ({'set' if is_set else 'unset'})", False,
                secret=True, variable=variable, variable_set=is_set,
            )  # fmt: skip
        return Setting(path, key, HIDDEN, False, secret=True)
    return Setting(path, key, _format(value), False)


def _format(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _hide_userinfo(value)
    if isinstance(value, (list, tuple)) and all(
        not isinstance(item, (Mapping, list, tuple)) for item in value
    ):
        return ", ".join(_format(item) for item in value) or "[]"
    return str(value)


def _leaves(value: Any, parts: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _leaves(item, (*parts, str(key)))
    elif isinstance(value, (list, tuple)) and any(
        isinstance(i, (Mapping, list, tuple)) for i in value
    ):
        for index, item in enumerate(value):
            yield from _leaves(item, (*parts, str(index)))
    else:
        yield parts, value


def _has(document: Any, parts: Sequence[str]) -> bool:
    node = document
    for part in parts:
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return False
    return True


def _schema_descriptions(file_key: str) -> dict[str, str]:
    """``dotted path → description`` from the file's JSON Schema (list items as ``*``)."""
    from opentide.generation.configuration_schemas import generate_configuration_schema

    try:
        schema = generate_configuration_schema(file_key)
    except (KeyError, LookupError, ValueError):
        return {}
    definitions = schema.get("$defs") or {}
    found: dict[str, str] = {}

    def resolve(node: Mapping[str, Any]) -> Mapping[str, Any]:
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            return definitions.get(ref.rsplit("/", 1)[-1], node)
        for key in ("anyOf", "oneOf", "allOf"):
            for option in node.get(key) or ():
                if isinstance(option, Mapping) and (option.get("$ref") or option.get("properties")):
                    return resolve(option)
        return node

    def walk(node: Mapping[str, Any], prefix: str, depth: int) -> None:
        if depth > 8:
            return
        node = resolve(node)
        for name, child in (node.get("properties") or {}).items():
            if not isinstance(child, Mapping):
                continue
            path = f"{prefix}.{name}" if prefix else str(name)
            description = child.get("description") or resolve(child).get("description")
            if isinstance(description, str):
                found[path] = " ".join(description.split())
            resolved = resolve(child)
            walk(resolved, path, depth + 1)
            items = resolved.get("items")
            if isinstance(items, Mapping):
                walk(items, f"{path}.*", depth + 1)

    walk(schema, "", 0)
    return found


def _comment_descriptions(text: str | None) -> dict[str, str]:
    """``dotted path → the comment above it`` in a bundled file (``lint.toml`` has no schema)."""
    if not text:
        return {}
    found: dict[str, str] = {}
    comments: list[str] = []
    table: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            # A commented-out key is an example, not a description.
            if body and not re.match(r"^[\w.\-\"]+\s*=", body) and not body.startswith("["):
                comments.append(body)
            continue
        header = re.match(r"^\[\[?([^\]]+)\]\]?$", line)
        if header:
            table = [part.strip() for part in header.group(1).split(".")]
            if comments:
                found[".".join(table)] = " ".join(comments)
            comments = []
            continue
        assignment = re.match(r"^([\w\-]+)\s*=", line)
        if assignment and comments:
            found[".".join([*table, assignment.group(1)])] = " ".join(comments)
        if line:
            comments = []
    return found


def _description(descriptions: Mapping[str, str], parts: Sequence[str]) -> str:
    starred = ".".join("*" if part.isdigit() else part for part in parts)
    plain = ".".join(part for part in parts if not part.isdigit())
    return descriptions.get(starred) or descriptions.get(plain) or ""


def _bundled_text(file_key: str) -> str | None:
    from opentide.core.root import get_data_root

    path = get_data_root() / "configurations" / file_key
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


class _ScanError(ValueError):
    """The redactor met text it does not read: the raw view is withheld."""


_BARE_KEY = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
_MISSING = object()


def _decode(token: str) -> Any:
    """The value a TOML value *token* (a string, number, date…) reads as."""
    return tomllib.loads(f"v = {token}")["v"]


def _basic_string(value: str) -> str:
    """*value* as a TOML basic string."""
    named = {"\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
    escaped: list[str] = []
    for char in value:
        if char in '"\\':
            escaped.append(f"\\{char}")
        elif char in named:
            escaped.append(named[char])
        elif char < " " or char == "\x7f":
            escaped.append(f"\\u{ord(char):04x}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def _scan_string(text: str, pos: int) -> int:
    """The end of the TOML string that starts at *pos*, any of its four forms."""
    quote = text[pos]
    if text.startswith(quote * 3, pos):
        i = pos + 3
        while True:
            if quote == '"' and text[i] == "\\":
                i += 2
            elif text[i] == quote:
                run = 1
                while i + run < len(text) and text[i + run] == quote:
                    run += 1
                if run >= 3:
                    # Up to two quotes may end the content, right before the closing three.
                    return i + min(run, 5)
                i += run
            else:
                i += 1
    i = pos + 1
    while text[i] != quote:
        if text[i] == "\n":
            raise _ScanError("a string ends at a newline")
        i += 2 if quote == '"' and text[i] == "\\" else 1
    return i + 1


def _scan_key(text: str, pos: int) -> tuple[int, list[str]]:
    """The end of the (dotted) key at *pos* and its parts, quotes decoded."""
    parts: list[str] = []
    i = pos
    while True:
        if text[i] in "\"'":
            end = _scan_string(text, i)
            parts.append(_decode(text[i:end]))
        else:
            end = i
            while end < len(text) and text[end] in _BARE_KEY:
                end += 1
            if end == i:
                raise _ScanError("not a key")
            parts.append(text[i:end])
        i = end
        dot = _skip_blank(text, i)
        if dot < len(text) and text[dot] == ".":
            i = _skip_blank(text, dot + 1)
            continue
        return end, parts


def _skip_blank(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    return pos


def _skip_trivia(text: str, pos: int) -> int:
    """Past blanks, newlines and comments, as arrays (and TOML 1.1 inline tables) allow."""
    while pos < len(text):
        if text[pos] in " \t\r\n":
            pos += 1
        elif text[pos] == "#":
            newline = text.find("\n", pos)
            pos = len(text) if newline < 0 else newline
        else:
            break
    return pos


def _scan_value(text: str, pos: int) -> int:
    """The end of the TOML value that starts at *pos*."""
    char = text[pos]
    if char in "\"'":
        return _scan_string(text, pos)
    if char == "[":
        i = _skip_trivia(text, pos + 1)
        while text[i] != "]":
            i = _skip_trivia(text, _scan_value(text, i))
            if text[i] == ",":
                i = _skip_trivia(text, i + 1)
        return i + 1
    if char == "{":
        i = _skip_trivia(text, pos + 1)
        while text[i] != "}":
            i, _ = _scan_key(text, i)
            i = _skip_trivia(text, i)
            if text[i] != "=":
                raise _ScanError("an inline table key without a value")
            i = _skip_trivia(text, _scan_value(text, _skip_trivia(text, i + 1)))
            if text[i] == ",":
                i = _skip_trivia(text, i + 1)
        return i + 1
    # A number, boolean or date: up to what may follow a value (a date may hold a space).
    end = pos
    while end < len(text) and text[end] not in ",]}#\n":
        end += 1
    while end > pos and text[end - 1] in " \t\r":
        end -= 1
    if end == pos:
        raise _ScanError("no value")
    return end


class _Redactor:
    """Copies a TOML document, each secret value replaced and each URL's user hidden.

    It reads the document as TOML does, value by value (strings of every form,
    arrays and inline tables over any number of lines), so a value never
    leaks for being written one way rather than another. It assumes the
    document parses; :func:`redact_toml` checks that first and the result after.
    """

    def __init__(self, text: str, environ: Mapping[str, str]) -> None:
        self.text = text
        self.environ = environ
        self.pos = 0
        self.out: list[str] = []

    def copy_to(self, end: int) -> None:
        """Copy up to *end*, a comment's URL user hidden."""
        chunk = self.text[self.pos : end]
        if "#" in chunk:
            chunk = "\n".join(_hide_userinfo(line) for line in chunk.split("\n"))
        self.out.append(chunk)
        self.pos = end

    def expect(self, token: str) -> None:
        if not self.text.startswith(token, self.pos):
            raise _ScanError(f"expected {token!r}")
        self.copy_to(self.pos + len(token))

    def run(self) -> str:
        text = self.text
        table: list[str] = []
        while True:
            self.copy_to(_skip_trivia(text, self.pos))
            if self.pos >= len(text):
                return "".join(self.out)
            if text[self.pos] == "[":
                closing = "]]" if text.startswith("[[", self.pos) else "]"
                self.copy_to(_skip_blank(text, self.pos + len(closing)))
                end, table = _scan_key(text, self.pos)
                self.copy_to(_skip_blank(text, end))
                self.expect(closing)
            else:
                self.key_value(table, top=True)
            # A statement ends with blanks, a comment, and a newline (or the end).
            self.copy_to(_skip_blank(text, self.pos))
            if self.pos < len(text) and text[self.pos] == "#":
                newline = text.find("\n", self.pos)
                self.copy_to(len(text) if newline < 0 else newline)
            if self.pos < len(text) and text[self.pos] not in "\r\n":
                raise _ScanError("text after a value")

    def key_value(self, table: Sequence[str], *, top: bool) -> None:
        end, parts = _scan_key(self.text, self.pos)
        self.copy_to(_skip_trivia(self.text, end) if not top else _skip_blank(self.text, end))
        self.expect("=")
        self.copy_to(_skip_blank(self.text, self.pos))
        self.value([*table, *parts], top=top)

    def value(self, path: Sequence[str], *, top: bool) -> None:
        text = self.text
        start = self.pos
        char = text[start]
        if char == "{":
            # Its keys are no secret: each value is redacted at its own path.
            self.expect("{")
            while True:
                self.copy_to(_skip_trivia(text, self.pos))
                if text[self.pos] == "}":
                    self.expect("}")
                    return
                self.key_value(path, top=False)
                self.copy_to(_skip_trivia(text, self.pos))
                if text[self.pos] == ",":
                    self.expect(",")
        end = _scan_value(text, start)
        token = text[start:end]
        if _is_secret(path) and token not in ("true", "false"):
            self.out.append(self.hidden(token, top=top))
            self.pos = end
            return
        if char == "[":
            self.expect("[")
            index = 0
            while True:
                self.copy_to(_skip_trivia(text, self.pos))
                if text[self.pos] == "]":
                    self.expect("]")
                    return
                self.value([*path, str(index)], top=False)
                index += 1
                self.copy_to(_skip_trivia(text, self.pos))
                if text[self.pos] == ",":
                    self.expect(",")
        if char in "\"'":
            decoded = _decode(token)
            shown = _hide_userinfo(decoded)
            self.out.append(token if shown == decoded else _basic_string(shown))
        else:
            self.out.append(token)
        self.pos = end

    def hidden(self, token: str, *, top: bool) -> str:
        """What a secret value reads as: its variable and whether it is set, or :data:`HIDDEN`."""
        from opentide.core.environment import env_reference

        reference = env_reference(_decode(token)) if token[0] in "\"'" else None
        if reference is None:
            return _basic_string(HIDDEN)
        if not top:
            return _basic_string(f"${{{reference}}}")
        state = "set" if self.environ.get(reference) else "unset"
        return f"{_basic_string(f'${{{reference}}}')}  # {state}"


def _scalars(value: Any, parts: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    """Every value that is no table or array, with its key path (array items by index)."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _scalars(item, (*parts, str(key)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _scalars(item, (*parts, str(index)))
    else:
        yield parts, value


def _at(document: Any, parts: Sequence[str]) -> Any:
    node = document
    for part in parts:
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return _MISSING
    return node


def _secrets(document: Any) -> set[str]:
    """Every text a secret of *document* could show as: never to appear in a raw view.

    Each secret value (a whole string, each of its lines, each item of an
    array, a number as written by Python), and the user part of each URL.
    A ``$NAME`` reference is no secret: the view shows it.
    """
    from opentide.core.environment import env_reference

    found: set[str] = set()
    for parts, value in _scalars(document):
        if isinstance(value, str):
            for match in _USERINFO.finditer(value):
                found.add(match.group(0)[len(match.group(1)) : -1])
        if isinstance(value, bool) or not _is_secret(parts):
            continue
        if not isinstance(value, str):
            found.add(str(value))
        elif env_reference(value) is None:
            found.add(value)
            found.update(line.strip() for line in value.split("\n"))
    found.discard("")
    return found


def _proven(document: Any, redacted: str) -> bool:
    """Whether *redacted* holds no secret of *document*, read back as TOML and as text.

    Read back, every value at a secret path is :data:`HIDDEN` or a variable
    reference (a switch excepted), and every other is the original's at the
    same path, its URL user hidden; and no secret's text appears anywhere in
    it, comments included.
    """
    from opentide.core.environment import env_reference

    try:
        shown = tomllib.loads(redacted)
    except (tomllib.TOMLDecodeError, RecursionError):
        return False
    for parts, value in _scalars(shown):
        if _is_secret(parts) and not isinstance(value, bool):
            if value != HIDDEN and env_reference(value) is None:
                return False
            continue
        original = _at(document, parts)
        expected = _hide_userinfo(original) if isinstance(original, str) else original
        if type(value) is not type(expected) or (
            value != expected and repr(value) != repr(expected)
        ):
            return False
    return not any(secret in redacted for secret in _secrets(document))


def _toml_position(exc: tomllib.TOMLDecodeError) -> str:
    """Where *exc* is, never its message: that may quote the file."""
    line, column = getattr(exc, "lineno", None), getattr(exc, "colno", None)
    if line is not None and column is not None:
        return f"line {line}, column {column}"
    match = re.search(r"\(at line (\d+), column (\d+)\)", str(exc))
    if match is not None:
        return f"line {match.group(1)}, column {match.group(2)}"
    return "at the end of the document" if "end of document" in str(exc) else "position unknown"


def redact_toml(text: str, environ: Mapping[str, str] | None = None) -> str:
    """*text* with every secret value replaced, as the raw view shows it.

    A value with a ``setup`` table or a secret-named key on its key path reads
    as its variable reference and whether it is set, or as :data:`HIDDEN`; the
    user part of a URL is hidden. Comments and layout stay. The result is then
    proven (:func:`_proven`).

    Raises :class:`UnsafeRawView`, whose message never quotes the file, when
    *text* is not valid TOML or its redaction cannot be proven.
    """
    environ = os.environ if environ is None else environ
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise UnsafeRawView(f"not valid TOML: {_toml_position(exc)}") from None
    except RecursionError:
        raise UnsafeRawView("not valid TOML: nested too deep") from None
    try:
        redacted = _Redactor(text, environ).run()
    except (_ScanError, IndexError, tomllib.TOMLDecodeError, RecursionError):
        raise UnsafeRawView(UNSAFE_RAW) from None
    if not _proven(document, redacted):
        raise UnsafeRawView(UNSAFE_RAW)
    return redacted


def _file(
    file_key: str,
    merged: Any,
    workspace_dir: Path | None,
    findings: Sequence[ConfigFinding],
    environ: Mapping[str, str],
) -> ConfigFile:
    path = workspace_dir / file_key if workspace_dir is not None else None
    own: Any = {}
    raw = raw_problem = None
    if path is not None and path.is_file():
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            raw_problem = f"the file could not be read ({type(exc).__name__})"
        else:
            with contextlib.suppress(tomllib.TOMLDecodeError, RecursionError):
                own = tomllib.loads(text)
            try:
                raw = redact_toml(text, environ)
            except UnsafeRawView as exc:
                raw_problem = str(exc)
    else:
        path = None
    schema_key = "platforms/*.toml" if file_key.startswith("platforms/") else file_key
    descriptions = {
        **_comment_descriptions(_bundled_text(file_key)),
        **_schema_descriptions(file_key if file_key != "lint.toml" else schema_key),
    }
    settings: list[Setting] = []
    for parts, value in _leaves(merged if isinstance(merged, Mapping) else {}):
        shown = _shown(value, parts, environ)
        settings.append(
            Setting(
                shown.path,
                shown.key,
                shown.shown,
                _has(own, parts),
                _description(descriptions, parts),
                shown.secret,
                shown.variable,
                shown.variable_set,
            )
        )
    present = {".".join("*" if p.isdigit() else p for p in s.path.split(".")) for s in settings}
    present |= {".".join(p for p in s.path.split(".") if not p.isdigit()) for s in settings}
    prefixes = {p.rsplit(".", n)[0] for p in present for n in range(1, p.count(".") + 1)}
    unset = tuple(
        (path_key, text)
        for path_key, text in sorted(descriptions.items())
        if path_key not in present
        and path_key not in prefixes
        and (path_key.rsplit(".", 1)[0] in prefixes | present if "." in path_key else True)
        and not _is_secret(path_key.split("."))
    )
    return ConfigFile(file_key, path, tuple(settings), unset, tuple(findings), raw, raw_problem)


def _findings(configs: Mapping[str, Any]) -> dict[str, list[ConfigFinding]]:
    from opentide.validation.configuration import workspace_configuration_issues

    found: dict[str, list[ConfigFinding]] = {}
    try:
        issues = workspace_configuration_issues(configs)
    except Exception:  # the checks are validate's: the tab shows what it can
        return found
    for issue in issues:
        context = getattr(issue, "context", None) or {}
        file_key = str(context.get("file") or "")
        found.setdefault(file_key, []).append(
            ConfigFinding(
                code=str(issue.code),
                severity=str(issue.severity),
                message=str(issue.message),
                field_path=tuple(str(part) for part in issue.field_path or ()),
            )
        )
    return found


def _platform_cards(
    configs: Mapping[str, Any], rules: Mapping[str, Any], environ: Mapping[str, str]
) -> list[PlatformCard]:
    from opentide._models.deployment_enums import StatusStrategy, deployed_by
    from opentide.cli.services.catalog import _status_strategies
    from opentide.core.environment import env_reference
    from opentide.core.object_fields import as_body

    strategies = _status_strategies(configs.get("deployment") or {})
    platforms = configs.get("platforms") or {}
    cards: list[PlatformCard] = []
    for platform, document in sorted(platforms.items()):
        if not isinstance(document, Mapping):
            continue
        platform_section = document.get("platform")
        enabled = bool(
            (platform_section or {}).get("enabled")
            if isinstance(platform_section, Mapping)
            else document.get("enabled")
        )
        with_block: list[tuple[str, Mapping[str, Any]]] = []
        for uuid, rule in rules.items():
            blocks = as_body(rule).get("configurations")
            block = blocks.get(platform) if isinstance(blocks, Mapping) else None
            if isinstance(block, Mapping):
                with_block.append((uuid, block))
        tenants: list[TenantCard] = []
        for index, tenant in enumerate(document.get("tenants") or ()):
            if not isinstance(tenant, Mapping):
                continue
            name = str(tenant.get("name") or f"tenant {index + 1}")
            accepted = tuple(str(s).upper() for s in tenant.get("strategies") or ())
            manual = tenant.get("manual") is True
            setup = tenant.get("setup") if isinstance(tenant.get("setup"), Mapping) else {}
            credentials = []
            for key, value in setup.items():
                variable = env_reference(value)
                credentials.append(
                    Credential(
                        str(key),
                        variable,
                        None if variable is None else bool(environ.get(variable)),
                        value if isinstance(value, bool) else None,
                    )
                )
            reaching: list[str] = []
            for uuid, block in with_block:
                if block.get("enabled") is False:
                    continue
                listed = [str(t) for t in block.get("tenants") or ()]
                if listed:
                    if name in listed:
                        reaching.append(uuid)
                    continue
                if manual:
                    continue
                status = str(block.get("status") or "")
                strategy = strategies.get(status)
                if strategy is None or strategy not in StatusStrategy.__members__:
                    continue
                runs = deployed_by(StatusStrategy[strategy])
                if any(run.name in accepted for run in runs):
                    reaching.append(uuid)
            tenants.append(TenantCard(name, accepted, manual, tuple(credentials), tuple(reaching)))
        cards.append(
            PlatformCard(
                platform=str(platform),
                enabled=enabled,
                tenants=tuple(tenants),
                rules=tuple(uuid for uuid, _ in with_block),
            )
        )
    return cards


def load_configuration_view(
    root: Path | None,
    rules: Mapping[str, Any],
    environ: Mapping[str, str] | None = None,
) -> ConfigurationView:
    """The tab's content for the workspace at *root*, its *rules* bodies by UUID."""
    from opentide.core.errors import ConfigFileError
    from opentide.core.files import resolve_configurations

    environ = dict(os.environ if environ is None else environ)
    try:
        configs = resolve_configurations(root)
    except ConfigFileError as exc:
        # Where, never what: the parser's message may quote the file.
        where = "" if exc.line is None else f" at line {exc.line}, column {exc.column}"
        return ConfigurationView(
            problem=f"The configuration could not be read: {exc.path} is not valid TOML{where}."
        )
    except Exception as exc:  # validate reports the file; the tab says why
        return ConfigurationView(problem=f"The configuration could not be read: {exc}")
    workspace_dir = None if root is None else root / ".opentide" / "configurations"
    findings = _findings(configs)
    files = [
        _file(
            key, configs.get(_MERGED_KEYS[key]) or {}, workspace_dir, findings.get(key, ()), environ
        )
        for key in FILES
    ]
    for platform, document in sorted((configs.get("platforms") or {}).items()):
        key = f"platforms/{platform}.toml"
        files.append(_file(key, document, workspace_dir, findings.get(key, ()), environ))
    return ConfigurationView(
        files=tuple(files),
        platforms=tuple(_platform_cards(configs, rules, environ)),
    )
