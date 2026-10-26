"""Shared file I/O helpers for YAML, JSON, and TOML."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, time
from pathlib import Path
from typing import Any

import orjson
import tomli_w
import yaml
from yaml.constructor import ConstructorError, SafeConstructor

try:
    from yaml import CSafeLoader as YamlLoader
except ImportError:
    from yaml import SafeLoader as YamlLoader

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def yaml_loader_name() -> str:
    """Return the active YAML loader class name (for benchmarks/diagnostics)."""
    return YamlLoader.__name__


def stringify_yaml_temporals(value: Any) -> Any:
    """Replace YAML timestamp objects with ISO-8601 strings.

    PyYAML's safe loaders parse unquoted ``YYYY-MM-DD`` and timestamp scalars
    into ``datetime.date`` / ``datetime.datetime``. Tide schemas declare those
    fields as strings, and ``json.dumps`` cannot serialize native date objects.
    """
    if isinstance(value, datetime):
        rendered = value.isoformat()
        if rendered.endswith("+00:00"):
            return rendered[:-6] + "Z"
        return rendered
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    if isinstance(value, dict):
        return {
            stringify_yaml_temporals(key): stringify_yaml_temporals(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [stringify_yaml_temporals(item) for item in value]
    return value


def json_timestamp_default(value: Any) -> str:
    """``json.dumps`` ``default=`` hook for leftover YAML date/time objects."""
    if isinstance(value, (date, time)):
        converted = stringify_yaml_temporals(value)
        if isinstance(converted, str):
            return converted
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


class DuplicateKeyError(yaml.MarkedYAMLError):
    """A mapping repeats a key. Carries the repeated key's position like a parser error."""

    #: Where the repeated key ends, so a diagnostic can underline all of it.
    end_mark: yaml.Mark | None = None

    def __str__(self) -> str:
        mark = self.problem_mark
        return f"{self.problem} at line {mark.line + 1}" if mark else str(self.problem)


@dataclass(frozen=True)
class YamlProblem:
    """Why a YAML document did not parse, and where. Positions are 1-based."""

    problem: str
    line: int | None = None
    column: int | None = None
    #: What the parser was doing (``while parsing a flow sequence``), and where it started.
    context: str | None = None
    context_line: int | None = None
    context_column: int | None = None
    #: Just past the text at fault, when the error spans more than one character.
    end_column: int | None = None

    @property
    def context_note(self) -> str | None:
        """``while parsing a flow sequence that starts at line 8, column 8``."""
        if not self.context:
            return None
        if self.context_line is None or (self.context_line, self.context_column) == (
            self.line,
            self.column,
        ):
            return self.context
        where = f"line {self.context_line}, column {self.context_column}"
        return f"{self.context} that starts at {where}"

    @property
    def message(self) -> str:
        """One line naming the problem and its position, never ``<unicode string>``."""
        text = self.problem
        if self.line is not None:
            text = f"{text} at line {self.line}, column {self.column}"
        note = self.context_note
        return f"{text} ({note})" if note else text


def describe_yaml_error(exc: BaseException) -> YamlProblem:
    """Read the problem and its position out of a PyYAML error.

    PyYAML's own text names the stream ``<unicode string>`` when it parsed a
    string, and spreads the problem over four lines.
    """
    if isinstance(exc, yaml.MarkedYAMLError):
        problem_mark = exc.problem_mark
        context_mark = exc.context_mark
        mark = problem_mark or context_mark
        problem = str(exc.problem or exc.context or type(exc).__name__)
        context = str(exc.context) if exc.problem and exc.context else None
        if context and problem.startswith("but "):
            # "expected a single document in the stream" / "but found another
            # document" reads as one sentence, not as a problem and a context.
            problem, context = f"{context}, {problem}", None
        end_mark = getattr(exc, "end_mark", None)
        end_column = (
            end_mark.column + 1
            if mark is not None and end_mark is not None and end_mark.line == mark.line
            else None
        )
        return YamlProblem(
            problem=problem,
            line=mark.line + 1 if mark else None,
            column=mark.column + 1 if mark else None,
            context=context,
            context_line=context_mark.line + 1 if context_mark and context else None,
            context_column=context_mark.column + 1 if context_mark and context else None,
            end_column=end_column,
        )
    text = str(exc).strip()
    return YamlProblem(problem=text.splitlines()[0] if text else type(exc).__name__)


def _reject_duplicate_keys(root: yaml.Node) -> None:
    """Reject repeated mapping keys, naming the key and its line.

    An alias is the very node its anchor names, so each node is checked once.
    Walking the document as a tree took exponential time on nested aliases (a
    368-byte file took 23 s) and recursed forever on a recursive alias, which
    is rejected here instead: nothing downstream can walk a cyclic document.
    """
    checked: set[yaml.Node] = set()
    # Nodes on the path from the root to the node being expanded.
    open_nodes: set[yaml.Node] = set()
    stack: list[tuple[yaml.Node, bool]] = [(root, False)]
    while stack:
        node, leaving = stack.pop()
        if leaving:
            open_nodes.discard(node)
            checked.add(node)
            continue
        if node in checked:
            continue
        if node in open_nodes:
            raise yaml.YAMLError(f"recursive alias at line {node.start_mark.line + 1}")
        if isinstance(node, yaml.MappingNode):
            seen: set[str] = set()
            for key_node, _value_node in node.value:
                key = key_node.value if isinstance(key_node, yaml.ScalarNode) else repr(key_node)
                if key in seen:
                    error = DuplicateKeyError(
                        problem=f"duplicate key {key!r}", problem_mark=key_node.start_mark
                    )
                    error.end_mark = key_node.end_mark
                    raise error
                seen.add(str(key))
            children = [value_node for _key_node, value_node in node.value]
        elif isinstance(node, yaml.SequenceNode):
            children = list(node.value)
        else:
            checked.add(node)
            continue
        open_nodes.add(node)
        stack.append((node, True))
        # Reversed, so children are checked in document order.
        stack.extend((child, False) for child in reversed(children))


def _construct_timestamp_text(loader: SafeConstructor, node: yaml.ScalarNode) -> Any:
    try:
        return stringify_yaml_temporals(loader.construct_yaml_timestamp(node))
    except ValueError as exc:
        # ``2026-13-45`` matches YAML's timestamp pattern, and ``datetime``
        # refuses it with a bare ValueError. Report it like any other parse
        # problem, at the value, instead of letting it escape as a crash.
        error = ConstructorError(
            problem=f"{node.value!r} is not a valid date ({exc})",
            problem_mark=node.start_mark,
        )
        error.end_mark = node.end_mark
        raise error from exc


class _TideYamlLoader(YamlLoader):  # ty: ignore[unsupported-base]  # libyaml or pure-Python safe loader
    """The safe loader, reading YAML timestamps as ISO-8601 strings.

    Converting while constructing, rather than copying the finished document,
    keeps an aliased node one shared object; the copy expanded every alias and
    grew exponentially with nested ones.
    """


_TideYamlLoader.add_constructor("tag:yaml.org,2002:timestamp", _construct_timestamp_text)


def parse_yaml(text: str) -> Any:
    """Parse YAML text using the fast safe loader when available.

    Timestamps load as ISO-8601 strings (see :func:`stringify_yaml_temporals`).
    """
    loader = _TideYamlLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            # An empty file, or one holding only comments, is no document.
            return None
        _reject_duplicate_keys(node)
        return loader.construct_document(node)
    finally:
        loader.dispose()


def load_yaml(path: Path) -> Any:
    """Load YAML from *path*."""
    return parse_yaml(path.read_text(encoding="utf-8"))


def not_utf8_problem(exc: UnicodeDecodeError) -> str:
    """Why a file that is not UTF-8 text cannot be read, in words, with the byte at fault."""
    byte = exc.object[exc.start : exc.start + 1].hex() if exc.object else ""
    where = f" (byte 0x{byte} at offset {exc.start})" if byte else ""
    return f"the file is not UTF-8 text{where}; save it as UTF-8"


def root_mapping_problem(document: Any) -> str | None:
    """Why a parsed object file is not one mapping, in words; ``None`` when it is."""
    if isinstance(document, dict):
        return None
    if document is None:
        found = "an empty file"
    elif isinstance(document, list):
        found = "a list"
    elif isinstance(document, str):
        found = "a string"
    else:
        found = "a single value"
    return f"expected a mapping at the top of the file, found {found}"


def first_content_span(text: str) -> tuple[int, int, int] | None:
    """``(line, column, end_column)`` of the first line holding YAML content, 1-based.

    Skips blank lines, comments, directives and the ``---`` marker, so a frame
    about the document's root points at where the document starts. ``None``
    for a file with no content.
    """
    for number, raw in enumerate(text.splitlines(), start=1):
        content = raw.split(" #", 1)[0].rstrip()
        stripped = content.lstrip()
        if not stripped or stripped.startswith(("#", "%")) or stripped == "---":
            continue
        column = len(content) - len(stripped) + 1
        return number, column, len(content) + 1
    return None


def load_json(path: Path) -> Any:
    """Load JSON from *path*."""
    return orjson.loads(path.read_bytes())


def parse_json(data: bytes | str) -> Any:
    """Parse JSON bytes or text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return orjson.loads(data)


def dump_json(
    data: Any,
    *,
    indent: bool = False,
    append_newline: bool = True,
    default: Any = None,
) -> bytes:
    """Serialize *data* as JSON bytes."""
    option = orjson.OPT_INDENT_2 if indent else 0
    if default is not None:
        payload = orjson.dumps(data, option=option, default=default)
    else:
        payload = orjson.dumps(data, option=option)
    if append_newline:
        return payload + b"\n"
    return payload


def dump_json_text(
    data: Any,
    *,
    indent: bool = False,
    append_newline: bool = True,
    default: Any = None,
) -> str:
    """Serialize *data* as a JSON string."""
    return dump_json(
        data,
        indent=indent,
        append_newline=append_newline,
        default=default,
    ).decode("utf-8")


def load_toml(path: Path) -> dict[str, Any]:
    """Load TOML from *path*."""
    return tomllib.loads(path.read_text(encoding="utf-8"))


def dump_toml(data: Mapping[str, Any]) -> str:
    """Serialize *data* as TOML text."""
    return tomli_w.dumps(dict(data))


def dump_yaml(
    path: Path,
    data: Mapping[str, Any],
    *,
    dumper: type[yaml.Dumper] | None = None,
) -> None:
    """Write *data* as YAML to *path*, creating parent directories."""
    if dumper is None:
        from opentide.core.files import IndentFullDumper

        dumper = IndentFullDumper
    write_text(path, yaml.dump(dict(data), Dumper=dumper, sort_keys=False))


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text to *path*, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
