"""Expand a Sysdig block's own macros and lists as Falco's rule loader does (sysdig-1.0).

Falco macros and lists are global to a ruleset: two rules that defined the same
name would overwrite each other on a tenant. A block's ``macros`` and ``lists``
are therefore private to the rule, and deploy writes them into what it sends,
by the algorithm of Falco's rule loader (``userspace/engine/rule_loader_compiler.cpp``),
so Sysdig receives the expression Falco would compile had the definitions been
loaded on the tenant:

1. Lists are flattened in block order (``compile_list_infos``): an item that
   names an earlier block list is replaced by that list's items.
2. Every block list is resolved, in block order, in the condition and in each
   macro condition, by :func:`resolve_list`, a port of Falco's ``resolve_list``.
   It is textual: it also rewrites occurrences inside quoted strings, as Falco
   does.
3. In exception values, a value (or a member of a value list) equal to a block
   list name becomes the list's items. Sysdig compiles exceptions itself, with
   its own lists, so a block list name anywhere else in a value is refused
   (``sysdig_list_in_value``).
4. A bare identifier in a check position that names a block macro becomes
   ``(<the macro's expanded condition>)``. A macro sees the block macros defined
   before it, and every block list (Falco orders macros, not lists).

Names the block does not define are left as written: they resolve on the tenant.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# --- Falco's operators (libsinsp parser.cpp, Falco rule_loader_cmpop.h) ----------------------

UNARY_OPERATORS = frozenset({"exists"})
NUMERIC_OPERATORS = frozenset({"<=", "<", ">=", ">"})
STRING_OPERATORS = frozenset(
    {
        "==",
        "=",
        "!=",
        "glob",
        "iglob",
        "contains",
        "icontains",
        "bcontains",
        "startswith",
        "bstartswith",
        "endswith",
        "regex",
    }
)
#: ``parser::supported_operators(true)``: operators whose right-hand side is a value list.
LIST_OPERATORS = frozenset({"intersects", "in", "pmatch"})
#: ``parser::supported_operators()``.
FALCO_OPERATORS = UNARY_OPERATORS | NUMERIC_OPERATORS | STRING_OPERATORS | LIST_OPERATORS
#: ``cmpop_supports_modifier``: the operators ``oneof``, ``anyof`` and ``allof`` may follow.
MODIFIABLE_OPERATORS = frozenset(
    {
        "=",
        "==",
        "!=",
        "contains",
        "icontains",
        "bcontains",
        "startswith",
        "bstartswith",
        "endswith",
        "glob",
        "iglob",
        "regex",
    }
)
MODIFIERS = frozenset({"oneof", "anyof", "allof"})
#: Field transformers, and ``val``.
TRANSFORMERS = frozenset(
    {"tolower", "toupper", "b64", "basename", "len", "join", "concat", "getopt", "val"}
)

#: Operators written as words; the token after one is a value.
WORD_OPERATORS = frozenset(op for op in FALCO_OPERATORS if op.isalpha())

#: Words that can never name a block macro or list (``sysdig_definition_name``).
RESERVED_WORDS = frozenset({"and", "or", "not", "in", "exists", "val"}) | WORD_OPERATORS

DEFINITION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: ``resolve_list``'s blanks and delimiters.
BLANKS = " \t\n\r"
DELIMITERS = BLANKS + "(),="

_SYMBOLS = ("!=", "<=", ">=", "==", "=", "<", ">")


class ExpansionError(ValueError):
    """A block's definitions cannot be expanded. ``code`` is the constraint code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def normalize_comp(comp: str) -> str:
    """Falco's ``normalize_comp``: leading and trailing ASCII whitespace stripped."""
    return comp.strip(" \t\r\n")


def is_modified_operator(op: str) -> bool:
    """Falco's ``is_str_operator_with_modifier``: ``<op> oneof|anyof|allof``.

    ``str_to_cmpop_with_modifier`` splits at the first space; the rest must be
    the modifier exactly.
    """
    head, space, modifier = op.partition(" ")
    return bool(space) and head in MODIFIABLE_OPERATORS and modifier in MODIFIERS


def is_exception_operator(op: str) -> bool:
    """A comparison an exception may use: a Falco operator or a modified operator."""
    return op in FALCO_OPERATORS or is_modified_operator(op)


def is_list_comparison(op: str) -> bool:
    """Falco's ``is_operator_for_list``: a list operator, or a modified operator."""
    return op in LIST_OPERATORS or is_modified_operator(op)


def quote_item(item: str) -> str:
    """Falco's ``quote_item``: double-quoted when it holds a space and is not quoted."""
    if " " in item and item[0] not in "\"'":
        return f'"{item}"'
    return item


def item_text(item: object) -> str:
    """A list or exception item as YAML gives it to Falco: its text."""
    if isinstance(item, bool):
        return "true" if item else "false"
    return str(item)


def resolve_list(condition: str, name: str, items: Sequence[str]) -> tuple[str, bool]:
    """Falco's ``resolve_list``, ported verbatim: *name* replaced by *items* in *condition*.

    An occurrence counts only with a delimiter on each side (the start or end of
    the text, a blank, ``(``, ``)``, ``,`` or ``=``). The blanks around it are
    consumed, and it becomes ``" " + items + " "`` (no leading blank at the
    start of the text). An empty list removes one comma next to it, the left one
    first. Returns the new condition and whether the list was used.
    """
    cnd = condition
    used = False
    start = cnd.find(name)
    while start != -1:
        end = start + len(name)
        if (start == 0 or cnd[start - 1] in DELIMITERS) and (
            end >= len(cnd) or cnd[end] in DELIMITERS
        ):
            while start > 0 and cnd[start - 1] in BLANKS:
                start -= 1
            while end < len(cnd) and cnd[end] in BLANKS:
                end += 1
            sub = ", ".join(quote_item(item) for item in items)
            if not sub:
                if start > 0 and cnd[start - 1] == ",":
                    start -= 1
                elif end < len(cnd) and cnd[end] == ",":
                    end += 1
            new = ""
            if start > 0:
                new += cnd[:start] + " "
            new += sub + " "
            if end <= len(cnd):
                new += cnd[end:]
            cnd = new
            start += len(sub) + 1
            used = True
        start = cnd.find(name, start + 1)
    return cnd, used


def occurs(text: str, name: str) -> bool:
    """Whether :func:`resolve_list` would replace an occurrence of *name* in *text*."""
    start = text.find(name)
    while start != -1:
        end = start + len(name)
        if (start == 0 or text[start - 1] in DELIMITERS) and (
            end >= len(text) or text[end] in DELIMITERS
        ):
            return True
        start = text.find(name, start + 1)
    return False


def join_lines(text: str) -> str:
    """Multiline YAML text as one line: each line stripped, joined by single spaces."""
    return " ".join(line.strip() for line in text.splitlines() if line.strip())


# --- the condition tokenizer (macros only) ----------------------------------------------------


@dataclass(frozen=True)
class Token:
    kind: str  # "space", "string", "open", "close", "comma", "symbol", "word"
    text: str


def tokenize(text: str) -> list[Token]:
    """Split a Falco condition into tokens that keep every character of *text*."""
    tokens: list[Token] = []
    i = 0
    n = len(text)
    while i < n:
        char = text[i]
        if char in BLANKS:
            j = i
            while j < n and text[j] in BLANKS:
                j += 1
            tokens.append(Token("space", text[i:j]))
            i = j
        elif char in "\"'":
            j = i + 1
            while j < n and text[j] != char:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            tokens.append(Token("string", text[i:j]))
            i = j
        elif char == "(":
            tokens.append(Token("open", char))
            i += 1
        elif char == ")":
            tokens.append(Token("close", char))
            i += 1
        elif char == ",":
            tokens.append(Token("comma", char))
            i += 1
        elif symbol := next((s for s in _SYMBOLS if text.startswith(s, i)), None):
            tokens.append(Token("symbol", symbol))
            i += len(symbol)
        else:
            j = i
            depth = 0
            # A field argument (`proc.aname[2]`, `proc.env["HOME"]`) stays in its word.
            while j < n:
                c = text[j]
                if c == "[":
                    depth += 1
                elif c == "]" and depth:
                    depth -= 1
                elif depth == 0 and (c in BLANKS or c in "(),\"'=<>!"):
                    break
                j += 1
            if j == i:  # a lone "!" or similar: keep it, never loop
                j = i + 1
            tokens.append(Token("word", text[i:j]))
            i = j
    return tokens


def _closing(tokens: Sequence[Token], start: int) -> int:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].kind == "open":
            depth += 1
        elif tokens[index].kind == "close":
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def _call_end(tokens: Sequence[Token], i: int) -> int | None:
    """The index of the ``)`` closing a call ``word(`` at *i*, when *i* starts one."""
    if i + 1 < len(tokens) and tokens[i + 1].kind == "open":
        return _closing(tokens, i + 1)
    return None


def substitute_macros(text: str, resolve: Callable[[str], str | None]) -> str:
    """*text* with each bare identifier in a check position replaced by ``resolve(name)``.

    ``resolve`` returns the replacement, or ``None`` to keep the name. Values
    (after an operator: a word, a string, a value list, ``val(...)`` or a
    transformer), field names, field arguments, transformer calls on the
    left-hand side, and quoted strings are never touched.
    """
    tokens = tokenize(text)
    out: list[str] = []
    expect = "check"  # "check", "operator" or "value"
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.kind == "space":
            out.append(token.text)
            i += 1
            continue
        if expect == "value":
            if token.kind == "word" and token.text in MODIFIERS:
                out.append(token.text)
                i += 1
                continue
            end = _closing(tokens, i) if token.kind == "open" else None
            if token.kind == "word":
                end = _call_end(tokens, i)
            last = i if end is None else end
            out.extend(t.text for t in tokens[i : last + 1])
            i = last + 1
            expect = "check"
            continue
        if expect == "operator":
            if token.kind == "symbol" or (token.kind == "word" and token.text in WORD_OPERATORS):
                out.append(token.text)
                expect = "check" if token.text in UNARY_OPERATORS else "value"
                i += 1
                continue
            expect = "check"
        if token.kind == "word":
            if token.text in ("and", "or", "not"):
                out.append(token.text)
                i += 1
                continue
            end = _call_end(tokens, i) if token.text in TRANSFORMERS else None
            if end is not None:
                out.extend(t.text for t in tokens[i : end + 1])
                i = end + 1
                expect = "operator"
                continue
            if "." in token.text:  # a field
                out.append(token.text)
                expect = "operator"
                i += 1
                continue
            replacement = resolve(token.text)
            out.append(token.text if replacement is None else replacement)
            i += 1
            continue
        out.append(token.text)
        i += 1
    return "".join(out)


def check_position_names(text: str) -> list[str]:
    """The bare identifiers in check positions of *text*: the macros it uses."""
    names: list[str] = []

    def record(name: str) -> str | None:
        names.append(name)
        return None

    substitute_macros(text, record)
    return names


# --- the block's definitions ------------------------------------------------------------------


class Expander:
    """Expands one block's macros and lists, in block order."""

    def __init__(
        self,
        macros: Mapping[str, str] | None = None,
        lists: Mapping[str, Sequence[object]] | None = None,
    ) -> None:
        self.macro_order = list(macros or {})
        self.list_order = list(lists or {})
        self.lists = self._flatten(lists or {})
        self.macros: dict[str, str] = {}
        for index, (name, condition) in enumerate((macros or {}).items()):
            visible = self.macro_order[:index]
            text = self.resolve_lists(join_lines(condition))
            used = [n for n in check_position_names(text) if n in self.macro_order]
            later = [n for n in used if n not in visible]
            if later:
                raise ExpansionError(
                    "sysdig_definition_order",
                    f"macro {name!r} uses {', '.join(map(repr, dict.fromkeys(later)))}, "
                    "which is not defined before it in the block",
                )
            self.macros[name] = self._substitute(text, frozenset(visible))

    def _flatten(self, lists: Mapping[str, Sequence[object]]) -> dict[str, list[str]]:
        """``compile_list_infos``: an item naming an earlier block list is its items."""
        order = list(lists)
        flat: dict[str, list[str]] = {}
        for index, (name, raw) in enumerate(lists.items()):
            items: list[str] = []
            for item in raw:
                text = item_text(item)
                if text in flat:
                    items.extend(flat[text])
                    continue
                if text in order[index:]:
                    raise ExpansionError(
                        "sysdig_definition_order",
                        f"list {name!r} names {text!r}, which is not defined before it "
                        "in the block",
                    )
                items.append(text)
            flat[name] = items
        return flat

    def _substitute(self, text: str, visible: frozenset[str]) -> str:
        """*text* with each visible block macro written in, in parentheses."""

        def macro(name: str) -> str | None:
            return f"({self.macros[name]})" if name in visible else None

        return substitute_macros(text, macro)

    def resolve_lists(self, text: str) -> str:
        """Every block list resolved in *text*, in block order (Falco's ``parse_condition``)."""
        for name in self.list_order:
            text, _ = resolve_list(text, name, self.lists[name])
        return text

    def expand(self, condition: str) -> str:
        """*condition* on one line, with the block's lists and macros written in."""
        return self._substitute(self.resolve_lists(join_lines(condition)), frozenset(self.macros))

    # --- exceptions ---------------------------------------------------------------------------

    def _list_in(self, value: object) -> str | None:
        """The block list whose name occurs inside *value*, by ``resolve_list``'s rule."""
        text = item_text(value)
        return next((name for name in self.list_order if occurs(text, name)), None)

    def _members(self, values: Iterable[object], where: str) -> list[Any]:
        """A value list with block list names spliced in."""
        out: list[Any] = []
        for value in values:
            text = item_text(value)
            if not isinstance(value, (list, dict)) and text in self.lists:
                out.extend(self.lists[text])
                continue
            if (name := self._list_in(value)) is not None:
                raise _list_in_value(name, where)
            out.append(value)
        return out

    def exception(self, entry: Mapping[str, Any]) -> dict[str, Any]:
        """An exception as Sysdig receives it: comps normalized, block lists expanded."""
        name = str(entry.get("name"))
        fields = entry.get("fields")
        comps = entry.get("comps")
        values = entry.get("values")
        out: dict[str, Any] = {"name": name, "fields": fields}
        where = f"exception {name!r}"
        if isinstance(fields, str):
            if comps is not None:
                out["comps"] = normalize_comp(str(comps))
            if values is not None:
                out["values"] = self._members(values, where)
            return out
        comp_list = (
            [normalize_comp(str(c)) for c in comps]
            if isinstance(comps, list)
            else ["="] * len(fields or [])
        )
        if comps is not None:
            out["comps"] = comp_list
        if values is None:
            return out
        rows: list[Any] = []
        for row in values:
            if not isinstance(row, list):
                rows.append(row)
                continue
            new_row: list[Any] = []
            for comp, item in zip(comp_list, row, strict=False):
                if isinstance(item, list):
                    new_row.append(self._members(item, where))
                    continue
                text = item_text(item)
                if text in self.lists:
                    if not is_list_comparison(comp):
                        raise _list_in_value(text, where)
                    new_row.append(list(self.lists[text]))
                    continue
                if (found := self._list_in(item)) is not None:
                    raise _list_in_value(found, where)
                new_row.append(item)
            rows.append(new_row)
        out["values"] = rows
        return out


def _list_in_value(name: str, where: str) -> ExpansionError:
    return ExpansionError(
        "sysdig_list_in_value",
        f"{where}: the block list {name!r} appears in a value where Falco's expansion would "
        "not produce a value list",
    )


def check_definitions(
    macros: Mapping[str, str],
    lists: Mapping[str, Sequence[object]],
    conditions: Iterable[str],
    exceptions: Iterable[Mapping[str, Any]] = (),
) -> None:
    """Expand the block; raise ``sysdig_definition_order`` or ``sysdig_list_in_value``."""
    expander = Expander(macros, lists)
    for condition in conditions:
        expander.expand(condition)
    for entry in exceptions:
        expander.exception(entry)
