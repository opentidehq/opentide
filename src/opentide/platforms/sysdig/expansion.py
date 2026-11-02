"""Expand a Sysdig block's own macros and lists into its Falco condition (sysdig-1.0, Expansion).

Falco macros and lists are global to a ruleset: two rules that defined the same
name would overwrite each other on a tenant. A block's ``macros`` and ``lists``
are therefore private to the rule, and deploy writes them into the condition:

1. a bare name in condition position that is a block macro becomes ``(<its
   condition, expanded>)``;
2. a bare name inside a value list (after ``in``, ``intersects`` or ``pmatch``)
   that is a block list becomes the list's items, expanded, joined by ``, ``;
3. expansion recurses through block definitions and leaves every other name as
   written, to resolve on the tenant;
4. quoted strings, field names, field arguments, and the value after a
   comparison operator are never expanded.

The tokenizer is lexical, not a Falco parser: it only has to tell those
positions apart. The analysis engine parses the condition.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

#: Operators that take a parenthesised value list.
LIST_OPERATORS = frozenset({"in", "intersects", "pmatch"})

#: Comparison operators written as words; the next word is a value.
WORD_COMPARISONS = frozenset(
    {
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

#: Comparison operators written as symbols.
SYMBOL_COMPARISONS = frozenset({"=", "==", "!=", "<", "<=", ">", ">="})

#: Every comparison operator an exception's ``comps`` may name (sysdig-1.0).
EXCEPTION_OPERATORS = frozenset(
    {
        "=",
        "!=",
        "<",
        "<=",
        ">",
        ">=",
        "contains",
        "icontains",
        "bcontains",
        "startswith",
        "bstartswith",
        "endswith",
        "glob",
        "iglob",
        "in",
        "intersects",
        "pmatch",
        "regex",
    }
)

#: Words that can never name a block macro or list (``sysdig_definition_name``).
RESERVED_WORDS = (
    frozenset({"and", "or", "not", "exists", "val"}) | WORD_COMPARISONS | LIST_OPERATORS
)

DEFINITION_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_SYMBOLS = ("!=", "<=", ">=", "==", "=", "<", ">")


class ExpansionError(ValueError):
    """A block's definitions cannot be expanded. ``code`` is the constraint code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


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
        if char.isspace():
            j = i
            while j < n and text[j].isspace():
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
            # A field argument (`proc.aname[2]`, `evt.arg[0]`) stays in its word.
            while j < n:
                c = text[j]
                if c == "[":
                    depth += 1
                elif c == "]" and depth:
                    depth -= 1
                elif depth == 0 and (c.isspace() or c in "(),\"'=<>!"):
                    break
                j += 1
            if j == i:  # a lone "!" or similar: keep it, never loop
                j = i + 1
            tokens.append(Token("word", text[i:j]))
            i = j
    return tokens


def join_lines(text: str) -> str:
    """Multiline YAML text as one line: each line stripped, joined by single spaces."""
    return " ".join(line.strip() for line in text.splitlines() if line.strip())


def format_item(item: object) -> str:
    """A list item as Falco reads it: quoted when it holds a space, comma, parenthesis or quote."""
    text = str(item)
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text
    if any(c.isspace() or c in ",()\"'" for c in text):
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return text


class Expander:
    """Expands one block's macros and lists."""

    def __init__(
        self,
        macros: Mapping[str, str] | None = None,
        lists: Mapping[str, Sequence[object]] | None = None,
    ) -> None:
        self.macros = {name: join_lines(cond) for name, cond in (macros or {}).items()}
        self.lists = {name: list(items) for name, items in (lists or {}).items()}
        self._macro_cache: dict[str, str] = {}
        self._list_cache: dict[str, list[str]] = {}

    # --- lists ---------------------------------------------------------------

    def list_items(self, name: str, stack: tuple[str, ...] = ()) -> list[str]:
        if name in stack:
            raise _cycle(stack, name)
        cached = self._list_cache.get(name)
        if cached is not None:
            return cached
        items: list[str] = []
        for item in self.lists[name]:
            if isinstance(item, str) and item in self.lists:
                items.extend(self.list_items(item, (*stack, name)))
            else:
                items.append(format_item(item))
        self._list_cache[name] = items
        return items

    # --- macros --------------------------------------------------------------

    def macro(self, name: str, stack: tuple[str, ...] = ()) -> str:
        if name in stack:
            raise _cycle(stack, name)
        cached = self._macro_cache.get(name)
        if cached is None:
            cached = self._expand(self.macros[name], (*stack, name))
            self._macro_cache[name] = cached
        return cached

    # --- conditions ----------------------------------------------------------

    def expand(self, condition: str) -> str:
        """*condition* with the block's macros and lists written in, on one line."""
        return self._expand(join_lines(condition), ())

    def _expand(self, text: str, stack: tuple[str, ...]) -> str:
        tokens = tokenize(text)
        out: list[str] = []
        i = 0
        expect_value = False
        while i < len(tokens):
            token = tokens[i]
            if token.kind == "space":
                out.append(token.text)
                i += 1
                continue
            if token.kind == "word" and token.text in LIST_OPERATORS:
                out.append(token.text)
                i += 1
                # Copy the spaces, then a value list if one follows.
                while i < len(tokens) and tokens[i].kind == "space":
                    out.append(tokens[i].text)
                    i += 1
                if i < len(tokens) and tokens[i].kind == "open":
                    end = _closing(tokens, i)
                    out.append(self._value_list(tokens[i : end + 1], stack))
                    i = end + 1
                expect_value = False
                continue
            if token.kind == "symbol":
                out.append(token.text)
                expect_value = token.text in SYMBOL_COMPARISONS
                i += 1
                continue
            if token.kind == "word":
                if token.text in WORD_COMPARISONS:
                    out.append(token.text)
                    expect_value = True
                elif expect_value:
                    out.append(token.text)
                    expect_value = False
                elif token.text in self.macros:
                    out.append(f"({self.macro(token.text, stack)})")
                else:
                    out.append(token.text)
                i += 1
                continue
            # strings, parentheses, commas
            if token.kind == "string":
                expect_value = False
            out.append(token.text)
            i += 1
        return "".join(out)

    def _value_list(self, tokens: Sequence[Token], stack: tuple[str, ...]) -> str:
        """``( … )`` with block lists expanded; untouched when it names none."""
        inner = tokens[1:-1]
        items: list[list[Token]] = [[]]
        for token in inner:
            if token.kind == "comma":
                items.append([])
            else:
                items[-1].append(token)
        names = [_item_name(item) for item in items]
        if not any(name is not None and name in self.lists for name in names):
            return "".join(t.text for t in tokens)
        written: list[str] = []
        for item, name in zip(items, names, strict=True):
            if name is not None and name in self.lists:
                written.extend(self.list_items(name, stack))
                continue
            text = "".join(t.text for t in item).strip()
            if text:
                written.append(text)
        return "(" + ", ".join(written) + ")"


def _item_name(item: Sequence[Token]) -> str | None:
    words = [t for t in item if t.kind != "space"]
    if len(words) == 1 and words[0].kind == "word":
        return words[0].text
    return None


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


def _cycle(stack: tuple[str, ...], name: str) -> ExpansionError:
    path = " -> ".join((*stack[stack.index(name) :], name))
    return ExpansionError(
        "sysdig_definition_cycle", f"block macros and lists reference themselves: {path}"
    )


def check_cycles(
    macros: Mapping[str, str], lists: Mapping[str, Sequence[object]], conditions: Iterable[str]
) -> None:
    """Expand every definition and *conditions*; raise ``sysdig_definition_cycle`` on a loop."""
    expander = Expander(macros, lists)
    for name in expander.lists:
        expander.list_items(name)
    for name in expander.macros:
        expander.macro(name)
    for condition in conditions:
        expander.expand(condition)
