"""Page layout: one title, an overview, a contents list, ordered sections.

Every object page is assembled here, so the three families share one layout
and one set of spacing rules. A renderer declares sections in reading order;
empty sections are dropped, and the contents list is built from the sections
that remain, with the anchors the flavor gives their headings.

A page reads, top to bottom:

1. the title (or GitLab wiki front matter);
2. the lead: a short summary line and the overview table;
3. the contents list, when the page has enough sections to need one;
4. the sections, each a level-2 heading with optional level-3 children.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.markdown.text import table_cell

#: A page with fewer sections than this gets no contents list.
CONTENTS_THRESHOLD = 4


@dataclass(frozen=True)
class Section:
    """A heading and its body. Children are rendered one level deeper."""

    title: str
    body: str = ""
    children: tuple[Section, ...] = ()
    #: Listed in the page's contents.
    in_contents: bool = True

    def is_empty(self) -> bool:
        return not self.body.strip() and all(child.is_empty() for child in self.children)


def section(
    title: str, *parts: str, children: Iterable[Section] = (), in_contents: bool = True
) -> Section:
    """A :class:`Section` whose body is *parts* joined as blocks."""
    kept = tuple(child for child in children if not child.is_empty())
    return Section(title, join(parts), kept, in_contents)


def join(parts: Iterable[str]) -> str:
    """Markdown blocks separated by exactly one blank line."""
    return "\n\n".join(part.strip("\n") for part in parts if part and part.strip())


def key_value_table(
    formatter: MarkdownFormatter, rows: Iterable[tuple[str, str]], *, headers: tuple[str, str]
) -> str:
    """A two-column table, skipping rows without a value (empty, or the ``-`` placeholder)."""
    kept = [[label, value] for label, value in rows if value and value.strip() not in {"", "-"}]
    if not kept:
        return ""
    return formatter.table(list(headers), kept)


@dataclass
class Page:
    """An object page under construction."""

    formatter: MarkdownFormatter
    title: str
    #: Write the title as front matter (GitLab wiki UUID permalinks).
    frontmatter: bool = False
    lead: list[str] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)

    def add_lead(self, *parts: str) -> Page:
        """Content shown under the title, before the contents list."""
        self.lead.extend(part for part in parts if part and part.strip())
        return self

    def add(self, item: Section | None) -> Page:
        """Append *item* unless it is empty."""
        if item is not None and not item.is_empty():
            self.sections.append(item)
        return self

    def render(self) -> str:
        """The page's Markdown, ending in one newline."""
        title = (
            self.formatter.frontmatter(self.title)
            if self.frontmatter
            else self.formatter.heading(1, self.title)
        )
        blocks = [title, *self.lead, self._contents()]
        anchors = _Anchors(self.formatter)
        anchors.claim(self.title)
        for item in self.sections:
            blocks.append(self._section(item, level=2, anchors=anchors))
        return join(blocks) + "\n"

    def _section(self, item: Section, *, level: int, anchors: _Anchors) -> str:
        anchors.claim(item.title)
        parts = [self.formatter.heading(level, item.title), item.body]
        parts.extend(
            self._section(child, level=level + 1, anchors=anchors) for child in item.children
        )
        return join(parts)

    def _contents(self) -> str:
        listed = [item for item in self.sections if item.in_contents]
        if len(listed) < CONTENTS_THRESHOLD:
            return ""
        native = self.formatter.table_of_contents()
        if native.strip():
            return native
        anchors = _Anchors(self.formatter)
        anchors.claim(self.title)
        lines = ["**Contents**", ""]
        for item in self.sections:
            anchor = anchors.claim(item.title)
            if item.in_contents:
                lines.append(f"- {self.formatter.link(table_cell(item.title), f'#{anchor}')}")
            for child in item.children:
                child_anchor = anchors.claim(child.title)
                if item.in_contents and child.in_contents:
                    link = self.formatter.link(table_cell(child.title), f"#{child_anchor}")
                    lines.append(f"  - {link}")
        return "\n".join(lines) + "\n"


class _Anchors:
    """Heading anchors as renderers assign them: a repeated heading gets ``-1``, ``-2``."""

    def __init__(self, formatter: MarkdownFormatter) -> None:
        self._formatter = formatter
        self._seen: dict[str, int] = {}

    def claim(self, title: str) -> str:
        base = self._formatter.heading_anchor(title)
        count = self._seen.get(base, 0)
        self._seen[base] = count + 1
        return base if count == 0 else f"{base}-{count}"
