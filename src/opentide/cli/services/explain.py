"""The pages behind ``opentide explain <code>``.

One Markdown page per diagnostic code and per ``failure.code`` lives in ``opentide/data/diagnostics/``:
a ``# <code>`` heading, a one-sentence summary, then ``## Example`` and
``## How to fix``. ``docs/cli/diagnostics.md`` is generated from them by
:func:`reference_markdown` (``scripts/build/render_diagnostics_docs.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from opentide.package.paths import bundled_data_root

#: Where the generated reference lives, relative to the repository root.
REFERENCE_PAGE = Path("docs", "cli", "diagnostics.md")


def pages_root() -> Path:
    return bundled_data_root() / "diagnostics"


@dataclass(frozen=True)
class ExplainPage:
    code: str
    #: The first paragraph: what the code means, in one sentence.
    summary: str
    markdown: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "meaning": self.summary, "markdown": self.markdown}


def diagnostic_codes() -> list[str]:
    """Every code that has a page, sorted."""
    return sorted(path.stem for path in pages_root().glob("*.md"))


def load_page(code: str) -> ExplainPage | None:
    """The page for *code* (in any case), or ``None`` when there is none."""
    code = code.strip().lower()
    if not code or code != Path(code).name:
        return None
    path = pages_root() / f"{code}.md"
    if not path.is_file():
        return None
    markdown = path.read_text(encoding="utf-8")
    return ExplainPage(code=code, summary=_summary(markdown), markdown=markdown)


def _summary(markdown: str) -> str:
    paragraphs = [block.strip() for block in markdown.split("\n\n") if block.strip()]
    for block in paragraphs:
        if not block.startswith("#"):
            return " ".join(block.split())
    return ""


def all_pages() -> list[ExplainPage]:
    return [page for code in diagnostic_codes() if (page := load_page(code)) is not None]


def reference_markdown() -> str:
    """``docs/cli/diagnostics.md``: every page, with its headings one level down."""
    lines = [
        "---",
        "title: Diagnostic codes",
        "description: What each opentide diagnostic code means, an example, and how to fix it.",
        "---",
        "",
        "<!-- Generated from src/opentide/data/diagnostics/ by",
        "     scripts/build/render_diagnostics_docs.py. Edit the pages there. -->",
        "",
        "# Diagnostic codes",
        "",
        "Every finding `opentide validate` and `opentide lint` report carries a stable `code`, "
        "and every command that fails sets a `failure.code` "
        "([JSON output](./json-output.md#failure-codes)). "
        "`opentide explain <code>` prints the page for either; this reference collects them all. "
        "`opentide explain` with no code lists the codes.",
        "",
        "| Code | Meaning |",
        "|------|---------|",
    ]
    pages = all_pages()
    lines.extend(f"| [`{page.code}`](#{page.code}) | {page.summary} |" for page in pages)
    for page in pages:
        lines.append("")
        in_fence = False
        for line in page.markdown.rstrip("\n").splitlines():
            if line.startswith("```"):
                in_fence = not in_fence
            if not in_fence and line.startswith("#"):
                line = "#" + line
            lines.append(line)
    return "\n".join(lines) + "\n"
