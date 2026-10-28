"""The pages behind ``opentide explain <code>``.

One Markdown page per diagnostic code and per ``failure.code`` lives in
``opentide/data/diagnostics/``: a ``# <code>`` heading, a one-sentence summary,
then ``## Example`` and ``## How to fix``. ``docs/cli/diagnostics.md`` is generated from them by
:func:`reference_markdown` (``scripts/build/render_diagnostics_docs.py``).

The analysis engine's codes (``kql_parse_error``, ...) get a page too, built
from the engine's own sentence (:func:`engine_page`), so a code the engine
adds is explained without a file here. A file of the same name wins.
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
    """Every code that has a page, the engine's included, sorted."""
    from opentide.analysis import engine_codes

    return sorted({path.stem for path in pages_root().glob("*.md")} | set(engine_codes()))


def load_page(code: str) -> ExplainPage | None:
    """The page for *code* (in any case), or ``None`` when there is none."""
    code = code.strip().lower()
    if not code or code != Path(code).name:
        return None
    path = pages_root() / f"{code}.md"
    if not path.is_file():
        return engine_page(code)
    markdown = path.read_text(encoding="utf-8")
    return ExplainPage(code=code, summary=_summary(markdown), markdown=markdown)


#: Engine codes that are about a Tide object, not a query, and where they show.
_OBJECT_CODES = frozenset({"filename_slug", "missing_author", "missing_organisation"})
#: Elastic block advisories (elastic-1.0): about the rule block's settings.
_ELASTIC_ADVISORIES = frozenset(
    {
        "lookback_zero",
        "lookback_long",
        "threshold_lookback",
        "risk_band",
        "technique_not_enterprise",
    }
)


def engine_page(code: str) -> ExplainPage | None:
    """A page for an analysis-engine code, from the engine's sentence; ``None`` for another code."""
    from opentide.analysis import describe
    from opentide.cli.ui.diagnostics import engine_reference

    sentence = describe(code)
    if sentence is None:
        return None
    reference = engine_reference(code)
    if reference is not None:
        language, url = reference
        where = (
            f"Reported by the analysis engine in a {language} query, at the place in the query: "
            "`opentide validate query`, `opentide validate --deep`, `opentide lsp check` and "
            "an editor running `opentide lsp start` show it."
        )
        example = "opentide validate query"
        fix = (
            "Change the query where the frame points, then run `opentide validate query` again "
            f"(`--file` for one rule). The [{language} reference]({url}) describes the syntax "
            "and the commands the engine checks against."
        )
    elif code in _ELASTIC_ADVISORIES:
        where = (
            "Reported by the analysis engine on an Elastic rule block (elastic-1.0): "
            "`opentide lsp check` and an editor running `opentide lsp start` show it, and "
            "`opentide validate query --platform elastic --live` checks the same settings."
        )
        example = "opentide lsp check objects/rules"
        fix = "Change the block's setting the frame points at, then run `opentide lsp check` again."
    else:
        scope = "a Tide object" if code in _OBJECT_CODES else "an object file"
        where = (
            f"Reported by the analysis engine for {scope}: `opentide lsp check` and an editor "
            "running `opentide lsp start` show it. `opentide validate` and `opentide lint` "
            "are the authority for objects and may name the same problem with their own code."
        )
        example = "opentide lsp check objects/rules"
        fix = "Change the file where the frame points, then run `opentide lsp check` again."
    markdown = (
        f"# {code}\n\n{sentence}\n\n{where}\n\n## Example\n\n```text\n{example}\n```\n\n"
        f"## How to fix\n\n{fix}\n"
    )
    return ExplainPage(code=code, summary=sentence, markdown=markdown)


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
        source = page.markdown.rstrip("\n").splitlines()
        for index, line in enumerate(source):
            if line.startswith("```"):
                in_fence = not in_fence
                following = source[index + 1] if index + 1 < len(source) else ""
                if in_fence and line == "```text" and not following.startswith("opentide "):
                    # Output an example shows, not a command the docs check could run.
                    line = "```text illustrative"
            if not in_fence and line.startswith("#"):
                line = "#" + line
            lines.append(line)
    return "\n".join(lines) + "\n"
