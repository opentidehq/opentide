"""Page layout and the text helpers every section uses."""

from __future__ import annotations

import pytest

from opentide.documentation.format.factory import formatter_for
from opentide.documentation.markdown.page import (
    GENERATED_NOTICE,
    Page,
    key_value_table,
    section,
)
from opentide.documentation.markdown.text import (
    first_sentence,
    inline_code,
    stringify,
    strip_citations,
    table_cell,
    truncate,
)
from opentide.documentation.types import DocumentFlavor


def _page(flavor: DocumentFlavor, count: int = 4) -> Page:
    page = Page(formatter_for(flavor), "Rule")
    page.add_lead("Lead text.")
    for index in range(count):
        page.add(section(f"Part {index}", f"Body {index}."))
    return page


def test_layout_is_title_lead_contents_then_sections() -> None:
    page = _page(DocumentFlavor.github)
    page.add(section("Part 0", "Repeated title.", children=[section("Child", "Nested.")]))
    text = page.render()
    assert text.startswith(
        "# Rule\n\nLead text.\n\n**On this page:** [Part 0](#part-0) · [Part 1](#part-1) · "
    )
    # A repeated heading gets the anchor GitHub gives it.
    assert "[Part 3](#part-3) · [Part 0](#part-0-1)\n" in text
    assert (
        "\n## Part 3\n\nBody 3.\n\n## Part 0\n\nRepeated title.\n\n### Child\n\nNested.\n" in text
    )
    assert text.endswith("Nested.\n\n" + GENERATED_NOTICE + "\n")


def test_breadcrumb_sits_above_the_title_and_below_front_matter() -> None:
    formatter = formatter_for(DocumentFlavor.gitlab)
    plain = Page(formatter, "Rule", breadcrumb="[Catalogue](../README)").render()
    assert plain.startswith("[Catalogue](../README)\n\n# Rule\n")
    framed = Page(formatter, "Rule", frontmatter=True, breadcrumb="[Catalogue](../README)").render()
    assert framed.startswith("---\ntitle: Rule\n---\n\n[Catalogue](../README)\n")


@pytest.mark.parametrize("flavor", [DocumentFlavor.gitlab, DocumentFlavor.azure_devops])
def test_wiki_flavors_use_their_native_contents(flavor: DocumentFlavor) -> None:
    text = _page(flavor).render()
    assert "[[_TOC_]]" in text
    assert "On this page" not in text


def test_short_pages_have_no_contents() -> None:
    assert "On this page" not in _page(DocumentFlavor.github, count=3).render()


def test_empty_sections_and_children_are_dropped() -> None:
    page = Page(formatter_for(DocumentFlavor.generic), "T")
    page.add(section("Empty", "", children=[section("Also empty", "  ")]))
    page.add(None)
    page.add(section("Parent", children=[section("Kept", "x"), section("Gone", "")]))
    text = page.render()
    assert "Empty" not in text and "Gone" not in text
    assert "## Parent\n\n### Kept\n\nx\n" in text


def test_frontmatter_replaces_the_title() -> None:
    page = Page(formatter_for(DocumentFlavor.gitlab), "Rule", frontmatter=True)
    assert page.render().startswith("---\ntitle: Rule\n---\n")


def test_key_value_table_skips_missing_values() -> None:
    formatter = formatter_for(DocumentFlavor.github)
    table = key_value_table(formatter, [("A", "1"), ("B", ""), ("C", "-")], headers=("K", "V"))
    assert table == "| K | V |\n| --- | --- |\n| A | 1 |\n"
    assert key_value_table(formatter, [("B", "")], headers=("K", "V")) == ""


def test_table_cell_and_inline_code() -> None:
    assert table_cell("a | b\nc") == "a \\| b c"
    assert table_cell("") == "-"
    assert inline_code("plain") == "`plain`"
    assert inline_code("has ` tick") == "``has ` tick``"
    assert inline_code("`edge`") == "`` `edge` ``"
    assert inline_code(None) == ""


def test_stringify_writes_yaml_spellings_never_reprs() -> None:
    assert stringify(True) == "true"
    assert stringify(("a", "b")) == "a, b"
    assert stringify(frozenset({"b", "a"})) == "a, b"
    assert stringify(None) == ""


def test_first_sentence_drops_citations_and_keeps_abbreviations() -> None:
    text = "Adversaries may abuse things, e.g. shells.(Citation: X 2020) Second sentence. Third."
    assert strip_citations("A (Citation: B) C") == "A C"
    assert first_sentence(text) == "Adversaries may abuse things, e.g. shells."
    assert first_sentence("") == ""


def test_truncate_cuts_on_a_word() -> None:
    assert truncate("alpha beta gamma", 12) == "alpha beta…"
    assert truncate("short", 12) == "short"
