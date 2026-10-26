"""Relative documentation backlinks."""

from __future__ import annotations

from unittest.mock import MagicMock

from opentide.documentation.catalog import DocumentationCatalog, SignalRecord
from opentide.documentation.format.generic import GenericFormatter
from opentide.documentation.format.github import GitHubFormatter
from opentide.documentation.markdown.links import (
    heading_anchor,
    object_link,
    page_href,
    page_slug,
    unique_slugs,
    wiki_target,
)
from opentide.documentation.types import DocumentRecord, DocumentScope


def test_wiki_target_joins_folder_and_slug() -> None:
    assert wiki_target(folder="Rules", slug="my-rule") == "Rules/my-rule.md"
    assert page_href(from_folder="Rules", to_folder="Rules", filename="rule.md") == "rule.md"


def test_page_href_cross_folder_uses_parent() -> None:
    assert (
        page_href(from_folder="Rules", to_folder="Objectives", filename="obj.md")
        == "../Objectives/obj.md"
    )


def test_page_href_from_root_index() -> None:
    assert page_href(from_folder="", to_folder="Rules", filename="rule.md") == "Rules/rule.md"


def test_page_href_with_signal_anchor() -> None:
    href = page_href(
        from_folder="Rules",
        to_folder="Objectives",
        filename="obj.md",
        anchor="exec-signal",
    )
    assert href == "../Objectives/obj.md#exec-signal"


def test_object_link_resolves_signal_to_parent_heading() -> None:
    catalog = DocumentationCatalog(
        rules=[],
        objectives=[
            DocumentRecord(
                DocumentScope.objectives,
                "obj-1",
                "Detect Stuff",
                model=object(),
            )
        ],
        threats=[],
        signals=[
            SignalRecord(
                uuid="sig-1",
                name="Exec signal",
                owner_uuid="obj-1",
                owner_name="Detect Stuff",
            )
        ],
    )
    rendered = object_link(
        GitHubFormatter(),
        catalog,
        "sig-1",
        from_folder="rules",
    )
    assert "[Exec signal](../objectives/detect-stuff.md#exec-signal)" in rendered
    assert "`sig-1`" in rendered
    assert heading_anchor("Exec signal") == "exec-signal"


def test_object_link_missing_uuid_is_code() -> None:
    catalog = DocumentationCatalog(rules=[], objectives=[], threats=[])
    assert object_link(GitHubFormatter(), catalog, "missing", from_folder="rules") == "`missing`"


def test_object_link_uses_resolve_name_when_unpaged() -> None:
    catalog = MagicMock(spec=DocumentationCatalog)
    catalog.resolve_signal.return_value = None
    catalog.resolve_record.return_value = None
    catalog.resolve_name.side_effect = lambda uuid: (
        "Cloud Discovery Follow-up" if uuid == "follow" else uuid
    )
    rendered = object_link(GitHubFormatter(), catalog, "follow", from_folder="threats")
    assert rendered == "Cloud Discovery Follow-up (`follow`)"


def _rule(uuid: str, name: str) -> DocumentRecord:
    return DocumentRecord(DocumentScope.rules, uuid, name, model=object())


def test_unique_slugs_suffix_colliding_names_only() -> None:
    """Names that slugify alike used to share one page file."""
    records = unique_slugs(
        [
            _rule("bbbbbbbb-2", "Sentinel-KQL rule"),
            _rule("aaaaaaaa-1", "Sentinel KQL Rule"),
            _rule("cccccccc-3", "Other rule"),
            _rule("dddddddd-4", "Sentinel KQL rule bbbbbbbb"),
        ]
    )
    assert [page_slug(record) for record in records] == [
        "sentinel-kql-rule-bbbbbbbb-1",
        "sentinel-kql-rule",
        "other-rule",
        "sentinel-kql-rule-bbbbbbbb",
    ]
    assert records[0].name == "Sentinel-KQL rule"


def test_page_slug_defaults_to_the_slugified_name() -> None:
    assert page_slug(_rule("u1", "My Rule")) == "my-rule"


def test_github_signal_links_use_githubs_heading_anchor() -> None:
    """GitHub keeps ``-`` and ``_``, drops other punctuation and never collapses hyphens.

    The slug-style anchor (``process-cmd-exe-spawn``) did not match the heading
    GitHub rendered, so a signal link opened the objective page at the top.
    """
    formatter = GitHubFormatter()
    assert formatter.heading_anchor("Exec signal") == "exec-signal"
    assert formatter.heading_anchor("Process - cmd.exe spawn") == "process---cmdexe-spawn"
    assert formatter.heading_anchor("LSASS (v2): read_mem") == "lsass-v2-read_mem"
    assert formatter.heading_anchor("Détection — accès") == "détection--accès"
    assert GenericFormatter().heading_anchor("Process - cmd.exe spawn") == "process-cmd-exe-spawn"
    catalog = DocumentationCatalog(
        rules=[],
        objectives=[_objective("obj-1", "Detect Stuff")],
        threats=[],
        signals=[SignalRecord("sig-1", "Process - cmd.exe spawn", "obj-1", "Detect Stuff")],
    )
    rendered = object_link(formatter, catalog, "sig-1", from_folder="rules")
    assert "(../objectives/detect-stuff.md#process---cmdexe-spawn)" in rendered


def _objective(uuid: str, name: str) -> DocumentRecord:
    return DocumentRecord(DocumentScope.objectives, uuid, name, model=object())
