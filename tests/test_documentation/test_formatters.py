from __future__ import annotations

from opentide.documentation.format.azure_devops import AzureDevOpsFormatter
from opentide.documentation.format.generic import GenericFormatter
from opentide.documentation.format.github import GitHubFormatter
from opentide.documentation.format.gitlab import GitLabFormatter


def test_github_page_filename_uses_slug() -> None:
    assert GitHubFormatter().page_filename("my-rule", "uuid-1") == "my-rule.md"


def test_gitlab_strike_and_index_table() -> None:
    formatter = GitLabFormatter()
    assert formatter.strike("x") == "[-x-]"
    assert formatter.wiki_link("Rule", "Rules/my-rule.md") == "[Rule](Rules/my-rule)"
    table = formatter.index_table(["A"], [["B"]])
    assert "json:table" in table
    assert '"fields"' in table
    assert '"items"' in table


def test_azure_flowchart_downgrade_and_toc() -> None:
    formatter = AzureDevOpsFormatter()
    rendered = formatter.diagram_flowchart("flowchart TD\nA ----> B")
    assert rendered.startswith("graph TD")
    assert "-->" in rendered
    assert "---->" not in rendered
    assert formatter.table_of_contents() == "[[_TOC_]]\n"
    assert formatter.mermaid_fence("graph TD") == "::: mermaid\ngraph TD\n:::\n"


def test_generic_mermaid_fence() -> None:
    assert "```mermaid" in GenericFormatter().mermaid_fence("flowchart TD")


def test_table_escapes_pipes_and_newlines_in_cells() -> None:
    """A ``|`` or a newline in a record name or author shifted the table's columns."""
    formatter = GitHubFormatter()
    table = formatter.table(
        ["Name", "Author", "Description"],
        [["[LSASS read | procdump](lsass.md)", "Jane\nDoe", "already \\| escaped"]],
    )
    row = table.splitlines()[2]
    assert row == "| [LSASS read \\| procdump](lsass.md) | Jane Doe | already \\| escaped |"
    assert len(row.replace("\\|", "").split("|")) == 5


def test_gitlab_index_table_keeps_cells_verbatim() -> None:
    table = GitLabFormatter().index_table(["Name"], [["a | b"]])
    assert '"a | b"' in table
