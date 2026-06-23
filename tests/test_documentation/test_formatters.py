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
