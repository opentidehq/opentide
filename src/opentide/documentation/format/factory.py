"""Formatter factory."""

from __future__ import annotations

from opentide.documentation.format.azure_devops import AzureDevOpsFormatter
from opentide.documentation.format.generic import GenericFormatter
from opentide.documentation.format.github import GitHubFormatter
from opentide.documentation.format.gitlab import GitLabFormatter
from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.types import DocumentFlavor


def formatter_for(flavor: DocumentFlavor) -> MarkdownFormatter:
    """Return a formatter implementation for the selected flavor."""
    if flavor is DocumentFlavor.github:
        return GitHubFormatter()
    if flavor is DocumentFlavor.gitlab:
        return GitLabFormatter()
    if flavor is DocumentFlavor.azure_devops:
        return AzureDevOpsFormatter()
    return GenericFormatter()
