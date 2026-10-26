"""Runtime context used by documentation rendering."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from opentide.documentation.format.protocol import MarkdownFormatter
from opentide.documentation.types import DocumentFlavor


def resolve_flavor(
    *, override: str | None = None, default: str = "generic", root: Path | None = None
) -> DocumentFlavor:
    """The Markdown flavor to render, adapting to where the docs will be read.

    In order: ``--flavor``; the CI platform running the job (Azure Pipelines,
    GitHub Actions, GitLab CI); the host of the repository's ``origin`` remote,
    so a local run renders what CI would; the configured default, plain
    CommonMark (``generic``) out of the box. Any other CI (Jenkins, CircleCI)
    sets only ``CI`` and used to be read as GitLab.
    """
    if override:
        return DocumentFlavor(override.replace("-", "_"))
    if os.getenv("TF_BUILD"):
        return DocumentFlavor.azure_devops
    if os.getenv("GITHUB_ACTIONS"):
        return DocumentFlavor.github
    if os.getenv("GITLAB_CI"):
        return DocumentFlavor.gitlab
    hosted = flavor_from_remote(root)
    if hosted is not None:
        return hosted
    return DocumentFlavor(default.replace("-", "_"))


def flavor_from_remote(root: Path | None = None) -> DocumentFlavor | None:
    """The flavor of the forge hosting the repository at *root*, from its ``origin`` URL."""
    url = _origin_url(root)
    return _flavor_for_host(_url_host(url)) if url else None


def _origin_url(root: Path | None) -> str | None:
    from dulwich.errors import NotGitRepository
    from dulwich.repo import Repo

    if root is None:
        from opentide.core.root import get_repo_root

        root = get_repo_root()
    try:
        with Repo.discover(str(root)) as repo:
            url = repo.get_config().get((b"remote", b"origin"), b"url")
    except (NotGitRepository, KeyError, OSError):
        return None
    return url.decode("utf-8", errors="replace")


def _url_host(url: str) -> str:
    """Host of an https/ssh URL or of scp-like ``user@host:path`` syntax."""
    if "://" in url:
        return (urlsplit(url).hostname or "").lower()
    head = url.split(":", 1)[0]
    return head.rpartition("@")[2].lower()


def _flavor_for_host(host: str) -> DocumentFlavor | None:
    if host in {"dev.azure.com", "ssh.dev.azure.com"} or host.endswith(".visualstudio.com"):
        return DocumentFlavor.azure_devops
    # Self-hosted forges usually keep the product name in the host
    # (github.example.com, gitlab.example.org).
    if "github" in host:
        return DocumentFlavor.github
    if "gitlab" in host:
        return DocumentFlavor.gitlab
    return None


@dataclass(frozen=True)
class DocumentationContext:
    """Shared context object for render and publish phases."""

    flavor: DocumentFlavor
    output_dir: Path
    formatter: MarkdownFormatter
    folder_index_pages: bool = True
    uuid_permalinks: bool = False
    relations_direction: Literal["upstream", "downstream", "both"] = "both"
    index_relation_counts: bool = True
    index_icons: bool = False
