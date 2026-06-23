from __future__ import annotations

from opentide.documentation.context import resolve_flavor
from opentide.documentation.types import DocumentFlavor


def test_resolve_flavor_github_actions(monkeypatch) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert resolve_flavor() is DocumentFlavor.github


def test_resolve_flavor_gitlab_ci(monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("CI", "true")
    assert resolve_flavor() is DocumentFlavor.gitlab
