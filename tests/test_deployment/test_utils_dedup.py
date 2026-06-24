"""Tests for deployment utility deduplication."""

from __future__ import annotations

from opentide.deployment import enabled_systems
from opentide.deployment.git_repo import diff_calculation, modified_mdr_files
from opentide.platforms.enabled import enabled_systems as canonical_enabled_systems


def test_enabled_systems_reexported_from_platforms() -> None:
    assert enabled_systems is canonical_enabled_systems


def test_git_repo_exports_diff_helpers() -> None:
    assert callable(diff_calculation)
    assert callable(modified_mdr_files)
