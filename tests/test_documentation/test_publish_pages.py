"""Page files written by ``generate docs`` against a materialised tide_corpus."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    TIDE_CORPUS_ROOT,
    clear_runtime_caches,
    drop_legacy_objects,
    materialise_corpus,
)

from opentide.documentation.cli import run

VARIANT_UUID = "00000000-0000-4000-8003-000000000201"


@pytest.fixture
def docs_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    repo = materialise_corpus(tmp_path / "corpus")
    drop_legacy_objects(repo)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    clear_runtime_caches()
    yield repo
    clear_runtime_caches()


def _sentinel_rule_text() -> str:
    source = TIDE_CORPUS_ROOT / "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"
    return source.read_text(encoding="utf-8")


def test_names_that_slugify_alike_get_separate_pages(docs_repo: Path) -> None:
    """``Sentinel KQL Rule`` and ``Sentinel-KQL rule`` both wrote ``sentinel-kql-rule.md``.

    The second page overwrote the first and both index rows linked to it.
    """
    variant = (
        _sentinel_rule_text()
        .replace(CORPUS_RULE_UUIDS["sentinel"], VARIANT_UUID)
        .replace("name: Sentinel KQL Rule\n", "name: Sentinel-KQL rule\n", 1)
    )
    (docs_repo / "objects" / "rules" / "rule-0201-variant.yaml").write_text(
        variant, encoding="utf-8"
    )
    clear_runtime_caches()

    run(flavor="github")

    rules = docs_repo / "docs" / "rules"
    original = rules / "sentinel-kql-rule.md"
    renamed = rules / "sentinel-kql-rule-00000000.md"
    assert CORPUS_RULE_UUIDS["sentinel"] in original.read_text(encoding="utf-8")
    assert VARIANT_UUID in renamed.read_text(encoding="utf-8")
    index = (rules / "README.md").read_text(encoding="utf-8")
    assert "[Sentinel KQL Rule](sentinel-kql-rule.md)" in index
    assert "[Sentinel-KQL rule](sentinel-kql-rule-00000000.md)" in index


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=docs@example.com", "-c", "user.name=docs", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def documented_repo(docs_repo: Path) -> Path:
    """The corpus committed on a single branch, with a full docs run on disk."""
    _git(docs_repo, "init", "-q", "-b", "trunk")
    _git(docs_repo, "add", "-A")
    _git(docs_repo, "commit", "-q", "-m", "init")
    run(flavor="github")
    clear_runtime_caches()
    return docs_repo


def _rename_objective(repo: Path, name: str) -> None:
    objective = next((repo / "objects" / "objectives").glob("*.yaml"))
    text = objective.read_text(encoding="utf-8")
    objective.write_text(
        text.replace("name: Credential Access Objective\n", f"name: {name}\n", 1),
        encoding="utf-8",
    )
    clear_runtime_caches()


def test_changed_keeps_the_page_of_a_moved_object(documented_repo: Path) -> None:
    """A moved, unstaged rule file used to lose its page under ``--changed``.

    The old path counted as a deletion, so the page was written for the new path
    and then unlinked for the old one, while the index still linked it.
    """
    rules = documented_repo / "objects" / "rules"
    (rules / "rule-0001-sentinel-kql.yaml").rename(rules / "rule-0001-moved.yaml")
    clear_runtime_caches()

    result = run(flavor="github", changed=True)

    assert result["removed"] == 0
    page = documented_repo / "docs" / "rules" / "sentinel-kql-rule.md"
    assert CORPUS_RULE_UUIDS["sentinel"] in page.read_text(encoding="utf-8")


def test_changed_keeps_the_page_a_replacement_object_now_owns(documented_repo: Path) -> None:
    """A deleted rule replaced by a new one of the same name used to lose the new page."""
    rules = documented_repo / "objects" / "rules"
    (rules / "rule-0001-sentinel-kql.yaml").unlink()
    (rules / "rule-0201-replacement.yaml").write_text(
        _sentinel_rule_text().replace(CORPUS_RULE_UUIDS["sentinel"], VARIANT_UUID),
        encoding="utf-8",
    )
    clear_runtime_caches()

    run(flavor="github", changed=True)

    page = documented_repo / "docs" / "rules" / "sentinel-kql-rule.md"
    assert VARIANT_UUID in page.read_text(encoding="utf-8")


def test_full_run_removes_the_page_of_a_renamed_object(documented_repo: Path) -> None:
    """A full run left ``credential-access-objective.md`` behind after a rename.

    Files in the output folders that the generator did not write must stay.
    """
    objectives = documented_repo / "docs" / "objectives"
    notes = objectives / "notes.md"
    notes.write_text("# Notes\n\nKept by hand.\n", encoding="utf-8")
    _rename_objective(documented_repo, "Renamed Credential Objective")

    result = run(flavor="github")

    assert result["removed"] == 1
    assert sorted(path.name for path in objectives.iterdir()) == [
        "README.md",
        "notes.md",
        "renamed-credential-objective.md",
    ]


def test_changed_rewrites_downstream_links_to_a_renamed_object(documented_repo: Path) -> None:
    """``--changed`` refreshed only upstream referrers of a renamed objective.

    Rule pages below it kept linking the old page, which was never removed.
    """
    _rename_objective(documented_repo, "Renamed Credential Objective")

    result = run(flavor="github", changed=True)

    docs = documented_repo / "docs"
    assert not (docs / "objectives" / "credential-access-objective.md").exists()
    assert result["removed"] == 1
    rule_page = (docs / "rules" / "sentinel-kql-rule.md").read_text(encoding="utf-8")
    assert (
        "[Renamed Credential Objective](../objectives/renamed-credential-objective.md)" in rule_page
    )
    assert "credential-access-objective.md" not in rule_page
    assert CORPUS_RULE_UUIDS["sentinel"] in result["targets"]
