"""Page files written by ``generate docs`` against a materialised tide_corpus."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    TIDE_CORPUS_ROOT,
    clear_runtime_caches,
    materialise_corpus,
    real_rules_folder,
)

from opentide.documentation.cli import run

VARIANT_UUID = "00000000-0000-4000-8003-000000000201"


@pytest.fixture
def docs_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    repo = materialise_corpus(tmp_path / "corpus")
    real_rules_folder(repo)
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
