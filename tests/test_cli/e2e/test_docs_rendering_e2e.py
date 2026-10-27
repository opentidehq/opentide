"""CLI E2E: ``generate docs`` writes values as text, never as Python reprs (#296).

0.5.0 wrote the actor Source cell of ``docs/threats/simulated-actor.md`` as
``('att&ck',)``: the vocabulary stores ``tide.vocab.stages`` as a tuple and the
renderer only joined lists. The guard below generates every page of the
tide_corpus in each flavor and fails on any container repr, so a renderer that
``str()``-s a collection is caught wherever it lands.
"""

from __future__ import annotations

import re
from itertools import dropwhile, takewhile
from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_ACTOR
from tests.test_cli.conftest import assert_json_ok
from tests.test_cli.e2e.helpers import write_tutorial_objects

from opentide.documentation.types import DocumentFlavor

pytestmark = pytest.mark.cli_e2e

_REPRS = re.compile(
    r"\('[^']*',?\)"
    r"|\['"
    r"|\{'"
    r"|\bfrozenset\("
    r"|\bdict_(?:keys|values|items)\("
    r"|<(?:generator|map|filter|zip) object"
)
_EMPTY_CONTAINER_CELLS = {"None", "()", "[]", "{}", "set()", "frozenset()"}
_NON_DIAGRAM_CODE = re.compile(r"^```(?!mermaid)[^\n]*\n.*?^```", re.MULTILINE | re.DOTALL)


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in re.split(r"(?<!\\)\|", line)[1:-1]]


def _actor_rows(page: Path) -> dict[str, list[str]]:
    lines = page.read_text(encoding="utf-8").splitlines()
    section = dropwhile(lambda line: not line.startswith("|"), lines[lines.index("## Actors") :])
    table = [_cells(line) for line in takewhile(lambda line: line.startswith("|"), section)]
    header, rows = table[0], table[2:]
    assert header == ["Actor", "ID", "Source", "Description"]
    return {row[1].strip("`"): row for row in rows}


def _reprs(page: Path) -> list[str]:
    """Container reprs in prose, tables and diagrams; rule queries are left alone."""
    text = _NON_DIAGRAM_CODE.sub("", page.read_text(encoding="utf-8"))
    found = [match.group(0) for match in _REPRS.finditer(text)]
    for line in text.splitlines():
        if line.startswith("|"):
            found.extend(cell for cell in _cells(line) if cell in _EMPTY_CONTAINER_CELLS)
    return found


def test_generate_docs_writes_section_indexes_for_an_empty_repository(
    invoke_cli, tmp_path: Path
) -> None:
    """#401: root README links to rules, objectives, and threats indexes at count 0."""
    assert_json_ok(
        invoke_cli(
            "setup",
            "repo",
            "--yes",
            "--name",
            "demo",
            "--platform",
            "sentinel",
            "--path",
            str(tmp_path),
            repo=tmp_path,
        )
    )
    assert_json_ok(invoke_cli("generate", repo=tmp_path))
    assert_json_ok(invoke_cli("generate", "docs", "--output", "docs", repo=tmp_path))
    docs = tmp_path / "docs"
    root = (docs / "README.md").read_text(encoding="utf-8")
    for folder in ("rules", "objectives", "threats"):
        assert (docs / folder / "README.md").is_file()
        assert f"{folder}/README.md" in root
    assert '"c":"0"' in root or "| 0 |" in root


def test_generate_docs_writes_the_tutorial_actor_source_as_its_stage(
    invoke_cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for ci_variable in ("CI", "GITHUB_ACTIONS", "TF_BUILD"):
        monkeypatch.delenv(ci_variable, raising=False)
    fresh = tmp_path / "tutorial-detections"
    assert_json_ok(
        invoke_cli(
            "setup",
            "--yes",
            "--name",
            "Tutorial Detections",
            "--org",
            "Example Corp",
            "--platform",
            "sentinel",
            "--path",
            str(fresh),
            repo=tmp_path,
        )
    )
    write_tutorial_objects(fresh)
    assert_json_ok(invoke_cli("generate", repo=fresh))
    page = fresh / "docs" / "threats" / "simulated-actor.md"

    for _ in range(2):
        assert_json_ok(invoke_cli("generate", "docs", repo=fresh))
        _, _, source, _ = _actor_rows(page)[CORPUS_ACTOR]
        assert source == "att&ck"
        assert _reprs(page) == []


@pytest.mark.parametrize("flavor", [flavor.value for flavor in DocumentFlavor])
def test_generate_docs_on_the_corpus_writes_no_python_reprs(
    invoke_cli, tide_corpus_repo: Path, flavor: str
) -> None:
    payload = assert_json_ok(invoke_cli("generate", "docs", "--flavor", flavor))
    assert all(payload["counts"][kind] > 0 for kind in ("rules", "objectives", "threats"))

    pages = sorted((tide_corpus_repo / "docs").rglob("*.md"))
    threat_pages = [page for page in pages if page.parent.name == "threats"]
    assert any(CORPUS_ACTOR in page.read_text(encoding="utf-8") for page in threat_pages)

    found = {str(page.relative_to(tide_corpus_repo)): _reprs(page) for page in pages}
    assert {page: reprs for page, reprs in found.items() if reprs} == {}


_NESTED_RULE = "objects/rules/team/nested-team-rule.yaml"
_NESTED_RULE_UUID = "00000000-0000-4000-8003-000000000584"


def test_generate_docs_and_export_skip_a_nested_object_file(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    """A file in a subfolder is not an object instance (#584): no page, one warning."""
    source = tide_corpus_repo / "objects" / "rules" / "rule-0001-sentinel-kql.yaml"
    nested = tide_corpus_repo / _NESTED_RULE
    nested.parent.mkdir(parents=True, exist_ok=True)
    nested.write_text(
        source.read_text(encoding="utf-8")
        .replace("00000000-0000-4000-8003-000000000001", _NESTED_RULE_UUID)
        .replace("name: Sentinel KQL Rule", "name: Nested Team Rule"),
        encoding="utf-8",
    )

    payload = assert_json_ok(invoke_cli("generate", "docs"))
    assert any("team/nested-team-rule.yaml" in warning for warning in payload["warnings"])
    pages = sorted((tide_corpus_repo / "docs").rglob("*.md"))
    assert pages
    for page in pages:
        text = page.read_text(encoding="utf-8")
        assert _NESTED_RULE_UUID not in text, page
        assert "Nested Team Rule" not in text, page
    assert not any("nested-team-rule" in page.name for page in pages)

    exported = assert_json_ok(invoke_cli("export", "objects"))
    assert any("team/nested-team-rule.yaml" in warning for warning in exported["warnings"])
    exports = [p for p in (tide_corpus_repo / ".opentide" / "exports").rglob("*") if p.is_file()]
    assert exports
    for path in exports:
        assert _NESTED_RULE_UUID not in path.read_text(encoding="utf-8", errors="replace"), path
