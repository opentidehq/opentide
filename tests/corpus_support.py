"""tide_corpus fixtures shared by CLI, MCP, and packaging suites.

Registered as a pytest plugin from the root ``conftest.py`` so every suite can
exercise the real corpus instead of mocking the registry.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
TIDE_CORPUS_ROOT = ROOT / "tests/fixtures/tide_corpus/current"
TIDE_CORPUS_MANIFEST = ROOT / "tests/fixtures/tide_corpus/manifest.toml"

CORPUS_RULE_UUIDS = {
    "sentinel": "00000000-0000-4000-8003-000000000001",
    "defender_for_endpoint": "00000000-0000-4000-8003-000000000002",
    "splunk": "00000000-0000-4000-8003-000000000003",
    "sentinel_one": "00000000-0000-4000-8003-000000000004",
    "carbon_black_cloud": "00000000-0000-4000-8003-000000000005",
    "crowdstrike": "00000000-0000-4000-8003-000000000006",
    "harfanglab": "00000000-0000-4000-8003-000000000007",
    "elastic": "00000000-0000-4000-8003-000000000009",
    "sysdig": "00000000-0000-4000-8003-0000005d1a90",
}
#: Rules deploy skips because they sit in subfolders (#312). One shares a
#: top-level file name, which a lookup by file name would resolve wrongly.
SUBFOLDER_RULE_UUIDS = {
    "team-a/rule-0101-subfolder.yaml": "00000000-0000-4000-8003-000000000101",
    "team-a/deep/rule-0001-sentinel-kql.yaml": "00000000-0000-4000-8003-000000000102",
}
#: A top-level rule no run strategy deploys: ``DESIGN`` maps to the ``INERT`` strategy.
INERT_RULE_UUID = "00000000-0000-4000-8003-000000000103"
CORPUS_THREAT_UUID = "00000000-0000-4000-8001-000000000001"
CORPUS_OBJECTIVE_UUID = "00000000-0000-4000-8002-000000000001"
CORPUS_TECHNIQUE = "T1059"
CORPUS_ACTOR = "att&ck::G0006"


def _symlink_dir(link: Path, target: Path) -> None:
    """Point ``link`` at directory ``target``, copying when symlinks are unavailable."""
    if link.exists() or link.is_symlink():
        return
    link.parent.mkdir(parents=True, exist_ok=True)
    rel = Path(os.path.relpath(target.resolve(), link.parent.resolve()))
    try:
        link.symlink_to(rel, target_is_directory=True)
    except OSError:
        # Windows rejects symlink creation without Developer Mode or elevation.
        shutil.copytree(target, link)


def migrate_tide_corpus_layout(dest: Path) -> None:
    """Adapt legacy tide_corpus fixture to greenfield ``.opentide/`` layout."""
    opentide = dest / ".opentide"
    opentide.mkdir(exist_ok=True)

    legacy_configs = dest / "Configurations"
    if legacy_configs.is_dir():
        shutil.copytree(legacy_configs, opentide / "configurations", dirs_exist_ok=True)

    object_links = {
        "objects/threats": "Objects/Threat Vectors",
        "objects/objectives": "Objects/Detection Objectives",
        "objects/rules": "Objects/Detection Rules",
    }
    for link_rel, target_rel in object_links.items():
        _symlink_dir(dest / link_rel, dest / target_rel)

    opentide.joinpath("schemas").mkdir(exist_ok=True)
    opentide.joinpath("templates").mkdir(exist_ok=True)
    opentide.joinpath("exports").mkdir(exist_ok=True)
    opentide.joinpath("inflight").mkdir(exist_ok=True)


def materialise_corpus(dest: Path) -> Path:
    """Copy tide_corpus into *dest* and migrate it to the current layout."""
    shutil.copytree(TIDE_CORPUS_ROOT, dest)
    migrate_tide_corpus_layout(dest)
    return dest


def real_rules_folder(repo: Path) -> Path:
    """Replace the ``objects/rules`` symlink with the folder ``opentide setup`` creates."""
    link = repo / "objects" / "rules"
    if link.is_symlink():
        target = link.resolve()
        link.unlink()
        target.rename(link)
    return link


def drop_legacy_objects(repo: Path) -> Path:
    """Leave only the current ``objects/`` folders, as real folders; return ``objects/``.

    The corpus keeps its legacy ``Objects/`` tree. A case-insensitive file
    system (macOS, Windows) makes it the same folder as ``objects/``, so git
    records the rules under ``Objects/`` and no diff path matches a configured
    object folder. Commit the corpus only after this.
    """
    staged = repo / ".objects-current"
    staged.mkdir()
    for family in ("threats", "objectives", "rules"):
        (repo / "objects" / family).resolve().rename(staged / family)
    # On a case-insensitive file system this also removes ``objects/``.
    shutil.rmtree(repo / "Objects")
    if (repo / "objects").exists():
        shutil.rmtree(repo / "objects")
    staged.rename(repo / "objects")
    return repo / "objects"


def write_rule_variant(rules: Path, relative: str, uuid: str, *, status: str = "STAGING") -> Path:
    """Write the corpus Sentinel rule to *rules*/*relative* under a new identity."""
    source = TIDE_CORPUS_ROOT / "Objects/Detection Rules/rule-0001-sentinel-kql.yaml"
    text = (
        source.read_text(encoding="utf-8")
        .replace(CORPUS_RULE_UUIDS["sentinel"], uuid)
        .replace("name: Sentinel KQL Rule", f"name: Sentinel KQL Rule {uuid[-3:]}")
        .replace("status: STAGING", f"status: {status}")
    )
    path = rules / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def add_unplanned_rules(rules: Path) -> None:
    """Add the rules a PREVIEW+RELEASE ``--all`` run leaves out: in subfolders, and ``INERT``."""
    for relative, uuid in SUBFOLDER_RULE_UUIDS.items():
        write_rule_variant(rules, relative, uuid)
    write_rule_variant(rules, "rule-0103-design.yaml", INERT_RULE_UUID, status="DESIGN")


def corpus_env(repo: Path) -> dict[str, str]:
    """Environment overrides that point opentide at a materialised corpus."""
    return {
        "OPENTIDE_REPO_ROOT": str(repo),
        "OPENTIDE_TIDE_WORKSPACE": str(repo),
    }


@pytest.fixture
def tide_corpus_root() -> Path:
    return TIDE_CORPUS_ROOT


@pytest.fixture
def tide_corpus_repo(
    tide_corpus_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """Copy tide_corpus into an isolated repo and wire opentide path env vars."""
    dest = materialise_corpus(tmp_path / "corpus")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(dest))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(dest))
    monkeypatch.delenv("DEPLOYMENT_PLAN", raising=False)
    monkeypatch.setenv("CI", "true")
    yield dest


@pytest.fixture
def corpus_rule_uuids() -> dict[str, str]:
    return dict(CORPUS_RULE_UUIDS)


def load_corpus_manifest() -> dict[str, Any]:
    return tomllib.loads(TIDE_CORPUS_MANIFEST.read_text(encoding="utf-8"))


def manifest_slices(*, status: str | None = None) -> list[dict[str, Any]]:
    manifest = load_corpus_manifest()
    slices = manifest.get("slices", [])
    if status is None:
        return slices
    return [slice_info for slice_info in slices if slice_info.get("status") == status]
