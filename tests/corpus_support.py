"""tide_corpus fixtures shared by CLI, MCP, and packaging suites.

Registered as a pytest plugin from the root ``conftest.py`` so every suite can
exercise the real corpus instead of mocking the registry.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import pytest

from opentide.core.io import load_toml
from opentide.models.deployment_enums import StatusStrategy

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
}
#: Rules deploy skips because they sit in subfolders (#312). One shares a
#: top-level file name, which a lookup by file name would resolve wrongly.
SUBFOLDER_RULE_UUIDS = {
    "team-a/rule-0101-subfolder.yaml": "00000000-0000-4000-8003-000000000101",
    "team-a/deep/rule-0001-sentinel-kql.yaml": "00000000-0000-4000-8003-000000000102",
}
#: A top-level rule no plan deploys: ``DESIGN`` maps to the ``INERT`` strategy.
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


def clear_runtime_caches() -> None:
    from opentide.core.index_manager import IndexManager
    from opentide.core.registry import OpenTide
    from opentide.core.root import get_data_root, get_repo_root
    from opentide.generation import schema_pipeline

    # The schema pipeline caches registry-backed globals; a stale binding points
    # generation at the previous test's repo root.
    schema_pipeline._runtime_ready = False  # noqa: SLF001
    get_repo_root.cache_clear()
    get_data_root.cache_clear()
    IndexManager._cache = None  # noqa: SLF001
    OpenTide._initialised = False  # noqa: SLF001
    OpenTide._objects_loaded = False  # noqa: SLF001
    OpenTide._index = None  # noqa: SLF001
    OpenTide._rules = {}
    OpenTide._threats = {}
    OpenTide._objectives = {}


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
    """Add the rules a FULL plan leaves out: in subfolders, and ``INERT``."""
    for relative, uuid in SUBFOLDER_RULE_UUIDS.items():
        write_rule_variant(rules, relative, uuid)
    write_rule_variant(rules, "rule-0103-design.yaml", INERT_RULE_UUID, status="DESIGN")


def classify_deploy_scope(
    repo: Path,
    indexed: Iterable[str],
    plan: dict[str, list[str]],
    warnings: Iterable[str],
    *,
    excluded: frozenset[StatusStrategy],
) -> dict[str, set[str]]:
    """Sort indexed rule UUIDs by why a plan has or lacks them (#312 guard).

    ``silent`` holds rules that are not planned, not excluded by a status
    strategy in *excluded*, and whose file no warning names.
    """
    from opentide.core.io import load_yaml
    from opentide.core.object_refs import object_uuid
    from opentide.deployment.utils import check_status

    planned = {uuid for uuids in plan.values() for uuid in uuids}
    named = {
        name
        for message in warnings
        if "): " in message
        for name in message.split("): ", 1)[1].split(", ")
    }
    root = repo.resolve()
    files: dict[str, tuple[str, dict[str, Any]]] = {}
    for path in (repo / "objects" / "rules").rglob("*.yaml"):
        data = load_yaml(path)
        files[object_uuid(data)] = (path.resolve().relative_to(root).as_posix(), data)
    scope: dict[str, set[str]] = {
        "planned": set(),
        "status": set(),
        "warned": set(),
        "silent": set(),
    }
    for uuid in indexed:
        file, data = files[uuid]
        strategies = {check_status(conf["status"]) for conf in data["configurations"].values()}
        if uuid in planned:
            scope["planned"].add(uuid)
        elif strategies <= excluded:
            scope["status"].add(uuid)
        elif file in named:
            scope["warned"].add(uuid)
        else:
            scope["silent"].add(uuid)
    return scope


def corpus_env(repo: Path) -> dict[str, str]:
    """Environment overrides that point OpenTide at a materialised corpus."""
    return {
        "OPENTIDE_REPO_ROOT": str(repo),
        "OPENTIDE_TIDE_WORKSPACE": str(repo),
        "DEPLOYMENT_PLAN": "FULL",
    }


@pytest.fixture
def tide_corpus_root() -> Path:
    return TIDE_CORPUS_ROOT


@pytest.fixture
def tide_corpus_repo(
    tide_corpus_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """Copy tide_corpus into an isolated repo and wire OpenTide path env vars."""
    dest = materialise_corpus(tmp_path / "corpus")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(dest))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(dest))
    monkeypatch.setenv("DEPLOYMENT_PLAN", "FULL")
    monkeypatch.setenv("CI", "true")
    clear_runtime_caches()
    yield dest
    clear_runtime_caches()


@pytest.fixture
def corpus_rule_uuids() -> dict[str, str]:
    return dict(CORPUS_RULE_UUIDS)


def load_corpus_manifest() -> dict[str, Any]:
    return load_toml(TIDE_CORPUS_MANIFEST)


def manifest_slices(*, status: str | None = None) -> list[dict[str, Any]]:
    manifest = load_corpus_manifest()
    slices = manifest.get("slices", [])
    if status is None:
        return slices
    return [slice_info for slice_info in slices if slice_info.get("status") == status]
