"""Object files saved as ``.yml`` are indexed like ``.yaml`` ones."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from opentide.registry.builder import build_registry
from opentide.registry.paths import object_yaml_files


def _object(uuid: str, schema: str) -> dict[str, object]:
    return {"name": f"object {uuid[:8]}", "metadata": {"uuid": uuid, "schema": schema}}


def test_registry_indexes_yml_object_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Deploy and lint read ``.yml`` rule files; the registry read only ``.yaml``.

    ``validate --strict`` then passed without ever checking a ``.yml`` rule, and
    deploy planned it from the file and failed with ``KeyError: '<uuid>'`` when
    it looked the rule up in the registry.
    """
    layout = {
        "objects/rules/short.yml": ("rule", str(uuid4())),
        "objects/rules/team-a/nested.yml": ("rule", str(uuid4())),
        "objects/rules/long.yaml": ("rule", str(uuid4())),
        "objects/threats/threat.yml": ("threat", str(uuid4())),
        "objects/objectives/objective.yml": ("objective", str(uuid4())),
    }
    for relative, (family, uuid) in layout.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(_object(uuid, f"{family}::1.0")), encoding="utf-8")
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path.resolve()))

    index = build_registry()

    for relative, (family, uuid) in layout.items():
        assert uuid in index["objects"][family], relative
        assert Path(index["file_paths"][uuid]) == (tmp_path / relative).resolve()


def test_object_yaml_files_lists_both_spellings_without_debug_dumps(tmp_path: Path) -> None:
    for name in ("b.yaml", "a.yml", "sub/c.yml", "x.debug.yaml", "y.debug.yml", "notes.md"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")

    assert object_yaml_files(tmp_path) == [
        tmp_path / "a.yml",
        tmp_path / "b.yaml",
        tmp_path / "sub" / "c.yml",
    ]
