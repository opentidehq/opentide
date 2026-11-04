"""``sync_sentinel_attack.py``: the Sentinel ATT&CK v18 list, from synthetic STIX bundles (#686)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "sync_sentinel_attack", ROOT / "scripts" / "build" / "sync_sentinel_attack.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered first: dataclasses resolve the module's annotations through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _technique(identifier: str, name: str, **flags: Any) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{identifier}",
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": identifier}],
        **flags,
    }


def _revoked_by(old: str, new: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "relationship_type": "revoked-by",
        "source_ref": f"attack-pattern--{old}",
        "target_ref": f"attack-pattern--{new}",
    }


def _write(stix: Path, release: str, objects: list[dict[str, Any]]) -> None:
    for domain in ("enterprise", "mobile", "ics"):
        path = stix / f"{domain}-attack" / f"{domain}-attack-{release}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = objects if domain == "enterprise" else []
        path.write_text(json.dumps({"type": "bundle", "objects": bundle}), encoding="utf-8")


@pytest.fixture
def stix(tmp_path: Path) -> Path:
    _write(
        tmp_path,
        "18.1",
        [
            _technique("T1556", "Modify Authentication Process"),
            _technique("T1556.009", "Conditional Access Policies"),
            _technique("T1059", "Command and Scripting Interpreter"),
            _technique("T1059.001", "PowerShell"),
            _technique("T1562", "Impair Defenses"),
            # Retired before v18: one revoked (twice over), one deprecated.
            _technique("T1086", "PowerShell", revoked=True),
            _technique("T1999", "Old PowerShell", revoked=True),
            _revoked_by("T1086", "T1999"),
            _revoked_by("T1999", "T1059.001"),
            _technique("T1064", "Scripting", x_mitre_deprecated=True),
        ],
    )
    _write(
        tmp_path,
        "20.0",
        [
            _technique("T1556", "Modify Authentication Process"),
            _technique("T1556.009", "Conditional Access Policies"),
            _technique("T1059", "Command and Scripting Interpreter"),
            _technique("T1059.001", "PowerShell"),
            # T1562 revoked by an intermediate id, itself revoked by T1685.
            _technique("T1562", "Impair Defenses", revoked=True),
            _technique("T1680", "Interim", revoked=True),
            _technique("T1685", "Disable or Modify Tools"),
            _revoked_by("T1562", "T1680"),
            _revoked_by("T1680", "T1685"),
            _technique("T1696", "Anti-Automation Evasion"),
        ],
    )
    return tmp_path


def _document(stix: Path) -> dict[str, Any]:
    return json.loads(_script().document(stix, "20.0"))


def test_techniques_are_the_active_v18_ids_with_parent_prefixed_names(stix: Path) -> None:
    assert _document(stix)["techniques"] == {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "Command and Scripting Interpreter: PowerShell",
        "T1556": "Modify Authentication Process",
        "T1556.009": "Modify Authentication Process: Conditional Access Policies",
        "T1562": "Impair Defenses",
    }


def test_a_later_id_names_the_v18_id_through_every_revocation(stix: Path) -> None:
    later = _document(stix)["later"]

    assert later["attack"] == "20.0"
    assert later["techniques"] == {
        "T1685": {"name": "Disable or Modify Tools", "replaces": ["T1562"]},
        "T1696": {"name": "Anti-Automation Evasion", "replaces": []},
    }


def test_retired_ids_name_their_v18_replacement_or_none(stix: Path) -> None:
    assert _document(stix)["retired"] == {
        "T1064": {"name": "Scripting", "replaced_by": []},
        "T1086": {"name": "PowerShell", "replaced_by": ["T1059.001"]},
        "T1999": {"name": "Old PowerShell", "replaced_by": ["T1059.001"]},
    }


def test_check_reports_a_stale_file_and_accepts_a_current_one(
    stix: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    script = _script()
    output = tmp_path / "out" / "attack-v18.json"
    monkeypatch.setattr(script, "OUTPUT", output)
    monkeypatch.setattr(script, "ROOT", tmp_path)
    monkeypatch.setattr(script, "vocabulary_release", lambda: "20.0")

    assert script.main(["--check", "--stix-dir", str(stix)]) == 1
    assert "is stale" in capsys.readouterr().err
    assert script.main(["--stix-dir", str(stix)]) == 0
    assert script.main(["--check", "--stix-dir", str(stix)]) == 0


def test_the_later_release_is_the_vocabulary_s() -> None:
    """The `later` table follows the release the bundled `att&ck` vocabulary was built from."""
    script = _script()
    bundled = json.loads(script.OUTPUT.read_text(encoding="utf-8"))

    assert bundled["later"]["attack"] == script.vocabulary_release()
