"""Bundled metaschema byte-stability gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
METASCHEMA_ROOT = ROOT / "src/opentide/schemas/data"


def test_bundled_metaschema_byte_checksum_gate() -> None:
    """CI gate: bundled metaschema/template sources must remain byte-stable."""
    tracked = [
        METASCHEMA_ROOT / "MDR Meta Schema.yaml",
        METASCHEMA_ROOT / "Detection Objective.metaschema.yaml",
        METASCHEMA_ROOT / "Threat Vector.metaschema.yaml",
    ]
    baseline_path = ROOT / "tests/fixtures/generation/metaschema_checksums.json"
    checksums = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in tracked
    }
    if not baseline_path.exists():
        pytest.fail("Missing generation baseline checksum file")
    expected = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert checksums == expected
