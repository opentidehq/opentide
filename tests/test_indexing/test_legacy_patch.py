"""Legacy object patching for Tide 1.x payloads."""

from __future__ import annotations

from pathlib import Path

from opentide.indexing.legacy_patch import LegacyObjectPatch


def test_legacy_patch_adds_schema_and_uuid() -> None:
    patch = LegacyObjectPatch(index_path=Path("/nonexistent/mapping.json"))
    model = {"name": "Legacy", "meta": {"version": 1}}
    patched = patch.tide_1_patch(model, "mdr")
    assert patched["metadata"]["schema"] == "mdr::2.0"
    assert patched["metadata"]["uuid"]
