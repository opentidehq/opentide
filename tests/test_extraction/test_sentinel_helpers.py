"""Sentinel importer: pure helpers and the listing-to-YAML path.

The importer needs no SDK stubs: it lists rules through the ARM REST client,
which ships with ``pip install opentide``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from opentide.extraction import sentinel_importer


def test_convert_period_strips_iso_prefix() -> None:
    assert sentinel_importer.convert_period("PT5M") == "5m"
    assert sentinel_importer.convert_period("P1D") == "1d"


def test_sanitize_filename_replaces_invalid_chars() -> None:
    assert sentinel_importer.sanitize_filename('rule<>:"/\\|?*name') == "rule         name"


def _listed(kind: str, name: str, **properties: Any) -> dict[str, Any]:
    return {
        "name": name,
        "kind": kind,
        "properties": {
            "displayName": f"{kind} rule",
            "description": "d",
            "enabled": True,
            "query": "SecurityEvent",
            "suppressionEnabled": False,
            "suppressionDuration": "PT1H",
            "severity": "High",
            "lastModifiedUtc": "2026-10-01T10:00:00Z",
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": False,
                    "lookbackDuration": "PT1H",
                    "matchingMethod": "AllEntities",
                },
            },
            **properties,
        },
    }


def test_import_writes_scheduled_and_nrt_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ARM lists near-real-time rules as kind ``NRT``; they used to be skipped as unknown."""
    listed = [
        _listed(
            "Scheduled",
            "11111111-1111-4111-8111-111111111111",
            queryFrequency="PT1H",
            queryPeriod="PT2H",
            triggerOperator="GreaterThan",
            triggerThreshold=0,
        ),
        _listed("NRT", "22222222-2222-4222-8222-222222222222"),
        _listed("Fusion", "33333333-3333-4333-8333-333333333333"),
    ]
    tenant = SimpleNamespace(
        name="tenant-a", setup=SimpleNamespace(resource_group="rg", workspace_name="ws")
    )
    service = SimpleNamespace(alert_rules=SimpleNamespace(list=lambda **_: iter(listed)))
    monkeypatch.setattr(
        sentinel_importer,
        "Opentide",
        SimpleNamespace(
            Configurations=SimpleNamespace(
                Systems=SimpleNamespace(Sentinel=SimpleNamespace(tenants=[tenant]))
            )
        ),
    )
    monkeypatch.setattr(
        sentinel_importer,
        "SentinelService",
        lambda _tenant: SimpleNamespace(connect=lambda: service),
    )
    monkeypatch.chdir(tmp_path)

    sentinel_importer.run()

    # The quoted rule name is sanitised: quotes become spaces in the file name.
    written = sorted(path.name for path in (tmp_path / "Imported").iterdir())
    assert written == [" NRT rule - tenant-a .yaml", " Scheduled rule - tenant-a .yaml"]
    nrt = (tmp_path / "Imported" / " NRT rule - tenant-a .yaml").read_text(encoding="utf-8")
    assert "nrt: true" in nrt
    assert "uuid: 22222222-2222-4222-8222-222222222222" in nrt
    scheduled = (tmp_path / "Imported" / " Scheduled rule - tenant-a .yaml").read_text(
        encoding="utf-8"
    )
    assert "frequency: 1h" in scheduled
    assert "lookback: 2h" in scheduled
