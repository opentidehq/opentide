"""Sentinel importer: pure helpers and the listing-to-YAML path.

The importer needs no SDK stubs: it lists rules through the ARM REST client,
which ships with ``pip install opentide``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

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


def _import(
    listed: list[dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, dict[str, Any]]:
    """Run the importer over *listed* for one tenant and return each written file, parsed."""
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
    return {
        path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in sorted((tmp_path / "Imported").iterdir())
    }


def _scheduled(name: str, **properties: Any) -> dict[str, Any]:
    return _listed(
        "Scheduled",
        name,
        queryFrequency="PT1H",
        queryPeriod="PT2H",
        triggerOperator="GreaterThan",
        triggerThreshold=0,
        **properties,
    )


def test_import_writes_incident_grouping_lists_as_valid_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Group-by lists were mis-indented, so a rule that grouped incidents was unparsable."""
    grouped = _scheduled(
        "11111111-1111-4111-8111-111111111111",
        incidentConfiguration={
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "Selected",
                "groupByEntities": ["Account", "Host"],
                "groupByAlertDetails": ["DisplayName"],
                "groupByCustomDetails": ["Computer", "a: b"],
            },
        },
    )

    files = _import([grouped], tmp_path, monkeypatch)

    sentinel = files[" Scheduled rule - tenant-a .yaml"]["configurations"]["sentinel"]
    alert = sentinel["grouping"]["alert"]
    assert alert["grouping_lookback"] == "5h"
    assert alert["matching"] == "Selected"
    assert alert["group_by_entities"] == ["Account", "Host"]
    assert alert["group_by_alert_details"] == ["DisplayName"]
    assert alert["group_by_custom_details"] == ["Computer", "a: b"]


def test_import_keeps_values_that_yaml_would_misread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Values were pasted into the YAML unescaped.

    An alert title starting with ``{{Computer}}`` opened a flow mapping, a ``"``
    in the display name ended the hand-quoted name, and a description or query
    whose first line is indented broke the block scalar.
    """
    rule = _scheduled(
        "11111111-1111-4111-8111-111111111111",
        displayName='Logon by "admin" \\ svc',
        description="  indented first line\nsecond line",
        query="  SecurityEvent\n| take 1",
        alertDetailsOverride={
            "alertDisplayNameFormat": "{{Computer}} logged on",
            "alertDescriptionFormat": "  {{Account}}: logon\nfrom {{IpAddress}}",
        },
        customDetails={"Host: name": "Computer"},
        entityMappings=[
            {
                "entityType": "Account",
                "fieldMappings": [{"identifier": "Name", "columnName": "#Account"}],
            }
        ],
    )

    files = _import([rule], tmp_path, monkeypatch)

    (document,) = files.values()
    assert document["name"] == 'Logon by "admin" \\ svc - tenant-a'
    assert document["description"] == "  indented first line\nsecond line\n"
    sentinel = document["configurations"]["sentinel"]
    assert sentinel["alert"]["title"] == "{{Computer}} logged on"
    assert sentinel["alert"]["description"] == "  {{Account}}: logon\nfrom {{IpAddress}}\n"
    assert sentinel["alert"]["custom_details"] == [{"key": "Host: name", "column": "Computer"}]
    assert sentinel["entities"] == [
        {"entity": "Account", "mappings": [{"identifier": "Name", "column": "#Account"}]}
    ]
    assert sentinel["query"] == "  SecurityEvent\n| take 1\n"
    assert sentinel["tenants"] == ["tenant-a"]


def test_import_never_overwrites_a_rule_with_the_same_display_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sentinel allows duplicate display names; the second rule overwrote the first file."""
    first = _scheduled("33333333-3333-4333-8333-333333333333", displayName="Dup rule")
    second = _scheduled("44444444-4444-4444-8444-444444444444", displayName="Dup rule")

    files = _import([first, second], tmp_path, monkeypatch)

    uuids = {name: document["metadata"]["uuid"] for name, document in files.items()}
    assert uuids == {
        " Dup rule - tenant-a .yaml": "33333333-3333-4333-8333-333333333333",
        " Dup rule - tenant-a  44444444.yaml": "44444444-4444-4444-8444-444444444444",
    }
