"""Defender for Endpoint importer: rule YAML and the files one import writes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from opentide.extraction import mde_importer


def _graph_rule(detector_id: str, name: str = "Suspicious logon") -> dict[str, Any]:
    return {
        "id": "123",
        "detectorId": detector_id,
        "displayName": name,
        "createdDateTime": "2026-01-01T00:00:00Z",
        "lastModifiedDateTime": "2026-01-02T00:00:00Z",
        "createdBy": "alice@example.com",
        "lastModifiedBy": "alice@example.com",
        "isEnabled": True,
        "schedule": {"period": "1H"},
        "queryCondition": {"queryText": "DeviceLogonEvents\n| take 1"},
        "detectionAction": {
            "alertTemplate": {
                "severity": "high",
                "description": "desc",
                "category": "InitialAccess",
                "impactedAssets": [],
            }
        },
    }


def test_render_rule_targets_the_tenant_it_was_listed_from() -> None:
    """Every imported rule used to name the original author's tenant, ``PandoraStores``."""
    rule = _graph_rule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", name='Logon by "admin"')

    _filename, body = mde_importer._render_rule(rule, "Contoso")

    document = yaml.safe_load(body)
    assert document["name"] == 'Logon by "admin"'
    assert document["metadata"]["uuid"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert document["configurations"]["defender_for_endpoint"]["tenants"] == ["Contoso"]
    assert "PandoraStores" not in body


def test_import_never_overwrites_a_rule_from_this_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two rules with one display name, or one per tenant, used to share one file."""
    listed = {
        "Contoso": [
            _graph_rule("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
            _graph_rule("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        ],
        "Fabrikam": [_graph_rule("cccccccc-cccc-4ccc-8ccc-cccccccccccc")],
    }

    class Importer:
        def __init__(self, tenant: SimpleNamespace) -> None:
            self.tenant = tenant

        def list_rules(self) -> list[dict[str, Any]]:
            return listed[self.tenant.name]

    tenants = [SimpleNamespace(name=name) for name in listed]
    monkeypatch.setattr(
        mde_importer,
        "Opentide",
        SimpleNamespace(
            Configurations=SimpleNamespace(
                Systems=SimpleNamespace(DefenderForEndpoint=SimpleNamespace(tenants=tenants))
            )
        ),
    )
    monkeypatch.setattr(mde_importer, "DefenderForEndpointImporter", Importer)
    monkeypatch.setattr(mde_importer, "record_external_id", lambda *_args: None)
    monkeypatch.chdir(tmp_path)

    mde_importer.run()

    written = {
        path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in (tmp_path / "Imported").iterdir()
    }
    assert {name: document["metadata"]["uuid"] for name, document in written.items()} == {
        "Suspicious logon - Contoso.yaml": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "Suspicious logon - Contoso bbbbbbbb.yaml": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "Suspicious logon - Fabrikam.yaml": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    }


class _Response:
    def __init__(self, status_code: int, payload: dict[str, Any], reason: str = "OK") -> None:
        self.status_code = status_code
        self.reason = reason
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class _Session:
    def __init__(self, pages: dict[str, _Response]) -> None:
        self.pages = pages
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> _Response:
        self.calls.append((url, kwargs))
        return self.pages[url]


def _importer(session: _Session) -> mde_importer.DefenderForEndpointImporter:
    # The real constructor fetches a token; only the listing is under test.
    importer = object.__new__(mde_importer.DefenderForEndpointImporter)
    importer.session = session
    importer.DETECTION_RULES_ENDPOINT = "https://graph.example/rules"
    importer.tenant_config = SimpleNamespace(name="Contoso")
    return importer


def test_list_rules_follows_next_links_with_a_timeout() -> None:
    """Only the first page was read, and a silent tenant hung the import forever."""
    session = _Session(
        {
            "https://graph.example/rules": _Response(
                200,
                {
                    "value": [{"detectorId": "a"}],
                    "@odata.nextLink": "https://graph.example/rules?$skiptoken=2",
                },
            ),
            "https://graph.example/rules?$skiptoken=2": _Response(
                200, {"value": [{"detectorId": "b"}]}
            ),
        }
    )

    rules = _importer(session).list_rules()

    assert [rule["detectorId"] for rule in rules] == ["a", "b"]
    assert [kwargs["timeout"] for _url, kwargs in session.calls] == [60, 60]


def test_list_rules_raises_on_an_error_answer() -> None:
    """A 401 or 403 body has no ``value`` and used to fail later with a bare KeyError."""
    session = _Session(
        {"https://graph.example/rules": _Response(403, {"error": {}}, reason="Forbidden")}
    )

    with pytest.raises(RuntimeError, match="tenant Contoso failed with HTTP 403 Forbidden"):
        _importer(session).list_rules()
