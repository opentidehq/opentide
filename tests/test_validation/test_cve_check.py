"""Tests for CVE validation against Vulnerability-Lookup."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import opentide.validation.cve_check as cve_check_module
from opentide.validation.scope import ValidationScope
from opentide.vulnerability_lookup import (
    CveSettings,
    VulnerabilityLookupClient,
    VulnerabilityLookupError,
    VulnerabilityRecord,
)


class _FakeLookup:
    def __init__(
        self,
        *,
        found: set[str] | None = None,
        error: str | None = None,
    ) -> None:
        self.found = found or set()
        self.error = error

    def get(self, vuln_id: str, *, with_linked: bool = False) -> VulnerabilityRecord | None:
        _ = with_linked
        if self.error:
            raise VulnerabilityLookupError(self.error)
        if vuln_id in self.found:
            return VulnerabilityRecord(
                identifier=vuln_id,
                page_url=f"https://vulnerability.circl.lu/vuln/{vuln_id}",
            )
        return None


def _threat_index(cve: list[str], uuid: str = "00000000-0000-4000-8000-000000000001") -> dict:
    return {
        "objects": {
            "threat": {
                "t1": {
                    "metadata": {"uuid": uuid},
                    "threat": {"cve": cve},
                }
            }
        },
        "files": {},
    }


def test_check_cve_issues_reports_invalid_cve() -> None:
    index = _threat_index(["CVE-2024-BAD"])
    with (
        patch.object(cve_check_module, "load_cve_settings", return_value=CveSettings()),
        patch.object(cve_check_module, "apply_cve_proxy_settings") as mock_proxy,
    ):
        issues = cve_check_module.check_cve_issues(
            index,
            ValidationScope.full(),
            client=_FakeLookup(),
        )

    mock_proxy.assert_called_once()
    assert len(issues) == 1
    assert issues[0].code == "invalid_cve"
    assert "CVE-2024-BAD" in issues[0].message
    assert issues[0].suggestion is not None
    assert "vulnerability.circl.lu" in issues[0].suggestion


def test_check_cve_issues_accepts_known_identifier() -> None:
    index = _threat_index(["CVE-2024-3094"])
    with (
        patch.object(cve_check_module, "load_cve_settings", return_value=CveSettings()),
        patch.object(cve_check_module, "apply_cve_proxy_settings"),
    ):
        issues = cve_check_module.check_cve_issues(
            index,
            client=_FakeLookup(found={"CVE-2024-3094"}),
        )
    assert issues == []


def test_check_cve_issues_skips_when_lookup_unavailable() -> None:
    index = _threat_index(["CVE-2024-3094"])
    with (
        patch.object(cve_check_module, "load_cve_settings", return_value=CveSettings()),
        patch.object(cve_check_module, "apply_cve_proxy_settings"),
    ):
        issues = cve_check_module.check_cve_issues(
            index,
            client=_FakeLookup(error="offline"),
        )
    assert issues == []


def test_check_cve_issues_respects_scope() -> None:
    index = _threat_index(["CVE-2024-0001"], uuid="00000000-0000-4000-8000-000000000099")
    scope = ValidationScope.narrow(uuids=frozenset({"00000000-0000-4000-8000-000000000001"}))
    client = MagicMock()
    with (
        patch.object(cve_check_module, "load_cve_settings", return_value=CveSettings()),
        patch.object(cve_check_module, "apply_cve_proxy_settings"),
    ):
        issues = cve_check_module.check_cve_issues(index, scope, client=client)
    assert issues == []
    client.get.assert_not_called()


def test_check_cve_issues_reports_only_unknown_among_mixed_list() -> None:
    index = _threat_index(["CVE-2024-3094", "CVE-2024-BAD"])
    with (
        patch.object(cve_check_module, "load_cve_settings", return_value=CveSettings()),
        patch.object(cve_check_module, "apply_cve_proxy_settings"),
    ):
        issues = cve_check_module.check_cve_issues(
            index,
            client=_FakeLookup(found={"CVE-2024-3094"}),
        )
    assert len(issues) == 1
    assert issues[0].context is not None
    assert issues[0].context["broken_cve"] == ["CVE-2024-BAD"]


def test_check_cve_issues_skips_threats_without_cve() -> None:
    index = _threat_index([])
    client = MagicMock()
    with (
        patch.object(cve_check_module, "load_cve_settings", return_value=CveSettings()),
        patch.object(cve_check_module, "apply_cve_proxy_settings"),
    ):
        issues = cve_check_module.check_cve_issues(index, client=client)
    assert issues == []
    client.get.assert_not_called()


def test_check_cve_issues_accepts_gcve0_mapped_to_cve() -> None:
    from tests.test_vulnerability_lookup.test_client import CVE5_PAYLOAD

    session = MagicMock()
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = CVE5_PAYLOAD
    session.get.return_value = response
    client = VulnerabilityLookupClient(CveSettings(), session=session)
    index = _threat_index(["GCVE-0-2024-3094"])
    with (
        patch.object(cve_check_module, "load_cve_settings", return_value=CveSettings()),
        patch.object(cve_check_module, "apply_cve_proxy_settings"),
    ):
        issues = cve_check_module.check_cve_issues(index, client=client)
    assert issues == []
    called_url = session.get.call_args.kwargs.get("url") or session.get.call_args.args[0]
    assert called_url.endswith("/api/vulnerability/CVE-2024-3094")
