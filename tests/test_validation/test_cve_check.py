"""Tests for CVE validation check."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import opentide.validation.cve_check as cve_check_module
from opentide.validation.cve_check import check_cve_issues
from opentide.validation.scope import ValidationScope


def test_check_cve_issues_skips_when_mitrecve_missing() -> None:
    index = {"objects": {"threat": {"t1": {"threat": {"cve": ["CVE-2024-0001"]}}}}}
    with patch("importlib.import_module", side_effect=ImportError("missing")):
        issues = check_cve_issues(index)
    assert issues == []


def test_check_cve_issues_reports_invalid_cve() -> None:
    index = {
        "objects": {
            "threat": {
                "t1": {
                    "metadata": {"uuid": "00000000-0000-4000-8000-000000000001"},
                    "threat": {"cve": ["CVE-2024-BAD"]},
                }
            }
        },
        "files": {},
    }
    mock_crawler = MagicMock()
    mock_crawler.get_main_page.side_effect = RuntimeError("not found")

    with (
        patch("importlib.import_module", return_value=mock_crawler),
        patch.object(cve_check_module, "_apply_cve_proxy_settings") as mock_proxy,
    ):
        issues = check_cve_issues(index, ValidationScope.full())

    mock_proxy.assert_called_once()
    assert len(issues) == 1
    assert issues[0].code == "invalid_cve"


def test_check_cve_issues_respects_scope() -> None:
    index = {
        "objects": {
            "threat": {
                "t1": {
                    "metadata": {"uuid": "00000000-0000-4000-8000-000000000099"},
                    "threat": {"cve": ["CVE-2024-0001"]},
                }
            }
        },
        "files": {},
    }
    scope = ValidationScope.narrow(uuids=frozenset({"00000000-0000-4000-8000-000000000001"}))
    with patch("importlib.import_module", side_effect=ImportError("missing")):
        issues = check_cve_issues(index, scope)
    assert issues == []
