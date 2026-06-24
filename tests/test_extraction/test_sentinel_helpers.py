"""Pure helper coverage for the Sentinel importer script."""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock


def _load_sentinel_helpers():
    azure = ModuleType("azure")
    azure.mgmt = ModuleType("azure.mgmt")
    azure.mgmt.securityinsight = MagicMock()
    azure.identity = MagicMock()
    sys.modules.setdefault("azure", azure)
    sys.modules.setdefault("azure.mgmt", azure.mgmt)
    sys.modules.setdefault("azure.mgmt.securityinsight", azure.mgmt.securityinsight)
    sys.modules.setdefault("azure.identity", azure.identity)

    from opentide.extraction.sentinel_importer import convert_period, sanitize_filename

    return convert_period, sanitize_filename


convert_period, sanitize_filename = _load_sentinel_helpers()


def test_convert_period_strips_iso_prefix() -> None:
    assert convert_period("PT5M") == "5m"
    assert convert_period("P1D") == "1d"


def test_sanitize_filename_replaces_invalid_chars() -> None:
    assert sanitize_filename('rule<>:"/\\|?*name') == "rule         name"
