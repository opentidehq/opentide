"""Pure helper coverage for the Sentinel importer script.

The helpers under test are string manipulation, but importing the module they
live in pulls in the Azure SDK. Stubs stand in when ``opentide[sentinel]`` is
absent — installed through ``patch.dict`` so they are torn down again. A
module-level ``sys.modules.setdefault`` left a non-package ``azure`` behind for
the rest of the session, which silently changed what every later test saw
about the installed SDK.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

AZURE_STUBS = ("azure", "azure.mgmt", "azure.mgmt.securityinsight", "azure.identity")


def _stub_modules() -> dict[str, Any]:
    """Minimal stand-ins for the Azure names the importer binds at module scope."""
    azure = ModuleType("azure")
    azure.__path__ = []  # type: ignore[attr-defined]
    mgmt = ModuleType("azure.mgmt")
    mgmt.__path__ = []  # type: ignore[attr-defined]
    return {
        "azure": azure,
        "azure.mgmt": mgmt,
        "azure.mgmt.securityinsight": MagicMock(),
        "azure.identity": MagicMock(),
    }


@pytest.fixture
def sentinel_helpers() -> Iterator[ModuleType]:
    stubs = {name: value for name, value in _stub_modules().items() if name not in sys.modules}
    # Re-import under the stubs, then drop the stub-bound module so nothing
    # downstream inherits a MagicMock where the real SDK belongs.
    sys.modules.pop("opentide.extraction.sentinel_importer", None)
    try:
        with patch.dict(sys.modules, stubs):
            import opentide.extraction.sentinel_importer as module

            yield module
    finally:
        sys.modules.pop("opentide.extraction.sentinel_importer", None)


def test_convert_period_strips_iso_prefix(sentinel_helpers: ModuleType) -> None:
    assert sentinel_helpers.convert_period("PT5M") == "5m"
    assert sentinel_helpers.convert_period("P1D") == "1d"


def test_sanitize_filename_replaces_invalid_chars(sentinel_helpers: ModuleType) -> None:
    assert sentinel_helpers.sanitize_filename('rule<>:"/\\|?*name') == "rule         name"


def test_azure_stubs_do_not_leak_into_the_session() -> None:
    """Regression guard: the stubs above must not outlive their fixture."""
    for name in AZURE_STUBS:
        module = sys.modules.get(name)
        assert not isinstance(module, MagicMock), f"{name} left stubbed in sys.modules"
