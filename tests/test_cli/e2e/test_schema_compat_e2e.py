"""CLI E2E: forward schema slice scaffold."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import load_corpus_manifest

pytestmark = pytest.mark.cli_e2e


@pytest.mark.xfail(reason="rule::1.1 slice reserved until SchemaVersionChain is registered")
def test_future_rule_1_1_slice_not_active() -> None:
    manifest = load_corpus_manifest()
    future = next(
        slice_info for slice_info in manifest["slices"] if slice_info["name"] == "future_rule_1_1"
    )
    assert future["status"] == "reserved"
    assert "rule::1.1" in future["schemas"]
