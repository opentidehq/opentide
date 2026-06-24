"""CLI E2E: generate command."""

from __future__ import annotations

import pytest
from tests.test_cli.conftest import assert_json_ok

pytestmark = pytest.mark.cli_e2e


def test_generate_phase_schemas(invoke_cli, tide_corpus_repo) -> None:
    result = invoke_cli("generate", "--phase", "schemas")
    assert_json_ok(result)
    assert (tide_corpus_repo / "Schemas" / "MDR Schema.json").is_file()
    assert (tide_corpus_repo / "Schemas" / "TVM Schema.json").is_file()
