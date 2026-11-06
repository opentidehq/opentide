"""explorer#85: ``generate explorer --include-visibility`` exports visibility, opt-in.

A telemetry inventory says what an organisation cannot see, so the export is
written only when asked for, and a run without the flag removes the one an
earlier run wrote. Synthetic fixtures only: the tide_corpus, with a
``visibility.toml`` declaring the table its Sentinel rules read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

VISIBILITY = """\
[[logsources]]
name = "SecurityEvent"
description = "Windows security events."
system = "sentinel"

[logsources.columns]
EventID = { type = "int", description = "The event's identifier." }

[[logsources]]
name = "Contoso_Audit_CL"
description = "Administrative audit events."
system = "sentinel"
"""


@pytest.fixture
def visibility_corpus(tide_corpus_repo: Path) -> Path:
    config = tide_corpus_repo / ".opentide" / "configurations"
    config.mkdir(parents=True, exist_ok=True)
    (config / "visibility.toml").write_text(VISIBILITY, encoding="utf-8")
    return tide_corpus_repo


def _export(repo: Path) -> Path:
    return repo / ".opentide" / "exports" / "explorer.visibility.json"


def test_visibility_is_not_exported_unless_asked_for(invoke_cli, visibility_corpus: Path) -> None:
    assert_json_ok(invoke_cli("generate", "explorer"))
    assert (visibility_corpus / ".opentide/exports/explorer.bundle.json").is_file()
    assert not _export(visibility_corpus).exists()
    bundle = (visibility_corpus / ".opentide/exports/explorer.bundle.json").read_text("utf-8")
    assert "Contoso_Audit_CL" not in bundle


def test_include_visibility_exports_log_sources_and_the_rules_that_read_them(
    invoke_cli, visibility_corpus: Path
) -> None:
    assert_json_ok(invoke_cli("generate", "explorer", "--include-visibility"))
    document = json.loads(_export(visibility_corpus).read_text(encoding="utf-8"))
    assert document["version"] == "1.0"
    assert document["tlp"] == "amber"
    assert document["present"] is True
    sources = {(s["system"], s["name"]): s for s in document["logsources"]}
    security = sources[("sentinel", "SecurityEvent")]
    assert security["columns"] == [
        {"name": "EventID", "type": "int", "description": "The event's identifier."}
    ]
    assert CORPUS_RULE_UUIDS["sentinel"] in security["read_by"]
    assert CORPUS_RULE_UUIDS["sentinel"] in security["rules"]
    assert sources[("sentinel", "Contoso_Audit_CL")]["rules"] == []
    reads = {(r["rule"], r["system"], r["name"]) for r in document["reads"]}
    assert (CORPUS_RULE_UUIDS["sentinel"], "sentinel", "SecurityEvent") in reads
    # Defender reads a table no defender log source declares.
    undeclared = {(u["system"], u["name"]): u for u in document["undeclared"]}
    defender = undeclared[("defender_for_endpoint", "DeviceProcessEvents")]
    assert defender["system_declares"] is False
    assert document["systems"]["sentinel"] == {"logsources": 2, "with_columns": 1, "used": 1}


def test_a_run_without_the_flag_removes_an_earlier_export(
    invoke_cli, visibility_corpus: Path
) -> None:
    assert_json_ok(
        invoke_cli("generate", "explorer", "--include-visibility", "--visibility-tlp", "RED")
    )
    assert json.loads(_export(visibility_corpus).read_text(encoding="utf-8"))["tlp"] == "red"
    assert_json_ok(invoke_cli("generate", "explorer"))
    assert not _export(visibility_corpus).exists()


def test_an_unknown_tlp_is_a_usage_error(invoke_cli, visibility_corpus: Path) -> None:
    result = invoke_cli("generate", "explorer", "--include-visibility", "--visibility-tlp", "pink")
    assert result.exit_code == 2, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["failure"]["code"].startswith("usage")
    assert "amber+strict" in payload["message"]
    assert not _export(visibility_corpus).exists()
