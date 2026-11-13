"""CLI E2E: the Graylog platform on the tide_corpus (graylog-1.0).

Only the network boundary is faked: the Graylog client's session answers as
Graylog does. The CLI, the registry, the planner, the validator and the runner
are real.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import requests
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import EVERY_RULE

from opentide.platforms.graylog.client import GraylogClient

pytestmark = pytest.mark.cli_e2e

UUID = CORPUS_RULE_UUIDS["graylog"]
RULE = "rule-0015-graylog-event-definition.yaml"
TOKEN = {"GRAYLOG_TOKEN": "token-value"}


def _response(status: int, body: Any) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


class FakeGraylog:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.verdict: dict[str, Any] = {"status": "OK", "explanations": []}

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        path = url.split("graylog.example", 1)[1]
        self.calls.append((method, path, kwargs.get("json")))
        if path == "/api/system":
            return _response(200, {"version": "7.2.2+94adc86"})
        if path == "/api/search/validate":
            return _response(200, self.verdict)
        if path == "/api/search/messages":
            return _response(
                200,
                {
                    "schema": [{"field": "timestamp", "type": "date"}, {"field": "source"}],
                    "datarows": [["2026-11-11T11:59:00.000Z", "host-1"]],
                },
            )
        raise AssertionError(f"unexpected {method} {path}")


@pytest.fixture
def graylog(monkeypatch: pytest.MonkeyPatch) -> FakeGraylog:
    fake = FakeGraylog()
    original = GraylogClient.__init__

    def init(self: GraylogClient, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        self.session.request = fake.request  # type: ignore[method-assign]

    monkeypatch.setattr(GraylogClient, "__init__", init)
    for name, value in TOKEN.items():
        monkeypatch.setenv(name, value)
    return fake


def _mock_deployer(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    deployer = MagicMock()

    class _MockDeployTide:
        def mdr_for(self, platforms: Iterable[str]) -> dict[str, MagicMock]:
            return {"graylog": deployer} if "graylog" in set(platforms) else {}

    monkeypatch.setattr("opentide.platforms.plugins.EnabledPlatforms", _MockDeployTide)
    return deployer


def _path(repo: Path) -> Path:
    return repo / "objects" / "rules" / RULE


def _rewrite(repo: Path, old: str, new: str) -> None:
    path = _path(repo)
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def test_the_corpus_graylog_rule_validates(invoke_cli, tide_corpus_repo: Path) -> None:
    payload = assert_json_ok(invoke_cli("validate", "--file", RULE))
    assert payload["summary"]["warnings"] == 0


def test_a_broken_condition_fails_with_its_code_at_its_path(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    _rewrite(tide_corpus_repo, "condition: count() >= 3", "condition: count() >= 3 or x")
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    (issue,) = [i for i in payload["report"]["issues"] if i["code"] == "graylog_aggregation"]
    assert issue["field_path"] == ["configurations", "graylog", "aggregation", "condition"]


def test_a_legacy_external_id_fails_external_id_in_rule(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(
        tide_corpus_repo,
        "    tags: [office]\n",
        "    tags: [office]\n    rule_id::staging: 65f1c0de2a3b4c5d6e7f8091\n",
    )
    result = invoke_cli("validate", "--file", RULE)
    assert result.exit_code == 1
    assert "external_id_in_rule" in result.output


def test_an_overlapping_filter_window_warns(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(
        tide_corpus_repo,
        "    aggregation:\n      group_by: source\n      condition: count() >= 3\n",
        "",
    )
    payload = assert_json_ok(invoke_cli("validate", "--file", RULE))
    codes = [w["code"] for w in payload["report"]["warnings"]]
    assert codes == ["graylog_overlapping_window"]


def test_two_rules_with_one_title_warn(invoke_cli, tide_corpus_repo: Path) -> None:
    source = _path(tide_corpus_repo)
    copy = source.with_name("rule-0016-graylog-copy.yaml")
    copy.write_text(
        source.read_text(encoding="utf-8").replace(UUID, "00000000-0000-4000-8003-00000091a7e1"),
        encoding="utf-8",
    )
    payload = assert_json_ok(invoke_cli("validate", "--file", RULE))
    assert "graylog_title_duplicate" in [w["code"] for w in payload["report"]["warnings"]]


def test_lint_reports_the_block_advisories(invoke_cli, tide_corpus_repo: Path) -> None:
    _rewrite(tide_corpus_repo, "    streams: sysmon\n", "")
    path = tide_corpus_repo / ".opentide" / "configurations" / "platforms" / "graylog.toml"
    path.write_text(
        path.read_text(encoding="utf-8").replace('streams = ["sysmon"]\n', ""), encoding="utf-8"
    )
    result = invoke_cli("lint", "--file", RULE)
    assert "graylog_all_streams" in result.output


def test_deploy_dry_run_previews_the_create_request(
    invoke_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployer = _mock_deployer(monkeypatch)
    result = invoke_cli(
        "deploy", "--dry-run", "--platform", "graylog", *EVERY_RULE, "--wide", "--skip-promotion"
    )
    payload = assert_json_ok(result)
    assert UUID in payload["plan"]["graylog"]
    preview = next(item for item in payload["payloads"]["graylog"] if item["uuid"] == UUID)
    request = preview["api_request"]
    assert (request["method"], request["path"]) == ("POST", "/api/events/definitions?schedule=true")
    entity = request["body"]["entity"]
    assert request["body"]["share_request"] is None
    assert entity["title"] == "Graylog Event Definition Rule"
    assert entity["priority"] == 3
    assert entity["config"]["streams"] == ["65f0c0ffee0123456789abcd"]
    assert entity["notifications"] == [{"notification_id": "65f0c0ffee0123456789abcf"}]
    assert f"opentide.{UUID}" in entity["tags"] and "managed-by-opentide" in entity["tags"]
    assert "T1059.005" in entity["tactics_techniques"]
    assert preview["tenant"] == "staging"
    assert preview["server_version"] == "7.2"
    deployer.deploy.assert_not_called()


def test_a_dry_run_fails_on_an_alias_the_tenant_lacks(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _rewrite(tide_corpus_repo, "notifications: soc-slack", "notifications: soc-teams")
    _mock_deployer(monkeypatch)
    result = invoke_cli(
        "deploy", "--dry-run", "--platform", "graylog", *EVERY_RULE, "--wide", "--skip-promotion"
    )
    assert result.exit_code == 1
    payload = parse_cli_json(result)
    preview = next(item for item in payload["payloads"]["graylog"] if item["uuid"] == UUID)
    assert preview["code"] == "graylog_alias_unknown"
    assert "soc-teams" in preview["error"]


def test_without_a_reached_tenant_the_preview_names_the_aliases(tide_corpus_repo: Path) -> None:
    from opentide.core.registry import Opentide
    from opentide.deployment.preview import preview_platform_deployment

    Opentide.initialise()
    (preview,) = preview_platform_deployment("graylog", [UUID], tenant_targets={})
    assert "tenant" not in preview
    assert preview["api_request"]["body"]["entity"]["config"]["streams"] == []
    assert preview["unresolved"]["streams"] == ["sysmon"]
    assert preview["unresolved"]["notifications"] == ["soc-slack"]


def test_validate_query_live_asks_the_tenant(invoke_cli, graylog: FakeGraylog) -> None:
    graylog.verdict = {
        "status": "WARNING",
        "explanations": [
            {
                "error_type": "UNKNOWN_FIELD",
                "begin_line": 1,
                "begin_column": 14,
                "error_title": "Unknown field",
                "error_message": "Query contains unknown field: parent_image_lc",
            }
        ],
    }
    result = invoke_cli(
        "validate", "query", "--platform", "graylog", "--live", "--wide", extra_env=TOKEN
    )
    payload = assert_json_ok(result)
    assert payload["supported"] is True
    validations = [call for call in graylog.calls if call[1] == "/api/search/validate"]
    assert validations, "the tenant was asked"
    body = validations[0][2]
    assert body["timerange"] == {"type": "relative", "range": 900}
    assert body["streams"] == ["65f0c0ffee0123456789abcd"]
    assert payload["queries_validated"] == 1
    assert payload["warnings"], "Graylog's WARNING explanations are the check's warnings"
    assert not any(call[1].startswith("/api/events") for call in graylog.calls)


def test_validate_query_live_fails_a_query_graylog_refuses(
    invoke_cli, graylog: FakeGraylog
) -> None:
    graylog.verdict = {
        "status": "ERROR",
        "explanations": [{"error_title": "Query parsing error", "error_message": "incomplete"}],
    }
    result = invoke_cli(
        "validate", "query", "--platform", "graylog", "--live", "--wide", extra_env=TOKEN
    )
    assert result.exit_code == 1
    assert "incomplete" in result.output


def test_validate_query_offline_is_supported(invoke_cli) -> None:
    """Offline, the engine checks the block's query as Lucene in its Graylog dialect.

    The engine finds the query through its bundled Tide catalog, which knows the
    graylog block once language-server regenerates it (the engine catalog gate).
    """
    payload = assert_json_ok(invoke_cli("validate", "query", "--platform", "graylog"))
    assert payload["supported"] is True and payload["mode"] == "offline"


def test_validate_query_checks_a_lucene_file_under_graylog(
    invoke_cli, tide_corpus_repo: Path
) -> None:
    query = tide_corpus_repo / "mshta.lucene"
    query.write_text("EventID:1 AND image_lc:/.*mshta\\.exe/\n", encoding="utf-8")
    payload = assert_json_ok(
        invoke_cli("validate", "query", "--platform", "graylog", "--file", str(query))
    )
    assert payload["queries"] == [
        {
            "path": "mshta.lucene",
            "platform": "graylog",
            "language": "lucene",
            "field_path": [],
            "line": 1,
            "column": 1,
            "errors": 0,
        }
    ]


def test_query_runs_a_read_only_search(invoke_cli, graylog: FakeGraylog) -> None:
    result = invoke_cli(
        "query", "EventID:1", "--platform", "graylog", "--since", "1h", extra_env=TOKEN
    )
    payload = assert_json_ok(result)
    (outcome,) = payload["results"] if "results" in payload else payload["tenants"]
    assert outcome["rows"] == [{"timestamp": "2026-11-11T11:59:00.000Z", "source": "host-1"}]
    assert [call[1] for call in graylog.calls] == ["/api/system", "/api/search/messages"]


def test_query_runs_the_rules_query_on_its_streams(invoke_cli, graylog: FakeGraylog) -> None:
    result = invoke_cli("query", "--platform", "graylog", "--rule", UUID, extra_env=TOKEN)
    assert_json_ok(result)
    body = graylog.calls[-1][2]
    assert body["query"].startswith("EventID:1 AND parent_image_lc")
    assert body["streams"] == ["65f0c0ffee0123456789abcd"]


def test_setup_platforms_enables_graylog(invoke_cli, tmp_path: Path) -> None:
    assert_json_ok(invoke_cli("setup", "platforms", str(tmp_path), "--graylog", "--yes"))
    written = tmp_path / ".opentide" / "configurations" / "platforms" / "graylog.toml"
    assert "enabled = true" in written.read_text(encoding="utf-8")


def test_lint_reports_the_engine_query_warnings(invoke_cli, tide_corpus_repo: Path) -> None:
    """``lint`` kept an engine warning only for a prefix with a language reference, and
    ``graylog_`` had none, so ``graylog_analyzed_field`` reached the editor alone."""
    _rewrite(tide_corpus_repo, "      EventID:1\n", "      message:/.*mimikatz.*/ AND EventID:1\n")
    payload = parse_cli_json(invoke_cli("lint", "--file", RULE))
    assert "graylog_analyzed_field" in [item["code"] for item in payload["findings"]]
