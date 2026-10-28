"""CLI E2E: a deploy reports each rule as it is sent and counts every run, failed ones too (#675).

The real Sentinel deployer runs against a fake tenant client, so the per-rule events,
the human log, and the ``--json`` ``results`` all come from the code a pipeline runs.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from azure.core.exceptions import HttpResponseError
from tests.corpus_support import CORPUS_RULE_UUIDS, write_rule_variant
from tests.test_cli.conftest import parse_cli_json
from tests.test_cli.e2e.helpers import uncomment_tenants

pytestmark = pytest.mark.cli_e2e

PLAN = ("deploy", "--platform", "sentinel", "--strategy", "PREVIEW", "--all", "--skip-promotion")
EXTRA = [f"00000000-0000-4000-8003-000000000{500 + index}" for index in range(4)]
#: The corpus's two Sentinel rules plus four variants, in the order the plan sends them.
EVERY = [CORPUS_RULE_UUIDS["sentinel"], "00000000-0000-4000-8003-000000000008", *EXTRA]


class _AlertRules:
    def __init__(self, failing: str | None) -> None:
        self.failing = failing
        self.sent: list[str] = []

    def create_or_update(self, **kwargs: Any) -> None:
        rule_id = str(kwargs["rule_id"])
        self.sent.append(rule_id)
        if rule_id == self.failing:
            error = HttpResponseError(
                message="(BadRequest) Failed to parse query: syntax error near '|'\n"
                "Code: BadRequest\nMessage: Failed to parse query: syntax error near '|'"
            )
            error.status_code = 400
            raise error


@pytest.fixture
def tenant(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for flag in ("DEPLOYMENT_ERROR_RAISED", "DEPLOYMENT_WARNING_RAISED"):
        monkeypatch.setenv(flag, "")
        monkeypatch.delenv(flag)
    for name in ("WORKSPACE_ID", "TENANT_ID", "SUBSCRIPTION_ID", "CLIENT_ID", "CLIENT_SECRET"):
        monkeypatch.setenv(f"AZURE_{name}", "demo")
    rules = tide_corpus_repo / "objects" / "rules"
    for index, uuid in enumerate(EXTRA):
        write_rule_variant(rules, f"rule-{500 + index}-progress.yaml", uuid)
    uncomment_tenants(tide_corpus_repo / ".opentide/configurations/systems/sentinel.toml")
    return tide_corpus_repo


def _fake_sentinel(monkeypatch: pytest.MonkeyPatch, failing: str | None = None) -> _AlertRules:
    alert_rules = _AlertRules(failing)

    class _Client:
        pass

    client = _Client()
    client.alert_rules = alert_rules  # ty: ignore[unresolved-attribute]  # test double

    class _Service:
        def __init__(self, tenant_config: object) -> None:
            self.tenant_config = tenant_config

        def connect(self) -> _Client:
            return client

    # Not a dotted-path setattr: a test that purges the module leaves the package
    # without its ``client`` attribute, which that form resolves through.
    sentinel_client = importlib.import_module("opentide.platforms.sentinel.client")
    monkeypatch.setattr(sentinel_client, "SentinelService", _Service)
    return alert_rules


def _human(invoke_cli, *args: str):
    return invoke_cli(*args, json_output=False, extra_env={"OPENTIDE_OUTPUT": "plain"})


def test_json_results_has_one_entry_per_rule_with_its_outcome(
    invoke_cli, tenant: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _fake_sentinel(monkeypatch)
    result = invoke_cli(*PLAN)
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "completed"
    rows = payload["results"]
    assert [row["id"] for row in rows] == sent.sent
    assert sorted(sent.sent) == sorted(EVERY)
    for row in rows:
        assert set(row) == {
            "id",
            "name",
            "platform",
            "tenant",
            "action",
            "status",
            "seconds",
            "error",
            "reason",
        }
        assert row["platform"] == "sentinel"
        assert row["tenant"]
        assert row["status"] == "deployed"
        assert row["action"] == "upsert"
        assert row["error"] is None
        assert row["seconds"] >= 0
    summary = payload["summary"]
    assert summary["upsert"] == len(EVERY)
    assert (summary["failed"], summary["not_attempted"], summary["skipped"]) == (0, 0, 0)
    assert summary["seconds"] >= 0
    assert payload["message"].startswith(f"Deployed {len(EVERY)} rules to 1 tenant")
    assert "0 failed, 0 not attempted" in payload["message"]


def test_a_rejected_rule_stops_the_run_and_the_result_says_what_happened(
    invoke_cli, tenant: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _fake_sentinel(monkeypatch, failing=EVERY[2])
    result = invoke_cli(*PLAN)
    assert result.exit_code == 1, result.stdout + result.stderr
    assert "Traceback" not in result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    assert payload["failure"]["code"] == "issues_found"
    # Rules before the rejected one went out, the rejected one was tried, the rest were not.
    assert sent.sent == EVERY[:3]
    assert [(row["id"], row["status"]) for row in payload["results"]] == [
        (EVERY[0], "deployed"),
        (EVERY[1], "deployed"),
        (EVERY[2], "failed"),
        (EVERY[3], "not_attempted"),
        (EVERY[4], "not_attempted"),
        (EVERY[5], "not_attempted"),
    ]
    failed = payload["results"][2]
    assert failed["error"] == "HTTP 400: Failed to parse query: syntax error near '|'"
    assert payload["results"][3]["reason"] == "not attempted after a failure"
    assert payload["results"][3]["seconds"] == 0
    summary = payload["summary"]
    assert (summary["upsert"], summary["failed"], summary["not_attempted"]) == (2, 1, 3)
    assert payload["message"].startswith(
        "Deployment failed · 2 created or updated, 1 failed, 3 not"
    )
    assert failed["name"] in payload["error"]


def test_the_human_log_has_a_line_per_rule_and_ends_on_the_counts(
    invoke_cli, tenant: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_sentinel(monkeypatch)
    result = _human(invoke_cli, *PLAN)
    assert result.exit_code == 0, result.stdout + result.stderr
    log = result.stderr
    assert "Deploy plan · strategy PREVIEW · 1 platform, 1 tenant" in log
    assert "Deploying to sentinel / " in log
    assert f"{len(EVERY)} rules" in log
    lines = [line for line in log.splitlines() if "] ✓ deployed" in line]
    assert [line.split("]")[0].strip() for line in lines] == [
        f"[{index}/{len(EVERY)}" for index in range(1, len(EVERY) + 1)
    ]
    assert "\r" not in log
    assert "\x1b" not in log
    assert f"✓ sentinel · {len(EVERY)} deployed, 0 failed, 0 not attempted" in log
    assert result.stdout.splitlines()[-1].startswith(f"✓ Deployed {len(EVERY)} rules to 1 tenant")


def test_the_human_log_of_a_failed_run_names_the_rule_and_the_platform_message(
    invoke_cli, tenant: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_sentinel(monkeypatch, failing=EVERY[1])
    result = _human(invoke_cli, *PLAN)
    assert result.exit_code == 1, result.stdout + result.stderr
    log = result.stderr
    assert "Traceback" not in log
    (failure,) = [line for line in log.splitlines() if "] ✗ failed" in line]
    assert "[2/6]" in failure
    assert "HTTP 400: Failed to parse query: syntax error near '|'" in failure
    assert len([line for line in log.splitlines() if "· skipped" in line]) == 4
    assert "✗ sentinel · 1 deployed, 1 failed, 4 not attempted" in log
    last = [line for line in log.splitlines() if line.strip()][-1]
    assert last.startswith("✗ Deployment failed · 1 created or updated, 1 failed, 4 not attempted")


def test_a_dry_run_sends_nothing_and_says_so_last(
    invoke_cli, tenant: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _fake_sentinel(monkeypatch)
    human = _human(invoke_cli, *PLAN, "--dry-run")
    assert human.exit_code == 0, human.stdout + human.stderr
    assert sent.sent == []
    assert human.stdout.splitlines()[-1] == "dry run, nothing sent"
    assert any(line.startswith("Plan: ") for line in human.stdout.splitlines())
    document = invoke_cli(*PLAN, "--dry-run")
    assert "results" not in parse_cli_json(document)
    assert "dry run, nothing sent" not in document.stdout
    assert json.loads(document.stdout)["dry_run"] is True


def test_json_stdout_stays_one_document_while_rules_are_sent(
    invoke_cli, tenant: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_sentinel(monkeypatch, failing=EVERY[1])
    result = invoke_cli(*PLAN)
    assert result.exit_code == 1
    json.loads(result.stdout)  # one document, nothing else on stdout
    assert "] ✓ deployed" not in result.stdout
