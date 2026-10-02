"""``opentide rules unreviewed`` lists the RFC 0008 predicate."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from opentide.cli.services.rules import run_unreviewed
from opentide.models.review import parse_window


def _write(path: Path, schema: str, reviewed: str | None) -> None:
    reviewed_line = f"  reviewed: {reviewed!r}\n" if reviewed is not None else ""
    path.write_text(
        "name: Rule\n"
        "metadata:\n"
        "  uuid: 00000000-0000-4000-8000-000000000001\n"
        f"  schema: {schema}\n"
        "  version: 1\n"
        "  created: '2026-01-01'\n"
        "  modified: '2026-01-02'\n"
        f"{reviewed_line}"
        "  tlp: clear\n",
        encoding="utf-8",
    )


def test_run_unreviewed_classifies_rules(tmp_path: Path) -> None:
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    _write(rules / "legacy.yaml", "rule::1.0", None)
    _write(rules / "missing.yaml", "rule::1.1", None)
    _write(rules / "stale.yaml", "rule::1.1", "2020-01-01")
    _write(rules / "fresh.yaml", "rule::1.1", "2026-09-15")
    payload = run_unreviewed(
        tmp_path,
        older_than="90d",
        now=datetime(2026, 10, 2, tzinfo=timezone.utc),
    )
    reasons = {item["path"]: item["reason"] for item in payload["rules"]}
    assert reasons["objects/rules/legacy.yaml"] == "schema"
    assert reasons["objects/rules/missing.yaml"] == "absent"
    assert reasons["objects/rules/stale.yaml"] == "stale"
    assert "objects/rules/fresh.yaml" not in reasons
    assert payload["count"] == 3
    assert parse_window("90d").days == 90


def test_cli_unreviewed_json(tmp_path: Path, invoke_cli) -> None:
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    _write(rules / "legacy.yaml", "rule::1.0", None)
    result = invoke_cli("rules", "unreviewed", "--older-than", "30d", repo=tmp_path)
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["count"] == 1
    assert payload["rules"][0]["reason"] == "schema"


def test_cli_unreviewed_prints_a_human_line(tmp_path: Path, invoke_cli) -> None:
    rules = tmp_path / "objects" / "rules"
    rules.mkdir(parents=True)
    _write(rules / "legacy.yaml", "rule::1.0", None)
    result = invoke_cli(
        "rules",
        "unreviewed",
        "--older-than",
        "30d",
        repo=tmp_path,
        json_output=False,
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    assert "objects/rules/legacy.yaml" in result.stdout
    assert "schema" in result.stdout
    assert "rule::1.0" in result.stdout


def test_cli_rejects_a_zero_window(tmp_path: Path, invoke_cli) -> None:
    result = invoke_cli("rules", "unreviewed", "--older-than", "0d", repo=tmp_path)
    assert result.exit_code != 0
