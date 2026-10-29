"""The per-rule deploy log: lines as rules finish, counts, rules a failure never reached (#675)."""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from opentide.cli.services.deploy_plan import (
    PlannedChange,
    outcome_message,
    run_counts,
    run_summary,
)
from opentide.cli.ui.deploy_log import (
    NOT_ATTEMPTED,
    DeployLog,
    counts_text,
    header_line,
    result_line,
)
from opentide.cli.ui.mode import OutputMode
from opentide.cli.ui.progress import Checklist
from opentide.core.deploy_events import RuleResult


def _change(index: int, *, platform: str = "sentinel", tenant: str = "contoso") -> PlannedChange:
    return PlannedChange(
        platform=platform,
        tenant=tenant,
        uuid=f"u{index}",
        name=f"Rule {index}",
        status="STAGING",
        action="upsert",
    )


def _result(index: int, status: str = "deployed", **fields: object) -> RuleResult:
    return RuleResult(
        platform="sentinel",
        tenant="contoso",
        id=f"u{index}",
        name=f"Rule {index}",
        status=status,  # ty: ignore[invalid-argument-type]  # parametrised in the tests
        seconds=0.9,
        **fields,  # ty: ignore[invalid-argument-type]
    )


def _log(
    changes: list[PlannedChange], *, mode: OutputMode = OutputMode.PLAIN, quiet: bool = False
) -> tuple[DeployLog, io.StringIO]:
    stream = io.StringIO()
    console = Console(file=stream, force_terminal=False, width=100, highlight=False)
    checklist = Checklist(console, mode=mode, quiet=quiet)
    return DeployLog(checklist, changes), stream


def test_each_rule_prints_its_line_when_it_finishes_not_at_the_end() -> None:
    log, stream = _log([_change(1), _change(2), _change(3)])
    log.rule_finished(_result(1, action="update"))
    after_first = stream.getvalue()
    assert "Deploying to sentinel / contoso · 3 rules" in after_first
    assert "[1/3] ✓ updated   Rule 1" in after_first
    assert "Rule 2" not in after_first
    log.rule_finished(_result(2))
    log.rule_finished(_result(3))
    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert [line.split("]")[0].strip() for line in lines[1:]] == ["[1/3", "[2/3", "[3/3"]
    assert "✓ deployed  Rule 2" in stream.getvalue()


def test_a_log_has_no_carriage_return_and_no_spinner_frame() -> None:
    log, stream = _log([_change(1), _change(2)])
    log.rule_finished(_result(1))
    log.rule_finished(_result(2, "failed", error="HTTP 400: bad query"))
    log.unreached()
    assert "\r" not in stream.getvalue()
    assert "\x1b" not in stream.getvalue()


def test_a_failure_line_carries_the_platform_message() -> None:
    log, stream = _log([_change(1)])
    log.rule_finished(_result(1, "failed", error="HTTP 400: Failed to parse query"))
    assert "✗ failed    Rule 1" in stream.getvalue()
    assert "HTTP 400: Failed to parse query" in stream.getvalue()


def test_rules_after_a_failure_are_reported_as_not_attempted() -> None:
    log, stream = _log([_change(index) for index in range(1, 6)])
    log.rule_finished(_result(1))
    log.rule_finished(_result(2, "failed", error="HTTP 400: nope"))
    missing = log.unreached()
    assert [(result.id, result.status, result.reason) for result in missing] == [
        ("u3", "not_attempted", NOT_ATTEMPTED),
        ("u4", "not_attempted", NOT_ATTEMPTED),
        ("u5", "not_attempted", NOT_ATTEMPTED),
    ]
    assert counts_text(log.results) == "1 deployed, 1 failed, 3 not attempted"
    out = stream.getvalue()
    assert "[3/5] · skipped   Rule 3" in out
    assert out.count("not attempted after a failure") == 3
    # A second call has nothing left to report.
    assert log.unreached() == []


def test_a_platform_the_run_never_reached_gets_a_header_and_its_rules_not_attempted() -> None:
    changes = [_change(1), _change(2, platform="splunk", tenant="soc")]
    log, stream = _log(changes)
    log.rule_finished(_result(1, "failed", error="HTTP 500: down"))
    log.unreached()
    assert "Deploying to splunk / soc · 1 rule" in stream.getvalue()
    assert [(r.platform, r.status) for r in log.results] == [
        ("sentinel", "failed"),
        ("splunk", "not_attempted"),
    ]


def test_an_engine_that_reports_no_rules_is_taken_at_its_word_silently() -> None:
    log, stream = _log([_change(1), _change(2)])
    log.settle("sentinel")
    assert [(r.id, r.status, r.action) for r in log.results] == [
        ("u1", "deployed", "upsert"),
        ("u2", "deployed", "upsert"),
    ]
    assert stream.getvalue() == ""


def test_an_engine_that_reports_some_rules_must_report_them_all() -> None:
    log, _ = _log([_change(1), _change(2)])
    log.rule_finished(_result(1))
    log.settle("sentinel")
    assert [(r.id, r.status) for r in log.results] == [("u1", "deployed"), ("u2", "skipped")]


def test_the_action_comes_from_the_plan_and_names_the_verb() -> None:
    changes = [
        PlannedChange("defender_for_endpoint", "t", "a", "A", "PROD", "create"),
        PlannedChange("defender_for_endpoint", "t", "b", "B", "PROD", "update"),
        PlannedChange("defender_for_endpoint", "t", "c", "C", "OFF", "disable"),
        PlannedChange("defender_for_endpoint", "t", "d", "D", "GONE", "delete"),
    ]
    log, stream = _log(changes)
    for change in changes:
        log.rule_finished(
            RuleResult(platform=change.platform, tenant="t", id=change.uuid, name=change.name)
        )
    out = stream.getvalue()
    for verb in ("created ", "updated ", "disabled", "deleted "):
        assert f"✓ {verb}" in out


def test_json_and_quiet_print_nothing_but_a_failure_survives_quiet() -> None:
    for mode in (OutputMode.JSON, OutputMode.MCP):
        log, stream = _log([_change(1)], mode=mode)
        log.rule_finished(_result(1, "failed", error="boom"))
        assert stream.getvalue() == ""
        assert log.results[0].status == "failed"
    log, stream = _log([_change(1), _change(2)], quiet=True)
    log.rule_finished(_result(1))
    log.rule_finished(_result(2, "failed", error="HTTP 400: nope"))
    assert "Rule 1" not in stream.getvalue()
    assert "HTTP 400: nope" in stream.getvalue()


def test_a_long_error_wraps_under_itself_on_a_terminal_and_stays_whole_in_a_log() -> None:
    error = "HTTP 400: " + "word " * 60
    on_terminal = result_line(
        _result(1, "failed", error=error.strip()), index=1, total=1, name_width=6, width=80
    ).plain
    assert on_terminal.count("\n") == 3
    assert on_terminal.endswith("…")
    assert all(len(line) <= 80 for line in on_terminal.splitlines())
    in_log = result_line(_result(1, "failed", error=error.strip()), index=1, total=1).plain
    assert "\n" not in in_log
    assert in_log.endswith("word")


def test_ascii_fallback_for_a_stream_that_cannot_encode_the_glyphs() -> None:
    ok = result_line(_result(1), index=1, total=1, encoding="ascii").plain
    failed = result_line(_result(1, "failed", error="x"), index=1, total=1, encoding="ascii").plain
    assert "ok " in ok and "✓" not in ok
    assert "x failed" in failed and "✗" not in failed
    assert "sentinel / t - 2 rules" in header_line("sentinel", "t", 2, encoding="ascii").plain


def test_run_counts_always_carry_every_count() -> None:
    results = [
        _result(1, action="create"),
        _result(2, action="update"),
        _result(3),
        _result(4, "failed", error="x"),
        _result(5, "not_attempted"),
        _result(6, "skipped"),
    ]
    counts = run_counts(results, 3.14159)
    assert counts == {
        "create": 1,
        "update": 1,
        "upsert": 1,
        "disable": 0,
        "delete": 0,
        "failed": 1,
        "skipped": 1,
        "not_attempted": 1,
        "seconds": 3.142,
    }
    assert run_summary(results, ["sentinel"], 1, 3.14159)["tenants"] == 1


def test_the_outcome_line_counts_failed_and_not_attempted_on_a_pass_and_on_a_failure() -> None:
    passed = [_result(index) for index in range(1, 4)]
    assert outcome_message(passed, 116.0, failed=False) == (
        "Deployed 3 rules to 1 tenant · 3 created or updated · 0 failed, 0 not attempted · 1m56s"
    )
    broken = [_result(1), _result(2, "failed", error="x"), _result(3, "not_attempted")]
    assert outcome_message(broken, 14.0, failed=True) == (
        "Deployment failed · 1 created or updated, 1 failed, 1 not attempted · 14.0s"
    )
    nothing = [_result(1, "failed", error="x")]
    assert outcome_message(nothing, 1.0, failed=True) == (
        "Deployment failed · 1 failed, 0 not attempted · 1.0s"
    )


@pytest.mark.parametrize("seconds", [0.0, 59.94])
def test_the_outcome_line_always_ends_with_the_elapsed_time(seconds: float) -> None:
    assert outcome_message([_result(1)], seconds, failed=False).endswith("s")


def test_rules_an_engine_never_reached_after_one_of_its_failures_are_not_attempted() -> None:
    """Elastic fails a tenant on an auth error and returns normally: the rest was not reached."""
    log, _ = _log([_change(1), _change(2), _change(3)])
    log.rule_finished(_result(1, "failed", error="HTTP 403: missing privileges"))
    log.settle("sentinel")
    assert [(r.id, r.status) for r in log.results] == [
        ("u1", "failed"),
        ("u2", "not_attempted"),
        ("u3", "not_attempted"),
    ]
