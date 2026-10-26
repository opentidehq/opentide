"""Detection-rule maintenance: RFC 0008 review staleness."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from opentide.core.io import load_yaml
from opentide.models.review import parse_window, reviewed_text, unreviewed_reason

_YAML_SUFFIXES = {".yaml", ".yml"}


def list_unreviewed_rules(
    repo: Path,
    *,
    window: timedelta,
    now: datetime | None = None,
    unreadable: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """List rules that fail the RFC 0008 review predicate. Does not modify files.

    A file that cannot be read or parsed is skipped and recorded in
    *unreadable* (path to reason): one malformed rule used to end the command
    with a traceback and no output.
    """
    evaluated_at = now or datetime.now(timezone.utc)
    if evaluated_at.tzinfo is None:
        evaluated_at = evaluated_at.replace(tzinfo=timezone.utc)
    root = repo / "objects" / "rules"
    if not root.is_dir():
        return []
    findings: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _YAML_SUFFIXES:
            continue
        try:
            document = load_yaml(path)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            if unreadable is not None:
                unreadable[path.relative_to(repo).as_posix()] = " ".join(str(exc).split())
            continue
        if not isinstance(document, dict):
            continue
        metadata = document.get("metadata")
        if not isinstance(metadata, dict):
            continue
        schema_id = metadata.get("schema")
        if not isinstance(schema_id, str) or not schema_id.startswith("rule::"):
            continue
        reviewed = reviewed_text(metadata.get("reviewed"))
        reason = unreviewed_reason(schema_id, reviewed, now=evaluated_at, window=window)
        if reason is None:
            continue
        findings.append(
            {
                "path": path.relative_to(repo).as_posix(),
                "schema": schema_id,
                "reason": reason,
                "reviewed": reviewed,
            }
        )
    return findings


_UNITS = {"d": "day", "h": "hour", "m": "minute"}


def window_text(older_than: str) -> str:
    """``90d`` → ``90 days``, ``12h`` → ``12 hours``, ``1`` → ``1 day``."""
    text = older_than.strip()
    unit = text[-1:] if text[-1:] in _UNITS else "d"
    number = text[:-1] if text[-1:] in _UNITS else text
    word = _UNITS[unit]
    return f"{number} {word}" if number == "1" else f"{number} {word}s"


def _has_rule_files(repo: Path) -> bool:
    root = repo / "objects" / "rules"
    return root.is_dir() and any(
        path.is_file() and path.suffix.lower() in _YAML_SUFFIXES for path in root.rglob("*")
    )


def _first_rule_step() -> dict[str, str]:
    """The command that writes a first rule: ``new rule`` where this build has it."""
    from opentide.cli.commands import ROOT_COMMANDS

    if any(spec.name == "new" for spec in ROOT_COMMANDS):
        return {"command": "opentide new rule", "reason": "scaffold your first rule"}
    return {
        "command": "opentide generate templates",
        "reason": "rule templates to copy into objects/rules/",
    }


def run_unreviewed(repo: Path, *, older_than: str, now: datetime | None = None) -> dict[str, Any]:
    """Build the ``rules unreviewed`` payload. Raises ``ValueError`` on a bad window."""
    window = parse_window(older_than)
    evaluated_at = now or datetime.now(timezone.utc)
    unreadable: dict[str, str] = {}
    rules = list_unreviewed_rules(repo, window=window, now=evaluated_at, unreadable=unreadable)
    count = len(rules)
    span = window_text(older_than)
    extra: dict[str, Any] = {}
    if count:
        noun = "rule" if count == 1 else "rules"
        message = f"{count} {noun} unreviewed for {span}"
        extra["_outcome_kind"] = "warning"
    elif not _has_rule_files(repo):
        # Nothing was checked, so nothing can be called reviewed.
        message = "No rules yet"
        extra["status"] = "skipped"
        extra["_next_actions"] = [_first_rule_step()]
    else:
        message = f"Every rule reviewed in the last {span}"
    payload: dict[str, Any] = {
        "message": message,
        "_summary": {"unreviewed": count},
        **extra,
        "evaluated_at": evaluated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "window": older_than.strip(),
        "count": count,
        "rules": rules,
    }
    if unreadable:
        payload["unreadable"] = unreadable
        payload["warnings"] = [
            f"Could not read {path}, so its review was not checked: {reason}"
            for path, reason in unreadable.items()
        ]
    return payload


def render_unreviewed(rules: list[dict[str, Any]]) -> None:
    """Print one line per unreviewed rule for the human renderer."""
    from opentide.core.logging.config import get_stdout_console

    console = get_stdout_console()
    for rule in rules:
        reviewed = rule.get("reviewed") or "-"
        console.print(f"{rule['path']}  {rule['reason']}  {rule['schema']}  {reviewed}")
