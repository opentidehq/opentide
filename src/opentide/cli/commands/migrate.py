"""``opentide migrate``: legacy client repository layouts."""

from __future__ import annotations

from typing import Any

import typer

from opentide.cli.context import get_context
from opentide.cli.output import emit_error, emit_success

migrate_app = typer.Typer(help="Migrate legacy repository layouts")


@migrate_app.command("objects")
def migrate_objects_cmd(
    ctx: typer.Context,
    apply: bool = typer.Option(
        False, "--apply", help="Perform the planned moves (default: dry-run)"
    ),
    copy: bool = typer.Option(False, "--copy", help="Copy files instead of moving them"),
) -> None:
    """Move Configurations/, Objects/, and .opentide/framework into the greenfield layout."""
    from opentide.cli.services.migrate_objects import run_migrate_objects

    cli = get_context(ctx)
    cli.apply_environment()
    emit_success(cli, run_migrate_objects(cli.repo, apply=apply, copy=copy))


@migrate_app.command("vocab-scope")
def migrate_vocab_scope_cmd(
    ctx: typer.Context,
    apply: bool = typer.Option(
        False, "--apply", help="Rewrite the objects (default: dry-run report)"
    ),
    field: list[str] = typer.Option(
        None,
        "--field",
        help="Limit to one scoped field (repeatable). Default: every scoped field.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Exit 0 even when values need a human decision",
    ),
) -> None:
    """Re-prefix stage-scoped vocabulary values (`Process` -> `Host::Process`).

    Applies only mechanical outcomes: a key defined under exactly one stage,
    and a stage whose casing drifted. A key defined under several stages is
    reported, never guessed. Exits 2 when anything is left for a human.
    """
    from opentide.cli.services.migrate_vocab_scope import (
        SCOPED_FIELDS,
        load_scoped_vocabularies,
        run_migrate_vocab_scope,
    )

    cli = get_context(ctx)
    cli.apply_environment()

    fields = dict(SCOPED_FIELDS)
    if field:
        unknown = sorted(set(field) - set(fields))
        if unknown:
            known = ", ".join(sorted(fields))
            emit_error(
                cli,
                f"Unknown scoped field(s) {', '.join(unknown)}. Known scoped fields: {known}.",
            )
        fields = {name: fields[name] for name in field}

    try:
        report = run_migrate_vocab_scope(
            cli.repo,
            load_scoped_vocabularies(fields),
            apply=apply,
            fields=fields,
        )
    except (OSError, ValueError) as exc:
        emit_error(cli, str(exc))

    blocked = {
        name: entry["blocked"] for name, entry in report["fields"].items() if entry["blocked"]
    }
    warnings = [f"{name}: {detail}" for name, items in blocked.items() for detail in items.values()]
    warnings += [f"{path}: {reason}" for path, reason in report["failed_files"].items()]

    verb = "Rewrote" if apply else "Would rewrite"
    changed = len(report["changed_files"])
    files = f"{changed} file" if changed == 1 else f"{changed} files"
    payload: dict[str, Any] = {
        **report,
        "message": f"{verb} {files} · {report['scanned']} scanned",
        "warnings": warnings,
        "_summary": {"files": changed, "scanned": report["scanned"]},
    }
    if report["failed_files"]:
        payload["status"] = "issues"
        payload["message"] = (
            f"{len(report['failed_files'])} file(s) could not be migrated safely and "
            "were left unchanged."
        )
        payload["_exit_code"] = 1
    elif blocked and not force:
        count = sum(len(items) for items in blocked.values())
        payload["status"] = "issues"
        payload["message"] = (
            f"{verb} {files}; {count} value(s) "
            "are defined under several stages and cannot be inferred. Choose a stage "
            "for each by hand, then re-run. Pass --force to treat this as success."
        )
        payload["_exit_code"] = 2
        payload["_failure_code"] = "needs_human_decision"
    emit_success(cli, payload)
