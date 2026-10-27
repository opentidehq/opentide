"""``opentide query``: run a read-only query on a platform's tenants and show the rows."""

from __future__ import annotations

import csv
import json
import sys
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import Any

import typer

from opentide.cli.context import CliContext, get_context
from opentide.cli.enums import PLATFORM_METAVAR, DetectionPlatform, platform_help
from opentide.cli.output import CommandResult, emit_result, emit_usage_error
from opentide.query.models import DEFAULT_LIMIT, DEFAULT_TIMEOUT, MAX_LIMIT

#: Columns the table shows when ``--columns`` names none; the rest are counted.
TABLE_COLUMNS = 8
#: Characters a table cell shows before it is cut with an ellipsis.
CELL_WIDTH = 60


class RowFormat(str, Enum):
    """How rows are written when ``--json`` is off."""

    table = "table"
    jsonl = "jsonl"
    csv = "csv"


TENANT_HELP = "Run on this tenant (repeatable), or 'all'. Default: the only tenant configured"
SINCE_HELP = "Look back this far from --to or now: 15m, 24h, 7d, PT1H. Default: 24h"
INDEX_HELP = "Elastic index pattern or CrowdStrike repository (repeatable)"
LANGUAGE_HELP = "Elastic only: esql (default), eql, lucene or kuery"


def query_cmd(
    ctx: typer.Context,
    query: str | None = typer.Argument(
        None, help="The query, in the platform's language. '-' reads it from stdin"
    ),
    platform: DetectionPlatform = typer.Option(
        ..., "--platform", metavar=PLATFORM_METAVAR, help=platform_help()
    ),
    tenant: list[str] | None = typer.Option(None, "--tenant", help=TENANT_HELP),
    rule: str | None = typer.Option(
        None, "--rule", help="Run the query this rule (by UUID) deploys to the platform"
    ),
    file: str | None = typer.Option(None, "--file", help="Run the query of the rule in this file"),
    query_file: str | None = typer.Option(
        None, "--query-file", help="Read the query from this file"
    ),
    since: str | None = typer.Option(None, "--since", help=SINCE_HELP),
    start: str | None = typer.Option(
        None, "--from", help="Start of the window, ISO-8601 (UTC unless it names an offset)"
    ),
    end: str | None = typer.Option(None, "--to", help="End of the window, ISO-8601. Default: now"),
    limit: int = typer.Option(
        DEFAULT_LIMIT, "--limit", help=f"Rows per tenant, at most {MAX_LIMIT}"
    ),
    language: str | None = typer.Option(None, "--language", help=LANGUAGE_HELP),
    index: list[str] | None = typer.Option(None, "--index", help=INDEX_HELP),
    timeout: float = typer.Option(
        DEFAULT_TIMEOUT, "--timeout", help="Seconds to wait for a search to finish"
    ),
    columns: str | None = typer.Option(
        None, "--columns", help="Comma-separated columns the table shows"
    ),
    row_format: RowFormat = typer.Option(
        RowFormat.table, "--format", help="table, jsonl or csv (--json prints the envelope)"
    ),
) -> None:
    """Run a read-only query on platform tenants and show rows

    Sends the query, or a rule's query, to each selected tenant over the
    window and prints at most --limit rows per tenant. Nothing is saved on
    the tenant.
    """
    from opentide.cli.services.query import query_platform

    cli = get_context(ctx)
    text = _query_text(cli, query, query_file)
    payload = query_platform(
        cli,
        platform.value,
        query=text,
        rule_uuid=rule,
        rule_file=file,
        tenants=tenant or (),
        since=since,
        start=start,
        end=end,
        limit=limit,
        language=language,
        index=index or (),
        timeout=timeout,
    )
    result = CommandResult.from_payload(payload)
    if cli.json_output:
        emit_result(cli, result)
        return
    outcomes = list(payload.get("results") or [])
    if row_format is RowFormat.table:
        wanted = [name.strip() for name in columns.split(",") if name.strip()] if columns else []
        _print_tables(outcomes, wanted, quiet=cli.quiet)
        emit_result(cli, result)
        return
    if row_format is RowFormat.jsonl:
        _write_jsonl(outcomes)
    else:
        _write_csv(outcomes)
    if not result.ok or result.exit_code:
        emit_result(cli, result)  # The error goes to stderr; stdout keeps only rows.


def _query_text(cli: CliContext, query: str | None, query_file: str | None) -> str | None:
    if query is not None and query_file is not None:
        emit_usage_error(
            cli, "QUERY and --query-file cannot be combined: give one query", argument="QUERY"
        )
    if query_file is not None:
        path = Path(query_file)
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            emit_usage_error(
                cli,
                f"cannot read --query-file {query_file}: {exc.strerror or exc}",
                argument="--query-file",
            )
    if query == "-":
        return sys.stdin.read()
    return query


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        text = str(value)
    text = " ".join(text.split())
    return text if len(text) <= CELL_WIDTH else text[: CELL_WIDTH - 1] + "…"


def _print_tables(
    outcomes: Sequence[Mapping[str, Any]], wanted: Sequence[str], *, quiet: bool
) -> None:
    from rich.table import Table
    from rich.text import Text

    from opentide.core.logging.config import get_console, get_stdout_console

    stdout = get_stdout_console()
    stderr = get_console()
    for outcome in outcomes:
        title = str(outcome.get("tenant"))
        if outcome.get("label"):
            title += f" · {outcome['label']}"
        if outcome.get("status") != "ok":
            if len(outcomes) > 1:
                stderr.print(
                    Text.assemble((title, "bold"), (f"  failed: {outcome.get('error')}", "red"))
                )
            continue
        rows = list(outcome.get("rows") or [])
        names = [str(column.get("name")) for column in outcome.get("columns") or []]
        shown = [name for name in wanted if name in names] if wanted else names[:TABLE_COLUMNS]
        count = f"{len(rows)} row{'s' if len(rows) != 1 else ''}"
        if outcome.get("truncated"):
            count += " (more matched; raise --limit)"
        stdout.print(Text.assemble((title, "bold"), ("  ", ""), (count, "dim")))
        if rows and shown:
            table = Table(show_edge=False, header_style="bold", pad_edge=False)
            for name in shown:
                table.add_column(name, overflow="ellipsis", no_wrap=True, max_width=CELL_WIDTH)
            for row in rows:
                table.add_row(*(_cell(row.get(name)) for name in shown))
            stdout.print(table)
        hidden = len(names) - len(shown)
        if hidden > 0 and not wanted:
            stdout.print(
                Text(
                    f"{hidden} more columns: name them with --columns, or use --format jsonl",
                    style="dim",
                )
            )
        if not quiet:
            for warning in outcome.get("warnings") or []:
                stderr.print(Text.assemble(("warning", "yellow bold"), (f": {warning}", "")))
        stdout.print()


def _labelled(outcome: Mapping[str, Any], row: Mapping[str, Any]) -> dict[str, Any]:
    labelled: dict[str, Any] = {"_tenant": outcome.get("tenant")}
    if outcome.get("label"):
        labelled["_label"] = outcome["label"]
    labelled.update(row)
    return labelled


def _write_jsonl(outcomes: Sequence[Mapping[str, Any]]) -> None:
    out = sys.stdout
    for outcome in outcomes:
        for row in outcome.get("rows") or []:
            out.write(json.dumps(_labelled(outcome, row), ensure_ascii=False) + "\n")
    out.flush()


def _write_csv(outcomes: Sequence[Mapping[str, Any]]) -> None:
    labelled = any(outcome.get("label") for outcome in outcomes)
    header: dict[str, None] = {"_tenant": None}
    if labelled:
        header["_label"] = None
    for outcome in outcomes:
        for column in outcome.get("columns") or []:
            header.setdefault(str(column.get("name")), None)
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(list(header))
    for outcome in outcomes:
        for row in outcome.get("rows") or []:
            values = _labelled(outcome, row)
            writer.writerow([_csv_value(values.get(name)) for name in header])
    sys.stdout.flush()


def _csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)
