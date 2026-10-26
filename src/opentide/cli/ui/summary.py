"""Markdown for CI job summaries: findings, a deploy plan, query validation results.

:func:`opentide.cli.ui.ci.append_summary` writes what these build. Each
summary is a ``###`` heading with the outcome glyph and the command, the
outcome line, then a table. Tables stop at :data:`MAX_ROWS`; the job log
and the report files keep the rest.

Standard library only.
"""

from __future__ import annotations

import html
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from opentide.cli.ui.diagnostics import Diagnostic

#: The generated reference of diagnostic codes; ``#<code>`` is each one's section.
DIAGNOSTICS_DOCS_URL = "https://opentide.org/docs/cli/diagnostics"

#: Rows per table. GitHub caps a step summary at 1 MiB.
MAX_ROWS = 100

#: Bytes one summary may take. GitHub refuses a step summary over 1 MiB, and
#: one step can run several commands, so each stays well under it.
MAX_SUMMARY_BYTES = 256 * 1024

#: Lines and characters of a deploy error shown after ``would fail:``.
MAX_ERROR_LINES = 2
MAX_ERROR_CHARS = 300

#: Inline Markdown that user text must not start: emphasis, code, links,
#: images, strikethrough, autolinks and table cells.
_MARKDOWN_PUNCTUATION = re.compile(r"([\\`*_\[\]()!~|#])")

_GLYPHS = {"ok": "✓", "failed": "✗", "warning": "!", "skipped": "–"}


def explain_url(code: str) -> str:
    """Where the published ``opentide explain <code>`` page lives."""
    return f"{DIAGNOSTICS_DOCS_URL}#{code}"


def cell(value: object) -> str:
    """User text as literal Markdown, safe inside a table cell.

    ``&``, ``<`` and ``>`` become entities, so a value such as ``<clear>``
    shows instead of being dropped as an unknown tag. Inline Markdown
    punctuation is backslash-escaped, so ``*em*`` or ``[l](url)`` stays text,
    and ``|`` cannot end the cell. Line breaks become ``<br>``.
    """
    text = html.escape(str(value), quote=False)
    text = _MARKDOWN_PUNCTUATION.sub(r"\\\1", text)
    return "<br>".join(part.strip() for part in text.splitlines()) or " "


def code(value: object) -> str:
    """``value`` as inline code, fenced with more backticks than it contains.

    A code span shows HTML and Markdown literally, and entities would show as
    ``&lt;``, so only ``|`` is escaped (a table splits cells before it reads
    code spans).
    """
    text = str(value).replace("|", "\\|")
    fence = "`"
    while fence in text:
        fence += "`"
    padded = f" {text} " if text.startswith("`") or text.endswith("`") else text
    return f"{fence}{padded}{fence}"


def heading(kind: str, title: str) -> str:
    """``### ✓ opentide validate``."""
    glyph = _GLYPHS.get(kind)
    return f"### {glyph} {title}" if glyph else f"### {title}"


def table(header: Sequence[str], rows: Iterable[Sequence[object]], *, total: int) -> list[str]:
    """A Markdown table, then ``… and N more`` when *total* is more than the rows given."""
    lines = [
        "| " + " | ".join(header) + " |",
        "|" + "|".join("---" for _ in header) + "|",
    ]
    shown = 0
    for row in rows:
        lines.append("| " + " | ".join(str(item) for item in row) + " |")
        shown += 1
    if total > shown:
        lines.extend(["", f"… and {total - shown} more in the job log."])
    return lines


def _sorted(diagnostics: Iterable[Diagnostic]) -> list[Diagnostic]:
    return sorted(
        diagnostics,
        key=lambda item: (item.path is None, item.path or "", item.line or 0, item.column or 0),
    )


def _location(diagnostic: Diagnostic, path: str | None) -> str:
    if path is None:
        return " "
    where = path
    if diagnostic.line is not None:
        where += f":{diagnostic.line}"
        if diagnostic.column is not None:
            where += f":{diagnostic.column}"
    return code(where)


def diagnostics_summary(
    title: str,
    outcome: str,
    diagnostics: Sequence[Diagnostic],
    *,
    kind: str,
    paths: Mapping[int, str | None] | None = None,
) -> str:
    """Findings as a table: severity, code (linked to its page), location, message.

    *paths* maps ``id(diagnostic)`` to the path to show, when it is not the
    diagnostic's own ``path`` (relative to the checkout rather than the workspace).
    """
    lines = [heading(kind, title), "", cell(outcome)]
    if diagnostics:
        ordered = _sorted(diagnostics)
        rows = []
        for item in ordered[:MAX_ROWS]:
            path = paths.get(id(item), item.path) if paths is not None else item.path
            message = item.message + (f" — help: {item.help}" if item.help else "")
            rows.append(
                (
                    item.severity,
                    f"[{code(item.code)}]({explain_url(item.code)})",
                    _location(item, path),
                    cell(message),
                )
            )
        lines.append("")
        lines.extend(
            table(("Severity", "Code", "Location", "Message"), rows, total=len(diagnostics))
        )
    return "\n".join(lines) + "\n"


def _status_kind(result: Mapping[str, Any]) -> str:
    status = str(result.get("status", ""))
    if status == "failed" or result.get("ok") is False:
        return "failed"
    if status == "skipped":
        return "skipped"
    if result.get("warnings"):
        return "warning"
    return "ok"


def _rule_names(result: Mapping[str, Any], platform: str) -> dict[str, Mapping[str, Any]]:
    payloads = result.get("payloads")
    entries = payloads.get(platform, []) if isinstance(payloads, Mapping) else []
    return {str(entry.get("uuid")): entry for entry in entries if isinstance(entry, Mapping)}


def shorten(text: object, *, lines: int = MAX_ERROR_LINES, chars: int = MAX_ERROR_CHARS) -> str:
    """The first *lines* lines of *text*, at most *chars* characters, with ``…`` when cut."""
    full = str(text).strip()
    kept = "\n".join(full.splitlines()[:lines])
    if len(kept) > chars:
        kept = kept[: chars - 1].rstrip()
    return kept if kept == full else kept + " …"


def fit(markdown: str, *, limit: int = MAX_SUMMARY_BYTES) -> str:
    """*markdown* cut at a line to at most *limit* bytes, saying so.

    An open ``<details>`` block is closed, so the rest of the job summary
    still renders.
    """
    if len(markdown.encode("utf-8")) <= limit:
        return markdown
    note = "\n… summary truncated; the job log has everything.\n"
    budget = limit - len(note.encode("utf-8")) - len("\n</details>\n")
    kept: list[str] = []
    used = 0
    for line in markdown.splitlines():
        size = len(line.encode("utf-8")) + 1
        if used + size > budget:
            break
        kept.append(line)
        used += size
    text = "\n".join(kept)
    if text.count("<details>") > text.count("</details>"):
        text += "\n</details>"
    return text + "\n" + note


def _rule_line(uuid: str, entry: Mapping[str, Any] | None) -> str:
    if entry is None or not entry.get("name"):
        return f"- {code(uuid)}"
    line = f"- {cell(entry['name'])} ({code(uuid)})"
    if entry.get("status") == "failed" and entry.get("error"):
        line += f" — would fail: {cell(shorten(entry['error']))}"
    return line


def deploy_summary(
    result: Mapping[str, Any], *, message: str | None = None, dry_run: bool | None = None
) -> str:
    """The deploy plan: rules per platform and tenant, then the rules themselves.

    *dry_run* is the command's flag; a payload from a deploy that failed early
    may not carry it.
    """
    dry_run = bool(result.get("dry_run")) if dry_run is None else dry_run
    title = "opentide deploy --dry-run" if dry_run else "opentide deploy"
    lines = [heading(_status_kind(result), title), "", cell(message or result.get("message", ""))]
    strategies = result.get("strategies")
    if strategies:
        lines.extend(["", "Strategies: " + ", ".join(code(item) for item in strategies)])
    plan = result.get("plan")
    plan = plan if isinstance(plan, Mapping) else {}
    if not plan:
        return "\n".join(lines) + "\n"
    tenants = result.get("tenants")
    tenants = tenants if isinstance(tenants, Mapping) else {}
    deployed = set(result.get("deployed") or ())
    rows: list[tuple[str, ...]] = []
    for platform, uuids in plan.items():
        reach = tenants.get(platform)
        if isinstance(reach, Mapping) and reach:
            rows.extend(
                (code(platform), cell(tenant), str(len(rules))) for tenant, rules in reach.items()
            )
        elif dry_run:
            rows.append((code(platform), "none", str(len(uuids))))
        else:
            done = "deployed" if platform in deployed else "not deployed"
            rows.append((code(platform), done, str(len(uuids))))
    lines.append("")
    header = ("Platform", "Tenant", "Rules") if dry_run else ("Platform", "Result", "Rules")
    lines.extend(table(header, rows[:MAX_ROWS], total=len(rows)))
    for platform, uuids in plan.items():
        names = _rule_names(result, platform)
        count = len(uuids)
        noun = "rule" if count == 1 else "rules"
        # An HTML block: Markdown escapes would show, so HTML escaping only.
        label = html.escape(str(platform))
        lines.extend(["", f"<details><summary>{label}: {count} {noun}</summary>", ""])
        lines.extend(_rule_line(str(uuid), names.get(str(uuid))) for uuid in uuids[:MAX_ROWS])
        if count > MAX_ROWS:
            lines.append(f"- … and {count - MAX_ROWS} more")
        lines.extend(["", "</details>"])
    return "\n".join(lines) + "\n"


def query_summary(result: Mapping[str, Any], *, message: str | None = None) -> str:
    """Live query validation: queries sent per tenant, and the verdict."""
    platform = str(result.get("platform", ""))
    title = f"opentide validate query --platform {platform}".rstrip()
    lines = [heading(_status_kind(result), title), "", cell(message or result.get("message", ""))]
    strategies = result.get("strategies")
    if strategies:
        lines.extend(["", "Strategies: " + ", ".join(code(item) for item in strategies)])
    reach = result.get("queries_per_tenant")
    if isinstance(reach, Mapping) and reach:
        rows = [(cell(tenant), str(count)) for tenant, count in reach.items()]
        lines.append("")
        lines.extend(table(("Tenant", "Queries"), rows[:MAX_ROWS], total=len(rows)))
    return "\n".join(lines) + "\n"
