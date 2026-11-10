"""Record what the oracle's renderers print, for opentide-cli's renderer tests (UC-3.4, #826).

Run with the oracle's interpreter (the frozen Python CLI of ``tests/golden/ORACLE``,
installed by ``cargo xtask golden record`` under the Cargo target directory), never
with this repository's ``opentide``::

    <target>/golden/oracle-<version>-<sha>/bin/python -I scripts/golden/render_oracle.py \\
        --fault <fault workspace> --out crates/opentide-cli/tests/render

``--fault`` is a fresh ``cargo xtask corpus faults --out <dir>`` workspace in the
``.opentide/`` layout. ``--check`` writes nothing and fails when a recorded file
differs from what the oracle prints now.

It writes, for each suite, the renderer's inputs as JSON (``*.input.json``) and
the oracle's output as insta snapshots (``snapshots/render__*.snap``), which
``crates/opentide-cli/tests/render.rs`` renders with the Rust renderers and
compares byte for byte. Inputs are what the oracle's commands build in memory
(their ``Diagnostic`` lists, captured where ``validate`` and ``lint`` hand them
to the report writer), with the workspace's path written ``<WS>``; outputs are
normalised the same way. Generated, never edited.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import io
import json
import os
import re
import sys
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

WS = "<WS>"
SOURCE = "crates/opentide-cli/tests/render.rs"
HUMAN_WIDTH = 100

# -- inputs ------------------------------------------------------------------


def diagnostic_json(diagnostic: Any, root: Path) -> dict[str, Any]:
    """Every field of a ``Diagnostic``, the workspace's path written ``<WS>``."""
    fix = diagnostic.fix
    return {
        "code": diagnostic.code,
        "severity": diagnostic.severity,
        "message": masked(diagnostic.message, root),
        "path": diagnostic.path,
        "file_path": None
        if diagnostic.file_path is None
        else masked(str(diagnostic.file_path), root),
        "line": diagnostic.line,
        "column": diagnostic.column,
        "end_column": diagnostic.end_column,
        "end_line": diagnostic.end_line,
        "field_path": list(diagnostic.field_path),
        "help": None if diagnostic.help is None else masked(diagnostic.help, root),
        "fix": None
        if fix is None
        else {
            "safe": fix.safe,
            "edits": [
                {
                    "line": edit.line,
                    "column": edit.column,
                    "end_column": edit.end_column,
                    "end_line": edit.end_line,
                    "replacement": edit.replacement,
                }
                for edit in fix.edits
            ],
        },
        "label": None if diagnostic.label is None else masked(diagnostic.label, root),
        "notes": [[label, masked(text, root)] for label, text in diagnostic.notes],
        "object_uuid": diagnostic.object_uuid,
    }


def masked(text: str, root: Path) -> str:
    return text.replace(str(root), WS)


def masked_diagnostic(diagnostic: Any, root: Path) -> Any:
    """*diagnostic* with ``<WS>`` in its texts, its file still readable."""
    return dataclasses.replace(
        diagnostic,
        message=masked(diagnostic.message, root),
        help=None if diagnostic.help is None else masked(diagnostic.help, root),
        label=None if diagnostic.label is None else masked(diagnostic.label, root),
        notes=tuple((label, masked(text, root)) for label, text in diagnostic.notes),
    )


# -- consoles ----------------------------------------------------------------


def console(mode: str) -> Any:
    """A console as the CLI gets it: ``human`` a 100-column terminal, ``plain`` a pipe."""
    from rich.console import Console

    if mode == "human":
        return Console(
            file=io.StringIO(),
            force_terminal=True,
            color_system="256",
            width=HUMAN_WIDTH,
            highlight=False,
            legacy_windows=False,
        )
    return Console(
        file=io.StringIO(), force_terminal=False, width=HUMAN_WIDTH, highlight=False, no_color=True
    )


def text_of(target: Any) -> str:
    return target.file.getvalue()


_LINK_ID = re.compile(r"\x1b\]8;id=[^;]*;")


def normalised(text: str, root: Path) -> str:
    """The workspace as ``<WS>``, terminal hyperlink ids as ``<ID>`` (Rich draws them at random)."""
    text = text.replace(root.as_uri(), "file://" + WS).replace(str(root), WS)
    return _LINK_ID.sub("\x1b]8;id=<ID>;", text)


# -- capture -----------------------------------------------------------------


def captured(command: Sequence[str], root: Path) -> list[Any]:
    """The diagnostics the oracle's *command* builds in *root*, as it renders them."""
    from opentide.cli import findings

    seen: list[Any] = []
    real = findings.write_report_file

    def capture(report_format: Any, output: Any, diagnostics: Any, *, command: str) -> Any:
        seen.extend(diagnostics)
        return real(report_format, output, diagnostics, command=command)

    module = __import__(f"opentide.cli.commands.{command[0]}", fromlist=["write_report_file"])
    module.write_report_file = capture
    try:
        run_cli(command, root)
    finally:
        module.write_report_file = real
    return seen


def run_cli(argv: Sequence[str], root: Path) -> None:
    import opentide.cli as cli

    previous = os.getcwd()
    os.chdir(root)
    sys.argv = ["opentide", *argv]
    sink = io.StringIO()
    try:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            cli.main()
    except SystemExit:
        pass
    finally:
        os.chdir(previous)


# -- snapshots ---------------------------------------------------------------


def snapshot(name: str, body: str) -> tuple[str, str]:
    """An insta snapshot file: ``render__<name>.snap`` holding *body* exactly, then a newline."""
    header = f"---\nsource: {SOURCE}\nexpression: {name}\n---\n"
    return f"snapshots/render__{name}.snap", header + body + "\n"


def frames(diagnostics: Sequence[Any], root: Path, mode: str) -> str:
    from opentide.cli.ui.codeframe import render_diagnostics
    from opentide.cli.ui.diagnostics import SourceFiles
    from opentide.cli.ui.mode import OutputMode

    target = console(mode)
    render_diagnostics(
        target,
        diagnostics,
        sources=SourceFiles(),
        mode=OutputMode.HUMAN if mode == "human" else OutputMode.PLAIN,
        cwd=root,
    )
    return normalised(text_of(target), root)


def sources_of(diagnostics: Sequence[Any], root: Path) -> dict[str, str]:
    from opentide.cli.ui.diagnostics import SourceFiles

    files = SourceFiles()
    texts: dict[str, str] = {}
    for item in diagnostics:
        if item.file_path is not None and (text := files.text(item.file_path)) is not None:
            texts[masked(str(item.file_path), root)] = text
    return dict(sorted(texts.items()))


# -- suites ------------------------------------------------------------------


def fault_suite(root: Path, command: str) -> dict[str, str]:
    """``validate`` or ``lint`` of the fault workspace: frames, reports and CI sinks."""
    from opentide import __version__
    from opentide.cli.ui import ci, summary
    from opentide.cli.ui.reports import codequality_report, sarif_report
    from opentide.core.io import dump_json_text

    raw = captured([command], root)
    shown = [masked_diagnostic(item, root) for item in raw]
    out: dict[str, str] = {}
    data = {
        "command": command,
        "version": __version__,
        "diagnostics": [diagnostic_json(item, root) for item in raw],
        "sources": sources_of(raw, root),
    }
    out[f"{command}-fault.input.json"] = json.dumps(data, indent=1, ensure_ascii=False) + "\n"
    for mode in ("human", "plain"):
        out.update([snapshot(f"{command}_fault_frames_{mode}", frames(shown, root, mode))])

    def path_for(item: Any) -> str | None:
        return ci.repository_path(item, root)

    sarif = sarif_report(shown, command=command, version=__version__, path_for=path_for)
    out.update(
        [
            snapshot(
                f"{command}_fault_sarif", dump_json_text(sarif, indent=True, append_newline=False)
            )
        ]
    )
    quality = codequality_report(shown, path_for=path_for)
    out.update(
        [
            snapshot(
                f"{command}_fault_codequality",
                dump_json_text(quality, indent=True, append_newline=False),
            )
        ]
    )
    for provider in ("github", "gitlab", "azure"):
        lines = ci.annotation_lines(shown, provider, root=root)
        out.update([snapshot(f"{command}_fault_ci_{provider}", normalised("\n".join(lines), root))])
    paths = {id(item): ci.repository_path(item, root) for item in shown}
    markdown = summary.diagnostics_summary(
        f"opentide {command}", "101 errors in 89 files", shown, kind="failed", paths=paths
    )
    out.update([snapshot(f"{command}_fault_summary", summary.fit(markdown))])
    return out


def rules_suite() -> dict[str, str]:
    """The SARIF rule catalogue: every code's page, as the oracle reads it."""
    from opentide.cli.services.explain import load_page

    try:
        from opentide.cli.services.retired_codes import RETIRED_CODES
    except ImportError:  # an oracle from before retired codes (0.23.0)
        RETIRED_CODES = {}
    from opentide.cli.ui.reports import rule_codes

    pages = []
    for code in rule_codes():
        page = load_page(code)
        pages.append(
            {
                "code": code,
                "retired": code in RETIRED_CODES,
                "summary": None if page is None else page.summary,
                "markdown": None if page is None else page.markdown,
            }
        )
    return {"rules.input.json": json.dumps(pages, indent=1, ensure_ascii=False) + "\n"}


def synthetic(root: Path) -> list[Any]:
    """One diagnostic per code with a page, and the frame shapes the fault workspace lacks."""
    from opentide.cli.services.explain import load_page
    from opentide.cli.ui.diagnostics import Diagnostic, Fix, TextEdit
    from opentide.cli.ui.reports import rule_codes

    source = root / "objects" / "rules" / "frame-shapes.yaml"
    path = "objects/rules/frame-shapes.yaml"
    items: list[Any] = []
    for number, code in enumerate(rule_codes()):
        page = load_page(code)
        severity = "error"
        found = (
            None if page is None else re.search(r"^Severity: (\w+)", page.markdown, re.MULTILINE)
        )
        if found is not None:
            severity = found.group(1) if found.group(1) in ("error", "warning", "note") else "error"
        line = 2 + number % 6
        items.append(
            Diagnostic(
                code=code,
                severity=severity,
                message=(page.summary if page is not None else code) or code,
                path=path,
                file_path=source,
                line=line,
                column=3,
                end_column=9,
                label="this value",
                help=f"opentide explain {code}",
                object_uuid="00000000-0000-4000-8003-000000000001",
            )
        )
    wide = "objects/rules/wide-→-名前.yaml"
    items.extend(
        [
            # No file: the frame is the header alone.
            Diagnostic(
                code="unknown_key", severity="error", message="deployment.toml.x: unknown key"
            ),
            # A file but no line.
            Diagnostic(
                code="yaml_parse",
                severity="error",
                message="found an empty file",
                path=path,
                file_path=source,
            ),
            # A tab and a wide character before the span, a fix, two notes.
            Diagnostic(
                code="vocab_unknown",
                severity="error",
                message="'clearr' is not a tlp value",
                path=path,
                file_path=source,
                line=9,
                column=8,
                end_column=14,
                label="not in tlp::1.0",
                notes=(("expected", "one of clear, green, amber"), ("note", "a second note")),
                fix=Fix(safe=True, edits=(TextEdit(9, 8, 14, "clear"),)),
            ),
            # A multi-line span, framed on its first line; a long label.
            Diagnostic(
                code="kql_parse_error",
                severity="warning",
                message="a span that ends two lines further down " * 4,
                path=path,
                file_path=source,
                line=11,
                column=5,
                end_line=13,
                end_column=4,
                label="a label long enough to pass the right edge of the terminal at its column "
                * 2,
                help="a help line long enough to wrap at the edge of a terminal of a hundred "
                "columns, at a word: " + "/very/long/path/segment" * 6,
            ),
            # A note, a column with no end, past the end of the line.
            Diagnostic(
                code="filename_mismatch",
                severity="note",
                message="the file name does not match the object's name",
                path=wide,
                file_path=root / wide,
                line=2,
                column=40,
            ),
            # A line past the end of the file: no source.
            Diagnostic(
                code="schema_validation",
                severity="error",
                message="nothing at this line",
                path=path,
                file_path=source,
                line=400,
                column=1,
            ),
        ]
    )
    return items


SHAPES = """\
name: Frame shapes
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::2.0
  created: 2026-01-01
  modified: 2026-01-02
detection:

\ttlp: 名前 clearr
query: |
  SecurityEvent
  | where EventID == 4625
  | take 10
"""

WIDE = "name: wide\ndescription: 🔥 a line with an emoji and 名前\n"


def codes_suite(root: Path) -> dict[str, str]:
    (root / "objects" / "rules").mkdir(parents=True, exist_ok=True)
    (root / "objects" / "rules" / "frame-shapes.yaml").write_text(SHAPES, encoding="utf-8")
    (root / "objects" / "rules" / "wide-→-名前.yaml").write_text(WIDE, encoding="utf-8")
    items = synthetic(root)
    out = {
        "codes.input.json": json.dumps(
            {
                "diagnostics": [diagnostic_json(item, root) for item in items],
                "sources": sources_of(items, root),
            },
            indent=1,
            ensure_ascii=False,
        )
        + "\n"
    }
    for mode in ("human", "plain"):
        # Each code's frame on its own, headed by the code, so a difference names it.
        parts = [f"== {item.code}\n" + frames([item], root, mode) for item in items]
        out.update([snapshot(f"codes_frames_{mode}", "".join(parts))])
    return out


def outcome_suite() -> dict[str, str]:
    """Outcome, warning, error and next-step lines, at a pipe and at a narrow terminal."""
    from opentide.cli.ui.contract import NextAction
    from opentide.cli.ui.mode import OutputMode
    from opentide.cli.ui.progress import Step, plural, seconds_text, step_line
    from opentide.cli.ui.render import (
        render_agent_tip,
        render_error,
        render_next_actions,
        render_notes,
        render_outcome,
        render_warnings,
    )

    cases: list[dict[str, Any]] = []
    long = (
        "101 errors in 89 files · 771 objects checked · 1531 queries · 12.4s, "
        "and a tail long enough to wrap"
    )
    for kind in ("ok", "warning", "skipped", "failed", "plan"):
        for message in ("3 rules checked", "Plan: 1 to create, 2 to update", "Plan for: x", long):
            cases.append({"kind": "outcome", "outcome": kind, "message": message})
    cases.append({"kind": "warnings", "messages": ["Vocabulary not found · vocab: reviewed", long]})
    cases.append({"kind": "notes", "notes": [["note", "a detail"], ["help", long]]})
    cases.append({"kind": "error", "message": long, "notes": [["help", "did you mean 'x'?"]]})
    actions = [
        ["opentide explain unknown_key", "how to fix it"],
        ["opentide validate", "check again"],
        ["opentide lint --fix", ""],
        ["opentide fourth", "never shown"],
    ]
    cases.append({"kind": "next", "actions": actions})
    cases.append({"kind": "tip"})
    steps = [
        {
            "name": "schemas",
            "count": 7,
            "unit": "file",
            "where": ".opentide/schemas/",
            "status": "ok",
        },
        {"name": "catalog", "count": 1, "unit": "rule", "where": None, "status": "ok"},
        {"name": "docs", "count": None, "outcome": "2 deployed, 1 failed", "status": "failed"},
        {"name": "explorer", "status": "skipped", "detail": "no rules"},
        {"name": "inflight", "count": 3, "unit": "entry", "plural": "entries", "status": "running"},
    ]
    cases.append({"kind": "steps", "steps": steps})
    out_cases = []
    for case in cases:
        rendered: dict[str, str] = {}
        for mode in ("human", "plain", "narrow"):
            target = console("human" if mode == "human" else "plain")
            if mode == "narrow":
                from rich.console import Console

                target = Console(
                    file=io.StringIO(),
                    force_terminal=True,
                    color_system="256",
                    width=40,
                    highlight=False,
                    legacy_windows=False,
                )
            output_mode = OutputMode.PLAIN if mode == "plain" else OutputMode.HUMAN
            kind = case["kind"]
            if kind == "outcome":
                render_outcome(target, case["outcome"], case["message"])
            elif kind == "warnings":
                render_warnings(target, case["messages"])
            elif kind == "notes":
                render_notes(target, [tuple(note) for note in case["notes"]])
            elif kind == "error":
                render_error(
                    target,
                    case["message"],
                    notes=[tuple(note) for note in case["notes"]],
                    mode=OutputMode.AGENT,
                )
            elif kind == "next":
                render_next_actions(target, [NextAction(*action) for action in case["actions"]])
            elif kind == "tip":
                render_agent_tip(target, OutputMode.AGENT)
                render_agent_tip(target, output_mode)
            elif kind == "steps":
                for spec in case["steps"]:
                    step = Step(name=spec["name"], unit=spec.get("unit", "file"), seconds=1.25)
                    step.done(
                        spec.get("count"), where=spec.get("where"), outcome=spec.get("outcome")
                    )
                    if spec.get("plural"):
                        step.outcome = plural(spec["count"], spec["unit"], spec["plural"])
                    if spec["status"] == "skipped":
                        step.skip(spec["detail"])
                    else:
                        step.status = spec["status"]
                    target.print(step_line(step), soft_wrap=True)
            rendered[mode] = normalised(text_of(target), Path("/nonexistent"))
        out_cases.append({**case, "rendered": rendered})
    words = {
        "plural": [
            [count, noun, plural(count, noun)] for count in (0, 1, 2) for noun in ("file", "rule")
        ],
        "seconds": [
            [value, seconds_text(value)]
            for value in (0.0, 0.04, 0.05, 1.25, 59.94, 59.96, 60.0, 125.4, 3600.5)
        ],
    }
    body = json.dumps({"cases": out_cases, "words": words}, indent=1, ensure_ascii=False)
    return {"outcome.input.json": body + "\n"}


def ci_suite() -> dict[str, str]:
    """Escaping, the GitHub cap and its notice, warnings about a run, the summary cap."""
    from opentide.cli.ui import ci, summary
    from opentide.cli.ui.diagnostics import Diagnostic

    def make(index: int, severity: str) -> Any:
        return Diagnostic(
            code="vocab_unknown",
            severity=severity,
            message=f"value {index}: 50% off, a,b: c;d] [e]\r\nsecond line",
            path=f"objects/rules/r{index}, a: b.yaml",
            line=index + 1,
            column=3 if index % 3 else None,
            end_column=(3 + index % 4) if index % 3 else None,
            end_line=(index + 3) if index % 5 == 0 else None,
            help="did you mean 'x'?" if index % 2 else None,
        )

    sets = {
        "few": [make(i, "error") for i in range(3)] + [make(3, "note"), make(4, "warning")],
        "capped": [make(i, ("error", "warning", "note")[i % 3]) for i in range(45)],
        "notes-capped": [make(i, "note") for i in range(12)],
        "errors-capped": [make(i, "error") for i in range(11)] + [make(20, "note")],
        "no-file": [
            Diagnostic(code="unknown_key", severity="error", message="x: unknown key", line=4)
        ],
    }
    cases = []
    for name, items in sets.items():
        cases.append(
            {
                "name": name,
                "diagnostics": [diagnostic_json(item, Path("/nonexistent")) for item in items],
                "github": ci.annotation_lines(items, "github"),
                "azure": ci.annotation_lines(items, "azure"),
                "gitlab": ci.annotation_lines(items, "gitlab"),
                "summary": summary.diagnostics_summary(
                    "opentide validate", "3 errors · <b>x</b> | y", items, kind="failed"
                ),
            }
        )
    many = [make(i, "error") for i in range(130)]
    big = summary.diagnostics_summary("opentide lint", "big", many, kind="warning")
    long_lines = "\n".join(["<details><summary>x</summary>"] + ["- " + "é" * 30] * 120)
    # [text, limit, what fit makes of it]; the default limit is 256 KiB.
    fits = [
        [big, 4096, summary.fit(big, limit=4096)],
        [long_lines, 1000, summary.fit(long_lines, limit=1000)],
        [big, None, summary.fit(big)],
        ["short\n", None, summary.fit("short\n")],
    ]
    escapes = {
        "cell": [
            [v, summary.cell(v)] for v in ("a|b", "<x> & *y*", "line\nnext", "", "`c` [l](u)")
        ],
        "code": [[v, summary.code(v)] for v in ("a", "a|b", "`x`", "a`b", "``")],
        "heading": [
            [k, summary.heading(k, "opentide x")]
            for k in ("ok", "failed", "warning", "skipped", "plan")
        ],
        "warning": [
            ci.github_command("warning", "the run: 50%, done", (("title", "opentide"),)),
            ci.github_command("warning", "no title", (("title", None),)),
            ci.azure_command(
                "task.logissue", "the run; done]", (("type", "warning"), ("code", "x;y"))
            ),
            ci.azure_command("task.uploadsummary", "/tmp/a b.md"),
        ],
        "file_names": [[c, ci.summary_file_name(c)] for c in ("validate", "validate query", "")],
    }
    deploys = [
        (deploy_result(), True),
        ({**deploy_result(), "dry_run": False, "deployed": ["sentinel"], "tenants": {}}, None),
        ({"status": "failed", "ok": False, "message": "", "plan": {}}, None),
    ]
    queries = [
        {
            "platform": "sentinel",
            "status": "ok",
            "message": "2 queries valid",
            "strategies": ["PREVIEW"],
            "queries_per_tenant": {"prod": 2, "<dev>": 1},
        },
        {"status": "skipped", "message": "nothing to check", "warnings": []},
        {"status": "ok", "message": "x", "warnings": ["w"]},
    ]
    result = {
        "deploy": [
            {
                "result": item,
                "dry_run": flag,
                "markdown": summary.deploy_summary(item, dry_run=flag),
            }
            for item, flag in deploys
        ],
        "query": [{"result": item, "markdown": summary.query_summary(item)} for item in queries],
    }
    body = {"cases": cases, "fits": fits, "escapes": escapes, "results": result}
    return {"ci.input.json": json.dumps(body, indent=1, ensure_ascii=False) + "\n"}


def deploy_result() -> dict[str, Any]:
    return {
        "status": "ok",
        "dry_run": True,
        "message": "Plan: 3 to create",
        "strategies": ["PREVIEW"],
        "plan": {"sentinel": ["u1", "u2"], "splunk": ["u3"]},
        "tenants": {"sentinel": {"prod | eu": ["u1", "u2"]}},
        "payloads": {
            "sentinel": [
                {"uuid": "u1", "name": "Rule *one*", "status": "ok"},
                {
                    "uuid": "u2",
                    "name": "Rule two",
                    "status": "failed",
                    "error": "line one\nline two\nline three",
                },
            ]
        },
    }


def progress_suite() -> dict[str, str]:
    """The events a ``Ticker`` writes for a step of *total* units advanced one at a time."""
    from opentide.core import progress_events

    cases = []
    for total, steps in (
        (0, [1]),
        (1, [1]),
        (7, [1] * 7),
        (45, [1] * 45),
        (100, [3] * 34),
        (41, [40, 1]),
    ):
        events: list[dict[str, Any]] = []
        with progress_events.sink(events.append):
            ticker = progress_events.Ticker("schemas", total)
            for count in steps:
                ticker.advance(count)
        cases.append({"step": "schemas", "total": total, "advances": steps, "events": events})
    lines = []
    sink = io.StringIO()
    previous = sys.stderr
    os.environ[progress_events.PROGRESS_ENV] = "json"
    sys.stderr = sink
    try:
        progress_events.progress("objects", 3, None)
        progress_events.tenant("sentinel", "prod 🔥", ok=False, rows=0, elapsed_ms=12)
        progress_events.tenant("elastic", "dev", ok=True, rows=4, elapsed_ms=5, label="query 2")
    finally:
        sys.stderr = previous
        del os.environ[progress_events.PROGRESS_ENV]
    lines = sink.getvalue()
    body = {"tickers": cases, "stderr": lines}
    return {"progress.input.json": json.dumps(body, indent=1, ensure_ascii=False) + "\n"}


# -- main --------------------------------------------------------------------


def suites(fault: Path, scratch: Path) -> Iterator[Callable[[], dict[str, str]]]:
    yield lambda: fault_suite(fault, "validate")
    yield lambda: fault_suite(fault, "lint")
    yield rules_suite
    yield lambda: codes_suite(scratch)
    yield outcome_suite
    yield ci_suite
    yield progress_suite


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="render_oracle.py", description=__doc__)
    parser.add_argument("--fault", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    os.environ.update({"TZ": "UTC", "OPENTIDE_LINKS": "file", "COLUMNS": str(HUMAN_WIDTH)})
    for name in ("GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "CI", "OPENTIDE_PROGRESS", "NO_COLOR"):
        os.environ.pop(name, None)
    fault, scratch = args.fault.resolve(), args.scratch.resolve()
    files: dict[str, str] = {}
    for suite in suites(fault, scratch):
        files.update(suite())
    stale = []
    for name, content in sorted(files.items()):
        target = args.out / name
        if args.check:
            current = target.read_text(encoding="utf-8") if target.exists() else None
            if current != content:
                stale.append(name)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        sys.stderr.write(
            "render_oracle.py: these differ from the oracle: " + ", ".join(stale) + "\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
