"""The Python runner of the cross-SDK conformance suite (UC-5.4, #839).

It runs every operation of ``tests/conformance/manifest.json`` on every corpus
of a plan through ``opentide.Workspace`` and ``opentide.run_json``, and writes
each result as a normalised JSON document, ``<out>/<corpus>/<operation>.json``.
``cargo xtask conformance`` runs it next to the Rust runner
(``crates/opentide/tests/conformance.rs``) and the Node runner
(``bindings/node/test/conformance.test.mjs``) and requires the three trees to
be byte-identical; ``tests/conformance/README.md`` says how a document is
built, the same way in each runner.

Driven by xtask, ``OPENTIDE_CONFORMANCE_PLAN`` names the plan (the corpora xtask
laid out, the operations, the tenants and the URLs of the stand-in tenants xtask
started, which every runner talks to) and ``OPENTIDE_CONFORMANCE_OUT`` the folder
to write; ``OPENTIDE_CONFORMANCE_DIVERGE`` (test-only) makes this runner diverge
on purpose, which the comparator must catch. Without them, as part of the suite,
the runner starts the stand-ins itself and runs every operation on the tide
corpus under a temporary folder.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import shutil
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import opentide
from opentide import Connection, OpentideError, TenantConfig, Workspace
from opentide.sdk import DEFAULT_LIMIT, DEFAULT_TIMEOUT, QueryResult, capabilities, platforms

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MANIFEST = HERE / "manifest.json"
PLAN_ENV = "OPENTIDE_CONFORMANCE_PLAN"
OUT_ENV = "OPENTIDE_CONFORMANCE_OUT"
DIVERGE_ENV = "OPENTIDE_CONFORMANCE_DIVERGE"

#: The tide corpus's legacy folders and today's.
TIDE_CORPUS_LAYOUT = (
    ("Configurations", ".opentide/configurations"),
    ("Objects/Threat Vectors", "objects/threats"),
    ("Objects/Detection Objectives", "objects/objectives"),
    ("Objects/Detection Rules", "objects/rules"),
)


#: The members that hold a run's own clock, by their path from the document's
#: root: its wall time and the time it ran, the values two runs of one
#: operation differ in. Every runner writes them as null, and changes nothing else.
VOLATILE = (("duration_ms",), ("evaluated_at",), ("report", "stats", "wall_ms"))


def normalise(document: Any) -> Any:
    """*document* with each member of :data:`VOLATILE` it has set to null."""
    for path in VOLATILE:
        parent = document
        for key in path[:-1]:
            parent = parent.get(key) if isinstance(parent, dict) else None
        if isinstance(parent, dict) and path[-1] in parent:
            parent[path[-1]] = None
    return document


def canonical(document: Any) -> str:
    """*document* as every runner writes it: two-space indentation, keys in
    their order, UTF-8 as is, a final newline."""
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def lay_out_tide_corpus(dest: Path) -> Path:
    """``tests/fixtures/tide_corpus/current`` in today's layout under *dest*."""
    source = REPO / "tests" / "fixtures" / "tide_corpus" / "current"
    for legacy, today in TIDE_CORPUS_LAYOUT:
        shutil.copytree(source / legacy, dest / today)
    return dest


def standalone_plan(tmp: Path) -> dict[str, Any]:
    """Every operation of the manifest on the tide corpus, laid out under *tmp*;
    its ``urls`` are the stand-ins' once :func:`stand_ins` started them."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    root = lay_out_tide_corpus(tmp / "tide_corpus")
    return {
        "corpora": [{"name": "tide_corpus", "root": str(root)}],
        "operations": manifest["operations"],
        "tenants": manifest["tenants"],
        "stand_ins": manifest["stand_ins"],
        "urls": {},
    }


@contextmanager
def stand_ins(plan: dict[str, Any]) -> Iterator[None]:
    """Starts each stand-in tenant of *plan* (``tests/cassettes/<name>/tenant.py``)
    on loopback for a run of this runner alone, its URL in ``plan["urls"]``."""
    from tests.stand_in_support import stand_in

    with ExitStack() as stack:
        for spec in plan["stand_ins"]:
            plan["urls"][spec["name"]] = stack.enter_context(
                stand_in(spec["name"], spec["environment"])
            )
        yield


def _error(exc: OpentideError) -> dict[str, Any]:
    return {"error": {"code": exc.code, "message": exc.message}}


def _tenant_error(exc: OpentideError) -> dict[str, Any]:
    """A tenant operation's error: its code, its message and the vendor's words."""
    return {"error": {"code": exc.code, "message": exc.message, "detail": exc.detail}}


def _files(root: Path) -> dict[str, str]:
    """Every file under *root*, by its path from *root* with ``/``, as text
    (decoded as is: no newline translation)."""
    return {
        path.relative_to(root).as_posix(): path.read_bytes().decode("utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@contextmanager
def _cwd(path: str) -> Iterator[None]:
    before = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(before)


def _call(ws: Workspace, operation: Mapping[str, Any]) -> Any:
    options: dict[str, Any] = dict(operation.get("options") or {})
    call = operation["call"]
    if call == "validate":
        v = ws.validate(
            check=options.get("check"),
            files=options.get("files", ()),
            uuids=options.get("uuids", ()),
            types=options.get("types", ()),
            strict=options.get("strict", False),
            queries=options.get("queries", "error"),
        )
        return {
            "checks": v.checks,
            "report": v.report,
            "summary": v.summary,
            "failed": v.failed,
            "warned": v.warned,
            "exit_code": v.exit_code,
        }
    if call == "lint":
        r = ws.lint(
            checks=options.get("checks", ()),
            files=options.get("files", ()),
            strict=options.get("strict", False),
        )
        return {
            "path": r.path,
            "checks": r.checks,
            "findings": r.findings,
            "status": r.status,
            "message": r.message,
            "exit_code": r.exit_code,
            "failure_code": r.failure_code,
            "summary": r.summary,
            "outcome": r.outcome,
            "unmatched": r.unmatched,
            "warnings": r.warnings,
            "next_actions": r.next_actions,
        }
    if call == "info":
        return ws.info()
    if call == "catalog":
        return ws.catalog()
    if call == "rules":
        return ws.rules()
    if call == "objectives":
        return ws.objectives()
    if call == "threats":
        return ws.threats()
    if call == "coverage":
        return ws.coverage(operation["technique"])
    if call == "tenants":
        return [
            {"platform": tenant.platform, "name": tenant.name, "setup_keys": tenant.setup_keys}
            for tenant in ws.tenants(operation["platform"])
        ]
    if call == "deploy_plan":
        plan = ws.deploy_plan(
            strategies=options.get("strategies", ("RELEASE",)),
            uuids=options.get("uuids", ()),
            files=options.get("files", ()),
            platform=options.get("platform"),
            keep_deprecated=options.get("keep_deprecated"),
        )
        return {"document": plan.document, "summary": plan.summary, "ok": plan.ok}
    raise ValueError(f"unknown call {call!r}")


#: The calls on a tenant (``Connection``), not on a workspace.
TENANT_CALLS = ("query", "validate_query", "deploy")


def _setup(tenant: Mapping[str, Any], urls: Mapping[str, str]) -> dict[str, str]:
    """*tenant*'s setup, each ``{<stand-in>}`` the URL that stand-in listens on."""
    setup: dict[str, str] = {}
    for key, value in tenant["setup"].items():
        for name, url in urls.items():
            value = value.replace("{" + name + "}", url)
        setup[key] = value
    return setup


def _connect(tenant: Mapping[str, Any], urls: Mapping[str, str]) -> Connection | dict[str, Any]:
    try:
        config = TenantConfig(tenant["platform"], tenant["name"], _setup(tenant, urls))
        return Connection.open(config, environment=tenant["environment"])
    except OpentideError as exc:
        return _tenant_error(exc)


def _instant(text: str | None) -> datetime | None:
    """An RFC 3339 instant of the manifest (``...Z``, which Python 3.10 does not read)."""
    return None if text is None else datetime.fromisoformat(text.replace("Z", "+00:00"))


def _query(result: QueryResult) -> dict[str, Any]:
    return {
        "columns": result.columns,
        "rows": result.rows,
        "truncated": result.truncated,
        "partial": result.partial,
        "warnings": result.warnings,
        "vendor_query_id": result.vendor_query_id,
        "sent": result.sent,
        "language": result.language,
    }


async def _tenant_call(connection: Connection, operation: Mapping[str, Any]) -> Any:
    call = operation["call"]
    if call == "deploy":
        outcome = await connection.deploy(
            operation["rule_id"], operation["operation"], operation["body"].encode("utf-8")
        )
        return {"remote_id": outcome.remote_id, "operation": outcome.operation}
    options: dict[str, Any] = dict(operation.get("options") or {})
    method = connection.query if call == "query" else connection.validate_query
    result = await method(
        operation["text"],
        options.get("language", ""),
        start=_instant(options.get("start")),
        end=_instant(options.get("end")),
        limit=options.get("limit", DEFAULT_LIMIT),
        index=options.get("index", ()),
        data_view=options.get("data_view"),
        timeout=options.get("timeout", DEFAULT_TIMEOUT),
    )
    if isinstance(result, QueryResult):
        return _query(result)
    return {
        "result": None if result.result is None else _query(result.result),
        "errors": result.errors,
        "warnings": result.warnings,
    }


def _tenant(connection: Connection | dict[str, Any], operation: Mapping[str, Any]) -> Any:
    if isinstance(connection, dict):
        return connection
    try:
        return asyncio.run(_tenant_call(connection, operation))
    except OpentideError as exc:
        return _tenant_error(exc)


def _connectors() -> dict[str, Any]:
    names = platforms()
    return {
        "platforms": names,
        "capabilities": {
            name: dataclasses.asdict(found)
            for name in names
            if (found := capabilities(name)) is not None
        },
    }


def _guarded(ws: Workspace, operation: Mapping[str, Any]) -> Any:
    try:
        return _call(ws, operation)
    except OpentideError as exc:
        return _error(exc)


def _run_json(root: str, operation: Mapping[str, Any]) -> Any:
    argv = list(operation["argv"])
    if operation.get("repo", True):
        argv = ["--repo", root, *argv]
    with _cwd(root):
        try:
            document = opentide.run_json(argv)
        except OpentideError as exc:
            return _error(exc)
    return document


def _open(root: str, mode: str) -> Workspace | dict[str, Any]:
    try:
        if mode == "files":
            return Workspace.from_files(root, _files(Path(root)))
        return Workspace.open(root)
    except OpentideError as exc:
        return _error(exc)


def run_plan(plan: Mapping[str, Any], out: Path, *, diverge: bool = False) -> list[Path]:
    """Writes the document of every operation on every corpus of *plan* under
    *out*; returns the files written, in the plan's order."""
    written: list[Path] = []
    tenants = {tenant["name"]: tenant for tenant in plan.get("tenants", ())}
    urls: Mapping[str, str] = plan.get("urls", {})
    for corpus in plan["corpora"]:
        name, root = corpus["name"], corpus["root"]
        opened: dict[str, Workspace | dict[str, Any]] = {}
        connected: dict[str, Connection | dict[str, Any]] = {}
        for operation in plan["operations"]:
            only = operation.get("corpora")
            if only is not None and name.split("/")[0] not in only:
                continue
            if operation["call"] == "run_json":
                document = _run_json(root, operation)
            elif operation["call"] == "connectors":
                document = _connectors()
            elif operation["call"] in TENANT_CALLS:
                tenant = operation["tenant"]
                if tenant not in connected:
                    connected[tenant] = _connect(tenants[tenant], urls)
                document = _tenant(connected[tenant], operation)
            else:
                mode = operation.get("open", "disk")
                if mode not in opened:
                    opened[mode] = _open(root, mode)
                ws = opened[mode]
                document = ws if isinstance(ws, dict) else _guarded(ws, operation)
                if diverge and operation["call"] == "validate" and not isinstance(ws, dict):
                    # The test-only divergence: the document as a binding that
                    # went through a sorted map would hand it back.
                    document = json.loads(json.dumps(document, sort_keys=True))
            path = out / name / f"{operation['name']}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(canonical(normalise(document)), encoding="utf-8", newline="\n")
            written.append(path)
    return written


def test_the_python_runner_writes_every_document(tmp_path: Path) -> None:
    plan_path = os.environ.get(PLAN_ENV)
    if plan_path:
        plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
        out = Path(os.environ[OUT_ENV])
    else:
        plan = standalone_plan(tmp_path)
        out = tmp_path / "out"
    diverge = bool(os.environ.get(DIVERGE_ENV))
    with ExitStack() as stack:
        if not plan_path:
            stack.enter_context(stand_ins(plan))
        written = run_plan(plan, out, diverge=diverge)
    assert written, "the plan names no operation"
    for path in written:
        json.loads(path.read_text(encoding="utf-8"))
    if not plan_path:
        # The tide corpus is clean: each operation ran, none failed to open.
        names = {path.stem for path in written}
        assert names == {operation["name"] for operation in plan["operations"]}
        validate = json.loads((out / "tide_corpus" / "validate.json").read_text(encoding="utf-8"))
        assert validate["failed"] is False
        assert validate["exit_code"] == 0
        # The tenant operations reached the stand-ins.
        query = json.loads((out / "tide_corpus" / "query-soc.json").read_text(encoding="utf-8"))
        assert query["rows"][0] == {"src.process.name": "cmd.exe", "endpoint.name": "ws-1"}
        created = json.loads(
            (out / "tide_corpus" / "deploy-soc-create.json").read_text(encoding="utf-8")
        )
        assert created == {"remote_id": "1900000000000000001", "operation": "create"}


def test_the_divergence_flag_changes_the_bytes_and_not_the_data(tmp_path: Path) -> None:
    """``OPENTIDE_CONFORMANCE_DIVERGE`` reorders the keys of the validate
    document: the data stays, the bytes change, and the comparator must say
    where (``xtask/src/conformance.rs``, ``cargo xtask conformance --diverge``)."""
    plan = standalone_plan(tmp_path)
    plan["operations"] = [op for op in plan["operations"] if op["name"] == "validate"]
    same = run_plan(plan, tmp_path / "same")
    diverged = run_plan(plan, tmp_path / "diverged", diverge=True)
    before = same[0].read_text(encoding="utf-8")
    after = diverged[0].read_text(encoding="utf-8")
    assert before != after
    assert json.loads(before) == json.loads(after)
    assert list(json.loads(before)) == [
        "checks",
        "report",
        "summary",
        "failed",
        "warned",
        "exit_code",
    ]
    assert list(json.loads(after))[1] == "exit_code"
