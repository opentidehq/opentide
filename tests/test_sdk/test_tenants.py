"""The SDK's tenant operations (UC-5.2b, #837): ``Workspace.tenants`` and ``Connection``.

``Connection.query``, ``validate_query`` and ``deploy`` are the facade's ``async``
operations under asyncio (pyo3-async-runtimes). They run against the SentinelOne
stand-in of ``tests/cassettes/`` on loopback, each connection given an environment
of its own so that no proxy of the process applies; nothing reaches a real host.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from collections.abc import Coroutine, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any, TypeVar

import pytest
from tests.stand_in_support import S1_TOKEN, sentinel_one

import opentide
from opentide import (
    Capabilities,
    Connection,
    DeployOutcome,
    LiveCheck,
    OpentideError,
    QueryResult,
    TenantConfig,
    Workspace,
)
from opentide.sdk import capabilities, platforms

_T = TypeVar("_T")

SPLUNK_TOML = (
    "[platform]\nenabled = true\n\n"
    '[[tenants]]\nname = "prod"\n[tenants.setup]\n'
    'url = "$SPLUNK_URL"\nport = 8089\ntoken = "$SPLUNK_TOKEN"\n\n'
    '[[tenants]]\nname = "lab"\n[tenants.setup]\nurl = "https://lab.example"\n'
)
ENVIRONMENT = {"S1_API_TOKEN": S1_TOKEN}


def run(work: Coroutine[Any, Any, _T]) -> _T:
    return asyncio.run(work)


def soc(url: str) -> TenantConfig:
    return TenantConfig(
        "sentinel_one", "soc", {"url": url, "api_token": "$S1_API_TOKEN", "account_id": "42"}
    )


@pytest.fixture(scope="module")
def s1_url() -> Iterator[str]:
    with sentinel_one() as url:
        yield url


@pytest.fixture
def connection(s1_url: str) -> Connection:
    return Connection.open(soc(s1_url), environment=ENVIRONMENT)


# --------------------------------------------------------------------------
# Tenants and connections
# --------------------------------------------------------------------------


def test_the_names_are_the_packages() -> None:
    assert opentide.Connection is Connection
    assert opentide.TenantConfig is TenantConfig
    assert {"Connection", "TenantConfig", "QueryResult", "LiveCheck", "DeployOutcome"} <= set(
        dir(opentide)
    )


def test_a_workspace_lists_its_tenants_in_file_order() -> None:
    ws = Workspace.from_files(
        "/ws", {".opentide/configurations/platforms/splunk.toml": SPLUNK_TOML}
    )
    tenants = ws.tenants("splunk")
    assert [tenant.name for tenant in tenants] == ["prod", "lab"]
    assert tenants[0].platform == "splunk"
    assert tenants[0].setup_keys == ["port", "token", "url"]
    assert repr(tenants[0]) == "TenantConfig('splunk', 'prod')"
    assert ws.tenants("elastic") == []


def test_the_platforms_and_what_each_can_do() -> None:
    assert len(platforms()) == 11
    assert capabilities("sysdig") == Capabilities(deploy=True, live_validation=False, query=False)
    assert capabilities("graylog") == Capabilities(deploy=True, live_validation=True, query=True)
    assert capabilities("nowhere") is None


def test_a_connection_names_its_tenant_and_never_its_secret(connection: Connection) -> None:
    assert (connection.platform, connection.tenant) == ("sentinel_one", "soc")
    assert connection.capabilities == Capabilities(deploy=True, live_validation=True, query=True)
    assert repr(connection) == "Connection('sentinel_one', 'soc')"
    assert S1_TOKEN not in repr(connection)


@pytest.mark.parametrize(
    ("tenant", "code"),
    [
        (TenantConfig("nowhere", "x", {"url": "https://x"}), "operation_unsupported"),
        (
            TenantConfig("harfanglab", "lab", {"url": "https://hl", "api_token": "$UNSET_TOKEN"}),
            "credential_unset",
        ),
        (TenantConfig("splunk", "prod", {"ssl": "maybe"}), "tenant_setup_invalid"),
    ],
)
def test_opening_refuses_what_cannot_connect(tenant: TenantConfig, code: str) -> None:
    with pytest.raises(OpentideError) as raised:
        Connection.open(tenant, environment={})
    assert raised.value.code == code
    assert raised.value.detail is None


def test_an_unset_credential_is_named(s1_url: str) -> None:
    with pytest.raises(OpentideError, match="S1_API_TOKEN") as raised:
        Connection.open(soc(s1_url), environment={})
    assert raised.value.code == "credential_unset"


@pytest.mark.parametrize("timeout", [-1.0, float("nan")])
def test_a_timeout_is_a_number_of_seconds(s1_url: str, timeout: float) -> None:
    with pytest.raises(OpentideError) as raised:
        Connection.open(soc(s1_url), environment=ENVIRONMENT, timeout=timeout)
    assert raised.value.code == "usage_invalid_value"


# --------------------------------------------------------------------------
# The async operations
# --------------------------------------------------------------------------


def test_a_query_returns_its_rows(connection: Connection) -> None:
    result = run(connection.query("event.type = 'Process Creation'"))
    assert isinstance(result, QueryResult)
    assert [column["name"] for column in result.columns] == ["src.process.name", "endpoint.name"]
    # The SentinelOne connector names no column types.
    assert [column["type"] for column in result.columns] == [None, None]
    assert result.rows == [
        {"src.process.name": "cmd.exe", "endpoint.name": "ws-1"},
        {"src.process.name": "powershell.exe", "endpoint.name": "ws-2"},
    ]
    assert result.truncated is False
    assert result.partial is False
    assert result.warnings == ["Add a filter on event.type to speed up the query"]


def test_a_query_stops_at_its_limit(connection: Connection) -> None:
    end = datetime(2026, 11, 12, 10, 0)  # noqa: DTZ001 -- a naive datetime is taken as UTC
    result = run(connection.query("x", limit=1, start=end - timedelta(hours=1), end=end))
    assert len(result.rows) == 1
    assert result.truncated is True


def test_a_refused_query_raises_its_code_and_the_vendors_words(connection: Connection) -> None:
    with pytest.raises(OpentideError) as raised:
        run(connection.query("x | syntax"))
    assert raised.value.code == "tenant_refused"
    assert raised.value.detail is not None
    assert "Syntax error at 3" in raised.value.detail


def test_a_window_that_ends_before_it_starts_is_refused(connection: Connection) -> None:
    end = datetime(2026, 11, 12, 10, 0, tzinfo=timezone.utc)
    with pytest.raises(OpentideError) as raised:
        run(connection.query("x", start=end + timedelta(seconds=1), end=end))
    assert raised.value.code == "usage_invalid_value"


def test_a_live_check_accepts_and_refuses(connection: Connection) -> None:
    check = run(connection.validate_query("event.type = 'Process Creation'"))
    assert isinstance(check, LiveCheck)
    assert check.errors == []
    assert check.result is not None
    assert check.result.rows[0]["endpoint.name"] == "ws-1"
    with pytest.raises(OpentideError) as raised:
        run(connection.validate_query("x | syntax"))
    assert raised.value.code == "tenant_refused"


def test_a_platform_that_cannot_check_live_says_so() -> None:
    lab = TenantConfig("harfanglab", "lab", {"url": "http://127.0.0.1:9", "api_token": "t"})
    connection = Connection.open(lab, environment={})
    assert connection.capabilities.live_validation is False
    with pytest.raises(OpentideError) as raised:
        run(connection.validate_query("process.name:cmd.exe"))
    assert raised.value.code == "operation_unsupported"


def test_a_deploy_creates_the_rule(connection: Connection) -> None:
    body = json.dumps({"data": {"name": "Example", "queryType": "events"}}).encode()
    outcome = run(connection.deploy("11111111-1111-4111-8111-111111111111", "create", body))
    assert isinstance(outcome, DeployOutcome)
    assert outcome.operation == "create"
    assert outcome.remote_id is not None
    assert outcome.remote_id.startswith("19000000000000000")


def test_a_deploy_takes_only_the_four_operations(connection: Connection) -> None:
    with pytest.raises(OpentideError) as raised:
        run(connection.deploy("x", "upsert", b"{}"))  # the refusal under test
    assert raised.value.code == "usage_invalid_choice"


def test_a_proxy_carries_every_request(s1_url: str) -> None:
    """The stand-in answers directly; a proxy that is not listening fails the query."""
    proxied = Connection.open(soc(s1_url), environment=ENVIRONMENT, proxy="http://127.0.0.1:9")
    with pytest.raises(OpentideError) as raised:
        run(proxied.query("x"))
    assert raised.value.code == "tenant_unreachable"


def test_the_native_classes_name_their_tenant_and_never_its_secret(s1_url: str) -> None:
    from opentide._native import sdk as native

    tenant = native.TenantConfig(
        "sentinel_one", "soc", [("url", s1_url), ("api_token", "native-secret")]
    )
    assert repr(tenant) == 'TenantConfig("sentinel_one", "soc")'
    connection = native.Connection.open(tenant, environment=[])
    assert repr(connection) == 'Connection("sentinel_one", "soc")'
    assert "native-secret" not in repr(connection)


def test_an_unreachable_tenant_is_reported() -> None:
    closed = Connection.open(soc("http://127.0.0.1:9"), environment=ENVIRONMENT)
    with pytest.raises(OpentideError) as raised:
        run(closed.query("x"))
    assert raised.value.code == "tenant_unreachable"
    assert S1_TOKEN not in str(raised.value)


# --------------------------------------------------------------------------
# The event loop, cancellation and the GIL
# --------------------------------------------------------------------------


def test_operations_run_while_the_loop_runs_other_tasks(connection: Connection) -> None:
    """A slow search (polled twice) leaves the event loop and the GIL free."""

    async def main() -> tuple[QueryResult, QueryResult, int]:
        ticks = 0

        async def tick() -> None:
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.01)

        ticker = asyncio.ensure_future(tick())
        slow, fast = await asyncio.gather(connection.query("slow"), connection.query("fast"))
        ticker.cancel()
        return slow, fast, ticks

    slow, fast, ticks = run(main())
    assert len(slow.rows) == len(fast.rows) == 2
    # The search takes at least one poll delay (0.5 s): the loop kept ticking.
    assert ticks >= 20


def test_a_thread_runs_python_while_an_operation_runs(connection: Connection) -> None:
    """The operation holds no GIL: a CPU-bound thread advances meanwhile."""
    import threading

    counted = 0
    stop = threading.Event()

    def count() -> None:
        nonlocal counted
        while not stop.is_set():
            counted += 1

    thread = threading.Thread(target=count)
    thread.start()
    try:
        before = counted
        run(connection.query("slow"))
        assert counted > before
    finally:
        stop.set()
        thread.join()


def test_cancelling_the_task_stops_the_operation(connection: Connection) -> None:
    async def main() -> float:
        task = asyncio.ensure_future(connection.query("slow"))
        await asyncio.sleep(0.1)
        started = time.monotonic()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return time.monotonic() - started

    assert run(main()) < 1.0


def test_a_cancelled_connection_is_interrupted(s1_url: str) -> None:
    connection = Connection.open(soc(s1_url), environment=ENVIRONMENT)
    canceller = connection.canceller()
    assert canceller.is_cancelled is False

    async def main() -> None:
        task = asyncio.ensure_future(connection.query("slow"))
        await asyncio.sleep(0.1)
        canceller.cancel()
        await task

    with pytest.raises(OpentideError) as raised:
        run(main())
    assert raised.value.code == "interrupted"
    assert canceller.is_cancelled is True
    # Every later operation is cancelled too.
    with pytest.raises(OpentideError, match="interrupted"):
        run(connection.query("x"))


def test_a_connection_serves_several_event_loops(connection: Connection) -> None:
    assert len(run(connection.query("x")).rows) == 2
    assert len(run(connection.query("x")).rows) == 2


def test_the_async_runtime_starts_on_the_first_operation_not_on_import() -> None:
    """No thread of the Rust runtime runs until an operation does."""
    script = (
        "import threading, opentide\n"
        "from opentide import Connection, TenantConfig\n"
        "t = TenantConfig('harfanglab', 'lab', {'url': 'http://127.0.0.1:9', 'api_token': 't'})\n"
        "c = Connection.open(t, environment={})\n"
        "import os\n"
        "names = os.listdir('/proc/self/task')\n"
        "print(len(names))\n"
    )
    if not sys.platform.startswith("linux"):
        pytest.skip("counts threads through /proc")
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True, timeout=60
    )
    assert int(done.stdout.strip()) == 1, done.stdout
