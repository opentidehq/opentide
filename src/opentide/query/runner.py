"""The engine each platform implements to run a read-only query on one tenant."""

from __future__ import annotations

import importlib
import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import replace
from typing import Any, ClassVar, TypeVar, cast

from opentide.models.system_config import SystemConfig
from opentide.query.models import LiveCheck, QueryRequest, QueryResult

_Client = TypeVar("_Client")

#: Platforms with a query runner: every detection platform.
QUERY_PLATFORMS: frozenset[str] = frozenset(
    {
        "sentinel",
        "defender_for_endpoint",
        "splunk",
        "sentinel_one",
        "carbon_black_cloud",
        "crowdstrike",
        "harfanglab",
        "elastic",
    }
)

#: Package under ``opentide.platforms`` holding each platform's ``runner`` module.
_RUNNER_PACKAGES = {"carbon_black_cloud": "carbon_black"}


class QueryRunner(ABC):
    """Runs one query on one tenant and returns at most ``request.limit`` rows.

    A runner never saves a search or a rule, and stops an asynchronous search
    it no longer waits for where the platform's API can.
    """

    #: The languages ``--language`` takes; the first is the default.
    languages: ClassVar[tuple[str, ...]]

    @abstractmethod
    def run(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> QueryResult:
        """Rows for *request* on *tenant*.

        Raises :class:`~opentide.query.models.QueryRefused` when the platform
        refuses the query, and lets a transport failure through for the caller
        to report as an unreachable tenant.
        """

    def check(self, request: QueryRequest, tenant: SystemConfig.Tenant) -> LiveCheck:
        """Whether *tenant* accepts *request*: ``validate query --live``'s question.

        By default a search for one row over ``request.window``; a platform
        with a parse-only call (Splunk, Carbon Black) asks that instead, so the
        check runs no search. Raises like :meth:`run`.
        """
        return LiveCheck(result=self.run(replace(request, limit=1), tenant))

    def client(
        self, tenant: SystemConfig.Tenant, build: Callable[[], _Client], *, key: str = ""
    ) -> _Client:
        """The client *build* makes for *tenant*, made once per runner.

        A live check sends every rule of a tenant through one runner: one
        client (one sign-in) serves them all, as one deploy does.
        """
        clients: dict[tuple[int, str], tuple[Any, Any]] = self.__dict__.setdefault("_clients", {})
        cached = clients.get((id(tenant), key))
        # The tenant is kept with its client: an id is reused once its object is freed.
        if cached is None or cached[0] is not tenant:
            cached = (tenant, build())
            clients[(id(tenant), key)] = cached
        return cast(_Client, cached[1])


class RunnerUnavailable(RuntimeError):
    """The platform's runner module could not be imported (a broken SDK install)."""


def load_runner(platform: str) -> QueryRunner:
    """*platform*'s runner, importing only that platform's module and SDK."""
    if platform not in QUERY_PLATFORMS:
        raise KeyError(platform)
    package = _RUNNER_PACKAGES.get(platform, platform)
    module_name = f"opentide.platforms.{package}.runner"
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise RunnerUnavailable(f"cannot load the {platform} query runner: {exc}") from exc
    return cast(QueryRunner, module.declare())


_KQL_TAIL = re.compile(r"\|\s*(?:take|limit)\s+\d+\s*$", re.IGNORECASE)


def kql_with_limit(query: str, limit: int) -> str:
    """*query* with ``| take limit+1`` appended, unless it already ends in ``take``/``limit``.

    One row past the limit tells the caller the result was truncated. The
    ``take`` goes on a line of its own, so a trailing ``//`` comment cannot
    swallow it.
    """
    text = query.rstrip().rstrip(";").rstrip()
    if _KQL_TAIL.search(kql_code(text).rstrip()):
        return text
    return f"{text}\n| take {limit + 1}"


def kql_code(query: str) -> str:
    """*query* with its ``//`` comments and string literals blanked, positions kept."""
    out: list[str] = []
    index = 0
    length = len(query)
    while index < length:
        char = query[index]
        if query.startswith("//", index):
            end = query.find("\n", index)
            end = length if end == -1 else end
            out.append(" " * (end - index))
            index = end
            continue
        if char in "'\"":
            verbatim = index > 0 and query[index - 1] == "@"
            end = index + 1
            while end < length and query[end] != char:
                end += 2 if query[end] == "\\" and not verbatim else 1
            end = min(end + 1, length)
            out.append(" " * (end - index))
            index = end
            continue
        out.append(char)
        index += 1
    return "".join(out)
