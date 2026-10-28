"""How a deployer says which rule it is sending and how that went, without printing.

A platform deployer wraps each rule it sends in :func:`deploying`. The CLI
listens for the length of a deploy (``opentide.cli.ui.deploy_log``), prints one
line per rule as it finishes and keeps the outcomes for the result's
``results``. With nobody listening, the outcome is an INFO log line, so SDK and
MCP callers lose nothing and pay nothing.

A rule is in one of four states:

``deployed``
    The platform accepted it.
``failed``
    The platform (or the plan) refused it; ``error`` says why.
``skipped``
    The engine chose not to send it (an inert status, a Sigma rule on a YARA
    tenant); ``reason`` says why.
``not_attempted``
    Never reached: an earlier rule failed. Set by the CLI from the plan, since
    a deployer that stopped never saw the rest.

Standard library and structlog only, so any module can import it.
"""

from __future__ import annotations

import re
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from types import TracebackType
from typing import Literal, Protocol

import structlog

logger = structlog.get_logger("opentide.core.deploy_events")

RuleStatus = Literal["deployed", "failed", "skipped", "not_attempted"]

#: The longest error kept on a result: a platform that answers with a page of HTML
#: must not fill a CI log.
MAX_ERROR_LENGTH = 400


@dataclass
class RuleResult:
    """One rule on one tenant: what was sent and how it went."""

    platform: str
    tenant: str | None
    id: str
    name: str
    status: RuleStatus = "deployed"
    #: ``create``, ``update``, ``upsert``, ``disable`` or ``delete``; the CLI sets it from the plan.
    action: str | None = None
    seconds: float | None = None
    error: str | None = None
    #: Why a ``skipped`` or ``not_attempted`` rule was not sent.
    reason: str | None = None
    started: float = field(default_factory=time.perf_counter, repr=False, compare=False)

    def to_dict(self) -> dict[str, object]:
        """The row ``results`` carries in a deploy's JSON document."""
        row = asdict(self)
        row.pop("started")
        row["seconds"] = None if self.seconds is None else round(self.seconds, 3)
        return row


class DeployListener(Protocol):
    """What the CLI implements to follow a deploy."""

    def rule_started(self, result: RuleResult) -> None:
        """A rule is about to be sent."""

    def rule_finished(self, result: RuleResult) -> None:
        """A rule ended: ``deployed``, ``failed`` or ``skipped``."""


_listeners: list[DeployListener] = []
_current: list[RuleScope] = []


def is_listening() -> bool:
    """Whether a caller is following the deploy right now."""
    return bool(_listeners)


@contextmanager
def listen(listener: DeployListener) -> Generator[None, None, None]:
    """Send every rule event reported inside this block to *listener*."""
    _listeners.append(listener)
    try:
        yield
    finally:
        _listeners.remove(listener)


class RuleScope:
    """The rule being sent. Leaving the block marks it ``deployed`` unless it failed."""

    def __init__(self, result: RuleResult) -> None:
        self.result = result

    def fail(self, error: str) -> None:
        """Record a failure the deployer reports without raising (the batch continues)."""
        if self.result.status != "failed":
            self.result.status = "failed"
            self.result.error = _bounded(error)

    def skip(self, reason: str) -> None:
        """Record that the engine chose not to send this rule."""
        if self.result.status != "failed":
            self.result.status = "skipped"
            self.result.reason = reason

    def __enter__(self) -> RuleScope:
        _current.append(self)
        for listener in _listeners:
            listener.rule_started(self.result)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        _current.remove(self)
        if exc is not None:
            self.fail(describe_error(exc))
        _finish(self.result)


@contextmanager
def deploying(
    platform: str,
    tenant: str | None,
    rule_id: object,
    name: str,
    *,
    action: str | None = None,
) -> Generator[RuleScope, None, None]:
    """Wrap the call that sends one rule.

    An exception marks the rule failed, with the platform's own message, and
    propagates: stopping the run is the deployer's decision, not this module's.
    """
    with RuleScope(
        RuleResult(platform=platform, tenant=tenant, id=str(rule_id), name=str(name), action=action)
    ) as scope:
        yield scope


def note_failure(message: str) -> None:
    """Mark the rule being sent as failed, for a deployer that records failures in flags.

    Nothing happens outside a :func:`deploying` block.
    """
    if _current:
        _current[-1].fail(message)


def note_skip(reason: str) -> None:
    """Mark the rule being sent as not sent, for a deployer that leaves it out mid-block.

    Nothing happens outside a :func:`deploying` block.
    """
    if _current:
        _current[-1].skip(reason)


def skipped(platform: str, tenant: str | None, rule_id: object, name: str, reason: str) -> None:
    """Report a rule the engine decided not to send."""
    result = RuleResult(
        platform=platform,
        tenant=tenant,
        id=str(rule_id),
        name=str(name),
        status="skipped",
        reason=reason,
    )
    result.seconds = 0.0
    _finish(result)


def refused(platform: str, tenant: str | None, rule_id: object, name: str, error: str) -> None:
    """Report a rule planning refused before anything was sent."""
    result = RuleResult(
        platform=platform,
        tenant=tenant,
        id=str(rule_id),
        name=str(name),
        status="failed",
        error=_bounded(error),
    )
    result.seconds = 0.0
    _finish(result)


def _finish(result: RuleResult) -> None:
    if result.seconds is None:
        result.seconds = time.perf_counter() - result.started
    if not _listeners:
        logger.info(
            "rule_result",
            rule=result.name,
            uuid=result.id,
            platform=result.platform,
            tenant=result.tenant,
            status=result.status,
            seconds=round(result.seconds, 3),
            error=result.error,
            reason=result.reason,
        )
    for listener in _listeners:
        listener.rule_finished(result)


def _bounded(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > MAX_ERROR_LENGTH:
        return text[: MAX_ERROR_LENGTH - 1].rstrip() + "…"
    return text


def http_status(exc: BaseException) -> int | None:
    """The HTTP status an SDK or ``requests`` exception carries, if any."""
    for holder in (exc, getattr(exc, "response", None)):
        # ``status_code``: Azure and ``requests``; ``status``: the Splunk SDK.
        for attribute in ("status_code", "status"):
            status = getattr(holder, attribute, None)
            if isinstance(status, int) and not isinstance(status, bool):
                return status
    return None


def _platform_message(exc: BaseException) -> str:
    """The platform's own words: the Azure error's message, the response body's, else ``str``."""
    detail = getattr(exc, "error", None)
    message = getattr(detail, "message", None)
    if isinstance(message, str) and message.strip():
        return message
    response = getattr(exc, "response", None)
    if response is not None:
        try:
            body = response.json()
        except (ValueError, TypeError, AttributeError):
            body = None
        if isinstance(body, dict):
            for key in ("message", "error", "detail", "title"):
                value = body.get(key)
                if isinstance(value, str) and value.strip():
                    return value
                if isinstance(value, dict) and isinstance(value.get("message"), str):
                    return str(value["message"])
    text = str(exc).strip()
    # Azure appends ``Code: …`` and ``Message: …`` lines that repeat the first line,
    # and opens it with ``(Code) ``, which the HTTP status already says.
    first = re.split(r"\n(?:Code|Message|Target): ", text, maxsplit=1)[0]
    return re.sub(r"^\(\w+\)\s*", "", first) or type(exc).__name__


def describe_error(exc: BaseException) -> str:
    """``HTTP 400: <platform message>``, or ``ExcType: message`` when no status is known."""
    message = _platform_message(exc)
    status = http_status(exc)
    if status is not None:
        return _bounded(f"HTTP {status}: {message}")
    if isinstance(exc, KeyboardInterrupt):
        return "interrupted"
    name = type(exc).__name__
    return _bounded(f"{name}: {message}" if message and message != name else name)
