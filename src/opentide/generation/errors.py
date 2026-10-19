"""Fail a generation phase by name, and say which object broke it (#579).

Without this, ``generate exports`` reported a ``KeyError`` as the bare key
(``'tlp'``), a phase that logged an error still exited ``0``, and a scoped
``generate docs`` let the exception escape as a traceback.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager

#: Keys structlog adds to every event; they say nothing about the failure.
_LOG_BOILERPLATE = frozenset({"event", "logger", "level", "timestamp"})


class ObjectGenerationError(Exception):
    """An object failed to render; the message names the object."""

    def __init__(self, uuid: str, cause: Exception) -> None:
        self.uuid = uuid
        self.cause = cause
        super().__init__(f"{describe_exception(cause)} while rendering {uuid}")


class GenerationPhaseError(RuntimeError):
    """A phase raised or logged an error; the message leads with the phase."""

    def __init__(self, phase: str, detail: str) -> None:
        self.phase = phase
        super().__init__(f"{phase}: {detail}")


def describe_exception(exc: BaseException) -> str:
    """Render *exc* as a traceback's last line: ``KeyError: 'tlp'``, not ``'tlp'``."""
    if isinstance(exc, ObjectGenerationError | GenerationPhaseError):
        return str(exc)
    detail = str(exc).strip()
    name = type(exc).__name__
    return f"{name}: {detail}" if detail else name


@contextmanager
def rendering(uuid: str) -> Generator[None, None, None]:
    """Name the object *uuid* on anything that escapes the block."""
    try:
        yield
    except ObjectGenerationError:
        raise
    except Exception as exc:
        raise ObjectGenerationError(uuid, exc) from exc


class _ErrorRecords(logging.Handler):
    """Keep the records a phase logs at ERROR or above."""

    def __init__(self) -> None:
        super().__init__(logging.ERROR)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _describe_record(record: logging.LogRecord) -> str:
    event = record.msg
    if not isinstance(event, dict):
        return " ".join(record.getMessage().split())
    fields = ", ".join(
        f"{key}={value}" for key, value in event.items() if key not in _LOG_BOILERPLATE
    )
    name = str(event.get("event", "error"))
    return " ".join((f"{name} ({fields})" if fields else name).split())


@contextmanager
def failing_phase(phase: str) -> Generator[None, None, None]:
    """Raise :class:`GenerationPhaseError` naming *phase* on what it raises or logs.

    A logged error used to leave the run green: the phase skipped the object
    it could not read and carried on, so CI published incomplete output.
    """
    errors = _ErrorRecords()
    root = logging.getLogger()
    root.addHandler(errors)
    try:
        yield
    except GenerationPhaseError:
        raise
    except Exception as exc:
        raise GenerationPhaseError(phase, describe_exception(exc)) from exc
    finally:
        root.removeHandler(errors)
    if errors.records:
        first = _describe_record(errors.records[0])
        count = len(errors.records)
        detail = (
            f"logged an error: {first}" if count == 1 else f"logged {count} errors, first: {first}"
        )
        raise GenerationPhaseError(phase, detail)
