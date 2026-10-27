"""Fail a generation phase by name, and say which object broke it (#579).

Without this, ``generate exports`` reported a ``KeyError`` as the bare key
(``'tlp'``), a phase that logged an error still exited ``0``, and a scoped
``generate docs`` let the exception escape as a traceback.
"""

from __future__ import annotations

import logging
from collections.abc import Generator
from contextlib import contextmanager

from opentide.core.errors import UserFileError
from opentide.core.logging.render import readable_event

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
    if _is_validation_error(exc):
        return _describe_validation_error(exc)
    detail = str(exc).strip()
    name = type(exc).__name__
    return f"{name}: {detail}" if detail else name


def _is_validation_error(exc: BaseException) -> bool:
    from pydantic import ValidationError

    return isinstance(exc, ValidationError)


def _describe_validation_error(exc: BaseException) -> str:
    """One line instead of Pydantic's report, which named the internal model
    (``DetectionRule_v1_1``), dumped the input and linked errors.pydantic.dev
    (post-merge end-to-end run of ``generate docs`` on an invalid rule).
    """
    from pydantic import ValidationError

    assert isinstance(exc, ValidationError)
    errors = exc.errors()
    if not errors:
        return "an object does not validate; opentide validate shows each finding"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ())) or "the object"
    message = str(first.get("msg", "is not valid"))
    message = message[:1].lower() + message[1:]
    data = first.get("input")
    name = data.get("name") if isinstance(data, dict) else None
    subject = f"{name!r}" if isinstance(name, str) and name else "an object"
    more = f" (and {len(errors) - 1} more)" if len(errors) > 1 else ""
    return (
        f"{subject} does not validate: {location}: {message}{more}; "
        "opentide validate shows each finding"
    )


@contextmanager
def rendering(uuid: str) -> Generator[None, None, None]:
    """Name the object *uuid* on anything that escapes the block."""
    try:
        yield
    except (ObjectGenerationError, UserFileError):
        raise
    except Exception as exc:
        raise ObjectGenerationError(uuid, exc) from exc


class _ErrorRecords(logging.Handler):
    """Keep the distinct records a phase logs at ERROR or above.

    The schemas and templates phases reload the registry, which parses the
    corpus again and logs the same error again; that is still one error.
    """

    def __init__(self) -> None:
        super().__init__(logging.ERROR)
        self.records: list[logging.LogRecord] = []
        self._seen: set[object] = set()

    def emit(self, record: logging.LogRecord) -> None:
        key = _record_key(record)
        if key not in self._seen:
            self._seen.add(key)
            self.records.append(record)


def _record_key(record: logging.LogRecord) -> object:
    """The event and its fields in sorted order; not when or where it was logged."""
    event = record.msg
    if not isinstance(event, dict):
        return record.getMessage()
    fields = sorted(
        (str(key), str(value)) for key, value in event.items() if key not in _LOG_BOILERPLATE
    )
    return (str(event.get("event")), tuple(fields))


def _describe_record(record: logging.LogRecord) -> str:
    """The record as a log line reads: readable text, then ``key: value`` fields."""
    event = record.msg
    if not isinstance(event, dict):
        return " ".join(record.getMessage().split())
    parts = [readable_event(event.get("event", "error"))]
    parts.extend(f"{key}: {value}" for key, value in event.items() if key not in _LOG_BOILERPLATE)
    return " ".join(" · ".join(parts).split())


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
    except (GenerationPhaseError, UserFileError):
        # A file the user must fix is reported by the CLI where it is.
        raise
    except Exception as exc:
        detail = describe_exception(exc)
        if errors.records:
            # What the phase logged before it raised is often the cause: an
            # object skipped as malformed, then a reference to it failing.
            detail = f"{detail}; {_describe_logged(errors.records)}"
        raise GenerationPhaseError(phase, detail) from exc
    finally:
        root.removeHandler(errors)
    if errors.records:
        raise GenerationPhaseError(phase, _describe_logged(errors.records))


def _describe_logged(records: list[logging.LogRecord]) -> str:
    first = _describe_record(records[0])
    if len(records) == 1:
        return f"logged an error: {first}"
    return f"logged {len(records)} errors, first: {first}"
