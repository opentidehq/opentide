"""Progress events for editors and scripts: NDJSON on stderr with ``OPENTIDE_PROGRESS=json``.

Under ``--json`` a command prints one document when it ends, which leaves an
editor nothing to show while ``generate``, a workspace ``validate``, a
``query`` across tenants or a ``deploy --dry-run`` runs. With
``OPENTIDE_PROGRESS=json`` those commands also write one JSON object per line
on stderr as they go. Stdout is unchanged: still exactly one document.

Two kinds of event, documented in ``docs/cli/json-output.md``::

    {"event": "progress", "step": "schemas", "done": 3, "total": 6}
    {"event": "tenant", "platform": "sentinel", "tenant": "prod", "status": "ok",
     "rows": 120, "elapsed_ms": 1800}

``opentide serve`` installs a :func:`sink` for the length of each run and
forwards the same events to its client as ``progress`` notifications.

Standard library only, so any module can import it.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from typing import Any

#: Environment variable; ``json`` turns the events on. Its boolean values belong to
#: the terminal's tab and taskbar progress (:mod:`opentide.cli.ui.terminal_progress`).
PROGRESS_ENV = "OPENTIDE_PROGRESS"
#: The value of :data:`PROGRESS_ENV` that writes events on stderr.
JSON_VALUE = "json"

#: Receives each event instead of stderr, while one is installed (``opentide serve``).
EventSink = Callable[[dict[str, Any]], None]

_sink: EventSink | None = None
#: One line at a time: validation reports from a thread pool.
_write_lock = threading.Lock()


def requested(env: Mapping[str, str] | None = None) -> bool:
    """Whether ``OPENTIDE_PROGRESS`` asks for events on stderr."""
    value = (os.environ if env is None else env).get(PROGRESS_ENV, "")
    return value.strip().lower() == JSON_VALUE


def enabled() -> bool:
    """Whether an event emitted now goes anywhere: a sink, or stderr."""
    return _sink is not None or requested()


def emit(event: Mapping[str, Any]) -> None:
    """Send *event* to the installed sink, or write it as one line on stderr.

    Nothing happens when neither is on. A closed stderr is not worth a crash.
    """
    sink = _sink
    if sink is not None:
        sink(dict(event))
        return
    if not requested():
        return
    line = json.dumps(dict(event), ensure_ascii=False, separators=(",", ":"), default=str)
    stream = sys.stderr
    if stream is None:
        return
    with _write_lock:
        try:
            stream.write(line + "\n")
            stream.flush()
        except (OSError, ValueError):
            pass


def progress(step: str, done: int, total: int | None) -> None:
    """``{"event": "progress", "step": …, "done": …, "total": …}``; *total* may be null."""
    if not enabled():
        return
    emit({"event": "progress", "step": step, "done": done, "total": total})


def tenant(
    platform: str,
    name: str,
    *,
    ok: bool,
    rows: int,
    elapsed_ms: int,
    label: str | None = None,
) -> None:
    """One tenant's outcome in a run across tenants (``opentide query``).

    ``label`` is added only for a platform whose rule holds several queries.
    """
    if not enabled():
        return
    event: dict[str, Any] = {
        "event": "tenant",
        "platform": platform,
        "tenant": name,
        "status": "ok" if ok else "failed",
        "rows": rows,
        "elapsed_ms": elapsed_ms,
    }
    if label is not None:
        event["label"] = label
    emit(event)


class Ticker:
    """``progress`` events for *total* units of one step, at most about 20 of them.

    :meth:`advance` is thread-safe. The last unit always reports, so a reader
    sees ``done == total``.
    """

    #: Events per step, at most (plus the last one).
    BATCHES = 20

    def __init__(self, step: str, total: int) -> None:
        self.step = step
        self.total = total
        self.done = 0
        self._every = max(1, total // self.BATCHES)
        self._lock = threading.Lock()
        self._on = enabled()

    def advance(self, count: int = 1) -> None:
        if not self._on:
            return
        with self._lock:
            before = self.done
            self.done += count
            done = self.done
        if done >= self.total or done // self._every != before // self._every:
            progress(self.step, done, self.total)


@contextmanager
def sink(receiver: EventSink) -> Generator[None, None, None]:
    """Send every event emitted inside this block to *receiver* instead of stderr."""
    global _sink
    previous = _sink
    _sink = receiver
    try:
        yield
    finally:
        _sink = previous
