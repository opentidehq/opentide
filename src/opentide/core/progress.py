"""How engine modules say which stage of a long run they are in, without printing.

Engine code (schema assembly, templates, snippets, promotion, validation
passes) calls :func:`report_stage` where it used to print a section header.
The CLI listens for the length of a command and shows the stage beside the
step it belongs to (``opentide.cli.ui.progress``); with nobody listening, the
stage is a DEBUG log line. Engine modules never draw anything themselves.

Standard library and structlog only, so any module can import it.
"""

from __future__ import annotations

from collections.abc import Callable, Generator
from contextlib import contextmanager

import structlog

logger = structlog.get_logger("opentide.core.progress")

#: Called with the name of each stage as it starts. The innermost listener wins.
StageListener = Callable[[str], None]

_listeners: list[StageListener] = []


def report_stage(name: str) -> None:
    """Announce that the engine has started *name* (``JSON schema assembly``)."""
    if _listeners:
        _listeners[-1](name)
        return
    logger.debug("stage_started", stage=name)


def is_listening() -> bool:
    """Whether a caller is showing stages right now."""
    return bool(_listeners)


@contextmanager
def listen(listener: StageListener) -> Generator[None, None, None]:
    """Send every stage reported inside this block to *listener*."""
    _listeners.append(listener)
    try:
        yield
    finally:
        _listeners.remove(listener)
