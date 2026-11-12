"""``opentide lsp``: the language server, for editors."""

from __future__ import annotations

import sys
import threading

#: What ``lsp start`` prints on stderr when a person runs it at a terminal.
TERMINAL_HINT = (
    "opentide lsp start speaks the language server protocol on stdin and stdout: "
    "your editor starts it (see https://opentide.org/docs/cli/lsp/). Ctrl-C stops it."
)


def serve() -> int:
    """Serve LSP on stdio until the editor exits or closes stdin; return the exit code:
    0 when the editor shut the server down first, 1 otherwise (LSP).

    The server runs on a thread without the GIL, so Ctrl-C still reaches
    Python and stops it (exit 130). Nothing else may write to stdout: the
    output mode for ``lsp start`` is ``mcp``, which keeps it for the protocol.
    """
    from opentide.analysis import EngineUnavailableError, engine

    try:
        engine()
    except EngineUnavailableError as exc:
        # Before any protocol byte, as a line the editor shows in its log.
        print(f"error: {exc}\n  help: {exc.advice}", file=sys.stderr)  # noqa: T201 -- stderr, outside the protocol
        return 1
    if sys.stdin.isatty():
        print(TERMINAL_HINT, file=sys.stderr)  # noqa: T201 -- stderr, outside the protocol
    # No catalog is handed over: the server generates each root's field
    # catalogs and configuration schemas from the models (#926), as
    # ``opentide lsp start`` on Rust does, and clients read ``catalog:
    # "models"`` at ``initialize`` (UC-6.0d, #841).
    _name_the_host()
    failure: list[BaseException] = []
    clean: list[bool] = []

    def run() -> None:
        from opentide.analysis import serve_stdio

        try:
            clean.append(serve_stdio())
        except BaseException as exc:  # reported on the main thread
            failure.append(exc)

    worker = threading.Thread(target=run, name="opentide-lsp", daemon=True)
    worker.start()
    while worker.is_alive():
        worker.join(timeout=0.2)
    if failure:
        print(f"error: the language server stopped: {failure[0]}", file=sys.stderr)  # noqa: T201 -- stderr, outside the protocol
        return 1
    # LSP: 0 after `shutdown` then `exit`, 1 when the editor exits or closes
    # stdin without shutting the server down.
    return 0 if clean and clean[0] else 1


def _name_the_host() -> None:
    """Tell clients the server runs inside opentide, and which one.

    They read it at ``initialize`` (``capabilities.experimental.opentide.host``)
    to tell ``opentide lsp start`` from the bare ``opentide-lsp`` binary.
    """
    from opentide import __version__
    from opentide.analysis import engine

    engine().set_host_info("opentide", __version__)
