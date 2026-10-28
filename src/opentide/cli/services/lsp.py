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
    """Serve LSP on stdio until the editor exits or closes stdin; return the exit code.

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
    _supply_catalogs()
    failure: list[BaseException] = []

    def run() -> None:
        from opentide.analysis import serve_stdio

        try:
            serve_stdio()
        except BaseException as exc:  # reported on the main thread
            failure.append(exc)

    worker = threading.Thread(target=run, name="opentide-lsp", daemon=True)
    worker.start()
    while worker.is_alive():
        worker.join(timeout=0.2)
    if failure:
        print(f"error: the language server stopped: {failure[0]}", file=sys.stderr)  # noqa: T201 -- stderr, outside the protocol
        return 1
    return 0


def _supply_catalogs() -> None:
    """Hand the server this opentide's catalogs for the workspace it starts in.

    The server would otherwise read the workspace's committed catalogs at
    ``initialize``, which may come from an older opentide, or fall back to
    the snapshot compiled into the engine. When they cannot be generated, the
    server does as before, and stderr says why.
    """
    from opentide.analysis import engine, own_catalog
    from opentide.registry.discovery import discover_workspace

    try:
        catalogs = own_catalog(discover_workspace())
        module = engine()
        module.set_default_catalog(
            fields=catalogs["fields.json"], deprecations=catalogs["deprecations.json"]
        )
        module.use_host_catalogs()
    except Exception as exc:  # the server still starts, on the workspace's catalogs
        print(  # noqa: T201 -- stderr, outside the protocol
            f"warning: opentide's catalogs could not be generated ({type(exc).__name__}: {exc}); "
            "using the workspace's, or the engine's bundled ones",
            file=sys.stderr,
        )
