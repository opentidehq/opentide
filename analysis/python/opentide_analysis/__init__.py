"""The opentide analysis engine and language server, for the ``opentide`` package.

``pip install opentide`` installs this package: it is a dependency, not an
extra. Use it through ``opentide`` (``opentide validate query``, ``opentide
validate --deep``, ``opentide lsp``) rather than directly; this API follows
what that package needs.

Positions are 1-based lines and columns, columns count Unicode code points,
and ``end_column`` is exclusive, as in the ``opentide`` CLI's diagnostics.
"""

from importlib.metadata import PackageNotFoundError, version

from opentide_analysis._native import (
    CODES,
    ENGINE_VERSION,
    LANGUAGES,
    Diagnostic,
    QueryReport,
    Workspace,
    analyze_query,
    bundled_catalog,
    catalog_is_workspace,
    catalog_version,
    describe_code,
    highlight,
    install_catalog,
    language_for_path,
    serve_stdio,
    set_default_catalog,
    use_host_catalogs,
)

try:
    __version__ = version("opentide-analysis")
except PackageNotFoundError:  # pragma: no cover - imported from a source tree
    __version__ = "0+unknown"

__all__ = [
    "CODES",
    "ENGINE_VERSION",
    "LANGUAGES",
    "Diagnostic",
    "QueryReport",
    "Workspace",
    "__version__",
    "analyze_query",
    "bundled_catalog",
    "catalog_is_workspace",
    "catalog_version",
    "describe_code",
    "highlight",
    "install_catalog",
    "language_for_path",
    "serve_stdio",
    "set_default_catalog",
    "use_host_catalogs",
]
