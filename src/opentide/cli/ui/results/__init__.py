"""Typed result models: the shape of each command's ``--json`` document.

:data:`RESULT_MODELS` maps a command path (``validate``, ``generate docs
rules``) to the pydantic model of what it prints. ``opentide commands --json``
publishes their JSON Schemas; the test suite checks every document a command
prints against its model. Production code never validates against them: a
command's output is whatever its service returns, and an extra key must not
fail a run.

A command added later registers its model here, or lists itself in
:data:`PENDING_MODELS` until it has one. ``tests/test_cli/test_result_models.py``
fails on a visible command that does neither.

Importing this package loads pydantic and every model, so only ``opentide
commands`` and the tests import it.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from pydantic.json_schema import models_json_schema

from opentide.cli.ui.results.base import CommandDocument, CommandError
from opentide.cli.ui.results.catalogue import (
    CommandsResult,
    ExplainResult,
    InfoResult,
    LintResult,
    QueryValidationResult,
    UnreviewedResult,
    ValidateResult,
)
from opentide.cli.ui.results.deploy import DeployResult, MigrateStateResult
from opentide.cli.ui.results.generate import DocsResult, ExportResult, ExtractResult, GenerateResult
from opentide.cli.ui.results.migrate import MigrateObjectsResult, MigrateVocabScopeResult
from opentide.cli.ui.results.setup import (
    SetupCiResult,
    SetupEnvResult,
    SetupHooksResult,
    SetupMcpResult,
    SetupPlatformsResult,
    SetupRepoResult,
    SetupResult,
    SetupSkillsResult,
    SetupVscodeResult,
    SkillsDiscoverResult,
    SkillsShowResult,
)
from opentide.cli.ui.results.share import ShareResult, ShareTargetsResult

__all__ = [
    "NO_DOCUMENT",
    "PENDING_MODELS",
    "RESULT_MODELS",
    "CommandDocument",
    "CommandError",
    "output_schemas",
    "result_model",
]

_DOCS = ("", " rules", " objectives", " threats", " index")
_EXPORTS = (" navigator", " objects", " revisions")
_IMPORTERS = (" sentinel", " defender", " elastic")

#: The model of each command's document, by command path. Hidden and
#: deprecated spellings are listed too: they still print a document.
RESULT_MODELS: dict[str, type[CommandDocument]] = {
    "validate": ValidateResult,
    "validate query": QueryValidationResult,
    "lint": LintResult,
    "info": InfoResult,
    "explain": ExplainResult,
    "commands": CommandsResult,
    "rules unreviewed": UnreviewedResult,
    "generate": GenerateResult,
    "generate explorer": GenerateResult,
    "generate inflight": GenerateResult,
    "generate inflight prune": GenerateResult,
    "generate exports": GenerateResult,
    **{f"generate docs{scope}": DocsResult for scope in _DOCS},
    **{f"generate exports{target}": ExportResult for target in _EXPORTS},
    **{f"generate extract{target}": ExtractResult for target in _IMPORTERS},
    "deploy": DeployResult,
    "deploy migrate-state": MigrateStateResult,
    "deploy metadata": CommandError,
    "setup": SetupResult,
    "setup repo": SetupRepoResult,
    "setup platforms": SetupPlatformsResult,
    "setup ci": SetupCiResult,
    "setup env": SetupEnvResult,
    "setup hooks": SetupHooksResult,
    "setup mcp": SetupMcpResult,
    "setup vscode": SetupVscodeResult,
    "setup skills": SetupSkillsResult,
    "setup skills discover": SkillsDiscoverResult,
    "setup skills show": SkillsShowResult,
    "share": ShareResult,
    "share push": ShareResult,
    "share preview": ShareResult,
    "share status": ShareResult,
    "share retract": ShareResult,
    "share targets": ShareTargetsResult,
    "migrate objects": MigrateObjectsResult,
    "migrate vocab-scope": MigrateVocabScopeResult,
    # Deprecated spellings of generate subcommands.
    **{f"document{scope}": DocsResult for scope in _DOCS},
    **{f"export{target}": ExportResult for target in (*_EXPORTS, " playbook-map")},
    **{f"extract{target}": ExtractResult for target in _IMPORTERS[:2]},
}

#: Root commands whose documents have no model yet, and the pull request that
#: adds the command. Their subcommands are pending too.
PENDING_MODELS: dict[str, str] = {
    "new": "#642",
    "doctor": "#642",
    "tui": "#639",
}

#: Commands that never print a JSON document: stdout is JSON-RPC, or the
#: command hands over to another program.
NO_DOCUMENT = frozenset({"mcp start", "deploy replay-state"})


def result_model(path: str) -> type[CommandDocument] | None:
    """The model of *path*'s document; ``None`` for a pending command or one that prints none."""
    return RESULT_MODELS.get(path)


def output_schemas(paths: list[str]) -> tuple[dict[str, dict[str, Any] | None], dict[str, Any]]:
    """Each path's output schema as a ``$ref``, and the ``$defs`` they refer to.

    A command's document is either its own result or a :class:`CommandError`
    (a usage error, or an error with nothing else to say), so each schema is
    ``anyOf`` the two. A path with no model gets ``None``.
    """
    models: list[type[BaseModel]] = [CommandError]
    for path in paths:
        model = RESULT_MODELS.get(path)
        if model is not None and model not in models:
            models.append(model)
    refs, schema = models_json_schema(
        [(model, "validation") for model in models], ref_template="#/$defs/{model}"
    )
    defs: dict[str, Any] = schema.get("$defs", {})
    error_ref = refs[(CommandError, "validation")]
    schemas: dict[str, dict[str, Any] | None] = {}
    for path in paths:
        model = RESULT_MODELS.get(path)
        if model is None:
            schemas[path] = None
        elif model is CommandError:
            schemas[path] = dict(error_ref)
        else:
            schemas[path] = {"anyOf": [dict(refs[(model, "validation")]), dict(error_ref)]}
    return schemas, defs
