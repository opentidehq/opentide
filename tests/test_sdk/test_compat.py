"""The compatibility shims of the SDK before ``opentide.Workspace`` (UC-5.2, #837).

Each keeps working for one deprecation cycle and warns code outside opentide
that calls it; opentide's own modules (the CLI, MCP) still run on them and never
warn. ``opentide.models`` is UC-1.9's (``tests/test_models``).
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from pathlib import Path

import pytest

from opentide._deprecation import REMOVED_IN, warn_external


def _warns(replacement: str) -> pytest.WarningsChecker:
    return pytest.warns(
        DeprecationWarning, match=rf"removed in opentide {REMOVED_IN}: use {replacement}"
    )


def test_opentide_initialise_and_its_accessors_still_work_with_a_warning(
    tide_corpus_repo: Path,
) -> None:
    from opentide import Workspace

    with _warns(r"opentide\.Workspace"):
        from opentide import Opentide
    with _warns(r"opentide\.Workspace\.open\(\)"):
        Opentide.initialise()
    assert sorted(Opentide.Rules) == sorted(
        rule["uuid"] for rule in Workspace.open(tide_corpus_repo).rules()
    )
    assert len(Opentide.Threats) == 1
    assert len(Opentide.Objectives) == 1


def test_run_validation_and_validation_scope_still_work_with_a_warning(
    tide_corpus_repo: Path,
) -> None:
    from opentide import Workspace
    from opentide.validation.scope import ValidationScope
    from opentide.validation.session import run_validation

    with _warns(r"opentide\.Workspace\.validate\(\)"):
        scope = ValidationScope.full()
    with _warns(r"opentide\.Workspace\.validate\(files="):
        ValidationScope.narrow(types=frozenset({"rule"}))
    with _warns(r"opentide\.Workspace\.validate\(\)"):
        report = run_validation(scope=scope)
    assert report.ok
    assert report.ok == (not Workspace.open(tide_corpus_repo).validate().failed)


@pytest.mark.parametrize(
    "name", ["write_rules", "write_objectives", "write_threats", "write_all", "run"]
)
def test_the_documentation_writers_still_work_with_a_warning(
    name: str, tide_corpus_repo: Path
) -> None:
    import opentide.documentation as documentation

    writer: Callable[..., object] = getattr(documentation, name)
    with _warns(r'opentide\.Workspace\.run_json\(\["generate", "docs"'):
        writer(output="docs") if name in {"write_all", "run"} else writer()
    assert any((tide_corpus_repo / "docs").rglob("*.md"))


def test_the_replacement_of_the_documentation_writers_writes_the_pages(
    tide_corpus_repo: Path,
) -> None:
    from opentide import Workspace

    result = Workspace.open(tide_corpus_repo).run_json(["generate", "docs"])
    assert result["ok"] is True
    assert any((tide_corpus_repo / "docs" / "rules").glob("*.md"))


def test_rendering_one_page_is_not_deprecated(tide_corpus_repo: Path) -> None:
    from tests.corpus_support import CORPUS_RULE_UUIDS

    from opentide.core.registry import Opentide
    from opentide.documentation import render_rule

    with pytest.warns(DeprecationWarning):
        Opentide.initialise()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert render_rule(Opentide.Rules[CORPUS_RULE_UUIDS["sentinel"]]).startswith("#")


def test_opentides_own_callers_do_not_warn() -> None:
    namespace: dict[str, object] = {
        "__name__": "opentide.cli.example",
        "warn_external": warn_external,
    }
    exec(
        "def shim():\n    warn_external('old()', 'new()')\n\ndef caller():\n    shim()\n", namespace
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        namespace["caller"]()  # ty: ignore[call-non-callable]  # defined by the exec above


def test_the_warning_points_at_the_callers_line() -> None:
    def shim() -> None:
        warn_external("old()", "new()")

    with pytest.warns(DeprecationWarning) as caught:
        shim()
    assert caught[0].filename == __file__


def test_the_command_line_runs_on_the_shims_without_a_warning(tide_corpus_repo: Path) -> None:
    """The CLI's services call ``ValidationScope``, ``run_validation`` and the writers."""
    from opentide.cli.services.document import run_document_all
    from opentide.cli.services.validation import run_uuid_format

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert run_uuid_format().ok
        run_document_all(output="docs")
