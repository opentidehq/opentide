"""``opentide.analysis``: the one door to the compiled engine (#332)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.test_cli.e2e.helpers import hidden_modules

from opentide import analysis
from opentide.analysis import (
    EngineUnavailableError,
    Finding,
    check_queries,
    check_query,
    describe,
    engine,
    engine_codes,
    engine_versions,
    install_workspace_catalog,
    language_for_path,
    reset_catalog,
)
from opentide.generation.lsp_catalog import CATALOG_DIR

TWO_PLATFORMS = """\
name: Two Platforms
metadata:
  uuid: 00000000-0000-4000-8003-000000000001
  schema: rule::1.0
configurations:
  sentinel:
    query: |
      SecurityEvent
      | where EventID == 4688
  splunk:
    query: |
      index=main | statz count
  crowdstrike:
    query: |
      anything at all
"""


@pytest.fixture
def no_engine() -> Iterator[None]:
    engine.cache_clear()
    with hidden_modules("opentide_analysis", purge=("opentide_analysis",)):
        yield
    engine.cache_clear()


@pytest.fixture
def bundled_catalog() -> Iterator[None]:
    """The catalog install is process-wide: leave the bundled one behind."""
    yield
    reset_catalog()


def test_the_engine_loads_and_names_its_versions() -> None:
    versions = engine_versions()
    assert set(versions) == {"package", "engine"}
    assert all(versions.values())
    assert "kql_parse_error" in engine_codes()
    assert describe("kql_parse_error") == "The KQL query does not parse."
    assert describe("vocab_unknown_not_a_code") is None


def test_a_missing_engine_is_an_error_with_the_reinstall_step(no_engine: None) -> None:
    with pytest.raises(EngineUnavailableError) as raised:
        engine()
    assert raised.value.code == "engine_unavailable"
    assert raised.value.advice == "reinstall opentide: pip install --force-reinstall opentide"
    assert str(raised.value).startswith("The opentide analysis engine does not load: ")
    # Explaining a code never needs the engine to load.
    assert describe("kql_parse_error") is None
    assert engine_codes() == ()


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("error", "error"), ("warning", "warning"), ("information", "note"), ("hint", "note")],
)
def test_engine_severities_become_the_cli_ones(severity: str, expected: str) -> None:
    raw = SimpleNamespace(
        code="x",
        severity=severity,
        message="m",
        line=2,
        column=3,
        end_line=4,
        end_column=1,
        field_path=None,
        suggestion=None,
    )
    finding = Finding.from_engine(raw)  # a stand-in for the compiled class
    assert finding.severity == expected
    assert finding.field_path == ()
    # A finding across lines is framed on its first line.
    assert finding.single_line_end == 4


def test_every_query_of_a_file_is_checked_and_platforms_filter_them(tmp_path: Path) -> None:
    rule = tmp_path / "two-platforms.yaml"
    rule.write_text(TWO_PLATFORMS, encoding="utf-8")
    checks = check_queries([rule], root=tmp_path).checks
    assert [(check.platform, check.language) for check in checks] == [
        ("sentinel", "kql"),
        ("splunk", "spl"),
    ], "CrowdStrike is never validated, so it is never a query here"
    sentinel, splunk = checks
    assert sentinel.findings == () and sentinel.errors == 0
    assert splunk.errors == 1
    (finding,) = splunk.findings
    assert finding.code == "spl_unknown_command"
    assert TWO_PLATFORMS.splitlines()[finding.line - 1][finding.column - 1 :].startswith("statz")
    only = check_queries([rule], root=tmp_path, platforms=["splunk"]).checks
    assert [check.platform for check in only] == ["splunk"]


def test_a_file_that_cannot_be_read_is_reported_not_skipped(tmp_path: Path) -> None:
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"name: \xff\xfe\n")
    broken = tmp_path / "broken.yaml"
    broken.write_text("name: [unclosed\n", encoding="utf-8")
    run = check_queries([binary, broken, tmp_path / "missing.yaml"], root=tmp_path)
    assert run.checks == []
    problems = {item.file_path.name: item for item in run.unreadable}
    assert problems["binary.yaml"].problem.startswith("the file is not UTF-8 text")
    assert problems["broken.yaml"].line == 2
    assert set(problems) == {"binary.yaml", "broken.yaml", "missing.yaml"}


def test_a_query_on_its_own_takes_its_platform_profile() -> None:
    query = "DeviceProcessEvents | take 1"
    assert check_query(query, language="kql", platform="defender_for_endpoint") == []
    assert [f.code for f in check_query(query, language="kql", platform="sentinel")] == [
        "kql_unknown_table"
    ]


@pytest.fixture
def no_own_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    """opentide cannot generate its catalog: the committed one, then the bundled one."""

    def fail(root: Path | None) -> dict[str, str]:
        raise RuntimeError("no registry")

    monkeypatch.setattr(analysis, "own_catalog", fail)


def test_opentides_own_catalog_comes_first_and_is_cached(
    tmp_path: Path, bundled_catalog: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#677: the engine checks objects with what this opentide generates, not a
    committed copy that may be from an older opentide."""
    import opentide
    from opentide.generation import lsp_catalog

    catalogs = tmp_path / CATALOG_DIR
    catalogs.mkdir(parents=True)
    stale = {"opentide": "0.0.1", "fields": [{"schema": "rule", "path": "name", "name": "name"}]}
    (catalogs / "fields.json").write_text(json.dumps(stale), encoding="utf-8")
    monkeypatch.setenv("OPENTIDE_CACHE_DIR", str(tmp_path / "cache"))
    state = install_workspace_catalog(tmp_path)
    assert (state.source, state.version, state.problem) == ("opentide", opentide.__version__, None)
    assert state.files == ("fields.json",)
    [cached] = (tmp_path / "cache" / "lsp-catalogs").iterdir()
    assert sorted(path.name for path in cached.iterdir()) == ["deprecations.json", "fields.json"]

    # Cached: the next install generates nothing.
    def no_generation() -> dict[str, str]:
        raise AssertionError("generated again")

    monkeypatch.setattr(lsp_catalog, "catalog_texts", no_generation)
    assert install_workspace_catalog(tmp_path).source == "opentide"
    # The workspace's configuration is part of the key: a change regenerates.
    configuration = tmp_path / ".opentide" / "configurations"
    configuration.mkdir(parents=True)
    (configuration / "visibility.toml").write_text("# changed\n", encoding="utf-8")
    state = install_workspace_catalog(tmp_path)
    assert state.source == "workspace"
    assert state.problem is not None and "generated again" in state.problem


def test_an_unwritable_cache_still_gives_the_catalog(
    tmp_path: Path, bundled_catalog: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    blocker = tmp_path / "cache"
    blocker.write_text("a file where the cache folder would be", encoding="utf-8")
    monkeypatch.setenv("OPENTIDE_CACHE_DIR", str(blocker))
    assert install_workspace_catalog(tmp_path).source == "opentide"


def test_the_workspace_catalog_is_used_when_it_parses(
    tmp_path: Path, bundled_catalog: None, no_own_catalog: None
) -> None:
    state = install_workspace_catalog(tmp_path)
    assert (state.source, state.files) == ("bundled", ())
    assert state.problem == "opentide's catalog could not be generated: RuntimeError: no registry"
    assert state.path == tmp_path / CATALOG_DIR

    catalogs = tmp_path / CATALOG_DIR
    catalogs.mkdir(parents=True)
    fields = {
        "opentide": "9.9.9",
        "fields": [{"schema": "rule", "path": "name", "name": "name", "type": "string"}],
    }
    (catalogs / "fields.json").write_text(json.dumps(fields), encoding="utf-8")
    state = install_workspace_catalog(tmp_path)
    assert (state.source, state.version, state.files) == ("workspace", "9.9.9", ("fields.json",))
    assert state.to_dict()["opentide"] == "9.9.9"

    (catalogs / "deprecations.json").write_text("not json", encoding="utf-8")
    state = install_workspace_catalog(tmp_path)
    assert state.source == "bundled"
    assert state.problem is not None and "; deprecations.json" in state.problem


def test_file_names_imply_their_language() -> None:
    assert language_for_path("objects/rules/a.yaml") == "opentide-yaml"
    assert language_for_path(Path("hunt.esql")) == "esql"
    assert language_for_path("notes.txt") is None


def test_the_module_imports_nothing_compiled() -> None:
    """``opentide --help`` and completion must never load the engine."""
    source = Path(analysis.__file__).read_text(encoding="utf-8")
    module_level = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
    assert not [line for line in module_level if "opentide_analysis" in line]


def test_deprecations_alone_are_a_workspace_catalog(
    tmp_path: Path, bundled_catalog: None, no_own_catalog: None
) -> None:
    catalogs = tmp_path / CATALOG_DIR
    catalogs.mkdir(parents=True)
    (catalogs / "deprecations.json").write_text(json.dumps({"fields": []}), encoding="utf-8")
    state = install_workspace_catalog(tmp_path)
    assert (state.source, state.files) == ("workspace", ("deprecations.json",))


def test_highlight_tokens_are_in_cli_coordinates() -> None:
    from opentide.analysis import highlight

    tokens = highlight('SecurityEvent | where x == "🔥" // done', "kql")
    by_capture = {token.capture: token for token in tokens}
    assert (by_capture["type"].column, by_capture["type"].end_column) == (1, 14)
    assert (by_capture["string"].column, by_capture["string"].end_column) == (28, 31)
    assert by_capture["comment"].column == 32


REVISION_RULE = """\
name: Revision Rule
metadata:
  uuid: 00000000-0000-4000-8003-000000000002
  schema: rule::1.1
  version: 1
  created: 2026-01-01
  modified: 2026-01-02
  tlp: clear
  author: Someone
description: |
  test
response:
  alert_severity: High
configurations:
  splunk:
    status: DESIGN
    query: index=main
"""


def _shape(tmp_path: Path, text: str) -> list[tuple[str, tuple[str, ...], int]]:
    from opentide.analysis import check_file, workspace

    path = tmp_path / "objects" / "rules" / "revision-rule.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return [
        (finding.message, finding.field_path, finding.line)
        for finding in check_file(workspace(tmp_path, [path]), path, text)
        if finding.code == "schema_validation"
    ]


def test_the_language_server_checks_the_revision_an_object_names(
    tmp_path: Path, bundled_catalog: None
) -> None:
    """#676: what validate reports, the language server reports, with this
    opentide's catalog: a rule::1.1 without description, a rule::1.0 carrying
    the 1.1-only metadata.reviewed."""
    assert install_workspace_catalog(tmp_path).source == "opentide"
    assert _shape(tmp_path, REVISION_RULE) == []
    assert _shape(tmp_path, REVISION_RULE.replace("description: |\n  test\n", "")) == [
        ("missing required field 'description'", ("description",), 1)
    ]
    older = REVISION_RULE.replace("rule::1.1", "rule::1.0").replace(
        "  author: Someone\n", "  author: Someone\n  reviewed: 2026-01-03\n"
    )
    assert _shape(tmp_path, older) == [
        ("field 'metadata.reviewed' is not defined in rule::1.0", ("metadata", "reviewed"), 10)
    ]
    assert _shape(tmp_path, older.replace("rule::1.0", "rule::1.1")) == []
    # A splunk::2.x spelling validates, so it is no finding either.
    legacy = REVISION_RULE.replace("    query: index=main\n", "    search: index=main\n")
    assert _shape(tmp_path, legacy) == []
