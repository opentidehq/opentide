"""The Exabeam Query Language in the analysis engine (exabeam-1.0 language spec).

opentide hands every Exabeam query to the engine as language ``exabeam``. The
pinned engine (opentide-analysis 0.13.0) predates the language: until the pin
moves, a check of an Exabeam query fails as an unavailable engine, never as a
pass. The tests that need the language itself skip on such an engine.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from opentide import analysis
from opentide.analysis import (
    EngineLanguageUnavailableError,
    EngineUnavailableError,
    check_query,
    check_query_file,
    is_query_file,
    query_file_language,
)
from opentide.validation.query_platforms import OFFLINE_QUERY_LANGUAGES

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "exabeam"


def _engine_knows_exabeam() -> bool:
    try:
        analysis.engine().analyze_query('activity_type:"x"', "exabeam")
    except ValueError:
        return False
    return True


needs_the_language = pytest.mark.skipif(
    not _engine_knows_exabeam(),
    reason=(
        "the pinned engine (opentide-analysis/opentide-lsp 0.13.0) predates the exabeam "
        "language; pending the engine pin that ships it (language-server)"
    ),
)


def _engine(error: str) -> SimpleNamespace:
    def analyze_query(text: str, language: str, **_: object) -> list[object]:
        raise ValueError(error.format(language=language))

    return SimpleNamespace(analyze_query=analyze_query, language_for_path=lambda path: None)


def test_exabeam_is_checked_offline_in_its_own_language() -> None:
    assert OFFLINE_QUERY_LANGUAGES["exabeam"] == ("exabeam",)


def test_an_engine_without_the_language_is_an_unavailable_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analysis, "engine", lambda: _engine('unknown language "{language}"'))
    with pytest.raises(EngineLanguageUnavailableError) as caught:
        check_query('activity_type:"x"', language="exabeam", platform="exabeam")
    error = caught.value
    assert isinstance(error, EngineUnavailableError)
    assert error.code == "engine_unavailable"
    assert error.language == "exabeam"
    assert str(error).startswith("The opentide analysis engine does not check exabeam queries")
    assert "upgrade opentide" in error.advice


def test_another_engine_error_is_not_read_as_a_missing_language(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(analysis, "engine", lambda: _engine("bad stack {language}"))
    with pytest.raises(ValueError, match="bad stack") as caught:
        check_query("x", language="exabeam")
    assert not isinstance(caught.value, EngineUnavailableError)
    monkeypatch.setattr(analysis, "engine", lambda: _engine('unknown language "{language}"'))
    with pytest.raises(ValueError) as unknown:
        check_query("x", language="cobol")
    assert not isinstance(unknown.value, EngineUnavailableError)


def test_an_exabeam_query_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "hunt.EXABEAM"
    path.write_text('activity_type:"app-login"\n', encoding="utf-8")
    assert is_query_file(path)
    assert query_file_language(path) == "exabeam"
    monkeypatch.setattr(analysis, "engine", lambda: _engine('unknown language "{language}"'))
    with pytest.raises(EngineLanguageUnavailableError):
        check_query_file(path, platform="exabeam")


@needs_the_language
def test_the_engine_refuses_the_advanced_form_in_a_sequence() -> None:
    findings = check_query(
        'SELECT user, COUNT(*) AS logins WHERE activity_type:"app-login" GROUP-BY user',
        language="exabeam",
        platform="exabeam",
    )
    assert "exabeam_advanced_in_rule" in {finding.code for finding in findings}


@needs_the_language
def test_the_engine_accepts_the_specification_sequences() -> None:
    import yaml

    for name in ("rule-exabeam-threshold-1.0.yaml", "rule-exabeam-sequence-1.0.yaml"):
        document = yaml.safe_load((FIXTURES / name).read_text(encoding="utf-8"))
        for sequence in document["configurations"]["exabeam"]["sequences"]:
            findings = check_query(sequence["query"], language="exabeam", platform="exabeam")
            assert [f.code for f in findings if f.severity == "error"] == []
