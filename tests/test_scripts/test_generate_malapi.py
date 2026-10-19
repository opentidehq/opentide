"""Tests for the MalAPI vocabulary scraper maintainer script.

The script needs BeautifulSoup, which opentide does not depend on, so these
tests stand in a tiny ``bs4`` that serves pre-built trees keyed by URL.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import requests

from opentide.vocabulary.io import read_vocab_document, write_vocab_file

_MODULE = Path(__file__).resolve().parents[2] / "scripts" / "vocabulary" / "generate_malapi.py"


class _Tag:
    def __init__(
        self,
        name: str,
        text: str = "",
        attrs: dict[str, str] | None = None,
        children: tuple[_Tag, ...] = (),
    ) -> None:
        self.name = name
        self.text = text
        self.attrs = attrs or {}
        self.children = children

    def find_all(self, name: str, attrs: dict[str, str] | None = None, **kwargs: str) -> list[_Tag]:
        wanted = {**(attrs or {}), **kwargs}
        found: list[_Tag] = []
        for child in self.children:
            if child.name == name and all(child.attrs.get(k) == v for k, v in wanted.items()):
                found.append(child)
            found.extend(child.find_all(name, attrs, **kwargs))
        return found

    def find(self, name: str, attrs: dict[str, str] | None = None, **kwargs: str) -> _Tag | None:
        found = self.find_all(name, attrs, **kwargs)
        return found[0] if found else None

    def __getitem__(self, key: str) -> str:
        return self.attrs[key]


def _detail(heading: str, content: str) -> _Tag:
    return _Tag(
        "div",
        attrs={"class": "detail-container"},
        children=(
            _Tag("div", f"\n  {heading}\n", {"class": "heading"}),
            _Tag("div", f"\n  {content}\n", {"class": "content"}),
        ),
    )


def _main_page() -> _Tag:
    headers = _Tag(
        "tr",
        children=tuple(
            _Tag("th", f" {stage} ", children=(_Tag("img", attrs={"title": f" {stage} APIs "}),))
            for stage in ("Enumeration", "Anti-Debugging")
        ),
    )
    apis = _Tag(
        "tr",
        children=(
            _Tag("tbody", children=(_Tag("a", " GetDriveTypeA "), _Tag("a", "IsDebuggerPresent"))),
            _Tag("tbody", children=(_Tag("a", "GetDriveTypeA"),)),
        ),
    )
    table = _Tag("table", attrs={"id": "main-table"}, children=(headers, apis))
    return _Tag("html", children=(table,))


_PAGES = {
    "https://malapi.io": _main_page(),
    "https://malapi.io/winapi/GetDriveTypeA": _Tag(
        "html",
        children=(
            _detail("Function Name", "GetDriveTypeA"),
            _detail("Description", "GetDriveTypeA is used to identify a drive."),
            _detail("Library", "Kernel32.dll"),
            _detail("Associated Attacks", "Enumeration\n\n      Anti-Debugging"),
            _detail("Documentation", "https://learn.microsoft.com/getdrivetypea"),
            _Tag("div", attrs={"class": "detail-container"}, children=(_Tag("div", "Credits"),)),
        ),
    ),
    "https://malapi.io/winapi/IsDebuggerPresent": _Tag(
        "html",
        children=(
            _detail("Function Name", "IsDebuggerPresent"),
            _detail("Description", "IsDebuggerPresent checks for a debugger."),
            _detail("Associated Attacks", "Anti-Debugging"),
            _detail("Documentation", "https://learn.microsoft.com/isdebuggerpresent"),
        ),
    ),
    "https://malapi.io/winapi/Missing": _Tag("html"),
}


class _Response:
    def __init__(self, url: str) -> None:
        self.text = url

    def raise_for_status(self) -> None:
        return None


class _Session:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def get(self, url: str, timeout: float) -> _Response:
        self.urls.append(url)
        return _Response(url)


class _DroppingSession(_Session):
    """Fails on IsDebuggerPresent, the second of the two APIs."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def get(self, url: str, timeout: float) -> _Response:
        if url.endswith("/IsDebuggerPresent"):
            raise self.error
        return super().get(url, timeout)


@pytest.fixture
def malapi(monkeypatch: pytest.MonkeyPatch) -> Any:
    bs4 = types.ModuleType("bs4")
    bs4.BeautifulSoup = lambda html, parser: _PAGES[html]
    monkeypatch.setitem(sys.modules, "bs4", bs4)
    spec = importlib.util.spec_from_file_location("generate_malapi", _MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # #539: the old in-package module scraped the site as a side effect of import.
    with patch("requests.Session.request", side_effect=AssertionError("network at import")):
        spec.loader.exec_module(module)
    return module


def test_fetch_stages_and_apis_reads_front_page(malapi: Any) -> None:
    stages, apis = malapi.fetch_stages_and_apis(_Session())

    assert stages == [
        {"name": "Enumeration", "description": "Enumeration APIs"},
        {"name": "Anti-Debugging", "description": "Anti-Debugging APIs"},
    ]
    assert apis == ["GetDriveTypeA", "IsDebuggerPresent"]


def test_fetch_win_api_details_matches_canonical_key_shape(malapi: Any) -> None:
    session = _Session()

    details = malapi.fetch_win_api_details(session, "GetDriveTypeA")

    assert session.urls == ["https://malapi.io/winapi/GetDriveTypeA"]
    assert list(details) == ["name", "description", "link", "tide.vocab.stages"]
    assert details["description"] == (
        "GetDriveTypeA is used to identify a drive.\nLibrary : `Kernel32.dll`"
    )
    assert details["tide.vocab.stages"] == ["Enumeration", "Anti-Debugging"]


def test_fetch_win_api_details_keeps_single_stage_as_string(malapi: Any) -> None:
    details = malapi.fetch_win_api_details(_Session(), "IsDebuggerPresent")

    assert details["tide.vocab.stages"] == "Anti-Debugging"
    assert details["description"] == "IsDebuggerPresent checks for a debugger."


def test_fetch_win_api_details_empty_raises(malapi: Any) -> None:
    with pytest.raises(ValueError, match="Empty parsed API: Missing"):
        malapi.fetch_win_api_details(_Session(), "Missing")


def test_build_document_keeps_versions_and_header(malapi: Any) -> None:
    existing = {
        "name": "Malicious Window API",
        "field": "malapi",
        "key": "name",
        "stages": [{"name": "Old", "description": "Old stage"}],
        "keys": [
            {"version": "1.0", "name": "Kept", "description": "old", "link": "l"},
            {"version": "1.0", "name": "Gone", "description": "gone", "link": "l"},
        ],
    }
    stages = [{"name": "Enumeration", "description": "Enumeration APIs"}]
    scraped = [
        {"name": "Kept", "description": "new", "link": "l", "tide.vocab.stages": "Enumeration"},
        {"name": "Added", "description": "added", "link": "l", "tide.vocab.stages": "Helper"},
    ]

    document = malapi.build_document(existing, stages, scraped)

    assert {k: document[k] for k in ("name", "field", "key")} == {
        "name": "Malicious Window API",
        "field": "malapi",
        "key": "name",
    }
    assert document["stages"] == stages
    keys = {key["name"]: key for key in document["keys"]}
    assert keys["Kept"]["version"] == "1.0"
    assert keys["Kept"]["description"] == "new"
    assert keys["Added"]["version"] == "1.1"
    assert keys["Gone"]["removed"] == "2.0"
    assert all(next(iter(key)) == "version" for key in document["keys"])
    assert existing["stages"] == [{"name": "Old", "description": "Old stage"}]


def test_build_document_carries_unfetched_keys_over(malapi: Any) -> None:
    existing = {
        "name": "Malicious Window API",
        "field": "malapi",
        "key": "name",
        "keys": [
            {"version": "1.0", "name": "Unreached", "description": "old", "link": "l"},
            {"version": "1.0", "name": "Gone", "description": "gone", "link": "l"},
            {"version": "1.0", "name": "Dead", "description": "d", "link": "l", "removed": "2.0"},
        ],
    }

    document = malapi.build_document(existing, [], [], unfetched=["Unreached", "Dead"])

    keys = {key["name"]: key for key in document["keys"]}
    assert keys["Unreached"] == existing["keys"][0]
    assert keys["Gone"]["removed"] == "2.0"
    assert keys["Dead"] == existing["keys"][2]


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.RetryError("too many 429 error responses"),
        requests.exceptions.ConnectionError("connection reset by peer"),
    ],
)
def test_main_writes_partial_scrape_when_the_site_gives_up(
    malapi: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    output_path = tmp_path / "vocabularies" / "malapi.vocab.toml"
    output_path.parent.mkdir()
    unreached = {
        "version": "1.0",
        "name": "IsDebuggerPresent",
        "description": "old",
        "link": "l",
        "tide.vocab.stages": "Anti-Debugging",
    }
    write_vocab_file(
        output_path,
        {
            "name": "Malicious Window API",
            "field": "malapi",
            "key": "name",
            "keys": [
                {"version": "1.0", "name": "GetDriveTypeA", "description": "old", "link": "l"},
                unreached,
            ],
        },
    )
    synced: list[Path] = []
    monkeypatch.setattr(sys, "argv", ["generate_malapi.py"])
    monkeypatch.setattr(malapi, "PAUSE_SECONDS", 0)
    monkeypatch.setattr(malapi, "_specifications_root", lambda: tmp_path)
    monkeypatch.setattr(malapi, "_session", lambda: _DroppingSession(error))
    monkeypatch.setattr(malapi, "_sync_bundled_vocabularies", synced.append)

    assert malapi.main() == 1

    keys = {key["name"]: key for key in read_vocab_document(output_path)["keys"]}
    assert keys["GetDriveTypeA"]["description"].startswith("GetDriveTypeA is used")
    assert keys["IsDebuggerPresent"] == unreached
    assert synced == []
    assert "1 of 2 APIs not fetched" in capsys.readouterr().err
