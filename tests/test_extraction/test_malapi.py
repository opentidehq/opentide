"""Tests for MalAPI vocabulary extraction."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

import pytest


def _detail_html() -> str:
    return "<html>detail</html>"


def _main_page_html() -> str:
    return "<html>main</html>"


class _FakeTag:
    def __init__(
        self,
        text: str = "",
        attrs: dict | None = None,
        children: list | None = None,
        tag_name: str = "div",
    ):
        self.text = text
        self.attrs = attrs or {}
        self._children = children or []
        self.tag_name = tag_name

    def find(self, name=None, attrs=None):
        attrs = attrs or {}
        for child in self._children:
            if (
                name
                and child.tag_name == name
                and (not attrs or all(child.attrs.get(k) == v for k, v in attrs.items()))
            ):
                return child
            if attrs.get("class") and child.attrs.get("class") == attrs.get("class"):
                return child
        return None

    def find_all(self, name=None, attrs=None):
        attrs = dict(attrs or {})
        if name == "div" and attrs.get("class") == "detail-container":
            return [
                _FakeTag(
                    children=[
                        _FakeTag("Function Name", {"class": "heading"}),
                        _FakeTag("CreateFileW", {"class": "content"}),
                    ]
                ),
                _FakeTag(
                    children=[
                        _FakeTag("Description", {"class": "heading"}),
                        _FakeTag("Creates or opens a file.", {"class": "content"}),
                    ]
                ),
                _FakeTag(
                    children=[
                        _FakeTag("Library", {"class": "heading"}),
                        _FakeTag("kernel32.dll", {"class": "content"}),
                    ]
                ),
                _FakeTag(
                    children=[
                        _FakeTag("Associated Attacks", {"class": "heading"}),
                        _FakeTag("Injection", {"class": "content"}),
                    ]
                ),
                _FakeTag(
                    children=[
                        _FakeTag("Documentation", {"class": "heading"}),
                        _FakeTag("https://docs.example.com", {"class": "content"}),
                    ]
                ),
            ]
        matches: list[_FakeTag] = []
        for child in self._children:
            if name and child.tag_name == name:
                matches.append(child)
            matches.extend(child.find_all(name, attrs))
        return matches

    def __getitem__(self, key):
        return self.attrs[key]


def _main_table() -> _FakeTag:
    img = _FakeTag("", {"title": "Injection attacks"}, tag_name="img")
    th = _FakeTag("Injection", children=[img], tag_name="th")
    header_row = _FakeTag(children=[th], tag_name="tr")
    link = _FakeTag("CreateFileW", tag_name="a")
    tbody = _FakeTag(children=[link], tag_name="tbody")
    data_row = _FakeTag(children=[tbody], tag_name="tr")
    return _FakeTag(children=[header_row, data_row], tag_name="table")


class _FakeSoup:
    def __init__(self, html: str, parser: str = "html.parser"):
        self.html = html

    def find(self, name, attrs=None, **kwargs):
        attrs = dict(attrs or {})
        if "id" in kwargs:
            attrs["id"] = kwargs["id"]
        if name == "table" and attrs.get("id") == "main-table":
            return _main_table()
        return None

    def find_all(self, name, attrs=None):
        return _main_table().find_all(name, attrs)


@pytest.fixture(scope="module")
def malapi_module(tmp_path_factory):
    """Import malapi once with network and filesystem mocked."""
    tmp_path = tmp_path_factory.mktemp("malapi")
    export_path = tmp_path / "malapi.vocab.toml"

    responses = {
        "https://malapi.io": MagicMock(text=_main_page_html()),
        "https://malapi.io/winapi/CreateFileW": MagicMock(text=_detail_html()),
    }

    requests_mod = types.ModuleType("requests")
    requests_mod.get = lambda url, timeout=30: responses[url]
    sys.modules["requests"] = requests_mod

    bs4_mod = types.ModuleType("bs4")
    bs4_mod.BeautifulSoup = _FakeSoup
    sys.modules["bs4"] = bs4_mod

    mock_opentide = MagicMock()
    mock_configs = MagicMock()
    mock_configs.Global.Paths.Core.vocabularies = str(tmp_path)
    mock_opentide.Configurations = mock_configs

    with patch.dict("sys.modules", {"opentide.core.registry": MagicMock(OpenTide=mock_opentide)}):
        import opentide.extraction.malapi as malapi

        malapi.VOCAB_FILE_PATH = export_path
        yield malapi


def test_fetch_win_api_details_parses_fields(malapi_module) -> None:
    details = malapi_module.fetch_win_api_details("CreateFileW")
    assert details["name"] == "CreateFileW"
    assert "Creates or opens a file" in details["description"]
    assert "kernel32.dll" in details["description"]
    assert details["tide.vocab.stages"] == "Injection"
    assert details["link"] == "https://docs.example.com"


def test_fetch_win_api_details_empty_raises(malapi_module) -> None:
    class _EmptySoup:
        def find_all(self, *args, **kwargs):
            return []

    with (
        patch("requests.get", return_value=MagicMock(text="<html></html>")),
        patch.object(malapi_module, "BeautifulSoup", return_value=_EmptySoup()),
        pytest.raises(ValueError, match="Empty parsed API"),
    ):
        malapi_module.fetch_win_api_details("MissingApi")


def test_module_builds_vocab_content(malapi_module) -> None:
    assert len(malapi_module.malapi_content) >= 1
    assert malapi_module.vocab_content["field"] == "malapi"
    assert malapi_module.vocab_content["keys"][0]["name"] == "CreateFileW"
