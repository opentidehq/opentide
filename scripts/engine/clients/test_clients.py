"""opentide-lsp as real editors see it (#185 P2.8).

pytest-lsp starts the server (``OPENTIDE_LSP_BIN``, else the debug build)
with the capabilities each editor records, and checks every response the
server sends against them: a Markdown hover for a plain-text client, a
pushed diagnostic for a client that pulls, and the like fail here.
"""

from __future__ import annotations

import os
import pathlib

import pytest
import pytest_lsp
from lsprotocol import types
from pytest_lsp import ClientServerConfig, LanguageClient, client_capabilities

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = os.environ.get("OPENTIDE_LSP_BIN", str(ROOT / "target" / "debug" / "opentide-lsp"))
CLIENTS = ["visual_studio_code", "neovim", "emacs"]
URI = "file:///tmp/opentide-clients/typo.kql"
TEXT = "SecurityEvent | wher EventID == 4688\n"


@pytest_lsp.fixture(params=CLIENTS, config=ClientServerConfig(server_command=[BIN, "--stdio"]))
async def client(request, lsp_client: LanguageClient):
    # What an editor answers to the server's requests pytest-lsp does not
    # already handle.
    for method in (
        types.CLIENT_REGISTER_CAPABILITY,
        types.WORKSPACE_SEMANTIC_TOKENS_REFRESH,
        types.WORKSPACE_INLAY_HINT_REFRESH,
        types.WORKSPACE_CODE_LENS_REFRESH,
    ):
        if method not in lsp_client.protocol.fm.features:
            lsp_client.feature(method)(lambda params: None)
    capabilities = client_capabilities(request.param)
    result = await lsp_client.initialize_session(
        types.InitializeParams(capabilities=capabilities, root_uri=ROOT.as_uri())
    )
    lsp_client.server_capabilities = result.capabilities
    lsp_client.pulls = result.capabilities.diagnostic_provider is not None
    yield
    await lsp_client.shutdown_session()


def _open(client: LanguageClient) -> None:
    client.text_document_did_open(
        types.DidOpenTextDocumentParams(
            text_document=types.TextDocumentItem(uri=URI, language_id="kql", version=1, text=TEXT)
        )
    )


async def test_initialize_reports_utf16_and_who_runs_the_server(client: LanguageClient):
    caps = client.server_capabilities
    assert caps.position_encoding == types.PositionEncodingKind.Utf16
    assert caps.experimental["opentide"]["engine"]


async def test_diagnostics_are_pulled_or_pushed_never_both(client: LanguageClient):
    _open(client)
    if client.pulls:
        report = await client.text_document_diagnostic_async(
            types.DocumentDiagnosticParams(text_document=types.TextDocumentIdentifier(uri=URI))
        )
        assert [d.code for d in report.items] == ["kql_unknown_operator"]
        assert URI not in client.diagnostics
    else:
        await client.wait_for_notification(types.TEXT_DOCUMENT_PUBLISH_DIAGNOSTICS)
        assert [d.code for d in client.diagnostics[URI]] == ["kql_unknown_operator"]


async def test_hover_and_completion_follow_the_client(client: LanguageClient):
    _open(client)
    hover = await client.text_document_hover_async(
        types.HoverParams(
            text_document=types.TextDocumentIdentifier(uri=URI),
            position=types.Position(line=0, character=3),
        )
    )
    assert hover is not None
    items = await client.text_document_completion_async(
        types.CompletionParams(
            text_document=types.TextDocumentIdentifier(uri=URI),
            position=types.Position(line=0, character=16),
        )
    )
    assert items


async def test_quick_fix_names_its_diagnostic(client: LanguageClient):
    _open(client)
    actions = await client.text_document_code_action_async(
        types.CodeActionParams(
            text_document=types.TextDocumentIdentifier(uri=URI),
            range=types.Range(start=types.Position(0, 0), end=types.Position(0, 30)),
            context=types.CodeActionContext(diagnostics=[]),
        )
    )
    fix = next(a for a in actions if a.title == "Apply suggestion: where")
    assert fix.is_preferred
    assert fix.diagnostics and fix.diagnostics[0].code == "kql_unknown_operator"


@pytest.mark.parametrize("unused", [None])
def test_the_server_binary_exists(unused):
    assert pathlib.Path(BIN).exists(), f"build it first: {BIN}"
