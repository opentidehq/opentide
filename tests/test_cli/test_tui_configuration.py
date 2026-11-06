"""#776: the Configuration tab, and the rule that no credential value appears in any view.

Synthetic fixtures only: the tutorial repository, with a Sentinel tenant whose
``setup`` holds a literal secret, a ``$VAR`` reference that is set, and one
that is not.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console
from tests.test_cli.test_tui import RULE, tutorial_repo  # noqa: F401 -- the fixture
from textual.widgets import DataTable, Static, TabbedContent
from textual.worker import WorkerFailed

from opentide.cli.context import CliContext
from opentide.cli.services.configuration_view import HIDDEN, load_configuration_view, redact_toml
from opentide.cli.services.tui import load_catalogue
from opentide.cli.tui_app import OpentideTui
from opentide.cli.tui_tabs.configuration import file_view, platform_card

#: A literal credential in the file. It must never be shown.
LITERAL = "s3cr3t-literal-do-not-show"
#: The value of a variable a tenant names. It must never be shown either.
VALUE = "value-of-the-variable-do-not-show"

TENANT = f"""
[[tenants]]
name = "Production"
description = "Synthetic tenant"
strategies = ["PREVIEW", "RELEASE"]

[tenants.setup]
ssl = true
workspace_id = "$OPENTIDE_TEST_WORKSPACE_ID"
azure_client_id = "${{OPENTIDE_TEST_UNSET_CLIENT_ID}}"
azure_client_secret = "{LITERAL}"
proxy_url = "https://user:{LITERAL}@proxy.example"

[[tenants]]
name = "Manual"
strategies = ["RELEASE"]
manual = true
setup = {{ azure_client_secret = "{LITERAL}" }}
"""


@pytest.fixture
def configured_repo(
    tutorial_repo: Path,  # noqa: F811 -- the fixture
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[Path]:
    config = tutorial_repo / ".opentide" / "configurations" / "platforms" / "sentinel.toml"
    config.write_text(config.read_text(encoding="utf-8") + TENANT, encoding="utf-8")
    lint = tutorial_repo / ".opentide" / "configurations" / "lint.toml"
    lint.write_text('[metadata]\nrequired = ["author"]\n', encoding="utf-8")
    monkeypatch.setenv("OPENTIDE_TEST_WORKSPACE_ID", VALUE)
    monkeypatch.delenv("OPENTIDE_TEST_UNSET_CLIENT_ID", raising=False)
    yield tutorial_repo


def _plain(renderable: Any) -> str:
    buffer = io.StringIO()
    Console(width=200, file=buffer).print(renderable)
    return buffer.getvalue()


def _no_secret(text: str) -> None:
    assert LITERAL not in text
    assert VALUE not in text


def test_the_view_reads_settings_and_never_holds_a_credential(configured_repo: Path) -> None:
    catalogue = load_catalogue(CliContext(repo=configured_repo))
    view = catalogue.configuration
    assert view is not None and view.problem is None
    # Nothing the view holds carries a credential, in any field.
    _no_secret(repr(view))
    sentinel = next(item for item in view.files if item.key == "platforms/sentinel.toml")
    settings = {s.path: s for s in sentinel.settings}
    secret = settings["tenants.0.setup.azure_client_secret"]
    assert secret.secret and secret.shown == HIDDEN and secret.variable is None
    workspace = settings["tenants.0.setup.workspace_id"]
    assert (workspace.variable, workspace.variable_set) == ("OPENTIDE_TEST_WORKSPACE_ID", True)
    unset = settings["tenants.0.setup.azure_client_id"]
    assert (unset.variable, unset.variable_set) == ("OPENTIDE_TEST_UNSET_CLIENT_ID", False)
    assert settings["tenants.1.setup.azure_client_secret"].shown == HIDDEN
    assert settings["tenants.0.name"].shown == "Production"
    assert settings["tenants.0.name"].set_here
    # The raw view is redacted too.
    assert sentinel.raw is not None
    _no_secret(sentinel.raw)
    assert '"${OPENTIDE_TEST_UNSET_CLIENT_ID}"  # unset' in sentinel.raw
    # lint.toml: the workspace sets metadata.required; the rest are defaults, each explained.
    lint = next(item for item in view.files if item.key == "lint.toml")
    lint_settings = {s.path: s for s in lint.settings}
    assert lint_settings["metadata.required"].set_here
    assert lint_settings["metadata.required"].shown == "author"
    style = lint_settings["filenames.style"]
    assert not style.set_here
    assert "stem" in style.description


def test_platform_cards_list_tenants_credentials_and_the_rules_that_reach_them(
    configured_repo: Path,
) -> None:
    catalogue = load_catalogue(CliContext(repo=configured_repo))
    assert catalogue.configuration is not None
    [card] = [c for c in catalogue.configuration.platforms if c.platform == "sentinel"]
    assert card.enabled
    production, manual = card.tenants
    assert production.strategies == ("PREVIEW", "RELEASE")
    credentials = {c.key: c for c in production.credentials}
    assert credentials["azure_client_secret"].variable is None
    assert credentials["workspace_id"].is_set is True
    assert credentials["azure_client_id"].is_set is False
    # The tutorial rule is STAGING (a PREVIEW strategy): it reaches the tenant that
    # accepts PREVIEW, not the manual one, which it does not list.
    assert production.rules == (RULE,)
    assert manual.manual and manual.rules == ()
    shown = _plain(platform_card(card, catalogue))
    _no_secret(shown)
    assert "$OPENTIDE_TEST_WORKSPACE_ID" in shown.replace("{", "").replace("}", "")
    assert "Sentinel KQL Rule" in shown


def test_the_configuration_tab_shows_no_credential_in_any_view(configured_repo: Path) -> None:
    async def main() -> None:
        app = OpentideTui(CliContext(repo=configured_repo))
        async with app.run_test(size=(180, 50)) as pilot:
            with contextlib.suppress(WorkerFailed):
                await app.workers.wait_for_complete()
            await pilot.pause()
            await pilot.press("5")
            await pilot.pause()
            assert app.query_one(TabbedContent).active == "configuration"
            table = app.query_one("#config-files", DataTable)
            keys = [row.value for row in table.rows]
            assert "deployment.toml" in keys and "platforms/sentinel.toml" in keys
            # Every file, read and raw: no credential, on screen or in the widget.
            for key in keys:
                table.move_cursor(row=table.get_row_index(key))
                await pilot.pause()
                for _ in range(2):
                    shown = _plain(app.query_one("#config-view", Static).content)
                    _no_secret(shown)
                    _no_secret(app.export_screenshot())
                    await pilot.press("t")
                    await pilot.pause()
            table.move_cursor(row=table.get_row_index("platforms/sentinel.toml"))
            await pilot.pause()
            shown = _plain(app.query_one("#config-view", Static).content)
            assert "Production" in shown and HIDDEN in shown
            # setup wrote every key of this file: the workspace sets them all.
            assert "set here" in shown
            assert "ssl                  true" in shown

    asyncio.run(main())


def test_redaction_covers_every_way_toml_writes_a_value() -> None:
    text = (
        '[[tenants]]\nsetup.api_key = "a1"\n'
        '[tenants.setup]\ntoken = """\na2\n"""\nkeys = [\n  "a3",\n]\n'
        "password = 'a4'\n"
        '[[tenants]]\nsetup = { api_key = "a5" }\n'
        'url = "https://user:a6@host"\n'
    )
    redacted = redact_toml(text, {})
    for secret in ("a1", "a2", "a3", "a4", "a5", "a6"):
        assert f'"{secret}"' not in redacted and f"{secret}@" not in redacted, secret
    assert redacted.count(HIDDEN) >= 6


def test_without_a_workspace_file_the_defaults_are_shown(tutorial_repo: Path) -> None:  # noqa: F811
    view = load_configuration_view(tutorial_repo, {})
    documentation = next(item for item in view.files if item.key == "documentation.toml")
    assert documentation.path is None or documentation.path.is_file()
    assert all(not s.set_here for s in documentation.settings) or documentation.path
    rendered = _plain(file_view(documentation, None, None))
    assert "documentation.toml" in rendered
