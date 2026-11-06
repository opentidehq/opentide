"""#776: the Configuration tab, and the rule that no credential value appears in any view.

Synthetic fixtures only: the tutorial repository, with a Sentinel tenant whose
``setup`` holds a literal secret, a ``$VAR`` reference that is set, and one
that is not.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
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
from opentide.cli.services import configuration_view
from opentide.cli.services.configuration_view import (
    HIDDEN,
    UNSAFE_RAW,
    ConfigurationView,
    UnsafeRawView,
    load_configuration_view,
    redact_toml,
)
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


#: Every way a credential leaked from an earlier redactor, in one valid platform file.
HOSTILE = f"""
api_key = {{ value = "{LITERAL}" }}
url = "https://user:pa@ss@{LITERAL}@proxy.example/path"
nested = [[{{ token = "{LITERAL}" }}]]
tenants = [
  {{ name = "inline", strategies = ["RELEASE"], setup = {{ client_secret = "{LITERAL}" }} }},
]

[platform]
enabled = false

[platform.credentials]
value = "{LITERAL}"

[auth]
value = "{LITERAL}"

[extra.'setup']
"client id" = "{LITERAL}"
'client name' = "{LITERAL}"
keys = [
  "a]",
  "{LITERAL}",
]
cert = \"\"\"
ab\\\"\"\"
{LITERAL}
\"\"\"
token = "a\u2028{LITERAL}\u0085{LITERAL}"
"""


@pytest.fixture
def hostile_repo(configured_repo: Path) -> Iterator[Path]:
    """The configured repository, with a platform file of every leak and an invalid file."""
    configurations = configured_repo / ".opentide" / "configurations"
    (configurations / "platforms" / "acme.toml").write_text(HOSTILE, encoding="utf-8")
    # sharing.toml is read by its own loader: the tab reads it even when it does not parse.
    (configurations / "sharing.toml").write_text(
        f'[[blocks]]\nname = "x"\n[blocks.setup]\nclient_secret: "{LITERAL}"\n',
        encoding="utf-8",
    )
    yield configured_repo


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


def test_the_configuration_tab_shows_no_credential_in_any_view(hostile_repo: Path) -> None:
    async def main() -> None:
        app = OpentideTui(CliContext(repo=hostile_repo))
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
            assert "platforms/acme.toml" in keys and "sharing.toml" in keys
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
            # The file of every leak is redacted raw; the invalid one has no raw view.
            await pilot.press("t")
            table.move_cursor(row=table.get_row_index("platforms/acme.toml"))
            await pilot.pause()
            shown = _plain(app.query_one("#config-view", Static).content)
            assert HIDDEN in shown and "proxy.example/path" in shown
            table.move_cursor(row=table.get_row_index("sharing.toml"))
            await pilot.pause()
            shown = _plain(app.query_one("#config-view", Static).content)
            assert "not valid TOML: line 4" in shown and "client_secret" not in shown

    asyncio.run(main())


def test_redaction_covers_every_way_toml_writes_a_value() -> None:
    text = (
        '[[tenants]]\nsetup.api_key = "a1"\n'
        'setup.token = """\na2\n"""\nsetup.keys = [\n  "a3",\n]\n'
        "setup.password = 'a4'\n"
        '[[tenants]]\nsetup = { api_key = "a5" }\n'
        'url = "https://user:a6@host"\n'
    )
    redacted = redact_toml(text, {})
    for secret in ("a1", "a2", "a3", "a4", "a5", "a6"):
        assert secret not in redacted, secret
    assert redacted.count(HIDDEN) == 6


SECRET = "S3CRET-trigger-value"

#: Each input that leaked a credential, by the finding that names it.
TRIGGERS = {
    "inline array of tables": (
        f'tenants = [ {{ name = "p", setup = {{ client_secret = "{SECRET}" }} }} ]\n'
    ),
    "inline array of tables over lines": (
        f'tenants = [\n  {{ name = "p", setup = {{ client_secret = "{SECRET}" }} }},\n]\n'
    ),
    "single-quoted header": f'[[tenants]]\nname = "p"\n[tenants.\'setup\']\nregion = "{SECRET}"\n',
    "double-quoted key with a space": f'[[tenants]]\n[tenants.setup]\n"client id" = "{SECRET}"\n',
    "single-quoted key with a space": f"[[tenants]]\n[tenants.setup]\n'client id' = \"{SECRET}\"\n",
    "array item holding ]": (
        f'[[tenants]]\n[tenants.setup]\nkeys = [\n  "a]",\n  "{SECRET}",\n]\nname = "x"\n'
    ),
    "escaped quotes in a multi-line string": (
        f'[[tenants]]\n[tenants.setup]\ncert = """\nab\\"""\n{SECRET}\n"""\n'
    ),
    "line separator in a value": f'[[tenants]]\n[tenants.setup]\ntoken = "a\u2028{SECRET}"\n',
    "next line in a value": f'[[tenants]]\n[tenants.setup]\ntoken = "a\u0085{SECRET}"\n',
    "secret-named table": f'[platform.credentials]\nvalue = "{SECRET}"\n',
    "auth table": f'[auth]\nvalue = "{SECRET}"\n',
    "secret-named inline table": f'api_key = {{ value = "{SECRET}" }}\n',
    "secret-named array of arrays": f'nested = [[{{ token = "{SECRET}" }}]]\n',
    "password holding @": f'url = "https://user:pa@ss@{SECRET}@proxy.example/path"\n',
}


def _workspace(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / ".opentide" / "configurations" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("text", TRIGGERS.values(), ids=TRIGGERS.keys())
def test_no_trigger_shows_its_secret_raw(text: str) -> None:
    redacted = redact_toml(text, {})
    assert SECRET not in redacted
    assert HIDDEN in redacted


@pytest.mark.parametrize("text", TRIGGERS.values(), ids=TRIGGERS.keys())
def test_no_trigger_shows_its_secret_read(tmp_path: Path, text: str) -> None:
    view = load_configuration_view(_workspace(tmp_path, "platforms/acme.toml", text), {})
    assert view.problem is None
    [item] = [f for f in view.files if f.key == "platforms/acme.toml"]
    assert item.raw is not None and item.raw_problem is None
    card = next(c for c in view.platforms if c.platform == "acme")
    for shown in (repr(view), repr(dataclasses.asdict(view)), _plain(file_view(item, card, None))):
        assert SECRET not in shown
    assert any(s.secret or HIDDEN in s.shown for s in item.settings)


def test_a_url_hides_its_user_up_to_the_last_at(tmp_path: Path) -> None:
    text = TRIGGERS["password holding @"]
    view = load_configuration_view(_workspace(tmp_path, "platforms/acme.toml", text), {})
    [item] = [f for f in view.files if f.key == "platforms/acme.toml"]
    [url] = [s for s in item.settings if s.path == "url"]
    assert url.shown == f"https://{HIDDEN}@proxy.example/path"
    assert f'"https://{HIDDEN}@proxy.example/path"' in (item.raw or "")


def test_a_secret_table_keeps_its_switches() -> None:
    redacted = redact_toml(f'[auth]\nenabled = true\nvalue = "{SECRET}"\n', {})
    assert "enabled = true" in redacted and SECRET not in redacted


INVALID = f'[[tenants]]\n[tenants.setup]\nclient_secret: "{SECRET}"\n'


def test_invalid_toml_has_no_raw_view() -> None:
    with pytest.raises(UnsafeRawView) as raised:
        redact_toml(INVALID, {})
    assert str(raised.value) == "not valid TOML: line 3, column 14"


def test_an_invalid_file_is_read_without_its_content(tmp_path: Path) -> None:
    # sharing.toml has its own loader: the tab still lists it, with no raw view.
    view = load_configuration_view(_workspace(tmp_path, "sharing.toml", INVALID), {})
    [item] = [f for f in view.files if f.key == "sharing.toml"]
    assert item.raw is None
    assert item.raw_problem == "not valid TOML: line 3, column 14"
    assert SECRET not in repr(view) and SECRET not in repr(dataclasses.asdict(view))
    # A file every command reads: the view says where, never what the parser quotes.
    view = load_configuration_view(_workspace(tmp_path, "platforms/acme.toml", INVALID), {})
    assert view.problem is not None and "line 3, column 14" in view.problem
    assert SECRET not in view.problem and "client_secret" not in view.problem


def test_a_redaction_that_cannot_be_proven_is_not_shown(monkeypatch: pytest.MonkeyPatch) -> None:
    text = f'[[tenants]]\n[tenants.setup]\ntoken = "{SECRET}"\n'
    # A redactor that misses a value: the proof withholds the raw view.
    monkeypatch.setattr(configuration_view._Redactor, "run", lambda self: self.text)
    with pytest.raises(UnsafeRawView) as raised:
        redact_toml(text, {})
    assert str(raised.value) == UNSAFE_RAW


def test_a_secret_quoted_in_a_comment_withholds_the_raw_view() -> None:
    text = f'# the old token was {SECRET}\n[[tenants]]\n[tenants.setup]\ntoken = "{SECRET}"\n'
    with pytest.raises(UnsafeRawView):
        redact_toml(text, {})
    # A variable reference is no secret: it is shown, with whether it is set.
    redacted = redact_toml('[auth]\ntoken = "$OT_TEST_TOKEN"\n', {"OT_TEST_TOKEN": SECRET})
    assert redacted == '[auth]\ntoken = "${OT_TEST_TOKEN}"  # set\n'


def test_the_view_holds_no_environment(configured_repo: Path) -> None:
    assert "environ" not in {f.name for f in dataclasses.fields(ConfigurationView)}
    view = load_catalogue(CliContext(repo=configured_repo)).configuration
    assert view is not None
    _no_secret(repr(dataclasses.asdict(view)))


def test_without_a_workspace_file_the_defaults_are_shown(tutorial_repo: Path) -> None:  # noqa: F811
    view = load_configuration_view(tutorial_repo, {})
    documentation = next(item for item in view.files if item.key == "documentation.toml")
    assert documentation.path is None or documentation.path.is_file()
    assert all(not s.set_here for s in documentation.settings) or documentation.path
    rendered = _plain(file_view(documentation, None, None))
    assert "documentation.toml" in rendered
