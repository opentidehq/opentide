"""The Configuration tab: the workspace's configuration files, read rather than as TOML (#776).

A list of the files on the left; on the right the highlighted one by
section, each setting with its effective value, whether the workspace sets it
(else the bundled default) and what it does, its findings in place, and the
options nothing sets with their descriptions. A platform file starts with
its card: enabled or not, and each tenant's strategies, credentials and the
rules that reach it. ``t`` shows the raw file instead.

No credential value is shown anywhere, the raw file included: a credential
reads as its variable name and whether it is set, or as hidden
(:mod:`opentide.cli.services.configuration_view`).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ClassVar

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import DataTable, Static

from opentide.cli.services.configuration_view import (
    HIDDEN,
    ConfigFile,
    ConfigurationView,
    PlatformCard,
    Setting,
)

if TYPE_CHECKING:
    from opentide.cli.services.tui import Catalogue

_SEVERITY_STYLE = {"error": "bold red", "warning": "bold yellow"}


def _value(setting: Setting) -> Text:
    if setting.secret:
        if setting.variable is None:
            return Text(HIDDEN, style="dim")
        state = "set" if setting.variable_set else "unset"
        return Text.assemble(
            (f"${{{setting.variable}}}", "bold"),
            (f"  {state}", "green" if setting.variable_set else "bold yellow"),
        )
    return Text(setting.shown or '""')


def platform_card(card: PlatformCard, catalogue: Catalogue | None) -> RenderableType:
    """A platform as a card: enabled or not, its tenants, and what reaches each."""

    def names(uuids: tuple[str, ...]) -> str:
        if not uuids:
            return "none"
        shown = [
            catalogue.entries[u].name if catalogue and u in catalogue.entries else u
            for u in uuids[:6]
        ]
        return ", ".join(shown) + (f" and {len(uuids) - 6} more" if len(uuids) > 6 else "")

    body: list[RenderableType] = [
        Text.assemble(
            ("enabled" if card.enabled else "disabled", "bold green" if card.enabled else "dim"),
            (
                f"  ·  {len(card.rules)} rule{'s' if len(card.rules) != 1 else ''} with a block",
                "dim",
            ),
        )
    ]
    if not card.tenants:
        body.append(Text("No tenant configured.", style="yellow"))
    for tenant in card.tenants:
        lines = Table.grid(padding=(0, 2))
        lines.add_column(style="bold", no_wrap=True)
        lines.add_column(ratio=1, overflow="fold")
        lines.add_row(
            "strategies",
            Text(
                ", ".join(tenant.strategies) or "none", style="" if tenant.strategies else "yellow"
            ),
        )
        if tenant.manual:
            lines.add_row("manual", "only the rules that list it reach it")
        for credential in tenant.credentials:
            if credential.flag is not None:
                shown = Text("true" if credential.flag else "false")
            elif credential.variable is None:
                shown = Text(f"{HIDDEN}  (a literal in the file)", style="dim")
            else:
                shown = Text.assemble(
                    (f"${{{credential.variable}}}", "bold"),
                    (
                        "  set" if credential.is_set else "  unset",
                        "green" if credential.is_set else "bold yellow",
                    ),
                )
            lines.add_row(credential.key, shown)
        lines.add_row(f"rules ({len(tenant.rules)})", names(tenant.rules))
        body.append(
            Panel(
                lines,
                title=Text(tenant.name, style="bold"),
                title_align="left",
                border_style="bright_black",
            )
        )
    return Panel(
        Group(*body),
        title=Text(card.platform, style="bold"),
        title_align="left",
        border_style="green" if card.enabled else "bright_black",
    )


def file_view(
    item: ConfigFile, card: PlatformCard | None, catalogue: Catalogue | None
) -> RenderableType:
    """One configuration file, read: its card, its settings by section, what it leaves unset."""
    parts: list[RenderableType] = []
    where = str(item.path) if item.path else "not in this workspace: the bundled defaults apply"
    parts.append(Text.assemble((item.key, "bold"), ("\n", ""), (where, "dim")))
    if card is not None:
        parts.append(platform_card(card, catalogue))
    findings: dict[str, list[Any]] = {}
    for finding in item.findings:
        findings.setdefault(".".join(finding.field_path), []).append(finding)
    loose = findings.pop("", [])
    for finding in loose:
        parts.append(
            Text.assemble(
                (
                    f"{finding.severity}[{finding.code}]",
                    _SEVERITY_STYLE.get(finding.severity, "bold"),
                ),
                f": {finding.message}",
            )
        )
    sections: dict[str, list[Setting]] = {}
    for setting in item.settings:
        sections.setdefault(
            setting.path.split(".", 1)[0] if "." in setting.path else "", []
        ).append(setting)
    for section, settings in sections.items():
        parts.append(Text(""))
        parts.append(
            Rule(Text(section or "top level", style="bold"), align="left", style="bright_black")
        )
        grid = Table.grid(padding=(0, 2))
        grid.add_column(no_wrap=True, style="bold", max_width=40)
        grid.add_column(ratio=2, overflow="fold")
        grid.add_column(no_wrap=True)
        grid.add_column(ratio=3, overflow="fold", style="dim italic")
        for setting in settings:
            label = setting.path.split(".", 1)[1] if "." in setting.path else setting.path
            source = (
                Text("set here", style="cyan") if setting.set_here else Text("default", style="dim")
            )
            grid.add_row(label, _value(setting), source, setting.description)
            for finding in findings.pop(setting.path, ()):
                grid.add_row(
                    "",
                    Text.assemble(
                        ("╰─ ", "blue"),
                        (
                            f"{finding.severity}[{finding.code}]",
                            _SEVERITY_STYLE.get(finding.severity, "bold"),
                        ),
                        f": {finding.message}",
                    ),
                    "",
                    "",
                )
        parts.append(grid)
    for path, found in findings.items():
        for finding in found:
            parts.append(
                Text.assemble(
                    (
                        f"{finding.severity}[{finding.code}]",
                        _SEVERITY_STYLE.get(finding.severity, "bold"),
                    ),
                    f" at {path}: {finding.message}",
                )
            )
    if item.unset:
        parts.append(Text(""))
        parts.append(
            Rule(
                Text(f"Not set ({len(item.unset)})", style="bold"),
                align="left",
                style="bright_black",
            )
        )
        grid = Table.grid(padding=(0, 2))
        grid.add_column(no_wrap=True, style="bold")
        grid.add_column(ratio=1, overflow="fold", style="dim")
        for path, description in item.unset:
            grid.add_row(path, description)
        parts.append(grid)
    return Group(*parts)


class ConfigurationPane(Horizontal):
    """The Configuration tab's content."""

    DEFAULT_CSS = """
    ConfigurationPane #config-files { width: 34; border-right: solid $panel; }
    ConfigurationPane #config-detail { width: 1fr; padding: 0 1; }
    """
    BINDINGS: ClassVar[list[BindingType]] = [Binding("t", "toggle_raw", "Raw TOML")]

    def __init__(self, open_object: Callable[[str], None], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.open_object = open_object
        self.view = ConfigurationView()
        self.catalogue: Catalogue | None = None
        self.raw = False
        self.current: str | None = None

    def compose(self) -> ComposeResult:
        yield DataTable(id="config-files", cursor_type="row", zebra_stripes=True)
        with VerticalScroll(id="config-detail"):
            yield Static("", id="config-view")

    def on_mount(self) -> None:
        self.query_one("#config-files", DataTable).add_columns("File", "Set", "Findings")

    def show(self, view: ConfigurationView | None, catalogue: Catalogue) -> None:
        self.view = view or ConfigurationView()
        self.catalogue = catalogue
        table = self.query_one("#config-files", DataTable)
        table.clear()
        for item in self.view.files:
            set_here = sum(1 for s in item.settings if s.set_here)
            errors = len(item.findings)
            table.add_row(
                Text(item.key, style="bold" if item.path else "dim"),
                str(set_here),
                Text(str(errors), style="bold red" if errors else "dim"),
                key=item.key,
            )
        if self.view.problem:
            self.query_one("#config-view", Static).update(Text(self.view.problem, style="red"))
            return
        self._show(self.current or (self.view.files[0].key if self.view.files else None))

    def file(self, key: str | None) -> ConfigFile | None:
        return next((item for item in self.view.files if item.key == key), None)

    def _show(self, key: str | None) -> None:
        self.current = key
        item = self.file(key)
        target = self.query_one("#config-view", Static)
        if item is None:
            target.update("")
            return
        if self.raw:
            if item.raw is None and item.raw_problem is not None:
                # Never the content: a file that is not proven redacted is not shown.
                target.update(Text(f"{item.key}: {item.raw_problem}", style="yellow"))
            elif item.raw is None:
                target.update(Text(f"The workspace has no {item.key}.", style="dim"))
            else:
                target.update(
                    Syntax(
                        item.raw,
                        "toml",
                        line_numbers=True,
                        background_color="default",
                        word_wrap=True,
                    )
                )
            return
        platform = item.key.removeprefix("platforms/").removesuffix(".toml")
        card = next((c for c in self.view.platforms if c.platform == platform), None)
        target.update(
            file_view(item, card if item.key.startswith("platforms/") else None, self.catalogue)
        )

    def action_toggle_raw(self) -> None:
        self.raw = not self.raw
        self._show(self.current)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "config-files":
            event.stop()
            self._show(event.row_key.value)
