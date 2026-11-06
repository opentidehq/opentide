"""The Visibility tab: the log sources ``visibility.toml`` declares, and what uses them (#776).

A table of log sources with their system, description, column count and the
rules that use each, filtered by a search (a name, or ``system:sentinel``).
The highlighted one is drilled into below: its columns with their types and
descriptions, and the rules and objectives that use it. Tiles at the top count
log sources per system and how many declare columns, and what needs attention:
log sources with no columns (column checks cannot run), log sources no rule
uses, and datasets rules read that no log source declares.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.coordinate import Coordinate
from textual.widgets import DataTable, Input, Static

from opentide.cli.services.visibility import LogSource, Undeclared, VisibilityReport

if TYPE_CHECKING:
    from opentide.cli.services.tui import Catalogue

#: Row keys of datasets rules read that no log source declares.
_UNDECLARED = "undeclared:"


def tiles(report: VisibilityReport) -> RenderableType:
    """Log sources per system, how many declare columns, and what needs attention."""
    grid = Table.grid(padding=(0, 3))
    cells: list[Text] = []
    for system, counts in report.systems.items():
        cell = Text()
        cell.append(f"{counts['logsources']}", style="bold")
        cell.append(f" {system}\n", style="bold")
        cell.append(f"{counts['with_columns']} with columns · {counts['used']} used", style="dim")
        cells.append(cell)
    no_columns = sum(1 for source in report.logsources if not source.columns)
    unused = sum(1 for source in report.logsources if not source.used)
    attention = Text()
    attention.append(f"{no_columns}", style="bold yellow" if no_columns else "bold green")
    attention.append(" without columns  ")
    attention.append(f"{unused}", style="bold yellow" if unused else "bold green")
    attention.append(" unused  ")
    missing = len(report.undeclared)
    attention.append(f"{missing}", style="bold red" if missing else "bold green")
    attention.append(" read but not declared")
    cells.append(attention)
    for _ in cells:
        grid.add_column()
    grid.add_row(*cells)
    return grid


def _flags(source: LogSource) -> Text:
    text = Text()
    if not source.columns:
        text.append("no columns ", style="yellow")
    if not source.used:
        text.append("unused", style="yellow")
    return text


def matches(query: str, system: str, name: str, description: str = "") -> bool:
    """Whether a row answers the search: ``system:<id>`` narrows by system, other words by name."""
    words = query.lower().split()
    for word in words:
        if word.startswith("system:"):
            if system.lower() != word.removeprefix("system:"):
                return False
        elif word not in name.lower() and word not in description.lower():
            return False
    return True


def detail(
    source: LogSource | Undeclared | None, catalogue: Catalogue | None, report: VisibilityReport
) -> RenderableType:
    """The highlighted row drilled into."""

    def names(uuids: tuple[str, ...]) -> Text:
        text = Text()
        for index, uuid in enumerate(uuids):
            entry = catalogue.entries.get(uuid) if catalogue else None
            if index:
                text.append(", ")
            text.append(entry.name if entry else uuid, style="bold" if entry else "dim")
        return text or Text("none", style="dim")

    if source is None:
        if report.reads_unavailable:
            return Text(
                f"Datasets queries read are not known: {report.reads_unavailable}", style="dim"
            )
        return Text(
            "Highlight a log source to see its columns and the detections that use it.", style="dim"
        )
    if isinstance(source, Undeclared):
        text = Text.assemble(
            (source.name, "bold"),
            (f"  {source.system}", "dim"),
            ("\nRead by rules, declared by no log source", "bold red"),
        )
        if not source.system_declares:
            text.append(
                f"\n{source.system} declares no log source, so the query checks do not "
                "warn about it.",
                style="dim",
            )
        text.append("\nRules: ")
        text.append_text(names(source.rules))
        return text
    parts: list[RenderableType] = [
        Text.assemble((source.name, "bold"), (f"  {source.system}", "dim")),
        Text(source.description or "No description.", style="italic"),
    ]
    if source.tenants:
        parts.append(Text(f"Tenants: {', '.join(source.tenants)}", style="dim"))
    parts.append(Text.assemble(("Read by queries: ", "bold"), names(source.read_by)))
    parts.append(Text.assemble(("Rules through signals: ", "bold"), names(source.signal_rules)))
    parts.append(Text.assemble(("Objectives: ", "bold"), names(source.objectives)))
    if source.columns:
        columns = Table(title=f"Columns ({len(source.columns)})", title_justify="left", expand=True)
        columns.add_column("Column", style="bold", no_wrap=True)
        columns.add_column("Type", style="cyan", no_wrap=True)
        columns.add_column("Description", overflow="fold")
        for column in source.columns:
            columns.add_row(column.name, column.type, column.description)
        parts.append(columns)
    else:
        parts.append(
            Text(
                "No columns declared: the column checks cannot run on this source.", style="yellow"
            )
        )
    return Group(*parts)


class VisibilityPane(Vertical):
    """The Visibility tab's content."""

    DEFAULT_CSS = """
    VisibilityPane #vis-tiles { height: auto; padding: 0 1; margin-bottom: 1; }
    VisibilityPane #vis-search { margin: 0 1; }
    VisibilityPane #vis-table { height: 1fr; min-height: 6; }
    VisibilityPane #vis-detail-scroll { height: 1fr; padding: 0 1; border-top: solid $panel; }
    """

    def __init__(self, open_object: Callable[[str], None], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.open_object = open_object
        self.report = VisibilityReport()
        self.catalogue: Catalogue | None = None

    def compose(self) -> ComposeResult:
        yield Static("", id="vis-tiles")
        yield Input(placeholder="Filter: a name, or system:sentinel", id="vis-search")
        yield DataTable(id="vis-table", cursor_type="row", zebra_stripes=True)
        with VerticalScroll(id="vis-detail-scroll"):
            yield Static("", id="vis-detail")

    def on_mount(self) -> None:
        self.query_one("#vis-table", DataTable).add_columns(
            "Log source", "System", "Columns", "Rules", "Attention", "Description"
        )

    def show(self, report: VisibilityReport | None, catalogue: Catalogue) -> None:
        self.report = report or VisibilityReport()
        self.catalogue = catalogue
        tiles_widget = self.query_one("#vis-tiles", Static)
        if not self.report.present:
            tiles_widget.update(
                Text(
                    "This workspace has no .opentide/configurations/visibility.toml: no log source "
                    "is declared.",
                    style="dim",
                )
            )
        elif self.report.problem:
            tiles_widget.update(Text(self.report.problem, style="red"))
        else:
            tiles_widget.update(tiles(self.report))
        self.refill()

    def refill(self) -> None:
        query = self.query_one("#vis-search", Input).value
        table = self.query_one("#vis-table", DataTable)
        table.clear()
        for source in self.report.logsources:
            if not matches(query, source.system, source.name, source.description):
                continue
            table.add_row(
                Text(source.name, style="bold"),
                source.system,
                Text(str(len(source.columns)), style="" if source.columns else "yellow"),
                Text(str(len(source.rules)), style="" if source.rules else "yellow"),
                _flags(source),
                Text(source.description, overflow="ellipsis", no_wrap=True),
                key=f"{source.system}:{source.name}",
            )
        for item in self.report.undeclared:
            if not matches(query, item.system, item.name):
                continue
            table.add_row(
                Text(item.name, style="bold red"),
                item.system,
                Text("—", style="dim"),
                str(len(item.rules)),
                Text("read, not declared", style="red"),
                Text("", style="dim"),
                key=f"{_UNDECLARED}{item.system}:{item.name}",
            )
        self._show(table.cursor_row if table.row_count else None)

    def selected(self, key: str | None) -> LogSource | Undeclared | None:
        if key is None:
            return None
        if key.startswith(_UNDECLARED):
            system, _, name = key.removeprefix(_UNDECLARED).partition(":")
            return next(
                (u for u in self.report.undeclared if u.system == system and u.name == name), None
            )
        system, _, name = key.partition(":")
        return self.report.find(system, name)

    def _show(self, row: int | None) -> None:
        table = self.query_one("#vis-table", DataTable)
        key = None
        if row is not None and 0 <= row < table.row_count:
            key = table.coordinate_to_cell_key(Coordinate(row, 0)).row_key.value
        self.query_one("#vis-detail", Static).update(
            detail(self.selected(key), self.catalogue, self.report)
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "vis-search":
            self.refill()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "vis-table":
            event.stop()
            self._show(event.cursor_row)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter opens the first rule that uses the log source."""
        if event.data_table.id != "vis-table":
            return
        event.stop()
        found = self.selected(event.row_key.value)
        rules = found.rules if found is not None else ()
        if rules:
            self.open_object(rules[0])
