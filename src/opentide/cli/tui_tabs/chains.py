"""The Chains tab: ``threat.chaining`` drawn as a chain you can read and follow (#776).

Focused on one threat (the one selected in the Catalogue, else the first with
links) and the threats within some hops of it, because a whole catalogue's
chaining is unreadable. Sequence links run left to right as attack flow, each
threat a box with the rules under it (red when none: an undetected step) and
how many of its techniques some rule covers; supporting and atomicity links
are listed beside the flow, labelled and coloured by relation. The list on
the left is the threats shown: the highlighted one's links are described
below, ``Enter`` opens it in the Catalogue and ``c`` centres the chain on it.
``+`` and ``-`` change the hops, ``r`` the relations shown.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ClassVar

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import DataTable, Static

from opentide.cli.services.chains_view import (
    STAGES,
    ChainEdge,
    ChainNode,
    Neighbourhood,
    neighbourhood,
)

if TYPE_CHECKING:
    from opentide.cli.services.tui import Catalogue

#: Each relation stage's colour, for its edges and their labels.
STAGE_STYLE = {"sequence": "bold white", "atomicity": "magenta", "support": "cyan"}
_MAX_HOPS = 4


def _node_box(node: ChainNode, *, focus: bool, selected: bool) -> Panel:
    rules = Text(f"{node.rules} rule{'s' if node.rules != 1 else ''}")
    rules.stylize("bold red" if node.rules == 0 else "green")
    covered, total = node.techniques
    body = Text.assemble(rules)
    if total:
        body.append(
            f"\n{covered}/{total} techniques", style="green" if covered == total else "yellow"
        )
    if node.missing:
        body = Text("not in the catalogue", style="dim italic")
    title = Text(node.name, style="bold" if focus else "")
    border = "white" if focus else "bright_black"
    if node.rules == 0 and not node.missing:
        border = "red"
    if selected:
        border = "bold yellow"
    return Panel(body, title=title, title_align="left", border_style=border, width=30)


def flow(view: Neighbourhood, selected: str | None) -> RenderableType:
    """Sequence links as columns, left to right; every other threat shown beside."""
    parts: list[RenderableType] = []
    if view.layers:
        grid = Table.grid(padding=(0, 0))
        for index, _ in enumerate(view.layers):
            grid.add_column(vertical="middle")
            if index < len(view.layers) - 1:
                grid.add_column(vertical="middle", width=5)
        cells: list[RenderableType] = []
        for index, layer in enumerate(view.layers):
            cells.append(
                Group(
                    *(
                        _node_box(
                            view.nodes[uuid], focus=uuid == view.focus, selected=uuid == selected
                        )
                        for uuid in layer
                        if uuid in view.nodes
                    )
                )
            )
            if index < len(view.layers) - 1:
                cells.append(Text(" ──▶ ", style=STAGE_STYLE["sequence"]))
        grid.add_row(*cells)
        parts.append(grid)
    in_flow = {uuid for layer in view.layers for uuid in layer}
    others = [node for uuid, node in sorted(view.nodes.items()) if uuid not in in_flow]
    if others:
        if view.layers:
            parts.append(Text("Linked, outside the sequence", style="dim"))
        row = Table.grid(padding=(0, 1))
        for _ in others:
            row.add_column()
        row.add_row(
            *(
                _node_box(node, focus=node.uuid == view.focus, selected=node.uuid == selected)
                for node in others
            )
        )
        parts.append(row)
    return Group(*parts)


def _edge_text(edge: ChainEdge, names: dict[str, str]) -> Text:
    style = STAGE_STYLE.get(edge.stage, "")
    arrow = "─▶" if edge.directed else "◀─▶"
    text = Text.assemble(
        (names.get(edge.source, edge.source), "bold"),
        (f"  ─{edge.label}{arrow}  ", style),
        (names.get(edge.target, edge.target), "bold"),
    )
    if edge.merged:
        text.append("  (written from both ends)", style="dim")
    if edge.missing:
        text.append("  (names no threat)", style="red")
    return text


def links(view: Neighbourhood, selected: str | None) -> RenderableType:
    """Each link shown, side links included; the highlighted threat's with their descriptions."""
    names = {uuid: node.name for uuid, node in view.nodes.items()}
    parts: list[RenderableType] = []
    for stage in STAGES:
        edges = [e for e in view.edges if e.stage == stage]
        if not edges:
            continue
        parts.append(Text(f"\n{stage} ({len(edges)})", style=f"underline {STAGE_STYLE[stage]}"))
        for edge in edges:
            parts.append(_edge_text(edge, names))
            if selected in (edge.source, edge.target):
                for description in edge.descriptions:
                    parts.append(Text(f"    {description}", style="dim italic"))
    if not parts:
        return Text("No chaining links at this distance.", style="dim")
    return Group(*parts)


class ChainsPane(Horizontal):
    """The Chains tab's content."""

    DEFAULT_CSS = """
    ChainsPane #chain-nodes { width: 40; border-right: solid $panel; }
    ChainsPane #chain-scroll { width: 1fr; padding: 0 1; }
    """
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("plus,equals_sign", "hops(1)", "More hops"),
        Binding("minus", "hops(-1)", "Fewer hops"),
        Binding("r", "cycle_stage", "Relations"),
        Binding("c", "centre", "Centre"),
    ]

    def __init__(self, open_object: Callable[[str], None], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.open_object = open_object
        self.catalogue: Catalogue | None = None
        self.focus_uuid: str | None = None
        self.selected: str | None = None
        self.hops = 1
        self.stage: str | None = None
        self.view: Neighbourhood | None = None

    def compose(self) -> ComposeResult:
        yield DataTable(id="chain-nodes", cursor_type="row", zebra_stripes=True)
        with VerticalScroll(id="chain-scroll"):
            yield Static("", id="chain-header")
            yield Static("", id="chain-flow")
            yield Static("", id="chain-links")

    def on_mount(self) -> None:
        self.query_one("#chain-nodes", DataTable).add_columns("Threat", "Hops", "Rules")

    def show(self, catalogue: Catalogue, selected: str | None) -> None:
        """Draw the chain around *selected* when it is a threat, else around the last focus."""
        self.catalogue = catalogue
        threats = {entry.uuid for entry in catalogue.of_kind("threat")}
        chained = {e.source for e in catalogue.chains} | {e.target for e in catalogue.chains}
        if selected in threats:
            self.focus_uuid = selected
        elif self.focus_uuid not in threats:
            ordered = [e.uuid for e in catalogue.of_kind("threat")]
            self.focus_uuid = next(
                (u for u in ordered if u in chained), ordered[0] if ordered else None
            )
        self.refill()

    def _rules(self) -> dict[str, int]:
        catalogue = self.catalogue
        if catalogue is None:
            return {}
        counts: dict[str, int] = {}
        for threat in catalogue.of_kind("threat"):
            rules = {
                r.uuid for o in catalogue.children(threat.uuid) for r in catalogue.children(o.uuid)
            }
            counts[threat.uuid] = len(rules)
        return counts

    def _techniques(self) -> dict[str, tuple[int, int]]:
        """Per threat: how many of the techniques it names some rule covers (own or inherited)."""
        catalogue = self.catalogue
        found: dict[str, list[bool]] = {}
        for row in catalogue.coverage if catalogue else ():
            for uuid in row.referenced_by:
                found.setdefault(uuid, []).append(bool(row.rules))
        return {uuid: (sum(flags), len(flags)) for uuid, flags in found.items()}

    def refill(self) -> None:
        catalogue = self.catalogue
        header = self.query_one("#chain-header", Static)
        table = self.query_one("#chain-nodes", DataTable)
        table.clear()
        if catalogue is None or self.focus_uuid is None:
            header.update(Text("No threat in this catalogue.", style="dim"))
            self.query_one("#chain-flow", Static).update("")
            self.query_one("#chain-links", Static).update("")
            return
        names = {entry.uuid: entry.name for entry in catalogue.of_kind("threat")}
        self.view = view = neighbourhood(
            self.focus_uuid,
            catalogue.chains,
            names,
            self._rules(),
            self._techniques(),
            hops=self.hops,
            stage=self.stage,
        )
        for node in sorted(view.nodes.values(), key=lambda n: (n.distance, n.name.lower())):
            table.add_row(
                Text(node.name, style="bold" if node.uuid == view.focus else ""),
                str(node.distance),
                Text(str(node.rules), style="bold red" if node.rules == 0 else ""),
                key=node.uuid,
            )
        summary = Text()
        summary.append(names.get(view.focus, view.focus), style="bold")
        summary.append(f"   {self.hops} hop{'s' if self.hops != 1 else ''} (+/-)", style="dim")
        summary.append(f"   relations: {self.stage or 'all'} (r)", style="dim")
        counts = "  ".join(f"{stage} {view.totals.get(stage, 0)}" for stage in STAGES)
        summary.append(f"\n{counts}", style="dim")
        if view.hidden:
            summary.append(
                f"   {view.hidden} more threat{'s' if view.hidden != 1 else ''} beyond", style="dim"
            )
        if not view.edges:
            summary.append("\nThis threat chains to no other at this distance.", style="dim")
        header.update(summary)
        if self.selected not in view.nodes:
            self.selected = view.focus
        self._draw()

    def _draw(self) -> None:
        if self.view is None:
            return
        self.query_one("#chain-flow", Static).update(flow(self.view, self.selected))
        self.query_one("#chain-links", Static).update(links(self.view, self.selected))

    def action_hops(self, step: int) -> None:
        self.hops = max(1, min(_MAX_HOPS, self.hops + step))
        self.refill()

    def action_cycle_stage(self) -> None:
        order: list[str | None] = [None, *STAGES]
        self.stage = order[(order.index(self.stage) + 1) % len(order)]
        self.refill()

    def action_centre(self) -> None:
        if self.selected:
            self.focus_uuid = self.selected
            self.refill()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "chain-nodes":
            event.stop()
            self.selected = event.row_key.value
            self._draw()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter opens the threat in the Catalogue."""
        if event.data_table.id == "chain-nodes":
            event.stop()
            uuid = event.row_key.value
            if uuid:
                self.open_object(uuid)
