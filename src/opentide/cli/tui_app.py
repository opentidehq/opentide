"""The Textual app behind ``opentide tui``.

The only module that imports Textual. :mod:`opentide.cli.commands.tui` imports
it when the UI opens, never for ``--help``, completion or a walk of the
command tree. What it shows and runs comes from
:mod:`opentide.cli.services.tui`; results print through
:func:`opentide.cli.output.render_result`, the renderer every command uses.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Iterable
from functools import partial
from pathlib import Path
from typing import Any, ClassVar, cast

from rich.cells import set_cell_size
from rich.console import Console, Group, RenderableType
from rich.style import Style
from rich.syntax import Syntax
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import DataTable, Footer, RichLog, Static, TabbedContent, TabPane, Tree
from textual.widgets.tree import TreeNode
from textual.worker import Worker, WorkerState
from typing_extensions import Self

from opentide.cli.context import CliContext
from opentide.cli.output import render_result
from opentide.cli.services.tui import (
    ACTIONS,
    ACTIONS_BY_NAME,
    Action,
    ActionOutcome,
    Catalogue,
    CatalogueEntry,
    Diagnostic,
    load_catalogue,
    plural,
    relative,
    run_action,
    summary_line,
)
from opentide.cli.ui.mode import OutputMode

# TODO: take the pill and colours from opentide.cli.ui.brand once the brand
# marks land there; they are defined here until both changes are merged.
BLUE = "#001489"  # Pantone Reflex Blue
WHITE = "#ffffff"
TAGLINE = "Spec-driven development for agentic detection engineering"

THEME = Theme(
    name="opentide",
    primary=BLUE,
    # Textual draws accent-coloured text (footer keys, links); Reflex Blue on a
    # dark surface would be all but invisible there.
    accent=WHITE,
    dark=True,
    # Blue is a fill, never a text colour: cursors are white on Reflex Blue,
    # and borders, footer keys and accent text are white.
    variables={
        "block-cursor-foreground": WHITE,
        "footer-key-foreground": WHITE,
        "text-accent": WHITE,
        "border": WHITE,
    },
)

#: The widget each tab focuses when shown.
_TAB_FOCUS = {"catalogue": "#tree", "coverage": "#coverage-table", "results": "#log"}

_SEVERITY_STYLE = {"error": "bold red", "warning": "bold yellow", "note": "bold blue"}
_FRAME_STYLE = "blue"


def pill() -> Text:
    """The one-line pill ``▐ ≋ opentide ▌``: white on Reflex Blue, half-block caps."""
    return Text.assemble(
        ("▐", Style(color=BLUE)),
        (" ≋ opentide ", Style(color=WHITE, bgcolor=BLUE, bold=True)),
        ("▌", Style(color=BLUE)),
    )


def masthead_brand(width: int, summary: Text) -> Text:
    """The pill, then the tagline when it fits whole beside *summary* in *width* cells.

    The tagline is never cut: at a narrow width it goes, the pill stays.
    """
    with_tagline = Text.assemble(pill(), _GAP, TAGLINE)
    if with_tagline.cell_len + len(_GAP) + summary.cell_len <= width:
        return with_tagline
    return pill()


#: Between the pill and the tagline, and before the summary (``#summary``'s margin).
_GAP = "  "


def fit_label(label: Text, width: int, tail: int = 0) -> Text:
    """*label* in at most *width* cells, cut after a whole word or character and ended by ``…``.

    The last *tail* characters (an object's facts and diagnostic counts) stay
    whole while the name before them keeps room for a character and the
    ellipsis; below that the whole label is cut.
    """
    if width <= 0 or label.cell_len <= width:
        return label
    split = len(label) - tail
    end = label[split:]
    room = width - end.cell_len
    if tail > 0 and room >= 2:
        return Text.assemble(_cut(label[:split], room), end)
    return _cut(label, width)


def _cut(text: Text, width: int) -> Text:
    """*text* in *width* cells, the last one ``…``; no space before it, so cuts read the same."""
    kept = set_cell_size(text.plain, width - 1).rstrip()
    # Slicing keeps the spans, so the ellipsis takes the style of the cell it replaces.
    cut = text[: len(kept) + 1]
    cut.plain = kept + "…"
    return cut


def empty_state(repo: Path, cwd: Path) -> str:
    """The tree's only line when the workspace holds no object, its path relative to *cwd*."""
    where = relative(repo, cwd)
    if where == "." or Path(where).is_absolute():
        # The workspace itself, or outside the current directory: relative to
        # the workspace, the path is the workspace.
        return "No detection objects in this workspace"
    return f"No detection objects under {where}"


class CatalogueTree(Tree[Any]):
    """The catalogue tree: every label fits its column, so it never scrolls sideways.

    An object's name gives way before its counts; the detail pane shows the
    name in full.
    """

    def __init__(self, label: str, *, id: str | None = None) -> None:
        super().__init__(label, id=id)
        #: Node id → how many trailing characters of its label to keep whole.
        self.tails: dict[int, int] = {}

    def clear(self) -> Self:
        # Node ids start again from 0 after a clear.
        self.tails.clear()
        return super().clear()

    def render_label(self, node: TreeNode[Any], base_style: Style, style: Style) -> Text:
        label = super().render_label(node, base_style, style)
        depth = 0
        parent = node.parent
        while parent is not None and (parent is not self.root or self.show_root):
            depth += 1
            parent = parent.parent
        width = self.scrollable_content_region.width - depth * self.guide_depth
        return fit_label(label, width, self.tails.get(node.id, 0))


def diagnostic_text(diagnostic: Diagnostic, root: Path) -> Text:
    """The frame of a diagnostic, without its source lines (the detail pane shows the file).

    ::

        error[vocab_unknown]: Value 'clearr' is not a valid 'tlp::1.0' vocabulary entry
          ╭─▶ objects/rules/sentinel-kql-rule.yaml:8
          ╰─ help: did you mean 'clear'?

    ``╰─▶`` closes the location when there is no help. The path is relative
    to the current directory when inside it, else to the workspace; the field
    stands in for the line when the line is not known.
    """
    text = Text()
    text.append(
        f"{diagnostic.severity}[{diagnostic.code}]",
        style=_SEVERITY_STYLE.get(diagnostic.severity, "bold"),
    )
    text.append(f": {diagnostic.message}", style="bold")
    where = relative(diagnostic.path, Path.cwd())
    if Path(where).is_absolute():
        where = relative(diagnostic.path, root)
    if where and diagnostic.line is not None:
        where = f"{where}:{diagnostic.line}"
    elif diagnostic.field_path:
        field = ".".join(diagnostic.field_path)
        where = f"{where} · {field}" if where else field
    help_text = diagnostic.help_text()
    if where:
        text.append("\n  ")
        text.append("╭─▶" if help_text else "╰─▶", style=_FRAME_STYLE)
        text.append(f" {where}")
    if help_text:
        text.append("\n  ")
        text.append("╰─", style=_FRAME_STYLE)
        text.append(" help:", style="bold cyan")
        text.append(f" {help_text}")
    return text


#: Wide enough that Rich never breaks a line: the Results log wraps to its own width.
_UNWRAPPED = 10_000


def outcome_text(outcome: ActionOutcome, root: Any) -> Text:
    """The command line, its diagnostics and plan, then the result as the CLI prints it.

    Every line is printed with ``soft_wrap`` on a console too wide to wrap, so
    the text carries no line breaks of its own; ``RichLog(wrap=True)`` wraps it
    to the width the Results tab has.
    """
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        width=_UNWRAPPED,
        force_terminal=True,
        color_system="truecolor",
        highlight=False,
    )
    console.print(Text(f"$ {outcome.action.command}", style="bold"), soft_wrap=True)
    for diagnostic in outcome.diagnostics:
        console.print(diagnostic_text(diagnostic, root), soft_wrap=True)
    plan = outcome.result.data.get("plan")
    if isinstance(plan, dict):
        for platform, uuids in plan.items():
            console.print(Text(f"  {platform}: {plural(len(uuids), 'rule')}"), soft_wrap=True)
    render_result(outcome.result, stdout=console, stderr=console, mode=OutputMode.HUMAN)
    return Text.from_ansi(buffer.getvalue().rstrip("\n"))


class OpentideTui(App[None]):
    """The ``opentide tui`` application."""

    TITLE = "opentide"
    SUB_TITLE = TAGLINE
    CSS = """
    #masthead { height: 1; dock: top; padding: 0 1; }
    #brand { width: 1fr; text-wrap: nowrap; }
    #summary { width: auto; margin-left: 2; color: $text-muted; text-wrap: nowrap; }
    #tree { width: 2fr; min-width: 30; border-right: solid $panel; overflow-x: hidden; }
    #detail { width: 3fr; padding: 0 1; }
    #heading { margin-bottom: 1; }
    #diagnostics { margin-bottom: 1; }
    TabbedContent { height: 1fr; }
    #status { height: 1; padding: 0 1; color: $text-muted; }
    /* Blue is a fill, never a text colour: the tab underline and the tree
       guides are drawn as coloured characters, so they take the foreground. */
    Underline > .underline--bar { color: $foreground; }
    Tree > .tree--guides-selected { color: $foreground 60%; }
    Tree:focus > .tree--guides-selected { color: $foreground; }
    """
    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("v", "run('validate')", "Validate"),
        Binding("g", "run('generate')", "Generate"),
        Binding("d", "run('deploy-preview')", "Deploy dry run"),
        Binding("r", "reload", "Reload"),
        Binding("1", "show_tab('catalogue')", "Catalogue", show=False),
        Binding("2", "show_tab('coverage')", "Coverage", show=False),
        Binding("3", "show_tab('results')", "Results", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, cli: CliContext) -> None:
        super().__init__()
        self.cli = cli
        self.catalogue: Catalogue | None = None
        self.diagnostics: tuple[Diagnostic, ...] = ()
        #: False until a validate run finished: "no diagnostics" means nothing then.
        self.validated = False
        #: The tree node's data the detail pane shows: a UUID, a group or a load error.
        self.selected: Any = None
        #: Name of the worker running, if any. One at a time: they share the registry.
        self.running: str | None = None
        self.outcomes: list[ActionOutcome] = []
        #: Set by quit while a command runs: the app exits when it finishes.
        self.quit_pending = False
        #: Why the reload after the last action failed, if it did.
        self.reload_error: str | None = None
        #: The masthead's right side: workspace name and counts.
        self.summary = Text()
        self.register_theme(THEME)
        self.theme = THEME.name

    # -- layout -------------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="masthead"):
            yield Static(pill(), id="brand")
            yield Static("", id="summary")
        with TabbedContent(initial="catalogue"):
            with TabPane("Catalogue", id="catalogue"), Horizontal():
                yield CatalogueTree("Catalogue", id="tree")
                with VerticalScroll(id="detail"):
                    yield Static("", id="heading")
                    yield Static("", id="diagnostics")
                    yield Static("", id="source")
            with TabPane("Coverage", id="coverage"):
                yield DataTable(id="coverage-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Results", id="results"):
                yield RichLog(id="log", wrap=True, markup=False, highlight=False)
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        self._fit_masthead()
        tree = self.query_one("#tree", Tree)
        tree.show_root = False
        tree.root.add_leaf("Loading the catalogue…")
        tree.focus()
        table = self.query_one("#coverage-table", DataTable)
        table.add_columns("Technique", "Rules", "Detected by", "Named by")
        self.query_one("#log", RichLog).write(
            Text("Results of validate, generate and deploy --dry-run appear here.", style="dim")
        )
        self._start("load", self._load, "Loading the catalogue")

    def get_system_commands(self, screen: Screen[Any]) -> Iterable[SystemCommand]:
        for action in ACTIONS:
            yield SystemCommand(action.command, action.help, partial(self.action_run, action.name))
        yield SystemCommand(
            "Reload the catalogue", "Read every object file again", self.action_reload
        )
        yield from super().get_system_commands(screen)

    # -- actions ------------------------------------------------------------

    def action_run(self, name: str) -> None:
        action = ACTIONS_BY_NAME[name]
        self._start(name, partial(self._run, action), action.command)

    def action_reload(self) -> None:
        self._start("load", self._load, "the catalogue reload")

    def action_show_tab(self, tab: str) -> None:
        self.query_one(TabbedContent).active = tab
        # Focus follows the tab: TabbedContent shows the pane holding the
        # focused widget, so a focus left in the hidden pane switches back.
        self.query_one(_TAB_FOCUS[tab]).focus()

    async def action_quit(self) -> None:
        """Quit, but never with a command half done.

        A worker thread cannot be cancelled: quitting under it would leave it
        writing files, and printing into the shell, after the UI has gone. So
        the UI stays up, says what it waits for, and quits when it is done.
        """
        if self.running is None:
            self.exit()
            return
        self.quit_pending = True
        message = f"Waiting for {self.running} to finish…"
        self._status(f"{message} The UI closes when it is done.")
        self.notify(message, title="Quitting", severity="warning")

    # -- workers ------------------------------------------------------------

    def _start(self, name: str, work: Callable[[], object], label: str) -> None:
        if self.quit_pending:
            return
        if self.running is not None:
            self.notify(f"Wait for {self.running} to finish", severity="warning")
            return
        self.running = label
        self._status(f"Running {label}…")
        self.run_worker(work, name=name, group="opentide", thread=True, exit_on_error=False)

    def _load(self) -> Catalogue:
        return load_catalogue(self.cli)

    def _run(self, action: Action) -> tuple[ActionOutcome, Catalogue | None]:
        outcome = run_action(self.cli, action)
        # generate rewrites what the registry reads, and any run may follow an
        # edit. A reload that fails must not lose the outcome of the action.
        self.reload_error = None
        try:
            catalogue = load_catalogue(self.cli)
        except Exception as exc:
            self.reload_error = f"{type(exc).__name__}: {exc}"
            return outcome, None
        return outcome, catalogue

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker.group != "opentide":
            return
        if event.state not in (WorkerState.SUCCESS, WorkerState.ERROR, WorkerState.CANCELLED):
            return
        self.running = None
        self._finish(event)
        if self.quit_pending:
            self.exit()

    def _finish(self, event: Worker.StateChanged) -> None:
        if event.state is WorkerState.ERROR:
            error = event.worker.error
            self._internal_error(f"{type(error).__name__}: {error}")
            return
        if event.state is WorkerState.CANCELLED:
            self._status("")
            return
        result = event.worker.result
        if isinstance(result, Catalogue):
            self._show_catalogue(result)
            self._status("")
            return
        outcome, catalogue = cast("tuple[ActionOutcome, Catalogue | None]", result)
        self._show_outcome(outcome)
        if catalogue is None:
            self._internal_error(f"the catalogue could not be read again: {self.reload_error}")
            return
        self._show_catalogue(catalogue)

    def _internal_error(self, message: str) -> None:
        self._log(Text.assemble(("error[internal]:", "bold red"), f" {message}"))
        self._status(f"error: {message}")
        self.notify(message, severity="error", title="opentide")

    # -- rendering ----------------------------------------------------------

    def on_resize(self, event: events.Resize) -> None:
        self._fit_masthead()

    def _fit_masthead(self) -> None:
        # The masthead pads one cell on each side.
        brand = masthead_brand(self.size.width - 2, self.summary)
        self.query_one("#brand", Static).update(brand)

    def _status(self, message: str) -> None:
        self.query_one("#status", Static).update(Text(message))

    def _log(self, text: Text) -> None:
        self.query_one("#log", RichLog).write(text)

    def _show_outcome(self, outcome: ActionOutcome) -> None:
        self.outcomes.append(outcome)
        if outcome.action.name == "validate":
            self.diagnostics = outcome.diagnostics
            self.validated = True
        root = self.cli.repo
        self._log(Text(""))
        self._log(outcome_text(outcome, root))
        result = outcome.result
        severity = "error" if not result.ok else "warning" if result.warnings else "information"
        first = result.message.splitlines()[0] if result.message else result.status
        self._status(f"{outcome.action.command}: {first}")
        self.notify(result.message, title=outcome.action.command, severity=severity)

    def _show_catalogue(self, catalogue: Catalogue) -> None:
        self.catalogue = catalogue
        self.summary = Text(f"{catalogue.repo.name} · {summary_line(catalogue)}")
        self.query_one("#summary", Static).update(self.summary)
        self._fit_masthead()
        self._fill_tree(catalogue)
        self._fill_coverage(catalogue)
        self._show_detail(self.selected)

    def _counts(self, uuid: str) -> Text:
        """``✗ 2 ! 1`` after an object the last validate run found issues in."""
        mark = Text()
        if self.catalogue is None:
            return mark
        entry = self.catalogue.entries[uuid]
        found = [item for item in self.diagnostics if item.concerns(entry)]
        errors = sum(1 for item in found if item.severity == "error")
        warnings = len(found) - errors
        if errors:
            mark.append(f"  ✗ {errors}", style="bold red")
        if warnings:
            mark.append(f"  ! {warnings}", style="bold yellow")
        return mark

    def _add_entry(
        self, parent: TreeNode[Any], entry: CatalogueEntry, facts: str = "", *, leaf: bool = False
    ) -> TreeNode[Any]:
        """*entry* under *parent*: its name, then its facts and diagnostic counts."""
        tail = Text()
        if facts:
            tail.append(f"  {facts}", style="dim")
        tail.append_text(self._counts(entry.uuid))
        label = Text.assemble(entry.name, tail)
        if leaf:
            node = parent.add_leaf(label, data=entry.uuid)
        else:
            node = parent.add(label, data=entry.uuid, expand=True)
        self.query_one("#tree", CatalogueTree).tails[node.id] = len(tail)
        return node

    def _fill_tree(self, catalogue: Catalogue) -> None:
        tree = self.query_one("#tree", Tree)
        tree.clear()
        root = tree.root
        for threat in catalogue.of_kind("threat"):
            objectives = catalogue.children(threat.uuid)
            rules = {rule.uuid for item in objectives for rule in catalogue.children(item.uuid)}
            node = self._add_entry(
                root,
                threat,
                f"{plural(len(objectives), 'objective')} · {plural(len(rules), 'rule')}",
            )
            for objective in objectives:
                self._add_objective(node, objective, catalogue)
        orphans = catalogue.unlinked("objective")
        if orphans:
            group = root.add(
                Text(f"Objectives without a threat ({len(orphans)})", style="italic"),
                data=("group", "objective"),
                expand=True,
            )
            for objective in orphans:
                self._add_objective(group, objective, catalogue)
        loose = catalogue.unlinked("rule")
        if loose:
            group = root.add(
                Text(f"Rules without an objective ({len(loose)})", style="italic"),
                data=("group", "rule"),
                expand=True,
            )
            for rule in loose:
                self._add_entry(group, rule, leaf=True)
        if catalogue.load_errors:
            group = root.add(
                Text(f"Files that failed to load ({len(catalogue.load_errors)})", style="bold red"),
                data=("group", "load_error"),
                expand=True,
            )
            for number, error in enumerate(catalogue.load_errors):
                name = error.path.name if error.path else "unknown file"
                group.add_leaf(Text(name), data=("load_error", number))
        if not catalogue.entries and not catalogue.load_errors:
            root.add_leaf(Text(empty_state(catalogue.repo, Path.cwd()), style="dim"), data=None)
        self._restore_cursor(tree)

    def _add_objective(
        self, parent: TreeNode[Any], objective: CatalogueEntry, catalogue: Catalogue
    ) -> None:
        rules = catalogue.children(objective.uuid)
        node = self._add_entry(parent, objective, plural(len(rules), "rule"))
        for rule in rules:
            self._add_entry(node, rule, leaf=True)

    def _restore_cursor(self, tree: Tree[Any]) -> None:
        """Keep the cursor on the object it was on; on the first load, on the first object."""
        node = None if self.selected is None else self._find(tree.root, self.selected)
        if node is None and tree.root.children:
            node = tree.root.children[0]
            self.selected = node.data
        if node is not None:
            self.call_after_refresh(tree.move_cursor, node)

    def _find(self, node: TreeNode[Any], data: Any) -> TreeNode[Any] | None:
        for child in node.children:
            if child.data == data:
                return child
            found = self._find(child, data)
            if found is not None:
                return found
        return None

    def select(self, uuid: str) -> None:
        """Show *uuid* in the catalogue tab, with the tree cursor on it."""
        self.action_show_tab("catalogue")
        tree = self.query_one("#tree", Tree)
        node = self._find(tree.root, uuid)
        if node is not None:
            tree.move_cursor(node)
        self._show_detail(uuid)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted[Any]) -> None:
        self._show_detail(event.node.data)

    def _show_detail(self, data: Any) -> None:
        self.selected = data
        heading = self.query_one("#heading", Static)
        found = self.query_one("#diagnostics", Static)
        source = self.query_one("#source", Static)
        catalogue = self.catalogue
        if catalogue is None:
            return
        if isinstance(data, tuple) and data and data[0] == "load_error":
            error = catalogue.load_errors[data[1]]
            heading.update(Text(relative(error.path, catalogue.repo), style="bold"))
            found.update(Text.assemble(("error[yaml_parse]:", "bold red"), f" {error.message}"))
            source.update(_yaml(error.path))
            return
        entry = catalogue.entries.get(data) if isinstance(data, str) else None
        if entry is None:
            heading.update(
                Text.assemble(
                    (catalogue.repo.name, "bold"),
                    "\n",
                    (summary_line(catalogue), "dim"),
                    "\n\nSelect an object to see its YAML and diagnostics.",
                )
            )
            found.update("")
            source.update("")
            return
        heading.update(
            Text.assemble(
                (entry.name, "bold"),
                (f"  {entry.kind}", "dim"),
                "\n",
                (entry.uuid, "dim"),
                "\n",
                relative(entry.path, catalogue.repo),
            )
        )
        diagnostics = [item for item in self.diagnostics if item.concerns(entry)]
        found.update(self._diagnostics_view(diagnostics, catalogue))
        source.update(_yaml(entry.path, {item.line for item in diagnostics if item.line}))

    def _diagnostics_view(
        self, diagnostics: list[Diagnostic], catalogue: Catalogue
    ) -> RenderableType:
        if not self.validated:
            return Text("Not validated yet: press v to run opentide validate.", style="dim")
        if not diagnostics:
            return Text.assemble(("✓", "bold green"), " No diagnostics from the last validate run")
        return Group(*(diagnostic_text(item, catalogue.repo) for item in diagnostics))

    def _fill_coverage(self, catalogue: Catalogue) -> None:
        table = self.query_one("#coverage-table", DataTable)
        table.clear()
        for row in catalogue.coverage:
            rules = [
                catalogue.entries[uuid].name for uuid in row.rules if uuid in catalogue.entries
            ]
            named = [
                catalogue.entries[uuid].name
                for uuid in row.referenced_by
                if uuid in catalogue.entries
            ]
            count = Text(str(len(row.rules)), style="" if row.rules else "bold red")
            table.add_row(
                row.technique,
                count,
                ", ".join(rules) or Text("no rule", style="dim"),
                ", ".join(named),
                key=row.technique,
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter on a technique opens the first rule that detects it."""
        if self.catalogue is None:
            return
        technique = event.row_key.value
        for row in self.catalogue.coverage:
            if row.technique == technique and row.rules:
                self.select(row.rules[0])
                return


def _yaml(path: Any, highlight: set[int] | None = None) -> RenderableType:
    """The object's file with line numbers; diagnostic lines are marked."""
    if path is None:
        return Text("The index does not record this object's file.", style="dim")
    try:
        code = path.read_text(encoding="utf-8")
    except OSError as exc:
        return Text(f"Cannot read {path}: {exc}", style="red")
    return Syntax(
        code,
        "yaml",
        line_numbers=True,
        highlight_lines=highlight or set(),
        background_color="default",
        word_wrap=True,
    )
