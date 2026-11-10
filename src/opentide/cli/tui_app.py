"""The Textual app behind ``opentide tui``.

The only module that imports Textual. :mod:`opentide.cli.commands.tui` imports
it when the UI opens, never for ``--help``, completion or a walk of the
command tree. What it shows and runs comes from
:mod:`opentide.cli.services.tui`; results print through
:func:`opentide.cli.output.render_result`, the renderer every command uses.
"""

from __future__ import annotations

import io
from collections.abc import Callable, Iterable, Mapping
from functools import partial
from pathlib import Path
from typing import Any, ClassVar, cast

from rich.cells import set_cell_size
from rich.console import Console, Group, RenderableType
from rich.style import Style
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from textual import events
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.theme import Theme
from textual.widgets import (
    Collapsible,
    DataTable,
    Footer,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)
from textual.widgets.tree import TreeNode
from textual.worker import Worker, WorkerState
from typing_extensions import Self

from opentide.cli.context import CliContext
from opentide.cli.output import render_result
from opentide.cli.services.object_view import FieldRow, LinkTarget, ObjectView
from opentide.cli.services.tui import (
    ACTIONS,
    ACTIONS_BY_NAME,
    ENGINE,
    Action,
    ActionOutcome,
    Catalogue,
    CatalogueEntry,
    Diagnostic,
    TechniqueCoverage,
    load_catalogue,
    plural,
    relative,
    run_action,
    summary_line,
)
from opentide.cli.tui_tabs.chains import ChainsPane
from opentide.cli.tui_tabs.configuration import ConfigurationPane
from opentide.cli.tui_tabs.visibility import VisibilityPane
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
_TAB_FOCUS = {
    "catalogue": "#tree",
    "coverage": "#coverage-table",
    "results": "#log",
    "visibility": "#vis-table",
    "configuration": "#config-files",
    "chains": "#chain-nodes",
}

_SEVERITY_STYLE = {"error": "bold red", "warning": "bold yellow", "note": "bold blue"}
_FRAME_STYLE = "blue"
#: How a finding's span is marked in the source pane, as an editor underlines it.
#: Rich cannot colour an underline apart from its text, so the severity is a
#: tint behind the span: the tokens keep their colours (#215).
_SPAN_STYLE = {"error": "underline bold", "warning": "underline", "note": "underline"}
_SPAN_TINT = {"error": "#5a1d1d", "warning": "#4a3f12", "note": "#1f2f4f"}
#: The gutter mark of a line with a finding, the worst one's.
_GUTTER_MARK = {"error": "✗", "warning": "!", "note": "·"}
_SEVERITY_RANK = {"error": 0, "warning": 1, "note": 2}
#: The key under which a finding span's style carries its index (Textual style ``meta``).
FINDING_META = "opentide.finding"


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
        if diagnostic.column is not None:
            where = f"{where}:{diagnostic.column}"
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


def status_text(result: Any) -> str:
    """The first line of what the CLI prints as *result*'s outcome: its counted line
    when it has one, else its message, else its status."""
    line = result.outcome or result.message or result.status
    return str(line).splitlines()[0] if line else ""


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
    if outcome.frames:
        from opentide.cli.ui.codeframe import render_diagnostics

        # The CLI's code frames (#641); PLAIN keeps them free of OSC 8 links,
        # and the query lines are coloured as at a terminal.
        render_diagnostics(console, outcome.frames, mode=OutputMode.PLAIN, highlight=True)
    if outcome.plan is not None:
        from opentide.cli.ui.plan import render_plan, render_plan_diagnostics

        # The plan view and compile frames a dry run prints (#643).
        plan = {**outcome.plan, "_summary": outcome.result.summary}
        render_plan(console, plan)
        render_plan_diagnostics(console, plan)
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
        Binding("y", "toggle_source", "YAML / page"),
        Binding("f", "follow_link", "Follow reference"),
        Binding("n", "next_finding", "Next finding"),
        Binding("p", "previous_finding", "Previous", show=False),
        Binding("1", "show_tab('catalogue')", "Catalogue", show=False),
        Binding("2", "show_tab('coverage')", "Coverage", show=False),
        Binding("3", "show_tab('results')", "Results", show=False),
        Binding("4", "show_tab('visibility')", "Visibility", show=False),
        Binding("5", "show_tab('configuration')", "Configuration", show=False),
        Binding("6", "show_tab('chains')", "Chains", show=False),
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
        #: The finding of the selected object that ``n`` and ``p`` moved to.
        self.current_finding: int | None = None
        #: Whether the detail pane shows the object's file rather than its page (``y``).
        self.raw = False
        #: The reference of the selected object ``f`` follows next.
        self.link_index = 0
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
                    yield Static("", id="object")
                    with Collapsible(title="Not set", id="unset", collapsed=True):
                        yield Static("", id="unset-list")
                    yield SourceView("", id="source")
            with TabPane("Coverage", id="coverage"):
                yield DataTable(id="coverage-table", cursor_type="row", zebra_stripes=True)
            with TabPane("Results", id="results"):
                yield RichLog(id="log", wrap=True, markup=False, highlight=False)
            with TabPane("Visibility", id="visibility"):
                yield VisibilityPane(self.select, id="visibility-pane")
            with TabPane("Configuration", id="configuration"):
                yield ConfigurationPane(self.select, id="configuration-pane")
            with TabPane("Chains", id="chains"):
                yield ChainsPane(self.select, id="chains-pane")
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
        if tab == "chains" and self.catalogue is not None:
            # The chain is drawn around the threat selected in the Catalogue.
            self.query_one(ChainsPane).show(self.catalogue, self.selected)
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
            unavailable = result.language_server.unavailable
            self._status(unavailable or "")
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
        if outcome.action.validates:
            self.diagnostics = outcome.diagnostics
            self.validated = True
        root = self.cli.repo
        self._log(Text(""))
        self._log(outcome_text(outcome, root))
        result = outcome.result
        severity = "error" if not result.ok else "warning" if result.warnings else "information"
        # The counted outcome the Results tab prints ("6 objects valid · 1.2s"),
        # not the JSON message ("Validation passed") (post-merge end-to-end run).
        said = status_text(result)
        self._status(f"{outcome.action.command}: {said}")
        self.notify(said, title=outcome.action.command, severity=severity)

    def _show_catalogue(self, catalogue: Catalogue) -> None:
        self.catalogue = catalogue
        self.summary = Text(f"{catalogue.repo.name} · {summary_line(catalogue)}")
        self.query_one("#summary", Static).update(self.summary)
        self._fit_masthead()
        self._fill_tree(catalogue)
        self._fill_coverage(catalogue)
        self.query_one(VisibilityPane).show(catalogue.visibility, catalogue)
        self.query_one(ConfigurationPane).show(catalogue.configuration, catalogue)
        self.query_one(ChainsPane).show(catalogue, self.selected)
        self._show_detail(self.selected)

    def findings(self, entry: CatalogueEntry) -> tuple[list[Diagnostic], list[Diagnostic]]:
        """What the language server reports for *entry*, and what the last validate run found.

        A validate finding the language server reports too (the same code on
        the same line) is shown once, as validate's: its help is the one
        ``opentide validate`` prints. The queries check's findings come
        from the same engine as the language server's, so they are left to it.
        """
        report = self.catalogue.language_server if self.catalogue else None
        validated = [
            item
            for item in self.diagnostics
            if item.concerns(entry)
            and not (item.source == ENGINE and report is not None and not report.unavailable)
        ]
        seen = {(item.code, item.line) for item in validated}
        live = [] if report is None else list(report.for_path(entry.path))
        return [item for item in live if (item.code, item.line) not in seen], validated

    def _counts(self, uuid: str) -> Text:
        """``✗ 2 ! 1`` after an object with errors or warnings, from the language
        server or the last validate run. Notes are not counted."""
        mark = Text()
        if self.catalogue is None:
            return mark
        entry = self.catalogue.entries[uuid]
        live, validated = self.findings(entry)
        found = [item for item in (*live, *validated) if item.severity != "note"]
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
            self.call_after_refresh(_move_cursor, tree, node)

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
        if data != self.selected:
            self.current_finding = None
            self.link_index = 0
            # `n` showed the file at a finding; another object opens on its page.
            self.raw = False
        self.selected = data
        heading = self.query_one("#heading", Static)
        found = self.query_one("#diagnostics", Static)
        source = self.query_one("#source", SourceView)
        catalogue = self.catalogue
        if catalogue is None:
            return
        if isinstance(data, tuple) and data and data[0] == "load_error":
            error = catalogue.load_errors[data[1]]
            heading.update(Text(relative(error.path, catalogue.repo), style="bold"))
            found.update(Text.assemble(("error[yaml_parse]:", "bold red"), f" {error.message}"))
            source.show(error.path, (), catalogue)
            self._show_page(None, None, (), catalogue)
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
            source.show(None, (), catalogue)
            self._show_page(None, None, (), catalogue)
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
        live, validated = self.findings(entry)
        found.update(self._diagnostics_view(live, validated, catalogue))
        source.show(entry.path, [*live, *validated], catalogue, self.current_finding)
        view = None if self.current_finding is not None else catalogue.object_view(entry.uuid)
        self._show_page(view, entry.path, [*live, *validated], catalogue)

    def _show_page(
        self,
        view: ObjectView | None,
        path: Path | None,
        findings: Iterable[Diagnostic],
        catalogue: Catalogue,
    ) -> None:
        """The object's page, or its file: ``y`` switches, ``n`` shows the file at a finding."""
        page = self.query_one("#object", Static)
        unset = self.query_one("#unset", Collapsible)
        source = self.query_one("#source", SourceView)
        show_page = view is not None and not self.raw
        page.display = show_page
        unset.display = show_page and bool(view and view.unset)
        source.display = not show_page
        if view is None:
            page.update("")
            return
        languages = _query_languages(catalogue, path)
        page.update(object_page(view, list(findings), languages))
        unset.title = f"Not set ({len(view.unset)})"
        self.query_one("#unset-list", Static).update(unset_fields(view))

    def action_toggle_source(self) -> None:
        """Switch the detail pane between the object's page and its file."""
        self.raw = not self.raw
        self.current_finding = None
        self._show_detail(self.selected)
        self._status("Showing the file" if self.raw else "Showing the object's page")

    def action_follow_link(self) -> None:
        """Open the next object or signal the selected object references."""
        catalogue = self.catalogue
        if catalogue is None or not isinstance(self.selected, str):
            return
        view = catalogue.object_view(self.selected)
        if view is None or not view.links:
            self._status("This object references nothing in the catalogue")
            return
        target = view.links[self.link_index % len(view.links)]
        self.link_index += 1
        if target.opens not in catalogue.entries:
            self._status(f"{target.name} is not in the catalogue")
            return
        self.select(target.opens)
        self._status(f"Opened {target.kind} {target.name}")

    def _diagnostics_view(
        self, live: list[Diagnostic], validated: list[Diagnostic], catalogue: Catalogue
    ) -> RenderableType:
        parts: list[RenderableType] = [Text("Language server", style="bold underline")]
        report = catalogue.language_server
        if report.unavailable:
            unavailable = Text(report.unavailable, style="dim")
            if report.advice:
                unavailable.append("\n  ╰─", style=_FRAME_STYLE)
                unavailable.append(" help:", style="bold cyan")
                unavailable.append(f" {report.advice}")
            parts.append(unavailable)
        elif live:
            parts.extend(_findings_summary(live, catalogue.repo))
        else:
            parts.append(Text.assemble(("✓", "bold green"), " Nothing to report"))
        parts.append(Text("\nLast validate run", style="bold underline"))
        if not self.validated:
            parts.append(Text("Not validated yet: press v to run opentide validate.", style="dim"))
        elif validated:
            parts.extend(_findings_summary(validated, catalogue.repo))
        else:
            parts.append(
                Text.assemble(("✓", "bold green"), " No diagnostics from the last validate run")
            )
        return Group(*parts)

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
            count = coverage_count(row)
            table.add_row(
                row.technique,
                count,
                ", ".join(rules) or Text("no rule", style="dim"),
                ", ".join(named),
                key=row.technique,
            )

    def action_next_finding(self) -> None:
        self._move_finding(1)

    def action_previous_finding(self) -> None:
        self._move_finding(-1)

    def _move_finding(self, step: int) -> None:
        """Go to the selected object's next (or previous) finding in its source.

        The source scrolls to the finding's line, its annotation is marked, and
        the status line carries its message and the hover for its span: the
        keyboard reaches what the mouse's tooltip shows (#215).
        """
        source = self.query_one("#source", SourceView)
        if not source.findings:
            self._status("No findings on this object")
            return
        self.action_show_tab("catalogue")
        count = len(source.findings)
        # A finding is read at its line, in the file.
        self.raw = True
        if self.current_finding is None:
            self.current_finding = 0 if step > 0 else count - 1
        else:
            self.current_finding = (self.current_finding + step) % count
        self._show_detail(self.selected)
        finding = source.findings[self.current_finding]
        hover = source.hover_for(self.current_finding)
        position = f"{self.current_finding + 1}/{count}"
        said = f"{position} {finding.severity}[{finding.code}]: {finding.message}"
        if hover:
            said = f"{said} · {_first_line(hover)}"
        self._status(said)
        self.call_after_refresh(self._scroll_to_finding)

    def _scroll_to_finding(self) -> None:
        source = self.query_one("#source", SourceView)
        row = source.marked_row()
        if row is None:
            return
        detail = self.query_one("#detail", VerticalScroll)
        top = source.virtual_region.y + row
        detail.scroll_to(y=max(top - 3, 0), animate=False)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter on a technique opens the first rule that detects it."""
        if self.catalogue is None:
            return
        technique = event.row_key.value
        for row in self.catalogue.coverage:
            if row.technique == technique and row.rules:
                self.select(row.rules[0])
                return


def _move_cursor(tree: Tree[Any], node: TreeNode[Any]) -> None:
    """Put *tree*'s cursor on *node*, laying the tree's lines out first.

    ``Tree`` lays its lines out lazily, on its own idle or render, and a node
    added since has line -1 until then. The screen may run this callback before
    the tree's idle; ``move_cursor`` would then clamp -1 to line 0 and highlight
    the first threat instead of the object that was selected. ``last_line``
    lays the lines out. A node still without a line sits under a collapsed
    ancestor and is not shown: leave the cursor where it is. The tree the TUI
    builds expands every branch, so this guard is defensive; a test reaches it
    with a collapsed branch.
    """
    if tree.last_line >= 0 and node.line >= 0:
        tree.move_cursor(node)


def coverage_count(row: TechniqueCoverage) -> Text:
    """``13  0 own · 13 inherited``: how many rules cover a technique, and how.

    A rule that lists the technique is a stronger claim than one whose
    objective does, so the split is shown; ``0`` in red is a gap.
    """
    if not row.rules:
        return Text("0", style="bold red")
    return Text.assemble(
        str(len(row.rules)),
        (f"  {len(row.own)} own · {len(row.inherited)} inherited", "dim"),
    )


#: A severity value's badge colours (background).
_SEVERITY_BADGE = {
    "critical": "#8b0000",
    "high": "#b03a00",
    "medium": "#8a6d00",
    "low": "#1f4f7a",
    "informational": "#3a3a3a",
}
#: A TLP's badge colours (foreground, background), as FIRST draws them.
_TLP_BADGE = {
    "clear": ("#000000", "#ffffff"),
    "green": ("#000000", "#33ff00"),
    "amber": ("#000000", "#ffc000"),
    "amber+strict": ("#000000", "#ffc000"),
    "red": ("#ffffff", "#ff2b2b"),
}


def _badge(text: str, foreground: str, background: str) -> Text:
    return Text(f" {text} ", style=Style(color=foreground, bgcolor=background, bold=True))


def severity_badge(value: str) -> Text:
    """*value* as a badge coloured by its severity (``High`` on deep orange)."""
    return _badge(value, WHITE, _SEVERITY_BADGE.get(value.lower(), "#3a3a3a"))


def tlp_badge(value: str) -> Text:
    """``TLP:AMBER`` in FIRST's colours."""
    foreground, background = _TLP_BADGE.get(value.lower(), (WHITE, "#3a3a3a"))
    return _badge(f"TLP:{value.upper()}", foreground, background)


def _query_languages(catalogue: Catalogue, path: Path | None) -> dict[str, str]:
    """Each query's field path in the object, to its language, as the engine reads them."""
    workspace = catalogue.language_server.workspace
    if path is None or workspace is None:
        return {}
    try:
        text = path.read_text(encoding="utf-8-sig")
        reports = workspace.analyze_queries(text)
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    return {".".join(report.field_path): str(report.language) for report in reports}


def _link_text(target: LinkTarget) -> Text:
    """``→ Name  objective`` that opens the object when clicked."""
    text = Text()
    text.append("→ ", style="bold")
    text.append(
        target.name,
        style=Style(bold=True, underline=True, meta={"@click": f"app.select({target.opens!r})"}),
    )
    text.append(f"  {target.kind}", style="dim")
    return text


def _value_text(row: FieldRow) -> Text:
    """A value as the page shows it: badges, links, and what a vocabulary value means."""
    text = Text()
    for index, value in enumerate(row.values):
        if index:
            text.append("\n")
        target = row.links[index] if index < len(row.links) else None
        meaning = row.meanings[index] if index < len(row.meanings) else ""
        if target is not None:
            text.append_text(_link_text(target))
            text.append(f"  {value}", style="dim")
            continue
        shown = str(value).rstrip("\n")
        if row.severity and isinstance(value, str):
            text.append_text(severity_badge(value))
        elif isinstance(value, bool):
            text.append("yes" if value else "no", style="bold green" if value else "bold red")
        else:
            text.append(shown)
        if meaning:
            text.append(f"  {meaning}", style="dim italic")
    if not row.values:
        text.append("—", style="dim")
    return text


def _query_panel(row: FieldRow, language: str | None) -> RenderableType:
    """A query in its own panel, coloured in its language by the engine."""
    from rich.panel import Panel

    code = str(row.value).rstrip("\n")
    body: RenderableType = Text(code)
    if language:
        from opentide.analysis import EngineUnavailableError, highlight
        from opentide.cli.ui.codeframe import SOURCE_STYLES

        try:
            tokens = highlight(code, language)
        except (EngineUnavailableError, ValueError):
            tokens = []
        text = Text(code)
        starts = _line_starts(code)
        for token in tokens:
            style = SOURCE_STYLES.get(token.capture)
            if style and 0 < token.line <= len(starts) and 0 < token.end_line <= len(starts):
                text.stylize(
                    style,
                    starts[token.line - 1] + token.column - 1,
                    starts[token.end_line - 1] + token.end_column - 1,
                )
        body = text
    title = f"{row.path.split('.', 2)[1] if row.path.startswith('configurations.') else row.title}"
    return Panel(
        body,
        title=Text.assemble((title, "bold"), (f"  {language or 'query'}", "dim")),
        title_align="left",
        border_style="bright_black",
        expand=True,
    )


def object_page(
    view: ObjectView, findings: list[Diagnostic], languages: Mapping[str, str]
) -> RenderableType:
    """An object as a page: a header, a section per top-level field, queries in panels.

    A field with a finding is marked under its value, as the file marks its
    line. Links open the object they name (click, or ``f``).
    """
    from rich.rule import Rule

    parts: list[RenderableType] = []
    header = view.header
    facts = Text()
    if header.get("version"):
        facts.append(f"v{header['version']}", style="bold")
    for label in ("created", "modified"):
        if header.get(label):
            facts.append(f"  {label} {header[label]}", style="dim")
    if header.get("tlp"):
        facts.append("  ")
        facts.append_text(tlp_badge(header["tlp"]))
        if view.tlp_meaning:
            facts.append(f"  {view.tlp_meaning}", style="dim italic")
    parts.append(facts)
    if header.get("schema"):
        parts.append(Text(header["schema"], style="dim"))
    if view.unknown_schema:
        parts.append(Text(view.unknown_schema, style="yellow"))
    by_path: dict[str, list[Diagnostic]] = {}
    for item in findings:
        if item.field_path:
            by_path.setdefault(".".join(item.field_path), []).append(item)
    for section in view.sections:
        parts.append(Text(""))
        parts.append(Rule(Text(section.title, style="bold"), align="left", style="bright_black"))
        if section.description:
            parts.append(Text(section.description, style="dim italic"))
        grid = Table.grid(padding=(0, 2))
        grid.add_column(no_wrap=True, max_width=36)
        grid.add_column(ratio=1, overflow="fold")
        queries: list[RenderableType] = []
        for row in section.rows:
            indent = "  " * row.depth
            if row.kind == "value" and (
                row.path in languages
                or (row.path.startswith("configurations.") and row.path.endswith(".query"))
            ):
                queries.append(_query_panel(row, languages.get(row.path)))
                queries.extend(_annotation(item, False) for item in by_path.get(row.path, ()))
                continue
            if row.kind == "group":
                grid.add_row(
                    Text(f"{indent}{row.title}", style="bold"),
                    Text(row.description, style="dim italic"),
                )
            elif row.kind == "item":
                grid.add_row(Text(f"{indent}{row.title}", style="bold cyan"), Text(""))
            else:
                grid.add_row(Text(f"{indent}{row.title}", style="bold"), _value_text(row))
            for item in by_path.get(row.path, ()):
                grid.add_row(Text(""), _annotation(item, False))
        parts.append(grid)
        parts.extend(queries)
    return Group(*parts)


def unset_fields(view: ObjectView) -> RenderableType:
    """The optional fields the object's revision allows and it does not set, with what each is."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(ratio=1, overflow="fold")
    for item in view.unset:
        label = Text(item.path, style="bold")
        if item.recommended:
            label.append(" ★", style="yellow")
        about = Text(item.description or item.title, style="dim")
        if item.choices:
            about.append(f"\none of: {', '.join(item.choices[:8])}", style="dim italic")
            if len(item.choices) > 8:
                about.append(" …", style="dim italic")
        grid.add_row(label, about)
    return grid


def _first_line(markdown: str) -> str:
    """The first line of hover Markdown with its emphasis marks dropped, for the status line."""
    line = next((part for part in markdown.splitlines() if part.strip()), "")
    return line.replace("**", "").replace("`", "").strip()


def _findings_summary(findings: list[Diagnostic], root: Path) -> list[RenderableType]:
    """``✗ 1  ! 2`` and how to reach them; a finding with no line is shown in full.

    A finding with a line is shown in the source, under the line it is about
    (#215), so only its count is here.
    """
    placed = [item for item in findings if item.line is not None]
    loose = [item for item in findings if item.line is None]
    parts: list[RenderableType] = []
    if placed:
        summary = Text()
        errors = sum(1 for item in placed if item.severity == "error")
        warnings = sum(1 for item in placed if item.severity == "warning")
        notes = len(placed) - errors - warnings
        for count, mark, style in (
            (errors, "✗", "bold red"),
            (warnings, "!", "bold yellow"),
            (notes, "·", "bold blue"),
        ):
            if count:
                summary.append(f"{mark} {count}  ", style=style)
        lines = sorted({item.line for item in placed if item.line is not None})
        where = ", ".join(str(line) for line in lines[:6]) + (" …" if len(lines) > 6 else "")
        summary.append(f"on line{'s' if len(lines) > 1 else ''} {where}", style="dim")
        summary.append("  · n next finding, p previous", style="dim")
        parts.append(summary)
    parts.extend(diagnostic_text(item, root) for item in loose)
    return parts


def source_view(
    path: Any,
    diagnostics: Iterable[Diagnostic] = (),
    current: int | None = None,
) -> tuple[RenderableType, list[Diagnostic]]:
    """The object's file with line numbers, coloured as the editor colours it,
    each finding in place: and the findings, in the order the view numbers them.

    The language server's tokens colour the YAML and the queries inside it;
    without the engine the file is coloured as plain YAML. A finding with a
    column is underlined on its span, with a severity tint behind it, and its
    style carries ``meta`` naming it, which the source pane's tooltip reads.
    Under each line with findings, an annotation gives each one's code,
    message and help, so a finding is read at its own line (#215). The
    finding *current* (``n``/``p``) is marked ``▶``.

    A line is one cell of a grid, so a long line wraps inside its cell and an
    underline stays on its own characters.
    """
    if path is None:
        return Text("The index does not record this object's file.", style="dim"), []
    try:
        code = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        return Text(f"Cannot read {path}: {exc}", style="red"), []
    findings = sorted(
        (item for item in diagnostics if item.line is not None),
        key=lambda item: (item.line or 0, item.column or 0, _SEVERITY_RANK.get(item.severity, 3)),
    )
    text = _highlighted(path, code)
    starts = _line_starts(code)
    for index, item in enumerate(findings):
        span = _span(code, starts, item)
        if span is None:
            continue
        style = Style.parse(_SPAN_STYLE.get(item.severity, "underline")) + Style(
            bgcolor=_SPAN_TINT.get(item.severity), meta={FINDING_META: index}
        )
        text.stylize(style, *span)
    lines = text.split("\n", allow_blank=True)
    if code.endswith("\n") and lines and not lines[-1].plain:
        lines = lines[:-1]
    by_line: dict[int, list[int]] = {}
    for index, item in enumerate(findings):
        by_line.setdefault(item.line or 0, []).append(index)
    grid = Table.grid(padding=(0, 1))
    grid.add_column(justify="right", no_wrap=True, style="dim")
    grid.add_column(width=1, no_wrap=True)
    grid.add_column(ratio=1, overflow="fold")
    for number, line in enumerate(lines, start=1):
        marked = by_line.get(number, [])
        mark = Text()
        if marked:
            worst = min(
                (findings[i] for i in marked), key=lambda d: _SEVERITY_RANK.get(d.severity, 3)
            )
            mark = Text(
                _GUTTER_MARK.get(worst.severity, "·"),
                style=_SEVERITY_STYLE.get(worst.severity, "bold"),
            )
        grid.add_row(Text(str(number)), mark, line)
        for index in marked:
            grid.add_row(Text(""), Text(""), _annotation(findings[index], index == current))
    return grid, findings


def _annotation(item: Diagnostic, current: bool) -> Text:
    """``╰─ error[code]: message · help: …`` under the line a finding is about."""
    text = Text()
    text.append("▶ " if current else "╰─ ", style="bold reverse" if current else _FRAME_STYLE)
    text.append(f"{item.severity}[{item.code}]", style=_SEVERITY_STYLE.get(item.severity, "bold"))
    text.append(f": {item.message}")
    help_text = item.help_text()
    if help_text:
        text.append(" · ", style="dim")
        text.append("help:", style="bold cyan")
        text.append(f" {help_text}")
    return text


def _line_starts(code: str) -> list[int]:
    """The offset in *code* where each line starts."""
    starts = [0]
    starts.extend(index + 1 for index, char in enumerate(code) if char == "\n")
    return starts


def _span(code: str, starts: list[int], item: Diagnostic) -> tuple[int, int] | None:
    """*item*'s span as offsets into *code*, on its line; ``None`` without a column."""
    if item.line is None or item.column is None or not 0 < item.line <= len(starts):
        return None
    start = starts[item.line - 1]
    line_end = starts[item.line] - 1 if item.line < len(starts) else len(code)
    begin = min(start + item.column - 1, line_end)
    end = line_end if item.end_column is None else min(start + item.end_column - 1, line_end)
    return (begin, max(end, begin + 1)) if begin < line_end else None


def _highlighted(path: Path, code: str) -> Text:
    """*code* coloured by the engine's tokens, else as plain YAML."""
    tokens = _tokens(path, code)
    if tokens is None:
        return Syntax(code, "yaml", background_color="default").highlight(code).copy()
    text = Text(code)
    starts = _line_starts(code)
    for line, column, end_line, end_column, style in tokens:
        if 0 < line <= len(starts) and 0 < end_line <= len(starts):
            text.stylize(
                style, starts[line - 1] + column - 1, starts[end_line - 1] + end_column - 1
            )
    return text


class SourceView(Static):
    """The source pane: the file with its findings in place, and a tooltip on each span.

    Hovering a finding's span shows its frame and what an editor's hover
    shows there (the field's description, the object a UUID names). Not
    every terminal reports the mouse: ``n`` and ``p`` reach the same
    content from the keyboard.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.findings: list[Diagnostic] = []
        self.path: Path | None = None
        self.code = ""
        self.catalogue: Catalogue | None = None
        self.current: int | None = None
        self._tooltip_for: int | None = None
        self._renderable: RenderableType = ""

    def show(
        self,
        path: Path | None,
        diagnostics: Iterable[Diagnostic],
        catalogue: Catalogue,
        current: int | None = None,
    ) -> None:
        self.path = path
        self.catalogue = catalogue
        self.current = current
        try:
            self.code = path.read_text(encoding="utf-8-sig") if path is not None else ""
        except (OSError, UnicodeDecodeError):
            self.code = ""
        if path is None and not list(diagnostics):
            self.findings = []
            self.update("")
            return
        self._renderable, self.findings = source_view(path, diagnostics, current)
        self._tooltip_for = None
        self.tooltip = None
        self.update(self._renderable)

    def hover_for(self, index: int) -> str | None:
        """The engine's hover at the start of finding *index*'s span."""
        if self.catalogue is None or not 0 <= index < len(self.findings):
            return None
        item = self.findings[index]
        if item.line is None:
            return None
        return self.catalogue.language_server.hover(
            self.path, self.code, item.line, item.column or 1
        )

    def tooltip_text(self, index: int) -> Text:
        """The tooltip of finding *index*: its frame, then the hover at its span."""
        item = self.findings[index]
        root = self.catalogue.repo if self.catalogue is not None else Path.cwd()
        text = diagnostic_text(item, root)
        hover = self.hover_for(index)
        if hover:
            text.append("\n\n")
            text.append(hover.replace("**", "").replace("`", ""), style="dim")
        return text

    def on_mouse_move(self, event: events.MouseMove) -> None:
        index = event.style.meta.get(FINDING_META) if event.style else None
        if index == self._tooltip_for:
            return
        self._tooltip_for = index
        if isinstance(index, int) and 0 <= index < len(self.findings):
            self.tooltip = self.tooltip_text(index)
        else:
            self.tooltip = None

    def marked_row(self) -> int | None:
        """The rendered row of the current finding's annotation, for scrolling to it."""
        if self.current is None:
            return None
        width = max(self.content_region.width, 20)
        lines = self.app.console.render_lines(
            self._renderable, self.app.console.options.update_width(width), pad=False
        )
        for row, segments in enumerate(lines):
            if "▶ " in "".join(segment.text for segment in segments):
                return row
        return None


def _tokens(path: Path, code: str) -> list[tuple[int, int, int, int, str]] | None:
    """The engine's tokens for *code* as ``(line, column, end_line, end_column, style)``.

    ``None`` when the engine does not load or does not know the file's
    language: the caller falls back to plain YAML colours.
    """
    from opentide.analysis import EngineUnavailableError, highlight, language_for_path
    from opentide.cli.ui.codeframe import SOURCE_STYLES

    try:
        language = language_for_path(path)
        if language is None:
            return None
        found = highlight(code, language)
    except (EngineUnavailableError, ValueError):
        return None
    return [
        (token.line, token.column, token.end_line, token.end_column, style)
        for token in found
        if (style := SOURCE_STYLES.get(token.capture))
    ]
