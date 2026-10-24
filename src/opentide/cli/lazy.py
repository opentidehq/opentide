"""Root command group that imports a command's module only when it runs.

It also owns two things every command shares: the boolean root flags are
accepted anywhere before ``--`` (:func:`hoist_root_flags`), and Click usage
errors render through the output contract (:mod:`opentide.cli.usage`).
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator, MutableMapping, Sequence
from contextlib import contextmanager
from typing import Any, NoReturn

import typer
from typer import _click
from typer.core import TyperCommand, TyperGroup

from opentide.cli.commands import ROOT_COMMANDS, CommandSpec

#: Boolean root options that may follow the command: ``opentide validate --json``.
#: Value-taking root options (``--repo``, ``--data``, ``--proxy``) stay before it.
HOISTED_FLAGS = frozenset({"--json", "--no-color", "--debug", "--quiet"})

#: ``ctx.meta`` key for the leading words of the command line, ``("mcp", "start")``.
COMMAND_WORDS_KEY = "opentide.command_words"


class _Commands(MutableMapping[str, Any]):
    """``TyperGroup.commands`` whose indexed values load on first access.

    Typer reads the keys for "Did you mean" suggestions; reading them must not
    import every command. Commands added at runtime take precedence.
    """

    def __init__(self, group: LazyTyperGroup, added: MutableMapping[str, Any]) -> None:
        self._group = group
        self.added = dict(added)

    def __getitem__(self, name: str) -> Any:
        if name in self.added:
            return self.added[name]
        spec = self._group.specs.get(name)
        if spec is None:
            raise KeyError(name)
        return self._group.load(spec)

    def __setitem__(self, name: str, command: Any) -> None:
        self.added[name] = command

    def __delitem__(self, name: str) -> None:
        del self.added[name]

    def __iter__(self) -> Iterator[str]:
        yield from self._group.specs
        yield from (name for name in self.added if name not in self._group.specs)

    def __len__(self) -> int:
        return sum(1 for _ in self)


class LazyTyperGroup(TyperGroup):
    """The ``opentide`` group: its commands come from :data:`ROOT_COMMANDS`.

    Help and completion list the commands from the index without importing
    them. Running a command, or asking for its own help, imports its module
    and builds it the way ``add_typer`` or ``command`` would have.
    """

    def __init__(self, **attrs: Any) -> None:
        added = attrs.pop("commands", None) or {}
        super().__init__(**attrs)
        self.specs: dict[str, CommandSpec] = {spec.name: spec for spec in ROOT_COMMANDS}
        self.commands: _Commands = _Commands(self, added)
        self._loaded: dict[str, _click.Command] = {}
        self._listing = 0

    @contextmanager
    def _list_from_index(self) -> Iterator[None]:
        self._listing += 1
        try:
            yield
        finally:
            self._listing -= 1

    def list_commands(self, ctx: _click.Context) -> list[str]:
        return list(self.commands)

    def main(
        self,
        args: Sequence[str] | None = None,
        prog_name: str | None = None,
        complete_var: str | None = None,
        standalone_mode: bool = True,
        **extra: Any,
    ) -> Any:
        from opentide.cli.ui.mode import resolve_mode, set_mode, start_clock

        argv = list(sys.argv[1:] if args is None else args)
        # A first guess, for usage errors Click raises before the root callback
        # resolves the mode properly from the parsed flags.
        options = argv[: argv.index("--")] if "--" in argv else argv
        if "--no-color" in options:
            # A usage error is printed before the root callback configures the
            # consoles; it has to honour --no-color too, FORCE_COLOR or not.
            from opentide.core.logging import LoggingConfig, init_logging

            init_logging(LoggingConfig(plain=True), force=True)
        start_clock()
        set_mode(
            resolve_mode(
                json_flag="--json" in options,
                no_color="--no-color" in options,
                command=_leading_words(self, argv),
            )
        )
        return super().main(
            args=args,
            prog_name=prog_name,
            complete_var=complete_var,
            standalone_mode=standalone_mode,
            **extra,
        )

    def parse_args(self, ctx: _click.Context, args: list[str]) -> list[str]:
        if not args and not ctx.resilient_parsing and _show_home():
            ctx.exit(0)
        args = hoist_root_flags(self, ctx, args)
        ctx.meta[COMMAND_WORDS_KEY] = _leading_words(self, args)
        return super().parse_args(ctx, args)

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: _click.Context | None = None,
        **extra: Any,
    ) -> _click.Context:
        try:
            return super().make_context(info_name, args, parent=parent, **extra)
        except _click.exceptions.UsageError as error:
            _usage_error(error)

    def invoke(self, ctx: _click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except _click.exceptions.UsageError as error:
            _usage_error(error)

    def get_command(self, ctx: _click.Context, cmd_name: str) -> _click.Command | None:
        if self._listing and cmd_name in self.specs and cmd_name not in self.commands.added:
            return _describe(self.specs[cmd_name])
        return self.commands.get(cmd_name)

    def load(self, spec: CommandSpec) -> _click.Command:
        """Import the module behind *spec* and build its Click command, once."""
        command = self._loaded.get(spec.name)
        if command is not None:
            return command
        target = getattr(importlib.import_module(spec.module), spec.attribute)
        # A throwaway parent with the root's settings, so the command is built
        # exactly as `app.add_typer(...)` or `@app.command(...)` on the root would.
        holder = typer.Typer(
            rich_markup_mode=self.rich_markup_mode,
            suggest_commands=self.suggest_commands,
        )
        panel: dict[str, Any] = {}
        if spec.rich_help_panel:
            panel["rich_help_panel"] = spec.rich_help_panel
        if isinstance(target, typer.Typer):
            holder.add_typer(target, name=spec.name, **panel)
        else:
            holder.command(spec.name, **panel)(target)
        command = typer.main.get_group(holder).commands[spec.name]
        from opentide.cli.help import decorate

        decorate(command, spec.name)
        self._loaded[spec.name] = command
        return command

    def format_help(self, ctx: _click.Context, formatter: _click.HelpFormatter) -> None:
        with self._list_from_index():
            super().format_help(ctx, formatter)

    def shell_complete(self, ctx: _click.Context, incomplete: str) -> list[Any]:
        with self._list_from_index():
            return super().shell_complete(ctx, incomplete)


def _show_home() -> bool:
    """Draw the home screen for a bare ``opentide`` in ``human`` mode.

    Every other mode, and a home screen that fails to gather its facts, falls
    back to the help ``no_args_is_help`` prints.
    """
    from opentide.cli.ui.mode import OutputMode, get_mode

    if get_mode() is not OutputMode.HUMAN:
        return False
    from opentide import __version__
    from opentide.cli.ui.home import gather, render_home
    from opentide.core.logging.config import get_stdout_console

    try:
        facts = gather(__version__)
    except Exception:  # noqa: BLE001 -- the help is always a correct answer
        return False
    render_home(get_stdout_console(), facts)
    return True


def _usage_error(error: _click.exceptions.UsageError) -> NoReturn:
    """Render a usage error through the contract, then exit 2.

    ``no_args_is_help`` raises a usage error too; it carries the help text and
    goes to Typer unchanged.
    """
    if isinstance(error, _click.exceptions.NoArgsIsHelpError):
        raise error
    from opentide.cli.usage import render_usage_error

    raise typer.Exit(render_usage_error(error))


def _option_lookup(command: Any) -> dict[str, Any]:
    lookup: dict[str, Any] = {}
    for param in getattr(command, "params", ()):
        if getattr(param, "param_type_name", "") != "option":
            continue
        for opt in (*param.opts, *param.secondary_opts):
            lookup[opt] = param
    return lookup


def _takes_value(param: Any) -> bool:
    return not (getattr(param, "is_flag", False) or getattr(param, "count", False))


def _root_options_end(group: Any, args: Sequence[str]) -> int:
    """Index of the first token after the root's own options: the command, or ``--``."""
    lookup = _option_lookup(group)
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--" or token == "-" or not token.startswith("-"):
            return index
        name, separator, _ = token.partition("=")
        param = lookup.get(name)
        index += 2 if param is not None and _takes_value(param) and not separator else 1
    return index


def _leading_words(group: Any, args: Sequence[str]) -> tuple[str, ...]:
    """The command words before the first option: ``("validate", "query")``."""
    words: list[str] = []
    for token in args[_root_options_end(group, args) :]:
        if token.startswith("-"):
            break
        words.append(token)
    return tuple(words)


def hoist_root_flags(group: Any, ctx: _click.Context, args: list[str]) -> list[str]:
    """Move :data:`HOISTED_FLAGS` typed after the command in front of it.

    Walks the command path so a token that is the value of the preceding
    option stays where it is (``--query --json`` searches for ``--json``), and
    leaves a flag alone when the command it follows defines it itself.
    Nothing after ``--`` moves. A command is imported only when one of these
    flags follows it.
    """
    start = _root_options_end(group, args)
    end = args.index("--") if "--" in args else len(args)
    if start >= end or not any(token in HOISTED_FLAGS for token in args[start + 1 : end]):
        return args
    hoisted: list[str] = []
    kept: list[str] = [args[start]]
    command = group.get_command(ctx, args[start])
    index = start + 1
    while index < end:
        token = args[index]
        index += 1
        lookup = _option_lookup(command)
        if token in HOISTED_FLAGS and token not in lookup:
            hoisted.append(token)
            continue
        kept.append(token)
        if token.startswith("-") and token != "-":
            name, separator, _ = token.partition("=")
            param = lookup.get(name)
            if param is not None and _takes_value(param) and not separator and index < end:
                kept.append(args[index])
                index += 1
            continue
        get_command = getattr(command, "get_command", None)
        if callable(get_command):
            sub = get_command(ctx, token)
            if sub is not None:
                command = sub
    return [*hoisted, *args[:start], *kept, *args[end:]]


def _describe(spec: CommandSpec) -> _click.Command:
    """A stand-in carrying only what a listing reads: name, help, hidden, panel."""
    return TyperCommand(
        spec.name, help=spec.help, hidden=spec.hidden, rich_help_panel=spec.rich_help_panel
    )
