"""Root command group that imports a command's module only when it runs."""

from __future__ import annotations

import importlib
from collections.abc import Iterator, MutableMapping
from contextlib import contextmanager
from typing import Any

import typer
from typer import _click
from typer.core import TyperCommand, TyperGroup

from opentide.cli.commands import ROOT_COMMANDS, CommandSpec


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
        self._loaded[spec.name] = command
        return command

    def format_help(self, ctx: _click.Context, formatter: _click.HelpFormatter) -> None:
        with self._list_from_index():
            super().format_help(ctx, formatter)

    def shell_complete(self, ctx: _click.Context, incomplete: str) -> list[Any]:
        with self._list_from_index():
            return super().shell_complete(ctx, incomplete)


def _describe(spec: CommandSpec) -> _click.Command:
    """A stand-in carrying only what a listing reads: name, help, hidden, panel."""
    return TyperCommand(
        spec.name, help=spec.help, hidden=spec.hidden, rich_help_panel=spec.rich_help_panel
    )
