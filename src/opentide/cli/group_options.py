"""Options typed on a command group before the subcommand.

A group callback returned as soon as a subcommand was named, so the group's
own options were dropped without a word: ``opentide share --dry-run push``
pushed, and ``opentide deploy --dry-run migrate-state`` edited rule files.
``opentide setup`` solves the same problem for its ``--path`` and ``--yes``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import typer
from typer.core import TyperGroup

if TYPE_CHECKING:
    from typer._click.core import Parameter

# `ctx.meta` is one dict shared by a group's context and its subcommand's.
_HANDED_DOWN = "opentide.group_options"


@dataclass(frozen=True)
class _HandedDown:
    group: str
    forwarded: frozenset[str]
    refused: tuple[str, ...]


def _typed(ctx: typer.Context, name: str) -> bool:
    # Compared by name: Typer vendors Click, so the ParameterSource enum lives in
    # a private module whose path is not part of Typer's API.
    source = ctx.get_parameter_source(name)
    return source is not None and source.name == "COMMANDLINE"


def _flags(param: Parameter) -> str:
    return "/".join([*param.opts, *param.secondary_opts])


def _signature(param: Parameter) -> tuple[str | None, str]:
    return param.name, _flags(param)


def hand_down(ctx: typer.Context) -> None:
    """Pass the options typed on this group to the subcommand that takes them too.

    Call from a group callback once ``ctx.invoked_subcommand`` is set. Click
    runs that callback before it parses the subcommand, so an option the
    subcommand also takes becomes its default. The rest are refused by
    :func:`refuse_dropped`, which the subcommand calls once it has parsed
    its own ``--help``.
    """
    name = ctx.invoked_subcommand
    group = ctx.command
    if name is None or not isinstance(group, TyperGroup):
        return
    subcommand = group.get_command(ctx, name)
    accepted = {_signature(param) for param in subcommand.params} if subcommand else set()
    forwarded: dict[str, object] = {}
    refused: list[str] = []
    for param in group.params:
        if not param.name or not _typed(ctx, param.name):
            continue
        if _signature(param) in accepted:
            forwarded[param.name] = ctx.params[param.name]
        else:
            refused.append(_flags(param))
    if forwarded:
        ctx.default_map = {**(ctx.default_map or {}), name: forwarded}
    handed: dict[tuple[str, str], _HandedDown] = ctx.meta.setdefault(_HANDED_DOWN, {})
    handed[ctx.command_path, name] = _HandedDown(
        group=ctx.command_path, forwarded=frozenset(forwarded), refused=tuple(refused)
    )


def refuse_dropped(ctx: typer.Context) -> None:
    """Refuse group options this subcommand would ignore, or that it was given twice."""
    if ctx.parent is None or ctx.info_name is None:
        return
    key = (ctx.parent.command_path, ctx.info_name)
    handed: _HandedDown | None = ctx.meta.get(_HANDED_DOWN, {}).get(key)
    if handed is None:
        return
    if handed.refused:
        verb = "configures" if len(handed.refused) == 1 else "configure"
        raise typer.BadParameter(
            f"{', '.join(handed.refused)} {verb} `{handed.group}` itself and would be "
            f"ignored by `{ctx.command_path}`."
        )
    twice = [
        _flags(param)
        for param in ctx.command.params
        if param.name in handed.forwarded and _typed(ctx, param.name)
    ]
    if twice:
        raise typer.BadParameter(
            f"Pass {', '.join(twice)} once, before or after `{ctx.info_name}`, "
            f"not both: `{ctx.command_path}` would use only the second."
        )
