"""One line per rule while a deploy runs: what was sent, how long it took, why one failed.

::

    Deploying to sentinel / contoso · 91 rules
      [ 1/91] ✓ deployed  Suspicious PowerShell encoded command        0.9s
      [ 2/91] ✗ failed    Rare process spawned by Office app           HTTP 400: Failed to parse
      [ 3/91] · skipped   Password spray from a single IP              not attempted after a failure

Lines are append-only and flushed as each rule finishes, so a CI log shows
progress and a hung platform shows which rule it is stuck on (the last line is
the last rule that finished). In ``human`` mode the running rule is also the
detail of the live checklist row, replaced by its line when it finishes. There
is no carriage return and no spinner frame in a log, in ``plain`` or ``agent``
mode. ``json`` and ``mcp`` print nothing: the result's ``results`` carries the
same rows.
"""

from __future__ import annotations

import textwrap
from collections import Counter
from collections.abc import Sequence
from typing import TYPE_CHECKING

from rich.text import Text

from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.progress import Checklist, plural, seconds_text
from opentide.core.deploy_events import RuleResult, RuleStatus

if TYPE_CHECKING:
    from opentide.cli.services.deploy_plan import PlannedChange

#: What a rule that was sent is called, by planned action. ``upsert`` is a write that
#: may create or update: opentide does not claim which.
_VERBS = {
    "create": "created",
    "update": "updated",
    "upsert": "deployed",
    "disable": "disabled",
    "delete": "deleted",
}

#: Longest rule name padded into a column; a longer one pushes its detail right.
NAME_WIDTH = 48

#: A wrapped error never gets narrower than this, nor longer than this many lines.
MIN_ERROR_WIDTH = 30
MAX_ERROR_LINES = 4

#: The wording of a rule an earlier failure kept from running.
NOT_ATTEMPTED = "not attempted after a failure"

Key = tuple[str, str | None]


def verb(result: RuleResult) -> str:
    """``created``, ``updated``, ``deployed``… for a sent rule, else ``failed`` or ``skipped``."""
    if result.status == "deployed":
        return _VERBS.get(result.action or "", "deployed")
    return "skipped" if result.status in ("skipped", "not_attempted") else "failed"


def result_line(
    result: RuleResult,
    *,
    index: int,
    total: int,
    name_width: int = NAME_WIDTH,
    encoding: str = "utf-8",
    width: int | None = None,
) -> Text:
    """``  [ 2/91] ✓ updated   <name>   0.9s`` for one finished rule.

    *width* is the terminal's: an error longer than what is left of it continues on
    the lines below, under itself, and is cut after four lines. A log passes ``None``
    and gets the error on the one line.
    """
    digits = len(str(total))
    failed = result.status == "failed"
    skipped = result.status in ("skipped", "not_attempted")
    mark = glyph("failed" if failed else "separator" if skipped else "ok", encoding=encoding)
    style = "bold red" if failed else "dim" if skipped else "green"
    line = Text("  ")
    line.append(f"[{index:>{digits}}/{total}]", style="dim")
    line.append(" ")
    line.append(f"{mark} {verb(result):<9} ", style=style)
    name = result.name
    line.append(name.ljust(name_width), style="bold" if failed else "")
    line.append("  ")
    if failed:
        detail = result.error or "failed"
        if width is not None:
            lead = len(line.plain)
            pieces = textwrap.wrap(detail, max(width - lead, MIN_ERROR_WIDTH)) or [detail]
            if len(pieces) > MAX_ERROR_LINES:
                pieces = pieces[:MAX_ERROR_LINES]
                pieces[-1] = pieces[-1].rstrip() + glyph("ellipsis", encoding=encoding)
            detail = ("\n" + " " * lead).join(pieces)
        line.append(detail, style="red")
    elif skipped:
        line.append(result.reason or "", style="dim")
    else:
        line.append(seconds_text(result.seconds or 0.0), style="dim")
    return line


def header_line(
    platform: str, tenant: str | None, rules: int | None, *, encoding: str = "utf-8"
) -> Text:
    """``Deploying to sentinel / contoso · 91 rules``."""
    where = f"{platform} / {tenant}" if tenant else platform
    line = Text("Deploying to ", style="bold")
    line.append(where, style="bold")
    if rules is not None:
        line.append(
            f" {glyph('separator', encoding=encoding)} {plural(rules, 'rule')}", style="dim"
        )
    return line


def counts_text(results: Sequence[RuleResult]) -> str:
    """``2 deployed, 1 failed, 88 not attempted``: failed and not attempted are always there."""
    counts = Counter(result.status for result in results)
    parts = [f"{counts['deployed']} deployed", f"{counts['failed']} failed"]
    if counts["skipped"]:
        parts.append(f"{counts['skipped']} skipped")
    parts.append(f"{counts['not_attempted']} not attempted")
    return ", ".join(parts)


class DeployLog:
    """Follows a deploy through :func:`opentide.core.deploy_events.listen`.

    *changes* are the plan: they say how many rules each tenant is to get, which
    action each rule has, and which rules an early stop left unreached.
    """

    def __init__(self, checklist: Checklist, changes: Sequence[PlannedChange]) -> None:
        self.checklist = checklist
        self.results: list[RuleResult] = []
        self._planned: dict[Key, list[PlannedChange]] = {}
        for change in changes:
            self._planned.setdefault((change.platform, change.tenant), []).append(change)
        self._actions = {
            (change.platform, change.tenant, change.uuid): change.action for change in changes
        }
        self._printed: dict[Key, int] = {}

    # -- DeployListener ----------------------------------------------------------------

    def rule_started(self, result: RuleResult) -> None:
        """The live row names the rule being sent."""
        step = self.checklist.current
        if step is not None:
            step.detail = result.name

    def rule_finished(self, result: RuleResult) -> None:
        result.action = result.action or self._action_for(result)
        self.results.append(result)
        self._print(result)

    # -- run end -----------------------------------------------------------------------

    def platform_results(self, platform: str) -> list[RuleResult]:
        return [result for result in self.results if result.platform == platform]

    def settle(self, platform: str) -> None:
        """A platform's ``deploy`` returned without raising.

        An engine that reports no rule at all (a third-party plugin, or one that
        predates rule events) is taken at its word: its planned rules count as
        deployed, with no line each. An engine that reports some must report them
        all; a planned rule it never mentioned is shown as skipped.
        """
        if not self.platform_results(platform):
            for (name, tenant), changes in self._planned.items():
                if name != platform:
                    continue
                for change in changes:
                    self.results.append(
                        RuleResult(
                            platform=name,
                            tenant=tenant,
                            id=change.uuid,
                            name=change.name,
                            action=change.action,
                        )
                    )
            return
        # After a failure the rest of its tenant was never reached (Elastic stops a tenant on an
        # auth error and carries on): that is not attempted, not a rule the engine chose to skip.
        if any(result.status == "failed" for result in self.platform_results(platform)):
            self.unreached([platform])
        else:
            self.unreached([platform], status="skipped", reason="not reported by the engine")

    def unreached(
        self,
        platforms: Sequence[str] | None = None,
        *,
        status: RuleStatus = "not_attempted",
        reason: str = NOT_ATTEMPTED,
    ) -> list[RuleResult]:
        """Report each planned rule that has no result, and return them.

        *platforms* narrows it to those platforms; ``None`` means the whole run.
        After a failure that is every rule the run never reached.
        """
        done = {(result.platform, result.id) for result in self.results}
        tenanted = {(result.platform, result.tenant, result.id) for result in self.results}
        added: list[RuleResult] = []
        for (platform, tenant), changes in self._planned.items():
            if platforms is not None and platform not in platforms:
                continue
            for change in changes:
                if (platform, tenant, change.uuid) in tenanted or (
                    tenant is None and (platform, change.uuid) in done
                ):
                    continue
                missing = RuleResult(
                    platform=platform,
                    tenant=tenant,
                    id=change.uuid,
                    name=change.name,
                    status=status,
                    action=change.action,
                    seconds=0.0,
                    reason=reason,
                )
                self.results.append(missing)
                added.append(missing)
                self._print(missing)
        return added

    # -- printing ----------------------------------------------------------------------

    def _key(self, result: RuleResult) -> Key:
        for key in ((result.platform, result.tenant), (result.platform, None)):
            if key in self._planned:
                return key
        return (result.platform, result.tenant)

    def _action_for(self, result: RuleResult) -> str | None:
        for tenant in (result.tenant, None):
            action = self._actions.get((result.platform, tenant, result.id))
            if action:
                return action
        return None

    def _print(self, result: RuleResult) -> None:
        key = self._key(result)
        planned = self._planned.get(key, [])
        if key not in self._printed:
            self.checklist.line(Text())
            self.checklist.line(
                header_line(
                    key[0],
                    key[1],
                    len(planned) or None,
                    encoding=self.checklist.console.encoding or "utf-8",
                )
            )
            self._printed[key] = 0
        self._printed[key] += 1
        # Past the plan (a deployer that sends more than planned) the count still reads right.
        total = max(len(planned), self._printed[key])
        name_width = min(max((len(change.name) for change in planned), default=0), NAME_WIDTH)
        console = self.checklist.console
        encoding = console.encoding or "utf-8"
        self.checklist.line(
            result_line(
                result,
                index=self._printed[key],
                total=total,
                name_width=name_width,
                encoding=encoding,
                width=console.width if console.is_terminal else None,
            ),
            always=result.status == "failed",
        )
