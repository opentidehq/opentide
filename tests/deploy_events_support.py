"""A listener that keeps every rule a deployer finishes, for platform deployer tests."""

from __future__ import annotations

from opentide.core.deploy_events import RuleResult


class Recorder:
    """Pass to :func:`opentide.core.deploy_events.listen`; ``results`` fills as rules finish."""

    def __init__(self) -> None:
        self.started: list[str] = []
        self.results: list[RuleResult] = []

    def rule_started(self, result: RuleResult) -> None:
        self.started.append(result.id)

    def rule_finished(self, result: RuleResult) -> None:
        self.results.append(result)

    def outcomes(self) -> list[tuple[str, str]]:
        """``(id, status)`` for each finished rule, in order."""
        return [(result.id, result.status) for result in self.results]
