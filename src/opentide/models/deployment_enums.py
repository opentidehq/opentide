from collections.abc import Iterable, Mapping
from enum import Enum, auto

class StatusStrategy(Enum):
    INERT = 'Does not interact with deployment'
    RELEASE = 'Deployment from the default branch (also called trunk, or main branch)'
    PREVIEW = 'Deployment from Pull/Merge Requests'
    DISABLEMENT = 'Deployment from the default branch, but only to disable an existing rule. If the target system does not have a concept of disabling rules, then defaults to deleting them.'
    DELETION = 'Deployment from the default branch, but removes the rule from the target system.'
    UNIVERSAL = 'Deployment from both Pull/Merge Requests, and default branch pipelines.'

class DetectionPlatforms(Enum):
    DEFENDER_FOR_ENDPOINT = auto()
    CARBON_BLACK_CLOUD = auto()
    SPLUNK = auto()
    SENTINEL = auto()
    SENTINEL_ONE = auto()
    CROWDSTRIKE = auto()
    HARFANGLAB = auto()
    ELASTIC = auto()
DetectionSystems = DetectionPlatforms

#: What a run deploys, and what a tenant accepts: ``--strategy`` and a tenant's
#: ``strategies`` take only these. ``UNIVERSAL`` rules are deployed by both;
#: ``DISABLEMENT`` and ``DELETION`` rules are retired by a ``RELEASE`` run;
#: ``INERT`` rules are never deployed.
DEPLOYABLE_STRATEGIES: tuple[StatusStrategy, ...] = (StatusStrategy.PREVIEW, StatusStrategy.RELEASE)

#: The strategies a run deploys, in ``DEPLOYABLE_STRATEGIES`` order.
RunStrategies = tuple[StatusStrategy, ...]

RETIRING_STRATEGIES = (StatusStrategy.DISABLEMENT, StatusStrategy.DELETION)


def deploys(rule_strategy: StatusStrategy, run_strategy: StatusStrategy) -> bool:
    """Whether a run with *run_strategy* acts on a rule whose status maps to *rule_strategy*.

    A ``PREVIEW`` run deploys ``PREVIEW`` and ``UNIVERSAL`` rules. A
    ``RELEASE`` run deploys ``RELEASE`` and ``UNIVERSAL`` rules, and disables
    or deletes ``DISABLEMENT`` and ``DELETION`` rules. Nothing deploys
    ``INERT``.
    """
    if rule_strategy is run_strategy or rule_strategy is StatusStrategy.UNIVERSAL:
        return run_strategy in DEPLOYABLE_STRATEGIES
    return run_strategy is StatusStrategy.RELEASE and rule_strategy in RETIRING_STRATEGIES


def deployed_by(rule_strategy: StatusStrategy) -> RunStrategies:
    """The run strategies that act on a rule whose status maps to *rule_strategy*."""
    return tuple(run for run in DEPLOYABLE_STRATEGIES if deploys(rule_strategy, run))


#: Why a name is not a strategy a run or a tenant can take, and what to pass.
_NOT_A_RUN_STRATEGY = {
    "UNIVERSAL": "UNIVERSAL is a status strategy that both PREVIEW and RELEASE runs deploy; pass PREVIEW or RELEASE",
    "DISABLEMENT": "a RELEASE run disables the changed rules whose status maps to DISABLEMENT; pass RELEASE",
    "DELETION": "a RELEASE run deletes the changed rules whose status maps to DELETION; pass RELEASE",
    "INERT": "rules whose status maps to INERT are never deployed",
    "FULL": "deployment plans were removed in 0.17.0; pass --strategy PREVIEW --strategy RELEASE --all to deploy every rule",
    "ALWAYS": "deployment plans were removed in 0.17.0; a tenant lists the strategies it accepts in 'strategies'",
    "MANUAL": "deployment plans were removed in 0.17.0; a tenant that only takes the rules naming it sets 'manual = true'",
    "DEBUG": "deployment plans were removed in 0.17.0; pass PREVIEW or RELEASE",
}


def parse_strategies(
    values: Iterable[str],
    *,
    statuses: Mapping[str, StatusStrategy] | None = None,
    source: str = "--strategy",
) -> RunStrategies:
    """Read ``PREVIEW`` / ``RELEASE`` values, refusing anything else with what to pass.

    *statuses* maps configured status names to their strategy, so a status
    name such as ``STAGING`` or ``DEVELOPMENT`` is answered with the strategy
    it maps to.
    """
    chosen: set[StatusStrategy] = set()
    for raw in values:
        for part in str(raw).split(","):
            name = part.strip().upper()
            if not name:
                continue
            member = StatusStrategy.__members__.get(name)
            if member in DEPLOYABLE_STRATEGIES:
                chosen.add(member)
                continue
            allowed = " or ".join(s.name for s in DEPLOYABLE_STRATEGIES)
            hints = [f"{source} {part.strip()!r} is not a deployable strategy. Use {allowed}"]
            if name in ("STAGING", "PRODUCTION"):
                hints.append(
                    f"{name} was a deployment plan, removed in 0.17.0: pass "
                    f"{'PREVIEW' if name == 'STAGING' else 'RELEASE'}"
                )
            elif name in _NOT_A_RUN_STRATEGY:
                hints.append(_NOT_A_RUN_STRATEGY[name])
            if statuses and name in statuses:
                mapped = statuses[name]
                runs = deployed_by(mapped)
                hint = f"{name} is also a configured status name; it maps to {mapped.name}"
                if runs:
                    hint += f", which a {' or '.join(r.name for r in runs)} run deploys"
                else:
                    hint += ", which no run deploys"
                hints.append(hint)
            message = ". ".join(hints)
            raise ValueError(message)
    return tuple(s for s in DEPLOYABLE_STRATEGIES if s in chosen)


#: Removed in 0.17.0; still named so a pipeline that sets it fails clearly.
REMOVED_PLAN_ENV = "DEPLOYMENT_PLAN"


def removed_plan_message(value: str | None = None, *, option: bool = False) -> str:
    """The error for ``--plan`` or ``DEPLOYMENT_PLAN``, naming the replacement."""
    where = "--plan" if option else REMOVED_PLAN_ENV
    replacement = {
        "STAGING": "--strategy PREVIEW",
        "PRODUCTION": "--strategy RELEASE",
        "FULL": "--strategy PREVIEW --strategy RELEASE --all",
    }.get(str(value or "").strip().upper(), "--strategy PREVIEW or --strategy RELEASE")
    unset = "" if option else f" Unset {REMOVED_PLAN_ENV}."
    return (
        f"{where} was removed in 0.17.0: a run now says which status strategy it deploys. "
        f"Use {replacement}.{unset} See 'opentide deploy --help'."
    )
