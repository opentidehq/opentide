"""Google SecOps advisories (google-secops-1.0, Advisories): warnings that never reject a rule.

Google accepts each of these, but the rule then does not do what its author
most likely meant. ``opentide validate`` reports them as warnings, and so does
``opentide lint`` with its ``queries`` check.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from opentide.platforms.google_secops.yaral import code_lines, event_variables

RISK_SCORE_MISSING = "google_secops_risk_score_missing"
RULE_ID_LITERAL = "google_secops_rule_id_literal"
LIVE_FREQUENCY_UNAVAILABLE = "google_secops_live_frequency_unavailable"

ADVISORY_CODES = frozenset({RISK_SCORE_MISSING, RULE_ID_LITERAL, LIVE_FREQUENCY_UNAVAILABLE})

_BLOCK = ("configurations", "google_secops")
_RISK_SCORE = re.compile(r"^\s*\$risk_score\s*=", re.MULTILINE)
_RULE_ID_FIELD = re.compile(r"\bdetection\.detection\.rule_id\b")
_RULE_ID_LITERAL = re.compile(r"""["`/]ru_[0-9a-fA-F]{8}-""")


@dataclass(frozen=True)
class Advisory:
    code: str
    field_path: tuple[str, ...]
    message: str


def google_secops_advisories(rule: Mapping[str, Any]) -> list[Advisory]:
    """Every advisory the rule's ``google_secops`` block, as authored, earns."""
    configurations = rule.get("configurations")
    block = configurations.get("google_secops") if isinstance(configurations, Mapping) else None
    if not isinstance(block, Mapping):
        return []
    found: list[Advisory] = []
    outcome = block.get("outcome")
    scored = isinstance(outcome, str) and _RISK_SCORE.search("\n".join(code_lines(outcome)))
    if not scored:
        found.append(
            Advisory(
                RISK_SCORE_MISSING,
                (*_BLOCK, "outcome") if "outcome" in block else _BLOCK,
                "outcome assigns no $risk_score, so Google scores every alert 40 and every "
                "non-alerting detection 15, whatever the rule detects; add $risk_score = <0-100>",
            )
        )
    for key in ("events", "condition"):
        text = block.get(key)
        if not isinstance(text, str):
            continue
        if any(
            _RULE_ID_FIELD.search(line) and _RULE_ID_LITERAL.search(line)
            for line in code_lines(text, blank_literals=False)
        ):
            found.append(
                Advisory(
                    RULE_ID_LITERAL,
                    (*_BLOCK, key),
                    f"{key} compares detection.detection.rule_id with a literal ru_ id, which "
                    "differs per instance and changes when the rule is recreated; match the "
                    "producer with detection.detection.rule_name",
                )
            )
    if block.get("run_frequency") == "LIVE" and len(event_variables(block.get("events"))) >= 2:
        found.append(
            Advisory(
                LIVE_FREQUENCY_UNAVAILABLE,
                (*_BLOCK, "run_frequency"),
                "run_frequency LIVE on a rule with two or more event variables: Google stores "
                "it as LIVE_CUSTOMIZABLE, so the rule differs from the block on every deploy; "
                "write LIVE_CUSTOMIZABLE",
            )
        )
    return found
