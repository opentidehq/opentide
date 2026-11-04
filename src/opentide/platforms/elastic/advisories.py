"""Advisory codes of the elastic-1.0 platform specification.

Each advisory ``opentide validate`` raises about an Elastic rule has a stable code, shared
with the language server, so the CLI and the editor name one finding the same way.
"""

from __future__ import annotations

from typing import Any

LOOKBACK_ZERO = "lookback_zero"
LOOKBACK_LONG = "lookback_long"
THRESHOLD_LOOKBACK = "threshold_lookback"
ESQL_METADATA_ID = "esql_metadata_id"
EQL_MAXSPAN_WINDOW = "eql_maxspan_window"
EQL_MAXSPAN_LOOKBACK = "eql_maxspan_lookback"
RISK_BAND = "risk_band"
TECHNIQUE_NOT_ENTERPRISE = "technique_not_enterprise"

#: Log event each code replaced. ``lookback_long`` and ``threshold_lookback`` shared one
#: event, as did ``eql_maxspan_window`` and ``eql_maxspan_lookback``. Carried as
#: ``legacy_event`` for one release, for log consumers that filtered on the old name.
LEGACY_EVENTS: dict[str, str] = {
    LOOKBACK_ZERO: "elastic_lookback_zero_warning",
    LOOKBACK_LONG: "elastic_lookback_long_warning",
    THRESHOLD_LOOKBACK: "elastic_lookback_long_warning",
    ESQL_METADATA_ID: "elastic_esql_metadata_id_warning",
    EQL_MAXSPAN_WINDOW: "elastic_eql_maxspan_window_warning",
    EQL_MAXSPAN_LOOKBACK: "elastic_eql_maxspan_window_warning",
    RISK_BAND: "elastic_risk_score_band_warning",
    TECHNIQUE_NOT_ENTERPRISE: "skipping_non_enterprise_technique",
}


def warn_advisory(logger: Any, code: str, **fields: Any) -> None:
    """Log the advisory *code* as a warning.

    The log event is the code; ``code`` repeats it as a field and ``legacy_event`` names
    the event it replaced.
    """
    logger.warning(code, code=code, legacy_event=LEGACY_EVENTS[code], **fields)
