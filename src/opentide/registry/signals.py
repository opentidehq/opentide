"""Index the signals nested in a detection objective.

Signals are authored inside ``objective.signals`` and indexed on their own in
the ``signal`` bucket, keyed by signal UUID. The owning objective is recorded
as ``owner``. The authored ``parent`` field is a *parent signal* UUID
(``objective-1.0``) and is kept exactly as written.
"""

from __future__ import annotations

from typing import Any

from opentide.core.logging import get_logger

logger = get_logger(__name__)

#: Index-only field naming the objective a signal is defined in.
SIGNAL_OWNER_FIELD = "owner"


def objective_signals(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the signal mappings authored in an objective body."""
    objective = body.get("objective")
    if not isinstance(objective, dict):
        return []
    signals = objective.get("signals") or []
    if not isinstance(signals, list):
        return []
    return [signal for signal in signals if isinstance(signal, dict)]


def index_objective_signals(
    signal_bucket: dict[str, Any],
    objective_uuid: str,
    body: dict[str, Any],
    *,
    source: str | None = None,
) -> None:
    """Add an objective's signals to ``signal_bucket``.

    Each entry is a copy of the authored signal plus ``owner``. A UUID already
    indexed under a *different* objective keeps its first definition; the clash
    is reported by ``opentide validate`` as ``duplicate_signal_uuid``. A
    re-ingest of the same objective (an inflight overlay) replaces its own
    signals.
    """
    for signal in objective_signals(body):
        signal_uuid = signal.get("uuid")
        if not signal_uuid:
            logger.error("signal_missing_uuid_in_objective", objective=source or objective_uuid)
            continue
        key = str(signal_uuid)
        existing = signal_bucket.get(key)
        if isinstance(existing, dict) and existing.get(SIGNAL_OWNER_FIELD) != objective_uuid:
            logger.warning(
                "duplicate_signal_uuid",
                signal=key,
                kept_owner=existing.get(SIGNAL_OWNER_FIELD),
                ignored_owner=objective_uuid,
            )
            continue
        signal_copy = signal.copy()
        signal_copy[SIGNAL_OWNER_FIELD] = objective_uuid
        signal_bucket[key] = signal_copy
