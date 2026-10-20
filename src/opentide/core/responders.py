"""Resolution of a rule's alert-handling team (``response.responders``).

``responders`` names the team that handles alerts raised by a rule. It is a
**configuration enum**, not a canonical vocabulary: the teams are
per-organisation, so an instance declares them in ``[[responders]]`` under
``deployment.toml`` and an authored value must be one of them. A repository
that declares none leaves the field unconstrained, which is what keeps a
shipped template from carrying a constraint no instance can satisfy.

``[deployment] default_responders`` supplies the team for a rule that names
none, and must itself be one of the configured names.

This lives in ``core`` because both the deployment path (platform deployers
writing an ownership field) and the documentation path (rendering the response
block) need the same answer, and neither should import the other.
"""

from __future__ import annotations

from typing import Any

__all__ = ["configured_responders", "default_responders", "resolve_responders"]


def configured_responders() -> list[str]:
    """Return the team names declared in ``[[responders]]``.

    An empty list means the instance has declared none, and therefore that
    ``response.responders`` is unconstrained.
    """
    from opentide.core.registry import Opentide

    try:
        configured = Opentide.Configurations.Deployment.responders or []
    except (KeyError, AttributeError):
        return []
    names: list[str] = []
    for responder in configured:
        name = getattr(responder, "name", None) or (
            responder.get("name") if isinstance(responder, dict) else None
        )
        if name:
            names.append(str(name))
    return names


def default_responders() -> str:
    """Return ``[deployment] default_responders``, or ``""`` when unset."""
    # Imported lazily: the registry builds configuration from the repository
    # index, which is not available at module import time.
    from opentide.core.registry import Opentide

    try:
        return Opentide.Configurations.Deployment.default_responders
    except (KeyError, AttributeError):
        # A repository with no deployment configuration block is legitimate --
        # documentation generation must not require one.
        return ""


def resolve_responders(response: Any | None) -> str:
    """Return the effective responders for *response*.

    The rule's own ``responders`` wins; an unset or blank value falls back to
    ``[deployment] default_responders``. Returns ``""`` when neither is set,
    so callers can treat "no owner configured" as a single case.
    """
    authored = getattr(response, "responders", None) if response is not None else None
    if authored is not None and str(authored).strip():
        return str(authored).strip()
    return default_responders()
