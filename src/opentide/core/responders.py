"""Resolution of a rule's alert-handling team (``response.responders``).

``responders`` names the team that handles alerts raised by a rule. It is
per-organisation configuration rather than a canonical vocabulary, so it is
free text with a repository-wide fallback from
``[deployment] default_responders``.

This lives in ``core`` because both the deployment path (platform deployers
writing an ownership field) and the documentation path (rendering the response
block) need the same answer, and neither should import the other.
"""

from __future__ import annotations

from typing import Any

__all__ = ["default_responders", "resolve_responders"]


def default_responders() -> str:
    """Return ``[deployment] default_responders``, or ``""`` when unset."""
    # Imported lazily: the registry builds configuration from the repository
    # index, which is not available at module import time.
    from opentide.core.registry import OpenTide

    try:
        return OpenTide.Configurations.Deployment.default_responders
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
