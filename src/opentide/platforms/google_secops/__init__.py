"""Google Security Operations: YARA-L 2.0 detection rules (``platform::google_secops::1.0``)."""

from __future__ import annotations

from typing import Any

__all__ = ["declare"]


def declare(*args: Any, **kwargs: Any) -> Any:
    from opentide.platforms.google_secops.deployer import declare as _declare

    return _declare(*args, **kwargs)
