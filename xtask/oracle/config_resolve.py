"""Print each workspace's resolved configuration as the oracle resolves it.

`cargo xtask config diff --against python` runs it with the oracle's
interpreter (opentide 0.23.0, beside the oracle executable):

    <oracle python> -I xtask/oracle/config_resolve.py WORKSPACE...

It prints one JSON object: for each workspace, `resolve_configurations` as
JSON (floats JSON cannot hold as `inf`, `-inf`, `nan`; dates and times as
their ISO text) with `workspace_configuration_issues`, or the error
resolution stops on.
"""

from __future__ import annotations

import datetime
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

from opentide.core.errors import UserFileError
from opentide.core.files import resolve_configurations
from opentide.validation.configuration import workspace_configuration_issues


def plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [plain(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return "nan" if math.isnan(value) else ("inf" if value > 0 else "-inf")
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat().replace("+00:00", "Z")
    return value


def one(workspace: Path) -> dict[str, Any]:
    try:
        configs = resolve_configurations(workspace)
    except UserFileError as exc:
        return {"error": {"code": exc.code, "message": exc.problem}}
    except ValueError as exc:
        return {"error": {"code": None, "message": str(exc)}}
    return {
        "resolved": plain(configs),
        "issues": [
            {
                "code": item.code,
                "severity": item.severity,
                "field_path": list(item.field_path),
                "message": item.message,
            }
            for item in workspace_configuration_issues(configs)
        ],
    }


def main() -> int:
    os.environ.pop("OPENTIDE_TIDE_WORKSPACE", None)
    out = {argument: one(Path(argument)) for argument in sys.argv[1:]}
    json.dump(out, sys.stdout, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
