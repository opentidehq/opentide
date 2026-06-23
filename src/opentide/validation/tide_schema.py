"""Schema validation — Pydantic model_validate pipeline."""

from __future__ import annotations

import os
import sys



from tabulate import tabulate

from opentide.core.registry import OpenTide
from opentide.validation.pipeline import validate_all_objects
from opentide.core.logging import log


def run() -> None:
    log("TITLE", "Pydantic Schema Validation")
    log("INFO", "Validates all OpenTide objects via model_validate()")

    OpenTide.initialise()
    errors = validate_all_objects(OpenTide.Index["objects"])

    stats: dict[str, int] = {}
    overall = 0

    for schema in OpenTide.Index["objects"]:
        count = len(OpenTide.Index["objects"].get(schema, {}))
        stats[schema.upper()] = count
        overall += count

    for uuid, error_list in errors.items():
        for error in error_list:
            log("FATAL", f"Failed validation for object {uuid}", error)

    if errors:
        log(
            "FATAL",
            "Failed Schema Validation",
            "OpenTide objects currently do not match Pydantic models",
            "Review the files before running the validation again",
        )
        os.environ["VALIDATION_ERROR_RAISED"] = "True"
    else:
        statstable = [["Category", "Count"]]
        for key in stats:
            statstable.append([key, stats[key]])
        statstable = tabulate(statstable, headers="firstrow")
        log("SUCCESS", f"Successfully verified {overall} OpenTide objects")
        print(statstable)


if __name__ == "__main__":
    run()
