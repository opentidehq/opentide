import sys
import os
import uuid
from pathlib import Path

import yaml


from opentide.core.logging import log
from opentide.core.files import safe_file_name, resolve_configurations, resolve_paths
from opentide.core.root import get_repo_root

ROOT = get_repo_root()
CONFIGURATIONS = resolve_configurations()
PATHS = resolve_paths()
MODELS_TYPES = CONFIGURATIONS["global"]["objects"]


def run():

    log("TITLE", "File Name Aligner")
    log(
        "INFO",
        "Aligns the file name with the YAML Content and assigns"
        " ID if missing (non-MDR objects only)",
    )

    MODELS_TYPES.remove("rule")
    for model in MODELS_TYPES:
        for file in sorted(os.listdir(PATHS[model])):
            if not file.endswith(".yaml"):
                if not file.endswith(".yml"):
                    log("INFO", "The file doesn't end with .yaml or .yml, skipping", file)
                    continue  

            data = yaml.safe_load(open(PATHS[model] / file, encoding="utf-8"))
            model_name = data["name"]
            standard_name = f"{safe_file_name(model_name)}.yaml"

            if file != standard_name:
                log("INFO", "Re-aligning file name with model_data", file)
                # Renaming goes through a temp file to still rename in case-insensitive OSs
                # when the only difference is capitalization
                os.rename(
                    PATHS[model] / file,
                    PATHS[model] / (standard_name + ".tmp"),
                )
                os.rename(
                    PATHS[model] / (standard_name + ".tmp"),
                    PATHS[model] / standard_name,
                )
                log("SUCCESS", f"Alligned file name with model data", standard_name)


        else:
            log("SKIP", "No files to assign ID or fix file names in model type", model)


if __name__ == "__main__":
    run()
