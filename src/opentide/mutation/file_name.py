import os

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
        model_files = [
            file
            for file in sorted(os.listdir(PATHS[model]))
            if file.endswith(".yaml") or file.endswith(".yml")
        ]
        if not model_files:
            log("SKIP", "No files to assign ID or fix file names in model type", model)
            continue
        for file in model_files:
            with open(PATHS[model] / file, encoding="utf-8") as model_file:
                data = yaml.safe_load(model_file)
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


if __name__ == "__main__":
    run()
