import os

import yaml

from opentide.core.files import resolve_configurations, resolve_paths, safe_file_name
from opentide.core.logging import get_logger
from opentide.core.logging.console import emit_section
from opentide.core.root import get_repo_root

logger = get_logger(__name__)

ROOT = get_repo_root()
CONFIGURATIONS = resolve_configurations()
PATHS = resolve_paths()
MODELS_TYPES = CONFIGURATIONS["global"]["objects"]


def run():
    emit_section("File Name Aligner")
    logger.info(
        "file_name_aligner_started",
        detail=(
            "Aligns the file name with the YAML Content and assigns "
            "ID if missing (non-MDR objects only)"
        ),
    )

    MODELS_TYPES.remove("rule")
    for model in MODELS_TYPES:
        model_files = [
            file
            for file in sorted(os.listdir(PATHS[model]))
            if file.endswith(".yaml") or file.endswith(".yml")
        ]
        if not model_files:
            logger.info("no_files_to_align", model_type=model)
            continue
        for file in model_files:
            with open(PATHS[model] / file, encoding="utf-8") as model_file:
                data = yaml.safe_load(model_file)
            model_name = data["name"]
            standard_name = f"{safe_file_name(model_name)}.yaml"

            if file != standard_name:
                logger.info("realigning_file_name", file=file)
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
                logger.info("file_name_aligned", standard_name=standard_name)


if __name__ == "__main__":
    run()
