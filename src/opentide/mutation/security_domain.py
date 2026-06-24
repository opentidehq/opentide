# This mutation was introduced to fix a previous schema error where
# the security_domain keyword, which is a notable parameter, was
# not nested under the notable block. It also indent drilldown,
# which on some older MDR may not be indented correctly.

import os
from pathlib import Path

import yaml

from opentide.core.files import resolve_paths
from opentide.core.logging import get_logger
from opentide.core.root import get_repo_root

logger = get_logger(__name__)

ROOT = get_repo_root()

PATHS = resolve_paths()
MDR_PATH = PATHS["rule"]


class MigrateSecurityDomainMDR:
    """
    If security_domain is commented, or uncommented, simply makes an indent
    to re-nest under notable. In edge cases where notable is uncommented but
    not security_domain, indent and uncomment notable. In edge cases where
    security_domain is not present at all, will not add it by safety.
    """

    def indent_security_domain(self, file_path: Path):
        with open(MDR_PATH / file_path, encoding="utf-8") as handle:
            data = handle.readlines()
        buffer = []
        for line in data:
            if line.startswith("    security_domain:"):
                line = "  " + line
                logger.info("found_and_added_indent_to_security_domain")
            buffer.append(line)

        if buffer != data:
            with open(MDR_PATH / file_path, "w", encoding="utf-8") as file:
                for line in buffer:
                    file.write(line)
            logger.info("rewrote_file")

    def uncomment_keyword(self, file_path: Path, keyword: str):
        with open(MDR_PATH / file_path, encoding="utf-8") as handle:
            data = handle.readlines()
        buffer = []
        for line in data:
            if line.strip().replace("#", "").split(":")[0] == keyword:
                line = line.replace("#", "")
                logger.info("found_and_uncommented_target_keyword", detail=keyword)
            buffer.append(line)

        if buffer != data:
            with open(MDR_PATH / file_path, "w", encoding="utf-8") as file:
                for line in buffer:
                    file.write(line)
                logger.info("rewrote_file")

    def indent_drilldown_section(self, file_path: Path):
        with open(MDR_PATH / file_path, encoding="utf-8") as handle:
            data = handle.readlines()
        buffer = []
        DRILLDOWN_RAW = [
            "    #drilldown:\n",
            "      #name: \n",
            "      #search: |\n",
            "        #Type Here\n",
        ]
        for line in data:
            if line in DRILLDOWN_RAW:
                line = "  " + line
                logger.info("indented_part_of_the_drilldown_section")
            buffer.append(line)

        if buffer != data:
            with open(MDR_PATH / file_path, "w", encoding="utf-8") as file:
                for line in buffer:
                    file.write(line)
            logger.info("rewrote_file")

    def migrate(self):
        for mdr in os.listdir(PATHS["rule"]):
            if not mdr.endswith(".yaml"):
                if not mdr.endswith(".yml"):
                    logger.info("the_file_doesn_t_end_with_yaml_or_yml_skipping", detail=mdr)
                    continue

            with open(MDR_PATH / mdr, encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            mdr_name = data["name"]
            logger.info("assessing_if_security_domain_should_be_migrated", detail=mdr_name)

            if "splunk" not in data["configurations"]:
                continue

            config = data["configurations"]["splunk"]
            if "security_domain" in config:
                logger.info("migrating_security_domain_under_the_notable_block")
                self.indent_security_domain(MDR_PATH / mdr)
                if "notable" not in config:
                    logger.info("uncommenting_notable_to_allow_nesting")
                    self.uncomment_keyword(MDR_PATH / mdr, "notable")
            else:
                self.indent_security_domain(MDR_PATH / mdr)

            if "drilldown" not in config.get("notable", {}):
                logger.info(
                    "drilldown_section_not_found_will_run_a_cleanup_in_case_it_is_not_indented_proper"
                )
                self.indent_drilldown_section(MDR_PATH / mdr)


def run():
    MigrateSecurityDomainMDR().migrate()


if __name__ == "__main__":
    run()
