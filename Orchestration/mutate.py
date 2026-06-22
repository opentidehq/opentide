import os
import git
import toml
import sys
from datetime import datetime
from pathlib import Path

toolchain_start_time = datetime.now()

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.logs import log, ANSI, print_banner
from Engines.mutation import (
    file_name,
    references,
    security_domain
)

ROOT = Path(str(git.Repo(".", search_parent_directories=True).working_dir))

print(print_banner())
print(f"""
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}
CoreTide Data Mutation
{ANSI.Formatting.STOP}
""")

file_name.run()
references.run()
security_domain.run()

print("\n" + "Execution Report".center(80, "="))

time_to_execute = datetime.now() - toolchain_start_time
time_to_execute = "%.2f" % time_to_execute.total_seconds() + " seconds"

log("SUCCESS", "Completed mutation toolchain", time_to_execute)
