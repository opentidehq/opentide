import git
import sys

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from opentide.core.registry import OpenTide
from opentide.core.index_manager import IndexManager
from Engines.modules.logs import log, ANSI, print_banner
from opentide.indexing.object_vocab import run as generate_object_vocab
from opentide.generation.template import run as generate_templates
from Engines.indexing.revisions import RevisionIndexer
from opentide.generation.schema import run as generate_schemas
from Engines.export import attack_navigator_layer
from Engines.export.table_export import TableExporter

print(print_banner())
print(f"""
{ANSI.Colors.BLUE}{ANSI.Formatting.ITALICS}{ANSI.Formatting.BOLD}
CoreTide Meta Model Compilation
{ANSI.Formatting.STOP}
""")

log("TITLE", "TIDE Indexes Generation")
log(
    "INFO",
    "Generate entries in Tide namespace containing model data supportive of other generation routines",
)

generate_object_vocab()
generate_templates()

IndexManager.reload()
OpenTide.reload()

generate_schemas()
RevisionIndexer().run()

from Engines.framework import vscode_snippets

vscode_snippets.run()
attack_navigator_layer.run()
TableExporter().run()