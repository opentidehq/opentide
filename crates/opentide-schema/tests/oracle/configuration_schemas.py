"""Write configuration_schemas.json: every configuration schema the oracle generates.

Run it with the oracle's interpreter (tests/golden/ORACLE):

    <oracle python> -I crates/opentide-schema/tests/oracle/configuration_schemas.py

The documents are ``generate_configuration_schemas()``'s (the JSON Schema of each
configuration file and the router keyed by file name). ``cargo xtask codegen
--check`` compares the schemas ``opentide_schema::generate::configuration``
writes with these by verdict: every configuration file of the corpora must be
accepted or refused by both. The router must be the same document.
"""

from __future__ import annotations

import json
from pathlib import Path

import opentide
from opentide.generation.configuration_schemas import generate_configuration_schemas

HERE = Path(__file__).resolve().parent


def main() -> None:
    document = {
        "oracle": opentide.__version__,
        "documents": generate_configuration_schemas(),
    }
    path = HERE / "configuration_schemas.json"
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
