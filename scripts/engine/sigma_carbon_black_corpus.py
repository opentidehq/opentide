"""Convert SigmaHQ rules to Carbon Black Cloud process search queries (#162).

    python scripts/sigma_carbon_black_corpus.py <SigmaHQ checkout> [count]

Uses pySigma-backend-carbonblack (MIT) with its `CarbonBlack_pipeline`, the
process search field mapping. The SigmaHQ checkout must be at the commit the
other Sigma-derived corpora use (SOURCES.md). Writes, for the first `count`
rules (sorted by path) that convert, in rule-category order:

  testdata/conformance/external/lucene-carbon-black/<rule>.lucene
  testdata/conformance/external/lucene-carbon-black/<rule>.broken.lucene

and prints the `sigma.tsv` rows and the SOURCES.md list for them. A broken
twin is the query with one unbalanced `(` added at the front. Neither
pySigma nor the backend ships: they generate test data.
"""

from __future__ import annotations

import pathlib
import sys

import yaml
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.carbonblack import CarbonBlack_pipeline

COMMIT = "05d1031f537e830b76da53bae2400c5814c89165"
CATEGORIES = [
    "rules/windows/process_creation",
    "rules/windows/image_load",
    "rules/windows/file/file_event",
    "rules/windows/network_connection",
    "rules/windows/registry/registry_set",
]
OUT = pathlib.Path(__file__).resolve().parents[1] / "testdata/conformance/external/lucene-carbon-black"


def main() -> None:
    sigma = pathlib.Path(sys.argv[1])
    per_category = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    OUT.mkdir(parents=True, exist_ok=True)
    backend = CarbonBlackBackend(CarbonBlack_pipeline())
    rows: list[str] = []
    sources: list[str] = []
    for category in CATEGORIES:
        taken = 0
        for path in sorted((sigma / category).glob("*.yml")):
            if taken == per_category:
                break
            text = path.read_text(encoding="utf-8")
            try:
                queries = backend.convert(SigmaCollection.from_yaml(text))
            except Exception:  # a rule the pipeline cannot map
                continue
            if len(queries) != 1 or not queries[0].strip():
                continue
            rule = yaml.safe_load(text)
            query = queries[0].strip()
            stem = path.stem
            (OUT / f"{stem}.lucene").write_text(query + "\n", encoding="utf-8")
            (OUT / f"{stem}.broken.lucene").write_text("(" + query + "\n", encoding="utf-8")
            relative = path.relative_to(sigma).as_posix()
            author = str(rule.get("author", "")).replace("\t", " ")
            rows.append(f"lucene-carbon-black/{stem}.lucene\t{relative}\t{rule.get('id', '')}\t{author}")
            sources.append(
                f"- `{stem}.lucene` from [`{relative}`](https://github.com/SigmaHQ/sigma/blob/{COMMIT}/{relative}) ({rule.get('id', '')}), author: {author}"
            )
            taken += 1
    print("\n".join(rows))
    print()
    print("\n".join(sources))


if __name__ == "__main__":
    main()
