---
name: pytest-coverage
description: Find and close coverage gaps in opentide with pytest-cov — the 85% gate on Python 3.14, the omit list, sysmon, and writing tests for the uncovered lines that matter. Use when the coverage gate fails, after adding code, or when asked to raise coverage.
---

# Coverage — opentide

## The gate

- `[tool.coverage.report] fail_under = 85.0` in `pyproject.toml`, enforced in CI on the
  **Python 3.14** test cell only (`COVERAGE_PYTHON` in `ci.yml`) and locally by
  `scripts/ci-local.sh --full`.
- `[tool.coverage.run].omit` leaves out `_version.py` alone. The gate covers what the package
  holds since UC-6.2 (#841): the console script, the SDK, the models, the plugin API and
  `analysis.py`; the Rust core's coverage is the Rust gates' (`xtask/coverage.toml`).
- Coverage is combined across xdist workers; `COVERAGE_CORE=sysmon` (3.12+) is set
  automatically by `ci-local.sh`.

```bash
scripts/ci-local.sh --full                                    # same gate as CI
uv run pytest tests/test_sdk -n 4 --cov=opentide --cov-report=term-missing:skip-covered \
  -m "not cli_e2e and not cli_smoke"                          # one area
```

## Policy

- Cover the lines your change adds; the target is behaviour, not 100%. A test that only
  executes a line without asserting its effect does not count.
- Never lower `fail_under`, widen `omit`, or add `# pragma: no cover` to testable code to get
  green. `pragma: no cover` is for `TYPE_CHECKING` blocks and unreachable guards only.
- Prefer one test per behaviour over one per line; see
  [`python-testing-patterns`](../python-testing-patterns/SKILL.md).

## Upstream technique: annotated reports

Use annotated reports to see exactly which lines are uncovered; the policy above decides which of them matter.

Generate a coverage report with:

pytest --cov --cov-report=annotate:cov_annotate

If you are checking for coverage of a specific module, you can specify it like this:

pytest --cov=your_module_name --cov-report=annotate:cov_annotate

You can also specify specific tests to run, for example:

pytest tests/test_your_module.py --cov=your_module_name --cov-report=annotate:cov_annotate

Open the cov_annotate directory to view the annotated source code.
There will be one file per source file. If a file has 100% source coverage, it means all lines are covered by tests, so you do not need to open the file.

For each file that has less than 100% test coverage, find the matching file in cov_annotate and review the file.

If a line starts with a ! (exclamation mark), it means that the line is not covered by tests.
Add tests to cover the missing lines.

Keep running the tests until the lines your change adds are covered.
