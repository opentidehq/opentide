"""``python -m opentide``: the console script's entry point, ``opentide._native:main``."""

from opentide._native import main

if __name__ == "__main__":
    raise SystemExit(main())
