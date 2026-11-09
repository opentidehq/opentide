"""Record Python's difflib answers as the Rust port's test fixture.

Writes crates/opentide-core/tests/data/difflib_cases.json: cases of
``difflib.get_close_matches`` (random ASCII and Unicode words, opentide's vocabulary
names, the CLI's command names, flags and choices, case and -/_ variants, empty
strings, strings over 200 characters for the autojunk heuristic, varying ``n`` and
``cutoff``), each with Python's result and the ``SequenceMatcher`` ratios of one
pair. ``crates/opentide-core/tests/difflib_cases.rs`` checks the Rust port
(``opentide_core::difflib``) against every case.

The script uses only the standard library (Python 3.11 or later, for tomllib) and a
fixed seed, so any interpreter writes the same file. Run from anywhere:

    python3 scripts/build/gen_difflib_cases.py          # write
    python3 scripts/build/gen_difflib_cases.py --check  # exit 1 when stale
"""

from __future__ import annotations

import argparse
import difflib
import json
import random
import sys
from pathlib import Path
from typing import Any

import tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "crates/opentide-core/tests/data/difflib_cases.json"
VOCAB_DIR = ROOT / "src/opentide/data/vocabulary"
COMMANDS = ROOT / "tests/golden/cases/commands/json/none/default/stdout"
SEED = 20261109
CASES_PER_KIND = 480

ASCII = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:+ "
# Code points from several planes, combining marks and look-alikes; no surrogates.
UNICODE = (
    "aeiouéèêëàçñßøåæœÉÈÇÑ"
    "αβγδεζηθλμπσωΑΒΓΔΩ"
    "абвгдежзиклмнопрстуАБВГД"
    "ابتثجحخدذر"
    "日本語漢字中文한국어"
    "\u0301\u0308\u200b\u00a0\u2028"
    "😀😁🚀🔒🛡\ufe0f\U0001d518\U0001d52b\U0001d526"
    "ﬁǅİ\u0131\u017fK"
)
CUTOFFS = (0.0, 0.5, 0.6, 0.6, 0.6, 0.75, 0.8, 0.9, 1.0)
NS = (1, 1, 1, 2, 3, 3, 5, 10)


def vocabulary_pools() -> dict[str, list[str]]:
    """Each vocabulary's lookup values (its `key` field), as given and casefolded."""
    pools: dict[str, list[str]] = {}
    for path in sorted(VOCAB_DIR.glob("*.vocab.toml")):
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        key = data.get("key", "name")
        names = [str(entry[key]) for entry in data.get("keys", []) if key in entry]
        if not names:
            continue
        stem = path.name.removesuffix(".vocab.toml")
        pools[f"vocab:{stem}"] = names
        pools[f"vocab-casefold:{stem}"] = [name.casefold() for name in names]
    return pools


def command_pools() -> dict[str, list[str]]:
    """The CLI's command paths and names, option flags and choices (the golden `commands`)."""
    data = json.loads(COMMANDS.read_text(encoding="utf-8"))
    paths: list[str] = []
    names: list[str] = []
    flags: list[str] = []
    choices: list[str] = []
    for command in data["commands"]:
        paths.append(command["path"])
        names.append(command["name"])
        for option in command.get("options", []):
            flags.extend(option.get("flags", []))
            choices.extend(str(c) for c in option.get("choices") or [])
    for option in data.get("global_options", []):
        flags.extend(option.get("flags", []))

    def dedupe(values: list[str]) -> list[str]:
        return list(dict.fromkeys(values))

    return {
        "commands:paths": dedupe(paths),
        "commands:names": dedupe(names),
        "commands:flags": dedupe(flags),
        "commands:choices": dedupe(choices),
    }


def random_word(rng: random.Random, alphabet: str, lo: int, hi: int) -> str:
    """`lo` to `hi` characters of `alphabet`; exactly `lo` when `hi` is 0."""
    length = lo if hi == 0 else rng.randint(lo, hi)
    return "".join(rng.choice(alphabet) for _ in range(length))


def mutate(rng: random.Random, word: str, alphabet: str) -> str:
    """A typo, case or separator variant of `word`."""
    kind = rng.randrange(10)
    if kind == 0 or not word:
        pos = rng.randint(0, len(word))
        return word[:pos] + rng.choice(alphabet) + word[pos:]
    pos = rng.randrange(len(word))
    if kind == 1:
        return word[:pos] + word[pos + 1 :]
    if kind == 2:
        return word[:pos] + rng.choice(alphabet) + word[pos + 1 :]
    if kind == 3 and len(word) > 1:
        pos = min(pos, len(word) - 2)
        return word[:pos] + word[pos + 1] + word[pos] + word[pos + 2 :]
    if kind == 4:
        return word.upper()
    if kind == 5:
        return word.swapcase()
    if kind == 6:
        return word.replace("-", "_") if "-" in word else word.replace("_", "-").replace(" ", "-")
    if kind == 7:
        return word.casefold()
    if kind == 8:
        return word.title()
    return word


def repeat_mutate(rng: random.Random, word: str, alphabet: str) -> str:
    for _ in range(rng.choice((0, 1, 1, 1, 2, 3))):
        word = mutate(rng, word, alphabet)
    return word


def long_word(rng: random.Random) -> str:
    """Over 200 characters, from a small alphabet so some elements are popular."""
    alphabet = rng.choice(("ab", "abc", "abcdefgh", "xyz-_", "aaab", ASCII, "αβγ日本"))
    return random_word(rng, alphabet, 200, 420)


def fmt(value: float) -> str:
    """repr(float): the shortest string that reads back as the same float."""
    return repr(value)


def ratio_pair(a: str, b: str, *, autojunk: bool = True, junk: str | None = None) -> dict[str, Any]:
    isjunk = None if junk is None else (lambda c: c in junk)
    s = difflib.SequenceMatcher(isjunk, a, b, autojunk)
    return {
        "a": a,
        "b": b,
        "autojunk": autojunk,
        "junk": junk,
        "ratio": fmt(s.ratio()),
        "quick_ratio": fmt(s.quick_ratio()),
        "real_quick_ratio": fmt(s.real_quick_ratio()),
        "matching_blocks": [list(m) for m in s.get_matching_blocks()],
    }


def make_case(
    rng: random.Random,
    kind: str,
    word: str,
    possibilities: list[str],
    pool: str | None,
    n: int,
    cutoff: float,
) -> dict[str, Any]:
    expected = difflib.get_close_matches(word, possibilities, n=n, cutoff=cutoff)
    probe = rng.choice(possibilities) if possibilities else ""
    if rng.randrange(4) == 0:
        probe = repeat_mutate(rng, word, ASCII)
    roll = rng.randrange(10)
    if roll == 0:
        pair = ratio_pair(probe, word, autojunk=False)
    elif roll == 1:
        pair = ratio_pair(probe, word, junk=rng.choice((" ", "-_", " \t", "ae")))
    else:
        pair = ratio_pair(probe, word)
    case: dict[str, Any] = {
        "kind": kind,
        "word": word,
        "n": n,
        "cutoff": fmt(cutoff),
        "expected": expected,
        "pair": pair,
    }
    if pool is None:
        case["possibilities"] = possibilities
    else:
        case["pool"] = pool
    return case


def build() -> dict[str, Any]:
    rng = random.Random(SEED)
    pools = {**vocabulary_pools(), **command_pools()}
    pool_names = sorted(pools)
    cases: list[dict[str, Any]] = []

    def params() -> tuple[int, float]:
        cutoff = rng.choice(CUTOFFS) if rng.randrange(4) else round(rng.random(), 2)
        return rng.choice(NS), cutoff

    for _ in range(CASES_PER_KIND):
        base = random_word(rng, ASCII, 0, 14)
        possibilities = [repeat_mutate(rng, base, ASCII) for _ in range(rng.randint(0, 12))]
        possibilities += [random_word(rng, ASCII, 0, 14) for _ in range(rng.randint(0, 8))]
        rng.shuffle(possibilities)
        cases.append(
            make_case(rng, "ascii", repeat_mutate(rng, base, ASCII), possibilities, None, *params())
        )

    for _ in range(CASES_PER_KIND):
        base = random_word(rng, UNICODE, 0, 10)
        possibilities = [repeat_mutate(rng, base, UNICODE) for _ in range(rng.randint(0, 12))]
        possibilities += [random_word(rng, UNICODE, 0, 10) for _ in range(rng.randint(0, 6))]
        rng.shuffle(possibilities)
        cases.append(
            make_case(
                rng, "unicode", repeat_mutate(rng, base, UNICODE), possibilities, None, *params()
            )
        )

    vocab = [name for name in pool_names if name.startswith("vocab")]
    for _ in range(CASES_PER_KIND * 2):
        pool = rng.choice(vocab)
        word = repeat_mutate(rng, rng.choice(pools[pool]), ASCII)
        if rng.randrange(3) == 0:
            word = word.casefold()
        cases.append(make_case(rng, "vocabulary", word, pools[pool], pool, *params()))

    commands = [name for name in pool_names if name.startswith("commands")]
    for _ in range(CASES_PER_KIND):
        pool = rng.choice(commands)
        word = repeat_mutate(rng, rng.choice(pools[pool]), ASCII)
        cases.append(make_case(rng, "commands", word, pools[pool], pool, *params()))

    for _ in range(CASES_PER_KIND // 2):
        base = long_word(rng)
        possibilities = [repeat_mutate(rng, base, ASCII) for _ in range(rng.randint(1, 4))]
        possibilities += [long_word(rng), random_word(rng, ASCII, 0, 20)]
        rng.shuffle(possibilities)
        word = repeat_mutate(rng, base, ASCII) if rng.randrange(2) else long_word(rng)
        cases.append(make_case(rng, "long", word, possibilities, None, *params()))

    for _ in range(CASES_PER_KIND // 4):
        # Either side of the autojunk threshold, len(b) == 200.
        alphabet = rng.choice(("ab", "abc", "abcd", "xyz-_", "aab"))
        base = random_word(rng, alphabet, rng.choice((198, 199, 200, 201, 202)), 0)
        possibilities = [repeat_mutate(rng, base, alphabet) for _ in range(rng.randint(1, 4))]
        possibilities.append(random_word(rng, alphabet, 150, 250))
        rng.shuffle(possibilities)
        cases.append(make_case(rng, "threshold", base, possibilities, None, *params()))

    for _ in range(CASES_PER_KIND // 2):
        # Empty strings, duplicates and ties.
        base = random_word(rng, "abc", 0, 4)
        possibilities = [random_word(rng, "abc", 0, 4) for _ in range(rng.randint(0, 10))]
        possibilities += [""] * rng.randint(0, 2) + [base] * rng.randint(0, 2)
        rng.shuffle(possibilities)
        word = "" if rng.randrange(3) == 0 else base
        cases.append(make_case(rng, "edge", word, possibilities, None, *params()))

    for _ in range(CASES_PER_KIND // 2):
        # Separator and case variants of real names.
        pool = rng.choice(pool_names)
        name = rng.choice(pools[pool])
        variant = rng.choice(
            (
                name.upper(),
                name.casefold(),
                name.replace("-", "_"),
                name.replace("_", "-"),
                name.replace(" ", "_"),
                name.replace(" ", "-"),
                name.title(),
                name.swapcase(),
            )
        )
        cases.append(make_case(rng, "variants", variant, pools[pool], pool, *params()))

    return {"pools": pools, "cases": cases}


def render(data: dict[str, Any]) -> str:
    """One pool and one case per line, so a regenerated file diffs line by line."""

    def dump(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)

    lines = [
        "{",
        f'"generator": {dump("scripts/build/gen_difflib_cases.py")},',
        '"pools": {',
        ",\n".join(f"{dump(name)}: {dump(values)}" for name, values in data["pools"].items()),
        "},",
        '"cases": [',
        ",\n".join(dump(case) for case in data["cases"]),
        "]",
        "}",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when the fixture is stale")
    args = parser.parse_args()
    rendered = render(build())
    relative = TARGET.relative_to(ROOT)
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
        if current != rendered:
            print(f"{relative} is stale; run python3 scripts/build/gen_difflib_cases.py")
            return 1
        print(f"{relative} is current")
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    with TARGET.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)
    print(f"wrote {relative}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
