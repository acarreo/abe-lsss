#!/usr/bin/env python3
"""Génère tests/abe-access-control-vectors.json à partir du binaire abe-policy.

Chaque cas est rejoué via le binaire (aucune valeur n'est calculée à la main) :
- `abe-policy policy "<policy>"` pour le parsing de la politique
- `abe-policy attributes "<attributes>"` pour le parsing de la liste d'attributs
- `abe-policy logic "<policy>" "<attributes>"` pour la satisfaction logique

Voir cli/POLICY.md section 6 pour la description du format de sortie et de la
démarche.
"""
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN = REPO_ROOT / ".build" / "cli" / "abe-policy"
OUTPUT = REPO_ROOT / "tests" / "abe-access-control-vectors.json"

# (name, policy_or_None, attributes_or_None, expect_satisfies_or_None)
# expect_satisfies is only meaningful when both policy and attributes are set
# and are expected to parse successfully.
CASES = [
    # --- Booléen ---
    ("cp-and-simple", "(Alice and Bob)", "Alice|Bob", True),
    ("cp-or-simple", "(Alice or Bob)", "Bob", True),
    ("cp-nested-satisfied", "Alice and (Bob or (Charlie and Dave))", "Alice|Charlie|Dave", True),
    ("cp-nested-unsatisfied", "Alice and (Bob or (Charlie and Dave))", "Alice|Charlie", False),
    ("cp-duplicate-attr-or", "(Alice or Alice)", "Alice", True),
    ("cp-duplicate-attr-and", "(Alice and Alice)", "Alice", True),
    ("cp-missing-attribute", "(Alice and Bob)", "Alice", False),

    # --- Attributs longs / préfixés ---
    ("cp-long-attribute", "a-very-long-attribute-name-past-sixteen",
     "a-very-long-attribute-name-past-sixteen", True),
    ("cp-prefixed-attribute-satisfied", "((Alice and Bob) or uid:567abc)", "uid:567abc", True),
    ("cp-prefixed-attribute-unsatisfied", "((Alice and Bob) or uid:567abc)", "Alice", False),

    # --- Numérique ---
    ("num-gt-satisfied", "Day > 5", "Day=7", True),
    ("num-gt-unsatisfied", "Day > 5", "Day=3", False),
    ("num-ge-satisfied", "(Day >= 5)", "Day=5", True),
    ("num-ge-unsatisfied", "(Day >= 12)", "Day=7", False),
    ("num-lt-satisfied", "(Day < 25)", "Day=17", True),
    ("num-lt-unsatisfied", "(Day < 5)", "Day=17", False),
    ("num-le-satisfied", "(Day <= 7000)", "Day=7000", True),
    ("num-le-unsatisfied", "(Day <= 5)", "Day=7000", False),
    ("num-eq-expint-satisfied", "(Month == 7#4)", "Month=7#4", True),
    ("num-eq-expint-unsatisfied", "(Month == 6#4)", "Month=7#4", False),
    ("num-in-range-exclusive-satisfied", "(Level in (2-35))", "Level=20", True),
    ("num-in-range-exclusive-boundary-excluded", "(Level in (2-35))", "Level=35", False),
    ("num-in-range-inclusive-boundary-included", "Level in {2-35}", "Level=35", True),
    ("num-mixed-and-satisfied", "(Month<12#4 and Bob)", "Month=7#4|Bob", True),
    ("num-mixed-and-unsatisfied-missing-attr", "(Month<12#4 and Bob)", "Month=7#4", False),

    # --- Dates ---
    ("date-eq-satisfied", "Date = May 5, 2016", "Date=May 5, 2016", True),
    ("date-eq-unsatisfied", "Date = May 5, 2016", "Date=May 6, 2016", False),
    ("date-lt-satisfied", "(Date < January 1, 2017 and Bob)", "Date=December 15, 2015|Bob", True),
    ("date-lt-unsatisfied", "(Date < January 1, 2017 and Bob)", "Date=March 10, 2017|Bob", False),
    ("date-range-satisfied", "((Date = December 10-16, 2016) and Charlie)",
     "Date=December 15, 2016|Charlie", True),
    ("date-range-unsatisfied", "((Date = December 10-16, 2016) and Charlie)",
     "Date=December 1, 2016|Charlie", False),

    # --- Politiques invalides (parsing uniquement, pas d'attributs) ---
    ("month-invalid-bits", "Month < 16#4", None, None),
    ("month-zero-bits", "Month < 4#0", None, None),
    ("negative-int-gt", "Month > -1#4", None, None),
    ("negative-int-lt", "Month < -3#4", None, None),
    ("date-before-epoch", "Date = January 1, 1968", None, None),
    ("date-invalid-start-range", "Date = January 0-10, 1970", None, None),
    ("date-invalid-end-range", "Date = January 1-40, 1970", None, None),
    ("date-invalid-format", "(One or Two) and (Date : January 1, 1970)", None, None),
    ("expint-in-input-policy", "Alice or foo_expint04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx", None, None),

    # --- Politiques valides mais testées seulement en parsing ---
    ("date-range-valid-parse-only", "Date = January 1-31, 2016", None, None),
    ("date-gt-valid-parse-only", "Date > January 5, 2016", None, None),
    ("date-lt-valid-parse-only", "Date < January 5, 2016", None, None),
    ("date-le-valid-parse-only", "Date <= January 5, 2016", None, None),
    ("date-ge-valid-parse-only", "Date >= January 5, 2016", None, None),
    ("int-range-equivalent-form", "Level > 2 and Level < 35", None, None),
]

# (name, attributes) — cas où seule la liste d'attributs est testée (pas de politique)
ATTR_ONLY_CASES = [
    ("expint-in-input-attribute", "foo_expint04_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx0xx|bar"),
    ("comparison-op-in-attrlist", "Alice|Day >= 100|Bob"),
    ("expint-overflow-in-attrlist", "Alice|Day = 1000#8|Bob"),
]


def run(args):
    proc = subprocess.run([str(BIN)] + args, capture_output=True, text=True)
    return proc.returncode, proc.stdout


def check_policy_parses(policy_str):
    rc, _ = run(["policy", policy_str])
    return rc == 0


def check_attrs_parses(attr_str):
    rc, _ = run(["attributes", attr_str])
    return rc == 0


def check_satisfies(policy_str, attr_str):
    rc, out = run(["logic", policy_str, attr_str])
    satisfied = "Check if satisfied => true" in out
    match_count = None
    for line in out.splitlines():
        if line.startswith("Number of matches"):
            match_count = int(line.split("=>")[1].strip())
    return satisfied, match_count


def build_vectors():
    if not BIN.exists():
        print(f"abe-policy binary not found at {BIN}. Build it first "
              f"(cmake --build .build --target abe-policy).", file=sys.stderr)
        sys.exit(1)

    vectors = []
    for name, policy_str, attr_str, expected_satisfies in CASES:
        entry = {"kind": "access-control", "name": name}
        expect_parses = check_policy_parses(policy_str)
        if attr_str is not None and expect_parses:
            expect_parses = expect_parses and check_attrs_parses(attr_str)
        entry["policy"] = policy_str
        if attr_str is not None:
            entry["attributes"] = attr_str
        entry["expect_parses"] = expect_parses

        if attr_str is not None and expect_parses:
            satisfied, match_count = check_satisfies(policy_str, attr_str)
            entry["expect_satisfies"] = satisfied
            if match_count is not None:
                entry["match_count"] = match_count
            if expected_satisfies is not None and expected_satisfies != satisfied:
                print(f"WARNING: {name}: expected satisfies={expected_satisfies} "
                      f"but got {satisfied}", file=sys.stderr)
        vectors.append(entry)

    for name, attr_str in ATTR_ONLY_CASES:
        entry = {
            "kind": "access-control",
            "name": name,
            "attributes": attr_str,
            "expect_parses": check_attrs_parses(attr_str),
        }
        vectors.append(entry)

    return vectors


def main():
    vectors = build_vectors()
    OUTPUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n")
    print(f"Wrote {len(vectors)} vectors to {OUTPUT}")


if __name__ == "__main__":
    main()
