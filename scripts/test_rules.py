#!/usr/bin/env python3
"""Compile every YARA rule in rules/ and check results against tests/expectations.yml.

Exits with status 0 when every fixture matches exactly the expected rules,
and 1 on any compile error, missing fixture, or mismatch.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml
import yara

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
FIXTURES_DIR = ROOT / "tests" / "fixtures"
EXPECTATIONS = ROOT / "tests" / "expectations.yml"


def build_eicar() -> bytes:
    """Assemble the EICAR test string in memory only.

    It is stored in two halves (the second reversed) so that no file in the
    repository contains the complete string and scanners are not triggered.
    """
    first = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    second_reversed = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE"
    return (first + second_reversed[::-1]).encode("ascii")


GENERATORS = {"eicar": build_eicar}


def compile_rules() -> yara.Rules:
    files = sorted(RULES_DIR.rglob("*.yar")) + sorted(RULES_DIR.rglob("*.yara"))
    if not files:
        sys.exit("No rule files found in rules/")
    filepaths = {str(p.relative_to(RULES_DIR)): str(p) for p in files}
    for ns, path in filepaths.items():
        print(f"  compiled  {ns}")
    rules = yara.compile(filepaths=filepaths)
    print(f"Compiled {len(files)} rule file(s).\n")
    return rules


def main() -> int:
    print("== Compiling rules ==")
    try:
        rules = compile_rules()
    except yara.Error as exc:
        print(f"COMPILE ERROR: {exc}")
        return 1

    spec = yaml.safe_load(EXPECTATIONS.read_text(encoding="utf-8")) or {}
    cases: list[tuple[str, bytes | None, set[str]]] = []
    for rel, expected in (spec.get("fixtures") or {}).items():
        path = FIXTURES_DIR / rel
        data = path.read_bytes() if path.is_file() else None
        cases.append((rel, data, set(expected or [])))
    for name, expected in (spec.get("generated") or {}).items():
        if name not in GENERATORS:
            print(f"Unknown generated fixture: {name}")
            return 1
        cases.append((f"<generated:{name}>", GENERATORS[name](), set(expected or [])))

    # Every file on disk must be listed in expectations.yml.
    listed = set((spec.get("fixtures") or {}).keys())
    unlisted = [str(p.relative_to(FIXTURES_DIR)) for p in FIXTURES_DIR.rglob("*")
                if p.is_file() and str(p.relative_to(FIXTURES_DIR)) not in listed]

    print("== Running fixtures ==")
    failures = 0
    for name, data, expected in cases:
        if data is None:
            print(f"  FAIL  {name}: fixture file not found")
            failures += 1
            continue
        actual = {m.rule for m in rules.match(data=data)}
        if actual == expected:
            label = ", ".join(sorted(actual)) or "no match (as expected)"
            print(f"  PASS  {name}: {label}")
        else:
            failures += 1
            print(f"  FAIL  {name}")
            if expected - actual:
                print(f"        missing:    {sorted(expected - actual)}")
            if actual - expected:
                print(f"        unexpected: {sorted(actual - expected)}")
    for rel in unlisted:
        failures += 1
        print(f"  FAIL  {rel}: not listed in tests/expectations.yml")

    total = len(cases) + len(unlisted)
    print(f"\n{total - failures}/{total} passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
