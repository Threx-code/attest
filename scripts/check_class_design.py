#!/usr/bin/env python3
"""Fail the build when the package drifts away from its class-based design.

Recorded as a rule rather than a preference because it decayed once already: the
capability layer grew a mix of engine classes and loose module functions doing the
same kind of job, which is the shape that makes a codebase feel arbitrary.

Two checks:

1. **No module-level functions in the package.** Behaviour belongs on a class — an
   engine that holds its collaborators, a namespace for shipped vocabulary, or a method
   on the value object it concerns. A free function taking six arguments is an object
   that has not been written yet, and it cannot be injected or swapped.

2. **No module-level private helpers.** A ``_helper`` beside a class is behaviour that
   escaped it. It becomes a private method.

Dunder module attributes (``__all__``, ``__version__``) are exempt: they are protocol,
not behaviour.

Run: python scripts/check_class_design.py
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "src" / "attest"


class DesignCheck:
    """Walks the package and reports drift from the class-based design."""

    def __init__(self, package: Path) -> None:
        self._package = package

    def run(self) -> list[str]:
        failures: list[str] = []
        for path in sorted(self._package.rglob("*.py")):
            failures.extend(self._check_file(path))
        return failures

    def _check_file(self, path: Path) -> list[str]:
        rel = path.relative_to(self._package.parent.parent)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        failures: list[str] = []

        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                failures.append(
                    f"{rel}:{node.lineno}: module-level function {node.name!r}. "
                    f"Behaviour belongs on a class — an engine holding its "
                    f"collaborators, a namespace for shipped vocabulary, or a method "
                    f"on the value object it concerns."
                )
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id.startswith("_")
                        and not target.id.startswith("__")
                        and not target.id.isupper()
                        and not target.id.lstrip("_").isupper()
                    ):
                        failures.append(
                            f"{rel}:{node.lineno}: module-level private {target.id!r}. "
                            f"A helper beside a class is behaviour that escaped it; "
                            f"make it a private method."
                        )
        return failures


def main() -> int:
    failures = DesignCheck(PACKAGE).run()
    if failures:
        print("Class-design check FAILED:\n", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s). See ADR 0042.", file=sys.stderr)
        return 1
    print("Class-design check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
