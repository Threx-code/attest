"""``attest new-profile`` — scaffolding that passes conformance on generation.

``docs/adoption.md`` sets the target: **a first profile that passes conformance in
under a day.** If the first profile takes weeks before anything runs, the open-world
claim is practically false, and this is the mitigation rather than a convenience.

The generated profile is deliberately *strict*. It inherits fail-closed defaults and
gates its own placeholder tool, so a team that generates one and forgets to finish it
gets refusals rather than a silently permissive agent.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["CommandLine", "ProfileScaffold"]


class ProfileScaffold:
    """Generates a domain profile package that conforms on the first run."""

    __slots__ = ("_jurisdiction", "_name")

    def __init__(self, name: str, *, jurisdiction: str | None = None) -> None:
        if not name.isidentifier():
            raise ValueError(
                f"{name!r} is not a valid Python identifier; the profile becomes a module name"
            )
        self._name = name
        self._jurisdiction = jurisdiction

    def files(self) -> dict[str, str]:
        """The generated package, as paths mapped to contents."""
        return {
            f"{self._name}_profile/__init__.py": self._init(),
            f"{self._name}_profile/profile.py": self._profile(),
            f"tests/test_{self._name}_conformance.py": self._conformance(),
            f"tests/test_{self._name}_redteam.py": self._redteam(),
            "pyproject.toml": self._pyproject(),
        }

    def write(self, destination: Path, *, force: bool = False) -> list[Path]:
        """Write the scaffold, refusing to destroy anything already there.

        The quickstart is ``attest new-profile mortgage`` run in an existing
        repository, and the generated set includes a root ``pyproject.toml``. Writing
        unconditionally would overwrite the host's — the single most valuable file in
        the directory — in the course of a command whose stated purpose is to help
        them get started.

        Nothing is written when anything would be clobbered: a partially-scaffolded
        tree is harder to recover from than none at all.
        """
        planned = {destination / relative: content for relative, content in self.files().items()}
        if not force:
            existing = sorted(str(path) for path in planned if path.exists())
            if existing:
                raise FileExistsError(
                    "refusing to overwrite files that already exist:\n  "
                    + "\n  ".join(existing)
                    + "\n\nScaffold into an empty directory, or pass --force if you "
                    "meant to replace them."
                )
        written: list[Path] = []
        for path, content in planned.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            written.append(path)
        return written

    # ── Templates ────────────────────────────────────────────────────────────

    def _class_name(self) -> str:
        return "".join(part.title() for part in self._name.split("_")) + "Profile"

    def _init(self) -> str:
        return (
            f'"""The {self._name} domain profile."""\n\n'
            f"from {self._name}_profile.profile import {self._class_name()}\n\n"
            f'__all__ = ["{self._class_name()}"]\n'
        )

    def _profile(self) -> str:
        jurisdiction = f'"{self._jurisdiction}"' if self._jurisdiction else "None"
        return f'''"""The {self._name} profile.

Two things to change before this is real, and the scaffold is deliberately strict
until you do — a generated profile that permitted everything would be worse than none.

1. `obligations_for` — what must be true before an action executes.
2. `extra_warrants` — what goes wrong here that the core four do not catch.

Everything else inherits fail-closed defaults from BaseProfile.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from attest.capabilities.authority import CapabilityCheck, ObligationSet
from attest.capabilities.profile import BaseProfile
from attest.kernel.warrants import WarrantKind

if TYPE_CHECKING:
    from attest.kernel.actions import Action
    from attest.kernel.context import ExecutionContext


class {self._class_name()}(BaseProfile):
    """Domain profile for {self._name}."""

    name = "{self._name}"
    version = "0.1.0"

    #: Jurisdiction is a PARAMETER, not a separate profile: the same shape with
    #: different data. Modelling it as a distinct profile is what produces the
    #: legal_ng.yaml / legal_uk_v2.yaml sprawl.
    jurisdiction = {jurisdiction}

    #: What goes wrong in this domain that the core four warrants do not catch?
    extra_warrants: frozenset[WarrantKind] = frozenset()

    def obligations_for(
        self, action: Action, context: ExecutionContext
    ) -> ObligationSet:
        """What must be discharged before this action executes.

        NOTE the shape of the default branch: it returns a capability check rather
        than an empty set. An empty ObligationSet for an unrecognised action permits
        every tool added after this file was written, and the conformance suite fails
        on exactly that.
        """
        obligations = [CapabilityCheck(action.capability or action.tool)]

        # if action.tool == "your_consequential_action":
        #     obligations.append(Approval(n=1, roles={{"your_role"}}))

        return ObligationSet(tuple(obligations))
'''

    def _conformance(self) -> str:
        return f'''"""Conformance. Two lines of integration, ~10 checks.

The fail-open cases are the point: a profile that cannot fail open is the minimum bar
for a high-stakes domain, and it is not something code review reliably catches.
"""

from attest.assurance.conformance import ProfileConformance

from {self._name}_profile import {self._class_name()}


class Test{self._class_name()}(ProfileConformance):
    profile = {self._class_name()}()
'''

    def _redteam(self) -> str:
        return f'''"""Domain-specific adversarial cases.

The shipped corpus covers all ten families generically. Add here the attacks that are
meaningless outside {self._name} — those are the ones nobody else can write for you.
"""

import pytest

from attest.assurance.redteam import Family, RedTeamCase, RedTeamSuite
from attest.kernel.verdicts import Verdict


class {self._class_name()}RedTeam(RedTeamSuite):
    extra_cases = (
        # RedTeamCase(
        #     family=Family.BOUNDARY_ESCAPE,
        #     name="a failure that only makes sense in {self._name}",
        #     must_not=(Verdict.ALLOW,),
        # ),
    )


def test_no_red_team_family_is_left_undeclared() -> None:
    """Structural only. This does NOT mean the families are tested.

    It passes for every domain, always, because the shipped declarations are non-empty.
    A green tick here has never sent an adversarial input at your profile — see the
    test below, which is the one that does.
    """
    assert {self._class_name()}RedTeam.families_undeclared() == frozenset()


def test_the_red_team_suite_actually_runs_against_this_profile() -> None:
    """The one that matters. Replace the skip once your engine is wired.

    A declared case with no attack counts as a FAILURE here rather than a skip: a skip
    in a red-team report reads as a pass to everybody except the person who wrote it.

        outcomes = {self._class_name()}RedTeam.run(engine=your_engine, binding=your_binding)
        failed = [o for o in outcomes if not o.passed]
        assert not failed, "\\n".join(o.render() for o in failed)
    """
    pytest.skip(
        "wire your engine and binding into RedTeamSuite.run(). Until you do, this "
        "profile has no adversarial coverage — the declaration test above is structural."
    )
'''

    def _pyproject(self) -> str:
        return f'''[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "{self._name}-profile"
version = "0.1.0"
description = "Attest domain profile for {self._name}"
requires-python = ">=3.11"
dependencies = ["attest-control-plane>=0.1"]

# Registered as an entry point so hosts can load it by name. Passing the profile
# directly works identically — entry points are a convenience, not a requirement.
[project.entry-points."attest.domains"]
{self._name} = "{self._name}_profile:{self._class_name()}"
'''


class CommandLine:
    """The ``attest`` command.

    A class rather than a function so the parser and the dispatch stay together: a
    subcommand added to one and forgotten in the other is the usual failure, and here
    they are members of the same object.
    """

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="attest", description="Attest — governed AI control plane"
        )
        sub = parser.add_subparsers(dest="command", required=True)

        new = sub.add_parser("new-profile", help="scaffold a domain profile package")
        new.add_argument("name", help="domain name, e.g. mortgage")
        new.add_argument("--jurisdiction", default=None, help="e.g. UK, NG")
        new.add_argument("--into", default=Path(), type=Path, help="destination directory")
        new.add_argument(
            "--force",
            action="store_true",
            help="overwrite existing files (the scaffold includes a root pyproject.toml)",
        )
        return parser

    @classmethod
    def run(cls, argv: Sequence[str] | None = None) -> int:
        """``attest new-profile <name> [--jurisdiction XX] [--into DIR]``."""
        args = cls.build_parser().parse_args(argv)
        if args.command == "new-profile":
            return cls._new_profile(
                name=args.name,
                jurisdiction=args.jurisdiction,
                into=args.into,
                force=args.force,
            )
        return 1  # pragma: no cover - argparse requires a known subcommand

    @classmethod
    def _new_profile(
        cls, *, name: str, jurisdiction: str | None, into: Path, force: bool = False
    ) -> int:
        scaffold = ProfileScaffold(name, jurisdiction=jurisdiction)
        try:
            written = scaffold.write(into, force=force)
        except FileExistsError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        for path in written:
            print(f"created {path}")
        print(
            "\nRun the conformance suite now — it should pass before you write a line "
            "of domain logic:\n    pytest"
        )
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(CommandLine.run())
