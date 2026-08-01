"""The scaffolding must produce a profile that passes conformance immediately.

docs/adoption.md: *a first profile that passes conformance in under a day*. If the
generated profile does not conform on generation, the open-world claim is practically
false and this whole mitigation is decorative.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from attest.cli import CommandLine, ProfileScaffold

pytestmark = pytest.mark.unit


def test_a_name_that_is_not_an_identifier_is_refused() -> None:
    with pytest.raises(ValueError, match="module name"):
        ProfileScaffold("food safety")


def test_the_scaffold_generates_a_complete_package(tmp_path: Path) -> None:
    written = ProfileScaffold("food_safety", jurisdiction="NG").write(tmp_path)
    names = {p.relative_to(tmp_path).as_posix() for p in written}
    assert "food_safety_profile/profile.py" in names
    assert "tests/test_food_safety_conformance.py" in names
    assert "tests/test_food_safety_redteam.py" in names
    assert "pyproject.toml" in names


@pytest.mark.security
def test_the_generated_profile_passes_conformance_on_generation(tmp_path: Path) -> None:
    # The claim adoption.md makes, executed. A generated profile that failed its own
    # kit would send every adopter straight into debugging scaffolding.
    ProfileScaffold("food_safety").write(tmp_path)
    # The environment is **inherited**, with only PYTHONPATH overridden. It used to be
    # replaced wholesale with `{"PYTHONPATH": ..., "PATH": "/usr/bin:/bin"}`, which was
    # meant to prove the generated package does not lean on the developer's shell. It
    # proved nothing of the sort — the interpreter is invoked by absolute path and finds
    # its own site-packages regardless — and on Windows it was actively broken: a child
    # process without `SystemRoot` cannot initialise winsock, so `import asyncio` inside
    # the nested pytest died with `OSError: [WinError 10106]` and this test failed on
    # every Windows run for a reason that had nothing to do with the scaffold.
    #
    # What the test is actually for is the claim in adoption.md: a generated profile
    # passes its own conformance suite on generation. That needs the package importable
    # from tmp_path and nothing else.
    environment = {**os.environ, "PYTHONPATH": str(tmp_path)}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "tests/"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    assert result.returncode == 0, (
        f"generated scaffolding does not pass its own conformance suite:\n"
        f"{result.stdout}\n{result.stderr}"
    )


@pytest.mark.security
def test_the_generated_default_branch_is_not_fail_open(tmp_path: Path) -> None:
    # The generated obligations_for must return a capability check rather than an
    # empty set, or the scaffold would teach the exact defect the kit catches.
    ProfileScaffold("food_safety").write(tmp_path)
    source = (tmp_path / "food_safety_profile" / "profile.py").read_text()
    assert "ObligationSet(tuple(obligations))" in source
    assert "return ObligationSet(())" not in source


def test_jurisdiction_is_a_parameter_not_a_separate_profile(tmp_path: Path) -> None:
    ProfileScaffold("mortgage", jurisdiction="UK").write(tmp_path)
    source = (tmp_path / "mortgage_profile" / "profile.py").read_text()
    assert 'jurisdiction = "UK"' in source
    assert "PARAMETER, not a separate profile" in source


def test_the_generated_package_registers_an_entry_point(tmp_path: Path) -> None:
    ProfileScaffold("mortgage").write(tmp_path)
    pyproject = (tmp_path / "pyproject.toml").read_text()
    assert '[project.entry-points."attest.domains"]' in pyproject
    assert "mortgage_profile:MortgageProfile" in pyproject


def test_the_cli_writes_the_scaffold(tmp_path: Path) -> None:
    code = CommandLine.run(["new-profile", "food_safety", "--into", str(tmp_path)])
    assert code == 0
    assert (tmp_path / "food_safety_profile" / "profile.py").exists()


def test_the_cli_accepts_a_jurisdiction(tmp_path: Path) -> None:
    CommandLine.run(["new-profile", "mortgage", "--jurisdiction", "NG", "--into", str(tmp_path)])
    assert 'jurisdiction = "NG"' in (tmp_path / "mortgage_profile" / "profile.py").read_text()
