"""The evidence authority floor, and the one direction it may not fail.

`docs/capabilities/guards.md` is explicit that a guard may fail closed and never open.
The floor is where that is easiest to get wrong, because a *lower* floor is
indistinguishable from a permissive profile at every call site — nothing looks broken,
evidence is simply admitted that should not have been.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKinds,
    SourceRef,
    SourceType,
)
from attest.kernel.identifiers import EvidenceId, Hash

pytestmark = [pytest.mark.unit, pytest.mark.security]

AT = datetime(2026, 1, 1, tzinfo=UTC)


def _evidence(*, authority: AuthorityLevel = AuthorityLevel.ADVISORY) -> Evidence:
    return Evidence(
        evidence_id=EvidenceId("ev_1"),
        kind=EvidenceKinds.OBSERVATION,
        source=SourceRef(
            source_id="ledger-1",
            source_type=SourceType.LEDGER,
            authority=authority,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("b" * 64),
        ),
        value="the balance is 500000",
    )


@pytest.mark.security
def test_a_profile_that_raises_gets_the_strictest_floor_not_the_weakest() -> None:
    """ATT-65. The failure path returned the engine's own default.

    On success the floor is `max(declared, required)` — the stricter of the two, because
    a domain may raise its requirement and may not lower it. On failure it returned
    `self._required_authority`, which is by construction the weaker one. So a KeyError in
    a lookup table, a typo in a claim kind, or a config reload halfway through *relaxed*
    the check, and nothing reported it: from the caller's side a lower floor looks exactly
    like a permissive profile.

    That is the one direction docs/capabilities/guards.md forbids, and the defect class
    the audit found in every surveyed codebase — `except Exception:` followed by the
    permissive answer.
    """
    from attest.capabilities.evidence import EvidenceEngine
    from attest.kernel.evidence import AuthorityLevel

    def broken(_kind: str) -> AuthorityLevel:
        raise KeyError("this claim kind is not in the table")

    engine = EvidenceEngine(required_authority=AuthorityLevel.ADVISORY, authority_for=broken)
    floor = engine.floor_for(_evidence(authority=AuthorityLevel.ADVISORY))
    assert floor is AuthorityLevel.AUTHORITATIVE, (
        "a broken profile lowered the evidence authority floor, which is the one "
        "direction a guard may never fail"
    )


def test_a_working_profile_still_takes_the_stricter_of_the_two() -> None:
    """The success path is unchanged: a domain may raise its floor and may not lower it."""
    from attest.capabilities.evidence import EvidenceEngine
    from attest.kernel.evidence import AuthorityLevel

    strict = EvidenceEngine(
        required_authority=AuthorityLevel.ADVISORY,
        authority_for=lambda _k: AuthorityLevel.AUTHORITATIVE,
    )
    assert strict.floor_for(_evidence()) is AuthorityLevel.AUTHORITATIVE

    lax = EvidenceEngine(
        required_authority=AuthorityLevel.AUTHORITATIVE,
        authority_for=lambda _k: AuthorityLevel.ADVISORY,
    )
    assert lax.floor_for(_evidence()) is AuthorityLevel.AUTHORITATIVE, (
        "the profile lowered the engine's floor"
    )
