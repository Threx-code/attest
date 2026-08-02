"""Reading inside a tenant is not the same question as reading across one.

Tenancy answers "whose data is this". It does not answer "may *this person* see it", and in
every regulated profession the second has its own answer: an ethical wall between two teams
in a law firm, a Chinese wall between advisory and trading, need-to-know on a clinical
record. A framework modelling only the tenant treats a firm as one undifferentiated reader,
which no firm is.
"""

from __future__ import annotations

import pytest

from attest.kernel.context import VisibilityScope
from attest.kernel.identifiers import CorpusId, RunId

pytestmark = pytest.mark.unit


def test_an_unrestricted_scope_permits_everything() -> None:
    """The default, and every deployment that has no walls stays on it."""
    assert VisibilityScope().permits(corpus=CorpusId("law"), source_id="matter-1")


@pytest.mark.security
def test_a_barred_source_is_refused() -> None:
    """The wall itself: one matter this reader is conflicted out of."""
    scope = VisibilityScope(barred_sources=frozenset({"matter-9"}))

    assert not scope.permits(corpus=CorpusId("law"), source_id="matter-9")
    assert scope.permits(corpus=CorpusId("law"), source_id="matter-1")


@pytest.mark.security
def test_a_bar_wins_over_a_permitted_corpus() -> None:
    """A domain that permits broadly and screens one thing means the screen - the same
    resolution `Scope.permits_evidence` uses, and for the same reason."""
    scope = VisibilityScope(
        permitted_corpora=frozenset({CorpusId("law")}),
        barred_sources=frozenset({"matter-9"}),
    )

    assert not scope.permits(corpus=CorpusId("law"), source_id="matter-9")


@pytest.mark.security
def test_a_corpus_outside_the_allowlist_is_refused() -> None:
    scope = VisibilityScope(permitted_corpora=frozenset({CorpusId("law")}))

    assert not scope.permits(corpus=CorpusId("hr"), source_id="review-3")


@pytest.mark.security
def test_an_unknown_corpus_is_refused_under_an_allowlist() -> None:
    """`None` means the source declared no corpus. Under an allowlist that cannot be
    checked, and admitting what cannot be checked is how an allowlist stops being one."""
    scope = VisibilityScope(permitted_corpora=frozenset({CorpusId("law")}))

    assert not scope.permits(corpus=None, source_id="somewhere")


@pytest.mark.security
def test_an_agent_cannot_widen_the_actor_s_scope() -> None:
    """An agent declaring corpora it may read cannot thereby reach past a wall the reader
    is behind. The rule `Scope.narrowed_to` applies to delegation, applied to the reader."""
    actor = VisibilityScope(permitted_corpora=frozenset({CorpusId("law")}))

    widened = actor.narrowed_to(frozenset({CorpusId("law"), CorpusId("hr")}))

    assert widened.permitted_corpora == frozenset({CorpusId("law")})


def test_an_agent_with_no_declared_corpora_changes_nothing() -> None:
    actor = VisibilityScope(barred_sources=frozenset({"matter-9"}))

    assert actor.narrowed_to(frozenset()) is actor


@pytest.mark.security
def test_narrowing_keeps_the_bars() -> None:
    """A narrowed scope that dropped the wall would be the widening this method exists to
    prevent, arriving by a different route."""
    actor = VisibilityScope(barred_sources=frozenset({"matter-9"}))

    narrowed = actor.narrowed_to(frozenset({CorpusId("law")}))

    assert not narrowed.permits(corpus=CorpusId("law"), source_id="matter-9")


def test_the_scope_is_part_of_what_the_context_hashes() -> None:
    """A run that read behind a wall and one that did not are different runs, and a record
    that cannot tell them apart cannot answer the only question a conflicts review asks."""
    from datetime import UTC, datetime

    from attest.kernel.context import (
        ExecutionContext,
        IdentitySnapshot,
        ProfileRef,
        TenantBinding,
    )
    from attest.kernel.identifiers import ActorId, Hash, RunId, TenantId

    def context(scope: VisibilityScope) -> ExecutionContext:
        return ExecutionContext(
            run_id=RunId("run_1"),
            captured_at=datetime(2026, 8, 2, tzinfo=UTC),
            identity=IdentitySnapshot(actor=ActorId("alice"), tenant=TenantId("t1")),
            binding=TenantBinding(
                tenant=TenantId("t1"),
                profile=ProfileRef(name="generic", version="1.0.0"),
                config_hash=Hash("c" * 64),
            ),
            framework_version="0.1.0",
            policy_version="2026.08",
            visibility=scope,
        )

    walled = context(VisibilityScope(barred_sources=frozenset({"matter-9"})))
    open_ = context(VisibilityScope())

    assert walled.content_hash() != open_.content_hash()


# ── Entity chains ────────────────────────────────────────────────────────────


def test_an_entity_chain_is_distinguishable_from_a_run() -> None:
    """A run that never sealed is a fault worth investigating. An entity history that has
    not sealed is still going, and a sweep reporting every one would bury the fault."""
    from attest.kernel.audit import Chains

    entity = Chains.for_entity("Matter", "m-1")

    assert Chains.is_entity(entity)
    assert not Chains.is_entity(RunId("run_00000001"))


def test_two_entities_never_share_a_chain() -> None:
    from attest.kernel.audit import Chains

    assert Chains.for_entity("Matter", "m-1") != Chains.for_entity("Matter", "m-2")
    assert Chains.for_entity("Matter", "x") != Chains.for_entity("Account", "x")


@pytest.mark.parametrize(("kind", "identifier"), [("", "m-1"), ("Matter", ""), ("Matter", None)])
def test_a_chain_without_both_halves_is_refused(kind: str, identifier: object) -> None:
    """Without both, two entities share a chain and a gap in one reads as a gap in the
    other - which is the one thing a chain exists to make impossible."""
    from attest.kernel.audit import Chains

    with pytest.raises(ValueError, match="entity chain needs"):
        Chains.for_entity(kind, identifier)
