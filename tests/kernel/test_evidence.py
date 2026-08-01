"""Evidence must not be able to claim more than it establishes.

Three separate failures are guarded here: evidence that did not verify claiming to
support something, a source with no authority passing as authoritative, and an
unbounded or self-referencing tree turning verification into a denial-of-service.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from attest.kernel.evidence import (
    CORE_EVIDENCE_KINDS,
    MAX_DERIVATION_BREADTH,
    MAX_DERIVATION_DEPTH_CEILING,
    AuthorityLevel,
    Evidence,
    EvidenceKind,
    EvidenceKinds,
    Persistence,
    SourceRef,
    SourceType,
    SupportResult,
    ValidityWindow,
    VerificationOutcome,
)
from attest.kernel.identifiers import EvidenceId, Hash

RETRIEVED = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


def _source(**kw: object) -> SourceRef:
    base: dict[str, object] = {
        "source_id": "PW-2019",
        "source_type": SourceType.POLICY_DOC,
        "authority": AuthorityLevel.AUTHORITATIVE,
        "version": "7",
        "retrieved_at": RETRIEVED,
        "integrity_hash": Hash("a" * 64),
    }
    return SourceRef(**{**base, **kw})  # type: ignore[arg-type]


def _evidence(eid: str = "e1", **kw: object) -> Evidence:
    base: dict[str, object] = {
        "evidence_id": EvidenceId(eid),
        "kind": EvidenceKinds.QUOTED_SPAN,
        "source": _source(),
        "value": "policy covers escape of water",
    }
    return Evidence(**{**base, **kw})  # type: ignore[arg-type]


# ── Support cannot overclaim ─────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize("outcome", [VerificationOutcome.FAIL, VerificationOutcome.UNVERIFIABLE])
def test_unverified_evidence_cannot_claim_to_support(
    outcome: VerificationOutcome,
) -> None:
    with pytest.raises(ValueError, match="has not been shown to support"):
        SupportResult(supported=True, outcome=outcome, discrepancy="x")


@pytest.mark.unit
def test_a_failure_must_say_what_the_discrepancy_was() -> None:
    with pytest.raises(ValueError, match="triaged"):
        SupportResult(supported=False, outcome=VerificationOutcome.FAIL)


@pytest.mark.unit
def test_unverifiable_is_distinct_from_fail() -> None:
    # Collapsing UNVERIFIABLE into either PASS or FAIL is a lie: the source simply
    # cannot answer the question, which is common for last-write-wins systems.
    unverifiable = SupportResult(supported=False, outcome=VerificationOutcome.UNVERIFIABLE)
    assert unverifiable.outcome is not VerificationOutcome.FAIL
    assert unverifiable.supported is False


@pytest.mark.unit
def test_exact_verification_carries_no_confidence() -> None:
    assert SupportResult(supported=True, outcome=VerificationOutcome.PASS).confidence is None


@pytest.mark.unit
def test_a_judged_result_carries_confidence_and_a_judge_ref() -> None:
    judged = SupportResult(
        supported=True,
        outcome=VerificationOutcome.PASS,
        confidence=0.82,
        judge_ref="cross-family-panel-v1",
    )
    assert judged.confidence == 0.82
    assert judged.judge_ref is not None


@pytest.mark.unit
@pytest.mark.parametrize("value", [-0.1, 1.5])
def test_confidence_outside_the_unit_interval_is_rejected(value: float) -> None:
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        SupportResult(supported=True, outcome=VerificationOutcome.PASS, confidence=value)


# ── Source authority is separate from content integrity ──────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_authority_levels_are_ordered_weakest_first() -> None:
    assert AuthorityLevel.AUTHORITATIVE.at_least(AuthorityLevel.ADVISORY)
    assert not AuthorityLevel.UNVERIFIED.at_least(AuthorityLevel.ADVISORY)
    assert AuthorityLevel.ADVISORY.at_least(AuthorityLevel.ADVISORY)


@pytest.mark.unit
@pytest.mark.security
def test_a_user_supplied_source_does_not_meet_an_authoritative_floor() -> None:
    # The counterexample from the docs: a quote verifies perfectly against a PDF
    # anyone could have uploaded. Integrity passed; authority did not.
    uploaded = _source(authority=AuthorityLevel.USER_SUPPLIED, source_type=SourceType.USER_SUPPLIED)
    assert not uploaded.authority.at_least(AuthorityLevel.AUTHORITATIVE)


@pytest.mark.unit
def test_a_source_must_be_versioned() -> None:
    with pytest.raises(ValueError, match="unverifiable"):
        _source(version="")


@pytest.mark.unit
def test_a_source_must_have_an_id() -> None:
    with pytest.raises(ValueError, match="source_id"):
        _source(source_id="")


# ── Validity is evaluated against the relevant date, not "now" ───────────────────


@pytest.mark.unit
def test_validity_window_covers_dates_inside_it() -> None:
    window = ValidityWindow(effective_from=date(2019, 1, 1), effective_to=date(2024, 3, 1))
    assert window.covers(date(2021, 6, 1))


@pytest.mark.unit
def test_validity_window_excludes_dates_outside_it() -> None:
    window = ValidityWindow(effective_from=date(2019, 1, 1), effective_to=date(2024, 3, 1))
    assert not window.covers(date(2018, 12, 31))
    assert not window.covers(date(2024, 3, 2))


@pytest.mark.unit
def test_an_unbounded_window_covers_everything() -> None:
    assert ValidityWindow().covers(date(1900, 1, 1))


@pytest.mark.unit
def test_a_superseded_wording_still_covers_the_loss_date() -> None:
    # The insurance case: the wording in force ON THE DATE OF LOSS governs, not
    # today's. Citing the current wording for a 2019 loss is a verifiable citation
    # and a wrong decision.
    wording = ValidityWindow(effective_from=date(2019, 1, 1), effective_to=date(2024, 3, 1))
    loss_date = date(2021, 6, 1)
    assert wording.covers(loss_date)
    assert not wording.covers(date(2026, 7, 31))


# ── Trees are bounded and acyclic ────────────────────────────────────────────────


@pytest.mark.unit
def test_a_leaf_has_depth_one() -> None:
    assert _evidence().depth() == 1
    assert _evidence().node_count() == 1


@pytest.mark.unit
def test_depth_and_node_count_walk_the_subtree() -> None:
    leaf_a = _evidence("a")
    leaf_b = _evidence("b", value="excess is GBP 250")
    mid = _evidence(
        "mid", kind=EvidenceKinds.DERIVATION, value="subtotal", sub_evidence=(leaf_a, leaf_b)
    )
    root = _evidence("root", kind=EvidenceKinds.DERIVATION, value="total", sub_evidence=(mid,))
    assert root.depth() == 3
    assert root.node_count() == 4


def _chain(depth: int) -> Evidence:
    """A derivation chain of exactly ``depth`` nodes."""
    node = _evidence("leaf")
    for level in range(depth - 1):
        node = _evidence(
            f"n{level}", kind=EvidenceKinds.DERIVATION, value=level, sub_evidence=(node,)
        )
    return node


@pytest.mark.unit
def test_a_tree_at_exactly_the_hard_ceiling_is_accepted() -> None:
    # The boundary matters as much as the rejection: a ceiling that fires one level
    # early would refuse legitimate reporting trees.
    assert _chain(MAX_DERIVATION_DEPTH_CEILING).depth() == MAX_DERIVATION_DEPTH_CEILING


@pytest.mark.unit
@pytest.mark.security
def test_a_tree_deeper_than_the_hard_ceiling_is_rejected() -> None:
    # Unbounded recursion makes verify() a denial-of-service target, and an
    # attestation may arrive from an untrusted export bundle.
    at_ceiling = _chain(MAX_DERIVATION_DEPTH_CEILING)
    with pytest.raises(ValueError, match="hard ceiling"):
        _evidence("over", kind=EvidenceKinds.DERIVATION, value="over", sub_evidence=(at_ceiling,))


@pytest.mark.unit
@pytest.mark.security
def test_an_over_wide_level_is_rejected() -> None:
    children = tuple(_evidence(f"c{i}", value=i) for i in range(MAX_DERIVATION_BREADTH + 1))
    with pytest.raises(ValueError, match="summarised"):
        _evidence("wide", kind=EvidenceKinds.DERIVATION, value="total", sub_evidence=children)


@pytest.mark.unit
@pytest.mark.security
def test_the_same_source_may_be_cited_from_two_branches_of_one_derivation() -> None:
    """A DAG, not a cycle — and the most ordinary shape in the target domains.

    A reconciliation summing two figures, each verified against the same ledger row at
    the same version, cites that row twice. Rejecting it as a cycle would make the
    framework unable to express its own worked examples.
    """
    leaf = _evidence("leaf")
    parent = _evidence("parent", kind=EvidenceKinds.DERIVATION, value="v", sub_evidence=(leaf,))
    root = Evidence(
        evidence_id=EvidenceId("root"),
        kind=EvidenceKinds.DERIVATION,
        source=_source(),
        value="v",
        sub_evidence=(parent, leaf, _evidence("leaf")),
    )
    assert len(root.sub_evidence) == 3


def test_a_tree_larger_than_the_node_budget_is_rejected() -> None:
    """The bound that actually does work: a hostile bundle is where recursion arrives.

    Depth and breadth multiply out to roughly sixteen thousand nodes, and verification
    walks every one of them.
    """
    from attest.kernel.evidence import MAX_DERIVATION_NODES

    # Within the breadth limit at every level, and over the node budget in total.
    wide = tuple(_evidence(f"leaf-{n}") for n in range(MAX_DERIVATION_BREADTH))
    branches = tuple(
        _evidence(f"b{n}", kind=EvidenceKinds.DERIVATION, value=f"v{n}", sub_evidence=wide)
        for n in range(9)
    )
    assert len(wide) * len(branches) > MAX_DERIVATION_NODES
    with pytest.raises(ValueError, match="nodes"):
        Evidence(
            evidence_id=EvidenceId("root"),
            kind=EvidenceKinds.DERIVATION,
            source=_source(),
            value="v",
            sub_evidence=branches,
        )


# ── Content addressing ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_identical_evidence_hashes_identically() -> None:
    assert _evidence().content_hash() == _evidence().content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_altering_the_value_changes_the_hash() -> None:
    assert _evidence().content_hash() != _evidence(value="tampered").content_hash()


@pytest.mark.unit
@pytest.mark.security
def test_altering_a_child_changes_the_root_hash() -> None:
    # Tampering deep in a derivation tree must surface at the root, or the leaf-set
    # summarisation in storage.md proves nothing.
    original = _evidence(
        "root", kind=EvidenceKinds.DERIVATION, value="t", sub_evidence=(_evidence("a"),)
    )
    tampered = _evidence(
        "root", kind=EvidenceKinds.DERIVATION, value="t", sub_evidence=(_evidence("a", value="x"),)
    )
    assert original.content_hash() != tampered.content_hash()


@pytest.mark.unit
def test_evidence_id_is_not_part_of_the_content_hash() -> None:
    # The hash addresses CONTENT. Two identical items retrieved under different
    # local ids are the same evidence.
    assert _evidence("e1").content_hash() == _evidence("e2").content_hash()


@pytest.mark.unit
def test_metadata_is_frozen_after_construction() -> None:
    evidence = _evidence(metadata={"note": "x"})
    with pytest.raises(TypeError):
        evidence.metadata["note"] = "y"  # type: ignore[index]


# ── Openness ─────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_the_five_shipped_kinds_are_exactly_these() -> None:
    assert len(CORE_EVIDENCE_KINDS) == 5
    assert EvidenceKinds.QUOTED_SPAN in CORE_EVIDENCE_KINDS
    assert EvidenceKinds.DERIVATION in CORE_EVIDENCE_KINDS


@pytest.mark.unit
def test_a_domain_can_register_its_own_evidence_kind() -> None:
    # Only one of the five shipped kinds is document-shaped; a domain that verifies
    # something we never imagined must not need a kernel change.
    chain_of_custody = EvidenceKind("chain_of_custody")
    item = _evidence(kind=chain_of_custody, persistence=Persistence.EMBEDDED)
    assert item.kind == "chain_of_custody"
    assert item.content_hash()


@pytest.mark.unit
def test_digest_is_the_default_persistence() -> None:
    # Right for most regulated work: self-verifying for the value actually cited,
    # without embedding a 40-page document.
    assert _evidence().persistence is Persistence.DIGEST
