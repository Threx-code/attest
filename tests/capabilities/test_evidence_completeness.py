"""Evidence verification and coverage. Red-team families 2 and 6."""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest

from attest.capabilities.completeness import (
    CorpusRef,
    CoverageReport,
    Query,
    RequiredSources,
    TruncationEvent,
)
from attest.capabilities.evidence import (
    EvidenceEngine,
    QuotedSpanVerifier,
    VerifierRegistry,
)
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKind,
    EvidenceKinds,
    SourceRef,
    SourceType,
    SupportResult,
    VerificationOutcome,
)
from attest.kernel.identifiers import CorpusId, EvidenceId, Hash
from tests.capabilities.conftest import AT, make_evidence

pytestmark = pytest.mark.unit
TODAY = date(2026, 7, 31)


class Records:
    """A source system keyed by source id, answering with canonical bytes."""

    def __init__(self, documents: dict[str, str]) -> None:
        self.documents = documents

    def fetch(self, source_id: str, version: str) -> bytes | None:
        found = self.documents.get(source_id)
        return None if found is None else found.encode()


class Sources:
    """A source system. **Outside the evidence**, which is the whole point.

    The verifiers used to read `metadata["source_text"]` — a key on the object being
    verified — so whoever wrote the citation also wrote the document it was checked
    against. Every test below that wants a PASS now has to say what the source actually
    holds, which is the property the production path needs too.
    """

    def __init__(self, **documents: str) -> None:
        self.documents = {name: text.encode() for name, text in documents.items()}
        self.asked: list[tuple[str, str]] = []

    def fetch(self, source_id: str, version: str) -> bytes | None:
        self.asked.append((source_id, version))
        return self.documents.get(source_id)

    def hash_of(self, source_id: str) -> Hash:
        from attest.kernel.canonical import Canonical

        return Hash(Canonical.digest_bytes(self.documents[source_id]))


def _engine(**kw: object) -> EvidenceEngine:
    return EvidenceEngine(**kw)  # type: ignore[arg-type]


def resolved(value: str, document: str, **metadata: Any) -> tuple[EvidenceEngine, Evidence]:
    """Evidence whose source really resolves, and whose integrity hash really matches."""
    sources = Sources(**{"PW-2019": document})
    item = make_evidence(value, integrity_hash=sources.hash_of("PW-2019"), **metadata)
    return EvidenceEngine(resolver=sources), item


# ── Verification ─────────────────────────────────────────────────────────────


def test_a_present_quote_verifies() -> None:
    engine, item = resolved("escape of water", "the policy covers escape of water")
    assert engine.verify(item, at=TODAY).outcome is VerificationOutcome.PASS


@pytest.mark.security
def test_a_fabricated_quote_fails() -> None:
    # The single most common LLM failure: an invented citation.
    engine, item = resolved("covers flood damage", "the policy covers escape of water")
    result = engine.verify(item, at=TODAY)
    assert result.outcome is VerificationOutcome.FAIL
    assert not result.supported


@pytest.mark.security
def test_a_quote_at_the_wrong_offset_fails() -> None:
    engine, item = resolved("escape", "the policy covers escape of water", char_start=0)
    assert engine.verify(item, at=TODAY).outcome is VerificationOutcome.FAIL


@pytest.mark.security
def test_a_quote_verified_against_its_own_metadata_is_unverifiable() -> None:
    """ATT-33. Whoever wrote the citation used to supply the document too.

    A fabricated quote to a statute that does not exist verified perfectly, because
    `metadata["source_text"]` was accepted as the source. With no resolver the honest
    answer is UNVERIFIABLE, which is a finding somebody can act on.
    """
    forged = make_evidence(
        "The threshold is GBP 10,000.",
        source_text="The threshold is GBP 10,000.",
        char_start=0,
    )
    assert _engine().verify(forged, at=TODAY).outcome is VerificationOutcome.UNVERIFIABLE


@pytest.mark.security
def test_a_source_whose_bytes_do_not_match_the_integrity_hash_is_unverifiable() -> None:
    """The hash is what pins the document. A swapped source must not verify."""
    sources = Sources(**{"PW-2019": "the policy covers escape of water"})
    mismatched = make_evidence("escape of water", integrity_hash=Hash("b" * 64))
    engine = EvidenceEngine(resolver=sources)
    assert engine.verify(mismatched, at=TODAY).outcome is VerificationOutcome.UNVERIFIABLE


@pytest.mark.security
def test_an_unreachable_source_is_unverifiable_rather_than_a_failure() -> None:
    """ "We could not reach the record system" is not "the record says otherwise".

    Collapsing them would make an outage look like forgery, and forgery look routine.
    """

    class Down:
        def fetch(self, source_id: str, version: str) -> bytes | None:
            raise ConnectionError("record system unreachable")

    engine = EvidenceEngine(resolver=Down())
    assert engine.verify(make_evidence("x"), at=TODAY).outcome is VerificationOutcome.UNVERIFIABLE


@pytest.mark.security
def test_absent_source_text_is_unverifiable_not_a_pass() -> None:
    # Under REFERENCE persistence the text is gone. Re-fetching whatever the source
    # says today would be a pass obtained by changing the question.
    assert _engine().verify(make_evidence(), at=TODAY).outcome is VerificationOutcome.UNVERIFIABLE


@pytest.mark.security
def test_an_unregistered_kind_is_unverifiable_not_assumed_verified() -> None:
    registry = VerifierRegistry((QuotedSpanVerifier(),))
    exotic = Evidence(
        evidence_id=EvidenceId("e9"),
        kind=EvidenceKind("chain_of_custody"),
        source=SourceRef(
            source_id="s",
            source_type=SourceType.THIRD_PARTY,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value="x",
    )
    assert registry.verify(exotic, at=TODAY).outcome is VerificationOutcome.UNVERIFIABLE


@pytest.mark.security
def test_a_verifier_that_raises_is_unverifiable_not_a_pass() -> None:
    class Exploding:
        kind = EvidenceKinds.QUOTED_SPAN

        def verify(
            self, evidence: Evidence, *, at: date, source: bytes | None = None
        ) -> SupportResult:
            raise RuntimeError("source system down")

    registry = VerifierRegistry((Exploding(),))
    result = registry.verify(make_evidence(), at=TODAY)
    assert result.outcome is VerificationOutcome.UNVERIFIABLE
    assert "RuntimeError" in (result.discrepancy or "")


def test_a_record_value_that_changed_fails_with_the_discrepancy() -> None:
    item = Evidence(
        evidence_id=EvidenceId("e2"),
        kind=EvidenceKinds.RECORD_VALUE,
        source=SourceRef(
            source_id="policy-8823",
            source_type=SourceType.RECORD_SYSTEM,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="7",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value="250",
    )
    # The record system says 500; the citation says 250. The source is asked, not the
    # citation — `metadata["recorded_value"]` used to answer this, which meant the
    # record was compared to a copy of itself supplied by whoever cited it.
    ledger = Records({"policy-8823": '"500"'})
    result = EvidenceEngine(resolver=ledger).verify(item, at=TODAY)
    assert result.outcome is VerificationOutcome.FAIL
    assert "500" in (result.discrepancy or "")


@pytest.mark.security
def test_a_record_value_with_no_source_system_is_unverifiable() -> None:
    """Many record systems are last-write-wins and cannot answer "what did it say at v7".

    UNVERIFIABLE is the honest answer to that, and it is what an auditor needs to see.
    """
    item = Evidence(
        evidence_id=EvidenceId("e2b"),
        kind=EvidenceKinds.RECORD_VALUE,
        source=SourceRef(
            source_id="policy-8823",
            source_type=SourceType.RECORD_SYSTEM,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="7",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value="250",
        metadata={"recorded_value": "250"},
    )
    assert _engine().verify(item, at=TODAY).outcome is VerificationOutcome.UNVERIFIABLE


def test_a_derivation_with_no_sub_evidence_derives_from_nothing() -> None:
    item = Evidence(
        evidence_id=EvidenceId("e3"),
        kind=EvidenceKinds.DERIVATION,
        source=SourceRef(
            source_id="calc",
            source_type=SourceType.LEDGER,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value="4.2m",
    )
    assert _engine().verify(item, at=TODAY).outcome is VerificationOutcome.FAIL


def test_an_out_of_calibration_observation_fails() -> None:
    item = Evidence(
        evidence_id=EvidenceId("e4"),
        kind=EvidenceKinds.OBSERVATION,
        source=SourceRef(
            source_id="lims",
            source_type=SourceType.LAB,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value="74 mmol/mol",
        metadata={"device_id": "cobas-c503", "calibration_valid": False},
    )
    registry = Records({"lims": '"74 mmol/mol"'})
    assert (
        EvidenceEngine(resolver=registry).verify(item, at=TODAY).outcome is VerificationOutcome.FAIL
    )


@pytest.mark.security
def test_an_observation_with_no_device_registry_is_unverifiable() -> None:
    """A reading must not assert that its own instrument was in calibration."""
    item = Evidence(
        evidence_id=EvidenceId("e4b"),
        kind=EvidenceKinds.OBSERVATION,
        source=SourceRef(
            source_id="lims",
            source_type=SourceType.LAB,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value="74 mmol/mol",
        metadata={"device_id": "cobas-c503", "calibration_valid": True},
    )
    assert _engine().verify(item, at=TODAY).outcome is VerificationOutcome.UNVERIFIABLE


# ── The epistemic warrant checks TWO things ──────────────────────────────────


@pytest.mark.security
def test_a_genuine_quote_from_an_unauthoritative_source_fails() -> None:
    # The counterexample: the quote verifies perfectly against a PDF anyone could
    # have uploaded. Content integrity is not source authority.
    item = make_evidence(
        "the threshold is GBP 10,000",
        authority=AuthorityLevel.USER_SUPPLIED,
        source_text="the threshold is GBP 10,000",
    )
    engine = _engine(required_authority=AuthorityLevel.AUTHORITATIVE)
    report = engine.evaluate([item], at=TODAY)
    assert not report.satisfied
    assert any(f.code == "insufficient_source_authority" for f in report.findings)


def test_an_authoritative_verified_quote_satisfies() -> None:
    engine, item = resolved("escape of water", "covers escape of water")
    assert engine.evaluate([item], at=TODAY).satisfied


@pytest.mark.security
def test_no_evidence_is_unsatisfied_not_vacuously_true() -> None:
    report = _engine().evaluate([], at=TODAY)
    assert not report.satisfied
    assert report.findings[0].code == "no_evidence"


# ── Coverage ─────────────────────────────────────────────────────────────────


def _coverage(**kw: object) -> CoverageReport:
    base: dict[str, object] = {
        "corpora": (CorpusRef(CorpusId("sanctions"), "2026-Q3"),),
        "query_plan": (Query("acme ltd", CorpusId("sanctions"), 50),),
        "required": RequiredSources.of("uk_sanctions", "un_consolidated"),
        "satisfied_sources": frozenset({"uk_sanctions", "un_consolidated"}),
    }
    return CoverageReport(**{**base, **kw})  # type: ignore[arg-type]


def test_full_coverage_satisfies() -> None:
    assert _coverage().warrant().satisfied


@pytest.mark.security
def test_a_missing_required_source_fails() -> None:
    # A sanctions determination that never consulted the UN list, caught
    # mechanically with no model judgement involved.
    report = _coverage(satisfied_sources=frozenset({"uk_sanctions"})).warrant()
    assert not report.satisfied
    assert any("un_consolidated" in f.message for f in report.findings)


@pytest.mark.security
def test_truncation_fails_the_warrant() -> None:
    # "top 20 of 4,312 matches", answered from the 20. The most common
    # completeness failure in production retrieval, and it errors nowhere else.
    report = _coverage(
        truncations=(TruncationEvent(CorpusId("sanctions"), returned=20, available=4312),)
    ).warrant()
    assert not report.satisfied
    assert any(f.code == "truncated" for f in report.findings)


@pytest.mark.security
def test_an_unavailable_source_fails() -> None:
    assert not _coverage(failed_sources=frozenset({"ofac_sdn"})).warrant().satisfied


def test_declared_residual_scope_is_recorded_but_does_not_fail() -> None:
    # Honest scope is not a failure — it is the difference between a stated
    # boundary and an implied claim of totality.
    report = _coverage(residual=("archived filings before 2010",)).warrant()
    assert report.satisfied
    assert any(f.code == "residual_scope" for f in report.findings)


def test_missing_sources_are_computed_from_the_requirement() -> None:
    assert _coverage(satisfied_sources=frozenset()).missing_sources == {
        "uk_sanctions",
        "un_consolidated",
    }


def test_a_truncation_cannot_claim_more_returned_than_available() -> None:
    with pytest.raises(ValueError, match="fewer than returned"):
        TruncationEvent(CorpusId("c"), returned=50, available=10)


# ── The tree, and the clock ──────────────────────────────────────────────────


def _leaf(eid: str, value: str, recorded: str) -> Evidence:
    return Evidence(
        evidence_id=EvidenceId(eid),
        kind=EvidenceKinds.RECORD_VALUE,
        source=SourceRef(
            source_id=eid,
            source_type=SourceType.LEDGER,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value=value,
        metadata={"recorded_value": recorded},
    )


def _derivation(*children: Evidence) -> Evidence:
    return Evidence(
        evidence_id=EvidenceId("total"),
        kind=EvidenceKinds.DERIVATION,
        source=SourceRef(
            source_id="calc",
            source_type=SourceType.LEDGER,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("a" * 64),
        ),
        value="Q3 provision is GBP 4.2m",
        sub_evidence=children,
    )


@pytest.mark.security
def test_a_failing_leaf_is_not_laundered_into_a_passing_total() -> None:
    """ATT-34. A derivation used to be verified by counting its children.

    `evaluate` iterated the top-level sequence only, so 412 fabricated leaves beneath a
    total were never handed to any verifier — and a child that fails on its own was
    invisible under a parent. That is the exact shape every aggregate in the reporting
    domain takes.
    """
    ledger = Records({"c1": '"1"'})
    engine = EvidenceEngine(resolver=ledger)
    liar = _leaf("c1", "4200000", "4200000")

    assert engine.verify(liar, at=TODAY).outcome is VerificationOutcome.FAIL
    report = engine.evaluate([_derivation(liar)], at=TODAY)
    assert not report.satisfied, "a failing leaf passed under its parent"
    assert any("sub-evidence items failed" in f.message for f in report.findings)


@pytest.mark.security
def test_every_node_in_the_tree_produces_its_own_finding() -> None:
    """The whole tree is verified, so a reader can see which leaf is the problem."""
    ledger = Records({"c1": '"1"', "c2": '"2"'})
    report = EvidenceEngine(resolver=ledger).evaluate(
        [_derivation(_leaf("c1", "999", "999"), _leaf("c2", "2", "2"))], at=TODAY
    )
    ids = {f.data.get("evidence_id") for f in report.findings}
    assert "c1" in ids, "the failing leaf is not named in the findings"


@pytest.mark.security
def test_a_derivation_over_unverifiable_children_is_unverifiable_not_passing() -> None:
    """ "We could not check the parts" cannot add up to "the total is verified"."""
    report = _engine().evaluate([_derivation(_leaf("c1", "1", "1"))], at=TODAY)
    assert not report.satisfied


@pytest.mark.security
def test_evidence_outside_its_validity_window_is_flagged() -> None:
    """ATT-35. ValidityWindow was implemented, correct, and called by nothing.

    A clinical guideline replaced in 2020, cited for a 2026 decision, satisfied the
    epistemic warrant — the right decision's shape with the wrong decision's content,
    and a verifiable citation attached.
    """
    from attest.kernel.evidence import ValidityWindow

    document = "old guidance"
    sources = Sources(**{"PW-2019": document})
    stale = Evidence(
        evidence_id=EvidenceId("stale"),
        kind=EvidenceKinds.QUOTED_SPAN,
        source=SourceRef(
            source_id="PW-2019",
            source_type=SourceType.POLICY_DOC,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="3",
            retrieved_at=AT,
            integrity_hash=sources.hash_of("PW-2019"),
            validity=ValidityWindow(effective_to=date(2020, 1, 1)),
        ),
        value="old guidance",
    )
    engine = EvidenceEngine(resolver=sources)
    assert engine.verify(stale, at=TODAY).outcome is VerificationOutcome.PASS, (
        "the content is genuine; it is the currency that fails"
    )
    report = engine.evaluate([stale], at=TODAY)
    assert not report.satisfied
    assert {f.code for f in report.findings} == {"evidence_out_of_validity"}


def test_evidence_inside_its_window_is_not_flagged() -> None:
    from attest.kernel.evidence import ValidityWindow

    sources = Sources(**{"PW-2019": "current guidance"})
    current = Evidence(
        evidence_id=EvidenceId("live"),
        kind=EvidenceKinds.QUOTED_SPAN,
        source=SourceRef(
            source_id="PW-2019",
            source_type=SourceType.POLICY_DOC,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="7",
            retrieved_at=AT,
            integrity_hash=sources.hash_of("PW-2019"),
            validity=ValidityWindow(effective_from=date(2026, 1, 1)),
        ),
        value="current guidance",
    )
    assert EvidenceEngine(resolver=sources).evaluate([current], at=TODAY).satisfied


@pytest.mark.security
def test_the_profiles_authority_floor_is_consulted_not_the_default() -> None:
    """ATT-44. A domain that requires AUTHORITATIVE used to get ADVISORY.

    The conformance kit tested `required_authority` for fail-closed behaviour and the
    run path never called it.
    """
    sources = Sources(**{"PW-2019": "covers escape of water"})
    advisory = make_evidence(
        "covers escape of water",
        authority=AuthorityLevel.ADVISORY,
        integrity_hash=sources.hash_of("PW-2019"),
    )
    lenient = EvidenceEngine(resolver=sources)
    assert lenient.evaluate([advisory], at=TODAY).satisfied

    strict = EvidenceEngine(
        resolver=sources,
        authority_for=lambda _kind: AuthorityLevel.AUTHORITATIVE,
    )
    report = strict.evaluate([advisory], at=TODAY)
    assert not report.satisfied
    assert {f.code for f in report.findings} == {"insufficient_source_authority"}


def test_a_profile_that_raises_does_not_lower_the_floor() -> None:
    """Fail-closed: a broken profile must not become a permissive one."""

    def explodes(kind: str) -> AuthorityLevel:
        raise RuntimeError("profile is broken")

    engine = EvidenceEngine(required_authority=AuthorityLevel.AUTHORITATIVE, authority_for=explodes)
    assert engine.floor_for(make_evidence()) is AuthorityLevel.AUTHORITATIVE
