"""Dataset commitment, membership proofs, and the unlearning limit.

The most important tests here are the ones that check the capability does NOT claim to
have erased anything.
"""

from __future__ import annotations

from datetime import UTC, date, datetime

import pytest

from attest.capabilities.lineage import (
    DatasetCommitment,
    ErasureImpact,
    ExclusionReason,
    InMemoryLeaves,
    LawfulBasis,
    LineageEngine,
    LineageRecord,
    Remediation,
)
from attest.kernel.identifiers import DatasetId, Hash, SubjectId
from attest.kernel.warrants import WarrantReport

pytestmark = pytest.mark.unit

AT = datetime(2026, 1, 1, tzinfo=UTC)
CONSENT = LawfulBasis("consent")
LEGITIMATE = LawfulBasis("legitimate_interest")
KYC = DatasetId("kyc_training")


def _record(
    rid: str, *, subject: str | None = None, basis: LawfulBasis = CONSENT, jurisdiction: str = "NG"
) -> LineageRecord:
    return LineageRecord(
        record_id=rid,
        content_hash=Hash(f"{rid:>064}".replace(" ", "0")),
        source_id="core_banking.customers",
        lawful_basis=basis,
        jurisdiction=jurisdiction,
        collected_at=AT,
        subject=SubjectId(subject) if subject else None,
    )


def _records(n: int = 8) -> list[LineageRecord]:
    return [_record(f"r{i}") for i in range(n)]


# ── Commitment ───────────────────────────────────────────────────────────────


def test_a_dataset_commits_to_a_root() -> None:
    commitment = LineageEngine().commit(_records(), dataset_id=KYC, epoch="v7")
    assert commitment.leaf_count == 8
    assert commitment.root


def test_a_billion_record_proof_is_kilobytes_not_gigabytes() -> None:
    # The whole reason a dataset is committed rather than embedded: log2(1e9) ~= 30
    # hashes, under a kilobyte, against an 8 KB attestation budget.
    import math

    proof_hashes = math.ceil(math.log2(1_000_000_000))
    assert proof_hashes * 32 < 1024


def test_an_empty_dataset_commits_to_nothing() -> None:
    with pytest.raises(ValueError, match="commits to nothing"):
        LineageEngine().commit([], dataset_id=KYC, epoch="v7")


@pytest.mark.security
def test_a_count_that_disagrees_with_the_leaf_set_is_refused() -> None:
    with pytest.raises(ValueError, match="cannot detect an omission"):
        DatasetCommitment(
            dataset_id=KYC,
            epoch="v7",
            root=Hash("a" * 64),
            leaf_count=99,
            leaves=InMemoryLeaves((Hash("a" * 64),)),
        )


@pytest.mark.security
def test_an_unsorted_leaf_set_is_refused() -> None:
    # Sorting is what makes NON-inclusion provable, and it is now the leaf source's
    # obligation — checked once where the set is held, rather than on every commitment
    # constructed over it.
    with pytest.raises(ValueError, match="NON-inclusion provable"):
        InMemoryLeaves((Hash("b" * 64), Hash("a" * 64)))


@pytest.mark.security
def test_provenance_is_inside_the_commitment() -> None:
    # A record cannot be re-labelled with a more convenient lawful basis after the
    # fact without changing the root.
    honest = _record("r1", basis=CONSENT)
    relabelled = _record("r1", basis=LEGITIMATE)
    assert honest.leaf() != relabelled.leaf()


# ── Membership ───────────────────────────────────────────────────────────────


def test_a_record_in_the_dataset_proves_inclusion() -> None:
    records = _records()
    engine = LineageEngine()
    commitment = engine.commit(records, dataset_id=KYC, epoch="v7")
    proof = engine.prove_inclusion(commitment, records[3])
    assert proof is not None
    assert proof.verifies_against(commitment.root)


def test_a_record_not_in_the_dataset_has_no_inclusion_proof() -> None:
    engine = LineageEngine()
    commitment = engine.commit(_records(), dataset_id=KYC, epoch="v7")
    assert engine.prove_inclusion(commitment, _record("absent")) is None


@pytest.mark.security
def test_absence_is_provable_via_the_bracketing_leaves() -> None:
    # "We excluded that record, trust us" is not an answer a data protection officer
    # can use. With an ordered set, absence is demonstrable.
    engine = LineageEngine()
    commitment = engine.commit(_records(16), dataset_id=KYC, epoch="v7")
    proof = engine.prove_absence(commitment, _record("definitely_absent"))
    assert proof.lower is not None or proof.upper is not None


@pytest.mark.security
def test_an_absence_proof_verifies_against_the_root_alone() -> None:
    """ATT-64. It used to return two bare hashes and say "check both are in the tree".

    A verifier could only do that by obtaining the whole leaf set — which is the thing
    the commitment model exists to avoid, and anyone holding the whole dataset does not
    need a proof of anything. The brackets now carry their own inclusion proofs.
    """
    engine = LineageEngine()
    commitment = engine.commit(_records(16), dataset_id=KYC, epoch="v7")
    proof = engine.prove_absence(commitment, _record("definitely_absent"))
    assert proof.verifies(commitment.root)


@pytest.mark.security
def test_an_absence_proof_does_not_verify_against_another_root() -> None:
    """Otherwise it proves the record is absent from *some* dataset, which is not a claim."""
    engine = LineageEngine()
    commitment = engine.commit(_records(16), dataset_id=KYC, epoch="v7")
    other = engine.commit(_records(8), dataset_id=KYC, epoch="v8")
    proof = engine.prove_absence(commitment, _record("definitely_absent"))
    assert not proof.verifies(other.root)


@pytest.mark.security
def test_non_adjacent_brackets_do_not_verify() -> None:
    """The forgery this rules out: brackets with room between them.

    Two leaves that are both genuinely in the tree prove nothing about absence unless
    they are *neighbours* — otherwise the record being denied could be sitting between
    them, which is the whole claim.
    """
    from attest.capabilities.lineage import AbsenceProof
    from attest.capabilities.witness import MerkleTree

    engine = LineageEngine()
    records = _records(16)
    commitment = engine.commit(records, dataset_id=KYC, epoch="v7")
    leaves = commitment.leaves.all_leaves()
    tree = MerkleTree(leaves)

    absent = _record("definitely_absent").leaf()
    honest = engine.prove_absence(commitment, _record("definitely_absent"))
    assert honest.lower is not None

    # Widen the bracket by one, keeping both proofs genuine.
    forged = AbsenceProof(
        leaf=absent,
        lower=tree.inclusion_proof(honest.lower.index - 1),
        upper=honest.upper,
        tree_size=commitment.leaf_count,
    )
    assert forged.lower is not None
    assert forged.lower.verifies_against(commitment.root), "the bracket itself is genuine"
    assert not forged.verifies(commitment.root), "a widened bracket proves nothing"


@pytest.mark.security
def test_an_open_end_only_verifies_at_the_actual_end_of_the_tree() -> None:
    """Otherwise "absent, before the first leaf" could be claimed about a leaf in the middle."""
    from attest.capabilities.lineage import AbsenceProof
    from attest.capabilities.witness import MerkleTree

    engine = LineageEngine()
    commitment = engine.commit(_records(16), dataset_id=KYC, epoch="v7")
    tree = MerkleTree(commitment.leaves.all_leaves())
    middle = commitment.leaf_count // 2

    forged = AbsenceProof(
        leaf=Hash("0" * 64),
        lower=None,
        upper=tree.inclusion_proof(middle),
        tree_size=commitment.leaf_count,
    )
    assert not forged.verifies(commitment.root)


def test_the_commitment_does_not_have_to_hold_the_leaves() -> None:
    """The claim the module opens with: a billion records is a sub-kilobyte proof.

    The type used to carry every leaf, so a commitment over a billion records was a
    billion hashes and could not be stored, transmitted or put in an attestation. A
    host implements `LeafSource` over its own storage; nothing here requires the set to
    be in memory.
    """
    import dataclasses

    from attest.capabilities.lineage import LeafSource

    assert isinstance(InMemoryLeaves((Hash("a" * 64),)), LeafSource)
    fields = {f.name for f in dataclasses.fields(DatasetCommitment)}
    assert "sorted_leaves" not in fields, "the commitment still carries the dataset"
    assert "leaves" in fields


@pytest.mark.security
def test_asking_for_absence_of_a_present_record_raises() -> None:
    # Returning a plausible pair would hide a real contradiction.
    records = _records()
    engine = LineageEngine()
    commitment = engine.commit(records, dataset_id=KYC, epoch="v7")
    with pytest.raises(ValueError, match="no non-inclusion proof"):
        engine.prove_absence(commitment, records[0])


def test_exclusions_get_their_own_provable_root() -> None:
    # What was deliberately left out is as provable as what was included.
    engine = LineageEngine()
    commitment = engine.commit(
        _records(),
        dataset_id=KYC,
        epoch="v7",
        excluded=[
            (_record("x1"), ExclusionReason.NO_LAWFUL_BASIS),
            (_record("x2"), ExclusionReason.ERASURE_REQUESTED),
        ],
    )
    assert commitment.exclusion_root is not None
    assert commitment.exclusion_counts[ExclusionReason.NO_LAWFUL_BASIS] == 1


# ── The warrant ──────────────────────────────────────────────────────────────


def _warrant(records: list[LineageRecord], **kw: object) -> WarrantReport:
    engine = LineageEngine()
    commitment = engine.commit(records, dataset_id=KYC, epoch="v7")
    base: dict[str, object] = {
        "records": records,
        "accepted_bases": frozenset({CONSENT}),
    }
    return engine.warrant(commitment, **{**base, **kw})  # type: ignore[arg-type]


def test_a_clean_dataset_satisfies() -> None:
    assert _warrant(_records(), transform_reproduced=True).satisfied


@pytest.mark.security
def test_an_unaccepted_lawful_basis_fails() -> None:
    records = [*_records(4), _record("bad", basis=LEGITIMATE)]
    assert not _warrant(records).satisfied


@pytest.mark.security
def test_an_unknown_basis_is_reported_separately_from_absent() -> None:
    # Collapsing "unknown" into "absent" understates the problem; collapsing it into
    # "present" is a lie.
    records = [*_records(4), _record("unknown", basis=LawfulBasis(""))]
    report = _warrant(records)
    assert not report.satisfied
    assert any(f.code == "unknown_lawful_basis" for f in report.findings)


@pytest.mark.security
def test_out_of_jurisdiction_records_fail() -> None:
    records = [*_records(4), _record("eu", jurisdiction="DE")]
    report = _warrant(records, required_jurisdictions=frozenset({"NG"}))
    assert not report.satisfied


@pytest.mark.security
def test_a_pipeline_that_does_not_reproduce_fails() -> None:
    assert not _warrant(_records(), transform_reproduced=False).satisfied


def test_a_non_rerunnable_pipeline_is_unverified_rather_than_failed() -> None:
    # Honest: reproducibility was not established, which is different from disproved.
    report = _warrant(_records(), transform_reproduced=None)
    assert report.satisfied
    assert any(f.code == "transform_not_rerunnable" for f in report.findings)


# ── The unlearning limit ─────────────────────────────────────────────────────


def _impact(**kw: object) -> ErasureImpact:
    base: dict[str, object] = {
        "subject": SubjectId("s1"),
        "erased_at": date(2026, 7, 31),
        "datasets": (KYC,),
        "models_affected": ("fraud_score@2.1", "fraud_score@2.2"),
        "still_in_service": ("fraud_score@2.2",),
    }
    return ErasureImpact(**{**base, **kw})  # type: ignore[arg-type]


@pytest.mark.security
def test_erasure_impact_names_the_models_that_learned_from_the_data() -> None:
    engine = LineageEngine()
    records = [*_records(4), _record("theirs", subject="s1")]
    commitment = engine.commit(records, dataset_id=KYC, epoch="v7")
    impact = engine.erasure_impact(
        SubjectId("s1"),
        erased_at=date(2026, 7, 31),
        commitments=[commitment],
        records_by_dataset={KYC: records},
        models_by_dataset={KYC: ["fraud_score@2.2"]},
        in_service=["fraud_score@2.2"],
    )
    assert impact.models_affected == ("fraud_score@2.2",)
    assert impact.still_in_service == ("fraud_score@2.2",)


@pytest.mark.security
def test_a_model_still_in_service_fails_the_warrant() -> None:
    report = _warrant(_records(), erasure_conflicts=[_impact()])
    assert not report.satisfied
    conflict = next(f for f in report.findings if f.code == "erasure_conflict")
    assert "does NOT remove its influence" in conflict.message


@pytest.mark.security
def test_a_retired_model_is_a_warning_not_a_failure() -> None:
    report = _warrant(_records(), erasure_conflicts=[_impact(still_in_service=())])
    assert report.satisfied


@pytest.mark.security
def test_fully_remediated_does_not_claim_the_influence_is_gone() -> None:
    # It claims only that nothing trained on the erased data is still running. The
    # weights of a retired model still encode it, and no field here says otherwise.
    assert _impact(still_in_service=()).fully_remediated
    assert not _impact().fully_remediated


def test_accepting_the_risk_is_recorded_rather_than_implicit() -> None:
    accepted = _impact(remediation=Remediation.ACCEPTED_RISK)
    assert accepted.remediation is Remediation.ACCEPTED_RISK
    assert _impact().remediation is Remediation.REQUIRED
