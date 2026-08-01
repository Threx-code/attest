"""Data lineage — which records produced this model, and were they lawfully held?

Every other capability governs a *decision*. This governs the artifact a
decision-making model was built from, and it is the only one whose central limit
cannot be engineered away.

A training run **is** an Action: it has arguments, costs money, produces an artifact
and is irreversible, so it uses the existing propose/discharge/grant/execute lifecycle
unchanged. The grant binds the **dataset root** alongside the model and
hyperparameters, so a run authorised against ``v7`` cannot silently train on ``v8``.

The genuine mismatch is scale, not lifecycle. Evidence trees are bounded at ~8 KB and a
training set has 10^6 to 10^9 leaves, so a dataset is **committed** rather than embedded: a
billion records is a 30-hash inclusion proof, under a kilobyte. The leaf set is
**sorted**, which buys non-inclusion proofs — and "we excluded that record, trust us"
is not an answer a data protection officer can use.

.. warning::

   **A model trained on data you must erase cannot un-learn it.** Deleting the record
   does not remove its influence on the weights. Machine unlearning is an open research
   problem, not an engineering task, and this capability does not solve it. What it
   does is convert an unanswerable question into a *tracked liability*: an
   :class:`ErasureImpact` naming which models are affected and which remain in service,
   with the decision to retrain or accept the risk recorded and owned by a human.

   That is a real contribution and it is not erasure. Any surface presenting it as
   erasure is misrepresenting the system.
"""

from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, NewType, Protocol, runtime_checkable

from attest.capabilities.witness import MerkleTree
from attest.kernel.canonical import Canonical
from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import date, datetime

    from attest.capabilities.witness import InclusionProof
    from attest.kernel.identifiers import DatasetId, Hash, SubjectId

__all__ = [
    "AbsenceProof",
    "DatasetCommitment",
    "ErasureImpact",
    "ExclusionReason",
    "InMemoryLeaves",
    "LawfulBasis",
    "LeafSource",
    "LineageEngine",
    "LineageRecord",
    "Remediation",
]

LawfulBasis = NewType("LawfulBasis", str)
"""Open, and deliberately so.

The framework does not know what GDPR Article 6(1)(f) or NDPA 2023 §25 mean, and
shipping that knowledge would breach the thesis. It knows only that a profile's policy
must accept the basis before a record may be committed.
"""


class ExclusionReason(StrEnum):
    """Why a record was deliberately left out.

    Recorded with its own root, so what was excluded is as provable as what was
    included — an exclusion nobody can demonstrate is indistinguishable from an
    omission nobody noticed.
    """

    NO_LAWFUL_BASIS = "no_lawful_basis"
    ERASURE_REQUESTED = "erasure_requested"
    OUT_OF_JURISDICTION = "out_of_jurisdiction"
    SPECIAL_CATEGORY = "special_category"
    QUALITY = "quality"


class Remediation(StrEnum):
    """What is being done about a model that learned from erased data."""

    REQUIRED = "required"
    SCHEDULED = "scheduled"
    ACCEPTED_RISK = "accepted_risk"
    """A human decided to keep it in service. Recorded and owned, never implicit."""


@dataclass(frozen=True, slots=True)
class LineageRecord:
    """One training record, committed by content plus its provenance."""

    record_id: str
    content_hash: Hash
    source_id: str
    lawful_basis: LawfulBasis
    jurisdiction: str
    collected_at: datetime
    subject: SubjectId | None = None
    """So erasure can find it later. ``None`` for a record about no identifiable
    person, never as a shorthand for 'we did not look'."""

    consent_ref: str | None = None

    def leaf(self) -> Hash:
        """The committed leaf: content AND provenance.

        Provenance is inside the commitment, so a record cannot be re-labelled with a
        more convenient lawful basis after the fact without changing the root.
        """
        return MerkleTree.leaf_hash(
            Canonical.encode(
                {
                    "record_id": self.record_id,
                    "content_hash": self.content_hash,
                    "source_id": self.source_id,
                    "lawful_basis": self.lawful_basis,
                    "jurisdiction": self.jurisdiction,
                    "collected_at": self.collected_at,
                    "subject": self.subject,
                    "consent_ref": self.consent_ref,
                }
            )
        )


@runtime_checkable
class LeafSource(Protocol):
    """Where a commitment's leaves live. **Not necessarily in the commitment.**

    This module opens by saying *"a billion records is a 30-hash inclusion proof, under
    a kilobyte"*, and the commitment type held a billion hashes — so the artefact that
    exists to avoid carrying the dataset carried the dataset. ATT-64.

    A host with a real dataset implements this over its own storage: an index, a table,
    an object store. :class:`InMemoryLeaves` is the small-dataset case and the one every
    test uses, and it is deliberately a separate class rather than a default, so that
    reaching for it in production is a decision somebody made rather than one they
    inherited.
    """

    def count(self) -> int: ...

    def index_of(self, leaf: Hash) -> int | None:
        """Where ``leaf`` sorts, or ``None`` if it is absent."""
        ...

    def bracket(self, leaf: Hash) -> tuple[int | None, int | None]:
        """The indices of the leaves immediately below and above ``leaf``.

        ``None`` on either side when ``leaf`` sorts outside the set. Indices rather than
        hashes, because the caller needs an inclusion proof for each and a proof is
        built from a position.
        """
        ...

    def at(self, index: int) -> Hash: ...

    def all_leaves(self) -> tuple[Hash, ...]:
        """Every leaf, in order. Needed to build a proof.

        On this protocol rather than assumed, because a source over a billion records
        will want to override how a proof is constructed rather than materialise the
        set — and a protocol that hid the cost would let it happen by accident.
        """
        ...


class InMemoryLeaves:
    """A leaf set held in memory. For datasets small enough that this is honest.

    Deliberately not a dataclass. A frozen dataclass generates ``__match_args__``, which
    makes it structurally incompatible with a hand-written :class:`LeafSource` — so a
    host implementing the protocol over its own storage would be rejected where this one
    is accepted, which is precisely backwards for the class that exists as the *small*
    case.
    """

    __slots__ = ("leaves",)

    def __init__(self, leaves: tuple[Hash, ...]) -> None:
        self.leaves = leaves
        if list(self.leaves) != sorted(self.leaves):
            raise ValueError(
                "leaves are not sorted. Sorting is what makes NON-inclusion provable, "
                "and non-inclusion is the proof a data protection officer needs."
            )

    def count(self) -> int:
        return len(self.leaves)

    def index_of(self, leaf: Hash) -> int | None:
        position = bisect_left(self.leaves, leaf)
        if position < len(self.leaves) and self.leaves[position] == leaf:
            return position
        return None

    def bracket(self, leaf: Hash) -> tuple[int | None, int | None]:
        position = bisect_left(self.leaves, leaf)
        lower = position - 1 if position > 0 else None
        upper = position if position < len(self.leaves) else None
        return lower, upper

    def at(self, index: int) -> Hash:
        return self.leaves[index]

    def all_leaves(self) -> tuple[Hash, ...]:
        return self.leaves


@dataclass(frozen=True, slots=True)
class AbsenceProof:
    """A record was **not** in the dataset, and here is why a verifier may believe it.

    The previous version returned two bare hashes and told the verifier to "check both
    are in the tree" — handing them nothing to check with. Verifying a bare hash's
    membership requires the whole leaf set, which is the thing the commitment model
    exists to avoid, so the proof was unverifiable by anyone who did not already have
    the dataset. And anyone who has the dataset does not need a proof.

    Now each bracket carries its own inclusion proof, so the check is: both proofs
    verify against the root, they are adjacent, and the absent leaf sorts strictly
    between them. All of that is checkable from this object and a root.
    """

    leaf: Hash
    lower: InclusionProof | None
    upper: InclusionProof | None
    tree_size: int

    def verifies(self, root: Hash) -> bool:
        """Whether this really proves absence, against ``root``. **No trust required.**

        Each of the four conditions rules out a distinct forgery:

        - the brackets verify against the root — otherwise they are hashes somebody
          made up;
        - they are *adjacent* — non-adjacent brackets leave room for the leaf between
          them, which is exactly what is being denied;
        - the absent leaf sorts strictly between them — a bracket on the wrong side
          proves nothing;
        - an open end is only permitted at the actual end of the tree, or an absence
          "before the first leaf" could be claimed about a leaf sitting in the middle.
        """
        if self.lower is None and self.upper is None:
            return self.tree_size == 0
        if self.lower is not None:
            if not self.lower.verifies_against(root) or not self.lower.leaf < self.leaf:
                return False
            if self.upper is None:
                return self.lower.index == self.tree_size - 1
        if self.upper is not None:
            if not self.upper.verifies_against(root) or not self.leaf < self.upper.leaf:
                return False
            if self.lower is None:
                return self.upper.index == 0
        # Both are non-None here: an open end returned above.
        return self.upper.index == self.lower.index + 1  # type: ignore[union-attr]


@dataclass(frozen=True, slots=True)
class DatasetCommitment:
    """A dataset, committed rather than embedded.

    The root and the count are the commitment. The **leaves are behind a
    :class:`LeafSource`**, because this type used to hold every one of them: a module
    whose opening claim is that a billion records is a sub-kilobyte proof shipped a
    value object carrying a billion hashes, so nothing about it could be stored,
    transmitted or put in an attestation. ATT-64.

    Ordering is still what makes non-inclusion provable — with an ordered leaf set,
    proving a record is absent means exhibiting the two adjacent leaves that bracket
    where it would have been — and it is now the source's obligation rather than a
    property re-checked on every construction.
    """

    dataset_id: DatasetId
    epoch: str
    root: Hash
    leaf_count: int
    leaves: LeafSource
    exclusion_root: Hash | None = None
    exclusion_counts: dict[ExclusionReason, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.leaf_count != self.leaves.count():
            raise ValueError(
                f"commitment claims {self.leaf_count} leaves but its source holds "
                f"{self.leaves.count()}; a count that disagrees with the set cannot "
                f"detect an omission"
            )


class LineageEngine:
    """Commits datasets, proves membership, and tracks erasure impact."""

    __slots__ = ()

    def commit(
        self,
        records: Sequence[LineageRecord],
        *,
        dataset_id: DatasetId,
        epoch: str,
        excluded: Sequence[tuple[LineageRecord, ExclusionReason]] = (),
    ) -> DatasetCommitment:
        """Commit a dataset by Merkle root.

        Excluded records get their own tree, so the exclusion set is provable rather
        than asserted.
        """
        if not records:
            raise ValueError("a dataset with no records commits to nothing")

        leaves = tuple(sorted(record.leaf() for record in records))
        tree = MerkleTree(leaves)

        exclusion_root: Hash | None = None
        counts: dict[ExclusionReason, int] = {}
        if excluded:
            excluded_leaves = tuple(sorted(record.leaf() for record, _ in excluded))
            exclusion_root = MerkleTree(excluded_leaves).root()
            for _, reason in excluded:
                counts[reason] = counts.get(reason, 0) + 1

        return DatasetCommitment(
            dataset_id=dataset_id,
            epoch=epoch,
            root=tree.root(),
            leaf_count=len(leaves),
            leaves=InMemoryLeaves(leaves),
            exclusion_root=exclusion_root,
            exclusion_counts=counts,
        )

    def prove_inclusion(
        self, commitment: DatasetCommitment, record: LineageRecord
    ) -> InclusionProof | None:
        """Prove a record was in the dataset. ``None`` when it was not."""
        leaf = record.leaf()
        index = commitment.leaves.index_of(leaf)
        if index is None:
            return None
        return MerkleTree(commitment.leaves.all_leaves()).inclusion_proof(index)

    def prove_absence(self, commitment: DatasetCommitment, record: LineageRecord) -> AbsenceProof:
        """Prove a record was NOT in the dataset, **verifiably**.

        Returns the two adjacent brackets *with inclusion proofs for each*, so a
        verifier holding only the root can check the claim. It used to return two bare
        hashes and a docstring instructing the verifier to "check both are in the tree",
        which they could only do by obtaining the whole leaf set — and a verifier with
        the whole dataset does not need a proof of anything. ATT-64.

        Raises if the record IS present: a caller asking for a non-inclusion proof of
        something that is there has a different problem, and returning a plausible pair
        would hide it.
        """
        leaf = record.leaf()
        if commitment.leaves.index_of(leaf) is not None:
            raise ValueError(
                f"record {record.record_id!r} IS in dataset {commitment.dataset_id!r}; "
                f"there is no non-inclusion proof to give"
            )
        lower_index, upper_index = commitment.leaves.bracket(leaf)
        tree = MerkleTree(commitment.leaves.all_leaves())
        return AbsenceProof(
            leaf=leaf,
            lower=None if lower_index is None else tree.inclusion_proof(lower_index),
            upper=None if upper_index is None else tree.inclusion_proof(upper_index),
            tree_size=commitment.leaf_count,
        )

    def erasure_impact(
        self,
        subject: SubjectId,
        *,
        erased_at: date,
        commitments: Sequence[DatasetCommitment],
        records_by_dataset: dict[DatasetId, Sequence[LineageRecord]],
        models_by_dataset: dict[DatasetId, Sequence[str]],
        in_service: Sequence[str],
    ) -> ErasureImpact:
        """Which models learned from this subject's data, and are they still running?

        This is the honest output. It does not un-learn anything.
        """
        datasets: list[DatasetId] = []
        models: list[str] = []
        for commitment in commitments:
            records = records_by_dataset.get(commitment.dataset_id, ())
            if any(r.subject == subject for r in records):
                datasets.append(commitment.dataset_id)
                models.extend(models_by_dataset.get(commitment.dataset_id, ()))
        affected = tuple(dict.fromkeys(models))
        return ErasureImpact(
            subject=subject,
            erased_at=erased_at,
            datasets=tuple(datasets),
            models_affected=affected,
            still_in_service=tuple(m for m in affected if m in in_service),
        )

    def warrant(
        self,
        commitment: DatasetCommitment,
        *,
        records: Sequence[LineageRecord],
        accepted_bases: frozenset[LawfulBasis],
        required_jurisdictions: frozenset[str] = frozenset(),
        transform_reproduced: bool | None = None,
        erasure_conflicts: Sequence[ErasureImpact] = (),
    ) -> WarrantReport:
        """The data-lineage warrant.

        ``basis_coverage`` counts records whose basis could not be established
        **separately** from those with none. Collapsing "unknown" into "absent"
        understates the problem; collapsing it into "present" is a lie.
        """
        findings: list[Finding] = []
        satisfied = True

        unaccepted = [r for r in records if r.lawful_basis not in accepted_bases]
        if unaccepted:
            satisfied = False
            findings.append(
                Finding(
                    code="unaccepted_lawful_basis",
                    message=(
                        f"{len(unaccepted)} record(s) carry a lawful basis the policy "
                        f"does not accept; they must not enter the committed set"
                    ),
                    severity=Severity.ERROR,
                )
            )

        unknown_basis = [r for r in records if not r.lawful_basis]
        if unknown_basis:
            satisfied = False
            findings.append(
                Finding(
                    code="unknown_lawful_basis",
                    message=(
                        f"{len(unknown_basis)} record(s) have no established lawful "
                        f"basis. Unknown is reported separately from absent, and "
                        f"neither is treated as present."
                    ),
                    severity=Severity.ERROR,
                )
            )

        if required_jurisdictions:
            out_of_scope = [r for r in records if r.jurisdiction not in required_jurisdictions]
            if out_of_scope:
                satisfied = False
                findings.append(
                    Finding(
                        code="out_of_jurisdiction",
                        message=f"{len(out_of_scope)} record(s) outside the permitted "
                        f"jurisdictions {sorted(required_jurisdictions)}",
                        severity=Severity.ERROR,
                    )
                )

        if transform_reproduced is False:
            satisfied = False
            findings.append(
                Finding(
                    code="transform_not_reproduced",
                    message=(
                        "re-running the pipeline over the pinned source did not "
                        "reproduce this dataset"
                    ),
                    severity=Severity.ERROR,
                )
            )
        elif transform_reproduced is None:
            findings.append(
                Finding(
                    code="transform_not_rerunnable",
                    message=(
                        "the pipeline is not re-runnable, so dataset reproducibility is "
                        "UNVERIFIED rather than established"
                    ),
                    severity=Severity.WARNING,
                )
            )

        for impact in erasure_conflicts:
            severity = Severity.ERROR if impact.still_in_service else Severity.WARNING
            if impact.still_in_service:
                satisfied = False
            findings.append(
                Finding(
                    code="erasure_conflict",
                    message=(
                        f"subject {impact.subject} was erased on {impact.erased_at}; "
                        f"models {list(impact.models_affected)} trained on data "
                        f"including it, and {list(impact.still_in_service)} remain in "
                        f"service. Deleting the record does NOT remove its influence "
                        f"on the weights."
                    ),
                    severity=severity,
                )
            )

        findings.append(
            Finding(
                code="dataset_committed",
                message=(
                    f"{commitment.dataset_id}@{commitment.epoch}: {commitment.leaf_count} "
                    f"records, root {commitment.root[:12]}"
                ),
            )
        )

        return WarrantReport(
            kind=WarrantKinds.DATA_LINEAGE,
            status=WarrantStatus.EVALUATED,
            satisfied=satisfied,
            findings=tuple(findings),
        )


@dataclass(frozen=True, slots=True)
class ErasureImpact:
    """What an erasure request actually reached — and what it could not.

    The honest artifact. It names the liability rather than pretending to remove it.
    """

    subject: SubjectId
    erased_at: date
    datasets: tuple[DatasetId, ...]
    models_affected: tuple[str, ...]
    still_in_service: tuple[str, ...]
    remediation: Remediation = Remediation.REQUIRED

    @property
    def fully_remediated(self) -> bool:
        """True only when nothing trained on the erased data is still running.

        Note what this does NOT claim: that the influence is gone from a retired
        model's weights. It is not, and no field here says otherwise.
        """
        return not self.still_in_service
