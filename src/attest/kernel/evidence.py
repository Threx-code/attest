"""Evidence — what supports a claim, and how that support is re-checked.

This module was almost called ``grounding``. That name carries a document-shaped
assumption — that evidence is quotable prose — and in medical, banking, mortgage and
reporting domains it usually is not. A blood glucose reading of 14.2 mmol/L has no
verbatim quote. Neither does an affordability calculation or a reconciled trial
balance. All three are perfectly good evidence; they just verify differently.

Two distinctions here are load-bearing, and collapsing either is how "verified" comes
to mean nothing:

*Content integrity is not source authority.* A quote can verify perfectly against a
document that has no business being authoritative. Verification answers "does the
source say this?" and never "is this source entitled to say it?".

*Support existing is not support entailing.* That the cited evidence exists and is
unaltered is mechanical, cheap and exact. That it actually supports the claim being
made is semantic, costly and probabilistic. They are separate fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, NewType

from attest.kernel.canonical import Canonical
from attest.kernel.identifiers import Hash

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import date, datetime

    from attest.kernel.identifiers import CorpusId, EvidenceId, TenantId

__all__ = [
    "CORE_EVIDENCE_KINDS",
    "MAX_DERIVATION_BREADTH",
    "MAX_DERIVATION_DEPTH",
    "MAX_DERIVATION_DEPTH_CEILING",
    "MAX_DERIVATION_NODES",
    "AuthorityLevel",
    "Evidence",
    "EvidenceKind",
    "EvidenceKinds",
    "Persistence",
    "SourceRef",
    "SourceType",
    "SupportResult",
    "ValidityWindow",
    "VerificationOutcome",
]

EvidenceKind = NewType("EvidenceKind", str)
"""Open, like ``WarrantKind``. A domain that verifies something we never imagined
registers its own kind and its own verifier, without touching the kernel."""


class EvidenceKinds:
    """The five verification strategies the framework ships.

    A namespace, not an enum: the type stays open. Note that only **one** of these is
    document-shaped — a framework whose evidence primitive is
    ``Citation(quote, start, end)`` serves regulatory and insurance and fails medical,
    banking, mortgage and reporting outright.
    """

    QUOTED_SPAN: Final = EvidenceKind("quoted_span")
    """The exact substring is still present at that offset in that source version."""

    RECORD_VALUE: Final = EvidenceKind("record_value")
    """Field F of record R at version V still equals X."""

    COMPUTATION: Final = EvidenceKind("computation")
    """Re-running model M over pinned inputs I reproduces output O."""

    OBSERVATION: Final = EvidenceKind("observation")
    """A measurement from device D at time T, within its calibration window."""

    DERIVATION: Final = EvidenceKind("derivation")
    """The stated operation over cited sub-evidence yields the stated result.

    The composite kind: its sub-evidence is itself evidence, so a reported figure
    traces down to source records. Bounded — see the limits below.
    """


CORE_EVIDENCE_KINDS: Final[frozenset[EvidenceKind]] = frozenset(
    {
        EvidenceKinds.QUOTED_SPAN,
        EvidenceKinds.RECORD_VALUE,
        EvidenceKinds.COMPUTATION,
        EvidenceKinds.OBSERVATION,
        EvidenceKinds.DERIVATION,
    }
)

# Derivation trees are bounded because unbounded recursion makes verification a
# denial-of-service target - and an attestation may arrive from an untrusted export
# bundle rather than from our own runtime.
MAX_DERIVATION_DEPTH: Final = 8
MAX_DERIVATION_DEPTH_CEILING: Final = 32
MAX_DERIVATION_BREADTH: Final = 512
MAX_DERIVATION_NODES: Final = 4096


class SourceType(StrEnum):
    """What kind of thing a source is. Domains may not need all of these."""

    STATUTE = "statute"
    POLICY_DOC = "policy_doc"
    GUIDELINE = "guideline"
    LEDGER = "ledger"
    RECORD_SYSTEM = "record_system"
    LAB = "lab"
    THIRD_PARTY = "third_party"
    USER_SUPPLIED = "user_supplied"
    MODEL_OUTPUT = "model_output"


class AuthorityLevel(StrEnum):
    """Whether the issuer is entitled to state this.

    A trust decision, not a mechanical one, so the *profile* decides which level is
    acceptable for which claim. A sanctions determination may require
    ``AUTHORITATIVE``; customer correspondence is fine at ``USER_SUPPLIED`` provided
    it is labelled as such.

    Ordered weakest-first so a profile can express a floor rather than a set.
    """

    UNVERIFIED = "unverified"
    USER_SUPPLIED = "user_supplied"
    ADVISORY = "advisory"
    AUTHORITATIVE = "authoritative"

    @property
    def rank(self) -> int:
        return _AUTHORITY_RANK[self]

    def at_least(self, floor: AuthorityLevel) -> bool:
        """Whether this level meets a required minimum."""
        return self.rank >= floor.rank


_AUTHORITY_RANK: Final[dict[AuthorityLevel, int]] = {
    AuthorityLevel.UNVERIFIED: 0,
    AuthorityLevel.USER_SUPPLIED: 1,
    AuthorityLevel.ADVISORY: 2,
    AuthorityLevel.AUTHORITATIVE: 3,
}


class VerificationOutcome(StrEnum):
    """The result of re-checking a piece of evidence."""

    # ruff and bandit both read `"pass"` as a credential. It is a verification
    # outcome; each tool needs its own suppression.
    PASS = "pass"  # noqa: S105  # nosec B105
    FAIL = "fail"
    """A discrepancy was found. A serious finding for `verify_historical`."""

    UNVERIFIABLE = "unverifiable"
    """The source cannot answer the question.

    Not a technicality. Re-checking a RecordValue at version 7 requires the source
    system to retain versioned history, and many are last-write-wins. Collapsing this
    into PASS (by checking the current value) or FAIL (by treating absence as
    tampering) are both lies.
    """


class Persistence(StrEnum):
    """How much of a source is carried in the attestation.

    Resolves the size-versus-self-verification tension per decision rather than
    globally: the profile chooses by materiality.
    """

    REFERENCE = "reference"
    """Source id and hash only, ~200 B. Verification needs the source, so it often
    degrades to UNVERIFIABLE later. Triage and internal ops."""

    DIGEST = "digest"
    """Id, hash, and the cited value or span, ~2 KB. Self-verifying for the value
    that was actually cited. The default, and right for most regulated work."""

    EMBEDDED = "embedded"
    """The full retrieved content. Fully self-verifying offline, and expensive.
    Payments, filings, clinical and adverse decisions."""


@dataclass(frozen=True, slots=True)
class ValidityWindow:
    """When evidence is considered current.

    Answered by the *domain*, because only the domain knows that a mortgage valuation
    expires at 90 days and a clinical guideline expires when its issuing body replaces
    it. ``None`` on either side means unbounded in that direction.
    """

    effective_from: date | None = None
    effective_to: date | None = None

    def covers(self, moment: date) -> bool:
        """Whether ``moment`` falls inside the window.

        Note the question a domain usually needs is not "is this current now?" but
        "was this in force on the relevant date" - a loss date, a decision date.
        Passing `now` where the loss date belongs is a wrong decision with a
        verifiable citation.
        """
        if self.effective_from is not None and moment < self.effective_from:
            return False
        return not (self.effective_to is not None and moment > self.effective_to)


@dataclass(frozen=True, slots=True)
class SourceRef:
    """Where evidence came from, and whether that origin carries weight."""

    source_id: str
    source_type: SourceType
    authority: AuthorityLevel
    version: str
    retrieved_at: datetime
    integrity_hash: Hash
    issuer: str | None = None
    """WHO published it. `None` where the source has no meaningful issuer, never as
    a shorthand for 'unknown' - an unknown issuer belongs at UNVERIFIED authority."""

    validity: ValidityWindow = field(default_factory=ValidityWindow)
    tenant: TenantId | None = None

    corpus: CorpusId | None = None
    """Which body of material this came from, for within-tenant read scoping.

    ``None`` means the source declared none, and under a `VisibilityScope` allowlist that
    is refused rather than admitted - an allowlist that admits what it cannot check has
    stopped being one. Optional because most deployments have no walls and every existing
    source predates the field.
    """

    def __post_init__(self) -> None:
        if not self.source_id:
            raise ValueError("source_id must not be empty")
        if not self.version:
            raise ValueError(
                "source version must not be empty: an unversioned source cannot be "
                "re-checked, which makes any citation of it unverifiable"
            )


@dataclass(frozen=True, slots=True)
class SupportResult:
    """Whether a piece of evidence supports what it was cited for."""

    supported: bool
    outcome: VerificationOutcome

    confidence: float | None = None
    """`None` means EXACT verification - a quote is present or it is not.

    A float means a judge decided. Never merge the two into one field: a reviewer must
    always be able to tell whether "supported" was established mechanically or by
    opinion.
    """

    discrepancy: str | None = None
    """What changed, when verification failed. Required for FAIL."""

    judge_ref: str | None = None

    def __post_init__(self) -> None:
        if self.outcome is not VerificationOutcome.PASS and self.supported:
            raise ValueError(
                f"support claims supported=True with outcome {self.outcome.value!r}. "
                f"Evidence that did not verify has not been shown to support anything."
            )
        if self.outcome is VerificationOutcome.FAIL and not self.discrepancy:
            raise ValueError(
                "a FAIL result must say what the discrepancy was; an unexplained "
                "verification failure cannot be triaged"
            )
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence!r}")


@dataclass(frozen=True, slots=True)
class Evidence:
    """One item of support, addressable by content.

    Sub-evidence makes this a tree: a ``DERIVATION`` cites other evidence, which may
    itself be a derivation, down to source records. Depth and breadth are bounded at
    construction because an attestation may arrive from an untrusted bundle, and an
    unbounded tree makes verification a denial-of-service target.
    """

    evidence_id: EvidenceId
    kind: EvidenceKind
    source: SourceRef
    value: Any
    persistence: Persistence = Persistence.DIGEST
    sub_evidence: tuple[Evidence, ...] = ()

    metadata: Mapping[str, Any] = field(default_factory=dict)

    _digest: list[Hash] = field(default_factory=list, compare=False, repr=False)
    """Memo for :meth:`content_hash`. Not data — see that method for why it exists.

    Last, so it never shifts a positional argument, and excluded from equality so two
    identical items still compare equal whether or not either has been hashed.
    """

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        depth = self.depth()
        if depth > MAX_DERIVATION_DEPTH_CEILING:
            raise ValueError(
                f"evidence tree depth {depth} exceeds the hard ceiling of "
                f"{MAX_DERIVATION_DEPTH_CEILING}; verification would be unbounded"
            )
        if len(self.sub_evidence) > MAX_DERIVATION_BREADTH:
            raise ValueError(
                f"evidence node has {len(self.sub_evidence)} children, above "
                f"{MAX_DERIVATION_BREADTH}; wide levels must be summarised rather "
                f"than embedded"
            )
        self._reject_cycles()

    def _reject_cycles(self) -> None:
        """Reject a self-referencing tree, and bound its total size.

        A cycle is content repeating **along an ancestor path**, not content repeating
        anywhere in the tree. The difference is the difference between a malformed
        structure and an ordinary one: a reconciliation that sums two figures, each
        verified against the same ledger row at the same version, cites that row twice
        from two branches. That is a DAG, it is the most common shape in the target
        domains, and rejecting it would make the framework unable to express its own
        worked examples.

        The node budget is enforced here too, and it is the part that does real work.
        An attestation may arrive from an untrusted export bundle, so the recursion an
        attacker controls has to be bounded by something other than the depth and
        breadth ceilings multiplying out to sixteen thousand nodes.

        The ancestor check itself is a **collision backstop**, not a live guard: because
        evidence is immutable and a parent's hash covers its children's, a node can only
        equal an ancestor if SHA-256 repeats. It is kept because the cost is a frozenset
        membership test and the alternative is trusting that assumption silently.
        """
        nodes = 0
        # (node, the content hashes on the path from the root to it)
        stack: list[tuple[Evidence, frozenset[Hash]]] = [(self, frozenset())]
        while stack:
            node, ancestors = stack.pop()
            nodes += 1
            if nodes > MAX_DERIVATION_NODES:
                raise ValueError(
                    f"evidence tree exceeds {MAX_DERIVATION_NODES} nodes. Verification "
                    f"walks every node, and an unbounded tree from an export bundle is "
                    f"a denial-of-service rather than an unusually thorough citation."
                )
            digest = node.content_hash()
            if digest in ancestors:
                raise ValueError(
                    f"evidence tree contains a cycle at {node.evidence_id!r}: the same "
                    f"content appears as its own ancestor"
                )
            path = ancestors | {digest}
            stack.extend((child, path) for child in node.sub_evidence)

    def depth(self) -> int:
        """Depth of this subtree, counting this node as 1."""
        if not self.sub_evidence:
            return 1
        return 1 + max(child.depth() for child in self.sub_evidence)

    def node_count(self) -> int:
        return 1 + sum(child.node_count() for child in self.sub_evidence)

    def content_hash(self) -> Hash:
        """The content address of this evidence, including its subtree.

        Covers the **whole** source reference, not only its identity. ``authority`` is
        the trust decision a profile gates on and ``validity`` decides whether the
        evidence was in force on the date in question — so a hash that omitted them
        would let both be edited in storage while the record still verified. The two
        fields that decide whether evidence counted are exactly the two worth forging.

        **Memoised, because the object is immutable.** Construction runs ``depth()`` and
        ``_reject_cycles()``, which hashes every node, and each of those hashes walked
        the entire subtree beneath it — so building an *n*-node tree cost O(n·depth)
        full subtree hashes, and decoding one repeated that at every nesting level.
        Measured: a legal 2016-node tree burned 4.2 seconds of CPU before any guard,
        verifier or authority check ran, and 4096 nodes are permitted. Any authenticated
        principal could post a handful concurrently and exhaust the pool.

        The cache is a one-element list rather than an attribute because the dataclass
        is frozen; the *contents* change, the field does not. It is excluded from
        equality and repr, and nothing that hashes or encodes this object reads it —
        both build explicit dicts.
        """
        if self._digest:
            return self._digest[0]
        digest = self._compute_hash()
        self._digest.append(digest)
        return digest

    def _compute_hash(self) -> Hash:
        return Hash(
            Canonical.digest(
                {
                    "kind": self.kind,
                    "source_id": self.source.source_id,
                    "source_type": self.source.source_type,
                    "source_version": self.source.version,
                    "authority": self.source.authority,
                    "issuer": self.source.issuer,
                    "retrieved_at": self.source.retrieved_at,
                    "integrity_hash": self.source.integrity_hash,
                    "tenant": self.source.tenant,
                    "validity_from": self.source.validity.effective_from,
                    "validity_to": self.source.validity.effective_to,
                    "persistence": self.persistence,
                    "value": self.value,
                    "metadata": dict(self.metadata),
                    "sub_evidence": [child.content_hash() for child in self.sub_evidence],
                }
            )
        )
