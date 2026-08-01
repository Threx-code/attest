"""External witness — Merkle checkpoints, inclusion proofs, and receipts.

Sealing stops application-level omission. It does not stop a host that fully controls
its own database from manufacturing a consistent history after the fact: recompute
every hash, renumber every sequence, re-seal, re-sign. The result is internally
perfect and completely false, and nothing *inside* the system can detect it.

The evidence has to be held where the host cannot reach it. This is Certificate
Transparency's model, and the two proofs fall out of the structure:

- an **inclusion proof** shows a record was in checkpoint N — O(log n) hashes;
- a **consistency proof** shows checkpoint N+1 extends N, which is what defeats
  wholesale rewriting.

A **receipt**, issued synchronously at decision time, closes the remaining gap: a host
that never adds the leaf has signed a promise it did not keep, and the affected party
holds it. That inverts the burden — the host no longer certifies its own completeness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

from attest.kernel.canonical import Canonical
from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import Hash

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from attest.kernel.identifiers import RunId
    from attest.kernel.ports import Signer

__all__ = [
    "Checkpoint",
    "ConsistencyProof",
    "InclusionProof",
    "MerkleTree",
    "Receipt",
    "Witness",
    "WitnessLevel",
    "WitnessPolicy",
    "WitnessReceipt",
    "WitnessService",
]


@dataclass(frozen=True, slots=True)
class InclusionProof:
    """Proof that one leaf is in a tree of a given size."""

    leaf: Hash
    index: int
    tree_size: int
    path: tuple[tuple[str, Hash], ...]

    def verifies_against(self, root: Hash) -> bool:
        """Fold the audit path and compare against an independently obtained root.

        The root must come from the third party, **never from the bundle**. Comparing
        against a root the bundle supplied proves only that the bundle is
        self-consistent, which is exactly what witnessing exists to get past.
        """
        current = self.leaf
        for side, sibling in self.path:
            current = (
                MerkleTree.node_hash(current, sibling)
                if side == "right"
                else MerkleTree.node_hash(sibling, current)
            )
        return current == root


@dataclass(frozen=True, slots=True)
class ConsistencyProof:
    """Proof that a newer checkpoint **extends** an older one.

    This is the proof that defeats history rewriting, and it is the reason the tree
    below follows RFC 6962 rather than a simpler shape. A host that rewrites its chain
    must publish a checkpoint inconsistent with one a third party already holds, and
    the inconsistency is then detectable by anyone rather than only by the host.
    """

    old_size: int
    new_size: int
    path: tuple[Hash, ...]

    def verifies(self, old_root: Hash, new_root: Hash) -> bool:
        """Check the proof against two **independently obtained** roots.

        Both roots must come from outside the bundle. Verifying against roots the host
        supplied proves the host is self-consistent, which is what witnessing exists to
        get past.
        """
        if self.old_size > self.new_size or self.old_size < 1:
            return False
        if self.old_size == self.new_size:
            return not self.path and old_root == new_root

        node, last = self.old_size - 1, self.new_size - 1
        while node & 1:
            node >>= 1
            last >>= 1

        index = 0
        if node:
            if not self.path:
                return False
            first = second = self.path[0]
            index = 1
        else:
            first = second = old_root

        while last:
            if node & 1:
                if index >= len(self.path):
                    return False
                first = MerkleTree.node_hash(self.path[index], first)
                second = MerkleTree.node_hash(self.path[index], second)
                index += 1
            elif node < last:
                if index >= len(self.path):
                    return False
                second = MerkleTree.node_hash(second, self.path[index])
                index += 1
            node >>= 1
            last >>= 1

        return first == old_root and second == new_root and index == len(self.path)


class MerkleTree:
    """A Merkle tree over ordered leaves, in the RFC 6962 shape.

    The shape is not incidental. A level-by-level tree that promotes the odd node
    produces correct roots and correct inclusion proofs, and **cannot** produce an
    O(log n) consistency proof — appending reshapes its interior. RFC 6962 splits at
    the largest power of two below the size instead, so every earlier tree is a prefix
    of every later one and "checkpoint N+1 extends checkpoint N" is provable in a
    handful of hashes. Certificate Transparency runs this at internet scale.

    Nothing is ever duplicated to pad a level, which is the CVE-2012-2459 shape where
    two distinct trees share a root.
    """

    # Domain separation, so an internal node can never be mistaken for a leaf. Without
    # the prefixes a crafted leaf whose bytes equal a node's concatenation could forge
    # a proof — the classic second-preimage attack on Merkle trees. The values are
    # RFC 6962's own.
    LEAF_PREFIX: Final = b"\x00"
    NODE_PREFIX: Final = b"\x01"

    __slots__ = ("_leaves",)

    def __init__(self, leaves: Sequence[Hash] = ()) -> None:
        self._leaves = list(leaves)

    @classmethod
    def leaf_hash(cls, payload: bytes) -> Hash:
        """Hash a leaf, domain-separated from internal nodes."""
        return Hash(Canonical.digest_bytes(cls.LEAF_PREFIX + payload))

    @classmethod
    def node_hash(cls, left: Hash, right: Hash) -> Hash:
        return Hash(
            Canonical.digest_bytes(cls.NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))
        )

    @classmethod
    def attestation_leaf(cls, attestation_hash: Hash, seal_hash: Hash) -> Hash:
        """The leaf for a run: its attestation bound to its seal."""
        return cls.leaf_hash(Canonical.encode({"attestation": attestation_hash, "seal": seal_hash}))

    def append(self, leaf: Hash) -> None:
        self._leaves.append(leaf)

    def __len__(self) -> int:
        return len(self._leaves)

    @property
    def leaves(self) -> tuple[Hash, ...]:
        return tuple(self._leaves)

    def root(self) -> Hash:
        if not self._leaves:
            raise ValueError("an empty tree has no root; there is nothing to witness")
        return self._root(tuple(self._leaves))

    @classmethod
    def _split(cls, size: int) -> int:
        """The largest power of two strictly below ``size``.

        This single line is what makes every earlier tree a prefix of every later one.
        """
        return 1 << (size - 1).bit_length() - 1

    @classmethod
    def _root(cls, leaves: tuple[Hash, ...]) -> Hash:
        if len(leaves) == 1:
            return leaves[0]
        split = cls._split(len(leaves))
        return cls.node_hash(cls._root(leaves[:split]), cls._root(leaves[split:]))

    def inclusion_proof(self, index: int) -> InclusionProof:
        """The audit path proving the leaf at ``index`` is in this tree."""
        if not 0 <= index < len(self._leaves):
            raise IndexError(f"leaf {index} is outside a tree of {len(self._leaves)}")
        return InclusionProof(
            leaf=self._leaves[index],
            index=index,
            tree_size=len(self._leaves),
            path=self._path(index, tuple(self._leaves)),
        )

    @classmethod
    def _path(cls, index: int, leaves: tuple[Hash, ...]) -> tuple[tuple[str, Hash], ...]:
        """Bottom-up: the nearest sibling first, so a verifier can fold from the leaf."""
        if len(leaves) == 1:
            return ()
        split = cls._split(len(leaves))
        if index < split:
            return (*cls._path(index, leaves[:split]), ("right", cls._root(leaves[split:])))
        return (*cls._path(index - split, leaves[split:]), ("left", cls._root(leaves[:split])))

    def consistency_proof(self, old_size: int) -> ConsistencyProof:
        """Prove this tree extends the tree of ``old_size`` leaves.

        Nothing was removed, reordered or rewritten — which no amount of internal
        re-sealing can fake, because a third party already holds the old root.
        """
        if not 1 <= old_size <= len(self._leaves):
            raise ValueError(
                f"cannot prove consistency with a tree of {old_size} leaves against one "
                f"of {len(self._leaves)}"
            )
        return ConsistencyProof(
            old_size=old_size,
            new_size=len(self._leaves),
            path=self._subproof(old_size, tuple(self._leaves), start=True),
        )

    @classmethod
    def _subproof(cls, old_size: int, leaves: tuple[Hash, ...], *, start: bool) -> tuple[Hash, ...]:
        """RFC 6962 SUBPROOF, verbatim.

        ``start`` is the specification's boolean: when the old tree is exactly this
        subtree and we arrived here without descending right, its root is already known
        to the verifier and must not be sent again.
        """
        if old_size == len(leaves):
            return () if start else (cls._root(leaves),)
        split = cls._split(len(leaves))
        if old_size <= split:
            return (
                *cls._subproof(old_size, leaves[:split], start=start),
                cls._root(leaves[split:]),
            )
        return (
            *cls._subproof(old_size - split, leaves[split:], start=False),
            cls._root(leaves[:split]),
        )


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A published commitment to everything witnessed so far."""

    root: Hash
    tree_size: int
    created_at: datetime
    signature: str | None = None

    def __post_init__(self) -> None:
        if self.tree_size < 1:
            raise ValueError("a checkpoint over an empty tree commits to nothing")


@dataclass(frozen=True, slots=True)
class Receipt:
    """A signed promise, issued at decision time, that a run will be included.

    Costs a hash rather than a round trip, which is why it can be synchronous. Its
    value is asymmetric: later the holder demands an inclusion proof, and a host that
    cannot produce one has signed a promise it did not keep. That is unanswerable
    evidence of omission, held by the affected party rather than by us.
    """

    run_id: RunId
    leaf: Hash
    promised_by: str
    issued_at: datetime
    signature: str | None = None


class WitnessLevel(StrEnum):
    """What a level defeats. Cost and operational weight vary enormously."""

    NONE = "none"
    """Seal only. Defeats application-level omission and modification."""

    TIMESTAMPED = "timestamped"
    """+ backdating a whole window."""

    LOGGED = "logged"
    """+ history rewriting, via consistency proofs held by a third party."""

    ANCHORED = "anchored"
    """+ collusion with the log operator."""


@dataclass(frozen=True, slots=True)
class WitnessPolicy:
    """Chosen by the domain, because the cost is real.

    Receipts are orthogonal and combine with any level.
    """

    level: WitnessLevel = WitnessLevel.NONE
    receipt: bool = False


@dataclass(frozen=True, slots=True)
class WitnessReceipt:
    """What the external party gave back when a checkpoint was submitted.

    ``reference`` is whatever the witness can be asked for later — a log index, a TSA
    token, an anchoring transaction. Opaque to the framework on purpose: the point is
    that it is *theirs*, so a host cannot manufacture it.
    """

    checkpoint: Checkpoint
    reference: str
    witnessed_at: datetime
    detail: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.reference:
            raise ValueError(
                "a witness receipt with no reference witnesses nothing: there is "
                "nothing to ask the third party for later"
            )


@runtime_checkable
class Witness(Protocol):
    """Publishes checkpoints somewhere the host cannot reach.

    Asynchronous and off the hot path: witnessing must not add latency to a decision.
    The receipt is the synchronous half.
    """

    def submit(self, checkpoint: Checkpoint) -> WitnessReceipt: ...

    def inclusion_proof(self, leaf: Hash) -> InclusionProof | None: ...

    def consistency_proof(self, old: Checkpoint, new: Checkpoint) -> ConsistencyProof | None:
        """Prove ``new`` extends ``old``. ``None`` when the witness cannot say.

        A witness that only timestamps has no view of the tree and returns ``None``
        rather than a proof it did not check — an unearned True here would defeat the
        only mechanism that catches history rewriting.
        """
        ...


class WitnessService:
    """The submission path: leaves in, checkpoints out, proofs retrievable per run.

    .. code-block:: text

        run completes ──▶ leaf queued
                               │
                               ▼
                        checkpoint window
                               │
                               ▼
                        Merkle root ──▶ Witness ──▶ external
                               │
                               ▼
                        inclusion proofs stored, per run

    Two things are deliberately separated. ``issue_receipt`` is **synchronous** and
    costs one hash — it is a signed promise handed to the affected party at decision
    time, and it is what inverts the burden: later the holder demands an inclusion
    proof, and a host that cannot produce one has signed a promise it did not keep.
    ``checkpoint`` is **asynchronous** and must never sit in the decision path;
    witnessing that adds latency to a decision gets turned off during the first
    incident and stays off.

    The tree is never truncated. Consistency proofs are meaningless against a tree that
    forgets, which is precisely the rewriting they exist to catch.
    """

    __slots__ = (
        "_allow_non_independent",
        "_checkpoints",
        "_index",
        "_receipts",
        "_signer",
        "_tree",
        "_witness",
    )

    def __init__(
        self,
        witness: Witness,
        *,
        signer: Signer | None = None,
        allow_non_independent: bool = False,
    ) -> None:
        self._witness = witness
        self._signer = signer
        self._allow_non_independent = allow_non_independent
        self._tree = MerkleTree()
        self._index: dict[RunId, int] = {}
        self._checkpoints: list[Checkpoint] = []
        self._receipts: list[WitnessReceipt] = []

    @property
    def tree_size(self) -> int:
        return len(self._tree)

    @property
    def checkpoints(self) -> tuple[Checkpoint, ...]:
        return tuple(self._checkpoints)

    def enqueue(self, run_id: RunId, attestation_hash: Hash, seal_hash: Hash) -> Hash:
        """Queue one run's leaf and return it. Off the hot path.

        A run already queued keeps its original position rather than being appended
        twice: two leaves for one decision would make the tree size disagree with the
        number of decisions, and every count derived from it wrong.
        """
        leaf = MerkleTree.attestation_leaf(attestation_hash, seal_hash)
        if run_id in self._index:
            return self._tree.leaves[self._index[run_id]]
        self._index[run_id] = len(self._tree)
        self._tree.append(leaf)
        return leaf

    @property
    def independent(self) -> bool:
        """Whether the witness is somewhere the host cannot reach.

        A witness that reports ``False`` — the in-process one — is honest about
        defeating nothing, and nothing consumed that signal: the service accepted any
        witness and the bundle builder wrote ``witness/`` from whatever it was handed,
        so a deployment could ship with the test witness and produce bundles that read
        as witnessed.
        """
        return bool(getattr(self._witness, "independent", True))

    def issue_receipt(self, run_id: RunId, leaf: Hash, *, at: datetime, window: str) -> Receipt:
        """The synchronous half: a signed promise that this run will be included.

        Issued *before or with* the effect, because a receipt handed over afterwards is
        a receipt the host could have chosen not to hand over.
        """
        if not (self.independent or self._allow_non_independent):
            raise ContractViolation(
                "refusing to issue a receipt against a witness that reports itself as "
                "not independent. A receipt's value is that it survives the host "
                "declining to cooperate, and an in-process witness is the host. Pass "
                "allow_non_independent=True if you are deliberately exercising the "
                "plumbing."
            )
        promise = self.receipt_payload(run_id=run_id, leaf=leaf, promised_by=window, issued_at=at)
        return Receipt(
            run_id=run_id,
            leaf=leaf,
            promised_by=window,
            issued_at=at,
            signature=None if self._signer is None else self._signer.sign(promise),
        )

    @staticmethod
    def receipt_payload(
        *, run_id: RunId, leaf: Hash, promised_by: str, issued_at: datetime
    ) -> bytes:
        """The exact bytes a receipt signature covers. **Includes ``issued_at``.**

        It was excluded, and the receipt's entire evidentiary value rests on it having
        been issued *before or with* the effect — so the one claim that matters was the
        one the signature did not cover, and the party the receipt exists to hold to
        account could restate it at will. Compare ``RunSeal.signing_payload``, which
        correctly covers ``sealed_at``.

        Exposed as a method so an external verifier can reconstruct the bytes without
        this package.
        """
        return Canonical.encode(
            {
                "run_id": run_id,
                "leaf": leaf,
                "promised_by": promised_by,
                "issued_at": issued_at,
            }
        )

    def checkpoint(self, *, at: datetime) -> WitnessReceipt | None:
        """Close the window: build the root, sign it, and publish it externally.

        Returns ``None`` when nothing has been queued. An empty checkpoint commits to
        nothing and would still consume a submission, so the window simply does not
        close.
        """
        if not len(self._tree):
            return None
        root = self._tree.root()
        payload = Canonical.encode({"root": root, "tree_size": len(self._tree), "created_at": at})
        checkpoint = Checkpoint(
            root=root,
            tree_size=len(self._tree),
            created_at=at,
            signature=None if self._signer is None else self._signer.sign(payload),
        )
        receipt = self._witness.submit(checkpoint)
        self._checkpoints.append(checkpoint)
        self._receipts.append(receipt)
        return receipt

    def proof_for(self, run_id: RunId) -> InclusionProof | None:
        """The inclusion proof for one run, or ``None`` if it was never queued.

        ``None`` is the honest answer and an alarming one: a run with no leaf is a run
        the log does not know about, which is exactly what a receipt-holder is checking.
        """
        position = self._index.get(run_id)
        return None if position is None else self._tree.inclusion_proof(position)

    def extends(self, older: Checkpoint) -> ConsistencyProof:
        """Prove the current tree extends an earlier published checkpoint.

        The proof is **checked before it is returned**. ``ConsistencyProof.verifies``
        was implemented, tested three times, and called by nothing in the package — so
        the mechanism that "defeats history rewriting" was never run by the system it
        defends. A proof this service hands out and has not folded itself is a proof
        nobody has folded.
        """
        proof = self._tree.consistency_proof(older.tree_size)
        if not proof.verifies(older.root, self._tree.root()):
            raise ContractViolation(
                f"the consistency proof this service just produced does not verify "
                f"against the checkpoint it claims to extend (tree_size "
                f"{older.tree_size} -> {len(self._tree)}). Either the earlier "
                f"checkpoint is not this log's, or this log has been rewritten."
            )
        return proof

    def audit(self, published: Checkpoint) -> InclusionProof | None:
        """Re-check one leaf against a checkpoint a third party holds.

        The receipt-holder's move, performed here so the plumbing is exercised by the
        system rather than only by a human following VERIFY.md.
        ``InclusionProof.verifies_against`` had five tests and no caller.
        """
        proof = self._witness.inclusion_proof(published.root)
        if proof is None:
            return None
        return proof if proof.verifies_against(published.root) else None

    def prove(self, run_id: RunId, *, against: Checkpoint) -> InclusionProof:
        """The inclusion proof for one run, folded before it is handed over."""
        proof = self.proof_for(run_id)
        if proof is None:
            raise ContractViolation(
                f"run {run_id!r} has no leaf in this log, so no inclusion proof exists. "
                f"If a receipt was issued for it, that receipt is now evidence of "
                f"omission."
            )
        if not proof.verifies_against(against.root):
            raise ContractViolation(
                f"the inclusion proof for {run_id!r} does not fold to the checkpoint "
                f"root. The leaf is in this tree and this tree is not that checkpoint."
            )
        return proof
