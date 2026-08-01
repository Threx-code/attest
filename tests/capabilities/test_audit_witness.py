"""Sealing, chain construction and external witnessing. Attacks 20 and 21."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

import pytest

from attest.capabilities.audit import ChainSealer, EventRecorder
from attest.capabilities.witness import (
    Checkpoint,
    MerkleTree,
    WitnessLevel,
    WitnessPolicy,
)
from attest.kernel.audit import AuditEvent, ChainVerifier, EventType
from attest.kernel.effects import EffectState
from attest.kernel.identifiers import Hash, RunId
from tests.capabilities.conftest import AT

if TYPE_CHECKING:
    from attest.kernel.ports import AuditSink

pytestmark = pytest.mark.unit
RUN = RunId("run_1")
ATT = Hash("a" * 64)


class FakeSigner:
    key_id = "test-key"

    def sign(self, payload: bytes) -> str:
        return f"sig:{len(payload)}"

    def verify(self, payload: bytes, signature: str) -> bool:
        return signature == f"sig:{len(payload)}"


def _recorder(n: int = 4) -> EventRecorder:
    rec = EventRecorder(run_id=RUN)
    rec.record(EventType.RUN_DISPATCHED, {}, at=AT)
    rec.record(EventType.EVIDENCE_RETRIEVED, {"count": 3}, at=AT)
    rec.record(EventType.EFFECT_SUBMITTED, {"grant_id": "g1"}, at=AT)
    rec.record(EventType.RUN_COMPLETED, {}, at=AT)
    return rec


# ── Positions are assigned at seal time ──────────────────────────────────────


def test_recorded_events_start_unsealed() -> None:
    # The application records causal structure and never chooses its own position.
    assert all(not e.is_sealed for e in _recorder().events)


def test_sealing_assigns_a_dense_sequence() -> None:
    sealed, seal = ChainSealer().seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    assert [e.sequence for e in sealed] == [1, 2, 3, 4]
    assert seal.event_count == 4


def test_a_sealed_chain_verifies() -> None:
    sealed, seal = ChainSealer().seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    assert ChainVerifier.verify(sealed, run_id=RUN, seal=seal)


def test_sealing_is_deterministic() -> None:
    # Two independent verifiers must compute the same chain, or the head hash is
    # meaningless as evidence.
    _, seal_a = ChainSealer().seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    _, seal_b = ChainSealer().seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    assert seal_a.head_hash == seal_b.head_hash


def test_an_empty_run_cannot_be_sealed() -> None:
    with pytest.raises(ValueError, match="cannot be attested"):
        ChainSealer().seal([], run_id=RUN, attestation_hash=ATT, sealed_at=AT)


def test_a_signer_signs_the_seal() -> None:
    _, seal = ChainSealer(signer=FakeSigner()).seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    assert seal.signer == "test-key"
    assert FakeSigner().verify(seal.signing_payload(), seal.signature or "")


def test_an_unsigned_seal_still_verifies_its_chain() -> None:
    # Chain verification works unsigned; only offline evidence needs a signature.
    sealed, seal = ChainSealer().seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    assert seal.signature is None
    assert ChainVerifier.verify(sealed, run_id=RUN, seal=seal)


# ── Batching does not disturb ordering ───────────────────────────────────────


@pytest.mark.security
def test_effect_events_are_marked_for_immediate_write() -> None:
    # Losing one creates a state nobody can reconcile. ~2% of events, 100% of risk.
    rec = _recorder()
    effect = next(e for e in rec.events if e.event_type.startswith("effect."))
    other = next(e for e in rec.events if not e.event_type.startswith("effect."))
    assert rec.requires_immediate_write(effect)
    assert not rec.requires_immediate_write(other)


@pytest.mark.security
def test_the_batch_excludes_effect_events() -> None:
    rec = _recorder()
    assert all(not e.event_type.startswith("effect.") for e in rec.pending_batch())


@pytest.mark.security
def test_causal_order_survives_a_mid_run_effect_write() -> None:
    # ADR 0034: the effect event is durable first, but must NOT be sequenced before
    # the evidence retrieval that caused it.
    sealed, _ = ChainSealer().seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    order = [e.event_type for e in sealed]
    assert order.index("evidence.retrieved") < order.index("effect.submitted")


def test_the_provenance_warrant_is_unsatisfied_without_a_seal() -> None:
    report = ChainSealer().evaluate(_recorder().events, seal=None)
    assert not report.satisfied
    assert report.findings[0].code == "unsealed"


def test_the_provenance_warrant_passes_for_a_sealed_chain() -> None:
    sealed, seal = ChainSealer().seal(
        _recorder().events, run_id=RUN, attestation_hash=ATT, sealed_at=AT
    )
    assert ChainSealer().evaluate(sealed, seal=seal).satisfied


def test_effect_events_map_back_to_their_state() -> None:
    assert ChainSealer.effect_state_from_event("effect.unknown") is EffectState.UNKNOWN
    assert ChainSealer.effect_state_from_event("run.completed") is None


# ── Merkle ───────────────────────────────────────────────────────────────────


def _tree(n: int) -> MerkleTree:
    return MerkleTree([MerkleTree.leaf_hash(f"leaf-{i}".encode()) for i in range(n)])


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 8, 9, 16, 31])
def test_every_leaf_proves_inclusion(size: int) -> None:
    tree = _tree(size)
    root = tree.root()
    for i in range(size):
        assert tree.inclusion_proof(i).verifies_against(root)


@pytest.mark.security
def test_a_proof_does_not_verify_against_a_different_root() -> None:
    tree = _tree(8)
    assert not tree.inclusion_proof(3).verifies_against(_tree(9).root())


@pytest.mark.security
def test_leaves_and_nodes_are_domain_separated() -> None:
    # Without the prefixes a crafted leaf equal to a node's concatenation could
    # forge a proof — the classic second-preimage attack.
    a, b = MerkleTree.leaf_hash(b"a"), MerkleTree.leaf_hash(b"b")
    node = MerkleTree.node_hash(a, b)
    forged = MerkleTree.leaf_hash(bytes.fromhex(a) + bytes.fromhex(b))
    assert node != forged


@pytest.mark.security
def test_odd_levels_promote_rather_than_duplicate() -> None:
    # Duplicating the last node is CVE-2012-2459: two distinct trees, one root.
    assert _tree(3).root() != _tree(4).root()


def test_an_empty_tree_has_no_root() -> None:
    with pytest.raises(ValueError, match="nothing to witness"):
        MerkleTree().root()


def test_a_proof_index_outside_the_tree_is_rejected() -> None:
    with pytest.raises(IndexError):
        _tree(4).inclusion_proof(9)


def test_a_run_leaf_binds_the_attestation_to_its_seal() -> None:
    leaf = MerkleTree.attestation_leaf(ATT, Hash("b" * 64))
    other = MerkleTree.attestation_leaf(ATT, Hash("c" * 64))
    assert leaf != other


def test_a_checkpoint_over_an_empty_tree_is_rejected() -> None:
    with pytest.raises(ValueError, match="commits to nothing"):
        Checkpoint(root=Hash("a" * 64), tree_size=0, created_at=AT)


def test_witness_defaults_to_none_and_no_receipt() -> None:
    policy = WitnessPolicy()
    assert policy.level is WitnessLevel.NONE
    assert policy.receipt is False


# ── Canonical order is canonical ─────────────────────────────────────────────


@pytest.mark.security
def test_the_canonical_order_does_not_depend_on_the_order_events_arrive_in() -> None:
    """ATT-03. It used to sort by *position in the list it was handed*.

    That is stable with respect to the input and not canonical at all: the same events
    read back from storage in a different order produced a different chain and a
    different head hash, so a run whose events were written by two paths could never
    re-verify. The order now comes from the parent links, which the application records
    and storage cannot reorder.
    """
    recorder = EventRecorder(run_id=RUN)
    for name in ("run.dispatched", "effect.submitted", "effect.committed", "run.completed"):
        recorder.record(name, {}, at=AT)
    events = recorder.events

    shuffled = (events[2], events[0], events[3], events[1])
    assert [e.event_type for e in ChainSealer.canonical_order(shuffled)] == [
        e.event_type for e in ChainSealer.canonical_order(events)
    ]


@pytest.mark.security
def test_a_chain_sealed_from_storage_order_matches_one_sealed_from_arrival_order() -> None:
    """The property StoredChainCheck depends on, stated directly."""
    recorder = EventRecorder(run_id=RUN)
    for name in ("run.dispatched", "authority.grant_redeemed", "effect.committed"):
        recorder.record(name, {}, at=AT)
    events = recorder.events

    _, arrival = ChainSealer().seal(
        events, run_id=RUN, attestation_hash=Hash("a" * 64), sealed_at=AT
    )
    # Storage returns the durable events first, then the batch — a different order.
    reordered = (events[2], events[1], events[0])
    _, stored = ChainSealer().seal(
        reordered, run_id=RUN, attestation_hash=Hash("a" * 64), sealed_at=AT
    )
    assert arrival.head_hash == stored.head_hash


@pytest.mark.security
def test_an_event_carries_its_own_identifier_not_only_its_parents() -> None:
    """A parent pointer with no self-identifier is half a graph.

    An event could say what it followed and nothing could say what followed it, which
    is why the ordering had to fall back to arrival.
    """
    recorder = EventRecorder(run_id=RUN)
    first = recorder.record("run.dispatched", {}, at=AT)
    second = recorder.record("effect.committed", {}, at=AT)
    assert first.event_id
    assert second.parent_event_id == first.event_id


@pytest.mark.security
def test_a_durable_event_is_written_through_the_sink_by_the_recorder() -> None:
    """One writer. The object that is stored is the object that gets sealed."""

    class Sink:
        def __init__(self) -> None:
            self.written: list[AuditEvent] = []

        def append(self, event: AuditEvent) -> None:
            self.written.append(event)

        def append_many(self, events: Sequence[AuditEvent]) -> None:
            self.written.extend(events)

        def read_chain(self, run_id: RunId) -> tuple[AuditEvent, ...]:
            return tuple(self.written)

    sink = Sink()
    recorder = EventRecorder(run_id=RUN, sink=sink)
    effect = recorder.record("effect.committed", {}, at=AT, durable=True)
    recorder.record("run.completed", {}, at=AT)

    assert sink.written == [effect], "the durable event was not written immediately"
    assert sink.written[0] is effect, "a second, differently-shaped copy was stored"
    recorder.flush(sink)
    assert [e.event_type for e in sink.written] == ["effect.committed", "run.completed"]


@pytest.mark.security
def test_a_sink_that_fails_on_a_durable_write_stops_the_run() -> None:
    """If we cannot record what we are about to do, we must not do it."""
    from attest.kernel.errors import AuditSinkError

    class Broken:
        def append(self, event: AuditEvent) -> None:
            raise RuntimeError("disk full")

    with pytest.raises(AuditSinkError, match="must not act"):
        EventRecorder(run_id=RUN, sink=cast("AuditSink", Broken())).record(
            "effect.submitted", {}, at=AT, durable=True
        )
