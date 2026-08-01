"""Chain integrity proves events were not modified. The seal proves none were omitted.

Threat-model attacks 20 and 21. The distinction is the whole point of this module:
remove an event and re-point its successor, and every hash still recomputes.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from attest.kernel.audit import (
    AuditEvent,
    ChainFailure,
    ChainVerifier,
    EventType,
    RunSeal,
)
from attest.kernel.canonical import NULL_HASH
from attest.kernel.identifiers import Hash, RunId

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
RUN = RunId("run_1")


def _event(kind: str = EventType.RUN_DISPATCHED, run: RunId = RUN, **kw: object) -> AuditEvent:
    base: dict[str, object] = {"run_id": run, "event_type": kind, "occurred_at": AT}
    return AuditEvent(**{**base, **kw})  # type: ignore[arg-type]


def _seal_chain(events: list[AuditEvent]) -> list[AuditEvent]:
    """Assign the canonical positions a sealer would."""
    sealed: list[AuditEvent] = []
    previous = Hash(NULL_HASH)
    for position, event in enumerate(events, start=1):
        node = event.sealed_as(position, previous)
        sealed.append(node)
        previous = node.event_hash()
    return sealed


def _chain(length: int = 4) -> list[AuditEvent]:
    return _seal_chain(
        [
            _event(EventType.RUN_DISPATCHED, occurred_at=AT + timedelta(seconds=i))
            for i in range(length)
        ]
    )


def _seal(events: list[AuditEvent], **kw: object) -> RunSeal:
    base: dict[str, object] = {
        "run_id": RUN,
        "event_count": len(events),
        "first_sequence": 1,
        "last_sequence": len(events),
        "head_hash": events[-1].event_hash(),
        "attestation_hash": Hash("a" * 64),
        "sealed_at": AT,
    }
    return RunSeal(**{**base, **kw})  # type: ignore[arg-type]


# ── Sequence assignment happens at seal time ─────────────────────────────────────


@pytest.mark.unit
def test_an_event_starts_unsealed() -> None:
    # The application records causal structure and never chooses its own position:
    # one that omits an event would otherwise also report the count that hides it.
    event = _event()
    assert not event.is_sealed
    assert event.sequence is None


@pytest.mark.unit
def test_an_unsealed_event_has_no_chain_hash() -> None:
    with pytest.raises(ValueError, match="no chain position"):
        _event().event_hash()


@pytest.mark.unit
def test_sealing_returns_a_new_value() -> None:
    original = _event()
    sealed = original.sealed_as(1, Hash(NULL_HASH))
    assert original.sequence is None
    assert sealed.sequence == 1


@pytest.mark.unit
@pytest.mark.security
def test_a_sealed_event_cannot_be_re_sealed() -> None:
    # Re-sealing is renumbering, which is exactly what the seal exists to detect.
    sealed = _event().sealed_as(1, Hash(NULL_HASH))
    with pytest.raises(ValueError, match="renumber"):
        sealed.sealed_as(2, Hash("b" * 64))


@pytest.mark.unit
def test_sequence_and_previous_hash_are_assigned_together() -> None:
    with pytest.raises(ValueError, match="together at seal time"):
        _event(sequence=1)


@pytest.mark.unit
def test_sequence_starts_at_one() -> None:
    with pytest.raises(ValueError, match=">= 1"):
        _event(sequence=0, previous_hash=Hash(NULL_HASH))


@pytest.mark.unit
def test_an_event_must_be_typed() -> None:
    with pytest.raises(ValueError, match="typed"):
        _event(kind="")


# ── A well-formed chain verifies ─────────────────────────────────────────────────


@pytest.mark.unit
def test_a_well_formed_chain_verifies() -> None:
    events = _chain()
    assert ChainVerifier.verify(events, run_id=RUN, seal=_seal(events))


@pytest.mark.unit
def test_the_first_event_links_to_the_null_hash() -> None:
    # A fixed sentinel rather than an empty string, so a truncated chain cannot
    # masquerade as one that simply started here.
    assert _chain()[0].previous_hash == NULL_HASH


@pytest.mark.unit
def test_an_empty_chain_does_not_verify() -> None:
    assert ChainFailure.EMPTY in ChainVerifier.verify([], run_id=RUN).failures


@pytest.mark.unit
def test_order_of_presentation_does_not_matter() -> None:
    # Verification sorts by sequence, so a store returning rows in any order still
    # produces the same result.
    events = _chain()
    assert ChainVerifier.verify(list(reversed(events)), run_id=RUN, seal=_seal(events))


# ── Modification is detected ─────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_altering_an_events_payload_breaks_the_chain() -> None:
    events = _chain()
    tampered = AuditEvent(
        run_id=RUN,
        event_type=events[1].event_type,
        occurred_at=events[1].occurred_at,
        payload={"injected": "value"},
        sequence=events[1].sequence,
        previous_hash=events[1].previous_hash,
    )
    events[1] = tampered
    result = ChainVerifier.verify(events, run_id=RUN)
    assert ChainFailure.BROKEN_LINKAGE in result.failures


@pytest.mark.unit
@pytest.mark.security
def test_renumbering_two_events_breaks_the_chain() -> None:
    # Verification sorts by sequence, so shuffling the *list* is a no-op by design.
    # The real attack is renumbering: giving e2 e3's position and vice versa. Each
    # event still carries the previous_hash it was sealed with, so the linkage no
    # longer matches once they trade places.
    events = _chain()
    second, third = events[1], events[2]
    events[1] = AuditEvent(
        run_id=RUN,
        event_type=second.event_type,
        occurred_at=second.occurred_at,
        payload=dict(second.payload),
        sequence=third.sequence,
        previous_hash=second.previous_hash,
    )
    events[2] = AuditEvent(
        run_id=RUN,
        event_type=third.event_type,
        occurred_at=third.occurred_at,
        payload=dict(third.payload),
        sequence=second.sequence,
        previous_hash=third.previous_hash,
    )
    assert ChainFailure.BROKEN_LINKAGE in ChainVerifier.verify(events, run_id=RUN).failures


@pytest.mark.unit
@pytest.mark.security
def test_an_event_from_another_run_is_rejected() -> None:
    events = _chain()
    events.append(_event(run=RunId("run_other")).sealed_as(5, events[-1].event_hash()))
    assert ChainFailure.WRONG_RUN in ChainVerifier.verify(events, run_id=RUN).failures


# ── Omission is detected only by the seal ────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_omitting_an_event_leaves_a_sequence_gap() -> None:
    # The attack this module exists for: drop e2 and the remaining events still
    # hash correctly among themselves.
    events = _chain()
    del events[1]
    result = ChainVerifier.verify(events, run_id=RUN)
    assert ChainFailure.SEQUENCE_GAP in result.failures


@pytest.mark.unit
@pytest.mark.security
def test_a_re_linked_omission_is_still_caught_by_the_count() -> None:
    # The sophisticated version: omit an event AND rebuild the chain so linkage is
    # internally perfect. Only the sealed count and head can see it.
    full = _chain(4)
    seal_over_four = _seal(full)

    rebuilt = _seal_chain(
        [_event(EventType.RUN_DISPATCHED, occurred_at=AT + timedelta(seconds=i)) for i in (0, 2, 3)]
    )
    internally_valid = ChainVerifier.verify(rebuilt, run_id=RUN)
    assert internally_valid.verified  # linkage alone is satisfied

    against_seal = ChainVerifier.verify(rebuilt, run_id=RUN, seal=seal_over_four)
    assert ChainFailure.COUNT_MISMATCH in against_seal.failures


@pytest.mark.unit
@pytest.mark.security
def test_a_seal_whose_head_disagrees_is_rejected() -> None:
    events = _chain()
    assert ChainFailure.HEAD_MISMATCH in (
        ChainVerifier.verify(
            events, run_id=RUN, seal=_seal(events, head_hash=Hash("f" * 64))
        ).failures
    )


@pytest.mark.unit
def test_an_unsealed_event_in_the_chain_is_rejected() -> None:
    events = _chain()
    events.append(_event())
    assert ChainFailure.NOT_SEALED in ChainVerifier.verify(events, run_id=RUN).failures


# ── Seal construction is fail-closed ─────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_a_seal_whose_range_and_count_disagree_is_rejected() -> None:
    # The self-certification case: an application that omits e2 also reports count=3.
    events = _chain(4)
    with pytest.raises(ValueError, match="cannot detect an omission"):
        _seal(events, event_count=3)


@pytest.mark.unit
def test_a_chain_must_start_at_sequence_one() -> None:
    events = _chain(4)
    with pytest.raises(ValueError, match="truncated prefix"):
        _seal(events, first_sequence=2, last_sequence=5)


@pytest.mark.unit
def test_a_run_with_no_events_cannot_be_sealed() -> None:
    with pytest.raises(ValueError, match="nothing to attest"):
        RunSeal(
            run_id=RUN,
            event_count=0,
            first_sequence=1,
            last_sequence=0,
            head_hash=Hash(NULL_HASH),
            attestation_hash=Hash("a" * 64),
            sealed_at=AT,
        )


@pytest.mark.unit
def test_signer_and_signature_come_as_a_pair() -> None:
    events = _chain()
    with pytest.raises(ValueError, match="together"):
        _seal(events, signature="sig")


@pytest.mark.unit
def test_an_unsigned_seal_is_permitted() -> None:
    # Chain verification works unsigned; only the offline-evidence property needs a
    # signature, which is why THIN may omit it.
    assert _seal(_chain()).signature is None


@pytest.mark.unit
def test_the_signing_payload_is_reconstructible_without_our_code() -> None:
    # VERIFY.md requires an offline verifier to recompute this, so it must be
    # plain canonical bytes over named fields.
    payload = _seal(_chain()).signing_payload()
    assert b"head_hash" in payload
    assert b"event_count" in payload


@pytest.mark.unit
@pytest.mark.security
def test_the_signing_payload_changes_with_the_head() -> None:
    events = _chain()
    assert (
        _seal(events).signing_payload() != _seal(events, head_hash=Hash("9" * 64)).signing_payload()
    )
