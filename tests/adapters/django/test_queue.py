"""The queue under the conditions that actually break queues.

Not "does it enqueue". Duplicate dispatch, duplicate delivery, workers racing for the
same row, a worker that dies mid-run, a run resumed twice, and whether the trail can
answer "did anything ever pick this up" — which is the only question that matters when
a caller holds a ticket that never resolved.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from attest.adapters.django.models import DispatchEvent, QueuedRun
from attest.adapters.django.stores import DjangoRunQueue
from attest.kernel.audit import EventType
from attest.kernel.errors import StoreError
from attest.kernel.identifiers import ActorId, RunId, TenantId
from attest.runtime.dispatch import RunEnvelope

pytestmark = pytest.mark.contract


def envelope(now: datetime, run_id: str = "run_1", tenant: str = "t1") -> bytes:
    return RunEnvelope(
        run_id=RunId(run_id),
        actor=ActorId("alice"),
        tenant=TenantId(tenant),
        payload={"claim": "8823", "amount": "12400.00"},
        submitted_at=now,
    ).encode()


def types_for(dispatch_id: str) -> list[str]:
    return [
        row.event_type
        for row in DispatchEvent.objects.filter(dispatch_id=dispatch_id).order_by("id")
    ]


# ── Idempotency ──────────────────────────────────────────────────────────────


@pytest.mark.security
def test_submitting_the_same_run_twice_queues_it_once(now: datetime) -> None:
    """A client retrying a timed-out dispatch must not get two runs.

    The second would propose the same effect again under a fresh grant, and the
    idempotency store only catches that when the action carries a key. Here the primary
    key does it, with no cooperation from the caller.
    """
    queue = DjangoRunQueue()
    first = queue.submit(RunId("run_1"), envelope(now))
    second = queue.submit(RunId("run_1"), envelope(now))
    assert first.startswith("queued:")
    assert second.startswith("duplicate:")
    assert QueuedRun.objects.count() == 1
    assert types_for("run_1").count(EventType.RUN_QUEUED) == 1


@pytest.mark.security
def test_a_duplicate_broker_notification_runs_the_effect_once(now: datetime) -> None:
    """Brokers deliver at least once. Fetching twice must not hand out the work twice."""
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    assert queue.fetch(RunId("run_1")) is not None
    assert queue.fetch(RunId("run_1")) is None, (
        "a second notification handed the same envelope out again; the effect would "
        "be proposed twice"
    )


def test_fetching_an_unknown_run_is_none_rather_than_an_error(now: datetime) -> None:
    assert DjangoRunQueue().fetch(RunId("run_absent")) is None


# ── Concurrency ──────────────────────────────────────────────────────────────


@pytest.mark.security
def test_claiming_moves_the_row_so_a_second_claim_cannot_take_it(now: datetime) -> None:
    """The invariant the lock exists to protect: each envelope is handed out once.

    ``SKIP LOCKED`` is what makes that hold *without serialising the pool*, and that
    part is a Postgres property this suite cannot demonstrate — SQLite serialises
    writers, so every interleaving here is trivially safe. What is testable everywhere,
    and what actually goes wrong when the filter is written loosely, is that a claimed
    row leaves the QUEUED set atomically.
    """
    queue = DjangoRunQueue()
    for index in range(3):
        queue.submit(RunId(f"run_{index}"), envelope(now, run_id=f"run_{index}"))

    taken: list[bytes] = []
    while batch := queue.claim(limit=2, now=now):
        taken.extend(batch)

    ids = [RunEnvelope.decode(raw).run_id for raw in taken]
    assert sorted(ids) == ["run_0", "run_1", "run_2"]
    assert len(ids) == len(set(ids)), f"an envelope was claimed more than once: {ids}"
    assert QueuedRun.objects.filter(state=QueuedRun.QUEUED).count() == 0
    assert queue.claim(limit=5, now=now) == ()


# ── A worker that dies ───────────────────────────────────────────────────────


@pytest.mark.security
def test_a_run_whose_worker_died_is_reclaimed_rather_than_stuck(now: datetime) -> None:
    """Pod evictions are not rare, so this is not a rare failure.

    Without a lease the row sits in ``running`` forever: neither retried nor visibly
    failed, with a caller whose ticket never resolves.
    """
    queue = DjangoRunQueue(lease=timedelta(minutes=1), worker_id="doomed")
    queue.submit(RunId("run_1"), envelope(now))
    assert queue.claim(limit=1, now=now)
    assert QueuedRun.objects.get(pk="run_1").state == QueuedRun.RUNNING

    later = now + timedelta(minutes=5)
    assert queue.reclaim_expired(now=later) == ("run_1",)
    row = QueuedRun.objects.get(pk="run_1")
    assert row.state == QueuedRun.QUEUED, "the run was not returned to the queue"
    assert row.worker_id == ""
    assert EventType.RUN_ABANDONED in types_for("run_1")


def test_a_live_lease_is_not_reclaimed(now: datetime) -> None:
    """Reclaiming a run still in progress would run its effect twice."""
    queue = DjangoRunQueue(lease=timedelta(minutes=15))
    queue.submit(RunId("run_1"), envelope(now))
    queue.claim(limit=1, now=now)
    assert queue.reclaim_expired(now=now + timedelta(minutes=5)) == ()


def test_a_long_run_can_renew_its_lease(now: datetime) -> None:
    """Rather than lengthening the default for every run in the deployment."""
    queue = DjangoRunQueue(lease=timedelta(minutes=1), worker_id="w1")
    queue.submit(RunId("run_1"), envelope(now))
    queue.claim(limit=1, now=now)
    assert queue.renew(RunId("run_1"), now=now + timedelta(seconds=30)) is True
    assert queue.reclaim_expired(now=now + timedelta(minutes=1, seconds=10)) == ()


def test_another_worker_cannot_renew_a_lease_it_does_not_hold(now: datetime) -> None:
    """Otherwise a stuck worker could keep a run alive it is no longer running."""
    DjangoRunQueue(worker_id="w1").submit(RunId("run_1"), envelope(now))
    DjangoRunQueue(worker_id="w1").claim(limit=1, now=now)
    assert DjangoRunQueue(worker_id="w2").renew(RunId("run_1"), now=now) is False


# ── Held and resumed ─────────────────────────────────────────────────────────


@pytest.mark.security
def test_a_held_run_resumes_and_nothing_was_waiting_on_a_worker(now: datetime) -> None:
    """The half that keeps a pool alive on a busy Monday."""
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    queue.claim(limit=1, now=now)
    queue.settle(RunId("run_1"), state=QueuedRun.HELD, detail="hold_for_approval", now=now)
    assert QueuedRun.objects.get(pk="run_1").state == QueuedRun.HELD

    queue.resume(RunId("run_1"), by="bob")
    row = QueuedRun.objects.get(pk="run_1")
    assert row.state == QueuedRun.QUEUED
    assert row.attempt == 2, "the resumption did not record that this is a second attempt"
    assert RunEnvelope.decode(bytes(row.envelope)).attempt == 2


@pytest.mark.security
def test_a_settled_run_cannot_be_resumed(now: datetime) -> None:
    """Resuming a finished run would propose its effect a second time."""
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    queue.claim(limit=1, now=now)
    queue.settle(RunId("run_1"), state=QueuedRun.DONE, now=now)
    with pytest.raises(StoreError, match="not held"):
        queue.resume(RunId("run_1"))


def test_resuming_an_unknown_dispatch_is_refused(now: datetime) -> None:
    with pytest.raises(StoreError, match="unknown dispatch"):
        DjangoRunQueue().resume(RunId("run_absent"))


def test_settling_into_a_state_that_is_not_an_ending_is_refused(now: datetime) -> None:
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    with pytest.raises(StoreError, match="not a settled state"):
        queue.settle(RunId("run_1"), state=QueuedRun.RUNNING)


# ── The trail ────────────────────────────────────────────────────────────────


@pytest.mark.security
def test_every_transition_leaves_a_trail_entry(now: datetime) -> None:
    """The trail must answer "did anything ever pick this up".

    That is the only question worth asking when a caller holds a ticket that never
    resolved, and the chain cannot answer it — the chain does not exist until the run
    does.
    """
    queue = DjangoRunQueue(worker_id="w1")
    queue.submit(RunId("run_1"), envelope(now))
    queue.claim(limit=1, now=now)
    queue.settle(RunId("run_1"), state=QueuedRun.HELD, now=now)
    queue.resume(RunId("run_1"), by="bob", now=now)
    queue.claim(limit=1, now=now)
    queue.settle(
        RunId("run_1"), state=QueuedRun.DONE, now=now, attestation=RunId("run_1_attempt_2")
    )

    assert types_for("run_1") == [
        EventType.RUN_QUEUED,
        EventType.RUN_CLAIMED,
        EventType.RUN_SUSPENDED,
        EventType.RUN_RESUMED,
        EventType.RUN_CLAIMED,
        EventType.RUN_SETTLED,
    ]
    trail = queue.trail("run_1")
    assert trail[1].actor == "w1", "the trail does not say which worker took it"
    assert trail[3].actor == "bob", "the trail does not say who resumed it"
    assert trail[-1].run_id == "run_1_attempt_2", (
        "the trail does not link the dispatch to the attestation it produced"
    )


@pytest.mark.security
def test_the_trail_cannot_be_rewritten(now: datetime) -> None:
    """Enforced by a trigger, below the application.

    A process that failed to run the job must not be able to edit the record of having
    taken it.
    """
    from django.db import connection, transaction

    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    with (
        pytest.raises(Exception, match="append-only"),
        transaction.atomic(),
        connection.cursor() as cursor,
    ):
        cursor.execute("UPDATE attest_dispatch_events SET event_type = 'forged'")


# ── Observability ────────────────────────────────────────────────────────────


def test_depth_and_age_are_both_available(now: datetime) -> None:
    """Depth alone hides a stalled queue: five waiting is fine, five waiting an hour is not."""
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    queue.submit(RunId("run_2"), envelope(now, run_id="run_2"))
    assert queue.depth() == 2
    assert queue.oldest_waiting(now=now + timedelta(minutes=3)) == timedelta(minutes=3)


def test_an_empty_queue_has_no_oldest(now: datetime) -> None:
    assert DjangoRunQueue().oldest_waiting(now=now) is None


# ── The envelope ─────────────────────────────────────────────────────────────


def test_an_envelope_round_trips(now: datetime) -> None:
    original = RunEnvelope.decode(envelope(now))
    assert original.run_id == RunId("run_1")
    assert original.payload["amount"] == "12400.00"
    assert original.submitted_at == now


@pytest.mark.security
def test_a_truncated_envelope_is_refused_rather_than_partially_decoded(now: datetime) -> None:
    """A worker running a half-decoded envelope executes a proposal nobody submitted."""
    from attest.kernel.errors import ContractViolation

    with pytest.raises(ContractViolation, match="could not decode"):
        RunEnvelope.decode(envelope(now)[:20])


@pytest.mark.security
def test_an_envelope_missing_its_tenant_is_refused(now: datetime) -> None:
    from attest.kernel.canonical import Canonical
    from attest.kernel.errors import ContractViolation

    partial = Canonical.encode(
        {"run_id": "run_1", "actor": "alice", "payload": {}, "submitted_at": now}
    )
    with pytest.raises(ContractViolation, match="missing"):
        RunEnvelope.decode(partial)


def test_the_envelope_is_byte_identical_for_the_same_content(now: datetime) -> None:
    """So a queue can deduplicate by content rather than trusting a client's id."""
    assert envelope(now) == envelope(now)


def _unused(_: Any) -> None:  # pragma: no cover - keeps the import list honest
    return None
