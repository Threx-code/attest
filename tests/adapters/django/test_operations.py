"""The operational surface: what it insists on, and what it deliberately leaves alone.

The service authorises nothing — that is the design. So these tests are about the two
things it *does* enforce, because they are integrity properties rather than policy:
every mutating operation names an operator, and every one states a reason.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from attest.adapters.django.models import AutonomyPolicy, PendingAction, QueuedRun
from attest.adapters.django.stores import (
    DjangoApprovalStore,
    DjangoAutonomyStore,
    DjangoRunQueue,
)
from attest.kernel.errors import ContractViolation, StoreError
from attest.kernel.identifiers import ActorId, RunId, TenantId
from attest.runtime.dispatch import RunEnvelope
from attest.runtime.operations import (
    AutonomyMode,
    OperationsService,
    Operator,
)

pytestmark = pytest.mark.contract

ACME = TenantId("t1")


class Clock:
    def __init__(self, at: datetime) -> None:
        self.at = at

    def now(self) -> datetime:
        return self.at


def service(now: datetime, **ports: Any) -> OperationsService:
    return OperationsService(clock=Clock(now), **ports)


def commander() -> Operator:
    return Operator(actor=ActorId("alice"), roles=frozenset({"incident_commander"}))


# ── What it insists on ───────────────────────────────────────────────────────


@pytest.mark.security
def test_an_operation_must_name_who_performed_it() -> None:
    """An anonymous kill switch is indistinguishable from a misconfiguration."""
    with pytest.raises(ContractViolation, match="must name who"):
        Operator(actor=ActorId(""))


@pytest.mark.security
def test_a_change_without_a_reason_is_refused(now: datetime) -> None:
    """During the incident everyone knows why. Two weeks later nobody does."""
    ops = service(now, autonomy=DjangoAutonomyStore())
    with pytest.raises(ContractViolation, match="requires a reason"):
        ops.disable(capability="transfer", tenant=ACME, by=commander(), reason="   ")
    assert AutonomyPolicy.objects.count() == 0, "the change landed despite the refusal"


@pytest.mark.security
def test_the_store_refuses_an_unattributed_change(now: datetime) -> None:
    """Defence in depth: the store checks too, for a caller that bypasses the service."""
    with pytest.raises(StoreError, match="must name who"):
        DjangoAutonomyStore().set_mode(
            tenant=ACME, capability="transfer", mode="blocked", enabled=False, by=""
        )


@pytest.mark.security
def test_a_missing_port_refuses_rather_than_silently_doing_nothing(now: datetime) -> None:
    """An operator told "disabled" when nothing was wired stops looking."""
    with pytest.raises(ContractViolation, match="without a 'autonomy' port"):
        service(now).disable(
            capability="transfer", tenant=ACME, by=commander(), reason="incident 4471"
        )


# ── The kill switch ──────────────────────────────────────────────────────────


@pytest.mark.security
def test_disabling_a_capability_blocks_it_and_records_who_and_why(now: datetime) -> None:
    ops = service(now, autonomy=DjangoAutonomyStore())
    record = ops.disable(capability="transfer", tenant=ACME, by=commander(), reason="incident 4471")
    assert record.operation == "autonomy.disabled"
    assert record.target == "t1/transfer"

    row = AutonomyPolicy.objects.get(tenant_id="t1", capability="transfer")
    assert row.enabled is False
    assert row.mode == AutonomyMode.BLOCKED
    assert "alice" in row.updated_by
    assert "incident_commander" in row.updated_by
    assert "incident 4471" in row.updated_by


@pytest.mark.security
def test_an_unclassified_capability_is_blocked_rather_than_permitted(now: datetime) -> None:
    """An absent policy is an unanswered question, not permission."""
    assert DjangoAutonomyStore().mode_for(tenant=ACME, capability="never_seen") == "blocked"


@pytest.mark.security
def test_re_enabling_does_not_go_straight_back_to_unattended(now: datetime) -> None:
    """How an incident recurs an hour after it was closed."""
    ops = service(now, autonomy=DjangoAutonomyStore())
    ops.disable(capability="transfer", tenant=ACME, by=commander(), reason="incident")
    ops.enable(capability="transfer", tenant=ACME, by=commander(), reason="upstream fixed")
    assert AutonomyPolicy.objects.get(capability="transfer").mode == AutonomyMode.APPROVE


def test_auto_is_available_but_must_be_asked_for(now: datetime) -> None:
    ops = service(now, autonomy=DjangoAutonomyStore())
    ops.enable(
        capability="transfer",
        tenant=ACME,
        by=commander(),
        reason="cleared by risk",
        mode=AutonomyMode.AUTO,
    )
    assert AutonomyPolicy.objects.get(capability="transfer").mode == AutonomyMode.AUTO


def test_an_unknown_mode_is_refused(now: datetime) -> None:
    ops = service(now, autonomy=DjangoAutonomyStore())
    with pytest.raises(ContractViolation, match="not an autonomy mode"):
        ops.enable(capability="transfer", tenant=ACME, by=commander(), reason="x", mode="yolo")


def test_autonomy_can_be_read_per_tenant(now: datetime) -> None:
    ops = service(now, autonomy=DjangoAutonomyStore())
    ops.disable(capability="transfer", tenant=ACME, by=commander(), reason="incident")
    ops.disable(capability="refund", tenant=TenantId("t2"), by=commander(), reason="incident")
    assert [row["capability"] for row in ops.autonomy(tenant=ACME)] == ["transfer"]
    assert len(ops.autonomy()) == 2


# ── The approval queue ───────────────────────────────────────────────────────


@pytest.mark.security
def test_resolving_through_the_service_still_hits_the_stores_refusals(now: datetime) -> None:
    """The console must not be the one path where dual control does not hold."""
    ops = service(now, approvals=DjangoApprovalStore())
    PendingAction.objects.create(
        approval_id="apr_1",
        run_id="run_1",
        tenant_id="t1",
        grant_id="g1",
        action_hash="b" * 64,
        opened_at=now,
        expires_at=now + timedelta(minutes=15),
        requested_by="alice",
    )
    from attest.kernel.errors import SelfApprovalError

    with pytest.raises(SelfApprovalError, match="may not approve"):
        ops.resolve(approval_id="apr_1", approved=True, by=commander(), role="manager")
    assert PendingAction.objects.get(pk="apr_1").state == PendingAction.PENDING


def test_pending_is_listed_and_scoped(now: datetime) -> None:
    ops = service(now, approvals=DjangoApprovalStore())
    for index, tenant in enumerate(("t1", "t2")):
        PendingAction.objects.create(
            approval_id=f"apr_{index}",
            run_id=f"run_{index}",
            tenant_id=tenant,
            grant_id="g1",
            action_hash="b" * 64,
            opened_at=now,
            expires_at=now + timedelta(minutes=15),
        )
    assert len(ops.pending(tenant=ACME)) == 1
    assert len(ops.pending()) == 2


# ── Queue health ─────────────────────────────────────────────────────────────


def envelope(now: datetime, run_id: str = "run_1") -> bytes:
    return RunEnvelope(
        run_id=RunId(run_id),
        actor=ActorId("alice"),
        tenant=ACME,
        payload={},
        submitted_at=now,
    ).encode()


def test_queue_health_reports_depth_age_and_what_is_in_flight(now: datetime) -> None:
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    queue.submit(RunId("run_2"), envelope(now, "run_2"))
    queue.claim(limit=1, now=now)

    health = service(now + timedelta(minutes=4), queue=queue).queue_health()
    assert health.depth == 1
    assert health.running == 1
    assert health.oldest_waiting == timedelta(minutes=4)
    assert health.stalled is False


@pytest.mark.security
def test_a_queue_with_work_and_nothing_running_reads_as_stalled(now: datetime) -> None:
    """Depth alone hides this: five waiting looks identical to five waiting an hour."""
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    assert service(now, queue=queue).queue_health().stalled is True


def test_reclaiming_stuck_runs_requires_a_reason(now: datetime) -> None:
    queue = DjangoRunQueue(lease=timedelta(minutes=1))
    queue.submit(RunId("run_1"), envelope(now))
    queue.claim(limit=1, now=now)
    ops = service(now + timedelta(minutes=5), queue=queue)

    with pytest.raises(ContractViolation, match="requires a reason"):
        ops.reclaim_stuck(by=commander(), reason="")
    assert QueuedRun.objects.get(pk="run_1").state == QueuedRun.RUNNING

    assert ops.reclaim_stuck(by=commander(), reason="pod evicted") == ["run_1"]


def test_the_trail_is_readable_through_the_service(now: datetime) -> None:
    queue = DjangoRunQueue()
    queue.submit(RunId("run_1"), envelope(now))
    assert len(service(now, queue=queue).trail("run_1")) == 1


# ── The scope is enforced, and the record is parseable ───────────────────────


@pytest.mark.security
def test_a_scoped_operator_cannot_act_for_another_tenant(now: datetime) -> None:
    """ATT-42. Operator.tenant was carried and read by nothing.

    Worse than absent: a host wrapping this would reasonably read it as scoping, and it
    scoped nothing.
    """
    scoped = Operator(actor=ActorId("alice"), tenant=TenantId("t1"))
    ops = service(now, autonomy=DjangoAutonomyStore())
    with pytest.raises(ContractViolation, match="scoped to tenant"):
        ops.disable(capability="transfer", tenant=TenantId("t2"), by=scoped, reason="incident")
    assert AutonomyPolicy.objects.count() == 0


def test_an_unscoped_operator_may_still_act_for_any_tenant(now: datetime) -> None:
    """A platform operator during an incident is a real thing."""
    ops = service(now, autonomy=DjangoAutonomyStore())
    ops.disable(capability="transfer", tenant=TenantId("t2"), by=commander(), reason="incident")
    assert AutonomyPolicy.objects.filter(tenant_id="t2").exists()


def test_a_scoped_operator_may_act_for_their_own_tenant(now: datetime) -> None:
    scoped = Operator(actor=ActorId("alice"), roles=frozenset({"ops"}), tenant=ACME)
    ops = service(now, autonomy=DjangoAutonomyStore())
    ops.disable(capability="transfer", tenant=ACME, by=scoped, reason="incident")
    assert AutonomyPolicy.objects.filter(tenant_id="t1").exists()


@pytest.mark.security
def test_the_attribution_record_is_structured_not_delimiter_joined(now: datetime) -> None:
    """ATT-43. Three fields in one column with "|" and no escaping.

    `reason` is operator-supplied free text, so a reason containing "|" made the audit
    record of a kill-switch change ambiguous — parseable only by convention.
    """
    import json

    ops = service(now, autonomy=DjangoAutonomyStore())
    ops.disable(
        capability="transfer",
        tenant=ACME,
        by=commander(),
        reason="incident 4471 | escalated | see #ops-war-room",
    )
    stored = json.loads(AutonomyPolicy.objects.get(capability="transfer").updated_by)
    assert stored["actor"] == "alice"
    assert stored["roles"] == ["incident_commander"]
    assert stored["reason"] == "incident 4471 | escalated | see #ops-war-room"


# ── Reconciliation: the sweep that nothing called ────────────────────────────


def _unknown_run(run_id: str = "run_unknown") -> Any:
    """An attestation whose transfer timed out. The state this framework exists for.

    Built through `attest.assurance.builders`, which is what the four kernel refusals
    this fixture originally hit are for: a COMMITTED effect with no reference, one with
    no grant, a context naming a different run, and UNKNOWN with nothing to be unknown
    about. Every one of those was the invariant working, and every one cost an edit.
    """
    from attest.assurance.builders import Build
    from attest.kernel.verdicts import Verdict

    return Build.attestation(
        run_id,
        verdict=Verdict.UNKNOWN,
        at=datetime(2026, 1, 1, tzinfo=UTC),
        tenant=ACME,
    )


class Upstream:
    """A resolver that knows what really happened. Host code, by construction."""

    def __init__(self, outcome: Any, *, raises: Exception | None = None) -> None:
        self.outcome = outcome
        self.raises = raises
        self.asked: list[Any] = []

    def resolve(self, record: Any) -> Any:
        self.asked.append(record)
        if self.raises is not None:
            raise self.raises
        return self.outcome


def _reconciliation_service(runs: Any, audit: Any, now: datetime) -> OperationsService:
    return service(now, runs=runs, audit=audit)


@pytest.mark.security
def test_an_unknown_effect_is_actually_reconciled() -> None:
    """ReconciliationSweep shipped complete and nothing in the package called it.

    Only the test suite imported it. So an UNKNOWN effect — a payment that may or may
    not have left, the state this whole framework exists to represent honestly rather
    than guess about — was terminal for the run and a work item with no worker.
    """
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())
    later = datetime(2026, 1, 3, tzinfo=UTC)

    result = _reconciliation_service(runs, audit, later).reconcile(
        RunId("run_unknown"),
        resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
        by=commander(),
        sla=timedelta(hours=1),
        reason="daily reconciliation",
    )

    assert len(result.items) == 1
    assert result.items[0].outcome is ReconciliationOutcome.COMMITTED


@pytest.mark.security
def test_reconciling_records_the_decision_in_the_chain() -> None:
    """Deciding after the fact that a payment did happen is a decision.

    An undocumented one is indistinguishable from editing the record.
    """
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())

    result = _reconciliation_service(runs, audit, datetime(2026, 1, 3, tzinfo=UTC)).reconcile(
        RunId("run_unknown"),
        resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
        by=commander(),
        sla=timedelta(hours=1),
    )

    # On the RECONCILIATION run, not the original — the original is sealed, and the
    # append-only guard refuses inserts for a closed chain. See ATT-59.
    assert audit.read_chain(RunId("run_unknown")) == ()
    recorded = audit.read_chain(result.record)
    assert [event.event_type for event in recorded] == ["effect.reconciled"]
    assert recorded[0].payload["outcome"] == "committed"
    assert recorded[0].payload["resolved_by"] == "alice", (
        "a human deciding what the upstream could not tell us is a different kind of "
        "evidence, and the record must be able to say so"
    )


def test_a_still_unknown_result_is_recorded_rather_than_dropped() -> None:
    """ "We asked and could not find out" is a finding.

    A sweep that recorded only its successes shows a clean reconciliation history while
    the same effect goes unresolved for a week.
    """
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())

    result = _reconciliation_service(runs, audit, datetime(2026, 1, 3, tzinfo=UTC)).reconcile(
        RunId("run_unknown"),
        resolver=Upstream(None, raises=ConnectionError("upstream unreachable")),
        by=commander(),
        sla=timedelta(hours=1),
    )

    assert result.items[0].outcome is ReconciliationOutcome.STILL_UNKNOWN
    # A run is opened even though nothing resolved: "we asked and could not find out" is
    # a finding, and the sealed original is not a place it can live.
    assert audit.read_chain(result.record)[0].payload["outcome"] == "still_unknown"
    assert not result.superseded
    assert runs.superseded_by(RunId("run_unknown")) is None, (
        "an unresolved sweep must not rewrite the record; nothing was established"
    )


@pytest.mark.security
def test_the_corrected_record_supersedes_and_the_original_is_retained() -> None:
    """A reader who acted on the UNKNOWN record must still see what they acted on."""
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome
    from attest.kernel.effects import EffectState

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())

    _reconciliation_service(runs, audit, datetime(2026, 1, 3, tzinfo=UTC)).reconcile(
        RunId("run_unknown"),
        resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
        by=commander(),
        sla=timedelta(hours=1),
    )

    original = runs.get(RunId("run_unknown"))
    assert original is not None
    assert original.effects[0].state is EffectState.UNKNOWN, "the original was mutated"

    correction_id = runs.superseded_by(RunId("run_unknown"))
    assert correction_id is not None
    corrected = runs.get(correction_id)
    assert corrected is not None
    assert corrected.effects[0].state is EffectState.COMMITTED
    assert corrected.supersedes == RunId("run_unknown")
    assert corrected.seal is None, (
        "the old seal covered the old effects; carrying it forward would produce a "
        "record whose chain verifies against content it does not contain"
    )


def test_an_effect_inside_its_sla_is_left_alone() -> None:
    """A sweep that reconciled everything immediately would be asking the upstream about
    calls that have not had time to answer."""
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())
    upstream = Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3"))

    result = _reconciliation_service(
        runs, audit, datetime(2026, 1, 1, 0, 30, tzinfo=UTC)
    ).reconcile(RunId("run_unknown"), resolver=upstream, by=commander(), sla=timedelta(hours=1))
    assert result.items == ()
    assert not result
    assert upstream.asked == []


def test_reconciling_a_run_we_have_no_record_of_is_refused() -> None:
    """Recording a resolution for a run this deployment never saw is worse than refusing."""
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    with pytest.raises(ContractViolation, match="nothing to reconcile"):
        _reconciliation_service(
            InMemoryRunStore(), InMemoryAuditSink(), datetime(2026, 1, 3, tzinfo=UTC)
        ).reconcile(
            RunId("no-such-run"),
            resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
            by=commander(),
            sla=timedelta(hours=1),
        )


def test_running_the_same_sweep_twice_leaves_one_correction() -> None:
    """The correction id is derived from the outcomes, not from the clock.

    So a repeated sweep — a retried cron, an operator clicking twice — reaches the same
    id with the same content, which the store treats as the idempotent retry it is. A
    supersession chain full of near-identical records is one nobody reads, and the
    reader it is for is an auditor reconstructing what was known when.
    """
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())
    ops = _reconciliation_service(runs, audit, datetime(2026, 1, 3, tzinfo=UTC))

    for _ in range(3):
        ops.reconcile(
            RunId("run_unknown"),
            resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
            by=commander(),
            sla=timedelta(hours=1),
        )

    correction = runs.superseded_by(RunId("run_unknown"))
    assert correction is not None
    assert "reconciled" in str(correction)


def test_a_second_sweep_reaching_a_different_answer_is_refused() -> None:
    """Two sweeps disagreeing about one payment is not something to store quietly.

    Overwriting would destroy the first finding; storing both under one id is
    impossible. Refusing leaves an operator with a contradiction to resolve, which is
    the correct amount of friction for "did this GBP 500,000 transfer settle or not".
    """
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())
    ops = _reconciliation_service(runs, audit, datetime(2026, 1, 3, tzinfo=UTC))

    ops.reconcile(
        RunId("run_unknown"),
        resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
        by=commander(),
        sla=timedelta(hours=1),
    )
    # Same outcome, different reference: the ids collide and the content does not.
    with pytest.raises(StoreError, match="different content"):
        ops.reconcile(
            RunId("run_unknown"),
            resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_OTHER")),
            by=commander(),
            sla=timedelta(hours=1),
        )


@pytest.mark.security
def test_reconciliation_events_do_not_go_on_the_sealed_original() -> None:
    """ATT-59. The two fixes collided, and the review caught it before either shipped.

    `events()` produced `effect.reconciled` for the ORIGINAL run id. Once the seal
    registry is armed — ATT-56's fix, which is what makes `NoEventsAfterSeal` do
    anything — that insert is rejected by the database, in production, on the path that
    resolves a payment nobody can account for.

    Of the two resolutions the review offered, this is the first: reconciliation opens a
    new run that supersedes the original. The alternative — an append-after-seal
    exception for reconciliation events — would put a hole in the one guarantee that is
    supposed to be structural, and a hole with a name is still a hole.
    """
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())
    # The original is sealed: the sink refuses further appends to it, exactly as the
    # database trigger does.
    audit.mark_sealed(RunId("run_unknown"))

    result = _reconciliation_service(runs, audit, datetime(2026, 1, 3, tzinfo=UTC)).reconcile(
        RunId("run_unknown"),
        resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
        by=commander(),
        sla=timedelta(hours=1),
    )

    assert result.record != RunId("run_unknown")
    assert audit.read_chain(result.record), "the reconciliation record went nowhere"
    assert audit.read_chain(RunId("run_unknown")) == ()


@pytest.mark.security
def test_the_reconciliation_run_is_the_one_the_correction_is_written_under() -> None:
    """One id for the events and the corrected attestation, or they cannot be joined."""
    from attest.adapters.memory import InMemoryAuditSink, InMemoryRunStore
    from attest.capabilities.reconciliation import ReconciliationOutcome

    runs, audit = InMemoryRunStore(), InMemoryAuditSink()
    runs.create(_unknown_run())
    audit.mark_sealed(RunId("run_unknown"))

    result = _reconciliation_service(runs, audit, datetime(2026, 1, 3, tzinfo=UTC)).reconcile(
        RunId("run_unknown"),
        resolver=Upstream((ReconciliationOutcome.COMMITTED, "pay_9f3")),
        by=commander(),
        sla=timedelta(hours=1),
    )

    assert result.superseded
    assert runs.superseded_by(RunId("run_unknown")) == result.record
    corrected = runs.get(result.record)
    assert corrected is not None
    assert corrected.supersedes == RunId("run_unknown")
    assert {e.run_id for e in audit.read_chain(result.record)} == {result.record}
