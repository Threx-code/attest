"""Crashes at each point in the lifecycle. Red-team families 5, 7 and 10.

The question every case asks is the same: after the process dies here, what does the
record say, and is that honest? A crash that leaves the system *looking* settled when
it is not is worse than one that leaves it visibly incomplete.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from attest.adapters.memory import InMemoryAuditSink, InMemoryNonceStore, InMemoryRunStore
from attest.capabilities.audit import ChainSealer, EventRecorder
from attest.capabilities.execution import (
    EffectOutcome,
    ExecutionBoundary,
    ExecutionRefused,
    UpstreamTimeout,
)
from attest.capabilities.reconciliation import ReconciliationSweep
from attest.kernel.actions import Action
from attest.kernel.audit import ChainVerifier, EventType
from attest.kernel.authority import AuthorizationGrant
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import EffectState
from attest.kernel.errors import AuditSinkError
from attest.kernel.identifiers import ActorId, GrantId, Hash, Nonce, RunId, TenantId

pytestmark = [pytest.mark.failure_injection, pytest.mark.security]

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
ACME = TenantId("acme")
ALICE = ActorId("alice")
RUN = RunId("run_1")


def _context() -> ExecutionContext:
    return ExecutionContext(
        run_id=RUN,
        captured_at=AT,
        identity=IdentitySnapshot(actor=ALICE, tenant=ACME),
        binding=TenantBinding(
            tenant=ACME,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )


def _action() -> Action:
    return Action(tool="transfer", actor=ALICE, tenant=ACME, arguments={"amount": "500000"})


def _grant(action: Action, context: ExecutionContext) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id=GrantId("g1"),
        action_hash=action.action_hash(),
        actor=action.actor,
        tenant=action.tenant,
        tool=action.tool,
        nonce=Nonce("n1"),
        issued_at=AT,
        expires_at=AT + timedelta(seconds=30),
        policy_version=context.policy_version,
        profile_version=context.binding.profile.version,
        context_hash=context.content_hash(),
    )


class Crashes:
    """Dies partway through the external call, having already committed upstream."""

    def execute(self, action: Action, context: ExecutionContext) -> EffectOutcome:
        raise UpstreamTimeout("process died after the bank committed")


# ── Crash before authorization ───────────────────────────────────────────────


def test_a_crash_before_authorization_leaves_no_effect() -> None:
    # Nothing was submitted, so there is nothing to reconcile — the honest state.
    events: list[str] = []
    action, context = _action(), _context()
    grant = _grant(action, context)
    boundary = ExecutionBoundary(nonces=InMemoryNonceStore(), audit=InMemoryAuditSink())
    with pytest.raises(ExecutionRefused):
        boundary.execute(
            action=action,
            grant=grant,
            context=context,
            executor=Crashes(),
            now=grant.expires_at,  # expired: refused before anything is submitted
            emit=lambda t, p: events.append(t),
        )
    assert "effect.submitted" not in events


# ── Crash between submit and commit ──────────────────────────────────────────


def test_a_crash_after_submit_leaves_a_dangling_submitted() -> None:
    # The intent write is what makes UNKNOWN distinguishable from "never attempted".
    events: list[str] = []
    action, context = _action(), _context()
    record = ExecutionBoundary(nonces=InMemoryNonceStore(), audit=InMemoryAuditSink()).execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=Crashes(),
        now=AT,
        emit=lambda t, p: events.append(t),
    )
    assert events == ["authority.grant_redeemed", "effect.submitted", "effect.unknown"]
    assert record.state is EffectState.UNKNOWN
    assert record.submitted_at == AT


def test_the_reconciliation_sweep_finds_the_dangling_effect() -> None:
    # It is a work item, and its age is an SLO rather than a chart metric.
    action, context = _action(), _context()
    record = ExecutionBoundary(nonces=InMemoryNonceStore(), audit=InMemoryAuditSink()).execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=Crashes(),
        now=AT,
    )
    sweep = ReconciliationSweep(sla=timedelta(hours=1))
    assert sweep.overdue([record], now=AT + timedelta(hours=2)) == (record,)


def test_the_nonce_stays_consumed_after_a_crash() -> None:
    # Otherwise a retry after restart would be a fresh authorisation, and the effect
    # could be applied twice.
    nonces = InMemoryNonceStore()
    action, context = _action(), _context()
    grant = _grant(action, context)
    boundary = ExecutionBoundary(nonces=nonces, audit=InMemoryAuditSink())
    boundary.execute(action=action, grant=grant, context=context, executor=Crashes(), now=AT)
    with pytest.raises(ExecutionRefused, match="already been redeemed"):
        boundary.execute(action=action, grant=grant, context=context, executor=Crashes(), now=AT)


# ── Crash before the audit commit ────────────────────────────────────────────


def test_an_unsealed_run_does_not_verify_as_complete() -> None:
    # A crash before sealing leaves events with no bound count. That must read as
    # incomplete rather than as a valid short run.
    recorder = EventRecorder(run_id=RUN)
    recorder.record(EventType.RUN_DISPATCHED, {}, at=AT)
    recorder.record(EventType.EFFECT_SUBMITTED, {}, at=AT)
    assert not ChainSealer().evaluate(recorder.events, seal=None).satisfied


def test_appending_after_the_seal_is_refused() -> None:
    # A late append would make the bound count wrong, which is exactly what the seal
    # exists to detect.
    sink = InMemoryAuditSink()
    recorder = EventRecorder(run_id=RUN)
    recorder.record(EventType.RUN_DISPATCHED, {}, at=AT)
    sealed, _ = ChainSealer().seal(
        recorder.events, run_id=RUN, attestation_hash=Hash("a" * 64), sealed_at=AT
    )
    sink.append_many(sealed)
    sink.mark_sealed(RUN)
    with pytest.raises(AuditSinkError, match="seal exists to detect"):
        sink.append(sealed[0])


def test_a_partial_batch_does_not_land() -> None:
    # Either every event lands or none does: a partial batch cannot be sealed
    # densely, which is indistinguishable from omission.
    sink = InMemoryAuditSink()
    recorder = EventRecorder(run_id=RUN)
    recorder.record(EventType.RUN_DISPATCHED, {}, at=AT)
    sealed, _ = ChainSealer().seal(
        recorder.events, run_id=RUN, attestation_hash=Hash("a" * 64), sealed_at=AT
    )
    sink.mark_sealed(RUN)
    with pytest.raises(AuditSinkError):
        sink.append_many(sealed)
    assert sink.read_chain(RUN) == ()


# ── Crash after the audit commit ─────────────────────────────────────────────


def test_a_sealed_chain_still_verifies_after_a_restart() -> None:
    # The record survives the process that wrote it — which is the whole point.
    sink = InMemoryAuditSink()
    recorder = EventRecorder(run_id=RUN)
    for kind in (EventType.RUN_DISPATCHED, EventType.EFFECT_COMMITTED, EventType.RUN_COMPLETED):
        recorder.record(kind, {}, at=AT)
    sealed, seal = ChainSealer().seal(
        recorder.events, run_id=RUN, attestation_hash=Hash("a" * 64), sealed_at=AT
    )
    sink.append_many(sealed)
    # "Restart": read the chain back from storage and re-verify from scratch.
    assert ChainVerifier.verify(sink.read_chain(RUN), run_id=RUN, seal=seal)


def test_an_attestation_cannot_be_silently_overwritten_after_a_retry() -> None:
    # A crashed run that retries must supersede rather than replace, or the record a
    # downstream consumer relied on disappears.
    from attest.kernel.attestation import Attestation
    from attest.kernel.errors import StoreError
    from attest.kernel.verdicts import Verdict

    store = InMemoryRunStore()
    first = Attestation(run_id=RUN, verdict=Verdict.ALLOW, context=_context(), created_at=AT)
    store.create(first)
    with pytest.raises(StoreError, match="immutable"):
        store.create(first)
