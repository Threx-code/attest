"""The execution boundary. Threat-model attacks 7, 8, 10, 11, 12, 13, 14, 15."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

import pytest

from attest.capabilities.execution import (
    EffectOutcome,
    ExecutionBoundary,
    ExecutionRefused,
    UpstreamTimeout,
)
from attest.kernel.actions import Action
from attest.kernel.audit import AuditEvent
from attest.kernel.authority import AuthorizationGrant
from attest.kernel.context import ExecutionContext
from attest.kernel.effects import EffectState
from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import GrantId, Nonce, RunId
from tests.capabilities.conftest import AT

pytestmark = pytest.mark.unit


class FakeNonceStore:
    """An in-memory NonceStore that is genuinely single-use.

    Not simplified: a double that permits a second redemption would let every host's
    tests pass against a store that violates its contract.
    """

    def __init__(self, *, revoked: set[str] | None = None) -> None:
        self.used: set[str] = set()
        self.revoked: set[str] = revoked or set()

    def redeem(self, nonce: Nonce, grant_id: GrantId) -> bool:
        if nonce in self.used:
            return False
        self.used.add(nonce)
        return True

    def is_revoked(self, grant_id: GrantId) -> bool:
        return grant_id in self.revoked


class BrokenNonceStore:
    def redeem(self, nonce: Nonce, grant_id: GrantId) -> bool:
        raise RuntimeError("store unreachable")

    def is_revoked(self, grant_id: GrantId) -> bool:
        return False


class FakeAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)

    def append_many(self, events: Sequence[AuditEvent]) -> None:
        self.events.extend(events)

    def read_chain(self, run_id: RunId) -> Sequence[AuditEvent]:
        return tuple(self.events)


class Succeeds:
    def execute(self, action: Action, context: ExecutionContext) -> EffectOutcome:
        return EffectOutcome(external_reference="pay-123")


class TimesOut:
    """Commits upstream and never answers — the case that forces UNKNOWN."""

    def execute(self, action: Action, context: ExecutionContext) -> EffectOutcome:
        raise UpstreamTimeout("no response after 30s")


class Fails:
    def execute(self, action: Action, context: ExecutionContext) -> EffectOutcome:
        raise ValueError("insufficient funds")


class SucceedsWithoutReference:
    def execute(self, action: Action, context: ExecutionContext) -> EffectOutcome:
        return EffectOutcome(external_reference="")


def _grant(
    action: Action,
    context: ExecutionContext,
    *,
    ttl: timedelta = timedelta(seconds=30),
    **kw: object,
) -> AuthorizationGrant:
    base: dict[str, object] = {
        "grant_id": GrantId("g1"),
        "action_hash": action.action_hash(),
        "actor": action.actor,
        "tenant": action.tenant,
        "tool": action.tool,
        "nonce": Nonce("n1"),
        "issued_at": AT,
        "expires_at": AT + ttl,
        "policy_version": context.policy_version,
        "profile_version": context.binding.profile.version,
        "context_hash": context.content_hash(),
    }
    return AuthorizationGrant(**{**base, **kw})  # type: ignore[arg-type]


def _boundary(
    nonces: FakeNonceStore | BrokenNonceStore | None = None,
    audit: FakeAuditSink | None = None,
) -> ExecutionBoundary:
    return ExecutionBoundary(nonces=nonces or FakeNonceStore(), audit=audit or FakeAuditSink())


# ── The happy path still records everything ──────────────────────────────────


def test_a_committed_effect_records_its_grant_and_reference(
    action: Action, context: ExecutionContext
) -> None:
    events: list[str] = []
    record = _boundary().execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=Succeeds(),
        now=AT,
        emit=lambda t, p: events.append(t),
    )
    assert record.state is EffectState.COMMITTED
    assert record.external_reference == "pay-123"
    assert record.grant_id == "g1"
    # The redemption is its own event, and it comes first: a nonce spent with no
    # submission after it is precisely what reconciliation looks for.
    assert events == [
        "authority.grant_redeemed",
        "effect.submitted",
        "effect.committed",
    ]


@pytest.mark.security
def test_submitted_is_emitted_before_the_external_call(
    action: Action, context: ExecutionContext
) -> None:
    # Intent before effect: a crash after this point leaves a dangling SUBMITTED,
    # which is what makes UNKNOWN distinguishable from "never attempted".
    events: list[str] = []

    class RecordsOrder:
        def execute(self, a: Action, c: ExecutionContext) -> EffectOutcome:
            events.append("external_call")
            return EffectOutcome(external_reference="x")

    _boundary().execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=RecordsOrder(),
        now=AT,
        emit=lambda t, p: events.append(t),
    )
    assert events.index("effect.submitted") < events.index("external_call")


# ── Refusals ─────────────────────────────────────────────────────────────────


@pytest.mark.security
def test_a_mutated_action_is_refused(action: Action, context: ExecutionContext) -> None:
    # Attack 10: argument mutation after approval.
    from dataclasses import replace

    grant = _grant(action, context)
    mutated = replace(action, arguments={"to": "Y", "amount": "500000.00"})
    with pytest.raises(ExecutionRefused, match="does not authorise"):
        _boundary().execute(
            action=mutated, grant=grant, context=context, executor=Succeeds(), now=AT
        )


@pytest.mark.security
def test_an_expired_grant_is_refused(action: Action, context: ExecutionContext) -> None:
    grant = _grant(action, context)
    with pytest.raises(ExecutionRefused, match="expired"):
        _boundary().execute(
            action=action,
            grant=grant,
            context=context,
            executor=Succeeds(),
            now=grant.expires_at,
        )


@pytest.mark.security
def test_a_replayed_grant_is_refused(action: Action, context: ExecutionContext) -> None:
    # Attack 8. The nonce is consumed on the first redemption.
    nonces = FakeNonceStore()
    boundary = _boundary(nonces)
    grant = _grant(action, context)
    boundary.execute(action=action, grant=grant, context=context, executor=Succeeds(), now=AT)
    with pytest.raises(ExecutionRefused, match="already been redeemed"):
        boundary.execute(action=action, grant=grant, context=context, executor=Succeeds(), now=AT)


@pytest.mark.security
def test_the_nonce_is_consumed_before_the_external_call(
    action: Action, context: ExecutionContext
) -> None:
    # A nonce consumed AFTER a successful call cannot stop a replay that arrives
    # while the first call is still in flight.
    nonces = FakeNonceStore()
    order: list[str] = []

    class Observes:
        def execute(self, a: Action, c: ExecutionContext) -> EffectOutcome:
            order.append(f"call:{len(nonces.used)}")
            return EffectOutcome(external_reference="x")

    _boundary(nonces).execute(
        action=action, grant=_grant(action, context), context=context, executor=Observes(), now=AT
    )
    assert order == ["call:1"]


@pytest.mark.security
def test_a_revoked_grant_is_refused(action: Action, context: ExecutionContext) -> None:
    # Attack 7: capability revoked between check and effect.
    nonces = FakeNonceStore(revoked={"g1"})
    with pytest.raises(ExecutionRefused, match="revoked"):
        _boundary(nonces).execute(
            action=action,
            grant=_grant(action, context),
            context=context,
            executor=Succeeds(),
            now=AT,
        )


@pytest.mark.security
def test_a_superseded_policy_is_refused(action: Action, context: ExecutionContext) -> None:
    with pytest.raises(ExecutionRefused, match="does not authorise"):
        _boundary().execute(
            action=action,
            grant=_grant(action, context),
            context=context,
            executor=Succeeds(),
            now=AT,
            current_policy_version="2.0.0",
        )


@pytest.mark.security
def test_a_broken_nonce_store_raises_rather_than_proceeding(
    action: Action, context: ExecutionContext
) -> None:
    # Without atomic redemption there is no replay defence at all, so proceeding
    # would be worse than refusing.
    with pytest.raises(ContractViolation, match="must be atomic"):
        _boundary(BrokenNonceStore()).execute(
            action=action,
            grant=_grant(action, context),
            context=context,
            executor=Succeeds(),
            now=AT,
        )


# ── UNKNOWN is never coerced ─────────────────────────────────────────────────


@pytest.mark.security
def test_a_timeout_yields_unknown_not_success_or_failure(
    action: Action, context: ExecutionContext
) -> None:
    # Attack 12. The bank may have committed. Only it knows.
    record = _boundary().execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=TimesOut(),
        now=AT,
    )
    assert record.state is EffectState.UNKNOWN
    assert record.submitted_at == AT
    assert record.settled_at is None


@pytest.mark.security
def test_an_unknown_records_whether_retry_is_permitted(
    action: Action, context: ExecutionContext
) -> None:
    # Attack 13: the retry decision and its reason are part of the record.
    record = _boundary().execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=TimesOut(),
        now=AT,
    )
    assert "FORBIDDEN" in record.detail  # default idempotency is FORBIDDEN


@pytest.mark.security
def test_success_without_an_external_reference_is_unknown(
    action: Action, context: ExecutionContext
) -> None:
    # A commit we cannot point at is not a commit we can defend. Attack 15.
    record = _boundary().execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=SucceedsWithoutReference(),
        now=AT,
    )
    assert record.state is EffectState.UNKNOWN
    assert "cannot be pointed at" in record.detail


def test_an_executor_error_is_a_failed_effect(action: Action, context: ExecutionContext) -> None:
    record = _boundary().execute(
        action=action,
        grant=_grant(action, context),
        context=context,
        executor=Fails(),
        now=AT,
    )
    assert record.state is EffectState.FAILED
    assert "insufficient funds" in record.detail
