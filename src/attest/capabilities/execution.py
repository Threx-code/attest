"""The execution boundary — where a decision becomes an effect in the world.

Everything else proves a decision was warranted. This proves the *effect* corresponded
to the decision, and admits when it cannot.

Two properties carry the design:

**Write the intent before the effect.** `SUBMITTED` is persisted before the external
call, so a crash leaves evidence that a call was in flight. Without it, `UNKNOWN` is
indistinguishable from "never attempted".

**`UNKNOWN` is never coerced.** A timeout after the upstream committed is neither
success nor failure. Only the external system knows, and guessing is how a system
reports a payment that did not happen, or misses one that did.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from attest.kernel.attestation import EffectRecord
from attest.kernel.audit import AuditEvent, EventType
from attest.kernel.effects import EffectState, IdempotencyMode
from attest.kernel.errors import AuditSinkError, ContractViolation
from attest.kernel.verdicts import Refusal, RefusalReason

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime

    from attest.kernel.actions import Action
    from attest.kernel.authority import AuthorizationGrant
    from attest.kernel.context import ExecutionContext
    from attest.kernel.identifiers import RunId
    from attest.kernel.ports import AuditSink, IdempotencyStore, NonceStore

__all__ = [
    "EffectOutcome",
    "ExecutionBoundary",
    "ExecutionRefused",
    "Executor",
    "UpstreamTimeout",
]


class UpstreamTimeout(Exception):
    """The external call did not answer.

    Deliberately distinct from a failure. An executor that raises this is saying "I do
    not know", and the boundary records `UNKNOWN` rather than choosing for it.
    """


class ExecutionRefused(Exception):
    """The boundary declined to execute. Carries the typed refusal."""

    def __init__(self, refusal: Refusal) -> None:
        super().__init__(refusal.detail)
        self.refusal = refusal


@dataclass(frozen=True, slots=True)
class EffectOutcome:
    """What the upstream reported."""

    external_reference: str
    detail: str = ""


@runtime_checkable
class Executor(Protocol):
    """Host code that performs one external effect.

    Receives a *verified* action and the context that proves authorisation. It must
    not decide authority — that stays in the obligation layer, and duplicating it
    creates two places to get it wrong — but it cannot act without having been reached
    through the boundary.

    Raises :class:`UpstreamTimeout` when it does not know the outcome. Returning a
    plausible answer instead is the single most damaging thing an executor can do.
    """

    def execute(self, action: Action, context: ExecutionContext) -> EffectOutcome: ...


class ExecutionBoundary:
    """The only path from an authorised action to an effect.

    Bypassing it means forging a grant rather than calling a function. That is
    structural in the signature and not absolute in Python — a determined host can
    construct a fake grant — which is why every COMMITTED effect records its grant id,
    so an effect without one is detectable by reconciliation.
    """

    __slots__ = ("_audit", "_idempotency", "_nonces")

    def __init__(
        self,
        *,
        nonces: NonceStore,
        audit: AuditSink,
        idempotency: IdempotencyStore | None = None,
    ) -> None:
        self._nonces = nonces
        self._audit = audit
        self._idempotency = idempotency

    def _already_done(
        self,
        action: Action,
        grant: AuthorizationGrant,
        *,
        record: Callable[[str, dict[str, object]], None],
        stamp: dict[str, str],
        now: datetime,
    ) -> EffectRecord | None:
        """Report the original outcome rather than causing a second one.

        Returns the prior effect where this action already ran, ``None`` where it did
        not. An action with no idempotency key and no store gets no protection, which
        is why :attr:`IdempotencyMode.FORBIDDEN` exists — a tool that must never repeat
        and cannot be keyed is a configuration error, not a risk to accept quietly.
        """
        if self._idempotency is None or not grant.idempotency_key:
            if action.idempotency is IdempotencyMode.KEYED and not grant.idempotency_key:
                raise ExecutionRefused(
                    Refusal(
                        reason=RefusalReason("unsafe_action"),
                        detail=(
                            f"{action.tool!r} declares KEYED idempotency but the grant "
                            f"carries no key, so a retry would execute it twice. The "
                            f"key must identify the action to the upstream — an "
                            f"invoice or payment reference — not the run."
                        ),
                    )
                )
            return None

        prior = self._idempotency.claim(
            grant.idempotency_key,
            tenant=action.tenant,
            action_hash=action.action_hash(),
            now=now,
        )
        if prior is None:
            return None

        record(
            EventType.EFFECT_COMMITTED.value,
            {**stamp, "idempotent_replay": True, "reference": prior},
        )
        return EffectRecord(
            action=action,
            state=EffectState.COMMITTED,
            grant_id=grant.grant_id,
            external_reference=prior,
            idempotency_key=grant.idempotency_key,
            submitted_at=now,
            settled_at=now,
            detail=(
                "already executed under this idempotency key; the original upstream "
                "reference is reported rather than the effect being repeated"
            ),
        )

    def _recorder(
        self, now: datetime, emit: Callable[[str, dict[str, object]], None] | None
    ) -> Callable[[str, dict[str, object]], None]:
        """Record an event to the in-run chain **and** durably, before it matters.

        The class held an ``AuditSink`` and never read it. Every event went to the
        ``emit`` hook, which routes to an in-process list that the engine appends once,
        after the effect has already run — so a crash between the payment committing
        and the run finalising left no audit record at all. Not a dangling
        ``SUBMITTED``: nothing. The reconciliation sweep this module points at had
        nothing to find.

        Writing through the sink here is what makes "the intent is persisted before the
        external call" true rather than described. A sink failure is an
        :class:`~attest.kernel.errors.AuditSinkError` and stops the effect, because if
        we cannot record what we are about to do, we must not do it.
        """

        def record(event_type: str, payload: dict[str, object]) -> None:
            if emit is not None:
                # The recorder writes it, durably, as the same object it will seal.
                # Writing here as well produced a second, differently-shaped copy of
                # every effect event — different instant, no causal parent, different
                # arrival order — so the stored chain could never re-seal to the head
                # the attestation recorded.
                emit(event_type, payload)
                return
            self._append(event_type, payload, now=now, run_id=self._run_id_of(payload))

        return record

    @staticmethod
    def _run_id_of(payload: Mapping[str, object]) -> RunId:
        """The run this event belongs to. Refuses the empty fallback.

        ``payload.get("run_id")`` with a ``""`` default is one forgotten ``**stamp``
        away from writing audit events into a nameless run, where no per-run
        verification will ever look at them.
        """
        found = payload.get("run_id")
        if not found:
            raise AuditSinkError(
                "an audit event was recorded with no run id. There is no correct empty "
                "value here: the event would land in a nameless run that no per-run "
                "verification looks at."
            )
        return cast("RunId", str(found))

    def _append(
        self, event_type: str, payload: dict[str, object], *, now: datetime, run_id: RunId
    ) -> None:
        """The standalone path: no recorder, so the boundary writes its own events."""
        try:
            self._audit.append(
                AuditEvent(
                    run_id=run_id,
                    event_type=event_type,
                    occurred_at=now,
                    payload=dict(payload),
                )
            )
        except AuditSinkError:
            raise
        except Exception as exc:
            raise AuditSinkError(
                f"could not durably record {event_type!r} before the effect: {exc}. "
                f"If we cannot record what happened, we must not act."
            ) from exc

    def execute(
        self,
        *,
        action: Action,
        grant: AuthorizationGrant,
        context: ExecutionContext,
        executor: Executor,
        now: datetime,
        current_policy_version: str | None = None,
        emit: Callable[[str, dict[str, object]], None] | None = None,
    ) -> EffectRecord:
        """Verify, redeem, submit, and record — in that order.

        The order is the design. Redemption happens *before* submission, because a
        nonce consumed after a successful call cannot stop the replay that arrives
        while the first call is still in flight.
        """
        record = self._recorder(now, emit)
        stamp = {"run_id": str(context.run_id)}

        # Deliberately redundant with AuthorityEngine.issue, and for the same reason
        # the tenancy guard is redundant with query-level scoping: reaching this means
        # the primary check was bypassed, and this is the last gate before the effect.
        # grant.check_against cannot catch it — the grant's tenant came from the
        # action, so the two always agree.
        if action.tenant != context.identity.tenant:
            record(EventType.TENANCY_VIOLATION.value, {**stamp, "action_tenant": action.tenant})
            raise ExecutionRefused(
                Refusal(
                    reason=RefusalReason("insufficient_authority"),
                    detail=(
                        f"the action acts for tenant {action.tenant!r} but the run is "
                        f"bound to {context.identity.tenant!r}. Refused at the "
                        f"boundary; an effect for another tenant is not a routing "
                        f"error to be tidied up afterwards."
                    ),
                )
            )

        check = grant.check_against(
            action,
            now=now,
            current_policy_version=current_policy_version,
            context_hash=context.content_hash(),
        )
        if not check.authorised:
            reasons = ", ".join(r.value for r in check.rejections)
            record(
                "authority.grant_rejected", {**stamp, "grant_id": grant.grant_id, "why": reasons}
            )
            raise ExecutionRefused(
                Refusal(
                    reason=RefusalReason("insufficient_authority"),
                    detail=f"grant {grant.grant_id!r} does not authorise this action: {reasons}",
                )
            )

        # Single-use redemption, atomic, and BEFORE the external call. A nonce
        # consumed afterwards cannot stop a replay that arrives mid-flight.
        try:
            first_use = self._nonces.redeem(grant.nonce, grant.grant_id)
        except Exception as exc:
            raise ContractViolation(
                f"NonceStore.redeem failed: {exc}. Redemption must be atomic; without "
                f"it there is no replay defence, and proceeding would be worse than "
                f"refusing."
            ) from exc
        if not first_use:
            record(EventType.GRANT_REPLAY_REJECTED.value, {**stamp, "grant_id": grant.grant_id})
            raise ExecutionRefused(
                Refusal(
                    reason=RefusalReason("insufficient_authority"),
                    detail=f"grant {grant.grant_id!r} has already been redeemed",
                )
            )

        if self._nonces.is_revoked(grant.grant_id):
            record(
                "authority.grant_rejected", {**stamp, "grant_id": grant.grant_id, "why": "revoked"}
            )
            raise ExecutionRefused(
                Refusal(
                    reason=RefusalReason("insufficient_authority"),
                    detail=f"grant {grant.grant_id!r} was revoked",
                )
            )

        # The nonce is spent. Recorded as its own fact: a redemption that happened
        # without a submission following it is exactly what reconciliation looks for.
        record(EventType.GRANT_REDEEMED.value, {**stamp, "grant_id": grant.grant_id})

        # Already done? The nonce defends one grant against replay; it does nothing
        # about the same action being re-proposed under a fresh grant, which is what a
        # retried request produces. Checked after redemption so a replay of *this*
        # grant is still refused as a replay.
        settled = self._already_done(action, grant, record=record, stamp=stamp, now=now)
        if settled is not None:
            return settled

        # Intent before effect. A crash after this point leaves a dangling SUBMITTED,
        # which the reconciliation sweep looks for.
        record(
            EventType.EFFECT_SUBMITTED.value,
            {
                **stamp,
                "grant_id": grant.grant_id,
                "action_hash": action.action_hash(),
                "idempotency_key": grant.idempotency_key,
            },
        )

        try:
            outcome = executor.execute(action, context)
        except UpstreamTimeout as exc:
            record(
                EventType.EFFECT_UNKNOWN.value,
                {**stamp, "grant_id": grant.grant_id, "detail": str(exc)},
            )
            return EffectRecord(
                action=action,
                state=EffectState.UNKNOWN,
                grant_id=grant.grant_id,
                idempotency_key=grant.idempotency_key,
                submitted_at=now,
                detail=(
                    f"upstream did not answer: {exc}. Retry is "
                    f"{'permitted' if action.semantics.may_retry_on_timeout(action.idempotency) else 'FORBIDDEN'} "
                    f"for this tool; resolution is a reconciliation work item."
                ),
            )
        except Exception as exc:
            # Released only on a definite failure. A timeout must keep the key: the
            # upstream may have committed, and giving the key back would let a retry
            # do it again.
            if self._idempotency is not None and grant.idempotency_key:
                self._idempotency.release(grant.idempotency_key, tenant=action.tenant)
            record(
                EventType.EFFECT_FAILED.value,
                {**stamp, "grant_id": grant.grant_id, "detail": str(exc)},
            )
            return EffectRecord(
                action=action,
                state=EffectState.FAILED,
                grant_id=grant.grant_id,
                idempotency_key=grant.idempotency_key,
                submitted_at=now,
                settled_at=now,
                detail=f"{type(exc).__name__}: {exc}",
            )

        if not outcome.external_reference:
            # A commit we cannot point at is not a commit we can defend.
            record(
                EventType.EFFECT_UNKNOWN.value,
                {**stamp, "grant_id": grant.grant_id, "detail": "no reference"},
            )
            return EffectRecord(
                action=action,
                state=EffectState.UNKNOWN,
                grant_id=grant.grant_id,
                idempotency_key=grant.idempotency_key,
                submitted_at=now,
                detail=(
                    "executor returned success with no external reference; recorded "
                    "UNKNOWN rather than asserting a commit that cannot be pointed at"
                ),
            )

        # Settled before the event, so a crash between the two leaves the key claimed
        # rather than released: a claimed key that is never settled is a reconciliation
        # item, while a released one invites the retry that commits twice.
        if self._idempotency is not None and grant.idempotency_key:
            self._idempotency.settle(
                grant.idempotency_key,
                tenant=action.tenant,
                external_reference=outcome.external_reference,
            )
        try:
            record(
                EventType.EFFECT_COMMITTED.value,
                {
                    **stamp,
                    "grant_id": grant.grant_id,
                    "external_reference": outcome.external_reference,
                },
            )
        except AuditSinkError as exc:
            # The money has already moved. Before the effect, a sink failure must stop
            # the run — if we cannot record what we are about to do, we must not do it.
            # After it, raising means the caller sees a 500 for a payment that
            # succeeded, and a client that retries on 500 — the normal behaviour —
            # re-proposes and, without a wired IdempotencyStore, pays twice.
            #
            # The submitted event is already durable, so a dangling SUBMITTED is exactly
            # the reconciliation signal this design has. UNKNOWN says what is true: it
            # happened, and our record of it is incomplete.
            return EffectRecord(
                action=action,
                state=EffectState.UNKNOWN,
                grant_id=grant.grant_id,
                external_reference=outcome.external_reference,
                idempotency_key=grant.idempotency_key,
                submitted_at=now,
                detail=(
                    f"the effect COMMITTED and the audit sink then failed ({exc}). "
                    f"Recorded UNKNOWN rather than raising: the money moved, and a 500 "
                    f"here invites a retry that moves it again. Reconcile against "
                    f"{outcome.external_reference!r}."
                ),
            )
        return EffectRecord(
            action=action,
            state=EffectState.COMMITTED,
            grant_id=grant.grant_id,
            external_reference=outcome.external_reference,
            idempotency_key=grant.idempotency_key,
            submitted_at=now,
            settled_at=now,
            detail=outcome.detail,
        )
