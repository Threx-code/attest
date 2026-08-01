"""Obligations, discharge, and grant issuance.

Authority is a **set of obligations**, not a ladder. A bank needs dual control; a
mortgage needs a cooling-off window during which the applicant may withdraw; an
insurer needs a second approver only above a threshold; a SAR filing must NOT notify
the subject. None of those is a rung.

Discharge is fail-fast and fail-closed: an obligation that raises is FAILED, never
skipped. A grant is issued only when every obligation is SATISFIED, which the kernel
enforces at construction.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from typing import TYPE_CHECKING

from attest.kernel.authority import AuthorizationGrant, Discharge, ObligationOutcome
from attest.kernel.effects import EffectClasses
from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence
    from datetime import datetime

    from attest.kernel.actions import Action
    from attest.kernel.authority import ApprovalRecord
    from attest.kernel.context import ExecutionContext
    from attest.kernel.identifiers import ApprovalId, GrantId, Nonce
    from attest.kernel.ports import BudgetStore

__all__ = [
    "Approval",
    "AuthorityEngine",
    "BoundObligations",
    "Budget",
    "CapabilityCheck",
    "CoolingOff",
    "DischargeResult",
    "DualControl",
    "Notification",
    "ObligationBinder",
    "ObligationSet",
    "Reversibility",
    "ReviewAttestation",
    "TimeWindow",
]


class _Obligation:
    """Base for shipped obligations. Domains may implement the protocol directly."""

    @property
    def name(self) -> str:
        return "obligation"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        raise NotImplementedError

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return ""


@dataclass(frozen=True, slots=True)
class CapabilityCheck(_Obligation):
    """The actor must hold a capability. The confused-deputy defence."""

    capability: str

    @property
    def name(self) -> str:
        return f"capability:{self.capability}"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        if context.identity.holds(self.capability):
            return Discharge.SATISFIED
        return Discharge.FAILED

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return f"actor {context.identity.actor!r} does not hold {self.capability!r}"


@dataclass(frozen=True, slots=True)
class Approval(_Obligation):
    """``n`` approvals from the given roles. ``n > 1`` is a quorum."""

    n: int = 1
    roles: frozenset[str] = frozenset()
    approvals: tuple[ApprovalRecord, ...] = ()

    @property
    def name(self) -> str:
        return f"approval:{'|'.join(sorted(self.roles)) or 'any'}"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        # Bound to the action, exactly as a grant is. An approval that does not say
        # what it was about is a free-floating "yes": a decision captured for a £50
        # refund would otherwise discharge this for a £500,000 transfer.
        relevant = [a for a in self.approvals if a.covers(action.action_hash())]
        granted = [a for a in relevant if a.approved and (not self.roles or a.role in self.roles)]
        if len(granted) >= self.n:
            return Discharge.SATISFIED
        if any(not a.approved for a in relevant):
            return Discharge.FAILED
        return Discharge.PENDING

    def detail(self, action: Action, context: ExecutionContext) -> str:
        relevant = sum(1 for a in self.approvals if a.covers(action.action_hash()))
        if relevant < len(self.approvals):
            return (
                f"{relevant} of {self.n} approvals are for this action; "
                f"{len(self.approvals) - relevant} were recorded for a different one"
            )
        return f"{relevant} of {self.n} required approvals present"


@dataclass(frozen=True, slots=True)
class DualControl(_Obligation):
    """Two DISTINCT humans, and the actor may not self-approve.

    Self-approval is the most common way dual control is defeated in practice, so it
    is checked here rather than assumed.
    """

    roles: frozenset[str] = frozenset()
    approvals: tuple[ApprovalRecord, ...] = ()

    @property
    def name(self) -> str:
        return f"dual_control:{'|'.join(sorted(self.roles)) or 'any'}"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        relevant = [a for a in self.approvals if a.covers(action.action_hash())]
        granted = [
            a
            for a in relevant
            if a.approved
            and a.approver != context.identity.actor
            and (not self.roles or a.role in self.roles)
        ]
        if len({a.approver for a in granted}) >= 2:
            return Discharge.SATISFIED
        if any(not a.approved for a in relevant):
            return Discharge.FAILED
        return Discharge.PENDING

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return "two distinct approvers required; the actor may not self-approve"


@dataclass(frozen=True, slots=True)
class Budget(_Obligation):
    """A spend ceiling, RESERVED before the call rather than read after it.

    The kernel side of this is a check against an already-obtained reservation: a
    budget that is merely read is a race, and the atomic reserve lives behind the
    BudgetStore port.
    """

    scope: str
    amount: str = "0"
    """What this action would spend, as a decimal string. Reserved, not merely checked.

    **Validated at construction**, so a malformed figure is refused while a refusal is
    still free. It used to reach ``Decimal()`` inside ``commit`` — after the effect had
    already committed — where it raised past the settle path to the caller as a 500 for
    a payment that succeeded, inviting the retry that pays twice.
    """

    amount_for: Callable[[Action], str] | None = None
    """How to compute the amount from the action, when it is not fixed.

    The profile supplies this, because the profile knows its own schema. The engine used
    to read ``action.arguments.get("amount", "")`` — the framework guessing a domain
    field name, in a codebase that elsewhere refuses to know what a claim is. A tool
    whose argument is ``value``, ``total`` or ``amount_pence`` charged the ceiling the
    *model spend* while moving half a million pounds, and the proposer chooses the key.
    """

    reservation_id: str | None = None
    """Supplied by :class:`ObligationBinder`, never by the profile.

    A profile knows *that* an action needs budget and *how much*; only the runtime can
    take the atomic reservation. Left unset this obligation is unsatisfiable, which is
    the correct failure — a budget that was never reserved has not been checked.
    """

    def __post_init__(self) -> None:
        self.assert_decimal(self.amount, where=f"budget:{self.scope}")

    @property
    def name(self) -> str:
        return f"budget:{self.scope}"

    def amount_of(self, action: Action) -> str:
        """What this action spends. Validated, and never guessed from the arguments."""
        if self.amount_for is None:
            return self.amount
        try:
            computed = str(self.amount_for(action))
        except Exception as exc:
            raise ConfigurationError(
                f"the profile's amount_for on budget:{self.scope} raised "
                f"{type(exc).__name__} for {action.tool!r}. Refusing before the "
                f"reservation: a budget whose amount cannot be computed cannot be "
                f"reserved, and reserving zero would let the ceiling be evaded."
            ) from exc
        self.assert_decimal(computed, where=f"budget:{self.scope} amount_for")
        return computed

    @staticmethod
    def assert_decimal(value: str, *, where: str) -> None:
        """Refuse a figure that is not one, **before** anything is reserved or spent.

        ``"GBP 500,000"``, ``"1,000"`` and a nested object all reach ``Decimal()``
        eventually. Whether that is a free refusal or a 500 for a completed payment
        depends entirely on when.
        """
        from decimal import Decimal, InvalidOperation

        try:
            parsed = Decimal(value)
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"{where} has amount {value!r}, which is not a decimal. Refused here, "
                f"where refusing is free — reaching Decimal() after the effect has "
                f"committed raises to the caller for a payment that succeeded."
            ) from exc
        if parsed < 0:
            raise ConfigurationError(f"{where} has a negative amount {value!r}")

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        if self.reservation_id:
            return Discharge.SATISFIED
        return Discharge.FAILED

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return f"no reservation held against {self.scope!r}; a read budget is a race"


@dataclass(frozen=True, slots=True)
class CoolingOff(_Obligation):
    """A period must elapse, during which the subject may cancel.

    Not a rung on any ladder, which is the concrete argument against autonomy levels.
    """

    duration: timedelta
    started_at: datetime | None = None
    cancelled: bool = False

    @property
    def name(self) -> str:
        return f"cooling_off:{int(self.duration.total_seconds())}s"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        if self.cancelled:
            return Discharge.FAILED
        if self.started_at is None:
            return Discharge.PENDING
        if context.captured_at - self.started_at >= self.duration:
            return Discharge.SATISFIED
        return Discharge.PENDING

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return "cancelled by the subject" if self.cancelled else "period has not elapsed"


@dataclass(frozen=True, slots=True)
class TimeWindow(_Obligation):
    """Only before a deadline, or within permitted hours.

    An obligation that FAILS with the passage of time rather than through any action.
    """

    before: datetime | None = None
    after: datetime | None = None

    @property
    def name(self) -> str:
        return "time_window"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        now = context.captured_at
        if self.after is not None and now < self.after:
            return Discharge.PENDING
        if self.before is not None and now >= self.before:
            return Discharge.FAILED
        return Discharge.SATISFIED

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return f"deadline {self.before.isoformat()} passed" if self.before else "outside window"


@dataclass(frozen=True, slots=True)
class Notification(_Obligation):
    """A party must be told, before the effect takes place.

    Mandatory in some domains and a criminal offence in others, which is why it is an
    obligation a profile chooses rather than framework behaviour.
    """

    party: str
    before_effect: bool = True
    sent: bool = False

    @property
    def name(self) -> str:
        return f"notification:{self.party}"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        if not self.before_effect:
            return Discharge.SATISFIED
        return Discharge.SATISFIED if self.sent else Discharge.PENDING

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return f"{self.party} has not been notified"


@dataclass(frozen=True, slots=True)
class ReviewAttestation(_Obligation):
    """A named human attests they reviewed specific facts.

    ``reviewed`` is what distinguishes this from an approval: an attestation that
    cannot say what was in front of the person is not evidence anything was reviewed.
    """

    role: str
    reviewed: tuple[str, ...] = ()
    attested_by: str | None = None

    @property
    def name(self) -> str:
        return f"review_attestation:{self.role}"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        if self.attested_by and self.reviewed:
            return Discharge.SATISFIED
        return Discharge.PENDING

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return f"no {self.role} attestation naming the facts reviewed"


@dataclass(frozen=True, slots=True)
class Reversibility(_Obligation):
    """Irreversible actions demand a strictly higher bar.

    Expressed as an obligation so a profile can require it uniformly across tools it
    has never seen, by their declared semantics rather than their names.
    """

    require_compensatable: bool = True

    @property
    def name(self) -> str:
        return "reversibility"

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge:
        semantics = action.semantics
        if semantics.reversible:
            return Discharge.SATISFIED
        if self.require_compensatable and semantics.compensatable:
            return Discharge.SATISFIED
        if EffectClasses.READ in action.effects:
            return Discharge.SATISFIED
        return Discharge.FAILED

    def detail(self, action: Action, context: ExecutionContext) -> str:
        return "action is neither reversible nor compensatable"


@dataclass(frozen=True, slots=True)
class ObligationSet:
    """An ordered set of obligations. Never silently empty for a real action."""

    obligations: tuple[_Obligation, ...] = ()

    def __iter__(self) -> Iterator[_Obligation]:
        return iter(self.obligations)

    def __len__(self) -> int:
        return len(self.obligations)

    def __bool__(self) -> bool:
        return bool(self.obligations)

    def __add__(self, other: ObligationSet | Sequence[_Obligation]) -> ObligationSet:
        extra = other.obligations if isinstance(other, ObligationSet) else tuple(other)
        return ObligationSet(self.obligations + extra)


@dataclass(frozen=True, slots=True)
class DischargeResult:
    """The outcome of discharging a whole set."""

    outcomes: tuple[ObligationOutcome, ...]

    @property
    def satisfied(self) -> bool:
        return all(o.discharge is Discharge.SATISFIED for o in self.outcomes)

    @property
    def pending(self) -> tuple[ObligationOutcome, ...]:
        return tuple(o for o in self.outcomes if o.discharge is Discharge.PENDING)

    @property
    def failed(self) -> tuple[ObligationOutcome, ...]:
        return tuple(o for o in self.outcomes if o.discharge is Discharge.FAILED)


class AuthorityEngine:
    """Discharges obligations and issues grants.

    A class rather than two functions because the two steps share a policy that must
    not diverge: the ttl a grant is issued with, and the rule that a grant is issued
    only when everything discharged. Splitting them lets a caller do the second
    without the first.
    """

    __slots__ = ("_ttl",)

    def __init__(self, *, grant_ttl: timedelta = timedelta(seconds=60)) -> None:
        self._ttl = grant_ttl

    def discharge(
        self, obligations: ObligationSet, action: Action, context: ExecutionContext
    ) -> DischargeResult:
        """Discharge every obligation, fail-closed.

        An obligation that RAISES is recorded FAILED rather than skipped. That is the
        typed form of the ``except Exception: return True`` found in surveyed guard
        code: an error in a check is not a pass.

        Every obligation is evaluated rather than short-circuiting on the first
        failure, because a caller triaging a refusal needs the whole picture — and a
        partially-evaluated set cannot be re-discharged consistently on resume.
        """
        outcomes: list[ObligationOutcome] = []
        for obligation in obligations:
            try:
                state = obligation.discharge(action, context)
                detail = "" if state is Discharge.SATISFIED else obligation.detail(action, context)
            except Exception as exc:
                state = Discharge.FAILED
                detail = f"obligation raised {type(exc).__name__}: {exc}"
            outcomes.append(
                ObligationOutcome(
                    name=obligation.name,
                    discharge=state,
                    detail=detail or ("failed" if state is Discharge.FAILED else ""),
                )
            )
        return DischargeResult(tuple(outcomes))

    def issue(
        self,
        *,
        grant_id: GrantId,
        nonce: Nonce,
        action: Action,
        context: ExecutionContext,
        result: DischargeResult,
        now: datetime,
        approvals: tuple[ApprovalRecord, ...] = (),
        idempotency_key: str | None = None,
    ) -> AuthorizationGrant:
        """Issue a grant, and only when everything discharged.

        The kernel's ``AuthorizationGrant`` refuses undischarged obligations too, so
        this is defence in depth — but raising here names the obligations that blocked
        it, which the constructor cannot.
        """
        if not result.satisfied:
            blocking = [o.name for o in (*result.pending, *result.failed)]
            raise ValueError(
                f"cannot issue a grant for {action.tool!r}: obligations {blocking} have "
                f"not discharged. A grant issued before every obligation is satisfied "
                f"is authority bypass."
            )
        if action.tenant != context.identity.tenant:
            # The confused deputy, and it is invisible downstream: the grant would
            # take its tenant FROM the action, so every later check — grant against
            # action, boundary against grant — would agree with itself while the
            # effect landed on a tenant this run was never bound to. This is the only
            # place that holds both the action and the context, so it is the only
            # place the mismatch can be seen.
            raise ValueError(
                f"cannot issue a grant: the action acts for tenant "
                f"{action.tenant!r} but the run is bound to "
                f"{context.identity.tenant!r}. Every downstream check would pass, "
                f"because they all compare against the action's own tenant."
            )
        if action.actor != context.identity.actor:
            raise ValueError(
                f"cannot issue a grant: the action names actor {action.actor!r} but "
                f"the run was dispatched by {context.identity.actor!r}. The "
                f"capability check discharged against the dispatching actor's "
                f"capabilities, so authorising a different one is a confused deputy."
            )
        return AuthorizationGrant(
            grant_id=grant_id,
            action_hash=action.action_hash(),
            actor=action.actor,
            tenant=action.tenant,
            tool=action.tool,
            nonce=nonce,
            issued_at=now,
            expires_at=now + self._ttl,
            policy_version=context.policy_version,
            profile_version=context.binding.profile.version,
            context_hash=context.content_hash(),
            obligations=result.outcomes,
            approvals=approvals,
            idempotency_key=idempotency_key,
        )


@dataclass(frozen=True, slots=True)
class BoundObligations:
    """A profile's obligations, with the runtime facts it could not know supplied."""

    obligations: ObligationSet
    reservations: tuple[str, ...] = ()
    """Budget reservations taken while binding. Released if the run does not proceed."""

    reserved_amount: str = "0"
    """What those reservations hold, as a decimal string.

    Settlement charges **this**, not a figure re-derived from the action's arguments.
    The engine used to guess a key called ``amount``, so a tool whose argument was
    ``value`` charged the ceiling the model spend while moving half a million pounds —
    and nothing looked wrong, which is the dangerous part.
    """

    approvals_applied: int = 0
    approvals: tuple[ApprovalRecord, ...] = ()
    """The decisions that were attached, so the caller can mark them spent.

    A decision must be spendable once. Returned here rather than left for the caller to
    re-fetch, because a second read could see a different set — and the set that
    authorised the grant is the set that must be consumed.
    """

    scopes_refused: tuple[str, ...] = ()
    """Scopes whose ceiling would have been breached. The obligation stays unsatisfiable."""


class ObligationBinder:
    """Supplies the runtime facts a profile cannot know, before anything discharges.

    The gap this closes is not cosmetic. A profile writes ``Budget("payments", "500")``
    and ``Approval(n=2, roles={"underwriter"})`` because those are policy. Neither can
    carry a reservation id or an approval record, because neither exists when the
    profile is written — so an unbound obligation set is one where the budget can never
    discharge and the approval waits forever.

    Reservation happens **here**, before any obligation is asked whether it is
    satisfied, which is what makes "reserved rather than read" true of the whole
    pipeline rather than of one store method.
    """

    __slots__ = ("_budget", "_reserved_amounts", "_ttl")

    def __init__(
        self, *, budget: BudgetStore | None = None, ttl: timedelta = timedelta(minutes=5)
    ) -> None:
        self._budget = budget
        self._ttl = ttl
        self._reserved_amounts: dict[str, str] = {}

    def bind(
        self,
        obligations: ObligationSet,
        *,
        action: Action | None = None,
        approvals: Sequence[ApprovalRecord] = (),
        now: datetime,
        on_reserved: Callable[[str, str], None] | None = None,
    ) -> BoundObligations:
        """Return the same obligations with reservations and approvals attached.

        ``on_reserved`` is called with ``(scope, reservation_id)`` so the caller can
        record the reservation in the run's chain. A reservation nobody recorded is a
        hold nobody can explain when it expires.
        """
        bound: list[_Obligation] = []
        attached: dict[ApprovalId, ApprovalRecord] = {}
        self._reserved_amounts = {}
        reservations: list[str] = []
        refused: list[str] = []
        applied = 0

        for obligation in obligations:
            if isinstance(obligation, Budget) and obligation.reservation_id is None:
                held = self._reserve(obligation, action=action, now=now)
                if held is None:
                    # The ceiling would be breached. The obligation is left unbound and
                    # therefore unsatisfiable, which is the refusal — rather than being
                    # dropped, which would be the ceiling silently not applying.
                    refused.append(obligation.scope)
                    bound.append(obligation)
                    continue
                reservations.append(held)
                if on_reserved is not None:
                    on_reserved(obligation.scope, held)
                bound.append(replace(obligation, reservation_id=held))
            elif isinstance(obligation, Approval | DualControl) and not obligation.approvals:
                relevant = tuple(
                    record
                    for record in approvals
                    if not obligation.roles or record.role in obligation.roles
                )
                applied += len(relevant)
                attached.update({record.approval_id: record for record in relevant})
                bound.append(replace(obligation, approvals=relevant))
            else:
                bound.append(obligation)

        return BoundObligations(
            obligations=ObligationSet(tuple(bound)),
            reservations=tuple(reservations),
            reserved_amount=self._total_reserved(),
            approvals_applied=applied,
            approvals=tuple(attached.values()),
            scopes_refused=tuple(refused),
        )

    def _total_reserved(self) -> str:
        """What was actually put aside, as the string settlement will charge.

        Settlement charges what reservation held. Re-deriving the figure somewhere else
        is how a ledger comes to disagree with the world.
        """
        from decimal import Decimal

        total = sum((Decimal(v) for v in self._reserved_amounts.values()), Decimal(0))
        return str(total)

    def commit(self, reservations: Sequence[str], *, actual: str) -> None:
        """Charge the ceiling for a run that actually spent. **The settle step.**

        Nothing ever called this, so ``BudgetSpend.amount`` stayed at zero for the life
        of the deployment and the ceiling check ran against *concurrently held
        reservations only*. The budget was a concurrency limiter wearing the costume of
        a spend ceiling: reserve, execute, let the hold expire unrecorded, repeat.
        Daily spend was unbounded and the ledger said zero.

        The first reservation carries the whole amount and the rest are released. A run
        holding several scopes has already been checked against each ceiling; charging
        the actual cost to every one of them would count the same money N times.
        """
        if self._budget is None or not reservations:
            return
        self._budget.commit(reservations[0], actual)
        for reservation in reservations[1:]:
            self._budget.release(reservation)

    def release(self, reservations: Sequence[str]) -> None:
        """Give back holds for a run that will not proceed.

        A crashed or refused run that kept its reservation starves every run behind it
        until the expiry sweep catches up.
        """
        if self._budget is None:
            return
        for reservation in reservations:
            self._budget.release(reservation)

    def _reserve(self, obligation: Budget, *, action: Action | None, now: datetime) -> str | None:
        """Reserve the obligation's **own** amount, computed by the profile.

        Returns the amount alongside so settlement charges what was reserved rather
        than re-deriving it from somewhere else and disagreeing.
        """
        if self._budget is None:
            return None
        amount = obligation.amount if action is None else obligation.amount_of(action)
        self._reserved_amounts[obligation.scope] = amount
        return self._budget.reserve(obligation.scope, amount, now + self._ttl)
