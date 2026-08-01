"""Authority — obligations, and the grant that closes the gap before an effect.

Discharging obligations is necessary and **not sufficient**. There is still a window
between the last check and the effect itself:

.. code-block:: text

    10:00:00  capability check      PASS
    10:00:01  approval              PASS
    10:00:02  budget check          PASS
    10:00:03  capability REVOKED            <- nothing observes this
    10:00:04  execute()                     <- proceeds anyway

An :class:`AuthorizationGrant` closes it: a short-lived token bound to the exact
action, issued only once every obligation has discharged, and re-checked at the effect
boundary. Bypassing the framework then means *forging a grant*, not merely calling a
function.

Authority is an **obligation set**, not an autonomy ladder. A four-rung ladder
(observe / suggest / act-with-approval / act) cannot express a seven-day cooling-off
window during which the applicant may withdraw, an obligation that fires only on
decline, two distinct humans above a threshold, or a notification that must precede
the effect. Every one of those is routine in the target domains.

What lives here is the **value type and its pure checks**. Single-use redemption needs
a store and an atomic compare-and-set, so it belongs at L1 — see
:meth:`AuthorizationGrant.check_against`, which deliberately does not answer "has this
nonce been used".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

from attest.kernel.canonical import Canonical
from attest.kernel.identifiers import Hash, Secrets

if TYPE_CHECKING:
    from datetime import datetime

    from attest.kernel.actions import Action
    from attest.kernel.context import ExecutionContext
    from attest.kernel.identifiers import (
        ActorId,
        ApprovalId,
        GrantId,
        Nonce,
        RunId,
        TenantId,
    )

__all__ = [
    "MAX_GRANT_TTL",
    "ApprovalRecord",
    "AuthorizationGrant",
    "Discharge",
    "GrantCheck",
    "GrantRejection",
    "Obligation",
    "ObligationOutcome",
]

MAX_GRANT_TTL: Final = timedelta(minutes=15)
"""Hard ceiling on a grant's lifetime.

The grant exists to shrink the window between the last check and the effect. A grant
valid for hours does not shrink it, so a long TTL is rejected at construction rather
than trusted to reviewer discipline. Domains that need a *pause* want an approval
hold, which is a different mechanism with its own expiry.
"""


class Discharge(StrEnum):
    """The outcome of discharging one obligation."""

    SATISFIED = "satisfied"
    PENDING = "pending"
    """Awaiting something external — a human decision, a cooling-off window.
    Produces `HOLD_FOR_APPROVAL`, never a silent drop."""

    FAILED = "failed"
    """Cannot be met. Produces `REFUSE`."""


@runtime_checkable
class Obligation(Protocol):
    """Something that must be discharged before an action may execute.

    Domains supply their own freely — a contraindication check, a sanctions screen, a
    tipping-off guard. The framework never learns what they mean; it only knows one
    must discharge.
    """

    @property
    def name(self) -> str: ...

    def discharge(self, action: Action, context: ExecutionContext) -> Discharge: ...


@dataclass(frozen=True, slots=True)
class ObligationOutcome:
    """The record that one obligation was discharged, and how."""

    name: str
    discharge: Discharge
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("obligation name must not be empty; outcomes are audited")
        if self.discharge is Discharge.FAILED and not self.detail:
            raise ValueError(
                f"obligation {self.name!r} failed without a reason; a refusal that "
                f"cannot be explained cannot be contested"
            )


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    """A human decision, with enough detail to be evidence of oversight.

    ``reviewed_items`` matters more than it looks: the quality of an approval is
    bounded by what the approver was shown, and an approval record that cannot say
    what was in front of the person is not evidence that anything was reviewed.
    """

    approval_id: ApprovalId
    approver: ActorId
    role: str
    approved: bool
    decided_at: datetime
    action_hash: Hash | None = None
    """The exact action this decision was about — arguments, not the tool name.

    Without it an approval is a free-floating "yes" that satisfies any obligation it is
    handed to: a decision captured for a £50 refund would discharge dual control on a
    £500,000 transfer. The obligation refuses an approval whose hash does not match, so
    ``None`` satisfies nothing. It is optional only because a historical record may
    predate the field, and such a record must fail closed rather than fail to load.
    """

    run_id: RunId | None = None
    reviewed_items: tuple[str, ...] = ()
    note: str = ""

    def covers(self, action_hash: Hash) -> bool:
        """Whether this decision was about *this* action."""
        return self.action_hash is not None and self.action_hash == action_hash

    def __post_init__(self) -> None:
        if not self.role:
            raise ValueError(
                "approval role must not be empty: an n-of-m quorum is defined over "
                "roles, so an unattributed approval cannot be counted"
            )


class GrantRejection(StrEnum):
    """Why a grant did not authorise an action.

    Typed rather than a bare ``False`` because each reason has a different operational
    meaning: an expired grant is routine, a mismatched action hash is an attack.
    """

    ACTION_MISMATCH = "action_mismatch"
    """The grant was issued for a different action. Threat-model attacks 5 and 10."""

    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    """Presented before issuance — a clock disagreement, or a forged timestamp."""

    ACTOR_MISMATCH = "actor_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    REVOKED = "revoked"
    POLICY_SUPERSEDED = "policy_superseded"
    """The policy version the grant was issued under is no longer current."""


@dataclass(frozen=True, slots=True)
class GrantCheck:
    """The result of checking a grant. Never a bare boolean.

    Carries **every** rejection found rather than the first, so an operator sees the
    whole picture: a grant that is both expired and bound to a different action is a
    materially different signal from one that merely lapsed.
    """

    rejections: tuple[GrantRejection, ...] = ()

    @property
    def authorised(self) -> bool:
        """True only when nothing rejected it.

        Note what this does **not** cover: whether the nonce has already been
        redeemed. That needs an atomic store operation and lives at L1. A caller
        that treats this as sufficient has not defended against replay.
        """
        return not self.rejections

    def __bool__(self) -> bool:
        return self.authorised


@dataclass(frozen=True, slots=True)
class AuthorizationGrant:
    """Permission to cause one specific effect, for a short time, once.

    Every field is part of the binding. ``action_hash`` covers the arguments, so a
    grant for "pay GBP 12,400 to X" cannot authorise "pay GBP 500,000 to Y".
    """

    grant_id: GrantId
    action_hash: Hash
    actor: ActorId
    tenant: TenantId
    tool: str
    nonce: Nonce
    issued_at: datetime
    expires_at: datetime
    policy_version: str
    profile_version: str
    context_hash: Hash
    """Binds the grant to the exact snapshot the obligations were discharged against.

    Without it a grant could be redeemed against a re-captured context whose identity
    or policy had since weakened.
    """

    obligations: tuple[ObligationOutcome, ...] = ()
    approvals: tuple[ApprovalRecord, ...] = ()
    idempotency_key: str | None = None
    revoked: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.expires_at <= self.issued_at:
            raise ValueError(
                f"grant {self.grant_id!r} expires at or before it is issued; it could "
                f"never authorise anything"
            )
        ttl = self.expires_at - self.issued_at
        if ttl > MAX_GRANT_TTL:
            raise ValueError(
                f"grant TTL {ttl} exceeds the {MAX_GRANT_TTL} ceiling. The grant exists "
                f"to shrink the window between the last check and the effect; a "
                f"long-lived one does not. For a deliberate pause, use an approval hold."
            )
        if not self.nonce:
            raise ValueError("grant nonce must not be empty: without it a grant is replayable")
        unsatisfied = [
            outcome.name
            for outcome in self.obligations
            if outcome.discharge is not Discharge.SATISFIED
        ]
        if unsatisfied:
            raise ValueError(
                f"grant {self.grant_id!r} carries undischarged obligations "
                f"{unsatisfied}. A grant is issued only after every obligation has "
                f"discharged - issuing one earlier is authority bypass by construction."
            )

    def check_against(
        self,
        action: Action,
        *,
        now: datetime,
        current_policy_version: str | None = None,
        context_hash: Hash | None = None,
    ) -> GrantCheck:
        """Check this grant against the action actually being executed.

        ``now`` is passed in rather than read: the kernel has no ambient clock, so
        this is a pure function of its arguments and can be replayed exactly.

        **This does not check nonce reuse.** Single-use redemption requires an atomic
        compare-and-set against a store, which is an L1 concern. A caller that stops
        here has bound the action but not defended against replay.
        """
        rejections: list[GrantRejection] = []

        # Constant-time throughout. The action hash is public and the timing is
        # near-irrelevant for it; the convention matters because the nonce beside it is
        # the single-use value that authorises an effect, and a mixed convention is how
        # the wrong one gets copied into the next check.
        if not Secrets.equal(str(action.action_hash()), str(self.action_hash)):
            rejections.append(GrantRejection.ACTION_MISMATCH)
        if action.actor != self.actor:
            rejections.append(GrantRejection.ACTOR_MISMATCH)
        if action.tenant != self.tenant:
            rejections.append(GrantRejection.TENANT_MISMATCH)
        if now < self.issued_at:
            rejections.append(GrantRejection.NOT_YET_VALID)
        if now >= self.expires_at:
            rejections.append(GrantRejection.EXPIRED)
        if self.revoked:
            rejections.append(GrantRejection.REVOKED)
        if context_hash is not None and not Secrets.equal(
            str(context_hash), str(self.context_hash)
        ):
            # Recorded is not enforced. Without this a grant could be redeemed against
            # a re-captured context whose identity or policy had since weakened — the
            # obligations discharged against one snapshot, the effect landing under
            # another.
            rejections.append(GrantRejection.POLICY_SUPERSEDED)
        if current_policy_version is not None and current_policy_version != self.policy_version:
            rejections.append(GrantRejection.POLICY_SUPERSEDED)

        return GrantCheck(rejections=tuple(rejections))

    def content_hash(self) -> Hash:
        """The content address of this grant, for the audit record."""
        return Hash(
            Canonical.digest(
                {
                    "grant_id": self.grant_id,
                    "action_hash": self.action_hash,
                    "actor": self.actor,
                    "tenant": self.tenant,
                    "tool": self.tool,
                    "nonce": self.nonce,
                    "issued_at": self.issued_at,
                    "expires_at": self.expires_at,
                    "policy_version": self.policy_version,
                    "profile_version": self.profile_version,
                    "context_hash": self.context_hash,
                    "obligations": [
                        {"name": o.name, "discharge": o.discharge} for o in self.obligations
                    ],
                    "approvals": [
                        {
                            "approval_id": a.approval_id,
                            "approver": a.approver,
                            "role": a.role,
                            "approved": a.approved,
                            "decided_at": a.decided_at,
                        }
                        for a in self.approvals
                    ],
                    "idempotency_key": self.idempotency_key,
                }
            )
        )
