"""Valid-by-construction kernel values, for tests and fixtures.

The kernel's dataclasses refuse a great many things, and every refusal is earned:

.. code-block:: text

    a COMMITTED effect must carry an external reference
    a COMMITTED effect must reference the grant that authorised it
    an UNKNOWN effect must record when it was submitted
    UNKNOWN and INCOMPLETE are reachable only after an effect was attempted
    a REFUSE verdict must carry a typed Refusal
    an attestation's run id must match the context it carries

Each of those exists because the absence it forbids produced a real defect. None of them
should be relaxed. But their combined effect is that **assembling a valid ``Attestation``
by hand takes six tries**, and that is not a hypothetical: writing the observability
tests for this package hit four of them in a row, in four consecutive edits, and each
time the honest fix was to correct the fixture rather than the kernel.

That is a bad experience to ship. Every adopter writing a conformance suite, a red-team
case or a regression test meets the same wall, and the failure mode is not that they give
up — it is that they reach for the shape that *does* construct. A test built around
``verdict=ALLOW`` with no effects, because that one worked first time, is a test of the
easy path, and the states this framework exists to represent honestly are all on the hard
one.

.. rubric:: What these do

Supply the field the invariant requires, derived from what you asked for:

.. code-block:: python

    Build.attestation(verdict=Verdict.UNKNOWN)   # gets an UNKNOWN effect, submitted
    Build.effect(EffectState.COMMITTED)          # gets a grant id and a reference
    Build.attestation(run_id="r7")               # context.run_id is r7 too

.. rubric:: What they deliberately do not do

They do not help you build an **invalid** value. A test asserting that the kernel refuses
something should construct that thing directly, so the refusal being asserted is visible
in the test rather than buried in a builder flag. These exist to make the *valid* case
cheap, which is the case that was expensive.

They are also not a fixture *framework*: no fixtures, no plugins, no autouse anything.
Static methods returning values, so a caller composes them with whatever they already
use.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar, Final

from attest.kernel.actions import Action
from attest.kernel.attestation import Attestation, CostRecord, EffectRecord
from attest.kernel.audit import AuditEvent, EventType, RunSeal
from attest.kernel.authority import (
    MAX_GRANT_TTL,
    ApprovalRecord,
    AuthorizationGrant,
)
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import EffectState, IdempotencyMode
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKinds,
    SourceRef,
    SourceType,
)
from attest.kernel.identifiers import (
    ActorId,
    ApprovalId,
    EvidenceId,
    GrantId,
    Hash,
    Nonce,
    RunId,
    TenantId,
)
from attest.kernel.verdicts import POST_EFFECT_VERDICTS, Refusal, RefusalReason, Verdict
from attest.kernel.warrants import (
    Finding,
    WarrantKinds,
    WarrantReport,
    WarrantStatus,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from attest.kernel.warrants import Severity, WarrantKind

__all__ = ["Build"]

AT: Final = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
"""The instant every value is dated at, unless you say otherwise.

Fixed rather than ``now()``. A fixture dated "now" makes a test that passes or fails
depending on when it ran, which is the least useful kind of flake — and this package
bans ambient time in its own source for the same reason.
"""


class Build:
    """Kernel values that satisfy their invariants without being told to.

    Every method takes overrides. What they add is the field the *kernel* would have
    demanded, worked out from what you asked for — so a caller can say
    ``Build.attestation(verdict=Verdict.UNKNOWN)`` and get a record that is actually
    about an unknown effect, rather than an ``AttestationError`` and a detour.
    """

    ACTOR: ClassVar[ActorId] = ActorId("alice")
    TENANT: ClassVar[TenantId] = TenantId("acme")
    PROFILE: ClassVar[str] = "generic"

    # ── Identity and context ─────────────────────────────────────────────────

    @staticmethod
    def binding(tenant: TenantId | None = None, **overrides: Any) -> TenantBinding:
        fields: dict[str, Any] = {
            "tenant": tenant or Build.TENANT,
            "profile": ProfileRef(name=Build.PROFILE, version="1.0.0"),
            "config_hash": Hash("c" * 64),
        }
        fields.update(overrides)
        return TenantBinding(**fields)

    @staticmethod
    def context(
        run_id: str = "run_1",
        *,
        at: datetime = AT,
        tenant: TenantId | None = None,
        actor: ActorId | None = None,
        capabilities: frozenset[str] = frozenset(),
        **overrides: Any,
    ) -> ExecutionContext:
        scope = tenant or Build.TENANT
        fields: dict[str, Any] = {
            "run_id": RunId(run_id),
            "captured_at": at,
            "identity": IdentitySnapshot(
                actor=actor or Build.ACTOR, tenant=scope, capabilities=capabilities
            ),
            "binding": Build.binding(scope),
            "framework_version": "0.1.0",
            "policy_version": "2026.07",
        }
        fields.update(overrides)
        return ExecutionContext(**fields)

    # ── Actions, grants, effects ─────────────────────────────────────────────

    @staticmethod
    def action(**overrides: Any) -> Action:
        fields: dict[str, Any] = {
            "tool": "transfer_funds",
            "actor": Build.ACTOR,
            "tenant": Build.TENANT,
            "arguments": {"amount": "500000.00", "to": "acct-9"},
            "capability": "transfer",
            "idempotency": IdempotencyMode.KEYED,
        }
        fields.update(overrides)
        return Action(**fields)

    @staticmethod
    def grant(action: Action | None = None, **overrides: Any) -> AuthorizationGrant:
        subject = action or Build.action()
        fields: dict[str, Any] = {
            "grant_id": GrantId("grt_1"),
            "action_hash": subject.action_hash(),
            "actor": subject.actor,
            "tenant": subject.tenant,
            "tool": subject.tool,
            "nonce": Nonce("nonce_1"),
            "issued_at": AT,
            # The ceiling, not an hour. `MAX_GRANT_TTL` is fifteen minutes — "the grant
            # exists to shrink the window between the last check and the effect; a
            # long-lived one does not" — and a builder that picked a round number would
            # hand every caller a ValueError. This was the fifth invariant met while
            # writing this module, which is the argument for the module.
            "expires_at": AT + MAX_GRANT_TTL,
            "policy_version": "2026.07",
            "profile_version": "1.0.0",
            "context_hash": Hash("0" * 64),
        }
        fields.update(overrides)
        return AuthorizationGrant(**fields)

    @staticmethod
    def effect(
        state: EffectState = EffectState.COMMITTED,
        *,
        action: Action | None = None,
        at: datetime = AT,
        **overrides: Any,
    ) -> EffectRecord:
        """An effect record that satisfies the three rules its state implies.

        - ``COMMITTED`` gets an ``external_reference``: *"recording a commit we cannot
          point at is how an audit chain comes to disagree with the world."*
        - anything past ``PROPOSED`` gets a ``grant_id``: *"an effect without one is
          unauthorised by definition."*
        - ``UNKNOWN`` and ``SUBMITTED`` get a ``submitted_at``: without it, ``UNKNOWN``
          is indistinguishable from "never attempted" and cannot be reconciled.

        Derived from ``state`` rather than defaulted on every record, so a
        ``PROPOSED`` effect does not quietly carry a grant it never had.
        """
        fields: dict[str, Any] = {"action": action or Build.action(), "state": state}
        if state is not EffectState.PROPOSED:
            fields["grant_id"] = GrantId("grt_1")
        if state is EffectState.COMMITTED:
            fields["external_reference"] = "upstream-ref-1"
        if state in (EffectState.UNKNOWN, EffectState.SUBMITTED, EffectState.COMMITTED):
            fields["submitted_at"] = at
        fields.update(overrides)
        return EffectRecord(**fields)

    # ── Evidence and warrants ────────────────────────────────────────────────

    @staticmethod
    def evidence(
        value: str = "the balance is 500000",
        *,
        at: datetime = AT,
        authority: AuthorityLevel = AuthorityLevel.AUTHORITATIVE,
        tenant: TenantId | None = None,
        **overrides: Any,
    ) -> Evidence:
        fields: dict[str, Any] = {
            "evidence_id": EvidenceId("ev_1"),
            "kind": EvidenceKinds.OBSERVATION,
            "source": SourceRef(
                source_id="ledger-1",
                source_type=SourceType.LEDGER,
                authority=authority,
                version="1",
                retrieved_at=at,
                integrity_hash=Hash("b" * 64),
                tenant=tenant,
            ),
            "value": value,
        }
        fields.update(overrides)
        return Evidence(**fields)

    @staticmethod
    def warrant(
        kind: WarrantKind = WarrantKinds.EPISTEMIC,
        *,
        satisfied: bool = True,
        findings: Sequence[tuple[str, Severity]] = (),
        **overrides: Any,
    ) -> WarrantReport:
        """A report. ``satisfied=False`` keeps ``status=EVALUATED``, which is the point.

        An unsatisfied warrant and an *unevaluated* one are different things — the
        kernel refuses ``satisfied=True`` on anything but ``EVALUATED`` for exactly that
        reason — so this builder never conflates them. Pass ``status`` explicitly for the
        pending case.
        """
        fields: dict[str, Any] = {
            "kind": kind,
            "status": WarrantStatus.EVALUATED,
            "satisfied": satisfied,
            "findings": tuple(
                Finding(code=code, message=code, severity=severity) for code, severity in findings
            ),
        }
        fields.update(overrides)
        return WarrantReport(**fields)

    @staticmethod
    def approval(
        approver: str = "bob", *, action: Action | None = None, **overrides: Any
    ) -> ApprovalRecord:
        fields: dict[str, Any] = {
            "approval_id": ApprovalId(f"apr_{approver}"),
            "approver": ActorId(approver),
            "role": "claims_director",
            "approved": True,
            "decided_at": AT,
            "action_hash": (action or Build.action()).action_hash(),
        }
        fields.update(overrides)
        return ApprovalRecord(**fields)

    # ── The whole record ─────────────────────────────────────────────────────

    @staticmethod
    def attestation(
        run_id: str = "run_1",
        *,
        verdict: Verdict = Verdict.ALLOW,
        at: datetime = AT,
        tenant: TenantId | None = None,
        effects: tuple[EffectRecord, ...] | None = None,
        warrants: Mapping[WarrantKind, WarrantReport] | None = None,
        sealed: bool = True,
        **overrides: Any,
    ) -> Attestation:
        """A complete, valid attestation for ``verdict``.

        Three things are supplied that a hand-written one keeps forgetting, and each was
        an ``AttestationError`` in a real editing session:

        - **the context names this run.** Passing ``run_id`` alone used to leave the
          context on ``run_1``, and the kernel refuses a record that "would describe a
          different run from the one it claims";
        - **a post-effect verdict gets an effect.** ``UNKNOWN`` and ``INCOMPLETE`` are
          reachable only after an attempt, so asking for one without effects is a
          contradiction — this resolves it rather than raising;
        - **a REFUSE gets a typed Refusal.** Refusal rates are monitored and refusals
          trigger downstream obligations; an unexplained one cannot be aggregated.

        ``sealed`` produces a real :class:`~attest.kernel.audit.RunSeal` rather than a
        truthy placeholder — a builder whose ``sealed=True`` left ``seal=None`` would
        make every fixture unsealed, and any test looking for a seal gap would fire on
        all of them.
        """
        if effects is None:
            effects = (
                (Build.effect(EffectState.UNKNOWN, at=at),)
                if verdict in POST_EFFECT_VERDICTS
                else ()
            )

        fields: dict[str, Any] = {
            "run_id": RunId(run_id),
            "verdict": verdict,
            "context": Build.context(run_id, at=at, tenant=tenant),
            "created_at": at,
            "answer": "the balance is 500000",
            "warrants": dict(warrants)
            if warrants is not None
            else {WarrantKinds.EPISTEMIC: Build.warrant()},
            "effects": effects,
            "cost": CostRecord(amount="0.42", currency="GBP"),
        }
        if verdict is Verdict.REFUSE:
            fields["refusal"] = Refusal(
                reason=RefusalReason("unsafe_action"),
                detail="refused by a fixture; override `refusal` to say why",
            )
        if sealed:
            fields["seal"] = Build.seal(run_id, at=at)
        fields.update(overrides)

        # After the overrides, so a caller passing `context=` is left alone but one
        # passing only `run_id=` still gets a coherent record.
        attestation = Attestation(**fields)
        if attestation.context.run_id != attestation.run_id:
            attestation = replace(
                attestation, context=replace(attestation.context, run_id=attestation.run_id)
            )
        return attestation

    @staticmethod
    def seal(
        run_id: str = "run_1", *, at: datetime = AT, events: int = 3, **overrides: Any
    ) -> RunSeal:
        fields: dict[str, Any] = {
            "run_id": RunId(run_id),
            "event_count": events,
            "first_sequence": 1,
            "last_sequence": events,
            "head_hash": Hash("d" * 64),
            "attestation_hash": Hash("e" * 64),
            "sealed_at": at,
        }
        fields.update(overrides)
        return RunSeal(**fields)

    @staticmethod
    def event(
        event_type: str = EventType.RUN_DISPATCHED.value,
        *,
        run_id: str = "run_1",
        at: datetime = AT,
        **overrides: Any,
    ) -> AuditEvent:
        fields: dict[str, Any] = {
            "run_id": RunId(run_id),
            "event_type": event_type,
            "occurred_at": at,
            "payload": {"k": "v"},
        }
        fields.update(overrides)
        return AuditEvent(**fields)
