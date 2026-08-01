"""The run entry point — one proposal in, one sealed attestation out.

Everything below this module was composable and nothing composed it. That is a real
gap, not a stylistic one: without an entry point, "the kernel decides whether an effect
may execute" is a claim about code a host has to assemble correctly, and each host
would assemble it slightly differently. This is the assembly, once.

.. code-block:: text

    RunRequest ──▶ capture context
                     │
                     ├── guards        inbound text, evidence tenancy   -> boundary
                     ├── evidence      verify each item                 -> epistemic
                     ├── coverage      what was searched, what was not  -> completeness
                     ├── obligations   profile's gates for this action  -> authority
                     │        │
                     │        ├── satisfied  -> grant -> ExecutionBoundary -> effect
                     │        ├── pending    -> HOLD_FOR_APPROVAL, no effect
                     │        └── failed     -> REFUSE, no effect
                     │
                     ├── seal          dense positions, chain, signature -> provenance
                     └── Attestation

.. rubric:: The ordering is the guarantee

Warrants are evaluated **before** the grant is issued, and the grant is issued before
the executor is reached. A pipeline that ran the effect and then assembled warrants
would produce an equally handsome record of an unauthorised action.

.. rubric:: What this does not decide

It does not decide whether the answer is *correct*. It decides whether the run was
warranted, and records what it was warranted by. See
``docs/concepts/assurance-boundaries.md``.

.. rubric:: A held run does not block

``HOLD_FOR_APPROVAL`` returns an attestation immediately, with the effect recorded as
``PROPOSED`` and the pending obligations named. The caller enqueues a resumption when
approval arrives. A worker pool held open by pending approvals is an outage waiting for
a busy Monday.
"""

from __future__ import annotations

import hashlib
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from attest.capabilities.audit import ChainSealer, EventRecorder
from attest.capabilities.authority import AuthorityEngine, ObligationBinder
from attest.capabilities.evidence import EvidenceEngine
from attest.capabilities.execution import ExecutionBoundary, ExecutionRefused, UpstreamTimeout
from attest.capabilities.guards import (
    GuardOutcome,
    GuardSuite,
    InjectionGuard,
    RedactionVault,
    TenancyGuard,
)
from attest.capabilities.profile import GenericProfile
from attest.capabilities.retrieval import RetrievalEngine
from attest.kernel.attestation import Attestation, CostRecord, EffectRecord
from attest.kernel.audit import EventType
from attest.kernel.authority import MAX_GRANT_TTL, AuthorizationGrant, Discharge
from attest.kernel.canonical import Canonical
from attest.kernel.context import ExecutionContext, IdentitySnapshot
from attest.kernel.effects import WORLD_REACHING_EFFECT_STATES, EffectState
from attest.kernel.errors import ConfigurationError
from attest.kernel.identifiers import GrantId, Nonces, RunId, RunIds
from attest.kernel.ports import AutonomyMode
from attest.kernel.verdicts import Refusal, RefusalReason, Verdict
from attest.kernel.warrants import (
    NON_DOWNGRADEABLE,
    Finding,
    Severity,
    WarrantKinds,
    WarrantPolicy,
    WarrantReport,
    WarrantStatus,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from attest.capabilities.authority import BoundObligations, DischargeResult
    from attest.capabilities.completeness import CoverageReport
    from attest.capabilities.execution import Executor
    from attest.capabilities.gateway import ModelCallLog
    from attest.capabilities.profile import DomainProfile
    from attest.kernel.actions import Action
    from attest.kernel.audit import AuditEvent, RunSeal
    from attest.kernel.authority import ApprovalRecord
    from attest.kernel.context import ModelRef, TenantBinding
    from attest.kernel.evidence import Evidence
    from attest.kernel.identifiers import ActorId, TenantId
    from attest.kernel.ports import (
        ApprovalStore,
        AuditSink,
        AutonomyStore,
        BudgetStore,
        Clock,
        IdempotencyStore,
        IdGenerator,
        NonceStore,
        Retriever,
        RunStore,
        SealRegistry,
        Signer,
    )
    from attest.kernel.warrants import WarrantKind
    from attest.runtime.agents import AgentSpec

__all__ = ["RunEngine", "RunRequest", "RunResult", "VerdictResolver"]


@dataclass(frozen=True, slots=True)
class RunRequest:
    """What a caller proposes. Values only — no callables, nothing live.

    An agent, a rules engine, a scheduled job and a human all propose through this
    same shape, which is what lets one control plane govern all four.
    """

    actor: ActorId
    tenant: TenantId
    answer: str = ""
    """The proposed output. Empty for a run that only performs an effect."""

    capabilities: frozenset[str] = frozenset()
    """What the actor could do **at dispatch**, resolved by the host's identity system.

    Snapshotted rather than queried live, so verification is reproducible. Empty is
    the honest default and it is deliberately restrictive: a capability gate cannot
    discharge against an unwired identity, so a host that has not connected one gets
    held runs rather than unauthorised effects.
    """

    roles: frozenset[str] = frozenset()

    structured: Mapping[str, Any] | None = None
    evidence: tuple[Evidence, ...] = ()
    action: Action | None = None
    """The effect being proposed, if any. ``None`` for an advisory run."""

    inbound_text: tuple[str, ...] = ()
    """Untrusted text to screen — the user's message, a retrieved document, a memory.

    Screened rather than trusted: memory is input the system wrote to itself, and text
    injected in one run is recalled as context in the next.
    """

    coverage: CoverageReport | None = None

    query: str = ""
    """A retrieval query. Run through the ``Retriever`` port when the engine has one,
    so what was rejected is recorded rather than dropped."""

    approval_summary: str = ""
    """What an approver is shown when the run holds.

    An approval screen that names only the tool is asking somebody to authorise an
    amount they were never shown. Empty falls back to the tool name, which is the
    honest minimum rather than a good default.
    """

    redactions: Mapping[str, str] = field(default_factory=dict)
    """``label -> value`` to withhold from anything that leaves the boundary.

    Redacted before screening, restored into the answer. The values never enter an
    audit event: the counts are recorded, the secrets are not.
    """

    model_calls: ModelCallLog | None = None
    """What the run spent at the gateway, from
    :meth:`~attest.capabilities.gateway.ModelSession.log`.

    Supply this and the engine **derives** ``model`` and ``cost`` from it rather than
    believing what it was told, and replays the model events into the run's chain. The
    log is bound to the context hash, so one assembled by hand or lifted from another
    run is refused.
    """

    model: ModelRef | None = None
    """Only for a run that did not go through the gateway. Conflicts with
    ``model_calls``, and supplying both is refused rather than silently preferred."""

    cost: CostRecord = field(default_factory=CostRecord)
    """Same: derived from ``model_calls`` when one is present."""
    prompt_hashes: Mapping[str, str] = field(default_factory=dict)
    idempotency_key: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    agent: AgentSpec | None = None
    """The agent this run is proposing as, where one exists.

    Absent, an ``AgentSpec`` could not influence a run at all: the engine never received
    one, so ``warrant_overrides`` and ``evidence_required`` were fields a caller filled
    in that were carried, serialised and consulted by nothing. The direction of the harm
    is what makes it worth a field here rather than a note - an agent declaring itself
    STRICTER than its deployment silently got the deployment's looser setting, and from
    the caller's side that is indistinguishable from a setting that was already the
    default.

    ``None`` for a rules engine, a scheduled job or a human proposing through the same
    shape, which is the ordinary case and stays exactly as it was.
    """


@dataclass(frozen=True, slots=True)
class RunResult:
    """The attestation, plus the events that were sealed into it.

    The events come back because a host that wants to persist them itself — the common
    case for an existing audit table — should not have to reach into the engine for
    them.
    """

    attestation: Attestation
    events: tuple[AuditEvent, ...]

    @property
    def verdict(self) -> Verdict:
        return self.attestation.verdict


class VerdictResolver:
    """Turns warrant reports and effect states into one of the six outcomes.

    A class rather than a chain of ``if`` statements at the call site, because this is
    the mapping every host would otherwise re-derive — and the two most dangerous
    mistakes in it are silent. Coercing ``UNKNOWN`` to failure claims a payment did not
    happen when it may have; treating a WARN as an ALLOW drops the qualification a
    reader needed.
    """

    def resolve(
        self,
        *,
        reports: Mapping[WarrantKind, WarrantReport],
        policies: Mapping[WarrantKind, WarrantPolicy],
        effects: Sequence[EffectRecord],
    ) -> tuple[Verdict, Refusal | None]:
        # Effect states win. A committed-but-unconfirmed transfer is the state the
        # whole framework exists to represent honestly, and no warrant outranks it.
        post_effect = self._from_effects(effects)
        if post_effect is not None:
            return post_effect, None

        floored = self._non_downgradeable(reports)
        if floored is not None:
            # Before everything below it, including the pending-approval path. These are
            # the findings docs/ says no profile can soften, and a tenancy crossing is
            # not a thing an approver can authorise — offering it to a human as a hold
            # would present a data leak as a decision somebody is allowed to make.
            #
            # Still after the effect states: if a payment already left, "nothing
            # happened" is not an available answer whatever else went wrong.
            kind, finding = floored
            return Verdict.REFUSE, Refusal(
                reason=RefusalReason(finding.code),
                detail=(
                    f"{finding.code}: {finding.message}. This is not downgradeable by "
                    f"profile configuration — see attest.kernel.warrants."
                    f"NON_DOWNGRADEABLE — so the {kind!r} policy was not consulted."
                ),
                warrant=kind,
            )

        if self._awaiting_a_human(reports):
            # Before the blocking check, and this is load-bearing. An obligation that is
            # PENDING is waiting on a person; one that is FAILED cannot be met. Under a
            # BLOCK policy both made the warrant unsatisfied, so a run awaiting dual
            # control came back REFUSE — which tells the caller the decision was already
            # made and forecloses the approval the run was asking for. The doctrine at
            # the top of this module says pending produces HOLD_FOR_APPROVAL; this is
            # where it becomes true.
            return Verdict.HOLD_FOR_APPROVAL, None

        blocking = self._unsatisfied_at(reports, policies, WarrantPolicy.BLOCK)
        if blocking and self._reached_the_world(effects):
            # A warrant failed, and something already happened. REFUSE would say
            # nothing did. The provenance warrant is the live case: it can only be
            # evaluated after the chain is sealed, which is after the effect.
            kind = sorted(blocking)[0]
            return Verdict.INCOMPLETE, Refusal(
                reason=self._reason_for(kind),
                detail=(
                    f"warrant {kind!r} was not satisfied, but effects had already "
                    f"reached the outside world, so this run is INCOMPLETE rather than "
                    f"refused. {self._explain(reports[kind])}"
                ),
                warrant=kind,
            )
        if blocking:
            kind = sorted(blocking)[0]
            return Verdict.REFUSE, Refusal(
                reason=self._reason_for(kind),
                detail=(
                    f"warrant {kind!r} was not satisfied and the profile blocks on it. "
                    f"{self._explain(reports[kind])}"
                ),
                warrant=kind,
            )

        if self._unsatisfied_at(reports, policies, WarrantPolicy.HOLD):
            return Verdict.HOLD_FOR_APPROVAL, None

        if any(not report.is_final for report in reports.values()):
            # Deferred assurance is not an ALLOW: nothing has been established yet.
            return Verdict.HOLD_FOR_APPROVAL, None

        # Last, and the order is the whole of it. A warrant-blocked run keeps that
        # warrant's reason, which is more specific and more contestable. A *held* run's
        # effect is PROPOSED because it is waiting, not because it was stopped — calling
        # that a refusal would tell an approver the decision was already made. What
        # lands here is the run whose claim was fine, whose obligations discharged, and
        # whose effect was stopped anyway: an expired grant, a revoked nonce, a refusal
        # from the upstream. Falling through reported ALLOW_WITH_WARNINGS for a payment
        # that never happened.
        stopped = self._stopped_at_the_boundary(effects)
        if stopped is not None:
            return Verdict.REFUSE, stopped

        if self._unsatisfied_at(reports, policies, WarrantPolicy.WARN) or self._has_findings(
            reports
        ):
            return Verdict.ALLOW_WITH_WARNINGS, None
        return Verdict.ALLOW, None

    def _reached_the_world(self, effects: Sequence[EffectRecord]) -> bool:
        """Whether "nothing happened" is still an available answer."""
        return any(record.state in WORLD_REACHING_EFFECT_STATES for record in effects)

    def _from_effects(self, effects: Sequence[EffectRecord]) -> Verdict | None:
        """``UNKNOWN`` and ``INCOMPLETE`` are reachable only after an attempt."""
        if any(record.state is EffectState.UNKNOWN for record in effects):
            return Verdict.UNKNOWN
        states = {record.state for record in effects}
        if EffectState.COMMITTED in states and states & {
            EffectState.FAILED,
            EffectState.REFUSED,
        }:
            # Part of the world moved and part did not. Reporting either as the whole
            # answer would be false.
            return Verdict.INCOMPLETE
        return None

    def _stopped_at_the_boundary(self, effects: Sequence[EffectRecord]) -> Refusal | None:
        """A refusal for a run whose effects were all stopped before reaching the world.

        ``None`` when there were no effects at all — an advisory run that proposes
        nothing is not a refusal, it simply had nothing to do.
        """
        if not effects or any(record.state not in self.STOPPED for record in effects):
            return None
        blocked = [record for record in effects if record.state is EffectState.REFUSED]
        first = blocked[0] if blocked else effects[0]
        return Refusal(
            reason=RefusalReason("effect_refused"),
            detail=(
                first.detail
                or f"the effect on {first.action.tool!r} did not happen; it was "
                f"{first.state.value} at the execution boundary"
            ),
        )

    STOPPED: ClassVar[frozenset[EffectState]] = frozenset(
        {EffectState.REFUSED, EffectState.FAILED, EffectState.PROPOSED}
    )
    """States in which nothing reached the outside world, so REFUSE is truthful.

    Deliberately not the complement of ``WORLD_REACHING_EFFECT_STATES``: this is the
    positive list, so a state added later defaults to *not* stopped and gets looked at
    rather than silently reported as "nothing happened".
    """

    def _non_downgradeable(
        self, reports: Mapping[WarrantKind, WarrantReport]
    ) -> tuple[WarrantKind, Finding] | None:
        """The first floored finding on an unsatisfied warrant, if there is one.

        Sorted, so a run carrying two of them refuses for the same reason every time —
        a verdict that depends on dict ordering is not reproducible, and reproducibility
        is what an attestation is for.

        Only on an *unsatisfied* report: a satisfied warrant that happens to carry an
        informational finding with a floored code has not failed at anything.
        """
        for kind in sorted(reports):
            report = reports[kind]
            if report.is_satisfied():
                continue
            for finding in report.findings:
                if finding.code in NON_DOWNGRADEABLE:
                    return kind, finding
        return None

    def _awaiting_a_human(self, reports: Mapping[WarrantKind, WarrantReport]) -> bool:
        """Something is outstanding and nothing has definitively failed.

        A failure alongside a pending obligation is decisive — the run cannot proceed
        however the human answers — so a failure wins and the verdict is a refusal that
        names it.
        """
        codes = {finding.code for report in reports.values() for finding in report.findings}
        return Discharge.PENDING.value in codes and Discharge.FAILED.value not in codes

    def _unsatisfied_at(
        self,
        reports: Mapping[WarrantKind, WarrantReport],
        policies: Mapping[WarrantKind, WarrantPolicy],
        policy: WarrantPolicy,
    ) -> list[WarrantKind]:
        return [
            kind
            for kind, report in reports.items()
            if policies.get(kind, WarrantPolicy.BLOCK) is policy and not report.is_satisfied()
        ]

    def _has_findings(self, reports: Mapping[WarrantKind, WarrantReport]) -> bool:
        return any(
            finding.severity in (Severity.WARNING, Severity.ERROR)
            for report in reports.values()
            for finding in report.findings
        )

    def _explain(self, report: WarrantReport) -> str:
        if report.status is WarrantStatus.UNEVALUATABLE:
            return "The check could not run, which is an unsatisfied warrant, not a pass."
        if not report.findings:
            return "No findings were recorded."
        return "; ".join(f"{f.code}: {f.message}" for f in report.findings)

    #: Which typed refusal reason a blocked warrant produces. A refusal nobody can
    #: aggregate or contest is one nobody will act on, so the mapping is explicit.
    REASONS: ClassVar[Mapping[WarrantKind, RefusalReason]] = {
        WarrantKinds.EPISTEMIC: RefusalReason("unsupported_claim"),
        WarrantKinds.AUTHORITY: RefusalReason("insufficient_authority"),
        WarrantKinds.BOUNDARY: RefusalReason("injection_detected"),
        WarrantKinds.COMPLETENESS: RefusalReason("incomplete_coverage"),
        WarrantKinds.PROVENANCE: RefusalReason("unsupported_claim"),
    }

    def _reason_for(self, kind: WarrantKind) -> RefusalReason:
        return self.REASONS.get(kind, RefusalReason("out_of_scope"))


class RunEngine:
    """Composes the capability layer into one governed run.

    Collaborators are injected rather than constructed, so a host swaps its own store,
    clock or profile without subclassing anything — and so a test can drive the whole
    pipeline deterministically.
    """

    __slots__ = (
        "_approval_ttl",
        "_approvals",
        "_audit",
        "_authority",
        "_autonomy",
        "_binder",
        "_boundary",
        "_clock",
        "_evidence",
        "_framework_version",
        "_guards",
        "_ids",
        "_nonces",
        "_policy_version",
        "_profile",
        "_resolver",
        "_retrieval",
        "_runs",
        "_sealer",
        "_seals",
    )

    def __init__(
        self,
        *,
        clock: Clock,
        ids: IdGenerator,
        audit: AuditSink,
        nonces: NonceStore,
        profile: DomainProfile | None = None,
        runs: RunStore | None = None,
        signer: Signer | None = None,
        guards: GuardSuite | None = None,
        evidence: EvidenceEngine | None = None,
        authority: AuthorityEngine | None = None,
        resolver: VerdictResolver | None = None,
        retriever: Retriever | None = None,
        budget: BudgetStore | None = None,
        approvals: ApprovalStore | None = None,
        autonomy: AutonomyStore | None = None,
        seals: SealRegistry | None = None,
        approval_ttl: timedelta = timedelta(days=7),
        idempotency: IdempotencyStore | None = None,
        brand: str = "",
        framework_version: str = "",
        policy_version: str = "",
    ) -> None:
        if guards is None and not brand:
            raise ConfigurationError(
                "RunEngine needs either a configured GuardSuite or a brand to build "
                "one from. The injection detector interpolates the brand, and an empty "
                "one silently weakens it — which is the failure that made two copies "
                "of a 319-line detector unshareable."
            )
        self._clock = clock
        self._ids = ids
        self._audit = audit
        self._nonces = nonces
        self._runs = runs
        self._profile = profile or GenericProfile()
        self._guards = guards or GuardSuite(injection=InjectionGuard(brand), tenancy=TenancyGuard())
        # The profile's floor, not a fixed default. A domain that raises its
        # requirement to AUTHORITATIVE for sanctions determinations used to get
        # ADVISORY, because nothing consulted the profile on the run path — the
        # conformance kit tested required_authority and the engine never called it.
        self._evidence = evidence or EvidenceEngine(authority_for=self._profile.required_authority)
        self._authority = authority or AuthorityEngine()
        self._sealer = ChainSealer(signer=signer)
        self._boundary = ExecutionBoundary(nonces=nonces, audit=audit, idempotency=idempotency)
        self._resolver = resolver or VerdictResolver()
        self._binder = ObligationBinder(budget=budget)
        self._approvals = approvals
        self._autonomy = autonomy
        self._seals = seals
        self._approval_ttl = approval_ttl
        self._retrieval = (
            None
            if retriever is None
            else RetrievalEngine(retriever, evidence=self._evidence, tenancy=TenancyGuard())
        )
        self._framework_version = framework_version or self._version()
        self._policy_version = policy_version or self._profile.version

    @staticmethod
    def _version() -> str:
        from attest.version import __version__

        return __version__

    # ── The entry point ──────────────────────────────────────────────────────

    @property
    def clock(self) -> Clock:
        """The engine's clock. Exposed so a dispatcher stamps envelopes with the same one.

        Two clocks means a submitted-at that disagrees with the run's captured-at, and
        a queue wait that reads as negative when the two drift.
        """
        return self._clock

    def new_run_id(self) -> RunId:
        """Mint a run id before dispatch.

        The gateway session is opened against a context, and the engine captures its
        own inside :meth:`execute` — so without this there is no way to make the two
        agree, and a model call log could never be bound to the run that made it.
        """
        return RunId(self._ids.new_id("run"))

    def capture(
        self, request: RunRequest, *, binding: TenantBinding, run_id: RunId
    ) -> ExecutionContext:
        """The context a caller should open its gateway session against.

        Public because the alternative is a binding nothing can satisfy: the caller
        needs the engine's view of the run *before* it makes the model calls that the
        run will be attested for.
        """
        return self._capture(request, binding=binding, run_id=run_id, at=self._clock.now())

    def execute(
        self,
        request: RunRequest,
        *,
        binding: TenantBinding,
        executor: Executor | None = None,
        run_id: RunId | None = None,
        supersedes: RunId | None = None,
        context: ExecutionContext | None = None,
    ) -> RunResult:
        """Run one proposal to a sealed attestation.

        ``executor`` is required only when ``request.action`` is set. Omitting it for
        an advisory run is normal; omitting it for a run that proposes an effect is a
        configuration error rather than a silently skipped effect.
        """
        if request.action is not None and executor is None:
            raise ConfigurationError(
                "the request proposes an action but no executor was supplied. "
                "Refusing rather than skipping it: a run that quietly performs no "
                "effect while reporting success is the worst available outcome."
            )

        self._assert_one_source_of_cost(request)

        now = self._clock.now()
        identifier = run_id or RunId(self._ids.new_id("run"))
        recorder = EventRecorder(run_id=identifier, clock=self._clock, sink=self._audit)
        try:
            return self._run(
                request,
                binding=binding,
                executor=executor,
                recorder=recorder,
                run_id=identifier,
                at=now,
                supersedes=supersedes,
                captured=context,
            )
        except Exception as exc:
            # Recorded before it propagates. A run that fell over and left no trace is
            # indistinguishable from one that never started, and the two need very
            # different responses. The exception still reaches the host — it decides
            # whether the request fails — but the chain says what happened first.
            recorder.record(
                EventType.RUN_FAILED.value,
                {"error": type(exc).__name__, "detail": str(exc)},
                at=now,
            )
            self._persist_failure(recorder)
            raise

    def _run(
        self,
        request: RunRequest,
        *,
        binding: TenantBinding,
        executor: Executor | None,
        recorder: EventRecorder,
        run_id: RunId,
        at: datetime,
        supersedes: RunId | None,
        captured: ExecutionContext | None = None,
    ) -> RunResult:
        request, vault = self._redact(request, recorder=recorder)
        # The caller's own context when they had one. A run that made model calls
        # obtained a context from `capture()` and opened the gateway session against
        # it; re-deriving one here would produce a different snapshot — a different
        # captured_at, and a model ref the gateway had not chosen yet — so the log
        # could never be bound to the context it actually ran under, and the binding
        # fell back to a run id the caller supplies to both sides.
        context = captured or self._capture(request, binding=binding, run_id=run_id, at=at)
        recorder.record(
            EventType.RUN_DISPATCHED.value,
            {"actor": str(request.actor), "tenant": str(request.tenant)},
        )
        # Checked against the snapshot the gateway ran under — before the model ref is
        # attached, because at capture time no provider had been chosen.
        self._replay_model_calls(request, context=context, recorder=recorder)
        context = self._with_model(context, request)
        request, context = self._retrieve(
            request, binding=binding, run_id=run_id, recorder=recorder, at=at
        )

        reports = dict(self._assess(request, recorder=recorder, at=at))
        effects, reports = self._authorise_and_execute(
            request,
            context=context,
            recorder=recorder,
            executor=executor,
            reports=reports,
            at=at,
        )

        verdict, refusal = self._resolver.resolve(
            reports=reports,
            policies=self._policies_for(request, reports),
            effects=effects,
        )
        if verdict is Verdict.HOLD_FOR_APPROVAL:
            self._request_approval(request, context=context, recorder=recorder)
        return self._finalise(
            request,
            context=context,
            recorder=recorder,
            reports=reports,
            effects=effects,
            verdict=verdict,
            refusal=refusal,
            at=at,
            supersedes=supersedes,
            vault=vault,
        )

    def _persist_failure(self, recorder: EventRecorder) -> None:
        """Write what the failed run did manage to record.

        Suppressed deliberately, and only here. This runs while an exception is already
        propagating; if the sink is what failed there is nothing to do, and raising a
        second error from the handler would replace the failure worth seeing with the
        failure to write about it. The effect events are already durable regardless —
        the boundary wrote them before the call.
        """
        with suppress(Exception):
            recorder.flush(self._audit)

    # ── Stages ───────────────────────────────────────────────────────────────

    def _redact(
        self, request: RunRequest, *, recorder: EventRecorder
    ) -> tuple[RunRequest, RedactionVault | None]:
        """Withhold declared values from anything that leaves the boundary.

        The vault is built **per run**, never held on the engine. A process-scoped
        vault accumulates raw values for the lifetime of the worker and can substitute
        one run's secrets into another run's text — which is a cross-tenant disclosure
        wearing the costume of a helper.

        The event records how many values were withheld. It never records the values:
        an audit chain that carried the PII it exists to prove was withheld would be
        the disclosure.
        """
        if not request.redactions:
            return request, None
        vault = RedactionVault()
        for label, value in request.redactions.items():
            vault.redact(value, label)
        recorder.record(
            EventType.PII_REDACTED.value,
            {"labels": sorted(request.redactions), "count": len(request.redactions)},
        )
        # Everything that leaves the boundary, not only the inbound message. The answer
        # and the structured payload reach the attestation and the audit chain, and
        # redacting the input while writing the value into the record is not redaction.
        return (
            replace(
                request,
                inbound_text=tuple(vault.apply(text) for text in request.inbound_text),
                answer=vault.apply(request.answer),
                structured=None
                if request.structured is None
                else {
                    key: vault.apply(value) if isinstance(value, str) else value
                    for key, value in request.structured.items()
                },
            ),
            vault,
        )

    def _restore(self, answer: str, vault: RedactionVault | None, recorder: EventRecorder) -> str:
        """Put the real values back on the way out, and record that it happened.

        Delegates to :meth:`RedactionVault.restore` rather than reimplementing it. The
        reimplementation searched for ``f"[{label.upper()}_1]"`` — hardcoding ``_1`` and
        upper-casing the label — while the vault numbers tokens by *position*. So the
        second and every subsequent redaction never restored, a lowercase label never
        restored at all, and the consumer received ``[NI_2]`` where a national insurance
        number belonged. Worse, ``PII_RESTORED`` was recorded whenever *anything*
        changed, so a partial restoration recorded success.

        The vault's own ``restore`` raises on an unmatched token, which is the documented
        behaviour: a token reaching the consumer reads as corruption, so the run fails
        rather than shipping it.

        The vault is per-run and dies with the run. A process-scoped one would let one
        run's values be substituted into another run's text — a cross-run leak wearing a
        privacy control's clothes.
        """
        if vault is None or not len(vault):
            return answer
        restored = vault.restore(answer)
        recorder.record(
            EventType.PII_RESTORED.value,
            {"count": len(vault)},
        )
        return restored

    def _retrieve(
        self,
        request: RunRequest,
        *,
        binding: TenantBinding,
        run_id: RunId,
        recorder: EventRecorder,
        at: datetime,
    ) -> tuple[RunRequest, ExecutionContext]:
        """Gather evidence through the port, recording what was not admitted.

        Evidence that failed verification and was silently dropped would leave an
        attestation whose sources look unanimous — the run would read as better
        supported than it was.
        """
        context = self._capture(request, binding=binding, run_id=run_id, at=at)
        if self._retrieval is None or not request.query:
            return request, context

        outcome = self._retrieval.retrieve(request.query, context=context)
        recorder.record(
            EventType.EVIDENCE_RETRIEVED.value,
            {"query_hash": Canonical.digest(request.query), "retrieved": outcome.retrieved},
        )
        for item in outcome.rejected:
            recorder.record(
                EventType.EVIDENCE_REJECTED.value,
                {
                    "evidence_id": item.evidence_id,
                    "source_id": item.source_id,
                    "outcome": item.outcome.value,
                    "detail": item.detail,
                },
            )
        widened = replace(request, evidence=(*request.evidence, *outcome.admitted))
        return widened, self._capture(widened, binding=binding, run_id=run_id, at=at)

    def _recorded_approvals(self, action: Action) -> tuple[ApprovalRecord, ...]:
        """The decisions a human actually made about **this** action.

        Empty when no store is wired, and that is the fail-safe answer: an ``Approval``
        or ``DualControl`` with no records is PENDING, so the run holds rather than
        proceeding on data the caller supplied. A deployment that wants those
        obligations to discharge has to wire the store that records real decisions.
        """
        if self._approvals is None:
            return ()
        try:
            return tuple(self._approvals.decisions(action.action_hash()))
        except Exception:
            return ()

    def _spend_approvals(
        self, grant: AuthorizationGrant, approvals: Sequence[ApprovalRecord]
    ) -> str:
        """Mark the decisions this grant consumed, so they cannot authorise twice.

        Without this, one legitimate "approve this GBP 500,000 transfer" authorised an
        unlimited number of them: the action hash is identical by construction on a
        re-submission, so the same historical decision discharged a fresh grant every
        time. The nonce defends one grant; nothing defended the decision.

        Returns ``""`` on success, or why it failed. **The caller must refuse on a
        non-empty return**, and the reason is worth stating precisely: an approval that
        was not marked spent is an approval that will discharge the next identical
        proposal, so proceeding here does not risk ATT-04 — it *is* ATT-04, with the
        control present in the source and absent at runtime.

        This used to be ``getattr(self._approvals, "consume", None)`` followed by
        ``with suppress(Exception)``. ``consume`` is declared on the
        :class:`~attest.kernel.ports.ApprovalStore` port, so the ``getattr`` guarded
        against nothing except a store that had quietly not implemented it — which is
        precisely the store this check needed to reject. Between them the two lines
        turned a documented control into one that reported success whether or not it
        ran, in the exact shape section 7 of the audit names.
        """
        if self._approvals is None or not approvals:
            return ""
        try:
            self._approvals.consume(
                tuple(a.approval_id for a in approvals), grant_id=grant.grant_id
            )
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
        return ""

    def _request_approval(
        self,
        request: RunRequest,
        *,
        context: ExecutionContext,
        recorder: EventRecorder,
    ) -> None:
        """Open the pending action a held run is waiting on.

        Recorded whether or not a store is wired: the run held, and the chain has to
        say so. Where a store exists the queue entry is **opened** here — which it was
        not, so no ``PendingAction`` row was ever created by the framework and the queue
        the approval surface renders was permanently empty for engine-produced runs. A
        held run could not be approved through the shipped surface at all.
        """
        recorder.record(
            EventType.APPROVAL_REQUESTED.value,
            {
                "run_id": str(context.run_id),
                "tool": request.action.tool if request.action else "",
            },
        )
        if self._approvals is None or request.action is None:
            return
        opened_at = self._clock.now()
        try:
            self._approvals.open(
                self._hold_grant(request.action, context, opened_at),
                run_id=context.run_id,
                expires_at=opened_at + self._approval_ttl,
                summary=request.approval_summary or request.action.tool,
            )
        except Exception as exc:
            recorder.record(
                EventType.OBLIGATION_FAILED.value,
                {
                    "obligation": "approval:open",
                    "detail": (
                        f"the run held but the pending action could not be opened "
                        f"({type(exc).__name__}). Nobody can approve it until this is "
                        f"resolved, so it is recorded rather than swallowed."
                    ),
                },
            )

    def _hold_grant(
        self, action: Action, context: ExecutionContext, at: datetime
    ) -> AuthorizationGrant:
        """A grant-shaped carrier for the hold. **Not an authorisation.**

        ``ApprovalStore.open`` takes a grant because the grant already carries the whole
        binding — tenant, actor, and the action hash that covers the arguments — and a
        caller assembling those by hand assembles them inconsistently. No grant exists
        yet at hold time, by construction: obligations have not discharged. So this one
        carries the binding and nothing else, and it is never redeemed — the run holds,
        and a real grant is issued only after the decision arrives and the obligations
        discharge on a later attempt.

        .. rubric:: The id is derived, not minted

        ``self._ids.new_id("hold")`` produced a fresh id on every hold, and
        ``ApprovalStore.open`` derives the approval id from it. A run that holds, is
        resumed, and holds again — the ordinary shape of an approval that arrives after
        a partial re-check — opened a *new* pending row each cycle. Nothing superseded
        the previous one, and ``decisions()`` is keyed on the action hash, so an approver
        was shown several identical rows for one decision and could approve any of them.

        Deriving it from ``(run_id, action_hash)`` makes the hold idempotent: the same
        run holding the same action re-opens the same row. Both halves are needed.
        Without the run id, two concurrent runs proposing the identical action would
        collide on one pending row and one human decision would silently cover both.
        Without the action hash, a run that holds, has its proposal changed, and holds
        again would re-use the row an approver is looking at — so they would be shown
        one action and be approving another.

        Truncated to 16 hex characters because it lands in a ``CharField(max_length=128)``
        alongside a run id, and the whole point is that it be stable rather than unique
        across the universe.
        """
        digest = hashlib.sha256(
            f"{RunIds.dispatch_of(context.run_id)}\x00{action.action_hash()}".encode()
        ).hexdigest()[:16]
        return AuthorizationGrant(
            grant_id=GrantId(f"hold_{digest}"),
            action_hash=action.action_hash(),
            actor=action.actor,
            tenant=action.tenant,
            tool=action.tool,
            nonce=Nonces.fresh(),
            issued_at=at,
            expires_at=at + MAX_GRANT_TTL,
            policy_version=context.policy_version,
            profile_version=context.binding.profile.version,
            context_hash=context.content_hash(),
        )

    # ── Stages ───────────────────────────────────────────────────────────────

    def _assert_one_source_of_cost(self, request: RunRequest) -> None:
        """A run has one account of what it spent, not two that might disagree."""
        if request.model_calls is None:
            return
        if request.model is not None:
            raise ConfigurationError(
                "the request supplies both model_calls and a hand-written model ref. "
                "Only one can be the record of what served this run, and picking one "
                "silently is how an attestation comes to name a model that did not "
                "answer it."
            )
        if request.cost != CostRecord():
            raise ConfigurationError(
                "the request supplies both model_calls and a hand-written cost. Cost "
                "is derived from what was actually charged; asserting it alongside "
                "would put an unreconcilable figure in a financial record."
            )

    @staticmethod
    def _with_model(context: ExecutionContext, request: RunRequest) -> ExecutionContext:
        """Attach the model that answered, without disturbing the captured snapshot.

        The model ref is the one fact that cannot be known at capture time — the
        gateway has not chosen a provider yet — so it is added afterwards rather than
        making the caller's context unusable as a binding.
        """
        if request.model_calls is None:
            return context
        return replace(context, model=request.model_calls.model_ref())

    def _replay_model_calls(
        self,
        request: RunRequest,
        *,
        context: ExecutionContext,
        recorder: EventRecorder,
    ) -> None:
        """Fold the gateway's log into this run's chain, once it is proved to be ours.

        The binding check is the point. Without it the log is a claim the host makes
        about its own spending, and a run could be attributed the cost — or the
        residency — of a different one.
        """
        log = request.model_calls
        if log is None:
            return
        if log.run_id != str(context.run_id):
            raise ConfigurationError(
                f"the model call log belongs to run {log.run_id!r}, not "
                f"{str(context.run_id)!r}. A log from another run would attribute its "
                f"cost, its models and its residency to this one. Obtain a run id from "
                f"RunEngine.new_run_id(), open the gateway session with it, and pass "
                f"the same id to execute()."
            )
        if log.context_hash and log.context_hash != str(context.content_hash()):
            # The run id alone proves the caller was *consistent*, not that the log
            # describes this run — it is a value the caller supplies to both sides. The
            # context hash is derived from the snapshot the gateway actually ran under,
            # so a fabricated log attributing arbitrary cost, model identity, family and
            # region to an attestation no longer passes. `family` matters most: it is
            # what the cross-family judging independence rule compares.
            raise ConfigurationError(
                f"the model call log was recorded against a different execution "
                f"context ({log.context_hash[:12]}… vs "
                f"{str(context.content_hash())[:12]}…). The log's identity, policy "
                f"version and residency are not this run's, so its cost and its model "
                f"family cannot be attributed here."
            )
        for provider in log.circuits_opened:
            recorder.record(EventType.CIRCUIT_OPENED.value, {"provider": provider})
        for call in log.calls:
            recorder.record(
                EventType.MODEL_CALL_COMPLETED.value,
                {
                    "provider": call.provider,
                    "model_id": call.model_id,
                    "family": call.family,
                    "region": call.region,
                    "prompt_hash": call.prompt_hash,
                    "input_tokens": call.input_tokens,
                    "output_tokens": call.output_tokens,
                    "amount": call.amount,
                },
            )
            if call.failover:
                # A distinct fact, not a footnote on the call: a decision made by a
                # fallback model is a materially different decision, and replay must
                # be able to see that without re-deriving routing state that is gone.
                recorder.record(
                    EventType.MODEL_FAILED_OVER.value,
                    {
                        "served_by": call.provider,
                        "model_id": call.model_id,
                        "attempted": list(call.attempted),
                    },
                )

    def _capture(
        self, request: RunRequest, *, binding: TenantBinding, run_id: RunId, at: datetime
    ) -> ExecutionContext:
        """Snapshot the moment. After this, nothing reads live external state."""
        return ExecutionContext(
            run_id=run_id,
            captured_at=at,
            identity=IdentitySnapshot(
                actor=request.actor,
                tenant=request.tenant,
                capabilities=request.capabilities,
                roles=request.roles,
            ),
            binding=binding,
            framework_version=self._framework_version,
            policy_version=self._policy_version,
            evidence=request.evidence,
            prompt_hashes=dict(request.prompt_hashes),  # type: ignore[arg-type]
            model=(request.model_calls.model_ref() if request.model_calls else request.model),
        )

    def _assess(
        self,
        request: RunRequest,
        *,
        recorder: EventRecorder,
        at: datetime,
    ) -> dict[WarrantKind, WarrantReport]:
        """Evaluate every warrant the profile asks for, before any authority is issued."""
        wanted = self._profile.warrant_kinds()
        reports: dict[WarrantKind, WarrantReport] = {}

        if WarrantKinds.BOUNDARY in wanted:
            # Evidence content is screened, not just the inbound message. Retrieved
            # documents are how indirect prompt injection arrives, and they were the
            # one channel never checked — `screen_evidence` is a tenancy comparison.
            tainted = self._guards.screen_evidence_content(request.evidence)
            outcome = GuardOutcome(
                inbound=(
                    *(self._guards.screen_inbound(text) for text in request.inbound_text),
                    *(result for _, result in tainted),
                ),
                tenancy=self._guards.screen_evidence(request.evidence, tenant=request.tenant),
            )
            if any(not screen.clean for screen in outcome.inbound):
                recorder.record(
                    EventType.INJECTION_DETECTED.value,
                    {
                        "screens": len(outcome.inbound),
                        # Naming the document is the difference between an alert
                        # somebody can act on and one they cannot.
                        "evidence": sorted(str(eid) for eid, _ in tainted),
                    },
                )
            reports[WarrantKinds.BOUNDARY] = self._guards.evaluate(outcome)

        if WarrantKinds.EPISTEMIC in wanted:
            reports[WarrantKinds.EPISTEMIC] = self._evidence.evaluate(
                request.evidence, at=at.date()
            )
            recorder.record(EventType.EVIDENCE_VERIFIED.value, {"items": len(request.evidence)})

        if WarrantKinds.COMPLETENESS in wanted:
            reports[WarrantKinds.COMPLETENESS] = (
                request.coverage.warrant()
                if request.coverage is not None
                else self._unevaluatable(
                    WarrantKinds.COMPLETENESS,
                    "no_coverage_report",
                    "the run supplied no coverage report, so what was not searched is "
                    "unknown. An absent report is not full coverage.",
                )
            )

        for kind in sorted(wanted - set(reports) - {WarrantKinds.PROVENANCE}):
            # A warrant the profile asks for and nothing evaluated is UNEVALUATABLE,
            # never absent — an absent warrant reads as a satisfied one.
            reports[kind] = self._unevaluatable(
                kind,
                "no_verifier",
                f"the profile requires warrant {kind!r} and this engine has no "
                f"evaluator for it. Supply one, or remove it from the profile.",
            )
        return reports

    def _authorise_and_execute(
        self,
        request: RunRequest,
        *,
        context: ExecutionContext,
        recorder: EventRecorder,
        executor: Executor | None,
        reports: dict[WarrantKind, WarrantReport],
        at: datetime,
    ) -> tuple[tuple[EffectRecord, ...], dict[WarrantKind, WarrantReport]]:
        """Discharge obligations, then — only if satisfied — reach the executor."""
        action = request.action
        if action is None:
            reports[WarrantKinds.AUTHORITY] = WarrantReport(
                kind=WarrantKinds.AUTHORITY,
                status=WarrantStatus.EVALUATED,
                satisfied=True,
                verifier_ref="no-action",
            )
            return (), reports

        recorder.record(
            EventType.TOOL_PROPOSED.value,
            {"tool": action.tool, "action_hash": str(action.action_hash())},
        )
        disabled = self._disabled(action)
        if disabled is not None:
            recorder.record(
                EventType.OBLIGATION_FAILED.value,
                {"obligation": "autonomy", "detail": disabled},
            )
            reports[WarrantKinds.AUTHORITY] = self._unevaluatable(
                WarrantKinds.AUTHORITY, "capability_disabled", disabled
            )
            return (
                EffectRecord(action=action, state=EffectState.PROPOSED, detail=disabled),
            ), reports

        misbinding = self._misbound(action, context)
        if misbinding is not None:
            # Caught here so the run still produces an attestation. The authority
            # layer raises on the same condition, but an exception discards the
            # evidence, the warrants and the reason at exactly the moment they are
            # most wanted — and this is a refusal the system *can* record.
            recorder.record(EventType.TENANCY_VIOLATION.value, {"detail": misbinding})
            reports[WarrantKinds.AUTHORITY] = self._unevaluatable(
                WarrantKinds.AUTHORITY, "action_not_bound_to_run", misbinding
            )
            return (
                EffectRecord(action=action, state=EffectState.PROPOSED, detail=misbinding),
            ), reports

        bound = self._binder.bind(
            self._profile.obligations_for(action, context),
            action=action,
            # From the store, never from the request. `RunRequest.approvals` used to
            # supply these, so any authenticated caller could post two well-formed
            # ApprovalRecords with role="claims_director" and distinct approvers —
            # computing the action hash themselves, since it is a pure function of
            # fields they control — and discharge dual control on a GBP 500,000
            # transfer that no human ever saw. Every defence built into the store sat
            # on a code path the engine did not use.
            approvals=self._recorded_approvals(action),
            now=at,
            on_reserved=lambda scope, held: self._reserved(recorder, scope, held),
        )
        for scope in bound.scopes_refused:
            recorder.record(
                EventType.OBLIGATION_FAILED.value,
                {"obligation": f"budget:{scope}", "detail": "ceiling would be breached"},
            )
        result = self._authority.discharge(bound.obligations, action, context)
        reports[WarrantKinds.AUTHORITY] = self._authority_report(result)

        for outcome in result.outcomes:
            if outcome.discharge is Discharge.SATISFIED:
                recorder.record(
                    EventType.OBLIGATION_DISCHARGED.value,
                    {"obligation": outcome.name},
                )
        if not result.satisfied:
            for outcome in result.pending:
                recorder.record(
                    EventType.OBLIGATION_PENDING.value,
                    {"obligation": outcome.name, "detail": outcome.detail},
                )
            for outcome in result.failed:
                recorder.record(
                    EventType.OBLIGATION_FAILED.value,
                    {"obligation": outcome.name, "detail": outcome.detail},
                )
            # No grant is issued, so the executor is unreachable. The effect is
            # recorded as PROPOSED so the record says what was asked for, and the
            # budget it would have spent goes back rather than starving the queue.
            self._binder.release(bound.reservations)
            return (
                EffectRecord(action=action, state=EffectState.PROPOSED, detail="not authorised"),
            ), reports

        # Every blocking warrant must hold before authority is issued. Granting first
        # and checking after would authorise an action the evidence does not support.
        policies = self._policies_for(request, reports)
        unsatisfied = [
            kind
            for kind, report in reports.items()
            if kind != WarrantKinds.AUTHORITY
            and policies.get(kind, WarrantPolicy.BLOCK) is WarrantPolicy.BLOCK
            and not report.is_satisfied()
        ]
        if unsatisfied:
            self._binder.release(bound.reservations)
            return (
                EffectRecord(
                    action=action,
                    state=EffectState.PROPOSED,
                    detail=f"blocked by warrant(s): {', '.join(sorted(unsatisfied))}",
                ),
            ), reports

        grant = self._authority.issue(
            grant_id=GrantId(self._ids.new_id("grant")),
            # From the CSPRNG, never the seeded id generator. determinism.md requires
            # ids to be reproducible under a seed; a seeded generator emits the same
            # nonce for the same position in every run, so the first run redeemed it
            # and every later run's effect was refused as a replay. Where ids are
            # merely predictable it is worse than a fault: anyone who can dispatch can
            # burn the nonce a victim's run will use, and their payment is refused.
            nonce=Nonces.fresh(),
            action=action,
            context=context,
            result=result,
            now=at,
            idempotency_key=request.idempotency_key,
        )
        unspent = self._spend_approvals(grant, bound.approvals)
        if unspent:
            # Refuse rather than proceed. The grant is sound and the human really did
            # approve — but the decision is still marked available, so executing here
            # would let this same approval authorise the next identical proposal, and
            # the one after that. A refused transfer is recoverable by asking again; an
            # approval that authorises without limit is not recoverable at all.
            recorder.record(
                EventType.APPROVAL_NOT_SPENT.value,
                {
                    "grant_id": str(grant.grant_id),
                    "approval_ids": ",".join(str(a.approval_id) for a in bound.approvals),
                    "detail": unspent,
                },
            )
            return (
                EffectRecord(
                    action=action,
                    state=EffectState.REFUSED,
                    grant_id=grant.grant_id,
                    detail=(
                        f"the approval store could not mark the decision as spent "
                        f"({unspent}), so it would still authorise the next identical "
                        f"proposal. Refusing rather than executing on an approval that "
                        f"cannot be spent."
                    ),
                ),
            ), reports

        recorder.record(EventType.GRANT_ISSUED.value, {"grant_id": str(grant.grant_id)})
        recorder.record(
            EventType.TOOL_VERIFIED.value,
            {"tool": action.tool, "action_hash": str(action.action_hash())},
        )

        if executor is None:  # pragma: no cover - execute() refuses this earlier
            # Not an assert: `python -O` strips those, and this one stands between an
            # authorised grant and an AttributeError three frames down.
            raise ConfigurationError(
                "an action was authorised but no executor was supplied. Refusing "
                "rather than reporting success for an effect that never happened."
            )
        effect = self._perform(action, grant, context, executor, recorder, at)
        self._settle_budget(bound, effect)
        return (effect,), reports

    def _settle_budget(self, bound: BoundObligations, effect: EffectRecord) -> None:
        """Charge what was **reserved**, or give the hold back. Never neither, never a guess.

        The amount is the one the profile sized and the store actually held. It used to
        come from ``action.arguments.get("amount", "")`` — the framework guessing a
        domain field name, in a package that elsewhere refuses to know what a claim is
        or what GBP 10,000 means. A tool whose argument was ``value``, ``total`` or
        ``amount_pence`` charged the ceiling the *model spend* — fractions of a penny —
        while moving half a million pounds, and the proposer chooses the key. Nothing
        looked wrong, which is the dangerous part.

        ``release`` used to be called on the not-authorised and blocked-warrant paths
        only, so a boundary refusal — an expired grant, a replayed nonce, a revoked
        grant, a tenancy mismatch — left the reservation held until expiry. Tripping the
        boundary in a loop held a tenant's whole ceiling in dead reservations for five
        minutes at a time, which is a cheap denial of service against every other run in
        that scope.

        UNKNOWN commits. The upstream may have moved the money, and a ceiling that gives
        back budget for a payment that might have happened is a ceiling that can be
        exceeded by inducing timeouts.
        """
        if not bound.reservations:
            return
        if effect.state in WORLD_REACHING_EFFECT_STATES:
            self._binder.commit(bound.reservations, actual=bound.reserved_amount)
            return
        self._binder.release(bound.reservations)

    def _policies_for(
        self, request: RunRequest, reports: Mapping[WarrantKind, WarrantReport]
    ) -> dict[WarrantKind, WarrantPolicy]:
        """The profile's policy per warrant, tightened by the agent's own.

        **An agent may tighten and may not loosen**, which is the rule and the only
        reason it is safe to let an agent have an opinion here at all. A supervisor that
        BLOCKs on the boundary warrant while its deployment only WARNs is a deployment
        choosing to be careful about one agent. The reverse - an agent quietly relaxing
        a policy its deployment set - is a configuration file granting itself an
        exemption, and it would be invisible in exactly the way that matters.

        The comparison is :meth:`WarrantPolicy.strictest`, which
        :class:`~attest.capabilities.profile.ProfileComposer` also uses when composing
        two profiles. One ordering, so the two cannot drift apart in the permissive
        direction.

        ``NON_DOWNGRADEABLE`` still sits above all of this in
        :meth:`VerdictResolver.resolve`: no policy from any source softens a tenancy
        crossing, and an agent is not a new way in.
        """
        base = {kind: self._profile.warrant_policy(kind) for kind in reports}
        overrides = request.agent.warrant_overrides if request.agent is not None else {}
        if not overrides:
            return base
        return {
            kind: WarrantPolicy.strictest(policy, overrides.get(kind))
            for kind, policy in base.items()
        }

    def _disabled(self, action: Action) -> str | None:
        """Why this capability may not act right now, or ``None`` if it may.

        The kill switch, read. It was written by ``OperationsConsole.disable`` with a
        mandatory operator and reason, recorded on the append-only trail before taking
        effect - and consulted by nothing. An operator flipped it during an incident,
        the row landed, the audit said who and why, and ``execute`` carried on, because
        it never asked. A control whose only observable effect is its own audit record
        is not a control.

        **Only ``BLOCKED`` is handled here, deliberately.** ``APPROVE`` means the
        capability may act with a human in the loop, and that is exactly what the
        profile's ``Approval`` obligation already expresses through the authority
        layer. Implementing it a second time here would put approval policy in two
        places, and the second one would drift - the same argument
        :class:`~attest.capabilities.gateway.ModelGateway` makes for leaving budget
        enforcement to the obligation layer.

        **A store that raises blocks.** Not knowing whether the switch is on is not the
        same as it being off, and the whole point of this control is the incident during
        which infrastructure is already unwell. Returning "allowed" on an exception is
        the ``except Exception:``-then-the-permissive-answer shape that
        :meth:`~attest.capabilities.evidence.EvidenceEngine.floor_for` documents as the
        defect class found in every surveyed codebase.

        A run proposing no effect is never blocked here: this switch stops a capability
        *acting*, and advisory runs act on nothing. A deployment that wants to stop
        those stops dispatching them.

        **Wiring a store is opting into deny-by-default.** The shipped store answers
        ``blocked`` for a capability with no row, on the stated ground that an absent
        policy is an unanswered question rather than permission. That is the right
        default and it is a real commitment: an engine handed this store refuses every
        effect until somebody classifies the capability. An engine handed no store is
        unaffected, which keeps the decision where it can be seen.
        """
        if self._autonomy is None:
            return None
        capability = action.capability or action.tool
        try:
            mode = self._autonomy.mode_for(tenant=action.tenant, capability=capability)
        except Exception as exc:
            return (
                f"the autonomy store could not say whether {capability!r} is enabled "
                f"({type(exc).__name__}). Refusing: during an incident, not knowing "
                f"whether the kill switch is on is not the same as it being off."
            )
        if mode != AutonomyMode.BLOCKED:
            return None
        return (
            f"capability {capability!r} is disabled for tenant {action.tenant!r}. An "
            f"operator stopped it; it is not a failure of this run."
        )

    def _misbound(self, action: Action, context: ExecutionContext) -> str | None:
        """Whether the action acts for someone other than the run it arrived in.

        A host that builds an ``Action`` from request fields will eventually build one
        naming a tenant or actor the caller does not hold. Nothing downstream can see
        it: the grant takes its tenant and actor *from the action*, so the grant check
        and the boundary check both compare the action against itself and agree.
        """
        if action.tenant != context.identity.tenant:
            return (
                f"the action acts for tenant {action.tenant!r} but the run is bound to "
                f"{context.identity.tenant!r}"
            )
        if action.actor != context.identity.actor:
            return (
                f"the action names actor {action.actor!r} but the run was dispatched "
                f"by {context.identity.actor!r}"
            )
        return None

    def _perform(
        self,
        action: Action,
        grant: AuthorizationGrant,
        context: ExecutionContext,
        executor: Executor,
        recorder: EventRecorder,
        at: datetime,
    ) -> EffectRecord:
        """Cross the boundary, and record every outcome as itself.

        ``UpstreamTimeout`` becomes ``UNKNOWN`` — never a failure. The upstream may
        have committed, and saying it did not is a lie the reconciliation sweep exists
        to avoid having to tell.
        """
        try:
            return self._boundary.execute(
                action=action,
                grant=grant,
                context=context,
                executor=executor,
                # Observed, not inherited. Reusing the instant the grant was issued at
                # made EXPIRED and NOT_YET_VALID unreachable on this path: the grant was
                # checked against the moment it was created, so the window it exists to
                # shrink was zero-width and the TTL ceiling guarded nothing.
                now=self._clock.now(),
                current_policy_version=self._policy_version,
                emit=lambda event_type, payload: self._emit(recorder, event_type, payload),
            )
        except UpstreamTimeout as exc:
            recorder.record(EventType.EFFECT_UNKNOWN.value, {"detail": str(exc)})
            return EffectRecord(
                action=action,
                state=EffectState.UNKNOWN,
                grant_id=grant.grant_id,
                submitted_at=at,
                detail=str(exc) or "the upstream did not answer; the outcome is unknown",
            )
        except ExecutionRefused as exc:
            recorder.record(EventType.TOOL_REFUSED.value, {"detail": exc.refusal.detail})
            return EffectRecord(
                action=action,
                state=EffectState.REFUSED,
                grant_id=grant.grant_id,
                detail=exc.refusal.detail,
            )

    @staticmethod
    def _reserved(recorder: EventRecorder, scope: str, held: str) -> None:
        """A reservation nobody recorded is a hold nobody can explain when it expires."""
        recorder.record(EventType.BUDGET_RESERVED.value, {"scope": scope, "reservation_id": held})

    @staticmethod
    def _emit(recorder: EventRecorder, event_type: str, payload: dict[str, object]) -> None:
        """Adapter for the boundary's emit hook, which expects no return value.

        Marked durable: the boundary writes these through its own sink before the call
        they describe, so the batch flush must not write them again.
        """
        recorder.record(event_type, dict(payload), durable=True)

    def _finalise(
        self,
        request: RunRequest,
        *,
        context: ExecutionContext,
        recorder: EventRecorder,
        reports: dict[WarrantKind, WarrantReport],
        effects: tuple[EffectRecord, ...],
        verdict: Verdict,
        refusal: Refusal | None,
        at: datetime,
        supersedes: RunId | None = None,
        vault: RedactionVault | None = None,
    ) -> RunResult:
        """Seal the chain, evaluate provenance against it, and persist.

        The provenance warrant is evaluated **after** sealing because that is what it
        is about: whether the record of this run is complete and linked. Assembling it
        earlier would be assessing a chain that did not exist yet.
        """
        recorder.record(EventType.RUN_COMPLETED.value, {"verdict": verdict.value})

        draft = Attestation(
            run_id=context.run_id,
            verdict=verdict,
            context=context,
            created_at=at,
            answer=self._restore(request.answer, vault, recorder),
            structured=request.structured,
            warrants=reports,
            effects=effects,
            refusal=refusal,
            cost=request.model_calls.cost() if request.model_calls else request.cost,
            supersedes=supersedes,
            metadata=request.metadata,
        )
        sealed_events, seal = self._sealer.seal(
            recorder.events,
            run_id=context.run_id,
            attestation_hash=draft.content_hash(),
            sealed_at=at,
        )
        if WarrantKinds.PROVENANCE in self._profile.warrant_kinds():
            reports[WarrantKinds.PROVENANCE] = self._sealer.evaluate(sealed_events, seal=seal)
            # The verdict is re-resolved because provenance may have changed it, and a
            # verdict that ignored its own record's integrity would be worthless.
            # `_policies_for`, not the profile. The verdict is re-resolved here after
            # sealing, and reading the profile directly threw away the agent's own
            # policy that the first resolve had honoured - so an agent could tighten a
            # warrant, see it applied, and have the answer silently reverted by the
            # provenance pass. One resolver, one source of policy.
            verdict, refusal = self._resolver.resolve(
                reports=reports,
                policies=self._policies_for(request, reports),
                effects=effects,
            )
            draft = replace(draft, verdict=verdict, refusal=refusal, warrants=reports)
            sealed_events, seal = self._sealer.seal(
                recorder.events,
                run_id=context.run_id,
                attestation_hash=draft.content_hash(),
                sealed_at=at,
            )

        attestation = replace(draft, seal=seal)
        # Only the batch. The boundary already wrote the effect and grant events
        # durably, before the call they describe — appending them again would put each
        # in the chain twice, and a chain with duplicates cannot be sealed densely.
        recorder.flush(self._audit)
        self._close(context.run_id, seal)
        if self._runs is not None:
            self._runs.create(attestation)
        return RunResult(attestation=attestation, events=sealed_events)

    def _close(self, run_id: RunId, seal: RunSeal) -> None:
        """Tell the registry this chain is shut. **After the flush, never before.**

        Order is the whole of it: the guard refuses inserts for a closed run, so closing
        first would reject the run's own final batch.

        A registry that nothing writes to leaves its trigger permanently unarmed — the
        table stays empty, every insert passes the check, and a deployment believes a
        sealed run cannot be appended to. That is the same defect as an uncalled method,
        wearing an empty table.
        """
        if self._seals is None:
            return
        try:
            self._seals.close(run_id, seal)
        except Exception as exc:
            # Not fatal: the attestation and its chain are durable, and the registry is
            # defence in depth behind them. But an unarmed guard must not be silent —
            # a deployment that thinks a sealed run is closed and finds it open has been
            # told something untrue.
            recorder = EventRecorder(run_id=run_id, clock=self._clock, sink=self._audit)
            with suppress(Exception):
                recorder.record(
                    EventType.RUN_FAILED.value,
                    {
                        "error": type(exc).__name__,
                        "detail": (
                            f"the run sealed and the seal registry refused it ({exc}). "
                            f"The chain is durable; the database guard against appending "
                            f"to this closed run is NOT armed."
                        ),
                    },
                    durable=True,
                )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _authority_report(self, result: DischargeResult) -> WarrantReport:
        return WarrantReport(
            kind=WarrantKinds.AUTHORITY,
            status=WarrantStatus.EVALUATED,
            satisfied=result.satisfied,
            findings=tuple(
                Finding(
                    code=outcome.discharge.value,
                    message=f"{outcome.name}: {outcome.detail}",
                    severity=Severity.ERROR
                    if outcome.discharge.value == "failed"
                    else (Severity.WARNING),
                )
                for outcome in (*result.pending, *result.failed)
            ),
            verifier_ref="authority-engine",
        )

    def _unevaluatable(self, kind: WarrantKind, code: str, message: str) -> WarrantReport:
        """A check that did not run. Never satisfied — the type forbids it."""
        return WarrantReport(
            kind=kind,
            status=WarrantStatus.UNEVALUATABLE,
            satisfied=False,
            findings=(Finding(code=code, message=message, severity=Severity.ERROR),),
        )
