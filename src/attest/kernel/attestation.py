"""Attestation — the artifact a run returns. **Not a string.**

The thing that must be durable is not the *response*. It is the record that the
response was warranted.

.. code-block:: text

    Conventional framework            Attest
    ──────────────────────            ──────────────────────────────────
    run() -> str                      run() -> Attestation
                                        ├── verdict
    "The claim is payable               ├── answer
     under section 4.2."                ├── warrants
                                        ├── effects
    (Trust me.)                         └── seal

``warrants`` is a **mapping, not four named fields**. That single choice is what keeps
the framework open: a clinical profile adds ``calibration``, an underwriting profile
adds ``fairness``, and neither requires touching the kernel.

Two properties are enforced here rather than documented:

*A non-final attestation cannot be exported.* Where a profile defers assurance, warrants
come back ``PENDING`` and :attr:`Attestation.is_final` is ``False``. An evidence bundle
is what goes to a regulator, so producing one whose warrants had not been evaluated
would present an unverified result as a settled record. See ADR 0035.

*Corrections never mutate.* A superseding attestation is a new record pointing at what
it replaces, so a reader who relied on the original can still see exactly what they
relied on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from attest.kernel.canonical import Canonical
from attest.kernel.effects import WORLD_REACHING_EFFECT_STATES, EffectState
from attest.kernel.identifiers import Hash
from attest.kernel.verdicts import POST_EFFECT_VERDICTS, Verdict
from attest.kernel.warrants import CORE_WARRANTS, WarrantStatus

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from attest.kernel.actions import Action
    from attest.kernel.audit import RunSeal
    from attest.kernel.context import ExecutionContext
    from attest.kernel.identifiers import GrantId, RunId
    from attest.kernel.verdicts import Refusal
    from attest.kernel.warrants import WarrantKind, WarrantReport

__all__ = ["Attestation", "AttestationError", "CostRecord", "EffectRecord"]


class AttestationError(Exception):
    """An attestation was asked for something it cannot honestly provide."""


@dataclass(frozen=True, slots=True)
class CostRecord:
    """What a run cost, priced against a pinned table.

    ``pricing_version`` is not decoration. Prices change, and a historical cost figure
    that silently re-prices at today's rate is not an audit record.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    currency: str = "USD"
    amount: str = "0"
    """Decimal as a string, so no float rounding enters a financial record."""

    pricing_version: str | None = None

    def __post_init__(self) -> None:
        for name in ("input_tokens", "output_tokens", "cached_tokens"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} cannot be negative")


@dataclass(frozen=True, slots=True)
class EffectRecord:
    """One external effect, and how far it got.

    Separate from the run's :class:`~attest.kernel.verdicts.Verdict`: a flow may commit
    one effect and leave another ``UNKNOWN``, so states are per-effect while the
    verdict is what the caller matches on.
    """

    action: Action
    state: EffectState
    grant_id: GrantId | None = None
    """Every COMMITTED effect must reference the grant that authorised it.

    An effect without one is detectable by reconciliation, which is what makes
    threat-model attack 11 - invoking an executor directly - visible after the fact
    even though Python cannot prevent it.
    """

    external_reference: str | None = None
    """The upstream's own identifier. Required for COMMITTED: without it we are
    asserting a commit we cannot point at."""

    idempotency_key: str | None = None
    submitted_at: datetime | None = None
    settled_at: datetime | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.state is EffectState.COMMITTED:
            if not self.external_reference:
                raise AttestationError(
                    "a COMMITTED effect must carry the external reference returned by "
                    "the upstream. Recording a commit we cannot point at is how an "
                    "audit chain comes to disagree with the world."
                )
            if self.grant_id is None:
                raise AttestationError(
                    "a COMMITTED effect must reference the grant that authorised it; "
                    "an effect without one is unauthorised by definition"
                )
        if self.state is EffectState.UNKNOWN and not self.submitted_at:
            raise AttestationError(
                "an UNKNOWN effect must record when it was submitted. Without that, "
                "UNKNOWN is indistinguishable from 'never attempted' and cannot be "
                "reconciled."
            )


@dataclass(frozen=True, slots=True)
class Attestation:
    """The provenance-bound record of a decision and its effects."""

    run_id: RunId
    verdict: Verdict
    context: ExecutionContext
    created_at: datetime

    answer: str = ""
    structured: Mapping[str, Any] | None = None
    warrants: Mapping[WarrantKind, WarrantReport] = field(default_factory=dict)
    effects: tuple[EffectRecord, ...] = ()
    refusal: Refusal | None = None
    cost: CostRecord = field(default_factory=CostRecord)
    seal: RunSeal | None = None
    """``None`` until the run is sealed. There is no chain head before then — the
    chain is a post-hoc verification artifact, not a live index."""

    supersedes: RunId | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "warrants", MappingProxyType(dict(self.warrants)))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        if self.structured is not None:
            object.__setattr__(self, "structured", MappingProxyType(dict(self.structured)))

        if self.run_id != self.context.run_id:
            raise AttestationError(
                f"attestation {self.run_id!r} carries a context for run "
                f"{self.context.run_id!r}; the record would describe a different run "
                f"from the one it claims"
            )
        if self.verdict is Verdict.REFUSE and self.refusal is None:
            raise AttestationError(
                "a REFUSE verdict must carry a typed Refusal. Refusal rates are "
                "monitored and refusals trigger downstream obligations; an "
                "unexplained one cannot be aggregated, acted on, or contested."
            )
        if self.verdict in POST_EFFECT_VERDICTS and not self.effects:
            raise AttestationError(
                f"verdict {self.verdict.value!r} is only reachable after an effect was "
                f"attempted, but no effects are recorded"
            )
        if self.verdict is Verdict.REFUSE:
            reached = [
                record for record in self.effects if record.state in WORLD_REACHING_EFFECT_STATES
            ]
            if reached:
                states = ", ".join(sorted({record.state.value for record in reached}))
                raise AttestationError(
                    f"run {self.run_id!r} is recorded as REFUSE while {len(reached)} "
                    f"effect(s) already reached the outside world ({states}). REFUSE "
                    f"means nothing happened, and 'nothing happened' and 'some of it "
                    f"happened' require different human responses — that is what "
                    f"INCOMPLETE and UNKNOWN are for. A refusal written over a "
                    f"committed transfer is the most dangerous record this system "
                    f"could produce."
                )
        for kind, report in self.warrants.items():
            if report.kind != kind:
                raise AttestationError(f"warrant filed under {kind!r} reports kind {report.kind!r}")

    # ── Assurance state ──────────────────────────────────────────────────────────

    @property
    def is_final(self) -> bool:
        """Whether every warrant has actually been evaluated.

        **Derived, never stored.** A stored flag can disagree with the warrants it
        summarises; this cannot.
        """
        return all(report.is_final for report in self.warrants.values())

    @property
    def pending_warrants(self) -> frozenset[WarrantKind]:
        """Warrants still awaiting deferred assurance."""
        return frozenset(
            kind for kind, report in self.warrants.items() if report.status is WarrantStatus.PENDING
        )

    def warrant(self, kind: WarrantKind) -> WarrantReport:
        """The report for ``kind``.

        Raises rather than returning ``None``: a caller asking whether a warrant held
        must not receive an absence it can mistake for a pass.
        """
        try:
            return self.warrants[kind]
        except KeyError:
            raise AttestationError(
                f"no warrant of kind {kind!r} was evaluated for run {self.run_id!r}. "
                f"An absent warrant is not a satisfied one."
            ) from None

    def missing_core_warrants(self) -> frozenset[WarrantKind]:
        """Core warrants that were never evaluated at all.

        The four core warrants are mandatory in every domain, so a non-empty result
        here means the run is not attestable rather than merely imperfect.
        """
        return frozenset(CORE_WARRANTS - set(self.warrants))

    def unsatisfied(self) -> frozenset[WarrantKind]:
        """Every warrant that did not pass, including those that could not run."""
        return frozenset(
            kind for kind, report in self.warrants.items() if not report.is_satisfied()
        )

    # ── Effects ──────────────────────────────────────────────────────────────────

    def effects_in_state(self, state: EffectState) -> tuple[EffectRecord, ...]:
        return tuple(record for record in self.effects if record.state is state)

    @property
    def has_unresolved_effects(self) -> bool:
        """Whether anything is outstanding against the external world.

        An `UNKNOWN` effect is a work item for reconciliation, and its age is an SLO:
        an unreconciled large transfer is an open incident, not a metric on a chart.
        """
        return any(
            record.state in {EffectState.SUBMITTED, EffectState.UNKNOWN} for record in self.effects
        )

    # ── Export ───────────────────────────────────────────────────────────────────

    def assert_exportable(self) -> None:
        """Raise unless this attestation may be turned into an evidence bundle.

        Two conditions, both refusals rather than warnings. An unsealed record has no
        verifiable chain; a non-final one has warrants nobody evaluated. Either would
        put something in front of a regulator that claims more than it establishes.
        """
        if self.seal is None:
            raise AttestationError(
                f"run {self.run_id!r} is not sealed, so its chain cannot be verified "
                f"offline. An unsealed record is not evidence."
            )
        if not self.is_final:
            pending = ", ".join(sorted(self.pending_warrants))
            raise AttestationError(
                f"run {self.run_id!r} has warrants still pending ({pending}). An "
                f"evidence bundle is what goes to a regulator; exporting one whose "
                f"warrants had not been evaluated would present an unverified result "
                f"as a settled record. Let deferred assurance settle first."
            )

    # ── Identity ─────────────────────────────────────────────────────────────────

    def content_hash(self) -> Hash:
        """The content address of this attestation, excluding its seal.

        The seal signs *this* value, so it cannot be part of what it signs.
        """
        return Hash(
            Canonical.digest(
                {
                    "run_id": self.run_id,
                    "verdict": self.verdict,
                    "context_hash": self.context.content_hash(),
                    "created_at": self.created_at,
                    "answer": self.answer,
                    "structured": None if self.structured is None else dict(self.structured),
                    "warrants": {
                        kind: {
                            "status": report.status,
                            "satisfied": report.satisfied,
                            "confidence": report.confidence,
                            "verifier_ref": report.verifier_ref,
                            "findings": [
                                {"code": f.code, "message": f.message, "severity": f.severity}
                                for f in report.findings
                            ],
                        }
                        for kind, report in sorted(self.warrants.items())
                    },
                    "effects": [
                        {
                            "action_hash": record.action.action_hash(),
                            "state": record.state,
                            "grant_id": record.grant_id,
                            "external_reference": record.external_reference,
                            "idempotency_key": record.idempotency_key,
                        }
                        for record in self.effects
                    ],
                    "refusal": None
                    if self.refusal is None
                    else {
                        "reason": self.refusal.reason,
                        "warrant": self.refusal.warrant,
                        "detail": self.refusal.detail,
                    },
                    "cost": {
                        "input_tokens": self.cost.input_tokens,
                        "output_tokens": self.cost.output_tokens,
                        "cached_tokens": self.cost.cached_tokens,
                        "currency": self.cost.currency,
                        "amount": self.cost.amount,
                        "pricing_version": self.cost.pricing_version,
                    },
                    "supersedes": self.supersedes,
                    # Covered because it is stored, returned and rendered. A field a
                    # host puts decisions in must not be editable without detection.
                    "metadata": dict(self.metadata),
                }
            )
        )
