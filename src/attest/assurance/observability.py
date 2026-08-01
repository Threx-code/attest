"""Observability — the signals only the kernel can compute, and the ones that page.

``docs/assurance/observability.md`` opens: *"Listing OpenTelemetry as an adapter is not
an observability story."* It then specifies twenty-odd signals and says of them, in as
many words: **"These are not optional instrumentation. Each is derived from data only
the kernel holds."** Nothing computed any of them.

That is the section 7 pattern again, and here it costs a specific thing. An operator
running this framework had no way to answer the four questions the document opens with —
is assurance degrading, is the governance real, what will break next, what did this cost
— because the data was all present in the attestations and nothing turned it into a
number. A dashboard built on request counts and latency is exactly the conventional APM
the document says is insufficient, and it is what a host would have built instead.

.. rubric:: The framework computes; the host emits

There is no metrics client here and there will not be one. Every adopter has Prometheus,
Datadog, OTel or something worse, and a framework that shipped its own would be wired up
beside the real one and drift from it. What only *this* package can do is derive the
numbers, because they come from warrant reports, verdict mixes and effect states — not
from anything an interceptor can see.

.. code-block:: python

    signals = Signals.over(attestations)
    for name, value, denominator in signals.gauges():
        statsd.gauge(f"attest.{name}", value)      # your metrics system, your names

.. rubric:: A rate without its denominator is not a signal

Every measurement here carries the population it was computed over. "Refusal rate 0%"
means one thing over 40,000 runs and nothing at all over three, and a dashboard that
cannot tell them apart will show a flat green line through an outage — because during
an outage the denominator is what collapses first.

.. rubric:: What this does not compute, and why

Judge-vs-human agreement, calibration drift and the drift canary need control items and
a gateway, neither of which is derivable from an attestation. They are named in
:attr:`Signals.NOT_DERIVABLE` rather than silently omitted, so a host reading this
module learns what it still has to wire rather than assuming the list is complete.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar

from attest.kernel.effects import EffectState
from attest.kernel.verdicts import Verdict

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from datetime import datetime

    from attest.kernel.attestation import Attestation

__all__ = ["Incident", "Measurement", "Severity", "Signals"]


class Severity(StrEnum):
    """Whether a signal is a dashboard line or somebody's night.

    The distinction is in the document and it is the useful half. Most of the signals
    are context; six of them are incidents, and a system that emits all of them at one
    level trains its operators to ignore the ones that matter.
    """

    DASHBOARD = "dashboard"
    PAGE = "page"


@dataclass(frozen=True, slots=True)
class Measurement:
    """One number, and the population it was computed over. **Never a bare float.**

    ``over`` is not decoration. A refusal rate of 0% across 40,000 runs is a healthy
    system; across three runs it is noise; across zero runs it is an outage that a
    ratio-only dashboard renders as a flat green line, because the numerator and the
    denominator collapsed together.
    """

    name: str
    value: Decimal
    over: int
    detail: str = ""

    @property
    def meaningful(self) -> bool:
        """Whether the population is large enough for the ratio to mean anything.

        Twenty is not a statistical claim; it is a floor below which an alert on this
        ratio would fire on noise. Exposed rather than applied silently, so a caller
        can render "insufficient data" instead of a number that looks like a fact.
        """
        return self.over >= Signals.MINIMUM_POPULATION

    def render(self) -> str:
        return f"{self.name} {self.value}% of {self.over}" + (
            f" — {self.detail}" if self.detail else ""
        )


@dataclass(frozen=True, slots=True)
class Incident:
    """Something that must page a person, with the evidence attached.

    Carries the run ids rather than a count, because the first thing anybody asks at
    3am is "which ones", and a page that answers it saves the ten minutes that a
    ``chain verification failed: 4`` costs.
    """

    signal: str
    detail: str
    runs: tuple[str, ...] = ()
    severity: Severity = Severity.PAGE

    def render(self) -> str:
        subjects = f" [{', '.join(self.runs[:5])}{'…' if len(self.runs) > 5 else ''}]"
        return f"PAGE {self.signal}: {self.detail}{subjects if self.runs else ''}"


@dataclass(frozen=True, slots=True)
class Signals:
    """Everything derivable about a population of runs.

    Built by :meth:`over` from attestations the host already stores. Deliberately a
    value: a snapshot that can be logged, compared against yesterday's, or asserted on
    in a test — which is the only way "assurance is degrading" becomes a thing anybody
    notices before a customer does.
    """

    population: int
    verdicts: dict[str, int] = field(default_factory=dict)
    refusals_by_reason: dict[str, int] = field(default_factory=dict)
    warrant_satisfaction: dict[str, Measurement] = field(default_factory=dict)
    findings_by_code: dict[str, int] = field(default_factory=dict)
    unresolved_effects: int = 0
    oldest_unresolved: timedelta | None = None
    unsealed: int = 0
    total_cost: Decimal = Decimal(0)
    incidents: tuple[Incident, ...] = ()

    MINIMUM_POPULATION: ClassVar[int] = 20
    """Below this a ratio is noise. See :attr:`Measurement.meaningful`."""

    NOT_DERIVABLE: ClassVar[tuple[str, ...]] = (
        "judge-vs-human agreement — needs control items the host labels",
        "calibration drift per judge — needs a judge history this package does not keep",
        "drift canary results — needs the gateway, and a scheduled canary run",
        "per-reviewer approval rate — needs the approval store, not the attestation",
        "approval time-to-decision — needs the approval store",
        "projected vs staffed review capacity — needs the host's rota",
        "circuit breaker state and failover rate — needs the gateway",
    )
    """Signals the document names that an attestation cannot yield.

    Listed rather than quietly dropped. A host that reads
    ``Signals.over(attestations)`` and sees a full-looking object would reasonably
    assume the list in the document was covered, and would not go and wire the four
    that are missing — three of which are the *leading* indicators, the ones that move
    before the failure.
    """

    #: Effect states that mean money may have moved and nobody knows.
    UNRESOLVED: ClassVar[frozenset[EffectState]] = frozenset(
        {EffectState.UNKNOWN, EffectState.SUBMITTED}
    )

    @classmethod
    def over(
        cls,
        attestations: Iterable[Attestation],
        *,
        now: datetime | None = None,
        unknown_effect_sla: timedelta = timedelta(hours=4),
    ) -> Signals:
        """Compute every derivable signal over a population of runs.

        ``now`` is passed rather than read — the kernel has no ambient clock, and a
        signal timestamped by the collector is one that cannot be recomputed from the
        same inputs six months later, which is the whole point of deriving it from
        attestations rather than scraping it.
        """
        runs = list(attestations)
        verdicts: Counter[str] = Counter()
        reasons: Counter[str] = Counter()
        codes: Counter[str] = Counter()
        satisfied: Counter[str] = Counter()
        evaluated: Counter[str] = Counter()
        cost = Decimal(0)
        unresolved: list[tuple[str, datetime | None]] = []
        unsealed: list[str] = []

        for run in runs:
            verdicts[run.verdict.value] += 1
            if run.refusal is not None:
                reasons[str(run.refusal.reason)] += 1
            if run.seal is None:
                unsealed.append(str(run.run_id))
            cost += cls._cost_of(run)
            for kind, report in run.warrants.items():
                evaluated[str(kind)] += 1
                if report.is_satisfied():
                    satisfied[str(kind)] += 1
                for finding in report.findings:
                    codes[finding.code] += 1
            for effect in run.effects:
                if effect.state in cls.UNRESOLVED:
                    unresolved.append((str(run.run_id), effect.submitted_at))

        oldest = cls._oldest(unresolved, now=now)
        signals = cls(
            population=len(runs),
            verdicts=dict(verdicts),
            refusals_by_reason=dict(reasons),
            warrant_satisfaction={
                kind: Measurement(
                    name=f"warrant.{kind}.satisfaction",
                    value=cls._percent(satisfied[kind], evaluated[kind]),
                    over=evaluated[kind],
                )
                for kind in sorted(evaluated)
            },
            findings_by_code=dict(codes),
            unresolved_effects=len(unresolved),
            oldest_unresolved=oldest,
            unsealed=len(unsealed),
            total_cost=cost,
        )
        return signals._with_incidents(
            runs, unresolved=unresolved, unsealed=unsealed, now=now, sla=unknown_effect_sla
        )

    # ── The dashboard ────────────────────────────────────────────────────────

    def verdict_mix(self) -> dict[str, Measurement]:
        """All six verdicts, and the last two are the ones that matter.

        ``UNKNOWN`` and ``INCOMPLETE`` are the states this framework exists to represent
        honestly, so a dashboard that shows "success rate" and folds them into failure
        has thrown away the distinction the whole design is built on.
        """
        return {
            verdict.value: Measurement(
                name=f"verdict.{verdict.value}",
                value=self._percent(self.verdicts.get(verdict.value, 0), self.population),
                over=self.population,
            )
            for verdict in Verdict
        }

    def refusal_rate(self) -> Measurement:
        return Measurement(
            name="refusal.rate",
            value=self._percent(sum(self.refusals_by_reason.values()), self.population),
            over=self.population,
            detail="by reason: " + (self._top(self.refusals_by_reason) or "none"),
        )

    def unverifiable_rate(self) -> Measurement:
        """The leading indicator the document singles out.

        *"A source system stopped retaining versions -> future attestations lose their
        evidentiary value MONTHS before anyone tries to verify one."* It rises long
        before anything fails, and it is invisible in conventional APM because every
        request still returns 200.
        """
        unverifiable = self.findings_by_code.get(
            "source_unavailable", 0
        ) + self.findings_by_code.get("insufficient_source_authority", 0)
        return Measurement(
            name="evidence.unverifiable_rate",
            value=self._percent(unverifiable, self.population),
            over=self.population,
            detail="a source system may have stopped retaining versions",
        )

    def deferred_rate(self) -> Measurement:
        """Non-final attestations. Assurance that has not concluded is not assurance."""
        return Measurement(
            name="attestation.deferred_rate",
            value=self._percent(self.unsealed, self.population),
            over=self.population,
        )

    def cost_per_decision(self) -> Measurement:
        return Measurement(
            name="cost.per_decision",
            value=(
                Decimal(0)
                if not self.population
                else (self.total_cost / self.population).quantize(Decimal("0.0001"))
            ),
            over=self.population,
            detail="not a percentage — currency units per run",
        )

    def gauges(self) -> tuple[Measurement, ...]:
        """Everything a host would push to its metrics system, in one call."""
        return (
            *self.verdict_mix().values(),
            *self.warrant_satisfaction.values(),
            self.refusal_rate(),
            self.unverifiable_rate(),
            self.deferred_rate(),
            self.cost_per_decision(),
        )

    def render(self) -> str:
        """A readable snapshot, including what is **not** covered.

        The uncovered list is printed every time, for the same reason
        :class:`~attest.assurance.conformance.ConformanceReport` prints its
        NOT_ESTABLISHED block on passes: a full-looking dashboard is read as a complete
        one, and documentation alone will not stop that inference.
        """
        lines = [f"SIGNALS over {self.population} runs"]
        lines += [f"  {m.render()}" for m in self.gauges()]
        if self.incidents:
            lines += ["INCIDENTS", *(f"  {i.render()}" for i in self.incidents)]
        lines += ["NOT DERIVED FROM ATTESTATIONS", *(f"  - {n}" for n in self.NOT_DERIVABLE)]
        return "\n".join(lines)

    # ── The six that page ────────────────────────────────────────────────────

    def _with_incidents(
        self,
        runs: Sequence[Attestation],
        *,
        unresolved: Sequence[tuple[str, datetime | None]],
        unsealed: Sequence[str],
        now: datetime | None,
        sla: timedelta,
    ) -> Signals:
        """The document's PAGE list, computed. Everything else is a dashboard."""
        incidents: list[Incident] = []

        breaches = self._breaching(unresolved, now=now, sla=sla)
        if breaches:
            incidents.append(
                Incident(
                    signal="unknown_effect_age",
                    detail=(
                        f"{len(breaches)} effect(s) unresolved beyond the {sla} SLA. An "
                        f"unreconciled transfer is not a metric on a chart, it is an "
                        f"open incident: money is in a state nobody knows."
                    ),
                    runs=tuple(breaches),
                )
            )

        tenancy = self._runs_with_finding(runs, "tenancy_violation")
        if tenancy:
            incidents.append(
                Incident(
                    signal="cross_tenant_access",
                    detail="a data boundary was crossed; this is never a warning",
                    runs=tenancy,
                )
            )

        leakage = self._runs_with_finding(runs, "outbound_leakage")
        if leakage:
            incidents.append(
                Incident(
                    signal="outbound_leakage",
                    detail="a value that must never leave the boundary reached a reader",
                    runs=leakage,
                )
            )

        if unsealed:
            incidents.append(
                Incident(
                    signal="seal_gap",
                    detail=(
                        f"{len(unsealed)} attestation(s) carry no seal, so their event "
                        f"count is unbound and an omission would not be detectable"
                    ),
                    runs=tuple(unsealed),
                )
            )

        divergent = tuple(
            str(run.run_id)
            for run in runs
            if run.verdict is Verdict.INCOMPLETE
            and any(e.state is EffectState.COMMITTED for e in run.effects)
        )
        if divergent:
            incidents.append(
                Incident(
                    signal="effect_vs_audit_divergence",
                    detail="an effect committed under a run whose record is incomplete",
                    runs=divergent,
                )
            )

        return Signals(
            population=self.population,
            verdicts=self.verdicts,
            refusals_by_reason=self.refusals_by_reason,
            warrant_satisfaction=self.warrant_satisfaction,
            findings_by_code=self.findings_by_code,
            unresolved_effects=self.unresolved_effects,
            oldest_unresolved=self.oldest_unresolved,
            unsealed=self.unsealed,
            total_cost=self.total_cost,
            incidents=tuple(incidents),
        )

    # ── Arithmetic, kept honest ──────────────────────────────────────────────

    @staticmethod
    def _percent(part: int, whole: int) -> Decimal:
        """Zero over zero is zero, and the ``over`` field is what says so.

        Returning ``None`` here would push a null check into every call site and one of
        them would render it as 0% anyway. The population travels with the number
        instead, which is the honest version of the same information.
        """
        if whole <= 0:
            return Decimal(0)
        return (Decimal(part) * 100 / Decimal(whole)).quantize(Decimal("0.01"))

    @staticmethod
    def _cost_of(run: Attestation) -> Decimal:
        amount = getattr(run.cost, "amount", None)
        if amount is None:
            return Decimal(0)
        try:
            return Decimal(str(amount))
        except (ValueError, ArithmeticError):
            # A cost that will not parse is a reporting problem, not a reason to lose
            # every other run's cost in the same batch.
            return Decimal(0)

    @staticmethod
    def _oldest(
        unresolved: Sequence[tuple[str, datetime | None]], *, now: datetime | None
    ) -> timedelta | None:
        if now is None:
            return None
        ages = [now - at for _, at in unresolved if at is not None]
        return max(ages) if ages else None

    @staticmethod
    def _breaching(
        unresolved: Sequence[tuple[str, datetime | None]],
        *,
        now: datetime | None,
        sla: timedelta,
    ) -> tuple[str, ...]:
        """Which runs are past the SLA. Empty when no clock was supplied.

        A caller that did not pass ``now`` gets no age incident rather than one computed
        against an ambient clock — the age would be right and unreproducible, and this
        is a page.
        """
        if now is None:
            return ()
        return tuple(run_id for run_id, at in unresolved if at is not None and now - at >= sla)

    @staticmethod
    def _runs_with_finding(runs: Sequence[Attestation], code: str) -> tuple[str, ...]:
        return tuple(
            str(run.run_id)
            for run in runs
            if any(
                finding.code == code
                for report in run.warrants.values()
                for finding in report.findings
            )
        )

    @staticmethod
    def _top(counts: dict[str, int], limit: int = 3) -> str:
        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
        return ", ".join(f"{name}={count}" for name, count in ranked)
