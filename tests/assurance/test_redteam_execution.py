"""The red-team corpus, executed against a real engine.

This file is the difference between ATT-45 and its fix. Before it, ``RedTeamCase`` held
a ``must_not`` field and nothing sent an adversarial input at anything — so the case
``family=EVIDENCE_FORGERY, name="fabricated citation", must_not=(ALLOW,)`` sat in the
repository beside a codebase where a fabricated citation verified perfectly. The
mechanism that should have caught two Critical findings certified itself instead.

Every assertion here is on an **outcome**: what the engine decided about an attack, not
whether a guard exists. That is the one durable defence the audit identified after three
rounds, and it is what these tests are for.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from attest.adapters.memory import (
    InMemoryAuditSink,
    InMemoryIdempotencyStore,
    InMemoryNonceStore,
    InMemoryRunStore,
)
from attest.assurance.redteam import Attacks, Family, RedTeamCase, RedTeamSuite
from attest.capabilities.profile import BaseProfile
from attest.kernel.context import ProfileRef, TenantBinding
from attest.kernel.effects import EffectState
from attest.kernel.identifiers import Hash, TenantId
from attest.kernel.verdicts import Verdict
from attest.runtime.engine import RunEngine

pytestmark = [pytest.mark.security, pytest.mark.redteam]

AT = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.at = AT

    def now(self) -> datetime:
        self.at += timedelta(milliseconds=1)
        return self.at


class Ids:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def new_id(self, prefix: str) -> str:
        with self._lock:
            self._counts[prefix] = self._counts.get(prefix, 0) + 1
            return f"{prefix}_{self._counts[prefix]}"


class Upstream:
    """An executor that would happily do whatever it is asked.

    Deliberately compliant. If a case reaches it, the framework let the attack through —
    a refusing executor would hide exactly the failure these tests exist to find.

    The signature has to be the real one. It was briefly wrong here, and the effect was
    instructive: the boundary caught a ``TypeError`` before the body ran, ``calls``
    stayed empty, and ``test_no_attack_in_the_corpus_reaches_the_executor`` passed for a
    reason that had nothing to do with the framework stopping anything. A check that
    cannot fail proves nothing — which is the finding this whole file exists to answer,
    reappearing inside the answer. ``test_the_harness_executor_actually_works`` below
    is what keeps it honest.
    """

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def execute(self, action: Any, context: Any) -> Any:
        from attest.capabilities.execution import EffectOutcome

        self.calls.append(action)
        return EffectOutcome(external_reference=f"upstream-{len(self.calls)}")


class Strict(BaseProfile):
    """A profile that blocks on every warrant — the posture a regulated domain takes."""

    name, version = "redteam", "1.0.0"


def _engine(**overrides: Any) -> RunEngine:
    defaults: dict[str, Any] = {
        "clock": Clock(),
        "ids": Ids(),
        "audit": InMemoryAuditSink(),
        "nonces": InMemoryNonceStore(),
        "runs": InMemoryRunStore(),
        "idempotency": InMemoryIdempotencyStore(),
        "profile": Strict(),
        "brand": "acme",
    }
    defaults.update(overrides)
    return RunEngine(**defaults)


def _binding() -> TenantBinding:
    return TenantBinding(
        tenant=TenantId(Attacks.TENANT),
        profile=ProfileRef(name="redteam", version="1.0.0"),
        config_hash=Hash("c" * 64),
    )


# ── The whole corpus, run ────────────────────────────────────────────────────


def test_the_harness_executor_actually_works() -> None:
    """Proves the compliant executor is reachable, so "nothing reached it" means something.

    Without this the corpus assertions are vacuous by construction, and they briefly
    were: an ``execute`` with the wrong signature raised inside the boundary before its
    body ran, ``calls`` stayed empty, and every "no attack reached the executor" test
    passed for a reason unrelated to the framework. The corpus was written to catch that
    class of defect; there is no reason to think the corpus is exempt from it.
    """
    executor = Upstream()
    result = _engine().execute(
        Attacks.authorised_transfer(AT), binding=_binding(), executor=executor
    )
    assert len(executor.calls) == 1, "the harness executor is unreachable, so it proves nothing"
    assert result.attestation.verdict is Verdict.ALLOW
    assert [e.state for e in result.attestation.effects] == [EffectState.COMMITTED]


def test_the_entire_shipped_corpus_runs_and_every_attack_is_stopped() -> None:
    """Seventeen adversarial proposals, against a real engine, in one assertion.

    A failure here means an attack the framework claims to stop got through. The report
    names which one, because "red team failed" is not actionable.
    """
    executor = Upstream()
    outcomes = RedTeamSuite.run(
        engine=_engine(), binding=_binding(), executor=executor, strict=True
    )

    assert len(outcomes) == len(RedTeamSuite.all_cases())
    failed = [outcome for outcome in outcomes if not outcome.passed]
    assert not failed, "\n" + "\n".join(outcome.render() for outcome in failed)


def test_no_attack_in_the_corpus_reaches_the_executor() -> None:
    """The outcome that matters most: nothing adversarial moved money.

    The executor here is deliberately compliant — it would do whatever it was asked —
    so anything reaching it is the framework having let the attack through.
    """
    executor = Upstream()
    RedTeamSuite.run(engine=_engine(), binding=_binding(), executor=executor)
    assert executor.calls == [], (
        f"{len(executor.calls)} adversarial proposals reached the executor: "
        f"{[a.tool for a in executor.calls]}"
    )


FAMILIES: list[Family] = sorted(Family, key=lambda f: f.value)


@pytest.mark.parametrize("family", FAMILIES, ids=[f.value for f in FAMILIES])
def test_each_family_has_a_case_that_runs_and_holds(family: Family) -> None:
    """Per family, so a failure names the threat rather than the suite."""
    cases = [c for c in RedTeamSuite.all_cases() if c.family is family]
    assert cases, f"no case declared for {family.value}"
    assert any(c.executable for c in cases), f"{family.value} is declared and cannot run"

    outcomes = RedTeamSuite.run(
        engine=_engine(), binding=_binding(), executor=Upstream(), cases=tuple(cases)
    )
    failed = [o for o in outcomes if not o.passed]
    assert not failed, "\n" + "\n".join(o.render() for o in failed)


# ── The suite reports honestly about itself ──────────────────────────────────


def test_a_case_with_no_attack_is_a_failure_not_a_skip() -> None:
    """A skip in a red-team report reads as a pass to everybody who did not write it."""
    declared_only = RedTeamCase(
        family=Family.INJECTION, name="declared and never run", must_not=(Verdict.ALLOW,)
    )
    outcomes = RedTeamSuite.run(
        engine=_engine(),
        binding=_binding(),
        cases=(declared_only,),
        strict=True,
    )
    assert not outcomes[0].passed
    assert "nothing was executed" in outcomes[0].detail


def test_the_runner_names_the_case_that_failed_not_merely_that_one_did() -> None:
    """ "Red team failed" is not actionable. Which case, and what was missing, is."""
    impossible = RedTeamCase(
        family=Family.INJECTION,
        name="an event nothing emits",
        must_emit=("no.such.event",),
        attack=lambda: Attacks.instruction_override(AT),
    )
    outcome = RedTeamSuite.run(
        engine=_engine(), binding=_binding(), cases=(impossible,), executor=Upstream()
    )[0]
    assert not outcome.passed
    assert "an event nothing emits" in outcome.render()
    assert "no.such.event" in outcome.detail


def test_a_forbidden_verdict_is_reported_against_the_case_that_produced_it() -> None:
    """The other failure path: the run decided something the case forbids."""
    inverted = RedTeamCase(
        family=Family.INJECTION,
        name="a case that forbids the right answer",
        must_not=(Verdict.REFUSE, Verdict.HOLD_FOR_APPROVAL, Verdict.ALLOW_WITH_WARNINGS),
        attack=lambda: Attacks.caller_asserted_approval(AT),
    )
    outcome = RedTeamSuite.run(
        engine=_engine(), binding=_binding(), cases=(inverted,), executor=Upstream()
    )[0]
    assert not outcome.passed
    assert "The attack succeeded" in outcome.detail
    assert outcome.verdict is not None


# ── What a profile is and is not allowed to soften ──────────────────────────


class Permissive(BaseProfile):
    """Records everything and blocks on nothing — the loosest posture expressible."""

    name, version = "permissive", "1.0.0"

    def warrant_policy(self, kind: Any) -> Any:
        from attest.kernel.warrants import WarrantPolicy

        return WarrantPolicy.RECORD


@pytest.mark.security
def test_the_loosest_possible_profile_cannot_downgrade_a_tenancy_crossing() -> None:
    """docs/kernel/tenancy.md: "There is no 'warn' setting for this."

    Before the corpus was given attacks to run, that sentence was true in the prose and
    false in the code: ``warrant_policy`` returned ``RECORD`` for ``BOUNDARY``, the
    resolver consulted it like any other policy, and a cross-tenant evidence read came
    back ``ALLOW_WITH_WARNINGS`` — a data leak reported as an answer with a note on it.
    Three review rounds read past it. The first execution of the corpus found it.
    """
    result = _engine(profile=Permissive()).execute(
        Attacks.cross_tenant_evidence(AT), binding=_binding(), executor=Upstream()
    )
    assert result.attestation.verdict is Verdict.REFUSE
    refusal = result.attestation.refusal
    assert refusal is not None
    assert refusal.reason == "tenancy_violation"
    assert "not downgradeable" in refusal.detail


@pytest.mark.security
def test_a_pending_approval_does_not_convert_a_tenancy_crossing_into_a_hold() -> None:
    """A hold offers a human a decision. This is not one they are allowed to make.

    Holding here would put "approve the cross-tenant read?" on somebody's screen, which
    is worse than refusing: it manufactures an audit trail in which a person authorised
    a leak.
    """
    request = Attacks.cross_tenant_evidence(AT)
    from dataclasses import replace

    held = replace(request, action=Attacks.misbound_action(AT).action)
    result = _engine(profile=Permissive()).execute(held, binding=_binding(), executor=Upstream())
    assert result.attestation.verdict is Verdict.REFUSE


@pytest.mark.security
def test_a_profile_may_still_soften_the_injection_signal() -> None:
    """The floor is per *finding*, and this is why that distinction is load-bearing.

    Injection detection is a heuristic with a known evasion rate and a known false-
    positive shape. A deployment has every right to record it rather than block on it.
    Flooring the whole BOUNDARY warrant would have forced that deployment to choose
    between drowning its reviewers and keeping the tenancy guarantee.
    """
    result = _engine(profile=Permissive()).execute(
        Attacks.instruction_override(AT), binding=_binding(), executor=Upstream()
    )
    assert result.attestation.verdict is not Verdict.REFUSE
    assert "boundary.injection_detected" in {e.event_type for e in result.events}


# ── Individual attacks, so a failure is diagnosable ─────────────────────────


@pytest.mark.parametrize(
    ("build", "why"),
    [
        (Attacks.fabricated_citation, "a citation that supplies its own source text"),
        (Attacks.unauthoritative_source, "content integrity is not source authority"),
        (Attacks.laundered_derivation, "a failing leaf under a plausible total"),
        (Attacks.stale_evidence, "superseded years before the decision"),
        (Attacks.no_evidence_at_all, "an assertion with nothing behind it"),
        (Attacks.contradictory_policy, "an answer no cited evidence supports"),
    ],
)
def test_an_unsupported_answer_never_reports_allow(build: Any, why: str) -> None:
    result = _engine().execute(build(AT), binding=_binding(), executor=Upstream())
    assert result.attestation.verdict is not Verdict.ALLOW, why


@pytest.mark.parametrize(
    "build",
    [Attacks.instruction_override, Attacks.delimiter_escape, Attacks.poisoned_memory],
    ids=["retrieved-document", "delimiter-escape", "recalled-directive"],
)
def test_an_injection_is_recorded_not_merely_survived(build: Any) -> None:
    """The deterministic gates stop the effect. The *record* is what makes it visible.

    An attack the system withstands and never mentions is invisible in the attestation
    and in every monitored signal built on the chain.
    """
    sink = InMemoryAuditSink()
    result = _engine(audit=sink).execute(build(AT), binding=_binding(), executor=Upstream())
    types = {event.event_type for event in result.events}
    assert "boundary.injection_detected" in types, sorted(types)


@pytest.mark.parametrize(
    ("build", "why"),
    [
        (Attacks.cross_tenant_evidence, "evidence belonging to another tenant"),
        (Attacks.misbound_action, "an action acting for another tenant"),
    ],
)
def test_a_tenant_boundary_is_never_crossed(build: Any, why: str) -> None:
    """There is no warn setting for this and a profile cannot downgrade it."""
    executor = Upstream()
    result = _engine().execute(build(AT), binding=_binding(), executor=executor)
    assert result.attestation.verdict not in (Verdict.ALLOW, Verdict.ALLOW_WITH_WARNINGS), why
    assert not executor.calls


@pytest.mark.parametrize(
    ("build", "why"),
    [
        (Attacks.caller_asserted_approval, "no recorded human decision exists"),
        (Attacks.missing_capability, "the actor does not hold the capability"),
        (Attacks.unbounded_spend, "no ceiling could cover it"),
    ],
)
def test_an_unauthorised_effect_never_reaches_the_upstream(build: Any, why: str) -> None:
    executor = Upstream()
    result = _engine().execute(build(AT), binding=_binding(), executor=executor)
    assert not executor.calls, why
    effects = result.attestation.effects
    assert all(e.state is not EffectState.COMMITTED for e in effects)


def test_the_same_proposal_twice_does_not_move_money_twice() -> None:
    """The outcome, not the mechanism. Whatever stops it, the second must not commit."""
    executor = Upstream()
    built = _engine()
    for _ in range(2):
        built.execute(Attacks.replayed_grant(AT), binding=_binding(), executor=executor)
    assert len(executor.calls) <= 1, "one proposal executed twice"


def test_a_truncated_retrieval_does_not_report_a_clean_allow() -> None:
    """An answer from the first 20 of 4,312 matches is an answer about the first 20."""
    result = _engine().execute(
        Attacks.truncated_retrieval(AT), binding=_binding(), executor=Upstream()
    )
    assert result.attestation.verdict is not Verdict.ALLOW
