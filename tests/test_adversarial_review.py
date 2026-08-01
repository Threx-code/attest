"""Regressions from the adversarial review of the provider / engine / adapter work.

Each test below corresponds to a defect that was **present and reachable** in the
implementation, found by attacking it rather than by reading it. They are kept together
because that is how they were found — the value is in the class of mistake, not in the
individual line.

The three that mattered:

*A refusal written over money that moved.* ``VerdictResolver`` could return ``REFUSE``
for a run whose effect had already committed, because the provenance warrant is
evaluated after sealing and sealing happens after the effect. ``REFUSE`` means nothing
happened; the kernel's own docstring says so.

*A run bound to one tenant executing for another.* Nothing tied ``Action.tenant`` to the
run's identity. The grant took its tenant *from the action*, so every downstream check
compared the action against itself and agreed.

*A reservation id that came back around.* Derived from a count of live reservations,
which falls when one is released — so a swept-and-woken worker could commit against
whichever reservation now held its id.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from attest.adapters.memory import InMemoryAuditSink, InMemoryNonceStore
from attest.capabilities.authority import AuthorityEngine, CapabilityCheck, ObligationSet
from attest.capabilities.execution import EffectOutcome, ExecutionBoundary, ExecutionRefused
from attest.kernel.actions import Action
from attest.kernel.attestation import Attestation, AttestationError, EffectRecord
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.effects import (
    WORLD_REACHING_EFFECT_STATES,
    EffectClasses,
    EffectSemantics,
    EffectState,
    IdempotencyMode,
)
from attest.kernel.identifiers import ActorId, GrantId, Hash, Nonce, RunId, TenantId
from attest.kernel.verdicts import Verdict
from attest.kernel.warrants import (
    Finding,
    Severity,
    WarrantKinds,
    WarrantPolicy,
    WarrantReport,
    WarrantStatus,
)
from attest.runtime.engine import RunEngine, RunRequest, VerdictResolver

pytestmark = pytest.mark.security

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
ACTOR = ActorId("alice")
TENANT = TenantId("t1")


class Clock:
    def now(self) -> datetime:
        return AT


class Ids:
    def __init__(self) -> None:
        self._n = 0

    def new_id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}_{self._n}"


class Upstream:
    def __init__(self) -> None:
        self.calls: list[Action] = []

    def execute(self, action: Action, context: ExecutionContext) -> EffectOutcome:
        self.calls.append(action)
        return EffectOutcome(external_reference="fp-777")


def context(tenant: str = "t1", actor: str = "alice") -> ExecutionContext:
    return ExecutionContext(
        run_id=RunId("run_1"),
        captured_at=AT,
        identity=IdentitySnapshot(
            actor=ActorId(actor),
            tenant=TenantId(tenant),
            capabilities=frozenset({"transfer"}),
        ),
        binding=TenantBinding(
            tenant=TenantId(tenant),
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="2026.07",
    )


def transfer(tenant: str = "t1", actor: str = "alice") -> Action:
    return Action(
        tool="transfer_funds",
        actor=ActorId(actor),
        tenant=TenantId(tenant),
        arguments={"amount": "500000.00", "to": "acct-9"},
        semantics=EffectSemantics(reversible=False),
        idempotency=IdempotencyMode.KEYED,
        effects=frozenset({EffectClasses.FINANCIAL}),
        capability="transfer",
    )


def committed() -> EffectRecord:
    return EffectRecord(
        action=transfer(),
        state=EffectState.COMMITTED,
        grant_id=GrantId("g1"),
        external_reference="fp-777",
    )


def report(kind: str, *, satisfied: bool) -> WarrantReport:
    return WarrantReport(
        kind=kind,  # type: ignore[arg-type]
        status=WarrantStatus.EVALUATED,
        satisfied=satisfied,
    )


# ── A: a refusal written over money that moved ───────────────────────────────


def test_an_attestation_cannot_refuse_over_an_effect_that_reached_the_world() -> None:
    """Unrepresentable, not merely resolved around.

    A host that assembles its own attestation gets the same guarantee the engine does.
    """
    with pytest.raises(AttestationError, match="REFUSE"):
        Attestation(
            run_id=RunId("run_1"),
            verdict=Verdict.REFUSE,
            context=context(),
            created_at=AT,
            effects=(committed(),),
            refusal=None,
        )


@pytest.mark.parametrize("state", sorted(WORLD_REACHING_EFFECT_STATES))
def test_every_world_reaching_state_blocks_a_refusal(state: EffectState) -> None:
    """SUBMITTED and UNKNOWN count too — we cannot say the request was not seen."""
    record = EffectRecord(
        action=transfer(),
        state=state,
        grant_id=GrantId("g1"),
        external_reference="fp-777",
        submitted_at=AT,
    )
    with pytest.raises(AttestationError, match="REFUSE"):
        Attestation(
            run_id=RunId("run_1"),
            verdict=Verdict.REFUSE,
            context=context(),
            created_at=AT,
            effects=(record,),
        )


def test_a_proposed_effect_still_permits_a_refusal() -> None:
    """Nothing left the building, so "nothing happened" is the truth."""
    from attest.kernel.verdicts import Refusal, RefusalReason

    attestation = Attestation(
        run_id=RunId("run_1"),
        verdict=Verdict.REFUSE,
        context=context(),
        created_at=AT,
        effects=(EffectRecord(action=transfer(), state=EffectState.PROPOSED),),
        refusal=Refusal(reason=RefusalReason("insufficient_authority"), detail="no capability"),
    )
    assert attestation.verdict is Verdict.REFUSE


def test_a_failed_warrant_after_a_committed_effect_resolves_to_incomplete() -> None:
    """The resolver's answer, and it must agree with what the kernel will accept."""
    reports = {
        WarrantKinds.AUTHORITY: report(WarrantKinds.AUTHORITY, satisfied=True),
        WarrantKinds.PROVENANCE: report(WarrantKinds.PROVENANCE, satisfied=False),
    }
    verdict, refusal = VerdictResolver().resolve(
        reports=reports,
        policies=dict.fromkeys(reports, WarrantPolicy.BLOCK),
        effects=[committed()],
    )
    assert verdict is Verdict.INCOMPLETE
    assert refusal is not None
    assert refusal.warrant == WarrantKinds.PROVENANCE
    # And the pair the resolver produced must be constructible.
    Attestation(
        run_id=RunId("run_1"),
        verdict=verdict,
        context=context(),
        created_at=AT,
        effects=(committed(),),
        refusal=refusal,
        warrants=reports,
    )


def test_incomplete_requires_human_attention_where_refuse_does_not() -> None:
    """The whole reason the distinction is load-bearing: different human responses."""
    assert Verdict.INCOMPLETE.requires_human_attention
    assert not Verdict.REFUSE.requires_human_attention


# ── B: a run bound to one tenant acting for another ──────────────────────────


def test_a_grant_is_not_issued_for_an_action_belonging_to_another_tenant() -> None:
    """The mint point, and the only place that holds both the action and the run."""
    engine = AuthorityEngine()
    foreign = transfer(tenant="t2")
    result = engine.discharge(ObligationSet((CapabilityCheck("transfer"),)), foreign, context())
    assert result.satisfied, "the capability check alone cannot see the mismatch"
    with pytest.raises(ValueError, match="tenant"):
        engine.issue(
            grant_id=GrantId("g1"),
            nonce=Nonce("n1"),
            action=foreign,
            context=context(),
            result=result,
            now=AT,
        )


def test_a_grant_is_not_issued_for_an_action_naming_another_actor() -> None:
    """The capability check discharged against the dispatching actor's capabilities."""
    engine = AuthorityEngine()
    foreign = transfer(actor="mallory")
    result = engine.discharge(ObligationSet((CapabilityCheck("transfer"),)), foreign, context())
    with pytest.raises(ValueError, match="actor"):
        engine.issue(
            grant_id=GrantId("g1"),
            nonce=Nonce("n1"),
            action=foreign,
            context=context(),
            result=result,
            now=AT,
        )


def test_the_boundary_refuses_a_foreign_action_even_with_a_matching_grant() -> None:
    """Deliberately redundant with the mint check — this is the last gate.

    The grant is built here the way a bypassed mint would build it, so it agrees with
    the action perfectly. Only the context disagrees, and only the boundary can see it.
    """
    foreign = transfer(tenant="t2")
    engine = AuthorityEngine()
    result = engine.discharge(ObligationSet((CapabilityCheck("transfer"),)), foreign, context("t2"))
    grant = engine.issue(
        grant_id=GrantId("g1"),
        nonce=Nonce("n1"),
        action=foreign,
        context=context("t2"),
        result=result,
        now=AT,
    )
    assert not grant.check_against(foreign, now=AT).rejections, "the grant itself is valid"

    upstream = Upstream()
    boundary = ExecutionBoundary(nonces=InMemoryNonceStore(), audit=InMemoryAuditSink())
    with pytest.raises(ExecutionRefused, match="tenant"):
        boundary.execute(
            action=foreign,
            grant=grant,
            context=context("t1"),
            executor=upstream,
            now=AT,
        )
    assert upstream.calls == [], "and nothing reached the upstream"


def test_the_engine_records_a_refusal_rather_than_raising_on_a_foreign_action() -> None:
    """If an attestation can be produced, it is a refusal — not an exception.

    An exception here would discard the evidence, the warrants and the reason at
    exactly the moment they are most wanted.
    """
    upstream = Upstream()
    engine = RunEngine(
        clock=Clock(),
        ids=Ids(),
        audit=InMemoryAuditSink(),
        nonces=InMemoryNonceStore(),
        brand="acme",
    )
    result = engine.execute(
        RunRequest(
            actor=ACTOR,
            tenant=TENANT,
            capabilities=frozenset({"transfer"}),
            action=transfer(tenant="t2"),
        ),
        binding=TenantBinding(
            tenant=TENANT,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        executor=upstream,
    )
    assert upstream.calls == []
    assert result.attestation.effects[0].state is EffectState.PROPOSED
    assert not result.attestation.warrant(WarrantKinds.AUTHORITY).is_satisfied()
    assert result.attestation.seal is not None, "and the run is still attested"
    assert "boundary.tenancy_violation" in [e.event_type for e in result.events]


# ── D: a guard that `python -O` would remove ─────────────────────────────────


def test_the_engine_ships_no_asserts() -> None:
    """`python -O` strips asserts, and one of these stood between a grant and a crash."""
    import pathlib

    source = pathlib.Path("src/attest/runtime/engine.py").read_text(encoding="utf-8")
    assert "\n        assert " not in source
    assert "\n    assert " not in source


# ── F: one definition of what counts as a warning ────────────────────────────


def test_the_qualifications_a_reader_must_see_are_defined_once() -> None:
    """Two copies of this rule drift until one quietly stops surfacing something."""
    report_with_findings = WarrantReport(
        kind=WarrantKinds.EPISTEMIC,
        status=WarrantStatus.EVALUATED,
        satisfied=True,
        findings=(
            Finding(code="a", message="shown", severity=Severity.WARNING),
            Finding(code="b", message="also shown", severity=Severity.ERROR),
            Finding(code="c", message="not shown", severity=Severity.INFO),
        ),
    )
    assert report_with_findings.qualifications() == ("shown", "also shown")


# ── F2/F4: the two ways money moves twice or untraceably ─────────────────────


def test_effect_events_are_durable_before_the_external_call() -> None:
    """A crash between the payment committing and the run finalising left nothing.

    Not a dangling SUBMITTED — no audit record at all, and the reconciliation sweep
    the boundary points at had nothing to find. The sink was held and never read.
    """
    from attest.capabilities.execution import ExecutionBoundary

    sink = InMemoryAuditSink()
    engine = AuthorityEngine()
    action = transfer()
    result = engine.discharge(ObligationSet((CapabilityCheck("transfer"),)), action, context())
    grant = engine.issue(
        grant_id=GrantId("g1"),
        nonce=Nonce("n1"),
        action=action,
        context=context(),
        result=result,
        now=AT,
        idempotency_key="invoice-1",
    )

    class Crashes:
        def execute(self, action: Action, ctx: ExecutionContext) -> EffectOutcome:
            raise RuntimeError("the process died mid-call")

    boundary = ExecutionBoundary(nonces=InMemoryNonceStore(), audit=sink)
    record = boundary.execute(
        action=action, grant=grant, context=context(), executor=Crashes(), now=AT
    )

    written = [event.event_type for event in sink.read_chain(RunId("run_1"))]
    assert "effect.submitted" in written, "the intent must survive the call"
    assert "effect.failed" in written
    assert record.state is EffectState.FAILED


def test_an_event_is_never_written_to_the_chain_twice() -> None:
    """The boundary writes durably; the recorder must not write those again.

    A chain with duplicates cannot be sealed densely, which is indistinguishable from
    omission — the exact condition the seal exists to detect.
    """
    sink = InMemoryAuditSink()
    engine = RunEngine(
        clock=Clock(), ids=Ids(), audit=sink, nonces=InMemoryNonceStore(), brand="acme"
    )
    result = engine.execute(
        RunRequest(
            actor=ACTOR,
            tenant=TENANT,
            capabilities=frozenset({"transfer"}),
            action=transfer(),
            idempotency_key="invoice-2",
        ),
        binding=TenantBinding(
            tenant=TENANT,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        executor=Upstream(),
    )
    stored = sink.read_chain(result.attestation.run_id)
    types = [event.event_type for event in stored]
    assert len(types) == len(result.events)
    assert not [t for t in set(types) if types.count(t) > 1]
    assert all(event.sequence is None for event in stored), "stored unsealed, per ADR 0034"


def test_a_repeated_action_reports_the_original_outcome_rather_than_repeating_it() -> None:
    """The nonce defends one grant. A retry produces a *new* grant, and executed again.

    For a framework whose thesis is that no consequential effect executes without
    authorisation, double-submit is the likeliest production failure and is not an
    authorisation failure at all.
    """
    from attest.adapters.memory import InMemoryIdempotencyStore

    idempotency = InMemoryIdempotencyStore()
    upstream = Upstream()

    def run(nonce: str) -> Any:
        engine = RunEngine(
            clock=Clock(),
            ids=Ids(),
            audit=InMemoryAuditSink(),
            nonces=InMemoryNonceStore(),
            idempotency=idempotency,
            brand="acme",
        )
        return engine.execute(
            RunRequest(
                actor=ACTOR,
                tenant=TENANT,
                capabilities=frozenset({"transfer"}),
                action=transfer(),
                idempotency_key="invoice-3",
            ),
            binding=TenantBinding(
                tenant=TENANT,
                profile=ProfileRef(name="generic", version="1.0.0"),
                config_hash=Hash("c" * 64),
            ),
            executor=upstream,
            run_id=RunId(nonce),
        )

    first = run("run_a")
    second = run("run_b")
    assert len(upstream.calls) == 1, "the upstream must be called exactly once"
    assert first.attestation.effects[0].external_reference == "fp-777"
    assert second.attestation.effects[0].external_reference == "fp-777"
    assert second.attestation.effects[0].state is EffectState.COMMITTED


def test_a_keyed_action_without_a_key_is_refused_rather_than_run_unguarded() -> None:
    """KEYED means safe to repeat *only* under a key. Without one, a retry repeats it."""
    engine = RunEngine(
        clock=Clock(),
        ids=Ids(),
        audit=InMemoryAuditSink(),
        nonces=InMemoryNonceStore(),
        brand="acme",
    )
    upstream = Upstream()
    result = engine.execute(
        RunRequest(
            actor=ACTOR,
            tenant=TENANT,
            capabilities=frozenset({"transfer"}),
            action=transfer(),
        ),
        binding=TenantBinding(
            tenant=TENANT,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        executor=upstream,
    )
    assert upstream.calls == []
    assert result.attestation.effects[0].state is EffectState.REFUSED


def test_a_key_claimed_for_a_different_action_is_refused() -> None:
    """The same key meaning two actions is a collision the caller has to fix."""
    from attest.adapters.memory import InMemoryIdempotencyStore
    from attest.kernel.errors import StoreError

    store = InMemoryIdempotencyStore()
    assert store.claim("k", tenant="t1", action_hash=Hash("a" * 64), now=AT) is None
    store.settle("k", tenant="t1", external_reference="fp-1")
    with pytest.raises(StoreError, match="different action"):
        store.claim("k", tenant="t1", action_hash=Hash("b" * 64), now=AT)


def test_an_in_flight_key_is_neither_repeated_nor_reported_as_done() -> None:
    """Its outcome is unknown, so both answers are wrong. It is a reconciliation item."""
    from attest.adapters.memory import InMemoryIdempotencyStore
    from attest.kernel.errors import StoreError

    store = InMemoryIdempotencyStore()
    store.claim("k", tenant="t1", action_hash=Hash("a" * 64), now=AT)
    with pytest.raises(StoreError, match="in flight"):
        store.claim("k", tenant="t1", action_hash=Hash("a" * 64), now=AT)


def test_a_released_reservation_id_is_never_reissued_in_memory() -> None:
    """Finding 8: the Django adapter got this right and the reference adapters did not."""
    from attest.adapters.memory import InMemoryBudgetStore

    store = InMemoryBudgetStore()
    first = store.reserve("s", "10", AT)
    assert first is not None
    store.release(first)
    second = store.reserve("s", "10", AT)
    assert first != second


# ── F19: the scaffold destroyed the host's pyproject.toml ────────────────────


def test_the_scaffold_refuses_to_overwrite_an_existing_file(tmp_path: Path) -> None:
    """The quickstart is run in an existing repository, and it writes a pyproject.toml.

    Overwriting the single most valuable file in the directory, during a command whose
    purpose is to help someone get started, is the worst available outcome.
    """
    from attest.cli import ProfileScaffold

    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'the-hosts-own'\n")
    with pytest.raises(FileExistsError, match=re.escape("pyproject.toml")):
        ProfileScaffold("mortgage").write(tmp_path)
    assert "the-hosts-own" in (tmp_path / "pyproject.toml").read_text()


def test_the_scaffold_writes_nothing_at_all_when_it_would_clobber(tmp_path: Path) -> None:
    """A half-scaffolded tree is harder to recover from than none."""
    from attest.cli import ProfileScaffold

    (tmp_path / "pyproject.toml").write_text("[project]\n")
    with pytest.raises(FileExistsError):
        ProfileScaffold("mortgage").write(tmp_path)
    assert not (tmp_path / "mortgage_profile").exists()


def test_the_scaffold_overwrites_when_the_operator_asks(tmp_path: Path) -> None:
    from attest.cli import ProfileScaffold

    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'old'\n")
    ProfileScaffold("mortgage").write(tmp_path, force=True)
    assert "old" not in (tmp_path / "pyproject.toml").read_text()


def test_the_command_reports_the_refusal_rather_than_raising(tmp_path: Path) -> None:
    from attest.cli import CommandLine

    (tmp_path / "pyproject.toml").write_text("[project]\n")
    assert CommandLine.run(["new-profile", "mortgage", "--into", str(tmp_path)]) == 1


@pytest.mark.security
def test_an_idempotency_key_does_not_cross_tenants() -> None:
    """ATT-11. The key is business-derived, which is the class that collides.

    With one global namespace, tenant B claiming ``INV-000123`` for a trivial action
    made every subsequent run of tenant A carrying that key fail with a 500 — repeat
    across the key space to deny a tenant's whole payment run. And where the two
    actions hashed equal, the second tenant received the first's upstream payment
    reference and the effect was skipped.
    """
    from attest.adapters.memory import InMemoryIdempotencyStore

    store = InMemoryIdempotencyStore()
    assert store.claim("INV-000123", tenant="a", action_hash=Hash("a" * 64), now=AT) is None
    # A different tenant, same business key, a completely different action.
    assert store.claim("INV-000123", tenant="b", action_hash=Hash("b" * 64), now=AT) is None


@pytest.mark.security
def test_settling_one_tenants_key_does_not_answer_for_another() -> None:
    """Otherwise the second tenant is handed the first's upstream payment reference."""
    from attest.adapters.memory import InMemoryIdempotencyStore

    store = InMemoryIdempotencyStore()
    store.claim("INV-1", tenant="a", action_hash=Hash("a" * 64), now=AT)
    store.settle("INV-1", tenant="a", external_reference="upstream-ref-a")
    assert store.claim("INV-1", tenant="b", action_hash=Hash("a" * 64), now=AT) is None
