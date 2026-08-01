"""Races that the design claims to survive. Red-team families 5 and 10.

These are the tests the earlier build could not have: they need a store implementing
atomic redemption and reserve-then-commit, which is why they land with the adapters
rather than with the capability that depends on them.

Every test here uses real threads and a barrier, so the operations genuinely overlap
rather than merely being written in an interleaved order.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import TypeVar

import pytest

from attest.adapters.memory import (
    InMemoryAuditSink,
    InMemoryBudgetStore,
    InMemoryNonceStore,
    InMemoryRunStore,
)
from attest.capabilities.execution import (
    EffectOutcome,
    ExecutionBoundary,
    ExecutionRefused,
)
from attest.kernel.actions import Action
from attest.kernel.attestation import Attestation
from attest.kernel.authority import AuthorizationGrant
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.errors import StoreError
from attest.kernel.identifiers import (
    ActorId,
    GrantId,
    Hash,
    Nonce,
    RunId,
    TenantId,
)
from attest.kernel.verdicts import Verdict

pytestmark = [pytest.mark.concurrency, pytest.mark.security]

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
ACME = TenantId("acme")
ALICE = ActorId("alice")
THREADS = 32
_R = TypeVar("_R")


def _context(run: str = "run_1") -> ExecutionContext:
    return ExecutionContext(
        run_id=RunId(run),
        captured_at=AT,
        identity=IdentitySnapshot(actor=ALICE, tenant=ACME, capabilities=frozenset({"pay"})),
        binding=TenantBinding(
            tenant=ACME,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )


def _action() -> Action:
    return Action(tool="transfer", actor=ALICE, tenant=ACME, arguments={"amount": "500000.00"})


def _grant(action: Action, context: ExecutionContext) -> AuthorizationGrant:
    return AuthorizationGrant(
        grant_id=GrantId("g1"),
        action_hash=action.action_hash(),
        actor=action.actor,
        tenant=action.tenant,
        tool=action.tool,
        nonce=Nonce("n1"),
        issued_at=AT,
        expires_at=AT + timedelta(seconds=30),
        policy_version=context.policy_version,
        profile_version=context.binding.profile.version,
        context_hash=context.content_hash(),
    )


def _run_together(fn: Callable[[int], _R], count: int = THREADS) -> list[_R]:
    """Run ``fn`` on ``count`` threads that all release from one barrier.

    The barrier matters: without it the pool would serialise short tasks and a
    'concurrent' test would pass against a store with no atomicity at all.
    """
    barrier = threading.Barrier(count)

    def worker(index: int) -> _R:
        barrier.wait()
        return fn(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(worker, range(count)))


# ── Grant redemption ─────────────────────────────────────────────────────────


def test_only_one_of_many_concurrent_redemptions_succeeds() -> None:
    # Threat-model attack 8. A read-then-write store would let several callers all
    # observe an unused nonce and all proceed.
    store = InMemoryNonceStore()
    results = _run_together(lambda i: store.redeem(Nonce("n1"), GrantId(f"g{i}")))
    assert sum(results) == 1


def test_a_concurrent_double_submit_executes_the_effect_exactly_once() -> None:
    # The end-to-end version: the same grant presented by many threads at once must
    # move money once.
    action, context = _action(), _context()
    grant = _grant(action, context)
    boundary = ExecutionBoundary(nonces=InMemoryNonceStore(), audit=InMemoryAuditSink())
    calls: list[int] = []
    lock = threading.Lock()

    class CountsCalls:
        def execute(self, a: Action, c: ExecutionContext) -> EffectOutcome:
            with lock:
                calls.append(1)
            return EffectOutcome(external_reference="pay-123")

    def attempt(_: int) -> str:
        try:
            record = boundary.execute(
                action=action,
                grant=grant,
                context=context,
                executor=CountsCalls(),
                now=AT,
            )
        except ExecutionRefused:
            return "refused"
        return record.state.value

    outcomes = _run_together(attempt)
    assert outcomes.count("committed") == 1
    assert outcomes.count("refused") == THREADS - 1
    assert sum(calls) == 1, "the external system must be called exactly once"


def test_distinct_nonces_all_redeem() -> None:
    # The guard must not be so strict that legitimate parallel work is blocked.
    store = InMemoryNonceStore()
    results = _run_together(lambda i: store.redeem(Nonce(f"n{i}"), GrantId(f"g{i}")))
    assert all(results)


# ── Budget reservation ───────────────────────────────────────────────────────


def test_concurrent_reservations_cannot_both_pass_the_same_ceiling() -> None:
    # Threat-model attack 9: two runs both read GBP 20,000 remaining, both pass, and
    # both spend GBP 18,000.
    store = InMemoryBudgetStore(ceilings={"payouts": "20000"})
    results = _run_together(
        lambda i: store.reserve("payouts", "18000", AT + timedelta(seconds=30), now=AT)
    )
    granted = [r for r in results if r is not None]
    assert len(granted) == 1


def test_reservations_are_held_against_the_ceiling_before_commit() -> None:
    # A reservation that only counted at commit would let every concurrent caller
    # through, which is the bug in a different disguise.
    store = InMemoryBudgetStore(ceilings={"payouts": "100"})
    first = store.reserve("payouts", "60", AT + timedelta(seconds=30), now=AT)
    second = store.reserve("payouts", "60", AT + timedelta(seconds=30), now=AT)
    assert first is not None
    assert second is None


def test_releasing_a_reservation_frees_the_headroom() -> None:
    store = InMemoryBudgetStore(ceilings={"payouts": "100"})
    first = store.reserve("payouts", "60", AT + timedelta(seconds=30), now=AT)
    assert first is not None
    store.release(first)
    assert store.reserve("payouts", "60", AT + timedelta(seconds=30), now=AT) is not None


def test_an_expired_reservation_does_not_hold_budget_forever() -> None:
    # A crashed run must not park the ceiling indefinitely.
    #
    # `reserve` excludes expired holds from the total in its own right, so this holds
    # whether or not the sweeper has run. It used to depend on the sweeper: between the
    # expiry and the next sweep the ceiling was enforced against money nobody was going
    # to move, and "the next sweep" is a schedule, not a guarantee.
    store = InMemoryBudgetStore(ceilings={"payouts": "100"})
    store.reserve("payouts", "90", AT - timedelta(seconds=1), now=AT - timedelta(seconds=2))
    assert store.expire_due(AT) == 1
    assert store.reserve("payouts", "90", AT + timedelta(seconds=30), now=AT) is not None


def test_committing_records_the_actual_spend() -> None:
    store = InMemoryBudgetStore(ceilings={"payouts": "100"})
    reservation = store.reserve("payouts", "60", AT + timedelta(seconds=30), now=AT)
    assert reservation is not None
    store.commit(reservation, "45")
    assert store.spent("payouts") == "45"


# ── Store immutability under concurrency ─────────────────────────────────────


def _attestation(run: str) -> Attestation:
    return Attestation(
        run_id=RunId(run), verdict=Verdict.ALLOW, context=_context(run), created_at=AT
    )


def test_only_one_concurrent_write_of_the_same_run_id_succeeds() -> None:
    # Attestations are immutable once written; a second create must not overwrite.
    store = InMemoryRunStore()

    def attempt(_: int) -> bool:
        try:
            store.create(_attestation("run_1"))
        except StoreError:
            return False
        return True

    assert sum(_run_together(attempt)) == 1


def test_concurrent_appends_all_land() -> None:
    # No event may be lost under concurrency: a missing one is indistinguishable
    # from omission when the chain is sealed.
    from attest.kernel.audit import AuditEvent, EventType

    sink = InMemoryAuditSink()

    def append(index: int) -> None:
        sink.append(
            AuditEvent(
                run_id=RunId("run_1"),
                event_type=EventType.TOOL_PROPOSED,
                occurred_at=AT,
                payload={"i": index},
            )
        )

    _run_together(append)
    assert len(sink.read_chain(RunId("run_1"))) == THREADS
