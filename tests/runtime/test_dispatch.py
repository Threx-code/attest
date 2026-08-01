"""The worker half of queued dispatch: what it re-checks, and what it must not abandon.

The envelope is the only thing standing between a queued run and the engine, because
``build_request`` runs here against a host-shaped payload. Whatever it fails to check is
unchecked.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast

import pytest

from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import ActorId, RunId, TenantId
from attest.runtime.dispatch import QueuedDispatch, RunEnvelope, RunTicket, RunWorker

if TYPE_CHECKING:
    from attest.kernel.context import TenantBinding
    from attest.kernel.ports import RunWorkQueue
    from attest.runtime.engine import RunEngine, RunRequest

pytestmark = pytest.mark.unit

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


class Clock:
    def now(self) -> datetime:
        return AT


class Queue:
    """A work queue that records how it was settled."""

    def __init__(self, envelopes: tuple[bytes, ...] = ()) -> None:
        self.envelopes = list(envelopes)
        self.settled: list[tuple[str, str, str]] = []
        self.submitted: list[tuple[str, bytes]] = []
        self.resumed: list[str] = []

    def submit(self, run_id: RunId, envelope: bytes) -> str:
        self.submitted.append((str(run_id), envelope))
        return f"queued:{run_id}"

    def resume(self, run_id: RunId) -> str:
        self.resumed.append(str(run_id))
        return f"resumed:{run_id}"

    def fetch(self, run_id: RunId) -> bytes | None:
        for index, raw in enumerate(self.envelopes):
            if RunEnvelope.decode(raw).run_id == run_id:
                return self.envelopes.pop(index)
        return None

    def claim(self, *, now: datetime | None = None, limit: int = 1) -> tuple[bytes, ...]:
        taken, self.envelopes = self.envelopes[:limit], self.envelopes[limit:]
        return tuple(taken)

    def settle(
        self, run_id: RunId, *, state: str, detail: str = "", now: datetime | None = None
    ) -> None:
        self.settled.append((str(run_id), state, detail))


class Result:
    def __init__(self, verdict: Any) -> None:
        self.verdict = verdict


class Engine:
    def __init__(self, *, verdict: Any = None) -> None:
        from attest.kernel.verdicts import Verdict

        self.verdict = verdict if verdict is not None else Verdict.ALLOW
        self.calls: list[RunId] = []

    def execute(self, proposal: Any, **kwargs: Any) -> Result:
        self.calls.append(cast("RunId", kwargs.get("run_id")))
        return Result(self.verdict)


class Proposal:
    def __init__(self, actor: str = "alice", tenant: str = "t1") -> None:
        self.actor = ActorId(actor)
        self.tenant = TenantId(tenant)


def envelope(run_id: str = "run_1", actor: str = "alice", tenant: str = "t1") -> bytes:
    return RunEnvelope(
        run_id=RunId(run_id),
        actor=ActorId(actor),
        tenant=TenantId(tenant),
        payload={"claim": "8823"},
        submitted_at=AT,
    ).encode()


# ── Submission ───────────────────────────────────────────────────────────────


def test_submitting_returns_a_ticket_and_runs_nothing() -> None:
    """A response carrying a verdict for a run no warrant has evaluated is worse than none."""
    queue = Queue()
    ticket = QueuedDispatch(queue, clock=Clock()).submit(
        run_id=RunId("run_1"),
        actor=ActorId("alice"),
        tenant=TenantId("t1"),
        payload={"claim": "8823"},
    )
    assert isinstance(ticket, RunTicket)
    assert ticket.as_dict()["status"] == "queued"
    assert queue.submitted[0][0] == "run_1"


def test_the_ticket_carries_the_run_id_the_caller_will_poll() -> None:
    ticket = QueuedDispatch(Queue(), clock=Clock()).submit(
        run_id=RunId("run_7"), actor=ActorId("a"), tenant=TenantId("t"), payload={}
    )
    assert ticket.as_dict()["run_id"] == "run_7"
    assert ticket.submitted_at == AT


# ── What the worker re-checks ────────────────────────────────────────────────


@pytest.mark.security
def test_a_proposal_that_changes_the_tenant_is_refused() -> None:
    """The tenant check happened at submission, against the caller."""
    with pytest.raises(ContractViolation, match="authorised for tenant"):
        QueuedDispatch.execute(
            envelope(),
            engine=cast("RunEngine", Engine()),
            builder=lambda _env: cast("RunRequest", Proposal(tenant="other")),
            binding=lambda _env: cast("TenantBinding", object()),
        )


@pytest.mark.security
def test_a_proposal_that_changes_the_actor_is_refused() -> None:
    """ATT-39. Only the tenant was checked, and the docstring claimed both were.

    `build_request` runs in the worker against a host-shaped payload, so a proposal
    could name any actor within the tenant — and the engine's own binding check compares
    the action's actor to the context's actor, both taken from that same proposal, so
    they agree. Horizontal escalation inside a tenant, with the capabilities built from
    the payload too.
    """
    with pytest.raises(ContractViolation, match="submitted by"):
        QueuedDispatch.execute(
            envelope(actor="alice"),
            engine=cast("RunEngine", Engine()),
            builder=lambda _env: cast("RunRequest", Proposal(actor="privileged-ops")),
            binding=lambda _env: cast("TenantBinding", object()),
        )


def test_a_matching_proposal_runs_under_the_queued_run_id() -> None:
    engine = Engine()
    QueuedDispatch.execute(
        envelope(),
        engine=cast("RunEngine", engine),
        builder=lambda _env: cast("RunRequest", Proposal()),
        binding=lambda _env: cast("TenantBinding", object()),
    )
    assert engine.calls == [RunId("run_1")]


def test_the_executor_factory_is_consulted_when_supplied() -> None:
    seen: list[RunEnvelope] = []

    def remember(env: RunEnvelope) -> object:
        seen.append(env)
        return object()

    QueuedDispatch.execute(
        envelope(),
        engine=cast("RunEngine", Engine()),
        builder=lambda _env: cast("RunRequest", Proposal()),
        binding=lambda _env: cast("TenantBinding", object()),
        executor=remember,
    )
    assert len(seen) == 1
    assert seen[0].run_id == RunId("run_1")


# ── The worker settles, always ───────────────────────────────────────────────


def _worker(queue: Queue, engine: Engine, *, builder: Any = None) -> RunWorker:
    """The fakes stand in for the real collaborators. Cast at the seam, deliberately.

    What is under test is the worker's own behaviour — what it re-checks, what it
    settles, what it must not abandon — and a real engine would drag a profile, stores
    and an executor into a test about none of those.
    """
    return RunWorker(
        queue=cast("RunWorkQueue", queue),
        engine=cast("RunEngine", engine),
        builder=builder or (lambda _env: cast("RunRequest", Proposal())),
        binding=lambda _env: cast("TenantBinding", object()),
    )


def test_a_completed_run_is_settled_done() -> None:
    queue = Queue((envelope(),))
    _worker(queue, Engine()).run_one(RunId("run_1"))
    assert queue.settled == [("run_1", "done", "allow")]


def test_a_held_run_is_settled_held_so_a_resumption_can_find_it() -> None:
    from attest.kernel.verdicts import Verdict

    queue = Queue((envelope(),))
    _worker(queue, Engine(verdict=Verdict.HOLD_FOR_APPROVAL)).run_one(RunId("run_1"))
    assert queue.settled[0][1] == "held"


@pytest.mark.security
def test_a_duplicate_notification_finds_nothing_to_do() -> None:
    """Brokers deliver at least once; running the effect twice because of one is not on."""
    queue = Queue((envelope(),))
    worker = _worker(queue, Engine())
    assert worker.run_one(RunId("run_1")) is not None
    assert worker.run_one(RunId("run_1")) is None


@pytest.mark.security
def test_a_run_that_raises_is_settled_failed_rather_than_left_running() -> None:
    """A row left in `running` forever is neither retryable nor visibly failed."""

    def explode(_env: RunEnvelope) -> Any:
        raise RuntimeError("builder is broken")

    queue = Queue((envelope(),))
    with pytest.raises(RuntimeError):
        _worker(queue, Engine(), builder=explode).run_one(RunId("run_1"))
    assert queue.settled[0][1] == "failed"
    assert "RuntimeError" in queue.settled[0][2]


@pytest.mark.security
def test_one_poison_envelope_does_not_strand_the_rest_of_its_batch() -> None:
    """ATT-41. A generator expression aborted on the first exception.

    Every envelope already claimed in that batch was left in `running` with a lease and
    no worker, recovered only when reclaim_expired runs — one lease later.
    """
    queue = Queue((envelope("run_bad"), envelope("run_ok_1"), envelope("run_ok_2")))

    def builder(env: RunEnvelope) -> Any:
        if env.run_id == RunId("run_bad"):
            raise RuntimeError("poison")
        return Proposal()

    results = _worker(queue, Engine(), builder=builder).drain(limit=3)
    assert len(results) == 2, "the siblings of the failing envelope were abandoned"
    settled = {run_id: state for run_id, state, _ in queue.settled}
    assert settled == {"run_bad": "failed", "run_ok_1": "done", "run_ok_2": "done"}


def test_draining_an_empty_queue_is_not_an_error() -> None:
    assert _worker(Queue(), Engine()).drain(limit=5) == ()


def test_resume_goes_through_the_queue() -> None:
    queue = Queue()
    assert QueuedDispatch(queue, clock=Clock()).resume(RunId("run_1")) == "resumed:run_1"
    assert queue.resumed == ["run_1"]


# ── The envelope ─────────────────────────────────────────────────────────────


def test_an_envelope_without_a_run_id_is_refused() -> None:
    with pytest.raises(ContractViolation, match="without a run id"):
        RunEnvelope(
            run_id=RunId(""),
            actor=ActorId("a"),
            tenant=TenantId("t"),
            payload={},
            submitted_at=AT,
        )


def test_an_attempt_below_one_is_refused() -> None:
    with pytest.raises(ContractViolation, match="attempt must be"):
        RunEnvelope(
            run_id=RunId("r"),
            actor=ActorId("a"),
            tenant=TenantId("t"),
            payload={},
            submitted_at=AT,
            attempt=0,
        )


def test_next_attempt_preserves_the_proposal() -> None:
    original = RunEnvelope.decode(envelope())
    resumed = original.next_attempt()
    assert resumed.attempt == 2
    assert resumed.payload == original.payload
    assert resumed.run_id == original.run_id


def test_a_payload_that_is_not_a_mapping_is_refused() -> None:
    from attest.kernel.canonical import Canonical

    bad = Canonical.encode(
        {
            "run_id": "r",
            "actor": "a",
            "tenant": "t",
            "payload": ["not", "a", "mapping"],
            "submitted_at": AT,
        }
    )
    with pytest.raises(ContractViolation, match="payload must be a mapping"):
        RunEnvelope.decode(bad)


def test_an_envelope_that_is_not_a_mapping_at_all_is_refused() -> None:
    from attest.kernel.canonical import Canonical

    with pytest.raises(ContractViolation, match="must decode to a mapping"):
        RunEnvelope.decode(Canonical.encode(["not", "an", "envelope"]))


# ── Resumption: a held run must actually be resumable ────────────────────────


def test_a_resumed_attempt_runs_under_its_own_attestation_id() -> None:
    """The approval loop did not work at all, and nothing tested the second attempt.

    Attestations are immutable — ``RunStore`` has no ``update``, deliberately, because a
    reader who relied on the held record must still be able to see what they relied on.
    The worker executed *every* attempt under ``envelope.run_id``, so the second one hit
    ``StoreError: attestation already exists`` and the run died. That second attempt is
    the resume path: a run holds, a human approves, ``resume`` re-dispatches, and the
    worker raises. Every held run was unresumable in any deployment that keeps records,
    which is every deployment this framework is for.
    """
    engine = Engine()
    raw = RunEnvelope.decode(envelope()).next_attempt().encode()
    QueuedDispatch.execute(
        raw,
        engine=cast("RunEngine", engine),
        builder=lambda _env: cast("RunRequest", Proposal()),
        binding=lambda _env: cast("TenantBinding", object()),
    )
    assert engine.calls == [RunId("run_1#2")], (
        "the second attempt reused the first attempt's attestation id, so the store "
        "refuses it and the held run can never be resumed"
    )


def test_a_resumed_attempt_supersedes_the_one_it_replaces() -> None:
    """Both records are retained, and the link is what makes the sequence orderable."""
    seen: list[dict[str, Any]] = []

    class Recording(Engine):
        def execute(self, proposal: Any, **kwargs: Any) -> Result:
            seen.append(dict(kwargs))
            return super().execute(proposal, **kwargs)

    envelopes = RunEnvelope.decode(envelope())
    for _ in range(2):
        envelopes = envelopes.next_attempt()
        QueuedDispatch.execute(
            envelopes.encode(),
            engine=cast("RunEngine", Recording()),
            builder=lambda _env: cast("RunRequest", Proposal()),
            binding=lambda _env: cast("TenantBinding", object()),
        )

    assert [call["run_id"] for call in seen] == [RunId("run_1#2"), RunId("run_1#3")]
    assert [call["supersedes"] for call in seen] == [RunId("run_1"), RunId("run_1#2")]


def test_the_first_attempt_still_writes_under_the_ticket_the_caller_holds() -> None:
    """Otherwise a caller polls an id that will never exist."""
    engine = Engine()
    QueuedDispatch.execute(
        envelope(),
        engine=cast("RunEngine", engine),
        builder=lambda _env: cast("RunRequest", Proposal()),
        binding=lambda _env: cast("TenantBinding", object()),
    )
    assert engine.calls == [RunId("run_1")]


def test_the_dispatch_is_recoverable_from_any_attempt_id() -> None:
    """What keeps the pending-approval row stable across a hold/resume/hold cycle."""
    from attest.kernel.identifiers import RunIds

    assert RunIds.dispatch_of(RunId("run_1")) == RunId("run_1")
    assert RunIds.dispatch_of(RunId("run_1#2")) == RunId("run_1")
    assert RunIds.dispatch_of(RunId("run_1#17")) == RunId("run_1")
    # Idempotent, so a caller that normalises twice does not corrupt the id.
    assert RunIds.dispatch_of(RunIds.dispatch_of(RunId("run_1#2"))) == RunId("run_1")
