"""The Celery wrapper, without Celery.

The point of these is the failure ordering. Celery itself is not under test — a fake
app with ``send_task`` and ``task`` is enough, because what matters is what happens
when the broker is having a bad day: the envelope is already durable, so the run is
late rather than lost, and a late run must not read as a rejected request.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from attest.adapters.celery import AttestTasks, CeleryRunQueue, CeleryUnavailable
from attest.kernel.identifiers import ActorId, RunId, TenantId
from attest.runtime.dispatch import RunEnvelope

pytestmark = pytest.mark.unit

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


class FakeResult:
    id = "task-1"


class FakeApp:
    """Enough of a Celery app to exercise the ordering, and nothing more."""

    def __init__(self, *, explode: bool = False) -> None:
        self.sent: list[tuple[str, list[Any], dict[str, Any]]] = []
        self.registered: dict[str, Any] = {}
        self._explode = explode

    def send_task(self, name: str, args: list[Any], **options: Any) -> FakeResult:
        if self._explode:
            raise ConnectionError("broker unreachable")
        self.sent.append((name, args, options))
        return FakeResult()

    def task(self, **options: Any) -> Any:
        def register(fn: Any) -> Any:
            self.registered[options.get("name", fn.__name__)] = (fn, options)
            return fn

        return register


class MemoryQueue:
    """A durable queue, standing in for DjangoRunQueue."""

    def __init__(self) -> None:
        self.rows: dict[str, bytes] = {}
        self.resumed: list[str] = []

    def submit(self, run_id: RunId, envelope: bytes) -> str:
        if str(run_id) in self.rows:
            return f"duplicate:{run_id}"
        self.rows[str(run_id)] = envelope
        return f"queued:{run_id}"

    def resume(self, run_id: RunId) -> str:
        self.resumed.append(str(run_id))
        return f"resumed:{run_id}"


def envelope(run_id: str = "run_1") -> bytes:
    return RunEnvelope(
        run_id=RunId(run_id),
        actor=ActorId("alice"),
        tenant=TenantId("t1"),
        payload={},
        submitted_at=AT,
    ).encode()


# ── Construction refuses early ───────────────────────────────────────────────


def test_a_missing_app_is_refused_at_construction() -> None:
    """A queue that fails only on the first run fails in production, on the path it protects."""
    with pytest.raises(CeleryUnavailable, match="needs a Celery application"):
        CeleryRunQueue(None, MemoryQueue())


def test_something_that_is_not_an_app_is_refused() -> None:
    with pytest.raises(CeleryUnavailable, match="does not look like a Celery application"):
        CeleryRunQueue(object(), MemoryQueue())


# ── Persist first, notify second ─────────────────────────────────────────────


@pytest.mark.security
def test_the_envelope_is_durable_before_the_broker_is_told() -> None:
    durable = MemoryQueue()
    queue = CeleryRunQueue(FakeApp(), durable)
    ticket = queue.submit(RunId("run_1"), envelope())
    assert "run_1" in durable.rows
    assert "queued:run_1" in ticket
    assert "task:task-1" in ticket


@pytest.mark.security
def test_a_broker_outage_does_not_lose_or_reject_the_run() -> None:
    """The row is already durable, so raising here would make a late run look rejected.

    A caller told "failed" retries, and the retry is a second run proposing the same
    effect.
    """
    durable = MemoryQueue()
    queue = CeleryRunQueue(FakeApp(explode=True), durable)
    ticket = queue.submit(RunId("run_1"), envelope())
    assert "run_1" in durable.rows, "the run was lost when the broker was unreachable"
    assert "notify-failed:ConnectionError" in ticket


@pytest.mark.security
def test_a_duplicate_submit_does_not_notify_again() -> None:
    """Notifying twice runs it twice if the first notification was slow rather than lost."""
    app = FakeApp()
    queue = CeleryRunQueue(app, MemoryQueue())
    queue.submit(RunId("run_1"), envelope())
    queue.submit(RunId("run_1"), envelope())
    assert len(app.sent) == 1


def test_a_resumption_notifies_the_broker() -> None:
    app = FakeApp()
    durable = MemoryQueue()
    queue = CeleryRunQueue(app, durable)
    assert "resumed:run_1" in queue.resume(RunId("run_1"))
    assert durable.resumed == ["run_1"]
    assert len(app.sent) == 1


def test_a_routing_queue_is_passed_through() -> None:
    """Governed runs are slow; sharing a queue with fast tasks delays everything else."""
    app = FakeApp()
    CeleryRunQueue(app, MemoryQueue(), queue_name="attest").submit(RunId("run_1"), envelope())
    assert app.sent[0][2] == {"queue": "attest"}


# ── Registering on the host's app ────────────────────────────────────────────


class FakeWorker:
    def __init__(self, result: Any = None) -> None:
        self.result = result
        self.calls: list[str] = []

    def run_one(self, run_id: RunId) -> Any:
        self.calls.append(str(run_id))
        return self.result


class FakeResultObject:
    class verdict:
        value = "allow"


def test_the_task_registers_on_the_hosts_app_with_the_hosts_options() -> None:
    """Retry policy for a governed run is a deployment decision, not the framework's."""
    app = FakeApp()
    worker = FakeWorker(FakeResultObject())
    AttestTasks(app, worker).register(queue="attest", acks_late=True)
    assert "attest.run" in app.registered
    _, options = app.registered["attest.run"]
    assert options["acks_late"] is True
    assert options["queue"] == "attest"


def test_the_registered_task_runs_the_worker() -> None:
    app = FakeApp()
    worker = FakeWorker(FakeResultObject())
    AttestTasks(app, worker).register()
    task, _ = app.registered["attest.run"]
    assert task("run_1") == "allow"
    assert worker.calls == ["run_1"]


@pytest.mark.security
def test_a_duplicate_delivery_reports_nothing_to_do_rather_than_a_failure() -> None:
    """Brokers deliver at least once. A no-op must not look like something to retry."""
    app = FakeApp()
    AttestTasks(app, FakeWorker(None)).register()
    task, _ = app.registered["attest.run"]
    assert task("run_1") is None


def test_registering_without_a_worker_is_refused() -> None:
    """A worker that can dequeue and cannot run is worse than no registration."""
    with pytest.raises(CeleryUnavailable, match="needs a RunWorker"):
        AttestTasks(FakeApp(), object())


def test_registering_on_something_that_is_not_an_app_is_refused() -> None:
    with pytest.raises(CeleryUnavailable, match="does not look like a Celery application"):
        AttestTasks(object(), FakeWorker())
