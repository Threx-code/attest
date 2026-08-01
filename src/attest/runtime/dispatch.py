"""Queued dispatch — the run leaves the request, and a held run leaves the worker.

.. code-block:: text

    SYNCHRONOUS                          QUEUED
    ─────────────────────────            ──────────────────────────────
    POST ──▶ guards                      POST ──▶ envelope persisted
             model calls  (2s)                    ticket returned  (2ms)
             the effect   (4s)                         │
             attestation                         worker picks it up
    ◀── 200, six seconds later           ◀── 202 with a run id

Two separate problems are solved here and they are often confused.

The first is **latency**: a run makes model calls and then an external effect, so a
worker held for the duration means peak throughput is bounded by the pool rather than
by anything the framework costs. Measured, the framework is ~0.4 ms of CPU per run; the
upstream is four orders of magnitude more.

The second is **held runs**, and it is the one that causes outages. A
``HOLD_FOR_APPROVAL`` that blocks a worker until a human clicks means the pool is sized
by how fast people answer email. On a busy Monday it is not sized at all. So the worker
*returns* on a hold, and approval submits the envelope again — the run resumes from the
proposal rather than from a parked thread.

**The envelope is the host's own payload, not a serialised ``RunRequest``.** That is
deliberate. ``build_request`` is where a host maps its request onto evidence,
capabilities and an action, and running it in the worker rather than the view means
there is exactly one such mapping. A framework that serialised ``RunRequest`` would
need a codec for every domain type a host puts in one, and would silently freeze the
mapping at submission time — so a fix to ``build_request`` would not apply to anything
already queued.
"""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from attest.kernel.canonical import Canonical
from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import ActorId, RunId, RunIds, TenantId
from attest.kernel.verdicts import Verdict

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from datetime import datetime

    from attest.kernel.context import TenantBinding
    from attest.kernel.ports import RunQueue, RunWorkQueue
    from attest.runtime.engine import RunEngine, RunRequest, RunResult

__all__ = ["QueuedDispatch", "RunEnvelope", "RunTicket", "RunWorker"]


@dataclass(frozen=True, slots=True)
class RunEnvelope:
    """Everything a worker needs to build and execute the proposal, and nothing more.

    ``actor`` and ``tenant`` are carried explicitly rather than left inside ``payload``
    because they are the ones the framework checks. A worker that had to dig them out
    of a host-shaped body would be parsing the payload to enforce the tenant boundary,
    and the boundary would then depend on the shape of a body the host is free to
    change.
    """

    run_id: RunId
    actor: ActorId
    tenant: TenantId
    payload: Mapping[str, Any]
    submitted_at: datetime
    attempt: int = 1
    """Which dispatch this is. A resumption increments it.

    Recorded so an operator can tell a run that was resumed twice from one that was
    retried by a client — the first is the approval loop working, the second is a
    client that did not trust the ticket it was given.
    """

    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ContractViolation(
                "an envelope without a run id cannot be made idempotent: a retried "
                "dispatch would become a second run proposing the same effect"
            )
        if self.attempt < 1:
            raise ContractViolation(f"attempt must be >= 1, got {self.attempt}")

    def encode(self) -> bytes:
        """Canonical bytes, so the same envelope is byte-identical on every submit.

        That is what lets a queue deduplicate a resubmission by content rather than by
        trusting a client to send the same id twice.
        """
        return Canonical.encode(
            {
                "run_id": self.run_id,
                "actor": self.actor,
                "tenant": self.tenant,
                "payload": self.payload,
                "submitted_at": self.submitted_at,
                "attempt": self.attempt,
                "metadata": dict(self.metadata),
            }
        )

    @classmethod
    def decode(cls, raw: bytes) -> RunEnvelope:
        """Rebuild an envelope. Raises rather than returning a partial one.

        A worker that ran a half-decoded envelope would execute a proposal nobody
        submitted, which is the one failure a queue must not have.
        """
        try:
            revived = Canonical.revive(json.loads(raw.decode("utf-8")))
        except Exception as exc:
            raise ContractViolation(f"could not decode a run envelope: {exc}") from exc
        if not isinstance(revived, dict):
            raise ContractViolation(
                f"a run envelope must decode to a mapping, got {type(revived).__name__}"
            )
        missing = {"run_id", "actor", "tenant", "payload", "submitted_at"} - set(revived)
        if missing:
            raise ContractViolation(
                f"run envelope is missing {sorted(missing)}; refusing to execute a "
                f"proposal that cannot say who it is for"
            )
        payload = revived["payload"]
        if not isinstance(payload, dict):
            raise ContractViolation("run envelope payload must be a mapping")
        return cls(
            run_id=RunId(str(revived["run_id"])),
            actor=ActorId(str(revived["actor"])),
            tenant=TenantId(str(revived["tenant"])),
            payload=payload,
            submitted_at=revived["submitted_at"],
            attempt=int(revived.get("attempt", 1)),
            metadata={str(k): str(v) for k, v in dict(revived.get("metadata", {})).items()},
        )

    def next_attempt(self) -> RunEnvelope:
        """The same proposal, dispatched again. Used by the resume path."""
        return RunEnvelope(
            run_id=self.run_id,
            actor=self.actor,
            tenant=self.tenant,
            payload=self.payload,
            submitted_at=self.submitted_at,
            attempt=self.attempt + 1,
            metadata=self.metadata,
        )

    def attestation_id(self) -> RunId:
        """Which run id **this attempt's** attestation is written under.

        The first attempt writes under the dispatch id, so the ticket a caller is
        holding resolves to a record. Every later attempt writes under a derived id and
        supersedes the one before it.

        Without this the approval loop did not work at all. The worker executed every
        attempt under ``envelope.run_id``, attestations are immutable by design — there
        is no ``update`` on ``RunStore``, deliberately — so the *second* attempt of any
        run raised ``StoreError: attestation already exists``. That is the resume path:
        a run holds, a human approves, ``resume`` re-dispatches, and the worker dies.
        Every held run was unresumable in any deployment with a run store wired, which
        is every deployment that keeps records.

        Derived rather than minted because the framework bans ambient identifiers — an
        id that differs on every execution cannot be replayed or diffed — and because
        ``run_7#2`` reads as the second attempt of ``run_7`` to a person looking at a
        row, where a fresh opaque id reads as an unrelated run.
        """
        return RunIds.attempt(self.run_id, self.attempt)

    def supersedes(self) -> RunId | None:
        """The attestation this attempt replaces. ``None`` on the first.

        Both records are retained — a reader who relied on the held attestation must
        still be able to see exactly what they relied on — and the link is what makes
        the sequence of attempts reconstructable rather than a set of near-identical
        records nobody can order.
        """
        if self.attempt <= 1:
            return None
        return RunIds.attempt(self.run_id, self.attempt - 1)


@dataclass(frozen=True, slots=True)
class RunTicket:
    """What a caller gets instead of an answer. Deliberately not an attestation.

    Returning a partial or optimistic record here would be worse than returning
    nothing: a caller who reads a verdict field gets one that no warrant has been
    evaluated for.
    """

    run_id: RunId
    ticket: str
    submitted_at: datetime

    def as_dict(self) -> dict[str, str]:
        return {
            "run_id": str(self.run_id),
            "ticket": self.ticket,
            "submitted_at": self.submitted_at.isoformat(),
            "status": "queued",
        }


class QueuedDispatch:
    """Both sides of the queue: submit from the request, execute in the worker.

    One class rather than two because the pair has to agree about the envelope, and
    two classes in different modules is how they stop agreeing.
    """

    __slots__ = ("_clock", "_queue")

    def __init__(self, queue: RunQueue, *, clock: object) -> None:
        self._queue = queue
        self._clock = clock

    def submit(
        self,
        *,
        run_id: RunId,
        actor: ActorId,
        tenant: TenantId,
        payload: Mapping[str, Any],
        metadata: Mapping[str, str] | None = None,
    ) -> RunTicket:
        """Persist the envelope, queue it, and return the ticket. No run happens here.

        The run id is generated by the caller and returned immediately, so the caller
        can poll or receive a webhook for a record that does not exist yet. That is the
        honest shape: the alternative is holding the connection until it does.
        """
        now = self._clock.now()  # type: ignore[attr-defined]
        envelope = RunEnvelope(
            run_id=run_id,
            actor=actor,
            tenant=tenant,
            payload=payload,
            submitted_at=now,
            metadata=dict(metadata or {}),
        )
        ticket = self._queue.submit(run_id, envelope.encode())
        return RunTicket(run_id=run_id, ticket=ticket, submitted_at=now)

    @classmethod
    def execute(
        cls,
        raw: bytes,
        *,
        engine: RunEngine,
        builder: Callable[[RunEnvelope], RunRequest],
        binding: Callable[[RunEnvelope], TenantBinding],
        executor: Callable[[RunEnvelope], Any] | None = None,
    ) -> RunResult:
        """The worker side. Decode, build the proposal, run it under the queued id.

        ``builder`` runs *here*, in the worker, so the mapping from payload to proposal
        is the host's single definition of it — and a fix to that mapping applies to
        everything still queued rather than only to what is submitted afterwards.

        The tenant is re-checked against the envelope after building, because
        ``build_request`` is host code and a mismatch between the tenant that was
        authorised at submission and the one the proposal names is the confused deputy
        arriving by a different route.
        """
        envelope = RunEnvelope.decode(raw)
        proposal = builder(envelope)
        if proposal.tenant != envelope.tenant:
            raise ContractViolation(
                f"the queued envelope was authorised for tenant {envelope.tenant!r} but "
                f"the proposal built from it names {proposal.tenant!r}. Refusing: the "
                f"tenant check happened at submission, against the caller, and a "
                f"proposal that changes it afterwards has escaped that check."
            )
        if proposal.actor != envelope.actor:
            # Only the tenant used to be checked, and the docstring above claimed both
            # were. `build_request` runs here against a host-shaped payload, so a
            # proposal could name any actor within the tenant — and the engine's own
            # binding check compares the action's actor to the context's actor, both
            # taken from that same proposal, so they agree. Horizontal escalation
            # inside a tenant, with the capabilities built from the payload too.
            raise ContractViolation(
                f"the queued envelope was submitted by {envelope.actor!r} and the "
                f"proposal built from it acts as {proposal.actor!r}. Refusing: the run "
                f"would be attributed to an actor who did not dispatch it, and "
                f"authority is resolved against the actor."
            )
        return engine.execute(
            proposal,
            binding=binding(envelope),
            executor=None if executor is None else executor(envelope),
            # Not `envelope.run_id`. A resumption is a second attestation for the same
            # dispatch, and attestations are immutable — see `attestation_id`.
            run_id=envelope.attestation_id(),
            supersedes=envelope.supersedes(),
        )

    def resume(self, run_id: RunId) -> str:
        """Re-dispatch a suspended run. Called when the thing it waited on arrives.

        This is what keeps a held run off a worker. The run suspended, the worker
        returned, and the approval — not a parked thread — is what starts it again.
        """
        return self._queue.resume(run_id)


class RunWorker:
    """Executes queued runs. Wired into the host's worker, not into one of ours.

    Most projects already have a Celery app, a worker container and a compose file.
    This class exists so adding governed runs to that is a few lines rather than a
    second deployment: it is a plain object with two entry points, and the host decides
    what calls them.

    .. code-block:: python

        # the host's existing tasks.py, beside their own tasks
        worker = RunWorker(
            queue=DjangoRunQueue(),
            engine=build_engine(),
            builder=lambda env: build_request(env.payload),
            binding=lambda env: binding_for(env.tenant),
        )

        @app.task(name="attest.run")             # their app, their options
        def run_governed(run_id: str) -> None:
            worker.run_one(RunId(run_id))

    ``run_one`` is the broker path: the worker is told which run to do.  ``drain`` is
    the polling path, for a host with no broker and for the sweeper that catches runs
    whose notification was lost. Both settle the row, and both treat a hold as a normal
    outcome rather than as work left undone.
    """

    __slots__ = ("_binding", "_builder", "_engine", "_executor", "_queue")

    def __init__(
        self,
        *,
        queue: RunWorkQueue,
        engine: RunEngine,
        builder: Callable[[RunEnvelope], RunRequest],
        binding: Callable[[RunEnvelope], TenantBinding],
        executor: Callable[[RunEnvelope], Any] | None = None,
    ) -> None:
        self._queue = queue
        self._engine = engine
        self._builder = builder
        self._binding = binding
        self._executor = executor

    def run_one(self, run_id: RunId) -> RunResult | None:
        """Execute the run a broker notified us about.

        ``None`` when there is nothing to do: the row is gone, or already running, or
        already finished. A duplicate notification is normal — brokers deliver at least
        once — and running the effect twice because of one is not.
        """
        envelope = self._queue.fetch(run_id)
        if envelope is None:
            return None
        return self._execute(envelope)

    def drain(self, *, limit: int = 1) -> tuple[RunResult, ...]:
        """Take work and do it. The polling path, and the lost-notification sweeper.

        Every claimed envelope is attempted, and a failure settles that run and moves
        on. A generator expression here aborted on the first exception, leaving every
        envelope already claimed in that batch sitting in ``running`` with a lease and
        no worker — recovered only when ``reclaim_expired`` runs, one lease later. With
        ``limit > 1`` a single poison envelope stalled the rest of its batch.
        """
        results: list[RunResult] = []
        for raw in self._queue.claim(limit=limit):
            # `_execute` settles the run that raised and records why before the
            # exception leaves it, so nothing is lost here — but letting it propagate
            # would abandon the siblings already claimed in this batch, which is the
            # failure being fixed.
            with suppress(Exception):
                results.append(self._execute(raw))
        return tuple(results)

    def _execute(self, raw: bytes) -> RunResult:
        """Run it, and settle the row whatever happens.

        A worker that raises without settling leaves a row in ``running`` forever: the
        run is neither retryable nor visibly failed, and the caller's ticket never
        resolves. The exception still propagates — the host's worker decides about
        retries and dead-letters — but the row says what happened first.
        """
        envelope = RunEnvelope.decode(raw)
        try:
            result = QueuedDispatch.execute(
                raw,
                engine=self._engine,
                builder=self._builder,
                binding=self._binding,
                executor=self._executor,
            )
        except Exception as exc:
            self._queue.settle(
                envelope.run_id,
                state="failed",
                detail=f"{type(exc).__name__}: {exc}",
            )
            raise
        self._queue.settle(
            envelope.run_id,
            state="held" if result.verdict is Verdict.HOLD_FOR_APPROVAL else "done",
            detail=result.verdict.value,
        )
        return result
