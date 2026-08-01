"""Celery, wrapped so it drops into the worker you already run.

Most projects arrive with a Celery app, their own tasks, a worker container and a
compose file. Nothing here asks for a second one. Wiring is two objects and one task
registration, on **your** app with **your** options:

.. code-block:: python

    # yourproject/tasks.py — beside your own tasks
    from attest.adapters.celery import AttestTasks
    from attest.adapters.django.stores import DjangoRunQueue
    from attest.runtime.dispatch import RunWorker

    worker = RunWorker(
        queue=DjangoRunQueue(),
        engine=build_engine(),                       # yours
        builder=lambda env: build_request(env.payload),
        binding=lambda env: binding_for(env.tenant),
    )
    AttestTasks(app, worker).register(queue="attest", acks_late=True)

.. code-block:: python

    # settings.py or wherever you build the view's dependencies
    queue = CeleryRunQueue(app, DjangoRunQueue())    # what the request path submits to

Your existing worker picks it up with no new container::

    celery -A yourproject worker -Q celery,attest

``-Q`` is worth spending a line on. Governed runs are slow — a model call and then an
external effect — so sharing a queue with your fast tasks means a burst of runs delays
everything else. A separate routing key and a couple of dedicated worker processes
costs one flag and one line in compose.

If you do not run Celery at all, you do not need it: ``DjangoRunQueue`` is durable on
its own and ``manage.py attest_worker`` drains it.

Losing a broker message costs a delay rather than a run.

.. code-block:: text

    submit()
      │
      ├── 1. write the envelope           durable, in your database
      │
      └── 2. notify the broker            best effort

    A broker that drops the message leaves a row in `queued`, which the
    sweeper picks up. A broker that is merely slow changes nothing. The
    run is lost only if the DATABASE loses it, which is the same
    durability the attestation itself has.

The order is the whole design. Enqueueing first and writing second gives a window where
a worker can pick up a run whose envelope is not yet visible; writing first and
notifying second gives a window where a run is late. Late is recoverable and invisible
is not.

Celery is an optional extra. The import is deferred so that installing
``attest[django]`` without ``attest[celery]`` does not fail at import time — a host that
does not queue should not need a broker library on its path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from attest.kernel.errors import ContractViolation

if TYPE_CHECKING:
    from attest.kernel.identifiers import RunId
    from attest.kernel.ports import RunQueue

__all__ = ["AttestTasks", "CeleryRunQueue", "CeleryUnavailable"]


class CeleryUnavailable(ContractViolation):
    """Celery is not installed, or no application was supplied.

    Raised at construction rather than at the first dispatch. A queue that fails only
    when the first run arrives fails in production, on the path it was added to
    protect.
    """


class CeleryRunQueue:
    """Writes the envelope through a durable queue, then notifies a broker.

    Satisfies :class:`~attest.kernel.ports.RunQueue`. Composes with
    :class:`~attest.adapters.django.stores.DjangoRunQueue` rather than replacing it:
    that one owns durability and the claim/settle lifecycle, this one owns the
    notification that stops workers from polling.

    ``task_name`` is a string rather than a task object so this module never imports the
    host's task module — which would make the import order between the queue and the
    tasks that use it load-bearing.
    """

    DEFAULT_TASK: Final = "attest.run"

    __slots__ = ("_app", "_durable", "_queue_name", "_task_name")

    def __init__(
        self,
        app: Any,  # noqa: ANN401 — a Celery app; typing it would import celery at module load
        durable: RunQueue,
        *,
        task_name: str = DEFAULT_TASK,
        queue_name: str | None = None,
    ) -> None:
        if app is None:
            raise CeleryUnavailable(
                "CeleryRunQueue needs a Celery application. Pass the one your worker "
                "runs, not a new one: two applications means the task is registered on "
                "one and dispatched on the other, and the run is never picked up."
            )
        if not hasattr(app, "send_task"):
            raise CeleryUnavailable(
                f"{type(app).__name__} does not look like a Celery application "
                f"(no send_task). Install attest[celery], or pass your app explicitly."
            )
        self._app = app
        self._durable = durable
        self._task_name = task_name
        self._queue_name = queue_name

    @property
    def durable(self) -> RunQueue:
        """The store of record. Exposed so a worker can claim and settle against it."""
        return self._durable

    def submit(self, run_id: RunId, envelope: bytes) -> str:
        """Persist first, notify second.

        A failed notification is **not** an error: the row is already durable and the
        sweeper will pick it up. Raising here would make a transient broker outage look
        like a rejected request, and the caller would retry a run that is already
        queued.
        """
        ticket = self._durable.submit(run_id, envelope)
        if ticket.startswith("duplicate:"):
            # Already queued. Notifying again would run it twice if the first
            # notification was merely slow rather than lost.
            return ticket
        return f"{ticket}|{self._notify(run_id)}"

    def resume(self, run_id: RunId) -> str:
        ticket = self._durable.resume(run_id)
        return f"{ticket}|{self._notify(run_id)}"

    def _notify(self, run_id: RunId) -> str:
        """Best effort. The envelope is already safe."""
        try:
            options: dict[str, Any] = {}
            if self._queue_name is not None:
                options["queue"] = self._queue_name
            async_result = self._app.send_task(self._task_name, args=[str(run_id)], **options)
        except Exception as exc:
            return f"notify-failed:{type(exc).__name__}"
        return f"task:{getattr(async_result, 'id', 'unknown')}"


class AttestTasks:
    """Registers attest's task on the host's Celery app, beside the host's own tasks.

    A class rather than a decorator so the registration is explicit and the host keeps
    every Celery option it cares about — ``queue``, ``acks_late``,
    ``autoretry_for``, ``rate_limit``. Those belong to the host: retry policy for a
    governed run is a deployment decision, and a framework that fixed it would be
    choosing how many times to re-propose an effect.

    ``acks_late=True`` is worth setting. A worker killed mid-run has already written
    its effect events durably, so redelivery is safe and the alternative — acking on
    receipt — silently drops the run when a pod is evicted.
    """

    DEFAULT_TASK: Final = "attest.run"

    __slots__ = ("_app", "_task_name", "_worker")

    def __init__(
        self,
        app: Any,  # noqa: ANN401 — a Celery app; typing it would import celery at module load
        worker: Any,  # noqa: ANN401 — a RunWorker; runtime types are not imported by adapters
        *,
        task_name: str = DEFAULT_TASK,
    ) -> None:
        if not hasattr(app, "task"):
            raise CeleryUnavailable(
                f"{type(app).__name__} does not look like a Celery application (no "
                f"task decorator). Pass the app your worker runs."
            )
        if not hasattr(worker, "run_one"):
            raise CeleryUnavailable(
                "AttestTasks needs a RunWorker — the object that owns the engine, the "
                "builder and the binding. Registering a task without one would give a "
                "worker that can dequeue and cannot run."
            )
        self._app = app
        self._worker = worker
        self._task_name = task_name

    def register(self, **options: Any) -> Any:  # noqa: ANN401 — passthrough to Celery
        """Register the task and return it. ``options`` go straight to ``app.task``.

        The task body is deliberately thin: fetch, run, settle, all inside
        :meth:`RunWorker.run_one`. Putting logic here would put it somewhere the
        polling path does not run, and the two would diverge exactly when the broker
        is having a bad day and the sweeper is what is actually working.
        """
        worker = self._worker

        def _run(run_id: str) -> str | None:
            from attest.kernel.identifiers import RunId

            result = worker.run_one(RunId(run_id))
            # A duplicate delivery finds nothing to do and says so, rather than
            # looking like a failure the host should retry.
            return None if result is None else result.verdict.value

        _run.__name__ = self._task_name.replace(".", "_")
        return self._app.task(name=self._task_name, **options)(_run)
