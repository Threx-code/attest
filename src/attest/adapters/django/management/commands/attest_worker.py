"""Drain the queue without a broker. ``manage.py attest_worker``.

The no-Celery path, and the sweeper for the Celery one. A host that must stand up a
broker before it can stop holding HTTP workers open will keep holding them open, so the
database-backed queue is a first-class way to run rather than a toy: ``DjangoRunQueue``
is durable and claims with ``SKIP LOCKED``, so several of these can run side by side.

.. code-block:: bash

    # a worker container, or a second process in the one you have
    python manage.py attest_worker --batch 4

    # or as a sweeper beside Celery, catching runs whose notification was lost
    python manage.py attest_worker --once --batch 50

The command cannot build the engine itself — that needs the profile, the stores and the
executor, which only the host has. It resolves a factory named in settings, so there is
exactly one definition of the engine and the web process and the worker cannot disagree
about it.
"""

from __future__ import annotations

import signal
import time
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils.module_loading import import_string

if TYPE_CHECKING:
    from argparse import ArgumentParser


class Command(BaseCommand):
    """Poll the durable queue and execute what it hands back."""

    help = "Execute queued attest runs. Set ATTEST_WORKER_FACTORY in settings."

    SETTING = "ATTEST_WORKER_FACTORY"

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument(
            "--batch",
            type=int,
            default=1,
            help="How many runs to claim at a time. Above 1, one slow run delays the rest.",
        )
        parser.add_argument(
            "--interval",
            type=float,
            default=1.0,
            help="Seconds to sleep when the queue is empty.",
        )
        parser.add_argument(
            "--once",
            action="store_true",
            help="Drain what is waiting and exit. For a cron sweeper.",
        )
        parser.add_argument(
            "--max-runs",
            type=int,
            default=0,
            help="Exit after this many runs. 0 means no limit. Use it to recycle workers.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        worker = self.build_worker()
        stopping = {"now": False}

        def stop(signum: int, frame: object) -> None:  # noqa: ARG001 — the signal handler signature
            # Finish the run in flight, then exit. Killing mid-run leaves a row in
            # `running` that no worker will pick up, and a caller whose ticket never
            # resolves.
            stopping["now"] = True
            self.stdout.write(self.style.WARNING("stopping after the current run"))

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)

        done = 0
        limit = int(options["max_runs"])
        while not stopping["now"]:
            results = worker.drain(limit=int(options["batch"]))
            done += len(results)
            for result in results:
                self.stdout.write(f"{result.attestation.run_id} {result.verdict.value}")
            if limit and done >= limit:
                break
            if options["once"] and not results:
                break
            if not results and not options["once"]:
                time.sleep(float(options["interval"]))
        self.stdout.write(self.style.SUCCESS(f"{done} run(s) executed"))

    def build_worker(self) -> Any:
        """Resolve the host's worker factory. Refuses rather than guessing.

        There is no default. An engine assembled from settings here would be a second
        definition of the profile, the stores and the executor, and it would diverge
        from the one the web process uses — so a run would be governed differently
        depending on which process happened to pick it up.
        """
        path = getattr(settings, self.SETTING, None)
        if not path:
            raise CommandError(
                f"set {self.SETTING} to a dotted path returning a RunWorker, e.g.\n"
                f'    {self.SETTING} = "yourproject.attest.build_worker"\n'
                f"It must return the same engine your web process dispatches with; two "
                f"definitions means a run is governed differently depending on which "
                f"process picked it up."
            )
        try:
            factory = import_string(path)
        except ImportError as exc:
            raise CommandError(f"could not import {self.SETTING} = {path!r}: {exc}") from exc
        worker = factory()
        if not hasattr(worker, "drain"):
            raise CommandError(
                f"{path} returned {type(worker).__name__}, which is not a RunWorker "
                f"(no drain). It must return the worker, not the engine."
            )
        return worker
