"""``manage.py verify_audit_chain`` — walk stored chains and report failures.

Exit status is meaningful: non-zero when any chain fails, so this belongs in a cron job
and a deploy gate rather than in someone's terminal history. A verification nobody runs
is a claim, not a check.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.core.management.base import BaseCommand, CommandError

from attest.adapters.django.chain import StoredChainCheck
from attest.adapters.django.models import AuditEventRecord
from attest.kernel.identifiers import RunId

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from collections.abc import Iterator

__all__ = ["Command"]


class Command(BaseCommand):
    help = "Verify the structural integrity of stored audit chains."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--run-id", help="Verify one run. Omit to verify every run.")
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Stop after N runs. 0 means no limit; a truncated sweep is reported as such.",
        )
        parser.add_argument(
            "--since",
            default="",
            help=(
                "Only runs with events at or after this ISO timestamp. Prefer a window "
                "to a full sweep: the table is append-only and grows forever."
            ),
        )

    #: Rows per keyset page. Small enough that a page is cheap, large enough that the
    #: round trips do not dominate.
    PAGE = 1000

    def run_ids(self, run_id: str | None, options: dict[str, Any]) -> Iterator[str]:
        """Every run to check, streamed.

        ``values_list(...).distinct()`` then ``sorted(set(...))`` loaded every distinct
        run id in the table into a Python set. At the documented target of millions of
        runs per day that is an out-of-memory condition in the one control that audit.md
        calls "the one that matters" — so the sweep died on the deployments that needed
        it most.

        A keyset cursor instead: ordered, paged, and never more than one page resident.
        """
        if run_id:
            yield run_id
            return

        since = options.get("since")
        after = ""
        while True:
            page = AuditEventRecord.objects.values_list("run_id", flat=True).distinct()
            if since:
                page = page.filter(occurred_at__gte=since)
            found = list(page.filter(run_id__gt=after).order_by("run_id")[: self.PAGE])
            if not found:
                return
            yield from found
            after = found[-1]

    def handle(self, *args: Any, **options: Any) -> None:
        run_id = options.get("run_id")
        limit = int(options.get("limit") or 0)

        checker = StoredChainCheck()
        failed = 0
        checked = 0
        truncated = False

        for identifier in self.run_ids(run_id, options):
            if limit and checked >= limit:
                truncated = True
                break
            checked += 1
            result = checker.run(RunId(identifier))
            if result.verified:
                seal = "sealed" if result.sealed else "no seal on record"
                self.stdout.write(f"OK    {identifier}  ({result.events} events, {seal})")
                continue
            failed += 1
            reasons = ", ".join(failure.value for failure in result.failures)
            self.stdout.write(self.style.ERROR(f"FAIL  {identifier}  {reasons}: {result.detail}"))

        # Stated every time, not only on failure: what a verification covers is part
        # of what it is worth.
        self.stdout.write(
            f"\nChecked {checked} run(s). Event hashes recomputed from content: "
            f"{StoredChainCheck.RECOMPUTED}. Sequence density, linkage, and — where the "
            f"run is sealed — the seal's event count and head."
        )
        if truncated:
            self.stdout.write(
                self.style.WARNING(f"Stopped at --limit {limit}; further runs were not checked.")
            )
        if failed:
            raise CommandError(f"{failed} chain(s) failed verification")
