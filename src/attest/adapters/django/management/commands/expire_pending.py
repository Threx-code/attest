"""``manage.py expire_pending`` — enforce approval and reservation expiry.

The sweep exists because expiry that is only *recorded* is not expiry. A pending action
whose deadline has passed but whose row still says ``pending`` will be approved by
whoever opens the queue next, authorising an effect whose window closed hours ago.

Run it on a schedule. Held budget is the same story from the other side: a crashed run
holding a reservation starves every later run until something releases it.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.utils import timezone

from attest.adapters.django.stores import DjangoApprovalStore, DjangoBudgetStore

__all__ = ["Command"]


class Command(BaseCommand):
    help = "Expire pending approvals and stale budget reservations."

    def handle(self, *args: Any, **options: Any) -> None:
        now = timezone.now()
        expired = DjangoApprovalStore().expire_due(now)
        released = DjangoBudgetStore().expire_due(now)

        for approval_id in expired:
            # Named individually: an expiry is a refusal with an owner, not a metric.
            self.stdout.write(f"expired approval {approval_id}")
        self.stdout.write(
            f"Expired {len(expired)} pending action(s); released {released} budget "
            f"reservation(s) as at {now.isoformat()}."
        )
