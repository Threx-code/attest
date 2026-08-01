"""Install the append-only and immutability triggers.

Separated from ``0001_initial`` on purpose. The tables can be created by any tooling;
the guarantees cannot, and keeping them in their own migration makes it obvious in a
review — and in ``showmigrations`` — whether a deployment actually has them.
"""

from __future__ import annotations

from django.db import migrations

from attest.adapters.django.triggers import AppendOnlyTable, ImmutableColumns


class Migration(migrations.Migration):
    dependencies = [("attest", "0001_initial")]

    operations = [
        AppendOnlyTable("attest_audit_events"),
        # ``superseded_by`` is deliberately absent: a correction must be able to point
        # forward from the original without being able to rewrite it.
        ImmutableColumns(
            "attest_attestations",
            ["content_hash", "payload", "verdict", "answer", "warnings", "created_at"],
        ),
        AppendOnlyTable("attest_redeemed_nonces"),
    ]
