"""Make the delivery trail append-only, at the same level as the audit chain.

The trail answers the question nobody can answer from the chain when a run has produced
no attestation: did anything ever pick it up. That answer is worthless if the process
that failed to run the job can also edit the record of having taken it — so the
enforcement is a trigger, below the application, exactly as for
``attest_audit_events``.

Kept in its own migration for the same reason as ``0002``: the table can be created by
any tooling, the guarantee cannot, and ``showmigrations`` should make it obvious
whether a deployment actually has it.
"""

from __future__ import annotations

from django.db import migrations

from attest.adapters.django.triggers import AppendOnlyTable


class Migration(migrations.Migration):
    dependencies = [("attest", "0007_dispatch_trail")]

    operations = [AppendOnlyTable("attest_dispatch_events")]
