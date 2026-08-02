"""One position per chain: no two events may claim the same sequence.

An entity chain is sealed incrementally - each event reads the tail and takes the next slot
- so two concurrent writers compute the same number. Without this constraint both rows
persist there, which is a fork presented as a chain, and the application has effectively
chosen its own sequence from a racy read: the precise thing the seal exists to prevent.

Partial, because unsealed rows legitimately share ``sequence IS NULL`` until a run's batch
sealer assigns positions.
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("attest", "0011_seal_guard")]

    operations = [
        migrations.AddConstraint(
            model_name="auditeventrecord",
            constraint=models.UniqueConstraint(
                fields=["run_id", "sequence"],
                condition=models.Q(sequence__isnull=False),
                name="attest_audit_events_dense_sequence",
            ),
        )
    ]
