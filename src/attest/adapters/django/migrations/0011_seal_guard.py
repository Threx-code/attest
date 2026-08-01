"""Refuse audit events for a run that is already sealed.

The append-only trigger stops UPDATE and DELETE and deliberately permits INSERT — the
table is append-only. That left the other half open: anything with database access,
including an SQL injection elsewhere in the host application, could append rows to a
closed run, and the seal's dense count catches it only when the periodic sweep runs.

Its own migration for the same reason as ``0002``: the table can be created by any
tooling, the guarantee cannot, and ``showmigrations`` should say plainly whether a
deployment has it.
"""

from __future__ import annotations

from django.db import migrations

from attest.adapters.django.triggers import NoEventsAfterSeal


class Migration(migrations.Migration):
    dependencies = [("attest", "0010_seal_registry")]

    operations = [NoEventsAfterSeal()]
