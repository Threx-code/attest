# Django adapter

**Optional.** `pip install attest[django]`. The core never imports Django.

## What it provides

```
   attest.adapters.django
     ├── SettingsBridge.from_settings()   builds AttestConfig from settings.ATTEST
     ├── models.py                 default port implementations
     │     AttestationRecord · AuditEventRecord · PendingAction
     │     AutonomyPolicy · MemoryRecord · nonce and budget rows
     ├── migrations/               including the append-only and immutability triggers
     ├── triggers.py               the migration operations that install them
     ├── stores.py                 RunStore · AuditSink · NonceStore · BudgetStore
     │                             ApprovalStore · MemoryStore
     ├── serializers.py            DRF, warning-preserving
     ├── views.py                  read the record, work the approval queue
     ├── operations.py             kill switch · approval queue · chain · queue health
     ├── dispatch via runtime/     queued runs; a held run leaves the worker
     └── management/
           verify_audit_chain · expire_pending · export_bundle
```

## Dispatch

`DispatchView` runs a proposal through `RunEngine` and returns the **attestation**, not
the answer. The HTTP status follows the verdict rather than whether the code threw:

```
   ALLOW / ALLOW_WITH_WARNINGS   200
   HOLD_FOR_APPROVAL             202     something is outstanding
   UNKNOWN                       202     the upstream did not answer
   INCOMPLETE                    409     part of the world moved
   REFUSE                        422
```

A `200` carrying the answer for a held or refused run would hand a caller a figure whose
qualification lives in a field they never had to read.

The view is abstract on purpose. A host supplies `engine_for()`, `build_request()` and
`binding_for()`, because the engine holds the profile, the stores and the executor — and
a view that assembled those from settings would be a second, divergent definition of the
deployment. It raises rather than guessing.

**A held run does not hold a worker.** The response returns at `HOLD_FOR_APPROVAL`;
resumption is a separate request triggered by the approval.

## Security defaults

These routes decide whether money moves, so none of them inherits a default that could
be permissive. The project's `SECURITY.md` carries the full table and what is in scope for a report.

| Concern | Default here |
|---|---|
| Authentication | `IsAuthenticated`, set on the class — DRF's project default is `AllowAny` |
| Tenant scoping | applied in the queryset, never after |
| Cross-tenant dispatch | refused `403` before the engine is reached |
| Disclosure | `DisclosureProfile.SUBJECT`; an operator console opts into `INTERNAL` |
| Rate limiting | `throttle_scope = "attest"` declared |
| Warnings | never withheld, from any audience |

## What is deliberately absent

**`replay_run`.** Replay needs a recorded provider transcript to re-execute against, and
the gateway's recording surface is not settled. `RunEngine` is deterministic given a
context, so this is a matter of storing the transcript rather than of design.

## Offered, never required

The critical property. A host with existing tables implements the ports against them and
uses none of these models.

```
   GREENFIELD                        EXISTING CODEBASE
   ──────────────────────            ────────────────────────────────
   INSTALLED_APPS += [               class MyRunStore:
     "attest.adapters.django",           def create(self, att): ...
   ]                                     # writes to YOUR table
   migrate. Done.
                                     No migration. No new table.
                                     Adopt the gateway today; adopt
                                     the rest later, or never.
```

This is what makes adoption incremental for codebases whose `AgentRun` tables have already
diverged — see [`../kernel/ports.md`](../kernel/ports.md) for the measured divergence that
forced this design.

## Settings

```python
ATTEST = {
    "BRAND": "acme",
    "CURRENCY": "GBP",
    "CURRENCY_SYMBOL": "£",
    "LOCALE": "en_GB",
    "MODELS": {"fast": "...", "balanced": "...", "reasoning": "..."},
    "MAX_STEPS": 8,
    "DAILY_BUDGET": "500.00",
}
```

`SettingsBridge.from_settings()` is a thin builder over `AttestConfig`. It performs no logic
beyond mapping keys — all validation lives in the frozen dataclass, so a worker that builds
config directly gets identical checks.

An unknown key is **rejected, not ignored**: a misspelled setting that is silently dropped
leaves the deployment running the default it was configured to replace, and every
attestation it produces records a value nobody chose.

## Running your test suite

`TransactionTestCase` truncates tables between tests, and truncation is `DELETE`. The
append-only triggers refuse, so every such class fails at teardown the moment an attest row
exists - which, once the engine is wired, is every test that executes a run. The failure
surfaces as an `IntegrityError` in teardown with no obvious connection to what the test was
doing, and the natural next move is to stop installing the app.

```python
# conftest.py
from attest.adapters.django.testing import AppendOnlyTriggers

@pytest.fixture(scope="session", autouse=True)
def _attest_test_db(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        AppendOnlyTriggers.drop()
```

It refuses to run against a database whose name does not look like a test one. A helper that
silently disabled an integrity control in production would be the most dangerous thing this
package ships, and "it is only called from conftest" is exactly the assumption that stops
being true.

## The append-only trigger

Shipped as a migration, because application-level discipline is not enforcement.
`verify_audit_chain` **recomputes each event's hash from its content** rather than
walking the stored `previous_hash` columns, so an event rewritten together with its
linkage is caught — a check that trusted the columns would report that chain as intact.

```sql
CREATE TRIGGER attest_attest_audit_events_no_update
  BEFORE UPDATE OR DELETE ON attest_audit_events
  FOR EACH ROW EXECUTE FUNCTION attest_reject_mutation();
```

The migration emits the right dialect for SQLite, PostgreSQL and MySQL. **An unsupported
vendor raises rather than applying nothing** — a migration that quietly succeeded would
leave a deployment believing it had enforcement it does not have, which is worse than
knowing it must build it.

Attestations get a narrower guard: the content columns are frozen while `superseded_by`
stays writable, so a correction can point forward without anyone rewriting what a reader
already relied on.

## Operations are a service, not an admin

There is no Django admin, deliberately. An admin is a console with a permission model
baked in, and every adopter already has roles, groups, SSO claims and an approval
hierarchy. A shipped permission model is either ignored or wired up beside the real one,
where it drifts until somebody who should not have been able to flip a kill switch does.

```
   OperationsService      what the operations ARE        attest.runtime.operations
   OperationsView         how they reach HTTP            abstract, here
   your subclass          who may perform them           yours
```

The service authorises nothing and says so. What it *does* insist on, because these are
integrity properties rather than policy, is that every mutating operation names an
operator and states a reason, and that both are recorded before the change takes effect.
An unattributed kill switch is indistinguishable from a misconfiguration when the
incident is reviewed.

Nothing is mounted automatically. A route that can disable a capability should be a line
somebody wrote on purpose.

### The switch is read on the run path

Wire `DjangoAutonomyStore` into `RunEngine(autonomy=...)` and every proposed effect asks it
first. Without that argument the engine has no opinion and behaves exactly as before, which
is deliberate: the store answers `blocked` for a capability with no row, on the ground that
an absent policy is an unanswered question rather than permission, so wiring it is a real
commitment and should be visible in the wiring rather than hidden in a default.

A store that cannot answer blocks. Not knowing whether the switch is on is not the same as
it being off, and the whole point of this control is the incident during which the
infrastructure is already unwell.

Only `blocked` is enforced here. `approve` means the capability may act with a human in the
loop, which is what the profile's `Approval` obligation already expresses - implementing it
twice would put approval policy in two places, and the second one would drift.

## Serialisers preserve warnings

A specific hazard called out in [`../concepts/verdicts.md`](../concepts/verdicts.md): an
`ALLOW_WITH_WARNINGS` figure rendered into a dashboard that shows only the figure is a
material misstatement delivered with a clean conscience.

```python
class AttestationSerializer(serializers.Serializer):
    # verdict and warnings are ALWAYS serialised.
    # There is no `fields` option that can drop them.
```

The adapter cannot force a frontend to display them, but it can refuse to make omission the
default.

## Scale operations you opt into

Three operations ship but are **not** in a shipped migration, because each needs a
decision only the deployment can make:

```
   TrigramIndex           memory recall stops being a sequential scan   PostgreSQL
   RangePartitionByMonth  the append-only tables get a retention story  PostgreSQL
   EnsurePartitions       next month's partition exists before it does  PostgreSQL
```

`content__icontains` is a sequential scan, and a B-tree cannot help — `LIKE '%x%'` has
no prefix to seek on. `TrigramIndex` builds a GIN index over three-character shingles,
which fits this query shape with no change at the call site.

Partitioning is the retention story. The chain tables are append-only at the database
level, so archival cannot be `DELETE`; it is `DETACH PARTITION`, which touches no rows
and leaves the chain over them verifying byte for byte. **A deployment that can turn the
append-only guarantee off in order to prune does not have the guarantee.**

`RangePartitionByMonth` refuses on a populated table rather than silently moving every
row — that is a maintenance window, not a migration step. Put these in your own
migration, at a time you chose:

```python
operations = [
    TrigramIndex("attest_memory", "content"),
    RangePartitionByMonth("attest_audit_events"),
    EnsurePartitions("attest_audit_events", months=6),
]
```

Then keep partitions ahead of the clock, because a partitioned table with no partition
covering `now` rejects every insert — in the audit sink, at midnight on the first:

```bash
python manage.py attest_partitions --ensure 6            # monthly, on a schedule
python manage.py attest_partitions --detach-before 2025-01-01
```

Detaching does not delete. The child table stands complete and unattached; dump it,
verify the dump, then drop it, in that order, by a person. Automating the drop would put
"irreversibly discard audit evidence" on a cron schedule.

## Async and workers

Views dispatch; long runs go to a task queue. The `attest[celery]` extra ships wrappers, but
the core is queue-agnostic — a run is a value in, an attestation out, so any worker system
does.

Held runs are the case to get right: a `HOLD_FOR_APPROVAL` must **not** keep a worker
blocked. The run suspends, the worker returns, and approval enqueues a resumption. A worker
pool held open by pending approvals is an outage waiting for a busy Monday.

## Layering rule

```
   adapters ──▶ runtime ──▶ capabilities ──▶ kernel        allowed
   kernel   ──▶ django                                     FORBIDDEN
```

Enforced by the `import-linter` contract in CI. See
[`../01-layering.md`](../01-layering.md).

## Related

- [`../kernel/ports.md`](../kernel/ports.md) — what these implement
- [`../kernel/config.md`](../kernel/config.md) — the config object
- [`../capabilities/audit.md`](../capabilities/audit.md) — append-only requirement
