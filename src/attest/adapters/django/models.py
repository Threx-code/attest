"""Django models — offered, never required.

A host with an existing ``AgentRun`` table implements the ports against it and uses
none of this. That is the whole design: across the codebases this framework was drawn
from, the same conceptual table had genuinely diverged — three table names, two
token-naming schemes, three governance field names — so a framework that mandated its
own would have required a migration merge against live production data before anyone
could adopt it.

.. code-block:: text

    GREENFIELD                        EXISTING CODEBASE
    ──────────────────────            ────────────────────────────────
    INSTALLED_APPS += [               class MyRunStore:
      "attest.adapters.django",           def create(self, ...): ...
    ]                                     # writes to YOUR table
    migrate. Done.
                                      No migration. No new table.

Two columns are deliberately denormalised out of the payload: ``verdict`` and
``warnings``. They are what a dashboard renders, and a renderer that has to decode a
blob to find the warnings is a renderer that will eventually stop bothering. See
:mod:`attest.adapters.django.serializers`.
"""

from __future__ import annotations

from django.db import models

__all__ = [
    "AttestationRecord",
    "AuditEventRecord",
    "AutonomyPolicy",
    "BudgetReservation",
    "BudgetSpend",
    "DispatchEvent",
    "MemoryRecord",
    "PendingAction",
    "QueuedRun",
    "RedeemedNonce",
    "RevokedGrant",
    "SealedRun",
]


class AttestationRecord(models.Model):
    """One attestation. **Immutable once written**, enforced by a database trigger.

    There is no ``update`` path and no ``updated_at``. A correction is a new row whose
    ``supersedes`` points at this one, so a reader who relied on the original can still
    see exactly what they relied on.
    """

    run_id = models.CharField(max_length=128, primary_key=True)
    tenant_id = models.CharField(max_length=128, db_index=True)
    verdict = models.CharField(max_length=32, db_index=True)
    """One of the six outcomes. Never null — an attestation without a verdict is not
    an attestation."""

    answer = models.TextField(blank=True, default="")
    warnings = models.JSONField(default=list)
    """Carried as a column, not buried in ``payload``.

    An ``ALLOW_WITH_WARNINGS`` figure rendered into a dashboard that shows only the
    figure is a material misstatement delivered with a clean conscience.
    """

    content_hash = models.CharField(max_length=64, db_index=True)
    payload = models.BinaryField()
    """The host's canonical encoding of the full attestation.

    This package does not impose a codec — see the module docstring of
    :mod:`attest.adapters.django.stores`.
    """

    is_final = models.BooleanField(default=False)
    """Whether every warrant was actually evaluated. Export refuses when false."""

    sealed = models.BooleanField(default=False)
    seal_signature = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(db_index=True)
    supersedes = models.CharField(max_length=128, blank=True, default="", db_index=True)
    superseded_by = models.CharField(max_length=128, blank=True, default="", db_index=True)

    class Meta:
        db_table = "attest_attestations"
        indexes = [models.Index(fields=["tenant_id", "created_at"])]

    def __str__(self) -> str:
        return f"{self.run_id} [{self.verdict}]"


class AuditEventRecord(models.Model):
    """One hash-chained event. **Append-only**, enforced by a database trigger.

    ``sequence`` and ``previous_hash`` are nullable because events arrive *unsealed*:
    the application records causal structure, and an independent sealer assigns the
    dense 1..N ordering later. A table that assigned its own sequence on insert would
    reintroduce the ordering bug ADR 0034 exists to fix, because effect events are
    written immediately while everything else batches.
    """

    id = models.BigAutoField(primary_key=True)
    run_id = models.CharField(max_length=128, db_index=True)
    event_type = models.CharField(max_length=64)
    occurred_at = models.DateTimeField()
    payload = models.BinaryField()
    sequence = models.IntegerField(null=True, blank=True)
    previous_hash = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        db_table = "attest_audit_events"
        indexes = [models.Index(fields=["run_id", "sequence"])]
        constraints = [
            # Two writers on the same chain must not both land at the same position.
            #
            # An entity chain is sealed incrementally - each act reads the tail and takes
            # the next slot - so two concurrent acts compute the same number. Without this
            # both rows persist there, which is a fork presented as a chain, and the
            # application has effectively chosen its own sequence from a racy read: the
            # precise thing the seal exists to prevent. With it the loser gets an
            # IntegrityError and retries against the new tail.
            #
            # Partial, because unsealed rows legitimately share `sequence IS NULL` until a
            # run's batch sealer assigns positions.
            models.UniqueConstraint(
                fields=["run_id", "sequence"],
                condition=models.Q(sequence__isnull=False),
                name="attest_audit_events_dense_sequence",
            )
        ]

    def __str__(self) -> str:
        return f"{self.run_id}/{self.event_type}"


class PendingAction(models.Model):
    """A human decision the run is waiting on.

    ``expires_at`` has no null and no default. An approval queue without enforced
    expiry becomes a backlog of half-executed decisions with no owner, and expiry
    produces a typed refusal rather than a silent drop.
    """

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    STATES = (
        (PENDING, "pending"),
        (APPROVED, "approved"),
        (REJECTED, "rejected"),
        (EXPIRED, "expired"),
    )

    approval_id = models.CharField(max_length=128, primary_key=True)
    run_id = models.CharField(max_length=128, db_index=True)
    tenant_id = models.CharField(max_length=128, db_index=True)
    grant_id = models.CharField(max_length=128)
    action_hash = models.CharField(max_length=64)
    """The grant is bound to the arguments, not the tool name. An approval screen that
    shows only the tool name is asking someone to authorise something they cannot see."""

    summary = models.TextField(blank=True, default="")
    state = models.CharField(max_length=16, choices=STATES, default=PENDING, db_index=True)
    opened_at = models.DateTimeField()
    expires_at = models.DateTimeField(db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    approver = models.CharField(max_length=128, blank=True, default="")
    approver_role = models.CharField(max_length=128, blank=True, default="")
    """Recorded because a quorum is defined over roles.

    ``DualControl`` filters approvals on ``role``, so a decision stored without one
    counts toward nothing — the REST surface would produce approvals the obligation
    layer could not consume.
    """

    redeemed_by_grant = models.CharField(max_length=128, blank=True, default="", db_index=True)
    """The grant this decision authorised. A decision is spendable once.

    Empty means unspent. Without it, one approval for a GBP 500,000 transfer authorised
    an unlimited number of them: the action hash is identical on a re-submission, so the
    same historical decision discharged every fresh grant."""

    requested_by = models.CharField(max_length=128, blank=True, default="")
    """Who proposed the action, so self-approval can be refused at resolution.

    Self-approval is the most common way dual control is defeated in practice, and it
    cannot be checked without knowing who asked.
    """

    class Meta:
        db_table = "attest_pending_actions"
        indexes = [models.Index(fields=["state", "expires_at"])]

    def __str__(self) -> str:
        return f"{self.approval_id} [{self.state}]"


class SealedRun(models.Model):
    """A run whose chain is closed. Written by the sealer, read by a trigger.

    The append-only trigger rejects UPDATE and DELETE. INSERT is unrestricted by
    design — the table is append-only — so any code path with database access, including
    an SQL injection anywhere else in the host application, could append rows to a run
    that had already been sealed. The seal's count catches it *at verification*, which
    is the wrong end: the sweep is periodic, and a bogus row sits in the record until it
    runs.

    The in-memory sink already enforces this with ``_assert_open``. This is the same
    rule, below the application, where a compromised application cannot skip it.
    """

    run_id = models.CharField(max_length=128, primary_key=True)
    sealed_at = models.DateTimeField(db_index=True)
    event_count = models.IntegerField()
    head_hash = models.CharField(max_length=64)

    class Meta:
        db_table = "attest_sealed_runs"

    def __str__(self) -> str:
        return f"{self.run_id} sealed at {self.sealed_at.isoformat()}"


class AutonomyPolicy(models.Model):
    """How much a capability may do without a human, per tenant.

    ``enabled = False`` is the kill switch: it is a row rather than a deploy, because
    a control you can only exercise by shipping code is not a control you can exercise
    during an incident.
    """

    AUTO = "auto"
    APPROVE = "approve"
    BLOCKED = "blocked"
    MODES = ((AUTO, "auto"), (APPROVE, "approve"), (BLOCKED, "blocked"))

    id = models.BigAutoField(primary_key=True)
    tenant_id = models.CharField(max_length=128, db_index=True)
    capability = models.CharField(max_length=128)
    mode = models.CharField(max_length=16, choices=MODES, default=APPROVE)
    """Defaults to ``approve``. A capability nobody has classified must not run
    unattended because the row was created by a migration."""

    enabled = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        db_table = "attest_autonomy_policies"
        constraints = [
            models.UniqueConstraint(
                fields=["tenant_id", "capability"], name="attest_autonomy_unique"
            )
        ]

    def __str__(self) -> str:
        return f"{self.tenant_id}/{self.capability}={self.mode}"


class QueuedRun(models.Model):
    """A run waiting for, or being worked by, a worker.

    The envelope is a column rather than a broker message because a broker that loses
    a message loses the run silently: the caller holds a run id that will never produce
    an attestation, which is indistinguishable from a run that is merely slow. Written
    here first, the envelope survives the broker, and the same row is what a resumption
    re-dispatches — there is nowhere else the proposal still exists once the worker has
    returned on a hold.
    """

    QUEUED = "queued"
    RUNNING = "running"
    HELD = "held"
    DONE = "done"
    FAILED = "failed"
    STATES = (
        (QUEUED, "queued"),
        (RUNNING, "running"),
        (HELD, "held"),
        (DONE, "done"),
        (FAILED, "failed"),
    )

    run_id = models.CharField(max_length=128, primary_key=True)
    tenant_id = models.CharField(max_length=128, db_index=True)
    actor_id = models.CharField(max_length=128)
    envelope = models.BinaryField()
    state = models.CharField(max_length=16, choices=STATES, default=QUEUED, db_index=True)
    attempt = models.IntegerField(default=1)
    """Incremented by a resumption, so a run resumed twice is distinguishable from one
    a client retried because it did not trust the ticket it was given."""

    submitted_at = models.DateTimeField(db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    detail = models.TextField(blank=True, default="")

    latest_run_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    """The attestation this dispatch most recently produced.

    A resumption is a **new run that supersedes the held one**, not a rewrite of it:
    the held attestation is a real record saying "we held", and a reader who relied on
    it must still be able to see it. So each attempt has its own run id and this column
    says which one is current, while the primary key stays the ticket the caller holds.
    """

    worker_id = models.CharField(max_length=128, blank=True, default="")
    lease_expires_at = models.DateTimeField(null=True, blank=True, db_index=True)
    """When another worker may take this run back.

    Without a lease, a worker killed mid-run leaves the row in ``running`` forever: the
    run is neither retried nor visibly failed, and the caller's ticket never resolves.
    A pod eviction is not a rare event, so this is not a rare failure.
    """

    class Meta:
        db_table = "attest_queued_runs"
        indexes = [
            models.Index(fields=["state", "submitted_at"]),
            models.Index(fields=["state", "lease_expires_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.run_id} [{self.state}]"


class DispatchEvent(models.Model):
    """The delivery trail for one queued run. Append-only, like the audit chain.

    Deliberately **not** in the run's sealed chain. A chain is sealed by the run
    itself, in one process, at one instant; these are written by other processes before
    and after that — a queue accepting the work, a worker claiming it, a lease expiring
    at 3am with nobody watching. Folding them in would mean the seal covered events it
    never saw, which is the ordering problem ADR 0034 exists to fix arriving by another
    door.

    They are still evidence, and they answer the questions the chain cannot: how long
    did this wait, which worker had it, how many times was it resumed, and — the one
    that matters at 3am — did anything take it and never come back.
    """

    id = models.BigAutoField(primary_key=True)
    dispatch_id = models.CharField(max_length=128, db_index=True)
    """The ticket the caller holds, stable across every attempt."""

    run_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    """The attestation this event concerns, when there is one yet."""

    tenant_id = models.CharField(max_length=128, db_index=True)
    event_type = models.CharField(max_length=64, db_index=True)
    occurred_at = models.DateTimeField(db_index=True)
    attempt = models.IntegerField(default=1)
    actor = models.CharField(max_length=128, blank=True, default="")
    """Who caused it: a worker id for a claim, a person for a resumption."""

    detail = models.TextField(blank=True, default="")

    class Meta:
        db_table = "attest_dispatch_events"
        indexes = [
            models.Index(fields=["dispatch_id", "occurred_at"]),
            models.Index(fields=["tenant_id", "occurred_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.dispatch_id}/{self.event_type}"


class MemoryRecord(models.Model):
    """Cross-run recall. Deletable, unlike the audit chain.

    Memory is untrusted input the system wrote to itself, and it is subject to erasure
    requests — which is exactly why it lives here rather than in the append-only chain.
    """

    id = models.BigAutoField(primary_key=True)
    tenant_id = models.CharField(max_length=128, db_index=True)
    subject_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    content = models.TextField()
    content_hash = models.CharField(max_length=64, db_index=True)
    created_at = models.DateTimeField()

    memory_class = models.CharField(max_length=16, default="fact", db_index=True)
    """FACT or INSTRUCTION, decided at write time and never re-derived at recall.

    A store that keeps only the text has thrown away the distinction, so an instruction
    smuggled in as a fact is recalled as one — which is the persistent injection this
    whole module exists to stop."""

    author = models.CharField(max_length=128, blank=True, default="")
    author_is_human = models.BooleanField(default=False)
    """Defaults to False because an unattributed write must be treated as an agent's:
    the guard forbids agent-authored instructions, and a default of True would make
    forgetting to pass the author a way past it."""

    origin_run = models.CharField(max_length=128, blank=True, default="", db_index=True)
    source_attestation = models.CharField(max_length=128, blank=True, default="")
    """The attestation that established this fact. Without it the item is hearsay: it
    may be recalled as context but must never be cited as support."""

    expires_at = models.DateTimeField(null=True, blank=True, db_index=True)

    class Meta:
        db_table = "attest_memory"
        indexes = [models.Index(fields=["tenant_id", "subject_id"])]

    def __str__(self) -> str:
        return f"memory:{self.tenant_id}/{self.pk}"


class RedeemedNonce(models.Model):
    """The replay defence, as a uniqueness constraint.

    Single-use redemption cannot be implemented as read-then-write: two concurrent
    redemptions would both observe an unused nonce and both proceed. The primary key
    does the work, and the second insert raises.
    """

    nonce = models.CharField(max_length=128, primary_key=True)
    grant_id = models.CharField(max_length=128, db_index=True)
    redeemed_at = models.DateTimeField()

    class Meta:
        db_table = "attest_redeemed_nonces"


class RevokedGrant(models.Model):
    """Grants withdrawn before use."""

    grant_id = models.CharField(max_length=128, primary_key=True)
    revoked_at = models.DateTimeField()
    reason = models.TextField(blank=True, default="")

    class Meta:
        db_table = "attest_revoked_grants"


class BudgetReservation(models.Model):
    """Spend held against a scope, reserved before the call rather than read after it."""

    reservation_id = models.CharField(max_length=128, primary_key=True)
    scope = models.CharField(max_length=128, db_index=True)
    amount = models.DecimalField(max_digits=20, decimal_places=6)
    """Decimal, never float. A financial record that rounds is not a record."""

    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        db_table = "attest_budget_reservations"


class BudgetSpend(models.Model):
    """Committed spend per scope. Also the row a reservation locks."""

    scope = models.CharField(max_length=128, primary_key=True)
    amount = models.DecimalField(max_digits=20, decimal_places=6, default=0)
    ceiling = models.DecimalField(max_digits=20, decimal_places=6, null=True, blank=True)
    reservation_seq = models.BigIntegerField(default=0)
    """Monotonic per scope. **Never derived from a count of live reservations.**

    A count goes back down when a reservation is released or committed, so the next
    reservation reuses the id the last one had. A worker that hung, had its
    reservation swept, and then woke up to commit would consume whichever
    reservation now holds that id — releasing a live hold and recording the wrong
    amount against the ceiling. Incremented under the same row lock as the ceiling
    check, so it is monotone without a second transaction.
    """

    class Meta:
        db_table = "attest_budget_spend"
