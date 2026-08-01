"""Ports — protocols the host implements. The kernel defines them and imports nothing.

The constraint that forced this design: across surveyed codebases the same conceptual
table had genuinely diverged — three different table names, two token-naming schemes,
three governance field names, and a user foreign key present in half of them. A
framework that mandates its own table cannot be adopted by any of them without a
migration merge against live production data. So it mandates nothing.

.. code-block:: text

    MANDATED MODEL                      PORT
    ─────────────────────               ────────────────────────────
    framework owns the table            host implements a protocol
    adoption = migration merge          adoption = write an adapter
    big bang, all or nothing            incremental, reversible

**Contract obligations a signature cannot express** are documented on each protocol and
tested by the conformance kit. They are not advisory. The highest-severity one is
:meth:`Retriever.retrieve`: scoping *after* retrieval means the index was already
queried across tenants, so a scoring bug becomes a data leak.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from attest.kernel.attestation import Attestation
    from attest.kernel.audit import AuditEvent, RunSeal
    from attest.kernel.authority import ApprovalRecord, AuthorizationGrant
    from attest.kernel.evidence import Evidence
    from attest.kernel.identifiers import (
        ActorId,
        ApprovalId,
        GrantId,
        Hash,
        Nonce,
        RunId,
        SubjectId,
        TenantId,
    )
    from attest.kernel.memory import MemoryItem

__all__ = [
    "SETTLED_STATES",
    "ApprovalStore",
    "AuditSink",
    "AutonomyMode",
    "AutonomyStore",
    "BudgetStore",
    "Clock",
    "IdGenerator",
    "IdempotencyStore",
    "MemoryStore",
    "NonceStore",
    "Retriever",
    "RunQueue",
    "RunStore",
    "RunWorkQueue",
    "SealRegistry",
    "Sealer",
    "Signer",
]


# ── Determinism ──────────────────────────────────────────────────────────────────


@runtime_checkable
class Clock(Protocol):
    """Time, injected.

    ``datetime.now()`` is banned in the core. A single ambient call in a prompt
    template renders a different body every call, so the content hash differs every
    call, so prompt versioning becomes meaningless and replay never reproduces — and
    nothing errors. It just stops working.

    **Contract:** ``now()`` returns a timezone-aware datetime, and is monotonic within
    a run. A clock that goes backwards mid-run produces an audit chain whose timestamps
    contradict its sequence.
    """

    def now(self) -> datetime: ...


@runtime_checkable
class IdGenerator(Protocol):
    """Identifiers, injected.

    ``uuid4`` is banned in the core for the same reason as ambient time: a run whose
    ids differ on every execution cannot be replayed or diffed against its original.

    **Contract:** ids are unique within a deployment, and the generator is seedable so
    a replay can reproduce them.
    """

    def new_id(self, prefix: str) -> str:
        """A fresh identifier. Deterministic under a seed, and **never a nonce**.

        See :meth:`NonceStore.redeem` for why the two id spaces cannot be the same one.
        """
        ...


# ── Storage ──────────────────────────────────────────────────────────────────────


@runtime_checkable
class RunStore(Protocol):
    """Persistence for attestations.

    **Contract:** attestations are **immutable once written**. There is no ``update``,
    deliberately. A correction is a new record referencing the old, so a reader who
    relied on the original can still see exactly what they relied on.
    """

    def create(self, attestation: Attestation) -> RunId: ...

    def get(self, run_id: RunId) -> Attestation | None: ...

    def supersede(self, run_id: RunId, replacement: Attestation) -> RunId:
        """Record ``replacement`` as superseding ``run_id``. Both are retained."""
        ...


@runtime_checkable
class AuditSink(Protocol):
    """Append-only event storage.

    **Contract, and it is not satisfiable in application code:** appends only.
    Enforcement belongs *below* the application — a database trigger or equivalent —
    because "we only ever INSERT" is a convention, and conventions decay. One surveyed
    codebase already does this correctly; it is the right pattern.

    Events arrive **unsealed**. The sink stores causal structure; the
    :class:`Sealer` assigns canonical positions later. A sink that assigns its own
    sequence numbers on insert reintroduces the ordering bug that ADR 0034 exists to
    fix, because effect events are written immediately while everything else batches.
    """

    def append(self, event: AuditEvent) -> None: ...

    def append_many(self, events: Sequence[AuditEvent]) -> None:
        """Append a batch atomically.

        Batching is how the write amplification of 15 events per run stays affordable
        at volume. Effect events are excluded from batching by the capability layer:
        losing one creates an unreconcilable state.
        """
        ...

    def read_chain(self, run_id: RunId) -> Sequence[AuditEvent]: ...


@runtime_checkable
class Sealer(Protocol):
    """Assigns canonical positions and produces the seal.

    **Contract: independent of the application.** An application that omits an event
    would otherwise also report the count that hides it — self-certification, which
    cannot detect anything. Acceptable implementations are a database function, a
    separate sealing service, or an append-only log with its own ordering guarantee.

    The sealer computes the canonical topological order over the run's complete durable
    event set, assigns a dense sequence from 1, builds the chain, and signs.
    """

    def seal(self, run_id: RunId, attestation_hash: Hash) -> RunSeal: ...


@runtime_checkable
class SealRegistry(Protocol):
    """Records that a run's chain is closed, so storage can enforce it.

    The append-only guard rejects UPDATE and DELETE and must permit INSERT — the table
    is append-only. That leaves the other half open: anything with database access,
    including an SQL injection elsewhere in the host application, can append rows to a
    run that was already sealed, and the seal's dense count catches it only when the
    periodic sweep next runs.

    **Contract: ``close`` is called by whoever seals, at the moment they seal.** A
    registry nothing writes to leaves its trigger permanently unarmed — which is the
    same defect as an unwired control, arriving as an empty table rather than an
    uncalled method.
    """

    def close(self, run_id: RunId, seal: RunSeal) -> None: ...

    def is_sealed(self, run_id: RunId) -> bool: ...


@runtime_checkable
class Signer(Protocol):
    """Signs seals, checkpoints and bundle manifests.

    Chain integrity proves *internal* consistency. A signature proves the record came
    from this system rather than from someone reconstructing a plausible chain.

    **Contract:** the private key never leaves the signer. ``verify`` must work from
    the public key alone, so an offline verifier can check a bundle without our code —
    which is the whole point of an evidence bundle.
    """

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, signature: str) -> bool: ...


class AutonomyMode:
    """How much a capability may do without a human. Mirrors the stored vocabulary."""

    AUTO = "auto"
    APPROVE = "approve"
    BLOCKED = "blocked"

    ALL = (AUTO, APPROVE, BLOCKED)


@runtime_checkable
class AutonomyStore(Protocol):
    """Where the kill switch lives.

    A row rather than a deploy, because a control you can only exercise by shipping
    code is not a control you can exercise during an incident.

    **Here rather than in ``runtime.operations`` for two reasons.** It is a storage port
    like every other one, and `docs/kernel/ports.md` already listed it in the port table
    under a name — ``PolicyStore`` — that existed nowhere in the code. And
    ``scripts/check_reachability.py`` derives its control list from the Protocols in
    *this file*, so a port declared elsewhere is a control the gate cannot see. Both
    halves of that mattered: the switch was written, audited, and read by nothing on any
    execution path, and the gate written to catch exactly that class of defect passed.

    **Contract:** ``set_mode`` is durable before it returns. A kill switch that is
    eventually consistent is a kill switch that is off during the window that matters.
    """

    def set_mode(
        self, *, tenant: TenantId, capability: str, mode: str, enabled: bool, by: str
    ) -> None: ...

    def modes(self, *, tenant: TenantId | None = None) -> Sequence[Mapping[str, object]]: ...

    def mode_for(self, *, tenant: TenantId, capability: str) -> str:
        """The mode in force for one capability. One of :class:`AutonomyMode`.

        Separate from :meth:`modes` because the run path asks about a single capability
        and must not pay for, or filter, every row in the deployment.

        **What absence means is the store's to decide, and it should decide BLOCKED.**
        The shipped Django store does: "a capability nobody has classified must not run
        unattended because a row was missing - an absent policy is an unanswered
        question, not permission." That is why an engine given no store at all is
        unaffected while an engine given one is opting into deny-by-default: the choice
        is made by wiring the store, which is visible, rather than by a default nobody
        reads.
        """
        ...


# ── Authority ────────────────────────────────────────────────────────────────────


@runtime_checkable
class NonceStore(Protocol):
    """Single-use redemption of authorization grants.

    **Contract: ``redeem`` is atomic, and returns True at most once per nonce.** This
    is the entire replay defence, and it cannot be implemented as read-then-write —
    two concurrent redemptions would both observe an unused nonce and both proceed.
    A unique constraint or a compare-and-set is required.

    A store that cannot guarantee this must raise rather than approximate it. See
    threat-model attack 8.

    **Contract: nonces come from a CSPRNG, not from the** :class:`IdGenerator`. The two
    documented requirements were in direct conflict and nothing reconciled them:
    determinism.md requires ids to be seedable so a replay reproduces them, and a
    seeded generator emits the same nonce for the same position in every run. The first
    run redeems it; every later run's redemption returns ``False`` and the boundary
    refuses the effect as a replay — a total outage of all effects from a generator
    that satisfies the documented rule.

    Where ids are merely *predictable* rather than repeated, it is an attack instead of
    a fault: anyone who can dispatch can burn the nonce values a victim's run will use,
    and their payment is refused. Denial of authority, targeted, with no privilege
    beyond dispatch.

    A replayed run re-executes nothing, so it needs no nonce, so nothing is lost by
    making these unpredictable.
    """

    def redeem(self, nonce: Nonce, grant_id: GrantId) -> bool:
        """Consume ``nonce``. True if this call consumed it; False if already used."""
        ...

    def is_revoked(self, grant_id: GrantId) -> bool: ...


@runtime_checkable
class IdempotencyStore(Protocol):
    """Remembers which actions already happened, across runs.

    The nonce defends one *grant* against replay. It does not defend against the same
    action being **re-proposed**: a retried request produces a new run, a new nonce and
    a new grant, and executes the effect a second time. For a framework whose thesis is
    that no consequential effect executes without authorisation, double-submit is the
    likeliest production failure, and it is not an authorisation failure at all.

    **Contract: ``claim`` is atomic and returns the prior outcome.** Two concurrent
    claims on one key must not both succeed. A store that reads and then writes lets
    both proceed, which is the failure this exists to prevent rather than a rare edge.

    The key is the caller's, and it must be derived from what makes the action unique
    to the *business* — an invoice id, a payment reference — not from the run. A key
    derived from the run is a different key on every retry, which is no key at all.
    """

    def claim(self, key: str, *, tenant: TenantId, action_hash: Hash, now: datetime) -> str | None:
        """Claim ``key`` for this action, **within this tenant**.

        The tenant is not optional. The key is explicitly business-derived — an invoice
        id, a payment reference — which is exactly the class of value that collides
        across tenants. With one global namespace, claiming ``INV-000123`` for a trivial
        action made every subsequent run of another tenant carrying that key fail; and
        where two actions hashed equal, the second tenant received the first's upstream
        payment reference and the effect was skipped.

        Returns ``None`` when the claim is new and the caller may proceed. Returns the
        recorded external reference when the action already ran, so the caller reports
        the original outcome rather than causing a second one.

        Raises when ``key`` was claimed for a *different* ``action_hash``: the same key
        meaning two different actions is a collision the caller has to fix, and
        silently allowing either would be worse than refusing both.
        """
        ...

    def settle(self, key: str, *, tenant: TenantId, external_reference: str) -> None:
        """Record what the upstream returned, so a later claim can report it."""
        ...

    def release(self, key: str, *, tenant: TenantId) -> None:
        """Give the key back when the effect did not reach the upstream at all."""
        ...


@runtime_checkable
class BudgetStore(Protocol):
    """Spend ceilings, reserved before the call rather than read after it.

    **Contract: ``reserve`` is atomic.** A budget that is *read* and then acted on is a
    race — two concurrent runs both observe headroom and both spend it. A store without
    transactions cannot satisfy this, and must raise rather than pretend.

    Reservations expire on the same short clock as a grant, so a crashed run cannot
    hold budget indefinitely. See threat-model attack 9.
    """

    def reserve(self, scope: str, amount: str, expires_at: datetime) -> str | None:
        """Reserve ``amount`` against ``scope``. Returns a reservation id, or None."""
        ...

    def commit(self, reservation_id: str, actual_amount: str) -> None: ...

    def release(self, reservation_id: str) -> None: ...


@runtime_checkable
class ApprovalStore(Protocol):
    """Pending human decisions.

    **Contract: every pending action has an expiry, and expiry is enforced.** An
    approval queue without expiry becomes a backlog of half-executed decisions with no
    owner. Expiry produces a refusal with a typed reason, never a silent drop.
    """

    def open(
        self,
        grant: AuthorizationGrant,
        *,
        run_id: RunId,
        expires_at: datetime,
        summary: str = "",
    ) -> str:
        """Open one pending decision against ``grant``. Returns its id.

        The grant is the argument rather than a spread of fields because it already
        carries the binding — tenant, actor, and the action hash that covers the
        arguments. A caller assembling those by hand can assemble them inconsistently,
        and an approval bound to the wrong action is exactly the failure ``covers``
        exists to prevent.

        ``summary`` is what the approver is shown. An approval screen that names only
        the tool is asking someone to authorise an amount they were never shown.
        """
        ...

    def resolve(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: ActorId,
        at: datetime,
        role: str,
    ) -> None:
        """Record one decision.

        ``at`` is passed rather than read. The kernel has no ambient clock, and a
        decision timestamped by the store is a decision whose time cannot be replayed.

        ``role`` is not optional. An n-of-m quorum is defined over roles, so a decision
        stored without one counts toward nothing — the queue would fill with approvals
        the authority layer cannot consume, and the run would hold forever.
        """
        ...

    def consume(self, approval_ids: Sequence[ApprovalId], *, grant_id: GrantId) -> None:
        """Mark decisions as spent by ``grant_id``. **A decision authorises once.**

        Without this, one legitimate "approve this GBP 500,000 transfer" authorised an
        unlimited number of them. The action hash is identical by construction on a
        re-submission, so ``decisions()`` returned the original approval, a fresh grant
        was issued and a fresh nonce redeemed — and the transfer executed again. The
        nonce defends one *grant*; nothing defended the *decision*.
        """
        ...

    def decisions(self, action_hash: Hash) -> Sequence[ApprovalRecord]:
        """Every **unspent** decision recorded about *this* action.

        Keyed on the action hash rather than the run, because that is what discharges:
        an approval must say what it was about, or it is a free-floating "yes" that
        would satisfy any obligation it were handed to. Without this method the
        obligations that need recorded approvals — :class:`Approval`, ``DualControl`` —
        have no way to reach them, and stay PENDING forever.
        """
        ...

    def expire_due(self, now: datetime) -> Sequence[str]:
        """Expire everything past its deadline. Returns the ids expired."""
        ...


@runtime_checkable
class RunQueue(Protocol):
    """Hands a run to a worker, so a long one does not hold a request open.

    A governed run makes model calls and then an external effect. Performed inside the
    HTTP request, one run holding a worker for six seconds means peak throughput is
    bounded by the worker pool rather than by anything the framework does — and the
    pool is exhausted by the slow upstream, not by load.

    **Contract: ``submit`` returns before the run executes**, and is idempotent on
    ``run_id``. Idempotency matters more than it looks: a client that retries a
    timed-out dispatch must not get two runs, because the second one would propose the
    same effect again with a fresh grant.

    **Contract: the envelope is durable before ``submit`` returns.** A queue that loses
    the envelope loses the run silently — the caller holds a run id that will never
    produce an attestation, which is indistinguishable from a run that is merely slow.
    This is also what makes resumption possible: a held run is resumed by submitting
    the same envelope again, and there is nowhere else the proposal still exists.
    """

    def submit(self, run_id: RunId, envelope: bytes) -> str:
        """Queue the run. Returns a ticket the host can use to track it."""
        ...

    def resume(self, run_id: RunId) -> str:
        """Re-dispatch a run that was suspended awaiting something external.

        Separate from ``submit`` because the two differ operationally: a resumption is
        expected to already have an envelope and a partially-built record, and a
        resumption for an unknown run is a bug rather than a new run.
        """
        ...


SETTLED_STATES: Final[frozenset[str]] = frozenset({"held", "done", "failed"})
"""The only values :meth:`RunWorkQueue.settle` accepts.

Written down here because it was not written down anywhere: the port declared
``state: str`` and the shipped adapter enforced a three-value vocabulary it had chosen
privately. An adapter author reading the port had no way to learn which strings were
meant, and would discover it from a ``StoreError`` in production.

``held`` is not an end. A resumption waits on that row, so a queue that treats it as
terminal strands every run awaiting a human.
"""


@runtime_checkable
class RunWorkQueue(Protocol):
    """The consumer half of :class:`RunQueue`. Implemented by the store of record.

    Split from ``RunQueue`` because the two halves are held by different processes and
    often by different objects: a web process needs only ``submit``, and giving it
    ``settle`` invites a view to mark a run done that it did not run.

    **Contract: ``claim`` is atomic and does not serialise workers.** The obvious
    implementation — take the oldest row under a lock — makes every worker contend for
    the same row, so the pool drains no faster than one worker. ``SKIP LOCKED`` or an
    equivalent is required, not an optimisation.
    """

    def fetch(self, run_id: RunId) -> bytes | None:
        """The envelope for one run, for a worker woken by a broker notification."""
        ...

    def claim(self, *, now: datetime | None = None, limit: int = 1) -> Sequence[bytes]:
        """Take up to ``limit`` envelopes and mark them running. For the polling path."""
        ...

    def settle(
        self, run_id: RunId, *, state: str, detail: str = "", now: datetime | None = None
    ) -> None:
        """Record how the run ended. A held run is not ended — resume waits on it.

        ``state`` is one of :data:`SETTLED_STATES`. It is a ``str`` rather than an enum
        because the queue rows are read by operators and by SQL neither this package nor
        the host controls, and a stored ``"RunState.DONE"`` is a value nobody can query
        for. The vocabulary is still closed, and an implementation must reject anything
        outside it — a state it does not recognise is a run whose outcome it is about to
        record incorrectly.
        """
        ...

    def depth(self) -> int:
        """How many runs are waiting. The number an operator pages on."""
        ...


# ── Retrieval and memory ─────────────────────────────────────────────────────────


@runtime_checkable
class Retriever(Protocol):
    """Fetches candidate evidence.

    **Contract, and the highest-severity one here: scope by tenant AT THE QUERY, never
    after.** Filtering after retrieval means the index was already searched across
    tenants, so a scoring bug becomes a data leak rather than a ranking error. The
    boundary guard's post-hoc assertion is deliberately redundant with this, and
    reaching it means the primary scoping already failed.
    """

    def retrieve(self, query: str, *, tenant: TenantId, limit: int) -> Sequence[Evidence]: ...


@runtime_checkable
class MemoryStore(Protocol):
    """Recall across runs. The most dangerous capability in the framework.

    Memory is untrusted input that the system wrote to itself: text injected in one run
    is recalled as trusted context in the next.

    **Contract:** scope filtering happens *before* semantic search, for the same reason
    as :class:`Retriever`. And ``delete_by_subject`` must actually delete — memory is
    subject to erasure requests, which is why it lives behind a port rather than in the
    append-only audit chain.
    """

    def recall(
        self, query: str, *, tenant: TenantId, subject: SubjectId | None, limit: int
    ) -> Sequence[MemoryItem]: ...

    def remember(self, item: MemoryItem) -> None:
        """Store one item. The tenant is **on the item**, not a separate argument.

        Two sources of truth for the boundary is how a cross-tenant write happens: a
        caller that passes one tenant while the item names another has to be right
        every time, and the store has no way to tell which one was meant.

        **Contract: an implementation screens the write.** An agent may not write
        instruction memory — that is persistent prompt injection — and the screening
        must happen here rather than at recall, because a store that accepts anything
        has already been poisoned by the time anyone reads it. See
        :class:`~attest.capabilities.memory.MemoryGuard`.
        """
        ...

    def delete_by_subject(self, subject: SubjectId, *, tenant: TenantId) -> int:
        """Erase everything concerning ``subject``. Returns the count removed."""
        ...
