"""In-memory reference adapters.

**Deliberately not simplified.** An in-memory ``AuditSink`` that permitted updates
would let every host's tests pass against a sink that violates its contract, so these
enforce append-only, dense sequencing and atomic redemption exactly as a production
store must.

Single-process only. ``threading.Lock`` gives real atomicity within one interpreter,
which is what makes the concurrency suite meaningful — but it is not distributed, and
a multi-process deployment needs a store with its own transactional guarantee.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from attest.kernel.errors import ApprovalStoreError, AuditSinkError, StoreError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from attest.kernel.attestation import Attestation
    from attest.kernel.audit import AuditEvent
    from attest.kernel.authority import ApprovalRecord, AuthorizationGrant
    from attest.kernel.identifiers import ActorId, ApprovalId, GrantId, Hash, Nonce, RunId

__all__ = [
    "InMemoryApprovalStore",
    "InMemoryAuditSink",
    "InMemoryBudgetStore",
    "InMemoryIdempotencyStore",
    "InMemoryNonceStore",
    "InMemoryRunStore",
]


class InMemoryRunStore:
    """Attestations, immutable once written."""

    __slots__ = ("_lock", "_runs", "_superseded_by")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: dict[RunId, Attestation] = {}
        self._superseded_by: dict[RunId, RunId] = {}

    def create(self, attestation: Attestation) -> RunId:
        with self._lock:
            if attestation.run_id in self._runs:
                raise StoreError(
                    f"attestation {attestation.run_id!r} already exists. Attestations "
                    f"are immutable; a correction is a new record via supersede()."
                )
            self._runs[attestation.run_id] = attestation
            return attestation.run_id

    def get(self, run_id: RunId) -> Attestation | None:
        with self._lock:
            return self._runs.get(run_id)

    def supersede(self, run_id: RunId, replacement: Attestation) -> RunId:
        """Record a correction. **Both are retained.**

        A reader who relied on the original must be able to see exactly what they
        relied on, which is why there is no update.
        """
        with self._lock:
            if run_id not in self._runs:
                raise StoreError(f"cannot supersede unknown run {run_id!r}")
            stored = self._runs.get(replacement.run_id)
            if stored is not None and stored.content_hash() != replacement.content_hash():
                # Immutability is a property of every write path, not only of create().
                # This assigned straight into the map, so the *correction* path — whose
                # whole purpose is that the earlier record survives — could destroy an
                # attestation. An identical replacement is an idempotent retry and is
                # allowed; a different one is refused.
                raise StoreError(
                    f"attestation {replacement.run_id!r} already exists with different "
                    f"content. Attestations are immutable on every path, not only on "
                    f"create(); a supersession may not overwrite one."
                )
            self._runs[replacement.run_id] = replacement
            self._superseded_by[run_id] = replacement.run_id
            return replacement.run_id

    def superseded_by(self, run_id: RunId) -> RunId | None:
        with self._lock:
            return self._superseded_by.get(run_id)


class InMemoryAuditSink:
    """Append-only, and it enforces that rather than assuming it."""

    __slots__ = ("_by_run", "_lock", "_sealed")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_run: dict[RunId, list[AuditEvent]] = {}
        self._sealed: set[RunId] = set()

    def append(self, event: AuditEvent) -> None:
        with self._lock:
            self._assert_open(event.run_id)
            self._by_run.setdefault(event.run_id, []).append(event)

    def append_many(self, events: Sequence[AuditEvent]) -> None:
        """Atomic: either every event lands or none does.

        A partial batch would leave a chain that cannot be sealed densely, which is
        indistinguishable from omission.
        """
        if not events:
            return
        with self._lock:
            for event in events:
                self._assert_open(event.run_id)
            for event in events:
                self._by_run.setdefault(event.run_id, []).append(event)

    def _assert_open(self, run_id: RunId) -> None:
        if run_id in self._sealed:
            raise AuditSinkError(
                f"run {run_id!r} is sealed; appending after the seal would make the "
                f"bound event count wrong, which is what the seal exists to detect"
            )

    def mark_sealed(self, run_id: RunId) -> None:
        with self._lock:
            self._sealed.add(run_id)

    def read_chain(self, run_id: RunId) -> Sequence[AuditEvent]:
        with self._lock:
            return tuple(self._by_run.get(run_id, ()))


class InMemoryNonceStore:
    """Single-use redemption, genuinely atomic within the process.

    ``redeem`` returns ``True`` at most once per nonce **under concurrency**, not just
    in sequence. Implemented as a check-and-insert under one lock rather than a read
    followed by a write, because the latter lets two concurrent callers both observe
    an unused nonce and both proceed — which is the entire replay defence gone.
    """

    __slots__ = ("_lock", "_redeemed", "_revoked")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._redeemed: dict[Nonce, GrantId] = {}
        self._revoked: set[GrantId] = set()

    def redeem(self, nonce: Nonce, grant_id: GrantId) -> bool:
        with self._lock:
            if nonce in self._redeemed:
                return False
            self._redeemed[nonce] = grant_id
            return True

    def revoke(self, grant_id: GrantId) -> None:
        with self._lock:
            self._revoked.add(grant_id)

    def is_revoked(self, grant_id: GrantId) -> bool:
        with self._lock:
            return grant_id in self._revoked


class InMemoryBudgetStore:
    """Reserve-then-commit, atomically.

    A budget that is *read* and then acted on is a race: two concurrent runs both see
    headroom and both spend it. Reservation and the ceiling check happen under one
    lock, so the second caller sees the first's reservation.
    """

    __slots__ = ("_ceilings", "_lock", "_reservations", "_sequence", "_spent")

    def __init__(self, ceilings: dict[str, str] | None = None) -> None:
        self._lock = threading.Lock()
        self._ceilings = {k: Decimal(v) for k, v in (ceilings or {}).items()}
        self._spent: dict[str, Decimal] = {}
        self._reservations: dict[str, tuple[str, Decimal, datetime]] = {}
        self._sequence: dict[str, int] = {}

    def reserve(
        self, scope: str, amount: str, expires_at: datetime, *, now: datetime | None = None
    ) -> str | None:
        """Reserve against ``scope``. ``None`` when it would breach the ceiling.

        **Expired reservations are excluded from the held total**, rather than counted
        until some sweeper runs. They were counted, which meant a crashed run held its
        budget for the rest of the window: one crash during a busy hour took the
        tenant's whole ceiling with it, and every later run was refused for a spend that
        never happened. The Django store already did this correctly and this one did
        not, which is the divergence the conformance kit exists to surface — and it went
        unsurfaced because the reference adapters had no conformance coverage.

        ``now`` is an optional keyword with a default, so a caller holding the port can
        still call ``reserve(scope, amount, expires_at)``. Injectable because a test
        that has to sleep to observe an expiry is a test nobody runs.
        """
        value = Decimal(amount)
        moment = now if now is not None else datetime.now(UTC)
        with self._lock:
            ceiling = self._ceilings.get(scope)
            committed = self._spent.get(scope, Decimal(0))
            held = sum(
                (
                    reservation[1]
                    for reservation in self._reservations.values()
                    if reservation[0] == scope and reservation[2] > moment
                ),
                Decimal(0),
            )
            if ceiling is not None and committed + held + value > ceiling:
                return None
            # Monotonic per scope, never a count of live reservations: a count falls
            # when one is released, so the next reservation would reuse a retired id
            # and a late commit from the previous holder would consume it — releasing
            # a live hold and charging the wrong amount against the ceiling.
            self._sequence[scope] = self._sequence.get(scope, 0) + 1
            reservation_id = f"res_{scope}_{self._sequence[scope]}"
            self._reservations[reservation_id] = (scope, value, expires_at)
            return reservation_id

    def commit(self, reservation_id: str, actual_amount: str) -> None:
        with self._lock:
            reservation = self._reservations.pop(reservation_id, None)
            if reservation is None:
                raise StoreError(f"unknown reservation {reservation_id!r}")
            scope, _, _ = reservation
            self._spent[scope] = self._spent.get(scope, Decimal(0)) + Decimal(actual_amount)

    def release(self, reservation_id: str) -> None:
        with self._lock:
            self._reservations.pop(reservation_id, None)

    def expire_due(self, now: datetime) -> int:
        """Release reservations past their expiry.

        Reservations expire on the same short clock as a grant, so a crashed run
        cannot hold budget indefinitely.
        """
        with self._lock:
            stale = [k for k, (_, _, exp) in self._reservations.items() if exp <= now]
            for key in stale:
                self._reservations.pop(key)
            return len(stale)

    def spent(self, scope: str) -> str:
        with self._lock:
            return str(self._spent.get(scope, Decimal(0)))


class InMemoryApprovalStore:
    """Pending actions, with expiry enforced and decisions bound to their action.

    This adapter had drifted off :class:`~attest.kernel.ports.ApprovalStore` entirely:
    ``open`` took no ``run_id`` or ``summary``, ``resolve`` took no ``at`` or ``role``,
    and ``decisions`` and ``consume`` did not exist. Because a Protocol's
    ``isinstance()`` compares **method names**, it satisfied the check and raised
    ``TypeError`` on the first real call — and the two methods it was missing are the
    read side ``Approval`` and ``DualControl`` need, so a deployment wiring this store
    got runs that held forever and no error explaining why.

    It was the reference adapter, used by every quickstart and every fixture, and it had
    no conformance coverage. That combination is how a framework teaches its own
    adopters the wrong contract.
    """

    __slots__ = ("_lock", "_pending", "_records", "_spent")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending: dict[str, tuple[AuthorizationGrant, datetime, str]] = {}
        self._records: dict[str, ApprovalRecord] = {}
        self._spent: dict[str, GrantId] = {}

    def open(
        self,
        grant: AuthorizationGrant,
        *,
        run_id: RunId,
        expires_at: datetime,
        summary: str = "",
    ) -> str:
        if expires_at <= grant.issued_at:
            raise ApprovalStoreError(
                "a pending action must expire after it opens; an open-ended hold is a "
                "backlog of half-executed decisions with no owner"
            )
        with self._lock:
            approval_id = f"apr_{grant.grant_id}_{run_id}"
            self._pending[approval_id] = (grant, expires_at, summary)
            return approval_id

    def resolve(
        self,
        approval_id: str,
        *,
        approved: bool,
        approver: ActorId,
        at: datetime,
        role: str,
    ) -> None:
        """Record one decision. ``role`` is not optional — a quorum is defined over it."""
        from attest.kernel.authority import ApprovalRecord
        from attest.kernel.identifiers import ApprovalId

        with self._lock:
            pending = self._pending.pop(approval_id, None)
            if pending is None:
                raise ApprovalStoreError(
                    f"approval {approval_id!r} is not pending; it may have expired or "
                    f"already been decided. Either is a refusal rather than a silent "
                    f"overwrite of a decision whose window has closed."
                )
            grant, _, summary = pending
            self._records[approval_id] = ApprovalRecord(
                approval_id=ApprovalId(approval_id),
                approver=approver,
                role=role,
                approved=approved,
                decided_at=at,
                action_hash=grant.action_hash,
                note=summary,
            )

    def consume(self, approval_ids: Sequence[ApprovalId], *, grant_id: GrantId) -> None:
        """Mark decisions spent. **A decision authorises once.**

        Raises when any id is unknown or already spent, rather than marking what it can
        and reporting success. The engine treats a successful ``consume`` as "these can
        no longer authorise anything" and executes on that basis, so a partial success
        reported as a success is one approval authorising an unlimited number of
        transfers.
        """
        with self._lock:
            unspendable = [
                str(identifier)
                for identifier in approval_ids
                if str(identifier) not in self._records or str(identifier) in self._spent
            ]
            if unspendable:
                raise ApprovalStoreError(
                    f"cannot spend {unspendable}: unknown to this store, or already "
                    f"taken by another grant. They would still authorise the next "
                    f"identical proposal."
                )
            for identifier in approval_ids:
                self._spent[str(identifier)] = grant_id

    def decisions(self, action_hash: Hash) -> Sequence[ApprovalRecord]:
        """Every **unspent** decision about *this* action.

        Keyed on the action hash rather than the run: an approval that cannot say what
        it was about is a free-floating "yes" that would discharge any obligation it
        were handed to.
        """
        with self._lock:
            return tuple(
                record
                for approval_id, record in sorted(self._records.items())
                if approval_id not in self._spent and record.covers(action_hash)
            )

    def expire_due(self, now: datetime) -> Sequence[str]:
        """Expire everything past its deadline. Expired decisions never become records.

        An expiry that produced a resolved-as-rejected record would put a decision in
        the chain that no human made.
        """
        with self._lock:
            due = [k for k, (_, expires_at, _) in self._pending.items() if expires_at <= now]
            for key in due:
                self._pending.pop(key)
            return tuple(due)

    def outcome(self, approval_id: str) -> bool | None:
        """Whether this decision was an approval. ``None`` when undecided or expired."""
        with self._lock:
            record = self._records.get(approval_id)
            return None if record is None else record.approved


class InMemoryIdempotencyStore:
    """Single-claim-per-key, genuinely atomic within the process.

    The claim is a check-and-insert under one lock rather than a read followed by a
    write. Two concurrent retries of the same request would otherwise both observe an
    unclaimed key and both proceed, which is the double-submit this exists to prevent.
    """

    __slots__ = ("_claims", "_lock")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (tenant, key) -> (action_hash, external_reference or None while in flight)
        # Keyed by the pair, because the key is business-derived — an invoice id, a
        # payment reference — which is exactly the class of value that collides across
        # tenants. A global namespace made one tenant able to deny another's whole
        # payment run by claiming its key space.
        self._claims: dict[tuple[str, str], tuple[str, str | None]] = {}

    def claim(self, key: str, *, tenant: str, action_hash: str, now: datetime) -> str | None:
        with self._lock:
            existing = self._claims.get((tenant, key))
            if existing is None:
                self._claims[(tenant, key)] = (action_hash, None)
                return None
            claimed_for, reference = existing
            if claimed_for != action_hash:
                raise StoreError(
                    f"idempotency key {key!r} was claimed for a different action. The "
                    f"same key meaning two actions is a collision the caller must fix; "
                    f"allowing either one would be worse than refusing both."
                )
            if reference is None:
                raise StoreError(
                    f"idempotency key {key!r} is claimed and still in flight. Its "
                    f"outcome is unknown, so neither repeating it nor reporting it as "
                    f"done is safe — this is a reconciliation item, not a retry."
                )
            return reference

    def settle(self, key: str, *, tenant: str, external_reference: str) -> None:
        with self._lock:
            claimed = self._claims.get((tenant, key))
            if claimed is None:
                raise StoreError(f"cannot settle unclaimed idempotency key {key!r}")
            self._claims[(tenant, key)] = (claimed[0], external_reference)

    def release(self, key: str, *, tenant: str) -> None:
        """Give the key back. Only ever for a *definite* failure.

        A timeout must keep its key: the upstream may have committed, and releasing
        would let a retry commit it again.
        """
        with self._lock:
            self._claims.pop((tenant, key), None)
