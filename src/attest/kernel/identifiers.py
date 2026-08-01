"""Typed identifiers.

Every id in the system is a ``NewType`` over ``str``. They are erased at runtime, so
they cost nothing, and ``mypy --strict`` rejects passing a ``TenantId`` where a
``RunId`` belongs.

That matters more here than in ordinary code. Most of these identifiers name a
security boundary: mixing up a ``TenantId`` and an ``ActorId`` in an authorisation
check is a cross-tenant read, and both are strings at runtime. The type checker is
the only thing that catches it before production.

Ids are **never generated here.** :mod:`attest.kernel.determinism` bans ambient
randomness, so construction goes through the injected ``IdGenerator`` port - otherwise
replay cannot reproduce a run.
"""

from __future__ import annotations

import hmac
import secrets
from typing import Final, NewType

__all__ = [
    "ID_PREFIXES",
    "ActorId",
    "ApprovalId",
    "AttestationId",
    "CorpusId",
    "DatasetId",
    "EvidenceId",
    "GrantId",
    "Hash",
    "Hashes",
    "Nonce",
    "Nonces",
    "PromptId",
    "RunId",
    "RunIds",
    "Secrets",
    "SubjectId",
    "TenantId",
]

# --- Identity and scope. Confusing any two of these is a boundary failure. ---
TenantId = NewType("TenantId", str)
ActorId = NewType("ActorId", str)
SubjectId = NewType("SubjectId", str)
"""The person a decision is *about* - distinct from the actor who requested it.

Banking has both boundaries and conflating them is a severe modelling error:
see docs/domains/banking.md.
"""

# --- Run lifecycle. ---
RunId = NewType("RunId", str)
AttestationId = NewType("AttestationId", str)
GrantId = NewType("GrantId", str)
ApprovalId = NewType("ApprovalId", str)


class RunIds:
    """The one convention shared by everything that identifies a run.

    A dispatch can produce several attestations. A run holds for approval, a human
    decides, the run is re-dispatched, and each attempt seals its own immutable record —
    ``RunStore`` has no ``update``, deliberately, because a reader who relied on the held
    record must still be able to see exactly what they relied on. So the attempts need
    distinguishable ids, and the *dispatch* needs to remain recoverable from any of them.

    .. code-block:: text

        run_7         attempt 1 — the id on the caller's ticket
        run_7#2       attempt 2, superseding run_7
        run_7#3       attempt 3, superseding run_7#2

    Written here rather than in the runtime layer because both sides need it and neither
    may import the other: :mod:`attest.runtime.dispatch` mints these and
    :mod:`attest.runtime.engine` reads them, and dispatch already imports the engine.
    """

    ATTEMPT: Final = "#"
    """Separator. Not in any generated id, so :meth:`dispatch_of` cannot mis-split one."""

    @classmethod
    def attempt(cls, run_id: RunId, attempt: int) -> RunId:
        """The id attempt ``n`` of ``run_id`` writes under. Attempt 1 is ``run_id``."""
        return run_id if attempt <= 1 else RunId(f"{run_id}{cls.ATTEMPT}{attempt}")

    @classmethod
    def dispatch_of(cls, run_id: RunId) -> RunId:
        """The dispatch an attestation belongs to. Idempotent, and safe on any id.

        What this is for: anything keyed on *the run a human is waiting on* rather than
        on one attempt of it. A pending approval row is the case — key it on the attempt
        and a run that holds, resumes and holds again opens a new row each cycle, while
        an approver sees several identical rows for one decision and may approve any of
        them.
        """
        return RunId(str(run_id).split(cls.ATTEMPT, 1)[0])


# --- Content and corpora. ---
EvidenceId = NewType("EvidenceId", str)
CorpusId = NewType("CorpusId", str)
DatasetId = NewType("DatasetId", str)
PromptId = NewType("PromptId", str)

# --- Cryptographic values. ---
Hash = NewType("Hash", str)
"""Lowercase hex SHA-256, as produced by :func:`attest.kernel.canonical.content_hash`."""

Nonce = NewType("Nonce", str)
"""Single-use value binding a grant to one redemption. Replay is detected, not prevented."""


ID_PREFIXES: Final[dict[str, str]] = {
    "run": "run",
    "attestation": "att",
    "grant": "grt",
    "approval": "apr",
    "evidence": "evd",
    "dataset": "dst",
    "event": "evt",
}
"""Human-readable prefixes for generated ids.

Purely an operational affordance: an id pasted into an incident channel should say
what it identifies. Nothing parses these, and no security property depends on them.
"""


class Nonces:
    """Single-use values for grant redemption. **Never from the id generator.**

    Separate from :class:`~attest.kernel.ports.IdGenerator` because the two have
    opposite requirements, and running them off one generator made them contradict each
    other. Ids must be reproducible so a replay can be diffed against its original;
    nonces must be unguessable so a grant cannot be pre-burned by someone who can
    dispatch runs. A seeded generator serving both meant the second run of a process
    had its effect refused as a replay.

    A replayed run re-executes nothing, so it never needs a nonce, so there is no
    replay requirement here to trade against.
    """

    BYTES: Final = 32
    """256 bits. The value is a database key an attacker may probe by attempting
    redemptions, and a short one is guessable in exactly the situation — a payment about
    to be made — where guessing is worth doing."""

    @classmethod
    def fresh(cls) -> Nonce:
        """A new nonce from the OS CSPRNG."""
        return Nonce(secrets.token_urlsafe(cls.BYTES))


class Hashes:
    """Construction and checking for :data:`Hash`.

    ``Hash = NewType("Hash", str)`` accepts any string — a ``NewType`` is a static
    fiction with no runtime check — and the value reaches places that assume otherwise:
    ``MerkleTree.node_hash`` calls ``bytes.fromhex`` and raises ``ValueError`` on
    anything else, and a witness client used to interpolate it into a URL path with no
    escaping, so a value containing ``?``, ``#`` or ``../`` altered the request.

    Not enforced inside ``Hash`` itself, because that would mean a runtime cost on every
    identifier in the system. Enforced where a hash crosses a boundary that cares.
    """

    LENGTH: Final = 64
    ALPHABET: Final = frozenset("0123456789abcdef")

    @classmethod
    def valid(cls, value: str) -> bool:
        return len(value) == cls.LENGTH and all(ch in cls.ALPHABET for ch in value)

    @classmethod
    def parse(cls, value: str, *, where: str = "hash") -> Hash:
        """A hash, or a refusal naming where it came from.

        Lowercase only: two spellings of one digest would compare unequal, and a
        content-addressed system in which the same content has two addresses is not
        content-addressed.
        """
        if not cls.valid(value):
            raise ValueError(
                f"{where} {value[:32]!r} is not a hash: expected {cls.LENGTH} lowercase "
                f"hex characters, got {len(value)}. A content address that is not one "
                f"reaches code that assumes it is — bytes.fromhex, and a URL path."
            )
        return Hash(value)


class Secrets:
    """Comparison for values that function as secrets. **Never ``==``.**

    A content hash compared with ``==`` is near-irrelevant — an attacker cannot iterate
    cheaply against a local comparison, and the digest is public anyway. A nonce is
    different: it is the single-use value that authorises an effect, and any future
    HMAC-style check would inherit whatever convention is set here.

    So the convention is set here rather than re-decided at each site: anything that
    functions as a secret is compared with :func:`hmac.compare_digest`.
    """

    @staticmethod
    def equal(left: str, right: str) -> bool:
        """Constant-time string comparison."""
        return hmac.compare_digest(left, right)
