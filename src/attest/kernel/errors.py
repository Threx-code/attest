"""Exceptions — the system being unable to decide.

The boundary between an exception and a :class:`~attest.kernel.verdicts.Refusal` is
decided once, here, because a framework built on fail-closed behaviour cannot afford
each call site to draw it differently.

.. code-block:: text

    A REFUSAL is a decision the system made.
    An EXCEPTION is the system being unable to decide.

    If an attestation can be produced, it is a refusal.
    If it cannot, it is an exception.

That test is mechanical and settles every case. Two near-misses are worth stating,
because they look backwards until the test is applied:

*An unreachable evidence source is a refusal.* The system is working, the world is not
cooperating, and that is a decision worth recording with its full context.

*An unwritable audit sink is an exception.* We cannot produce a record, so we must not
act at all.

Note what is deliberately **not** here: ``Refusal`` is not an exception. An earlier
implementation made it the base of half this hierarchy, so refusing raised — and a
raised refusal produces no attestation, which discards the evidence, the warrants and
the reason at exactly the moment they are most wanted. A refusal is a value returned
from a completed run. See :mod:`attest.kernel.verdicts` and ADR 0031.

The refusal taxonomy is **open** — a domain has reasons we cannot enumerate. This
hierarchy is **closed**: the framework's own failure modes are ours to know and finite.
A domain that wants a new exception type wants a refusal reason instead.

Nothing here is catchable by domain code. Profiles and tools handle refusals;
exceptions propagate to the host, which fails the request. A domain that catches
:class:`ContractViolation` and continues has defeated the guarantee.
"""

from __future__ import annotations

__all__ = [
    "ApprovalStoreError",
    "AttestError",
    "AuditSinkError",
    "BudgetStoreError",
    "ConfigurationError",
    "ContractViolation",
    "IntegrityError",
    "KernelError",
    "RetrieverScopeError",
    "SealError",
    "SelfApprovalError",
    "SignatureError",
    "StoreError",
]


class AttestError(Exception):
    """Base for every framework failure. Never raised directly."""


# ── Configuration: always at startup or construction, never mid-run ──────────────


class ConfigurationError(AttestError):
    """Invalid config, profile, flow spec, or an unsafe combination of them.

    Raised at construction so a misconfiguration surfaces at boot rather than at
    3am under load. Some of what lands here is a *combination* that is individually
    valid and jointly unsafe — deferred assurance on an irreversible effect, or
    streaming enabled for an agent holding irreversible tools.
    """


# ── Contract violations: a port broke its documented obligation ──────────────────


class ContractViolation(AttestError):
    """A host-supplied port did not honour its contract.

    These are obligations a type signature cannot express, which is why they are
    documented in ``docs/kernel/ports.md`` and tested by the conformance kit.
    Reaching one at runtime means the adapter is wrong, not the input.
    """


class StoreError(ContractViolation):
    """An attestation could not be persisted, or a stored one came back altered."""


class AuditSinkError(ContractViolation):
    """The audit sink could not append, or is not append-only.

    An exception rather than a refusal: if we cannot record what happened, we must
    not act. This is the case that most often tempts a fallback, and must not have one.
    """


class RetrieverScopeError(ContractViolation):
    """A retriever returned results outside the requesting actor's tenant.

    Always an incident, never a warning, and a profile cannot downgrade it. The
    guard that catches this is deliberately redundant with the query-level filter —
    reaching it means the primary scoping already failed.
    """


class ApprovalStoreError(ContractViolation):
    """The approval store failed, or returned a pending action with no expiry.

    An open-ended hold is a backlog of half-executed decisions with no owner, so a
    missing ``expires_at`` is a contract violation rather than a default we supply.
    """


class SelfApprovalError(ApprovalStoreError):
    """The actor who proposed an action tried to approve it.

    Separate from the general store error because the response differs: a late click
    on an expired action is a conflict, whereas this is a refusal of authority. Self
    approval is the most common way dual control is defeated in practice, so it is
    refused at the write rather than left to a reviewer to notice.
    """


class BudgetStoreError(ContractViolation):
    """The budget store cannot perform an atomic reserve-then-commit.

    A budget that is merely *read* and then acted on is a race: two concurrent runs
    both see headroom and both spend it. A store without transactions cannot satisfy
    the contract, and failing loudly is the only safe response.
    """


# ── Integrity: the record itself is wrong ────────────────────────────────────────


class IntegrityError(AttestError):
    """The provenance record failed verification.

    Always a serious finding. Distinct from a failed ``verify_current()``, which is
    often expected and benign — policies expire, records move on. Reporting the
    second as though it were the first cries wolf until nobody looks.
    """


class SealError(IntegrityError):
    """A run seal is missing, malformed, or does not cover the whole chain.

    Includes the case the seal exists to catch: a chain that is internally valid
    with an event omitted. Linkage alone cannot detect that; a dense sequence can.
    """


class SignatureError(IntegrityError):
    """A signature over a seal, checkpoint or bundle manifest did not verify."""


# ── Internal ─────────────────────────────────────────────────────────────────────


class KernelError(AttestError):
    """An internal invariant was violated.

    Reaching this is a bug in the framework. Deliberately not a refusal: we cannot
    vouch for a decision produced by a kernel that is in an impossible state.
    """
