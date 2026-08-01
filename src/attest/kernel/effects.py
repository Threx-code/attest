"""Effects — how a consequence behaves in the world.

Separate from :mod:`attest.kernel.actions` because the two have different reasons to
change. An action is *what someone proposed*; this module is *what happens if it
proceeds*, and profiles write obligation rules against these declarations rather than
against tool names — so a tool written next year inherits the right gates by
describing itself honestly.

The two ideas that carry weight here:

*Every default is the cautious one.* A tool that declares nothing is treated as
irreversible, legally binding and unsafe to retry. Forgetting to describe a tool
cannot silently weaken its gates.

*``UNKNOWN`` is a real state.* A payment that timed out after the bank committed it is
neither success nor failure, and coercing it to either is how a system reports a
payment that never happened, or misses one that did.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NewType

__all__ = [
    "TERMINAL_EFFECT_STATES",
    "WORLD_REACHING_EFFECT_STATES",
    "EffectClass",
    "EffectClasses",
    "EffectSemantics",
    "EffectState",
    "IdempotencyMode",
]

EffectClass = NewType("EffectClass", str)
"""What kind of consequence a tool has.

**Open, like** :data:`~attest.kernel.warrants.WarrantKind` **and**
:data:`~attest.kernel.evidence.EvidenceKind`. An earlier version made this a closed
enum, which is the exact failure the thesis forbids: a domain needing a consequence we
never thought of would have to edit the kernel. Nothing matches on these exhaustively
— profiles test membership — so closing the set bought nothing and cost the open-world
guarantee.

::

    def obligations_for(self, action, ctx):
        obs = [CapabilityCheck(action.capability)]
        if FINANCIAL in action.effects:
            obs.append(Budget("payments", ctx.actor))
        if LIBERTY in action.effects:
            obs += [DualControl(), ContestabilityNotice(ctx.subject)]
        return ObligationSet(obs)
"""


class EffectClasses:
    """The effect classes the framework ships.

    A namespace, not an enum. Call sites read ``EffectClasses.LIBERTY`` — as clear as
    an enum member — while the underlying type stays open, so a domain writes
    ``EffectClass("breaks_trial_blinding")`` without a kernel change.

    Namespaced rather than exported as bare module constants because ``READ``,
    ``WRITE`` and ``EXTERNAL`` are far too generic to put into an importer's namespace,
    and ``from ... import READ`` does not say read *of what*.
    """

    # --- State we control ---
    READ: Final = EffectClass("read")
    """Observes without changing anything."""

    WRITE: Final = EffectClass("write")
    """Changes internal state we control."""

    DESTRUCTIVE: Final = EffectClass("destructive")
    """Erases or overwrites such that the prior state cannot be recovered.

    Distinct from ``reversible=False``: an irreversible payment can still be
    evidenced, whereas a destroyed record cannot. Erasure obligations attach here.
    """

    # --- Consequence to a person or an institution ---
    FINANCIAL: Final = EffectClass("financial")
    """Money moves, or a financial obligation is created."""

    LEGAL: Final = EffectClass("legal")
    """Creates, alters or discharges a legal obligation or standing.

    A regulatory filing cannot be un-sent; a contract binds. Neither is financial in
    itself, and ``docs/domains/regulatory.md`` gates ``submit_filing`` on exactly this.
    """

    LIBERTY: Final = EffectClass("liberty")
    """Restricts a person's freedom, rights, or entitlement.

    Bail, parole, detention, removal, a safeguarding referral, a benefits refusal.
    Tier 1 of ``docs/domains/catalog.md`` is 'liberty, life, and legal standing', and
    no state or money class expresses it — which is how an obligation rule for a
    detention decision would otherwise end up written against ``EXTERNAL``.
    """

    CLINICAL: Final = EffectClass("clinical")
    """Affects a person's care or treatment."""

    # --- Boundary ---
    EXTERNAL: Final = EffectClass("external")
    """A third party observes it. Once seen, it cannot be unseen."""

    DISCLOSURE: Final = EffectClass("disclosure")
    """Personal data crosses the boundary.

    Separate from ``EXTERNAL`` because the gate differs: disclosure needs a lawful
    basis and is recorded as a disclosure event, whereas an external effect may carry
    no personal data at all.
    """

    NOTIFICATION: Final = EffectClass("notification")
    """A person is told something.

    Its own class because domains genuinely disagree. ``docs/domains/mortgage.md``
    *mandates* notification before an offer takes effect; ``docs/domains/banking.md``
    makes notifying the subject of a SAR a **criminal offence**. The same primitive,
    required in one domain and forbidden in another — the clearest argument that no
    fixed list written here could be right for both.
    """

    # --- Physical ---
    PHYSICAL: Final = EffectClass("physical")
    """Actuates something in the world. Aviation, rail, energy, industrial control."""

    @classmethod
    def shipped(cls) -> frozenset[EffectClass]:
        """Every class the framework ships. Domains add their own outside this set."""
        return frozenset(
            EffectClass(value)
            for name, value in vars(cls).items()
            if not name.startswith("_") and isinstance(value, str)
        )


class IdempotencyMode(StrEnum):
    """Whether *we* may safely submit the same effect twice."""

    NATURAL = "natural"
    """Inherently safe to repeat — reads, and pure computations."""

    KEYED = "keyed"
    """Safe to repeat only under a caller-supplied idempotency key."""

    FORBIDDEN = "forbidden"
    """Must never repeat. Registering one without a keyed guard upstream is a
    configuration error, caught at startup rather than at 2am."""


class EffectState(StrEnum):
    """The lifecycle of a consequential effect.

    ``SUBMITTED`` is persisted **before** the external call, so a crash leaves evidence
    that a call was in flight. Without that write, ``UNKNOWN`` is indistinguishable
    from "never attempted".
    """

    PROPOSED = "proposed"
    AUTHORIZED = "authorized"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    COMMITTED = "committed"
    """Written ONLY on positive acknowledgement carrying an external reference."""

    FAILED = "failed"
    REFUSED = "refused"

    UNKNOWN = "unknown"
    """The call went out and we do not know what happened.

    Terminal for the run and a work item for reconciliation. Never silently coerced to
    `COMMITTED` or `FAILED`: only the external system knows, and guessing is how a
    system reports a payment that did not happen, or misses one that did.
    """


TERMINAL_EFFECT_STATES: Final[frozenset[EffectState]] = frozenset(
    {
        EffectState.COMMITTED,
        EffectState.FAILED,
        EffectState.REFUSED,
        EffectState.UNKNOWN,
    }
)
"""States from which the run does not advance further on its own.

``UNKNOWN`` is terminal *for the run* and still open as a work item — reconciliation
resolves it out of band and supersedes the attestation.
"""


WORLD_REACHING_EFFECT_STATES: Final[frozenset[EffectState]] = frozenset(
    {
        EffectState.SUBMITTED,
        EffectState.ACKNOWLEDGED,
        EffectState.COMMITTED,
        EffectState.UNKNOWN,
    }
)
"""States in which an external system has already seen the request.

The distinction this exists to make: once any effect is in one of these, "nothing
happened" is no longer an available answer. ``REFUSE`` means the run did not act, and
the kernel refuses to record it over an effect that did — see
:meth:`~attest.kernel.attestation.Attestation.__post_init__`.

``UNKNOWN`` belongs here precisely because we cannot say it did *not* reach the world.
That is the whole reason the state exists.
"""


@dataclass(frozen=True, slots=True)
class EffectSemantics:
    """How an effect behaves in the world.

    ``reversible: bool`` alone is too coarse for these domains: a regulatory filing
    cannot be un-sent, but it can be amended — neither reversible nor irreversible.

    Every field defaults to the **cautious** value, so a tool that declares nothing is
    treated as irreversible, legally binding and unsafe to retry.
    """

    reversible: bool = False
    compensatable: bool = False
    externally_visible: bool = True
    financially_material: bool = True
    legally_binding: bool = True
    idempotent_upstream: bool = False
    """Whether the EXTERNAL system honours our idempotency key.

    A property of the integration, asserted per tool, and frequently false — many
    upstreams accept a key and ignore it. Retrying a non-idempotent financial effect
    after a timeout is how duplicate payments happen.
    """

    transactional: bool = False

    def may_retry_on_timeout(self, mode: IdempotencyMode) -> bool:
        """Whether a timed-out effect may be resubmitted automatically.

        Retry safety needs **both** levels to agree, and reading only one is the bug:

        ===============  =======================  ==========================
        ``mode``         ``idempotent_upstream``  on timeout
        ===============  =======================  ==========================
        ``NATURAL``      either                   retry
        ``KEYED``        ``True``                 retry with the same key
        ``KEYED``        ``False``                UNKNOWN -> reconciliation
        ``FORBIDDEN``    either                   UNKNOWN -> reconciliation
        ===============  =======================  ==========================

        Row three is the trap. A ``KEYED`` tool looks safe to retry because we hold a
        key, but the key only helps if the upstream honours it.
        """
        if mode is IdempotencyMode.NATURAL:
            return True
        if mode is IdempotencyMode.KEYED:
            return self.idempotent_upstream
        return False
