"""Warrants — defensible reasons, verifiable after the fact.

A warrant is not a confidence score and not a metadata blob. The distinction is that a
warrant can be **re-checked months later and can fail**; a metadata dict means whatever
its writer thought it meant. The regulator's question is not "what did you think at the
time?" but "show me".

``WarrantKind`` is a ``NewType`` over ``str``, deliberately **not** an enum. An enum is
a closed set, so adding a domain would mean editing the kernel - precisely the failure
this design exists to avoid. A clinical profile registers ``calibration``, an
underwriting profile registers ``fairness``, and neither touches this file. See ADR 0001.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final, NewType

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "CORE_WARRANTS",
    "NON_DOWNGRADEABLE",
    "Finding",
    "Severity",
    "WarrantKind",
    "WarrantKinds",
    "WarrantPolicy",
    "WarrantReport",
    "WarrantStatus",
]

WarrantKind = NewType("WarrantKind", str)


class WarrantKinds:
    """The warrant kinds the framework ships.

    A namespace, not an enum — the type stays open so a clinical profile registers
    ``WarrantKind("calibration")`` and an underwriting profile ``("fairness")``
    without touching this file.

    Namespaced rather than exported as bare constants because ``AUTHORITY`` and
    ``BOUNDARY`` are too generic to put into an importer's namespace, and
    ``WarrantKinds.AUTHORITY`` does not read as the :mod:`attest.kernel.authority`
    module at a call site.
    """

    # --- The four core warrants. Mandatory in every domain. ---
    EPISTEMIC: Final = WarrantKind("epistemic")
    """What evidence supports this?"""

    AUTHORITY: Final = WarrantKind("authority")
    """Was this permitted, for this actor, at this moment?"""

    PROVENANCE: Final = WarrantKind("provenance")
    """What happened, in what order, and can the record be forged?"""

    BOUNDARY: Final = WarrantKind("boundary")
    """Did untrusted input steer it? Did anything leak out?"""

    # --- Shipped, but not core. Registered by domains that need them. ---
    COMPLETENESS: Final = WarrantKind("completeness")
    """Was what we used *enough*?

    The core four all validate what WAS used; none asks what was missed. Not core
    because an agent with no retrieval surface has nothing to be incomplete about,
    and a warrant that is trivially satisfied trains people to ignore warrants.
    """

    DATA_LINEAGE: Final = WarrantKind("data_lineage")
    """Which records produced this model, and were they lawfully held? See ADR 0040."""


CORE_WARRANTS: Final[frozenset[WarrantKind]] = frozenset(
    {
        WarrantKinds.EPISTEMIC,
        WarrantKinds.AUTHORITY,
        WarrantKinds.PROVENANCE,
        WarrantKinds.BOUNDARY,
    }
)
"""The four that are mandatory everywhere. Everything else is the domain's call."""


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class WarrantStatus(StrEnum):
    """Whether the check behind this warrant actually ran.

    Without this, deferred assurance (docs/kernel/performance.md) returns `ALLOW`
    with warrants nobody evaluated and no way for a consumer to tell. See ADR 0035.
    """

    EVALUATED = "evaluated"
    """The check ran and produced a result. `satisfied` is meaningful."""

    PENDING = "pending"
    """Deferred; not yet run. `satisfied` is NOT meaningful and must not be read."""

    UNEVALUATABLE = "unevaluatable"
    """The check could not run - a source is unreachable, a verifier raised.

    Never read as a pass. This is the typed form of the `except Exception: return True`
    that was found in surveyed guard code.
    """


class WarrantPolicy(StrEnum):
    """What an unsatisfied warrant does to the run. Chosen by the domain, not here.

    A medical profile BLOCKs on unsatisfied `epistemic`; a reporting profile only
    WARNs, because reconciliation is its load-bearing check. Same machinery,
    opposite policy.
    """

    BLOCK = "block"
    HOLD = "hold"
    WARN = "warn"
    RECORD = "record"

    @property
    def rank(self) -> int:
        """How strict this is. Higher is stricter.

        Here rather than on whoever needs it, because two places already needed it and a
        third was about to. Composing profiles takes the stricter of two opinions, and an
        agent may tighten its own warrant policy and may not loosen it - the same
        comparison, and a second copy of this ordering would eventually disagree with the
        first in the direction that lets something through.
        """
        return _POLICY_RANK[self]

    @classmethod
    def strictest(cls, *policies: WarrantPolicy | None) -> WarrantPolicy:
        """The strictest of the given policies, ignoring ``None``.

        ``None`` is no opinion, not a permissive one. A caller that has not expressed a
        policy must not be able to weaken one that has - which is the entire direction
        this method exists to enforce.
        """
        stated = [p for p in policies if p is not None]
        if not stated:
            raise ValueError("strictest() needs at least one stated policy")
        return max(stated, key=lambda p: p.rank)


_POLICY_RANK: Final[Mapping[WarrantPolicy, int]] = {
    WarrantPolicy.RECORD: 0,
    WarrantPolicy.WARN: 1,
    WarrantPolicy.HOLD: 2,
    WarrantPolicy.BLOCK: 3,
}


NON_DOWNGRADEABLE: Final[frozenset[str]] = frozenset(
    {
        # docs/kernel/tenancy.md — "Cross-tenant is always an incident. There is no
        # 'warn' setting for this. A profile cannot downgrade it."
        "tenancy_violation",
        # docs/capabilities/guards.md — "the value must never reach the model", and
        # "Restoration is total. Unmatched tokens fail the run rather than shipping."
        "outbound_leakage",
        "incomplete_restoration",
    }
)
"""Finding codes whose failure no :class:`WarrantPolicy` can soften.

Warrant policy is the domain's to choose, and almost all of it should be: a medical
profile blocks on ``epistemic`` where a reporting profile only warns, and neither is
wrong. These three are the exceptions, and each one is here because a document in
``docs/`` states the guarantee in those words.

The finding is the unit rather than the warrant kind, and that distinction is the whole
reason this works. All three arrive under ``BOUNDARY``, which also carries
``injection_detected`` — a heuristic signal a deployment has every right to set to
``RECORD`` rather than drown its reviewers in false positives. Flooring the *kind* would
force that deployment to choose between noise and a tenancy guarantee. Flooring the
*finding* lets it have both.

This exists because the guarantee was written down and never implemented. A profile
returning ``WarrantPolicy.RECORD`` for ``BOUNDARY`` turned a cross-tenant evidence read
into ``ALLOW_WITH_WARNINGS`` — a data leak reported as an answer with a note attached —
while ``docs/kernel/tenancy.md`` said in as many words that it could not. The shipped
red-team corpus found it by *running*, on the first execution after it was given attacks
to run; three human review rounds had read past it. That is the argument for executing a
corpus rather than declaring one, and it is worth remembering the next time an
unconditional claim is made in prose.

A code here is decisive and not merely blocking: it is checked before the pending-
approval path, because a tenancy crossing is not a thing an approver can authorise.
"""


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing that was checked, and what came of it."""

    code: str
    message: str
    severity: Severity = Severity.INFO
    data: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("finding code must not be empty; findings are aggregated")


@dataclass(frozen=True, slots=True)
class WarrantReport:
    """The outcome of evaluating one warrant.

    ``satisfied`` is only meaningful when ``status`` is ``EVALUATED``. Reading it
    otherwise is the bug this class exists to make visible, so :meth:`is_satisfied`
    is provided and should be preferred at every call site.
    """

    kind: WarrantKind
    status: WarrantStatus
    satisfied: bool
    findings: tuple[Finding, ...] = ()

    confidence: float | None = None
    """`None` means the verification was EXACT - a quote is present or it is not.

    A float means a judge decided, and a judge is probabilistic. Merging the two into
    one field is how "verified" comes to mean nothing (docs/capabilities/judging.md).
    """

    verifier_ref: str | None = None
    """Which verifier or judge produced this, for calibration and replay."""

    def __post_init__(self) -> None:
        if self.status is not WarrantStatus.EVALUATED and self.satisfied:
            raise ValueError(
                f"warrant {self.kind!r} claims satisfied=True with status "
                f"{self.status.value!r}. An unevaluated check has not passed - it has "
                f"not run. Fail closed."
            )
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0, 1], got {self.confidence!r}")

    def qualifications(self) -> tuple[str, ...]:
        """The finding messages a reader must be shown.

        Lives on the report rather than in each renderer: it was duplicated in a store
        and a serialiser, and two copies of "which findings count as a warning" drift
        until one of them quietly stops surfacing something.
        """
        return tuple(
            finding.message
            for finding in self.findings
            if finding.severity in (Severity.WARNING, Severity.ERROR)
        )

    def is_satisfied(self) -> bool:
        """True only when the check ran *and* passed.

        Prefer this to reading `satisfied` directly: it cannot be accidentally true
        for a warrant that was never evaluated.
        """
        return self.status is WarrantStatus.EVALUATED and self.satisfied

    @property
    def is_final(self) -> bool:
        """Whether this warrant needs no further work."""
        return self.status is not WarrantStatus.PENDING
