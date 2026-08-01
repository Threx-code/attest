"""Domain profiles — the extensibility contract.

The naive design has the framework know about domains. That design is closed: a new
domain means editing the framework, cutting a release, and waiting for it. Here a
domain supplies *return values*, and nothing is a branch inside the framework.

The full protocol is assembled from focused parts, because a large interface is itself
a barrier to the open-world goal it exists to serve. :class:`BaseProfile` supplies
fail-closed defaults for all of them, so the minimum viable profile is two overrides.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from attest.kernel.config import AssuranceTier
from attest.kernel.errors import ConfigurationError
from attest.kernel.evidence import AuthorityLevel, Persistence, ValidityWindow
from attest.kernel.warrants import CORE_WARRANTS, WarrantPolicy

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import date

    from attest.capabilities.authority import ObligationSet
    from attest.kernel.actions import Action
    from attest.kernel.context import ExecutionContext
    from attest.kernel.evidence import Evidence
    from attest.kernel.warrants import WarrantKind

__all__ = [
    "BaseProfile",
    "ConflictClass",
    "DomainProfile",
    "GenericProfile",
    "PolicyConflict",
    "ProfileComposer",
]


class ConflictClass(StrEnum):
    """How two profiles' opinions relate.

    An earlier draft said "strictest wins, and it is the only safe resolution". That
    is wrong for any policy without a scalar ordering: retention of 30 days versus 90
    has no stricter — minimising exposure says 30, evidentiary obligation says 90.
    Forcing those into "strictest" silently picks one, which is the failure mode the
    framework exists to prevent.
    """

    STRICTER = "stricter"
    COMPATIBLE = "compatible"
    CONDITIONAL = "conditional"
    CONTRADICTORY = "contradictory"


@dataclass(frozen=True, slots=True)
class PolicyConflict:
    """A disagreement between composed profiles. Never auto-resolved when contradictory."""

    key: str
    left: str
    right: str
    classification: ConflictClass
    detail: str = ""


@runtime_checkable
class DomainProfile(Protocol):
    """What a domain must answer. Everything is a return value."""

    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    def warrant_kinds(self) -> frozenset[WarrantKind]: ...

    def warrant_policy(self, kind: WarrantKind) -> WarrantPolicy: ...

    def obligations_for(self, action: Action, context: ExecutionContext) -> ObligationSet: ...

    def required_authority(self, claim_kind: str) -> AuthorityLevel: ...

    def validity(self, evidence: Evidence, at: date) -> ValidityWindow: ...

    def requires_support(self, output: str, context: ExecutionContext) -> bool: ...

    def evidence_persistence(self, action: Action, context: ExecutionContext) -> Persistence: ...

    def sensitive_classes(self) -> frozenset[str]: ...

    def assurance_tier(self) -> AssuranceTier: ...

    def policy_dimensions(self) -> Mapping[str, str]:
        """Named opinions that have **no scalar ordering**.

        Warrant policy is orderable, so "stricter wins" is legitimate there. Retention
        is not: minimising exposure says 30 days, evidentiary obligation says 90, and
        neither is stricter. Notification before versus after an effect is genuinely
        contradictory. A profile declares those here so composition can *detect* the
        disagreement instead of merging it away.

        An absent key is no opinion, which composes with anything. It is not permission,
        and it does not weaken another profile's answer.
        """
        ...


class BaseProfile:
    """Fail-closed defaults for every part of the protocol.

    Every default here answers "we do not know" with the cautious option, so a profile
    that forgets to override something is stricter than intended rather than weaker.
    """

    name: str = "base"
    version: str = "0.0.0"
    extra_warrants: frozenset[WarrantKind] = frozenset()
    default_warrant_policy: WarrantPolicy = WarrantPolicy.BLOCK
    tier: AssuranceTier = AssuranceTier.STANDARD

    def warrant_kinds(self) -> frozenset[WarrantKind]:
        return CORE_WARRANTS | self.extra_warrants

    def warrant_policy(self, kind: WarrantKind) -> WarrantPolicy:
        """BLOCK by default.

        A profile that has not thought about a warrant gets the strictest treatment,
        not the most permissive: an unconsidered warrant must not silently pass.
        """
        return self.default_warrant_policy

    def obligations_for(self, action: Action, context: ExecutionContext) -> ObligationSet:
        """Never empty.

        Returning an empty set for an unrecognised action is the fail-open default the
        conformance suite exists to catch: add a tool next year and it ships with no
        gates at all.
        """
        from attest.capabilities.authority import CapabilityCheck, ObligationSet

        return ObligationSet((CapabilityCheck(action.capability or action.tool),))

    def required_authority(self, claim_kind: str) -> AuthorityLevel:
        return AuthorityLevel.AUTHORITATIVE

    def validity(self, evidence: Evidence, at: date) -> ValidityWindow:
        return evidence.source.validity

    def requires_support(self, output: str, context: ExecutionContext) -> bool:
        """Assume support is required unless the domain says otherwise.

        The surveyed codebases each hardcoded a word-count floor plus a regex, which
        silently exempted any short answer that named a statute.
        """
        return bool(output.strip())

    def evidence_persistence(self, action: Action, context: ExecutionContext) -> Persistence:
        if not action.semantics.reversible:
            return Persistence.EMBEDDED
        return Persistence.DIGEST

    def sensitive_classes(self) -> frozenset[str]:
        return frozenset()

    def assurance_tier(self) -> AssuranceTier:
        return self.tier

    dimensions: Mapping[str, str] = MappingProxyType({})
    """Non-orderable policy opinions, as a class attribute.

    Empty by default: a profile with no opinion must not constrain another's. Declaring
    one here is how a domain says "retention is 30 days" in a way composition can see.
    """

    def policy_dimensions(self) -> Mapping[str, str]:
        return self.dimensions


class GenericProfile(BaseProfile):
    """The reference profile. Ships no domain knowledge, by construction.

    Used in tests and as a worked example. It is deliberately weaker than a regulated
    profile — epistemic WARNs rather than BLOCKs — so low-stakes work is not taxed by
    machinery it does not need.
    """

    name = "generic"
    version = "1.0.0"
    default_warrant_policy = WarrantPolicy.WARN

    def required_authority(self, claim_kind: str) -> AuthorityLevel:
        return AuthorityLevel.ADVISORY


class ProfileComposer:
    """Composes profiles, classifying disagreements rather than silently picking.

    Warrant policy IS scalar-ordered, so "stricter wins" is legitimate there and only
    there. Absence is not permission: a profile with no opinion composes as COMPATIBLE
    and does not weaken another's.
    """

    __slots__ = ("resolvers",)

    def __init__(self, resolvers: Mapping[str, str] | None = None) -> None:
        """``resolvers`` names the dimensions a domain has decided how to resolve.

        The value is the resolution the domain has chosen. Registering one is a
        deliberate act by whoever owns both profiles — which is the point: someone with
        the authority to decide has decided, rather than the framework guessing.
        """
        self.resolvers: Mapping[str, str] = (
            MappingProxyType({}) if resolvers is None else MappingProxyType(dict(resolvers))
        )

    def compose(self, *profiles: DomainProfile) -> tuple[DomainProfile, tuple[PolicyConflict, ...]]:
        """Compose profiles and report every conflict found.

        A CONTRADICTORY conflict raises: composition fails loudly at construction,
        which is the normal case and the one to fix. Silently picking one side is the
        failure mode the framework exists to prevent.
        """
        if not profiles:
            raise ConfigurationError("compose() requires at least one profile")
        if len(profiles) == 1:
            return profiles[0], ()

        conflicts: list[PolicyConflict] = []
        kinds: set[WarrantKind] = set()
        for profile in profiles:
            kinds |= profile.warrant_kinds()

        resolved: dict[WarrantKind, WarrantPolicy] = {}
        for kind in kinds:
            opinions = [p.warrant_policy(kind) for p in profiles if kind in p.warrant_kinds()]
            if not opinions:
                continue
            strictest = WarrantPolicy.strictest(*opinions)
            resolved[kind] = strictest
            if len(set(opinions)) > 1:
                conflicts.append(
                    PolicyConflict(
                        key=f"warrant_policy:{kind}",
                        left=min(opinions, key=lambda p: p.rank).value,
                        right=strictest.value,
                        classification=ConflictClass.STRICTER,
                        detail="scalar ordering exists; the stricter policy was taken",
                    )
                )

        conflicts.extend(self._dimension_conflicts(profiles))

        contradictory = [c for c in conflicts if c.classification is ConflictClass.CONTRADICTORY]
        if contradictory:
            raise ConfigurationError(
                f"profiles cannot be composed: {len(contradictory)} contradictory "
                f"policy conflict(s) with no scalar ordering. Resolve them explicitly "
                f"rather than letting composition pick one: {contradictory}"
            )

        return _Composite(profiles, frozenset(kinds), resolved), tuple(conflicts)

    def _dimension_conflicts(self, profiles: tuple[DomainProfile, ...]) -> list[PolicyConflict]:
        """Classify the disagreements that have no stricter side.

        A resolver registered for a key makes the conflict CONDITIONAL — the domain has
        said how to decide it. Without one it is CONTRADICTORY and composition fails,
        because the alternative is picking a side on the domain's behalf and recording
        the result as though it were policy.
        """
        found: list[PolicyConflict] = []
        keys: set[str] = set()
        for profile in profiles:
            keys |= set(self.dimensions_of(profile))

        for key in sorted(keys):
            opinions = {
                value
                for profile in profiles
                if (value := self.dimensions_of(profile).get(key)) is not None
            }
            if len(opinions) < 2:
                continue
            left, right = sorted(opinions)[0], sorted(opinions)[-1]
            resolvable = key in self.resolvers
            found.append(
                PolicyConflict(
                    key=key,
                    left=left,
                    right=right,
                    classification=(
                        ConflictClass.CONDITIONAL if resolvable else ConflictClass.CONTRADICTORY
                    ),
                    detail=(
                        f"a resolver is registered for {key!r}; it decides per context"
                        if resolvable
                        else f"{key!r} has no scalar ordering, so neither side is "
                        f"stricter. Resolve it explicitly — register a resolver or "
                        f"change one profile — rather than letting composition pick."
                    ),
                )
            )
        return found

    @staticmethod
    def dimensions_of(profile: DomainProfile) -> Mapping[str, str]:
        """A profile written before this existed has no opinions, not a crash."""
        declared = getattr(profile, "policy_dimensions", None)
        return {} if declared is None else declared()


@dataclass(frozen=True, slots=True)
class _Composite:
    """The result of composing profiles. Obligations union; policies take the stricter."""

    profiles: tuple[DomainProfile, ...]
    kinds: frozenset[WarrantKind]
    policies: Mapping[WarrantKind, WarrantPolicy]

    @property
    def name(self) -> str:
        return "+".join(p.name for p in self.profiles)

    @property
    def version(self) -> str:
        return "+".join(f"{p.name}@{p.version}" for p in self.profiles)

    def warrant_kinds(self) -> frozenset[WarrantKind]:
        return self.kinds

    def warrant_policy(self, kind: WarrantKind) -> WarrantPolicy:
        return self.policies.get(kind, WarrantPolicy.BLOCK)

    def obligations_for(self, action: Action, context: ExecutionContext) -> ObligationSet:
        from attest.capabilities.authority import ObligationSet

        combined: list[object] = []
        for profile in self.profiles:
            combined.extend(profile.obligations_for(action, context))
        return ObligationSet(tuple(combined))  # type: ignore[arg-type]

    def required_authority(self, claim_kind: str) -> AuthorityLevel:
        return max(
            (p.required_authority(claim_kind) for p in self.profiles),
            key=lambda level: level.rank,
        )

    def validity(self, evidence: Evidence, at: date) -> ValidityWindow:
        """The **intersection** of every profile's window, not the first one's answer.

        Taking ``profiles[0]`` silently picked a side: composing a domain that expires
        evidence at 90 days with one that expires it at 30 would report the first one
        listed, so the order of the arguments decided whether stale evidence passed.

        Both windows have to hold for the composed profile to hold, so the intersection
        is the only answer that is not a choice — the latest start and the earliest end.
        An empty intersection is returned as-is rather than widened: it means no date
        satisfies both, and ``covers()`` correctly answers False for every moment.
        """
        windows = [profile.validity(evidence, at) for profile in self.profiles]
        starts = [w.effective_from for w in windows if w.effective_from is not None]
        ends = [w.effective_to for w in windows if w.effective_to is not None]
        return ValidityWindow(
            effective_from=max(starts) if starts else None,
            effective_to=min(ends) if ends else None,
        )

    def policy_dimensions(self) -> Mapping[str, str]:
        """The union. Composition already refused anything that disagreed.

        A CONTRADICTORY dimension raises at construction, so by the time a composite
        exists every key has exactly one value or a resolver chose it.
        """
        merged: dict[str, str] = {}
        for profile in self.profiles:
            merged.update(ProfileComposer.dimensions_of(profile))
        return MappingProxyType(merged)

    def requires_support(self, output: str, context: ExecutionContext) -> bool:
        return any(p.requires_support(output, context) for p in self.profiles)

    def evidence_persistence(self, action: Action, context: ExecutionContext) -> Persistence:
        chosen = [p.evidence_persistence(action, context) for p in self.profiles]
        rank = {Persistence.REFERENCE: 0, Persistence.DIGEST: 1, Persistence.EMBEDDED: 2}
        return max(chosen, key=lambda p: rank[p])

    def sensitive_classes(self) -> frozenset[str]:
        result: frozenset[str] = frozenset()
        for profile in self.profiles:
            result |= profile.sensitive_classes()
        return result

    def assurance_tier(self) -> AssuranceTier:
        rank = {
            AssuranceTier.THIN: 0,
            AssuranceTier.STANDARD: 1,
            AssuranceTier.FULL: 2,
            AssuranceTier.MAX: 3,
        }
        return max((p.assurance_tier() for p in self.profiles), key=lambda t: rank[t])
