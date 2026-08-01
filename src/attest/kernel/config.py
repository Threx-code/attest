"""Configuration — values, never behaviour.

Two surveyed codebases each carried a 199-line rules engine. The entire difference
between them was one character in a comment: ``₦`` against ``£``. A 199-line file that
could never be shared, because a configuration value had been baked into code. The same
pattern appears in a 319-line injection detector where the difference is a brand name
inside a regex.

Those are not code differences. They are configuration that got hardcoded, and this
module exists so the pattern cannot recur.

The split that matters is the other half:

.. code-block:: text

    AttestConfig                  DomainProfile
    ─────────────────────────     ──────────────────────────────
    currency symbol               what counts as evidence
    brand name                    which obligations gate an action
    model per tier                which warrants apply
    token and step ceilings       what is sensitive
    locale, timezone              how long evidence stays valid
    ─────────────────────────     ──────────────────────────────
    scalars and toggles           strategies and policy

Getting it wrong produces a ``domain:`` enum field in config, which closes the world.

Frozen, and passed rather than read from ambient global state — which is what makes
per-tenant overrides and deterministic replay possible at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from attest.kernel.canonical import Canonical
from attest.kernel.errors import ConfigurationError
from attest.kernel.identifiers import Hash

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ["AssuranceTier", "AttestConfig", "ModelTier"]


class ModelTier(StrEnum):
    """Agents reference a tier; config resolves it to a model.

    Switching provider is then a configuration change rather than fifty edits, and a
    historical run still records the concrete model it actually used.
    """

    FAST = "fast"
    BALANCED = "balanced"
    REASONING = "reasoning"


class AssuranceTier(StrEnum):
    """How much assurance machinery runs on the hot path.

    A framework usable only at the top end is a second stack rather than the stack:
    every organisation running tier-1 work also runs support bots and document triage,
    and if those must be built on something else the framework loses both.
    """

    THIN = "thin"
    """Guards, provenance and budget. No evidence verification, no warrant evaluation.
    Internal ops and triage, where overhead must be indistinguishable from a bare
    gateway call."""

    STANDARD = "standard"
    """Adds exact evidence verification, warrant evaluation and declarative
    completeness. No model spend beyond the run itself."""

    FULL = "full"
    """Adds entailment judging on a sample, and source authority resolution."""

    MAX = "max"
    """Adds entailment on every claim and an adversarial critic. Multiplies model
    spend; reserved for the highest materiality."""


_MIN_STEPS: Final = 1
_MAX_STEPS_CEILING: Final = 64
"""A hard stop on agent iterations. Not a suggestion: hitting it produces a refusal
with a full attestation, never a partial answer presented as complete."""


@dataclass(frozen=True, slots=True)
class AttestConfig:
    """Deployment values. Validated at construction, never at first use."""

    brand: str
    """Used by the injection detector, which is why it is config.

    Hardcoding it into a regex is what made two copies of a 319-line detector
    unshareable.
    """

    brand_aliases: tuple[str, ...] = ()

    # --- Locale. Hardcoding any of these forks the rules engine. ---
    currency: str = "USD"
    currency_symbol: str = "$"
    locale: str = "en_US"
    timezone: str = "UTC"

    # --- Models, by tier rather than by id. ---
    models: Mapping[ModelTier, str] = field(default_factory=dict)
    fallback_models: Mapping[ModelTier, tuple[str, ...]] = field(default_factory=dict)

    # --- Limits. ---
    max_steps: int = 8
    max_tokens_per_run: int = 32_000
    daily_budget: str | None = None
    """Decimal as a string, so no float rounding enters a spend ceiling."""

    # --- Assurance and caching. ---
    assurance_tier: AssuranceTier = AssuranceTier.STANDARD
    exact_cache: bool = True
    semantic_cache: bool = False
    """Off by default and enabled per domain.

    Returning a near-miss cached answer is acceptable for a support chatbot and
    unacceptable for a claim adjudication. The framework will not make that choice on
    a domain's behalf.
    """

    extras: Mapping[str, Any] = field(default_factory=dict)
    """Host-specific scalars. Deliberately not a place for behaviour."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "models", MappingProxyType(dict(self.models)))
        object.__setattr__(self, "fallback_models", MappingProxyType(dict(self.fallback_models)))
        object.__setattr__(self, "extras", MappingProxyType(dict(self.extras)))
        self._validate()

    def _validate(self) -> None:
        """Everything checkable, checked now.

        A misconfiguration that surfaces at 3am under load is one that should have
        failed at boot.
        """
        if not self.brand:
            raise ConfigurationError(
                "brand must be set: it is interpolated into injection-detection "
                "patterns, and an empty brand silently weakens them"
            )
        if not self.currency or len(self.currency) != 3:
            raise ConfigurationError(f"currency must be a three-letter code, got {self.currency!r}")
        if not self.currency_symbol:
            raise ConfigurationError("currency_symbol must be set")

        if not _MIN_STEPS <= self.max_steps <= _MAX_STEPS_CEILING:
            raise ConfigurationError(
                f"max_steps must be between {_MIN_STEPS} and {_MAX_STEPS_CEILING}, "
                f"got {self.max_steps}. An unbounded agent loop is an unbounded spend."
            )
        if self.max_tokens_per_run < 1:
            raise ConfigurationError("max_tokens_per_run must be positive")

        if self.daily_budget is not None:
            try:
                budget = Decimal(self.daily_budget)
            except (InvalidOperation, ValueError) as exc:
                raise ConfigurationError(
                    f"daily_budget must be a decimal string, got {self.daily_budget!r}"
                ) from exc
            if budget < 0:
                raise ConfigurationError("daily_budget cannot be negative")

        for tier, fallbacks in self.fallback_models.items():
            if tier not in self.models:
                raise ConfigurationError(
                    f"fallback models are configured for tier {tier.value!r}, which has "
                    f"no primary model. A failover list for a tier nobody can reach is "
                    f"a configuration that will never do what it appears to."
                )
            if not fallbacks:
                raise ConfigurationError(
                    f"tier {tier.value!r} declares an empty fallback list; omit the key "
                    f"rather than implying a failover path that does not exist"
                )

        if self.semantic_cache and self.assurance_tier is AssuranceTier.MAX:
            raise ConfigurationError(
                "semantic_cache cannot be enabled at the MAX assurance tier: MAX exists "
                "to judge every claim, and serving a near-miss cached answer discards "
                "the judgement that was paid for"
            )

    def for_tenant(self, **overrides: Any) -> AttestConfig:  # noqa: ANN401
        """A new frozen instance with ``overrides`` applied.

        Nothing mutates, so one tenant's configuration cannot leak into another's run.
        Overrides are re-validated, so a tenant cannot be given a configuration the
        deployment would have rejected.
        """
        unknown = set(overrides) - set(self.__slots__)
        if unknown:
            raise ConfigurationError(
                f"unknown configuration field(s): {sorted(unknown)}. Host-specific "
                f"values belong in `extras`, and behaviour belongs in a DomainProfile."
            )
        return replace(self, **overrides)

    def model_for(self, tier: ModelTier) -> str:
        """The configured model for ``tier``.

        Raises rather than falling back to another tier: silently answering a
        reasoning request with a fast model is a materially different decision.
        """
        try:
            return self.models[tier]
        except KeyError:
            raise ConfigurationError(
                f"no model configured for tier {tier.value!r}. Configure one rather "
                f"than relying on a fallback: silently substituting another tier "
                f"changes the decision without recording that it changed."
            ) from None

    def content_hash(self) -> Hash:
        """The content address of this configuration, pinned into the attestation."""
        return Hash(
            Canonical.digest(
                {
                    "brand": self.brand,
                    "brand_aliases": sorted(self.brand_aliases),
                    "currency": self.currency,
                    "currency_symbol": self.currency_symbol,
                    "locale": self.locale,
                    "timezone": self.timezone,
                    "models": dict(sorted(self.models.items())),
                    "fallback_models": {
                        t: list(m) for t, m in sorted(self.fallback_models.items())
                    },
                    "max_steps": self.max_steps,
                    "max_tokens_per_run": self.max_tokens_per_run,
                    "daily_budget": self.daily_budget,
                    "assurance_tier": self.assurance_tier,
                    "exact_cache": self.exact_cache,
                    "semantic_cache": self.semantic_cache,
                    "extras": dict(self.extras),
                }
            )
        )
