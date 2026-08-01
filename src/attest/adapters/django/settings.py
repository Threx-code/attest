"""``settings.ATTEST`` → :class:`~attest.kernel.config.AttestConfig`.

A **thin builder, with no logic of its own beyond mapping keys**. Every check lives in
the frozen dataclass, so a Celery worker that constructs config directly gets identical
validation to a request that comes through Django. A bridge that validated here would
create two definitions of a valid configuration, and the one nobody looks at would rot.

.. code-block:: python

    ATTEST = {
        "BRAND": "acme",
        "CURRENCY": "GBP",
        "CURRENCY_SYMBOL": "£",
        "LOCALE": "en_GB",
        "MODELS": {"fast": "...", "balanced": "...", "reasoning": "..."},
        "MAX_STEPS": 8,
        "DAILY_BUDGET": "500.00",
    }
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from attest.kernel.config import AssuranceTier, AttestConfig, ModelTier
from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = ["SettingsBridge"]


class SettingsBridge:
    """Builds an :class:`AttestConfig` from a Django settings mapping."""

    #: ``settings`` attribute read when no mapping is supplied.
    SETTINGS_KEY = "ATTEST"

    @classmethod
    def from_settings(cls, settings: Any = None) -> AttestConfig:
        """Build config from ``settings.ATTEST``.

        ``settings`` defaults to Django's lazy settings object. Passing one explicitly
        is how a test or a management command builds config without a configured
        project.
        """
        if settings is None:
            from django.conf import settings as django_settings

            settings = django_settings
        raw = getattr(settings, cls.SETTINGS_KEY, None)
        if raw is None:
            raise ConfigurationError(
                f"settings.{cls.SETTINGS_KEY} is not defined. The Django adapter does "
                f"not invent a default brand, currency or model set — a deployment "
                f"running on guessed configuration is one whose attestations record "
                f"values nobody chose."
            )
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> AttestConfig:
        """Build config from a plain mapping. No Django import required."""
        unknown = set(raw) - cls._KNOWN
        if unknown:
            raise ConfigurationError(
                f"unknown {cls.SETTINGS_KEY} keys: {sorted(unknown)}. Rejected rather "
                f"than ignored: a misspelled key that is silently dropped leaves the "
                f"deployment running the default it was configured to replace. "
                f"Host-specific values belong under 'EXTRAS'."
            )
        if "BRAND" not in raw:
            raise ConfigurationError(
                f"{cls.SETTINGS_KEY}['BRAND'] is required: it is interpolated into "
                f"injection-detection patterns, and an absent brand silently weakens them"
            )

        fields: dict[str, Any] = {"brand": raw["BRAND"]}
        for key, name in cls._SCALARS.items():
            if key in raw:
                fields[name] = raw[key]
        if "BRAND_ALIASES" in raw:
            fields["brand_aliases"] = tuple(raw["BRAND_ALIASES"])
        if "MODELS" in raw:
            fields["models"] = cls._tiers(raw["MODELS"], "MODELS")
        if "FALLBACK_MODELS" in raw:
            fields["fallback_models"] = {
                tier: tuple(value)
                for tier, value in cls._tiers(raw["FALLBACK_MODELS"], "FALLBACK_MODELS").items()
            }
        if "ASSURANCE_TIER" in raw:
            fields["assurance_tier"] = cls._assurance(raw["ASSURANCE_TIER"])
        return AttestConfig(**fields)

    #: ``settings.ATTEST`` key → :class:`AttestConfig` field, for the plain scalars.
    _SCALARS = {
        "CURRENCY": "currency",
        "CURRENCY_SYMBOL": "currency_symbol",
        "LOCALE": "locale",
        "TIMEZONE": "timezone",
        "MAX_STEPS": "max_steps",
        "MAX_TOKENS_PER_RUN": "max_tokens_per_run",
        "DAILY_BUDGET": "daily_budget",
        "EXACT_CACHE": "exact_cache",
        "SEMANTIC_CACHE": "semantic_cache",
        "EXTRAS": "extras",
    }

    _KNOWN = frozenset(
        {*_SCALARS, "BRAND", "BRAND_ALIASES", "MODELS", "FALLBACK_MODELS", "ASSURANCE_TIER"}
    )

    @classmethod
    def _tiers(cls, mapping: Mapping[str, Any], key: str) -> dict[ModelTier, Any]:
        """Coerce string tier names to :class:`ModelTier`, rejecting unknown ones."""
        resolved: dict[ModelTier, Any] = {}
        for name, value in mapping.items():
            try:
                resolved[ModelTier(name)] = value
            except ValueError as exc:
                valid = ", ".join(sorted(tier.value for tier in ModelTier))
                raise ConfigurationError(
                    f"{cls.SETTINGS_KEY}['{key}'] names tier {name!r}; valid tiers are {valid}"
                ) from exc
        return resolved

    @classmethod
    def _assurance(cls, value: str) -> AssuranceTier:
        try:
            return AssuranceTier(value)
        except ValueError as exc:
            valid = ", ".join(sorted(tier.value for tier in AssuranceTier))
            raise ConfigurationError(
                f"{cls.SETTINGS_KEY}['ASSURANCE_TIER'] is {value!r}; valid tiers are {valid}"
            ) from exc
