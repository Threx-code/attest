"""Config holds values; profiles hold behaviour.

The 199-line rules engine that could never be shared differed by one character — a
currency symbol baked into code. Everything here exists so that cannot recur, and so a
misconfiguration fails at boot rather than at 3am under load.
"""

from __future__ import annotations

import pytest

from attest.kernel.config import AssuranceTier, AttestConfig, ModelTier
from attest.kernel.errors import ConfigurationError


def _config(**kw: object) -> AttestConfig:
    base: dict[str, object] = {"brand": "acme"}
    return AttestConfig(**{**base, **kw})  # type: ignore[arg-type]


# ── Validation happens at construction ───────────────────────────────────────────


@pytest.mark.unit
def test_a_minimal_config_is_valid() -> None:
    assert _config().currency == "USD"


@pytest.mark.unit
@pytest.mark.security
def test_an_empty_brand_is_rejected() -> None:
    # The brand is interpolated into injection-detection patterns; an empty one
    # silently weakens them.
    with pytest.raises(ConfigurationError, match="injection"):
        _config(brand="")


@pytest.mark.unit
@pytest.mark.parametrize("currency", ["", "GB", "POUND"])
def test_currency_must_be_a_three_letter_code(currency: str) -> None:
    with pytest.raises(ConfigurationError, match="three-letter"):
        _config(currency=currency)


@pytest.mark.unit
def test_the_currency_symbol_is_configuration_not_code() -> None:
    # The entire diff between two copies of a 199-line rules engine.
    naira = _config(currency="NGN", currency_symbol="₦", locale="en_NG")
    sterling = _config(currency="GBP", currency_symbol="£", locale="en_GB")
    assert naira.currency_symbol != sterling.currency_symbol
    assert naira.content_hash() != sterling.content_hash()


@pytest.mark.unit
@pytest.mark.parametrize("steps", [0, -1, 65, 1000])
def test_step_ceilings_outside_the_permitted_range_are_rejected(steps: int) -> None:
    with pytest.raises(ConfigurationError, match="unbounded"):
        _config(max_steps=steps)


@pytest.mark.unit
def test_a_non_positive_token_ceiling_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="positive"):
        _config(max_tokens_per_run=0)


@pytest.mark.unit
@pytest.mark.parametrize("budget", ["not-a-number", "1.2.3"])
def test_a_non_decimal_budget_is_rejected(budget: str) -> None:
    with pytest.raises(ConfigurationError, match="decimal string"):
        _config(daily_budget=budget)


@pytest.mark.unit
def test_a_negative_budget_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="negative"):
        _config(daily_budget="-1")


# ── Combinations that are individually valid and jointly unsafe ──────────────────


@pytest.mark.unit
def test_a_fallback_for_an_unconfigured_tier_is_rejected() -> None:
    # A failover list for a tier nobody can reach will never do what it appears to.
    with pytest.raises(ConfigurationError, match="no primary model"):
        _config(fallback_models={ModelTier.REASONING: ("backup",)})


@pytest.mark.unit
def test_an_empty_fallback_list_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        _config(models={ModelTier.FAST: "m"}, fallback_models={ModelTier.FAST: ()})


@pytest.mark.unit
@pytest.mark.security
def test_semantic_cache_cannot_be_enabled_at_the_max_assurance_tier() -> None:
    # MAX exists to judge every claim; serving a near-miss cached answer discards
    # the judgement that was paid for.
    with pytest.raises(ConfigurationError, match="discards"):
        _config(semantic_cache=True, assurance_tier=AssuranceTier.MAX)


@pytest.mark.unit
def test_semantic_cache_is_off_by_default() -> None:
    # Acceptable for a support chatbot, unacceptable for a claim adjudication. The
    # framework will not make that choice for a domain.
    assert _config().semantic_cache is False


# ── Model resolution ─────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_a_tier_resolves_to_its_configured_model() -> None:
    config = _config(models={ModelTier.REASONING: "big-model"})
    assert config.model_for(ModelTier.REASONING) == "big-model"


@pytest.mark.unit
@pytest.mark.security
def test_an_unconfigured_tier_raises_rather_than_substituting_another() -> None:
    # Silently answering a reasoning request with a fast model changes the decision
    # without recording that it changed.
    config = _config(models={ModelTier.FAST: "small-model"})
    with pytest.raises(ConfigurationError, match="without recording"):
        config.model_for(ModelTier.REASONING)


# ── Tenant overrides ─────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_for_tenant_returns_a_new_instance() -> None:
    base = _config(currency="USD", currency_symbol="$")
    tenant = base.for_tenant(currency="NGN", currency_symbol="₦")
    assert base.currency == "USD"
    assert tenant.currency == "NGN"


@pytest.mark.unit
@pytest.mark.security
def test_an_override_cannot_produce_a_config_the_deployment_would_reject() -> None:
    # Overrides are re-validated, so a tenant cannot be handed something invalid.
    with pytest.raises(ConfigurationError, match="unbounded"):
        _config().for_tenant(max_steps=999)


@pytest.mark.unit
def test_an_unknown_override_field_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="DomainProfile"):
        _config().for_tenant(domain="medical")


@pytest.mark.unit
def test_config_is_frozen() -> None:
    with pytest.raises((AttributeError, TypeError)):
        _config().brand = "other"  # type: ignore[misc]


@pytest.mark.unit
def test_mappings_are_frozen_after_construction() -> None:
    config = _config(models={ModelTier.FAST: "m"})
    with pytest.raises(TypeError):
        config.models[ModelTier.FAST] = "other"  # type: ignore[index]


# ── Content addressing ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_identical_configs_hash_identically() -> None:
    assert _config().content_hash() == _config().content_hash()


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("brand", "other"),
        ("max_steps", 4),
        ("max_tokens_per_run", 1000),
        ("assurance_tier", AssuranceTier.THIN),
        ("exact_cache", False),
        ("daily_budget", "500.00"),
    ],
)
def test_config_fields_are_bound_into_the_hash(field: str, value: object) -> None:
    # The config hash is pinned into every attestation, so a threshold change must be
    # visible in the record rather than silently altering historical decisions.
    assert _config().content_hash() != _config(**{field: value}).content_hash()
