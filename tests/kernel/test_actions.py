"""Action hashing is the binding that makes a grant mean something.

Threat-model attacks 5 and 10: a grant issued for one payment must not authorise a
different beneficiary or a different amount, and mutating arguments after issuance
must invalidate it.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from attest.kernel.actions import Action
from attest.kernel.effects import (
    TERMINAL_EFFECT_STATES,
    EffectClass,
    EffectClasses,
    EffectSemantics,
    EffectState,
    IdempotencyMode,
)
from attest.kernel.identifiers import ActorId, TenantId


def _action(**kw: object) -> Action:
    base: dict[str, object] = {
        "tool": "transfer",
        "actor": ActorId("alice"),
        "tenant": TenantId("acme"),
        "arguments": {"to": "X", "amount": Decimal("12400.00")},
    }
    return Action(**{**base, **kw})  # type: ignore[arg-type]


# ── Binding ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_identical_actions_hash_identically() -> None:
    assert _action().action_hash() == _action().action_hash()


@pytest.mark.unit
def test_argument_order_does_not_change_the_hash() -> None:
    left = _action(arguments={"to": "X", "amount": Decimal("1.00")})
    right = _action(arguments={"amount": Decimal("1.00"), "to": "X"})
    assert left.action_hash() == right.action_hash()


@pytest.mark.unit
@pytest.mark.security
def test_changing_the_beneficiary_changes_the_hash() -> None:
    # Threat-model attack 5: wrong beneficiary.
    authorised = _action(arguments={"to": "X", "amount": Decimal("12400.00")})
    attacker = _action(arguments={"to": "Y", "amount": Decimal("12400.00")})
    assert authorised.action_hash() != attacker.action_hash()


@pytest.mark.unit
@pytest.mark.security
def test_changing_the_amount_changes_the_hash() -> None:
    authorised = _action(arguments={"to": "X", "amount": Decimal("12400.00")})
    attacker = _action(arguments={"to": "X", "amount": Decimal("500000.00")})
    assert authorised.action_hash() != attacker.action_hash()


@pytest.mark.unit
@pytest.mark.security
def test_the_hash_covers_arguments_not_merely_the_tool_name() -> None:
    # The whole point: a grant binds THESE arguments, not this tool.
    same_tool_different_args = {
        _action(arguments={"to": "X"}).action_hash(),
        _action(arguments={"to": "Y"}).action_hash(),
    }
    assert len(same_tool_different_args) == 2


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool", "refund"),
        ("actor", ActorId("mallory")),
        ("tenant", TenantId("other-corp")),
        ("capability", "elevated"),
        ("idempotency", IdempotencyMode.NATURAL),
        ("effects", frozenset({EffectClasses.FINANCIAL})),
        ("semantics", EffectSemantics(reversible=True)),
    ],
)
def test_every_authority_relevant_field_is_bound(field: str, value: object) -> None:
    assert _action().action_hash() != _action(**{field: value}).action_hash()


@pytest.mark.unit
def test_metadata_is_deliberately_not_bound() -> None:
    # Operational annotation - trace ids, UI hints - must not change what was
    # authorised, or attaching a log field would invalidate a live grant.
    assert _action().action_hash() == _action(metadata={"trace": "abc"}).action_hash()


@pytest.mark.unit
@pytest.mark.security
def test_arguments_cannot_be_mutated_after_construction() -> None:
    # Without freezing, action_hash binds nothing: the proposer holds a reference it
    # could edit between issuance and redemption.
    action = _action()
    before = action.action_hash()
    with pytest.raises(TypeError):
        action.arguments["amount"] = Decimal("500000.00")  # type: ignore[index]
    assert action.action_hash() == before


# ── Construction is fail-closed ──────────────────────────────────────────────────


@pytest.mark.unit
def test_defaults_are_the_cautious_values() -> None:
    # A tool that declares nothing must be treated as dangerous, not as safe.
    semantics = EffectSemantics()
    assert semantics.reversible is False
    assert semantics.compensatable is False
    assert semantics.legally_binding is True
    assert semantics.financially_material is True
    assert semantics.idempotent_upstream is False
    assert _action().idempotency is IdempotencyMode.FORBIDDEN


@pytest.mark.unit
@pytest.mark.parametrize(
    ("field", "message"),
    [("tool", "tool"), ("tenant", "tenancy"), ("actor", "actor")],
)
def test_identity_fields_must_not_be_empty(field: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _action(**{field: ""})


# ── Retry policy ─────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize(
    ("mode", "upstream", "expected"),
    [
        (IdempotencyMode.NATURAL, True, True),
        (IdempotencyMode.NATURAL, False, True),
        (IdempotencyMode.KEYED, True, True),
        (IdempotencyMode.KEYED, False, False),
        (IdempotencyMode.FORBIDDEN, True, False),
        (IdempotencyMode.FORBIDDEN, False, False),
    ],
)
def test_retry_requires_both_levels_to_agree(
    mode: IdempotencyMode, upstream: bool, expected: bool
) -> None:
    # Row (KEYED, False) is where duplicate payments come from: the tool looks safe
    # to retry because we hold a key, but the upstream ignores it.
    semantics = EffectSemantics(idempotent_upstream=upstream)
    assert semantics.may_retry_on_timeout(mode) is expected


@pytest.mark.unit
@pytest.mark.security
def test_a_keyed_tool_with_a_dishonest_upstream_is_never_retried() -> None:
    assert (
        EffectSemantics(idempotent_upstream=False).may_retry_on_timeout(IdempotencyMode.KEYED)
        is False
    )


# ── Effect lifecycle ─────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_unknown_is_terminal_for_the_run() -> None:
    assert EffectState.UNKNOWN in TERMINAL_EFFECT_STATES


@pytest.mark.unit
def test_submitted_is_not_terminal() -> None:
    # A dangling SUBMITTED is exactly what the reconciliation sweep looks for.
    assert EffectState.SUBMITTED not in TERMINAL_EFFECT_STATES


@pytest.mark.unit
def test_terminal_states_are_exactly_these() -> None:
    assert {
        EffectState.COMMITTED,
        EffectState.FAILED,
        EffectState.REFUSED,
        EffectState.UNKNOWN,
    } == TERMINAL_EFFECT_STATES


# ── Effect classes are open ──────────────────────────────────────────────────────


@pytest.mark.unit
def test_the_shipped_effect_classes_cover_more_than_state_and_money() -> None:
    # Tier 1 of docs/domains/catalog.md is "liberty, life, and legal standing".
    # A detention decision is not financial and not physical, so without EffectClasses.LIBERTY an
    # obligation rule for it would end up written against `external`.
    assert {
        EffectClasses.LIBERTY,
        EffectClasses.LEGAL,
        EffectClasses.CLINICAL,
        EffectClasses.DISCLOSURE,
        EffectClasses.NOTIFICATION,
    } <= EffectClasses.shipped()


@pytest.mark.unit
def test_notification_is_its_own_class_because_domains_disagree_about_it() -> None:
    # mortgage.md MANDATES notification before an offer takes effect; banking.md
    # makes notifying the subject of a SAR a criminal offence. Same primitive,
    # opposite obligation, so it cannot be folded into EffectClasses.EXTERNAL.
    assert EffectClasses.NOTIFICATION in EffectClasses.shipped()
    assert EffectClasses.NOTIFICATION != EffectClasses.EXTERNAL


@pytest.mark.unit
def test_a_domain_can_register_its_own_effect_class() -> None:
    # The openness test. If EffectClass were an enum this would not type-check, and
    # a domain needing a consequence we never imagined would have to edit the kernel.
    blinding = EffectClass("breaks_trial_blinding")
    action = _action(effects=frozenset({blinding}))
    assert blinding in action.effects
    assert action.action_hash()


@pytest.mark.unit
@pytest.mark.security
def test_a_domain_effect_class_is_bound_into_the_action_hash() -> None:
    custom = _action(effects=frozenset({EffectClass("breaks_trial_blinding")}))
    assert _action().action_hash() != custom.action_hash()
