"""Tools: the registry, the filter, and the argument checks.

Assertions are on **what a mistake costs**, not on whether a method exists. The two
properties `docs/capabilities/tools.md` promises are both safety properties, and both
are about what happens when somebody gets a declaration wrong:

- a tool that declares its effects honestly inherits the right gates, so a profile never
  enumerates tools — which means an action assembled with the wrong effects is not
  refused, it is *correctly* processed against a false description of itself;
- `for_actor` filters before the model sees the list, so a tool the actor cannot use is
  never advertised.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

import pytest

from attest.capabilities.tools import (
    ArgumentError,
    CitedAmount,
    Schema,
    ToolRegistry,
    ToolSpec,
)
from attest.kernel.effects import EffectClasses, EffectSemantics, IdempotencyMode
from attest.kernel.errors import ConfigurationError
from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKinds,
    SourceRef,
    SourceType,
)
from attest.kernel.identifiers import ActorId, EvidenceId, Hash, TenantId

pytestmark = pytest.mark.unit

ACTOR = ActorId("alice")
TENANT = TenantId("t1")
AT = datetime(2026, 1, 1, tzinfo=UTC)

TRANSFER = {
    "type": "object",
    "properties": {
        "amount": {"type": "string", "pattern": r"^\d+\.\d{2}$"},
        "to": {"type": "string", "minLength": 1},
    },
    "required": ["amount", "to"],
    "additionalProperties": False,
}


def transfer_spec(**overrides: Any) -> ToolSpec:
    fields: dict[str, Any] = {
        "name": "transfer_funds",
        "description": "Move money between accounts.",
        "parameters": Schema(TRANSFER),
        "capability": "transfer",
        "effects": frozenset({EffectClasses.FINANCIAL}),
        "semantics": EffectSemantics(reversible=False, compensatable=True),
        "idempotency": IdempotencyMode.KEYED,
        "key_from": lambda args: str(args["to"]),
    }
    fields.update(overrides)
    return ToolSpec(**fields)


def evidence(value: str, *, sub: tuple[Evidence, ...] = ()) -> Evidence:
    return Evidence(
        evidence_id=EvidenceId("ev_1"),
        kind=EvidenceKinds.OBSERVATION,
        source=SourceRef(
            source_id="ledger-1",
            source_type=SourceType.LEDGER,
            authority=AuthorityLevel.AUTHORITATIVE,
            version="1",
            retrieved_at=AT,
            integrity_hash=Hash("b" * 64),
        ),
        value=value,
        sub_evidence=sub,
    )


# ── The property the whole type exists for ──────────────────────────────────


def test_a_proposed_action_carries_the_declaration_not_the_callers_opinion() -> None:
    """`obligations_for` dispatches on these, so the caller must not be able to state them.

    A caller free to pass `effects=frozenset()` is a caller free to skip the budget gate,
    and the profile would never know: the action is not refused, it is correctly
    processed against a false description of itself.
    """
    action = transfer_spec().propose(
        actor=ACTOR, tenant=TENANT, arguments={"amount": "500000.00", "to": "acct-9"}
    )
    assert action.effects == frozenset({EffectClasses.FINANCIAL})
    assert action.capability == "transfer"
    assert action.idempotency is IdempotencyMode.KEYED
    assert action.semantics.reversible is False


def test_a_tool_that_declares_a_new_effect_inherits_the_gate_without_a_profile_change() -> None:
    """The claim in the docs: a tool added next year gets the right gates for free.

    Tested through a profile that enumerates no tool names at all — if this passes, the
    authority rules really are written against declarations rather than against a list
    somebody has to remember to update.
    """

    def obligations_for(action: Any) -> list[str]:
        gates = ["capability"]
        if EffectClasses.FINANCIAL in action.effects:
            gates.append("budget")
        if not action.semantics.reversible:
            gates.append("dual_control")
        return gates

    written_next_year = ToolSpec(
        name="issue_refund",
        description="Refund a settled claim.",
        parameters=Schema({"type": "object"}),
        capability="refund",
        effects=frozenset({EffectClasses.FINANCIAL}),
        semantics=EffectSemantics(reversible=False),
        idempotency=IdempotencyMode.KEYED,
        key_from=lambda args: "r-1",
    )
    action = written_next_year.propose(actor=ACTOR, tenant=TENANT, arguments={})
    assert obligations_for(action) == ["capability", "budget", "dual_control"]


# ── for_actor filters before the model sees anything ────────────────────────


def test_a_tool_the_actor_cannot_use_is_never_advertised() -> None:
    """Removes a class of confused-deputy attempts rather than defending against them."""
    registry = ToolRegistry()
    registry.register(transfer_spec())
    registry.register(
        ToolSpec(
            name="read_balance",
            description="Read an account balance.",
            parameters=Schema({"type": "object"}),
            capability=None,
            idempotency=IdempotencyMode.NATURAL,
        )
    )

    visible = registry.advertise(frozenset({"read"}))
    assert [tool["name"] for tool in visible] == ["read_balance"]


def test_the_advertised_tool_never_names_the_capability_it_needs() -> None:
    """Model-visible text is untrusted in both directions.

    A model that can see the capability name can put it in an argument, a summary, or an
    answer a person reads.
    """
    registry = ToolRegistry()
    registry.register(transfer_spec())
    advertised = registry.advertise(frozenset({"transfer"}))[0]
    assert "capability" not in advertised
    assert "transfer" not in str(advertised.get("effects", ""))


def test_the_advertised_list_is_stable_across_calls() -> None:
    """An unordered tool list changes the prompt, so the prompt hash changes, so prompt
    versioning becomes meaningless and replay never reproduces.
    """
    registry = ToolRegistry()
    for name in ("zeta", "alpha", "mu"):
        registry.register(
            ToolSpec(
                name=name,
                description=name,
                parameters=Schema({"type": "object"}),
                idempotency=IdempotencyMode.NATURAL,
            )
        )
    first = [tool["name"] for tool in registry.advertise(frozenset())]
    assert first == sorted(first)
    assert first == [tool["name"] for tool in registry.advertise(frozenset())]


def test_an_actor_with_no_capabilities_gets_only_the_ungated_tools() -> None:
    """The correct, restrictive answer for an unwired identity — not an empty list and
    not everything."""
    registry = ToolRegistry()
    registry.register(transfer_spec())
    registry.register(
        ToolSpec(
            name="read_balance",
            description="Read a balance.",
            parameters=Schema({"type": "object"}),
            idempotency=IdempotencyMode.NATURAL,
        )
    )
    assert [spec.name for spec in registry.for_actor(frozenset())] == ["read_balance"]


@pytest.mark.security
def test_proposing_an_unadvertised_tool_is_refused_at_the_registry() -> None:
    """The proposal did not come from the list the actor was shown."""
    registry = ToolRegistry()
    registry.register(transfer_spec())
    with pytest.raises(ArgumentError, match="capability they do not hold"):
        registry.propose(
            "transfer_funds",
            actor=ACTOR,
            tenant=TENANT,
            capabilities=frozenset({"read"}),
            arguments={"amount": "1.00", "to": "acct-9"},
        )


# ── Registration is where a mistake is cheap ────────────────────────────────


def test_a_forbidden_tool_without_a_key_fails_at_registration() -> None:
    """ "...not at 2am." Queues redeliver and clients retry timeouts."""
    with pytest.raises(ConfigurationError, match="fail at registration"):
        ToolSpec(
            name="wire_transfer",
            description="Send a wire.",
            parameters=Schema({"type": "object"}),
            idempotency=IdempotencyMode.FORBIDDEN,
        )


def test_a_keyed_tool_without_a_key_fails_at_registration() -> None:
    with pytest.raises(ConfigurationError, match="nothing can deduplicate a retry"):
        ToolSpec(
            name="charge_card",
            description="Charge a card.",
            parameters=Schema({"type": "object"}),
            idempotency=IdempotencyMode.KEYED,
        )


def test_a_natural_tool_needs_no_key() -> None:
    """A read really is safe to repeat, and demanding a key for one would push hosts to
    declare KEYED with a fake key — which is worse than either."""
    spec = ToolSpec(
        name="read_balance",
        description="Read a balance.",
        parameters=Schema({"type": "object"}),
        idempotency=IdempotencyMode.NATURAL,
    )
    assert spec.idempotency_key({}) == ""


def test_an_empty_capability_is_refused_rather_than_read_as_none() -> None:
    """An empty string reads as a capability nobody holds, silently making the tool
    uninvokable — a tool that is quietly dead is worse than one that fails to load."""
    with pytest.raises(ConfigurationError, match="empty capability"):
        ToolSpec(
            name="x",
            description="x",
            parameters=Schema({"type": "object"}),
            capability="",
            idempotency=IdempotencyMode.NATURAL,
        )


def test_registering_one_name_twice_is_refused() -> None:
    """A grant binds to the tool name, so two definitions means whichever import order
    won gets to define what a grant authorised."""
    registry = ToolRegistry()
    registry.register(transfer_spec())
    with pytest.raises(ConfigurationError, match="already registered"):
        registry.register(transfer_spec())


def test_an_unknown_tool_raises_rather_than_returning_none() -> None:
    """A caller handed None would assemble the action by hand, which is the situation
    this module exists to end."""
    with pytest.raises(ConfigurationError, match="no tool named"):
        ToolRegistry().get("nope")


# ── Schema: no silent gaps ──────────────────────────────────────────────────


def test_a_schema_keyword_we_cannot_enforce_is_refused_not_ignored() -> None:
    """The rule that makes a hand-written validator safe to ship.

    Silently skipping `allOf` reports success for a constraint never applied, and every
    reader of that schema believes the argument is bounded.
    """
    with pytest.raises(ConfigurationError, match="does not implement"):
        Schema({"type": "object", "allOf": [{"type": "object"}]})


def test_requiring_a_property_the_schema_does_not_define_is_refused() -> None:
    """Nothing would constrain the value a caller supplies for it."""
    with pytest.raises(ConfigurationError, match="requires 'amount' and does not define"):
        Schema({"type": "object", "properties": {"to": {"type": "string"}}, "required": ["amount"]})


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({"to": "acct-9"}, "required property 'amount' is missing"),
        ({"amount": "1.00", "to": "acct-9", "memo": "x"}, "'memo' is not a declared property"),
        ({"amount": "1", "to": "acct-9"}, "does not match"),
        ({"amount": "1.00", "to": ""}, "shorter than 1"),
        ({"amount": 100, "to": "acct-9"}, "expected string, got int"),
    ],
    ids=["missing", "undeclared", "pattern", "too-short", "wrong-type"],
)
def test_bad_arguments_are_refused_before_an_action_exists(
    arguments: dict[str, Any], expected: str
) -> None:
    """An action that exists is one a grant can be bound to, so a partial one is never
    returned."""
    with pytest.raises(ArgumentError, match=expected):
        transfer_spec().propose(actor=ACTOR, tenant=TENANT, arguments=arguments)


def test_every_problem_is_reported_not_only_the_first() -> None:
    """A caller fixing arguments one round-trip at a time stops validating."""
    with pytest.raises(ArgumentError) as raised:
        transfer_spec().propose(actor=ACTOR, tenant=TENANT, arguments={"memo": "x"})
    message = str(raised.value)
    assert "'amount' is missing" in message
    assert "'to' is missing" in message
    assert "'memo' is not a declared property" in message


def test_a_boolean_is_not_an_integer() -> None:
    """`bool` subclasses `int`, so a flag passed where a quantity belongs would pass."""
    assert Schema({"type": "integer"}).check(True), "True was accepted as an integer"
    assert not Schema({"type": "integer"}).check(3)


def test_bounds_and_enums_are_enforced() -> None:
    assert Schema({"type": "number", "minimum": 0}).check(-1)
    assert Schema({"type": "number", "maximum": 10}).check(11)
    assert Schema({"enum": ["a", "b"]}).check("c")
    assert not Schema({"type": "number", "minimum": 0, "maximum": 10}).check(5)


def test_array_items_are_checked() -> None:
    schema = Schema({"type": "array", "items": {"type": "string"}})
    assert schema.check(["a", 2])
    assert not schema.check(["a", "b"])


# ── The consistency check, which is the strongest tier ──────────────────────


@pytest.mark.security
def test_an_amount_that_no_cited_evidence_supports_is_refused() -> None:
    """The docs' own example: cites a settlement of GBP 12,400, proposes paying 21,400.

    Deterministic, and without another model call — a second model answering this would
    be a probabilistic check on a question that has an exact answer.
    """
    spec = transfer_spec(validators=(CitedAmount("amount"),))
    with pytest.raises(ArgumentError, match="cited one figure and proposed acting on another"):
        spec.propose(
            actor=ACTOR,
            tenant=TENANT,
            arguments={"amount": "21400.00", "to": "acct-9"},
            evidence=(evidence("settlement computed at 12400.00"),),
        )


def test_an_amount_the_evidence_supports_is_accepted() -> None:
    spec = transfer_spec(validators=(CitedAmount("amount"),))
    action = spec.propose(
        actor=ACTOR,
        tenant=TENANT,
        arguments={"amount": "12400.00", "to": "acct-9"},
        evidence=(evidence("settlement computed at 12400.00"),),
    )
    assert action.arguments["amount"] == "12400.00"


def test_a_supporting_figure_in_a_sub_item_still_counts() -> None:
    """Evidence is a tree, and the figure that supports a total is usually a leaf."""
    spec = transfer_spec(validators=(CitedAmount("amount"),))
    action = spec.propose(
        actor=ACTOR,
        tenant=TENANT,
        arguments={"amount": "12400.00", "to": "acct-9"},
        evidence=(evidence("total settlement", sub=(evidence("line 3: 12400.00"),)),),
    )
    assert action.arguments["amount"] == "12400.00"


@pytest.mark.security
def test_proposing_an_amount_with_no_evidence_at_all_is_refused() -> None:
    """Nothing supports the figure being acted on, which is not the same as it being fine."""
    spec = transfer_spec(validators=(CitedAmount("amount"),))
    with pytest.raises(ArgumentError, match="no cited evidence"):
        spec.propose(actor=ACTOR, tenant=TENANT, arguments={"amount": "1.00", "to": "acct-9"})


def test_a_host_validator_runs_and_its_problems_reach_the_caller() -> None:
    """Referential and semantic checks are host code by construction — only the host
    knows whether account 8823 exists."""

    def account_must_exist(arguments: Any, _evidence: Any) -> list[str]:
        known = {"acct-9"}
        return [] if arguments["to"] in known else [f"account {arguments['to']!r} does not exist"]

    spec = transfer_spec(validators=(account_must_exist,))
    with pytest.raises(ArgumentError, match="does not exist"):
        spec.propose(actor=ACTOR, tenant=TENANT, arguments={"amount": "1.00", "to": "acct-nope"})


# ── Idempotency keys are business-derived ───────────────────────────────────


def test_the_key_is_derived_from_the_arguments_not_supplied_by_the_caller() -> None:
    """A key the caller invents is a different key on every retry, which is no key at all
    — and double-submit is the likeliest production failure in the whole framework."""
    spec = transfer_spec(key_from=lambda args: f"pay:{args['to']}:{args['amount']}")
    arguments = {"amount": "500000.00", "to": "acct-9"}
    assert spec.idempotency_key(arguments) == "pay:acct-9:500000.00"
    assert spec.idempotency_key(dict(arguments)) == spec.idempotency_key(arguments)


def test_the_registry_reports_what_it_holds() -> None:
    registry = ToolRegistry()
    registry.register(transfer_spec())
    assert registry.names() == ("transfer_funds",)
    assert "transfer_funds" in registry
    assert len(registry) == 1


def test_an_executor_registered_with_a_tool_can_be_found_again() -> None:
    """The framework defines the protocol; the host writes the executor."""
    sentinel = object()
    registry = ToolRegistry()
    registry.register(transfer_spec(), sentinel)
    assert registry.executor_for("transfer_funds") is sentinel
    assert registry.executor_for("read_balance") is None


def test_a_decimal_amount_is_compared_as_written() -> None:
    """`Decimal("1.00")` and `"1.00"` must agree, or a domain using Decimal internally
    gets a spurious consistency failure on every payment."""
    spec = transfer_spec(parameters=Schema({"type": "object"}), validators=(CitedAmount("amount"),))
    action = spec.propose(
        actor=ACTOR,
        tenant=TENANT,
        arguments={"amount": Decimal("12400.00"), "to": "acct-9"},
        evidence=(evidence("settlement computed at 12400.00"),),
    )
    assert action.arguments["amount"] == Decimal("12400.00")
