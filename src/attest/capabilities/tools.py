"""Tools — what an agent may propose, and what turns a proposal into an ``Action``.

``docs/capabilities/tools.md`` specifies a ``ToolSpec``, a registry, and a
``for_actor`` filter. None of it existed. That is worse than an unimplemented feature,
because the two things the document promises are both *safety* properties and both were
being done by hand at every call site:

.. code-block:: text

    THE DOCUMENT SAYS                        WHAT WAS ACTUALLY HAPPENING
    ─────────────────────────────────        ──────────────────────────────────────
    a tool declares its effects, and         every caller hand-assembled an Action
    a profile writes authority rules         with `effects=frozenset({...})` spelled
    against them — so a tool added next      out inline. A tool that forgot
    year inherits the right gates            `FINANCIAL` skipped the budget gate and
                                             the profile never knew

    for_actor filters the list BEFORE        nothing filtered anything, so every
    the model sees it, which removes a       actor's model saw every tool and the
    class of confused-deputy attempts        capability check was the only thing
    rather than defending against it         between them and a proposal

The first is the more serious. `obligations_for` dispatches on ``action.effects`` and
``action.semantics``, so an action assembled with the wrong ones is not refused — it is
*correctly* processed against a false description of itself, and produces an attestation
saying so.

.. rubric:: Registration is the checkpoint

Everything here fails at import time rather than at 2am: a ``FORBIDDEN`` tool with no way
to derive an idempotency key, a schema naming a required property it does not define, a
capability that is the empty string. A registry assembled at start-up is the last moment
where a mistake is cheap.

.. rubric:: What this deliberately does not do

It does not validate against the whole of JSON Schema. :class:`Schema` covers types,
required properties, enums, numeric bounds, string lengths and patterns — and refuses a
keyword it does not implement rather than ignoring it, so a schema that *looks* like it
constrains something either does, or fails loudly at registration. Silently ignoring
``allOf`` would be the worst of the three options: an argument constraint that reads as
enforced and is not.

It does not do referential or semantic validation, which are host concerns by
construction — only the host knows whether account 8823 exists. It provides the hook
(:attr:`ToolSpec.validators`) and the one cross-cutting check the framework *can* make,
which is the strongest and least common: :class:`CitedAmount`, arguments against the
evidence the model cited for proposing them.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Final

from attest.kernel.actions import Action
from attest.kernel.effects import EffectSemantics, IdempotencyMode
from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from attest.kernel.effects import EffectClass
    from attest.kernel.evidence import Evidence
    from attest.kernel.identifiers import ActorId, TenantId

__all__ = [
    "ArgumentError",
    "CitedAmount",
    "Schema",
    "ToolRegistry",
    "ToolSpec",
    "Validator",
]


class ArgumentError(ValueError):
    """A proposal's arguments were rejected.

    A ``ValueError`` rather than a refusal verdict: this is raised while *building* the
    action, before any warrant exists, and a caller that cannot build an action has
    nothing to attest about. The engine's refusal path begins one step later.
    """


# ── Schema ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Schema:
    """A deliberately small JSON Schema subset, with no silent gaps.

    The rule that makes this safe to ship: **an unimplemented keyword is an error at
    registration**, never an ignored one. A validator that quietly skips ``allOf``
    reports success for a constraint it never applied, and every reader of that schema
    believes the argument is bounded.

    Implemented: ``type``, ``properties``, ``required``, ``enum``, ``minimum``,
    ``maximum``, ``minLength``, ``maxLength``, ``pattern``, ``items``,
    ``additionalProperties``.
    """

    definition: Mapping[str, Any]

    KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {
            "type",
            "properties",
            "required",
            "enum",
            "minimum",
            "maximum",
            "minLength",
            "maxLength",
            "pattern",
            "items",
            "additionalProperties",
            "description",
            "title",
        }
    )

    TYPES: ClassVar[Mapping[str, type | tuple[type, ...]]] = {
        "object": dict,
        "array": (list, tuple),
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "null": type(None),
    }

    def __post_init__(self) -> None:
        self._assert_supported(self.definition, path="")

    @classmethod
    def _assert_supported(cls, definition: Any, *, path: str) -> None:
        """Refuse a schema we would only partly enforce. At registration, loudly."""
        if not isinstance(definition, dict):
            return
        unknown = sorted(set(definition) - cls.KEYWORDS)
        if unknown:
            raise ConfigurationError(
                f"schema at {path or '<root>'!r} uses {unknown}, which this validator "
                f"does not implement. Refusing rather than ignoring them: a constraint "
                f"that reads as enforced and is not is worse than no constraint. "
                f"Supported keywords are {sorted(cls.KEYWORDS)}."
            )
        declared = definition.get("properties", {})
        if isinstance(declared, dict):
            for name, sub in declared.items():
                cls._assert_supported(sub, path=f"{path}.{name}")
        for name in definition.get("required", ()):
            if isinstance(declared, dict) and name not in declared:
                raise ConfigurationError(
                    f"schema at {path or '<root>'!r} requires {name!r} and does not "
                    f"define it, so nothing constrains the value a caller supplies"
                )
        if "items" in definition:
            cls._assert_supported(definition["items"], path=f"{path}[]")

    def check(self, value: Any, *, path: str = "") -> tuple[str, ...]:
        """Every way ``value`` fails this schema. Empty means it passes.

        All problems rather than the first, because a caller fixing arguments one
        round-trip at a time is a caller who gives up and stops validating.
        """
        problems: list[str] = []
        where = path or "arguments"
        definition = self.definition

        expected = definition.get("type")
        if expected is not None:
            wanted = self.TYPES.get(str(expected))
            if wanted is not None and not self._is(value, wanted, expected):
                return (f"{where}: expected {expected}, got {type(value).__name__}",)

        if "enum" in definition and value not in definition["enum"]:
            problems.append(f"{where}: {value!r} is not one of {definition['enum']}")

        problems.extend(self._bounds(value, definition, where))

        if isinstance(value, dict):
            problems.extend(self._object(value, definition, where))
        elif isinstance(value, (list, tuple)) and "items" in definition:
            item_schema = Schema(definition["items"])
            for index, item in enumerate(value):
                problems.extend(item_schema.check(item, path=f"{where}[{index}]"))

        return tuple(problems)

    @staticmethod
    def _is(value: Any, wanted: type | tuple[type, ...], expected: Any) -> bool:
        # bool is a subclass of int, and "integer" must not accept True. A flag passed
        # where a quantity belongs is exactly the kind of confusion a schema is for.
        if expected in ("integer", "number") and isinstance(value, bool):
            return False
        return isinstance(value, wanted)

    @staticmethod
    def _bounds(value: Any, definition: Mapping[str, Any], where: str) -> list[str]:
        problems: list[str] = []
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in definition and value < definition["minimum"]:
                problems.append(f"{where}: {value} is below the minimum {definition['minimum']}")
            if "maximum" in definition and value > definition["maximum"]:
                problems.append(f"{where}: {value} is above the maximum {definition['maximum']}")
        if isinstance(value, str):
            if "minLength" in definition and len(value) < definition["minLength"]:
                problems.append(f"{where}: shorter than {definition['minLength']}")
            if "maxLength" in definition and len(value) > definition["maxLength"]:
                problems.append(f"{where}: longer than {definition['maxLength']}")
            pattern = definition.get("pattern")
            if pattern is not None and not re.search(str(pattern), value):
                problems.append(f"{where}: does not match {pattern!r}")
        return problems

    @staticmethod
    def _object(value: Mapping[str, Any], definition: Mapping[str, Any], where: str) -> list[str]:
        problems: list[str] = []
        declared = definition.get("properties", {})
        for name in definition.get("required", ()):
            if name not in value:
                problems.append(f"{where}: required property {name!r} is missing")
        for name, sub in declared.items():
            if name in value:
                problems.extend(Schema(sub).check(value[name], path=f"{where}.{name}"))
        if definition.get("additionalProperties") is False:
            for name in value:
                if name not in declared:
                    problems.append(f"{where}: {name!r} is not a declared property")
        return problems


# ── Domain validation ────────────────────────────────────────────────────────

Validator = Callable[[Mapping[str, Any], Sequence["Evidence"]], Sequence[str]]
"""Host-supplied argument check. Returns problems; empty means it passed.

Takes the cited evidence as well as the arguments, because the check the document calls
"the strongest and the least common" needs both. Host code by construction: only the
host knows whether account 8823 exists, and none of that belongs in the framework.
"""


@dataclass(frozen=True, slots=True)
class CitedAmount:
    """The consistency check the framework *can* make, and the one worth shipping.

    From ``docs/capabilities/tools.md``: if the model cites a settlement computation of
    GBP 12,400 and then proposes paying GBP 21,400, that is caught here —
    deterministically, without another model call.

    It is the strongest tier because it does not ask "is this argument well-formed" or
    even "is this a real account", but "does what you are about to do match what you
    said your reason for doing it was". Schema validation cannot see that, and a second
    model call answering it is a probabilistic check on a deterministic question.

    Cheap, exact, and narrow on purpose: it looks for the argument's value as a literal
    in the cited evidence. A domain needing tolerance, currency conversion or unit
    handling writes its own :data:`Validator` — this one refuses to guess, because an
    amount check that silently accepted "close enough" would be worse than absent.
    """

    argument: str
    """Which argument must be supported. Usually ``"amount"``."""

    def __call__(self, arguments: Mapping[str, Any], evidence: Sequence[Evidence]) -> Sequence[str]:
        if self.argument not in arguments:
            return ()
        proposed = str(arguments[self.argument])
        if not evidence:
            return (
                f"{self.argument}={proposed!r} is proposed with no cited evidence, so "
                f"nothing supports the figure being acted on",
            )
        for item in self._walk(evidence):
            if proposed in str(item.value):
                return ()
        return (
            f"{self.argument}={proposed!r} does not appear in any cited evidence. The "
            f"model cited one figure and proposed acting on another.",
        )

    @classmethod
    def _walk(cls, evidence: Sequence[Evidence]) -> list[Evidence]:
        """Every item and every descendant. A supporting figure may be a sub-item."""
        out: list[Evidence] = []
        stack = list(evidence)
        while stack:
            item = stack.pop()
            out.append(item)
            stack.extend(item.sub_evidence)
        return out


# ── The specification ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """What a tool is, declared once, so authority rules never enumerate tools.

    ``effects`` and ``semantics`` are the load-bearing fields, and the reason this type
    exists rather than each caller assembling an :class:`~attest.kernel.actions.Action`
    by hand. A profile writes:

    .. code-block:: python

        def obligations_for(self, action, ctx):
            obs = [CapabilityCheck(action.capability)]
            if EffectClasses.FINANCIAL in action.effects:
                obs.append(Budget("payments", ctx.actor))
            if not action.semantics.reversible:
                obs.append(DualControl())
            return ObligationSet(obs)

    — and a tool added next year inherits the right gates by declaring its effects
    honestly. Hand-assembled actions break that: a tool that forgets ``FINANCIAL`` is
    not refused, it is *correctly* processed against a false description of itself.
    """

    name: str
    description: str
    """What the model is told the tool does. Shown to the model, so it is untrusted
    output as much as input — see ``docs/capabilities/guards.md``."""

    parameters: Schema
    capability: str | None = None
    """Which capability an actor must hold to invoke it. ``None`` means none is
    required, which is a claim about the tool and should be rare."""

    effects: frozenset[EffectClass] = frozenset()
    semantics: EffectSemantics = field(default_factory=EffectSemantics)
    """Every field defaults to the cautious value, so a tool declaring nothing is
    treated as irreversible, legally binding and unsafe to retry."""

    idempotency: IdempotencyMode = IdempotencyMode.FORBIDDEN
    key_from: Callable[[Mapping[str, Any]], str] | None = None
    """Derives the business idempotency key from the arguments.

    Required for ``KEYED`` and ``FORBIDDEN``, and checked at registration — *"a
    FORBIDDEN tool without an idempotency key fails at registration, not at 2am"*.

    Derived from the arguments rather than supplied by the caller because the key must
    be what makes the action unique **to the business** — an invoice id, a payment
    reference. A key the caller invents is a different key on every retry, which is no
    key at all, and that is the likeliest production failure in the whole framework.
    """

    validators: tuple[Validator, ...] = ()
    """Referential, semantic and consistency checks. Host code, run after the schema."""

    def __post_init__(self) -> None:
        if not self.name:
            raise ConfigurationError("a tool must be named; the name is what a grant binds")
        if self.capability == "":
            raise ConfigurationError(
                f"tool {self.name!r} declares an empty capability. Use None to mean "
                f"'no capability required' — an empty string reads as a capability "
                f"nobody can hold and silently makes the tool uninvokable."
            )
        if self.idempotency is not IdempotencyMode.NATURAL and self.key_from is None:
            raise ConfigurationError(
                f"tool {self.name!r} is {self.idempotency.value.upper()} and supplies no "
                f"key_from, so nothing can deduplicate a retry. Queues redeliver, "
                f"approvals get double-clicked and clients retry timeouts; this must "
                f"fail at registration rather than at 2am. Declare NATURAL only if the "
                f"tool is genuinely safe to repeat."
            )

    def propose(
        self,
        *,
        actor: ActorId,
        tenant: TenantId,
        arguments: Mapping[str, Any],
        evidence: Sequence[Evidence] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Action:
        """Verify the arguments and build the action. **Raises rather than returning a
        partial one**, because an action that exists is one a grant can be bound to.

        The effects, semantics, capability and idempotency come from the spec, not from
        the caller. That is the whole point: they are what a profile's authority rules
        dispatch on, and a caller free to state them is a caller free to understate them.
        """
        problems = list(self.parameters.check(dict(arguments)))
        for validator in self.validators:
            problems.extend(validator(arguments, evidence))
        if problems:
            raise ArgumentError(
                f"{self.name} was proposed with arguments that do not verify:\n  "
                + "\n  ".join(problems)
            )
        return Action(
            tool=self.name,
            actor=actor,
            tenant=tenant,
            arguments=dict(arguments),
            semantics=self.semantics,
            idempotency=self.idempotency,
            effects=self.effects,
            capability=self.capability,
            metadata=dict(metadata or {}),
        )

    def idempotency_key(self, arguments: Mapping[str, Any]) -> str:
        """The business key for these arguments, or ``""`` for a NATURAL tool."""
        return "" if self.key_from is None else self.key_from(arguments)

    def advertised(self) -> dict[str, Any]:
        """The tool as the model is told about it. Never the capability or the effects.

        A model that can see which capability a tool needs can name it in an argument,
        in a summary, or in an answer a person reads — and the framework's own guidance
        is that model-visible text is untrusted in both directions.
        """
        return {
            "name": self.name,
            "description": self.description,
            "parameters": dict(self.parameters.definition),
        }


# ── The registry ─────────────────────────────────────────────────────────────


class ToolRegistry:
    """The tools a deployment has, and which of them an actor may see.

    ``for_actor`` filtering happens **before the model sees the tool list**. That is a
    different and stronger thing than checking capability at discharge: a tool the actor
    cannot use is never advertised, so a confused-deputy attempt has nothing to aim at.
    Capability is *still* re-checked at discharge, because the actor's grants may have
    changed mid-run — the filter narrows the attack surface and does not replace the gate.
    """

    __slots__ = ("_executors", "_specs")

    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._executors: dict[str, Any] = {}

    def register(self, spec: ToolSpec, executor: Any = None) -> ToolSpec:
        """Add a tool. Refuses a duplicate name rather than replacing silently.

        A second registration under one name would mean a grant bound to
        ``transfer_funds`` authorising whichever definition happened to load last, which
        depends on import order.
        """
        if spec.name in self._specs:
            raise ConfigurationError(
                f"tool {spec.name!r} is already registered. A grant binds to the tool "
                f"name, so two definitions under one name means a grant authorises "
                f"whichever import order happened to win."
            )
        self._specs[spec.name] = spec
        if executor is not None:
            self._executors[spec.name] = executor
        return spec

    def get(self, name: str) -> ToolSpec:
        """The spec, or a refusal naming it. Never ``None``.

        A caller that got ``None`` here would build the action by hand, which is the
        situation this module exists to end.
        """
        spec = self._specs.get(name)
        if spec is None:
            raise ConfigurationError(
                f"no tool named {name!r} is registered. Registered: "
                f"{sorted(self._specs) or '(none)'}."
            )
        return spec

    def executor_for(self, name: str) -> Any:
        """The host's executor for this tool, or ``None`` if it registered none."""
        return self._executors.get(name)

    def for_actor(self, actor_capabilities: frozenset[str]) -> tuple[ToolSpec, ...]:
        """Only the tools this actor may invoke, sorted by name.

        Takes the **capabilities** rather than the actor, because the framework does not
        resolve identity — the host's identity system does, and the result is
        snapshotted into the execution context so verification is reproducible. Passing
        an ``ActorId`` here would mean querying live identity mid-run, which is the
        thing ``ExecutionContext`` exists to prevent.

        Sorted so the tool list a model sees is stable: an unordered list changes the
        prompt on every call, so the prompt hash changes, so prompt versioning becomes
        meaningless and replay never reproduces.
        """
        return tuple(
            spec
            for spec in sorted(self._specs.values(), key=lambda s: s.name)
            if spec.capability is None or spec.capability in actor_capabilities
        )

    def advertise(self, actor_capabilities: frozenset[str]) -> tuple[dict[str, Any], ...]:
        """The tool list to put in front of a model, filtered and stripped."""
        return tuple(spec.advertised() for spec in self.for_actor(actor_capabilities))

    def propose(
        self,
        name: str,
        *,
        actor: ActorId,
        tenant: TenantId,
        capabilities: frozenset[str],
        arguments: Mapping[str, Any],
        evidence: Sequence[Evidence] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> Action:
        """Build a verified action for a tool this actor may invoke.

        The capability is checked **here as well as** at discharge, and refusing here is
        not redundant: a proposal for a tool the actor cannot use should not become an
        action at all, because an action exists to have a grant bound to it and there is
        no honest grant for this one. The discharge-time check remains the gate — the
        actor's capabilities may change between proposal and effect, and only the later
        check sees that.
        """
        spec = self.get(name)
        if spec.capability is not None and spec.capability not in capabilities:
            raise ArgumentError(
                f"{actor!r} proposed {name!r}, which requires the {spec.capability!r} "
                f"capability they do not hold. This tool is not advertised to them, so "
                f"the proposal did not come from the list they were shown."
            )
        return spec.propose(
            actor=actor,
            tenant=tenant,
            arguments=arguments,
            evidence=evidence,
            metadata=metadata,
        )

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def __len__(self) -> int:
        return len(self._specs)

    def __contains__(self, name: object) -> bool:
        return name in self._specs


UNRESTRICTED: Final[frozenset[str]] = frozenset()
"""What ``for_actor`` is given for an actor with no capabilities.

Named because ``for_actor(frozenset())`` reads as a mistake at a call site and is not:
it returns exactly the tools that require no capability, which is the correct and
restrictive answer for an unwired identity.
"""
