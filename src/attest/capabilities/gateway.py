"""The LLM gateway — one call site for every model interaction.

Nothing calls a provider SDK directly. That rule is what makes cost attribution,
redaction and drift detection possible at all: each was reimplemented per call site in
the surveyed codebases, and therefore inconsistently.

Two properties matter more than the plumbing:

**Failover is filtered by residency BEFORE it is consulted**, never after. A fallback
provider in another region turns an outage into a data-transfer breach, and where no
permitted provider remains the run refuses rather than silently leaving the region.

**A failover is recorded as a distinct fact.** A decision made by a fallback model is
a materially different decision, and replay must know.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field, replace
from datetime import timedelta
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from uuid import uuid4

from attest.kernel.attestation import CostRecord
from attest.kernel.canonical import Canonical
from attest.kernel.context import ModelRef
from attest.kernel.errors import ConfigurationError
from attest.kernel.identifiers import Hash
from attest.kernel.verdicts import Refusal, RefusalReason

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence
    from datetime import datetime

    from attest.kernel.context import ExecutionContext
    from attest.kernel.ports import Clock

__all__ = [
    "CacheEntry",
    "CanaryPrompt",
    "CircuitBreaker",
    "CircuitState",
    "CompletionRequest",
    "CompletionResponse",
    "DriftCanary",
    "DriftFinding",
    "DriftReport",
    "ExactCache",
    "Feature",
    "LLMProvider",
    "ModelCall",
    "ModelCallLog",
    "ModelGateway",
    "ModelPrice",
    "ModelSession",
    "PricingTable",
    "ProviderRouter",
    "ProviderSpec",
    "ResidencyRefused",
    "RetryPolicy",
    "SemanticCache",
    "StreamInterrupted",
    "StreamingProvider",
]


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    """Fast-fail for a cooldown window, so a degraded provider is not hammered."""

    HALF_OPEN = "half_open"


class Feature(StrEnum):
    """What a request may need a provider to honour.

    Named so the gateway can **refuse** a request a provider cannot serve rather than
    silently degrading it — a failover that quietly drops tool calling leaves the run
    continuing while unable to do what it was asked.
    """

    TOOLS = "tools"
    JSON_MODE = "json_mode"
    VISION = "vision"
    CACHING = "caching"
    STREAMING = "streaming"
    """Tokens as they are generated, rather than one response at the end.

    A feature rather than a second provider list, so a streamed call is filtered by the
    same rule as every other one: a backend that cannot stream is dropped from the
    failover chain for a streamed request, and an empty chain refuses.
    """


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """A provider endpoint, and what it is permitted to serve.

    ``family`` is the model's weights, not the vendor — the cross-family judging check
    compares this, because several providers serve the same open-weight family.
    """

    name: str
    model_id: str
    family: str
    region: str
    tier: str = ""
    """How capable this model is, as an opaque label the profile orders.

    Deliberately not an enum and deliberately unnamed here: a domain calls its tiers
    whatever it calls them, and naming them in the package would be domain knowledge.
    Empty means the deployment does not model tiers, and tier filtering is then inert.
    """

    zero_retention: bool = False
    supports_tools: bool = True
    supports_json: bool = True
    supports_vision: bool = False
    supports_caching: bool = False
    supports_streaming: bool = False
    """All three default to ``False``: an undeclared capability is absent, so a provider
    that forgot to describe itself is filtered out rather than asked to do something
    it cannot."""

    def supports(self, feature: Feature) -> bool:
        return {
            Feature.TOOLS: self.supports_tools,
            Feature.JSON_MODE: self.supports_json,
            Feature.VISION: self.supports_vision,
            Feature.CACHING: self.supports_caching,
            Feature.STREAMING: self.supports_streaming,
        }[feature]


@dataclass(frozen=True, slots=True)
class CompletionRequest:
    prompt_hash: str
    messages: tuple[str, ...]
    max_tokens: int
    temperature: float = 0.0
    seed: int | None = None
    requires_tools: bool = False
    """Retained as the common case. ``requires`` carries the rest."""

    requires: frozenset[Feature] = frozenset()
    """Everything else this request needs a provider to honour."""

    min_tier: str = ""
    """The weakest model tier that may serve this call.

    Empty means any. Set it on work whose quality a reader cannot audit from the output -
    the shape of a poor answer and a good one are the same.
    """

    idempotency_key: str = ""
    """One key per logical call, carried across every retry and failover.

    Filled by the gateway, not the caller: it has to be identical on the retry of a call
    that may already have been billed, and no caller can guarantee that for a retry it
    does not know happened.
    """

    cacheable: bool = True
    """Whether an exact repeat may be served from cache.

    ``False`` for a request whose answer must be recomputed — a fresh sample, or a
    call whose value is the act of making it.
    """

    def __post_init__(self) -> None:
        """The prompt hash must be the hash of the prompt.

        It was a caller-supplied string bound to nothing, and it is the main component
        of the cache key — so a host that hashed the prompt *template* rather than the
        rendered body (a natural reading of the prompts doc) made every tenant asking
        the same question collide on one entry. Binding it here means the key cannot be
        aliased by a caller, deliberately or by accident.
        """
        expected = self.digest_of(self.messages)
        if str(self.prompt_hash) != expected:
            raise ValueError(
                f"prompt_hash {self.prompt_hash!r} is not the hash of these messages "
                f"({expected!r}). The hash is the cache key: an unbound one lets two "
                f"different prompts share an entry, and two different tenants share an "
                f"answer. Use CompletionRequest.for_messages()."
            )

    @staticmethod
    def digest_of(messages: Sequence[str]) -> str:
        """The canonical digest of the rendered messages. One definition, used by both sides."""
        return Canonical.digest(list(messages))

    @classmethod
    def for_messages(
        cls,
        messages: Sequence[str],
        **kwargs: Any,  # noqa: ANN401 — a passthrough to this dataclass's own fields
    ) -> CompletionRequest:
        """Build a request whose hash is correct by construction."""
        return cls(prompt_hash=Hash(cls.digest_of(messages)), messages=tuple(messages), **kwargs)

    def required_features(self) -> frozenset[Feature]:
        return self.requires | ({Feature.TOOLS} if self.requires_tools else frozenset())


@dataclass(frozen=True, slots=True)
class CompletionResponse:
    text: str
    provider: str
    model_id: str
    family: str
    input_tokens: int = 0
    output_tokens: int = 0
    failover: bool = False
    metadata: dict[str, str] = field(default_factory=dict)


@runtime_checkable
class LLMProvider(Protocol):
    """One provider backend. The gateway is the only thing that calls these."""

    @property
    def spec(self) -> ProviderSpec: ...

    def complete(self, request: CompletionRequest) -> CompletionResponse: ...

    def supports(self, feature: Feature) -> bool:
        """Whether this backend can honour ``feature``.

        Present so the gateway can refuse rather than degrade. Backends answer from
        their :class:`ProviderSpec`; it is on the protocol because the *gateway* asks
        the provider, not the spec, and a backend may know something the spec does not.
        """
        ...


@runtime_checkable
class StreamingProvider(Protocol):
    """A backend that can emit tokens as they are generated.

    Separate from :class:`LLMProvider` rather than a method on it, because most backends
    do not stream and a Protocol that demanded it would exclude them from the
    ``isinstance`` checks they currently pass.

    The final :class:`CompletionResponse` is the generator's **return value**, not a
    yielded item. It carries the token counts, and the counts are the only way the call
    can be priced - a stream reporting nothing but text would be a model call the cost
    record could not see.
    """

    @property
    def spec(self) -> ProviderSpec: ...

    def complete(self, request: CompletionRequest) -> CompletionResponse: ...

    def supports(self, feature: Feature) -> bool: ...

    def stream(self, request: CompletionRequest) -> Generator[str, None, CompletionResponse]:
        """Yield text chunks, then return the completed response."""
        ...


class ResidencyRefused(Exception):
    """No permitted provider remains within the tenant's residency boundary.

    A refusal rather than a fallback. Crossing the boundary to keep serving is the
    specific hazard that turns an outage into a breach.
    """

    def __init__(self, refusal: Refusal) -> None:
        super().__init__(refusal.detail)
        self.refusal = refusal


class StreamInterrupted(Exception):
    """A stream failed after the reader had already seen part of it.

    Not a failover. Once bytes have left, switching provider means the reader is shown
    the answer a second time, which is worse than a truncation they can see. The partial
    text is carried so a caller can hand it to whatever it was filling.
    """

    def __init__(self, refusal: Refusal, *, partial: str) -> None:
        super().__init__(refusal.detail)
        self.refusal = refusal
        self.partial = partial


class ProviderRouter:
    """Chooses which providers may serve a run, residency first.

    Holds the tenant's residency constraints, so filtering cannot be skipped by a
    caller who forgot to pass them — which is the whole failure mode: a gateway that
    tries providers and checks residency afterwards has already sent the data.
    """

    __slots__ = ("_permitted_regions", "_tier_order", "_zero_retention_required")

    def __init__(
        self,
        *,
        permitted_regions: frozenset[str] = frozenset(),
        zero_retention_required: bool = False,
        tier_order: Sequence[str] = (),
    ) -> None:
        self._permitted_regions = permitted_regions
        self._zero_retention_required = zero_retention_required
        self._tier_order = tuple(tier_order)

    def _rank(self, tier: str) -> int:
        """Where a tier sits in the profile's ordering; -1 for one it never declared.

        An undeclared tier ranks BELOW every declared one rather than above, so a provider
        that forgot to describe its capability is filtered out of a tiered call instead of
        trusted with it - the same reading `ProviderSpec` already applies to features.
        """
        try:
            return self._tier_order.index(tier)
        except ValueError:
            return -1

    def select(
        self,
        candidates: Sequence[ProviderSpec],
        *,
        requires_tools: bool = False,
        requires: frozenset[Feature] = frozenset(),
        min_tier: str = "",
    ) -> tuple[ProviderSpec, ...]:
        """Filter the failover list by residency, capability tier and features, in that order.

        Features are filtered because a failover that silently drops one mid-run is worse
        than an error — the run continues and quietly cannot do what it was asked.

        ``min_tier`` is the same argument one level up, and the gap it closes is worse.
        A model that supports tools and JSON is not thereby as GOOD at the work, so a
        frontier-tier call failing over to a small fast model returns output that is
        structurally identical and materially weaker: same shape, same fields, same
        citation envelope, poorer reasoning. Nothing downstream can tell, which is exactly
        why it cannot be left to the caller to notice.

        Refusing is the right failure. This router already declines to fail over out of
        region rather than degrade the boundary; declining to fail over below tier is the
        same decision about a different axis.
        """
        needed = requires | ({Feature.TOOLS} if requires_tools else frozenset())
        floor = self._rank(min_tier) if min_tier else -1
        eligible = [
            spec
            for spec in candidates
            if (not self._permitted_regions or spec.region in self._permitted_regions)
            and (not self._zero_retention_required or spec.zero_retention)
            and (floor < 0 or self._rank(spec.tier) >= floor)
            and all(spec.supports(feature) for feature in needed)
        ]
        if not eligible:
            raise ResidencyRefused(
                Refusal(
                    reason=RefusalReason("residency_unavailable"),
                    detail=(
                        f"no provider satisfies residency "
                        f"{sorted(self._permitted_regions)} at tier "
                        f"{min_tier or 'any'} with features "
                        f"{sorted(needed) or 'none required'}. Refusing rather than "
                        f"failing over out of region, below tier, or silently degrading."
                    ),
                )
            )
        return tuple(eligible)


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """What one model costs, per million tokens. Decimal strings, never floats."""

    input_per_million: str
    output_per_million: str
    cached_input_per_million: str | None = None
    """``None`` means cached input is billed at the full input rate."""


@dataclass(frozen=True, slots=True)
class PricingTable:
    """A **versioned** price list, pinned into every cost record it produces.

    Prices change. A historical cost figure that silently re-prices at today's rate is
    not an audit record, so the version travels with the number rather than being
    looked up again at read time.

    A model the table does not list produces a cost of zero **and says so** — see
    :meth:`price`. Guessing a rate would put a fabricated number in a financial record.
    """

    version: str
    currency: str = "USD"
    prices: Mapping[str, ModelPrice] = field(default_factory=dict)

    def price(
        self, model_id: str, *, input_tokens: int, output_tokens: int, cached: int = 0
    ) -> str:
        """The cost of one call, as a decimal string.

        Raises for an unlisted model rather than returning zero: a zero that means
        "free" and a zero that means "we had no rate" are indistinguishable once
        written, and only one of them is true.
        """
        rate = self.prices.get(model_id)
        if rate is None:
            raise KeyError(
                f"pricing table {self.version!r} has no rate for model {model_id!r}. "
                f"Refusing to price it at zero: a zero meaning 'free' and a zero "
                f"meaning 'we had no rate' are indistinguishable once recorded."
            )
        billed_input = max(input_tokens - cached, 0)
        cached_rate = Decimal(rate.cached_input_per_million or rate.input_per_million)
        total = (
            Decimal(billed_input) * Decimal(rate.input_per_million)
            + Decimal(cached) * cached_rate
            + Decimal(output_tokens) * Decimal(rate.output_per_million)
        ) / Decimal(1_000_000)
        return str(total.quantize(Decimal("0.000001")))


@dataclass(frozen=True, slots=True)
class ModelCall:
    """One completed model call, priced and attributed.

    ``failover`` is recorded here rather than inferred later, because by then the
    routing state is gone — which is the reason
    :attr:`~attest.kernel.context.ModelRef.failover` exists at all.
    """

    provider: str
    model_id: str
    family: str
    region: str
    prompt_hash: str
    input_tokens: int
    output_tokens: int
    cached_tokens: int
    amount: str
    failover: bool
    attempted: tuple[str, ...] = ()
    """Providers tried before this one answered. Empty on a first-attempt success."""

    served_from_cache: bool = False
    """Whether no provider was called at all.

    Recorded rather than hidden: a cache hit costs nothing and involves no model, and
    an attestation showing a call that never happened would misstate both.
    """


@dataclass(frozen=True, slots=True)
class ModelCallLog:
    """Every model call made during one run, bound to the run that made them.

    ``context_hash`` is the binding, and it is what lets
    :class:`~attest.runtime.engine.RunEngine` treat this as evidence rather than as a
    claim: a log assembled by hand, or lifted from another run, does not match the
    context the engine captured. The same trick a grant uses to bind to its action.
    """

    run_id: str
    """The run these calls belong to.

    The binding the engine actually checks. ``context_hash`` cannot serve: the engine
    captures its context *inside* execute, with a run id and a timestamp it mints
    itself, so a hash taken by a caller beforehand could never match — the check would
    reject every honest log and pass none.
    """

    context_hash: str
    """The context the caller held when the calls were made.

    Recorded rather than enforced. It is what a caller who pins its own context can
    compare against, and it is the field to tighten if pinning ever becomes the norm.
    """

    pricing_version: str
    currency: str
    calls: tuple[ModelCall, ...] = ()
    circuits_opened: tuple[str, ...] = ()
    """Providers whose circuit opened during this run.

    Recorded because it changes what the run's later calls could reach: a decision
    made while a provider was fast-failing had a smaller pool to route within, and
    that is not visible from the calls that succeeded.
    """

    streams_abandoned: tuple[str, ...] = ()
    """Providers whose stream the reader walked away from mid-generation.

    Recorded as a distinct fact rather than as a zero-cost :class:`ModelCall`, because
    a zero would be false: the provider generated tokens and billed for them, and the
    consumer disconnected before learning how many. That is the same shape as an
    upstream timeout after a commit, which this framework types as ``UNKNOWN`` rather
    than coercing to a number - see :meth:`complete`.
    """

    def cost(self) -> CostRecord:
        """The run's total, summed from what was actually charged."""
        return CostRecord(
            input_tokens=sum(call.input_tokens for call in self.calls),
            output_tokens=sum(call.output_tokens for call in self.calls),
            cached_tokens=sum(call.cached_tokens for call in self.calls),
            currency=self.currency,
            amount=str(sum((Decimal(call.amount) for call in self.calls), Decimal(0))),
            pricing_version=self.pricing_version,
        )

    def complete(self) -> bool:
        """Whether :meth:`cost` is the whole bill.

        ``False`` once a stream was abandoned: the tokens it generated are in no call
        here and cannot be, so the total under-reports by an amount nobody in this
        process knows. Anything reconciling against a provider invoice needs telling,
        rather than inferring completeness from a figure that looks complete.
        """
        return not self.streams_abandoned

    def model_ref(self) -> ModelRef | None:
        """The model that produced the run's output — the last one to answer.

        ``None`` for a run that called no model, which is the honest value for a rules
        engine or a scheduled job proposing through the same kernel.
        """
        if not self.calls:
            return None
        last = self.calls[-1]
        return ModelRef(
            provider=last.provider,
            model_id=last.model_id,
            family=last.family,
            failover=any(call.failover for call in self.calls),
        )


class RetryPolicy:
    """Retry the *same* provider before failing over to a different one.

    The order matters and the doc states it: retry, then failover. A transient 503 on
    the primary should not silently move the run onto a different model — that is a
    materially different decision, and spending a failover on a blip means the record
    says a fallback answered when a retry would have done.

    Jitter is not decoration. Without it every run that hit the same outage retries in
    lockstep and the recovering provider is knocked over again by the herd.
    """

    __slots__ = ("_attempts", "_base_delay", "_max_delay")

    def __init__(
        self, *, attempts: int = 2, base_delay: float = 0.2, max_delay: float = 5.0
    ) -> None:
        if attempts < 1:
            raise ConfigurationError("a retry policy needs at least one attempt")
        self._attempts = attempts
        self._base_delay = base_delay
        self._max_delay = max_delay

    @property
    def attempts(self) -> int:
        return self._attempts

    def delay(self, attempt: int, *, jitter: float) -> float:
        """Exponential backoff for ``attempt`` (1-based), with ``jitter`` in [0, 1)."""
        backoff: float = min(self._base_delay * (2.0 ** (attempt - 1)), self._max_delay)
        return backoff + backoff * jitter


@dataclass(frozen=True, slots=True)
class CacheEntry:
    """A stored response, with what is needed to decide whether it may still be served."""

    response: CompletionResponse
    region: str
    tenant: str = ""
    """Who the answer was produced for. Compared on read, not merely recorded."""

    corpus_epochs: Mapping[str, str] = field(default_factory=dict)


class ExactCache:
    """Identical request in, stored response out. **Partitioned per tenant, always.**

    The tenant is in the key and is asserted again on read. It was absent from both,
    which made this a cross-tenant disclosure channel: the cache lives on the gateway,
    the gateway is a per-process singleton shared by every tenant's runs, and it is
    consulted before any provider is chosen — so one tenant's claim decision was served
    to another as that run's model output, priced at zero, with no provider call for
    residency, budget or audit to observe.

    The belt-and-braces read check is deliberate. A key is a hash, and a hash collision
    or a future change to what goes into it would silently reopen the hole; comparing
    the stored tenant costs one string comparison and cannot.

    The key also includes the corpus epochs the run was reading, so a document update
    invalidates the answers derived from it rather than serving a stale citation with a
    fresh timestamp, and the sampling parameters, because a response produced at one
    temperature is not the answer to a request made at another.

    Entries record the region that served them and are skipped when that region is no
    longer permitted — otherwise a residency change would keep replaying answers a
    tenant may no longer receive.
    """

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: dict[str, CacheEntry] = {}

    @staticmethod
    def key(request: CompletionRequest, *, model_id: str, context: ExecutionContext) -> str:
        return Canonical.digest(
            {
                # First, and not optional. A cache hit across tenants is a data leak
                # wearing a performance optimisation.
                "tenant": str(context.identity.tenant),
                "config_hash": str(context.binding.config_hash),
                "prompt_hash": request.prompt_hash,
                "model_id": model_id,
                "max_tokens": request.max_tokens,
                "temperature": request.temperature,
                "seed": request.seed,
                # A document update must invalidate answers derived from it.
                "corpus_epochs": {str(k): v for k, v in context.corpus_epochs.items()},
            }
        )

    def get(
        self, request: CompletionRequest, *, model_id: str, context: ExecutionContext
    ) -> CompletionResponse | None:
        entry = self._entries.get(self.key(request, model_id=model_id, context=context))
        if entry is None:
            return None
        if entry.tenant != str(context.identity.tenant):
            # Unreachable while the key carries the tenant, and checked anyway: this is
            # the highest-severity failure available in a multi-tenant system, and it
            # must not depend on one line of key construction staying correct.
            return None
        permitted = context.binding.residency_regions
        if permitted and entry.region not in permitted:
            return None
        return entry.response

    def put(
        self,
        request: CompletionRequest,
        response: CompletionResponse,
        *,
        model_id: str,
        region: str,
        context: ExecutionContext,
    ) -> None:
        self._entries[self.key(request, model_id=model_id, context=context)] = CacheEntry(
            response=response,
            region=region,
            tenant=str(context.identity.tenant),
            corpus_epochs={str(k): v for k, v in context.corpus_epochs.items()},
        )


@runtime_checkable
class SemanticCache(Protocol):
    """Similar request in, stored response out. **Domain-gated, off by default.**

    Returning a near-miss cached answer is acceptable for a support chatbot and
    unacceptable for a claim adjudication, so the framework will not make that choice
    on a domain's behalf: there is no default implementation, and a gateway without one
    passed in does not consult one.
    """

    def lookup(
        self, request: CompletionRequest, *, model_id: str, context: ExecutionContext
    ) -> CompletionResponse | None: ...

    def store(
        self, request: CompletionRequest, response: CompletionResponse, *, model_id: str
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class CanaryPrompt:
    """One frozen prompt, and the response recorded when the baseline was taken."""

    name: str
    request: CompletionRequest
    baseline_text: str
    baseline_taken_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class DriftFinding:
    """One canary that no longer answers the way it did."""

    canary: str
    model_id: str
    baseline: str
    observed: str
    similarity: float


@dataclass(frozen=True, slots=True)
class DriftReport:
    """The outcome of a canary sweep, and the marker later runs are stamped with."""

    model_id: str
    checked: int
    findings: tuple[DriftFinding, ...] = ()
    checked_at: datetime | None = None

    @property
    def drifted(self) -> bool:
        return bool(self.findings)

    def version_marker(self) -> str:
        """A stamp for the attestations produced after this sweep.

        Without one, "the model changed under us" is discovered through a support
        ticket months later with no way to tell which decisions were affected. With
        one, the attestations either side of the change are distinguishable.
        """
        return Canonical.digest(
            {
                "model_id": self.model_id,
                "drifted": self.drifted,
                "findings": sorted(f.canary for f in self.findings),
                "checked_at": self.checked_at,
            }
        )[:16]


class DriftCanary:
    """Runs frozen prompts against a live provider and compares them to baselines.

    The capability none of the surveyed systems had, and the one that matters most for
    a long-lived regulated system: providers change model behaviour under a stable
    name. The prompt is pinned, the model id is pinned, and the behaviour is not.

    Similarity is a token-overlap ratio — deliberately crude and deliberately local.
    A judge model would make drift detection depend on the very thing being checked
    for drift, and an embedding model would add a dependency to a package whose base
    install pulls nothing.
    """

    __slots__ = ("_canaries", "_clock", "_tolerance")

    def __init__(
        self,
        canaries: Sequence[CanaryPrompt],
        *,
        clock: Clock,
        tolerance: float = 0.85,
    ) -> None:
        if not 0.0 <= tolerance <= 1.0:
            raise ConfigurationError("drift tolerance must be a similarity between 0 and 1")
        self._canaries = tuple(canaries)
        self._clock = clock
        self._tolerance = tolerance

    @staticmethod
    def similarity(left: str, right: str) -> float:
        """Token overlap, 0.0 to 1.0. Identical text is exactly 1.0."""
        a, b = set(left.split()), set(right.split())
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def sweep(self, provider: LLMProvider) -> DriftReport:
        """Run every canary and report what moved outside tolerance."""
        findings: list[DriftFinding] = []
        for canary in self._canaries:
            response = provider.complete(canary.request)
            score = self.similarity(canary.baseline_text, response.text)
            if score < self._tolerance:
                findings.append(
                    DriftFinding(
                        canary=canary.name,
                        model_id=provider.spec.model_id,
                        baseline=canary.baseline_text,
                        observed=response.text,
                        similarity=score,
                    )
                )
        return DriftReport(
            model_id=provider.spec.model_id,
            checked=len(self._canaries),
            findings=tuple(findings),
            checked_at=self._clock.now(),
        )


class CircuitBreaker:
    """Fast-fail for a degraded provider, per provider name.

    Without it, a provider that is down is retried by every run at once — the
    thundering herd that turns one outage into a slower outage everywhere.

    Time is passed in rather than read, like everything else here, so the cooldown is
    reproducible in a replay.
    """

    __slots__ = ("_cooldown", "_failures", "_opened_at", "_threshold")

    def __init__(self, *, threshold: int = 3, cooldown: timedelta = timedelta(seconds=30)) -> None:
        self._threshold = threshold
        self._cooldown = cooldown
        self._failures: dict[str, int] = {}
        self._opened_at: dict[str, datetime] = {}

    def state(self, provider: str, *, now: datetime) -> CircuitState:
        opened = self._opened_at.get(provider)
        if opened is None:
            return CircuitState.CLOSED
        if now - opened >= self._cooldown:
            return CircuitState.HALF_OPEN
        return CircuitState.OPEN

    def allows(self, provider: str, *, now: datetime) -> bool:
        return self.state(provider, now=now) is not CircuitState.OPEN

    def record_failure(self, provider: str, *, now: datetime) -> bool:
        """Count a failure. Returns ``True`` if this one opened the circuit."""
        self._failures[provider] = self._failures.get(provider, 0) + 1
        if self._failures[provider] >= self._threshold and provider not in self._opened_at:
            self._opened_at[provider] = now
            return True
        return False

    def record_success(self, provider: str) -> None:
        self._failures.pop(provider, None)
        self._opened_at.pop(provider, None)


class ModelSession:
    """The gateway, scoped to one run.

    Exists because a run is not one model call. An agent calls the model several times
    before it proposes anything, so a gateway that returned a single response could
    never account for a run — and cost, failover and residency would go back to being
    things each call site remembered separately.

    Held by the caller for the length of its own loop, then handed to the engine as
    :meth:`log`.
    """

    __slots__ = ("_abandoned", "_calls", "_circuits", "_context", "_gateway")

    def __init__(self, gateway: ModelGateway, context: ExecutionContext) -> None:
        self._gateway = gateway
        self._context = context
        self._calls: list[ModelCall] = []
        self._circuits: list[str] = []
        self._abandoned: list[str] = []

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        """One governed model call. Residency is filtered before any provider is asked."""
        response, call = self._gateway.call(
            request, context=self._context, on_circuit_open=self._circuits.append
        )
        self._calls.append(call)
        return response

    def stream(self, request: CompletionRequest) -> Generator[str, None, None]:
        """One governed streamed call, under the same rules as :meth:`complete`.

        Iterate it to read the tokens. The :class:`ModelCall` lands in this session's log
        when generation finishes, so a streamed run accounts for itself exactly as a
        completed one does - which is the point. A call site that had to stream was a
        call site that escaped the gateway, and cost, residency and failover went back to
        being things each one remembered separately.

        A ``Generator`` rather than an ``Iterator`` because ``close()`` is part of the
        contract: a reader that disconnects closes this, and closing it is what records
        the abandonment on :meth:`log`.
        """
        call = yield from self._gateway.stream(
            request,
            context=self._context,
            on_circuit_open=self._circuits.append,
            on_abandoned=self._abandoned.append,
        )
        self._calls.append(call)

    def log(self) -> ModelCallLog:
        """What this run actually spent, bound to the run that spent it."""
        return ModelCallLog(
            run_id=str(self._context.run_id),
            context_hash=str(self._context.content_hash()),
            pricing_version=self._gateway.pricing.version,
            currency=self._gateway.pricing.currency,
            calls=tuple(self._calls),
            circuits_opened=tuple(dict.fromkeys(self._circuits)),
            streams_abandoned=tuple(dict.fromkeys(self._abandoned)),
        )


class ModelGateway:
    """The only thing that calls a provider.

    .. code-block:: text

        redact ─ cache ─ residency ─ breaker ─ retry ─ failover ─ price
                   │        │          │        │        │         │
                   │        │          │        │        │         versioned
                   │        │          │        │        │         table, pinned
                   │        │          │        │        └─ a DIFFERENT provider,
                   │        │          │        │            recorded as a fact
                   │        │          │        └─ same provider, backoff + jitter
                   │        │          └─ fast-fail a degraded provider
                   │        └─ filtered BEFORE any provider is asked
                   └─ exact always; semantic only if a domain enabled it

    **Residency is read from the context**, not taken as a constructor argument. The
    router already refuses to let a caller skip the filter; sourcing the regions from
    :attr:`~attest.kernel.context.TenantBinding.residency_regions` closes the other
    half — the constraint that filtered the providers is the same one the attestation
    records, so the record cannot claim a boundary that was never applied.

    **Retry before failover, and the difference matters.** A transient 503 answered by
    retrying the primary is an outage survived; the same 503 answered by moving to a
    fallback model is a materially different decision that replay must know about.

    **The gateway measures; it does not decide.** Budget enforcement lives in the
    obligation layer — see ``docs/capabilities/authority.md`` and
    :class:`~attest.capabilities.authority.Budget`. Pricing a call here and *also*
    refusing on a ceiling here would put spend authority in two places, and the second
    one would drift.
    """

    __slots__ = (
        "_breaker",
        "_cache",
        "_clock",
        "_jitter",
        "_providers",
        "_residency_floor",
        "_retry",
        "_semantic",
        "_sleep",
        "_tier_order",
        "_total_deadline",
        "pricing",
    )

    def __init__(
        self,
        providers: Sequence[LLMProvider],
        *,
        pricing: PricingTable,
        clock: Clock,
        retry: RetryPolicy | None = None,
        breaker: CircuitBreaker | None = None,
        cache: ExactCache | None = None,
        semantic: SemanticCache | None = None,
        sleep: Callable[[float], None] | None = None,
        jitter: Callable[[], float] | None = None,
        tier_order: Sequence[str] = (),
        total_deadline: timedelta | None = None,
        residency_floor: frozenset[str] = frozenset(),
    ) -> None:
        """Assemble the gateway.

        ``semantic`` has no default implementation on purpose: a near-miss cached
        answer is a domain's decision, and one passed in is the domain making it.

        ``sleep`` and ``jitter`` are injected so a retry is reproducible in a test and
        in a replay, rather than depending on a wall clock and a global RNG.

        ``tier_order`` is the deployment's own capability ordering, weakest first, and it
        is empty by default: a deployment that does not model tiers gets exactly the
        previous behaviour. Naming the tiers here would be domain knowledge, so the
        package only ever compares positions in a list somebody else supplied.

        ``total_deadline`` bounds the WHOLE chain in wall-clock terms, and is ``None``
        by default. Without one the timeouts compound: an SDK's own retries, times
        :class:`RetryPolicy`'s attempts, times every candidate. A single logical call
        can then hold a provider for minutes while every layer believes it is being
        patient. Survivable on a worker, not on a request thread, and the gateway
        cannot tell which it is on - so the deployment says. Read from ``clock``, whose
        contract already requires monotonicity within a run, rather than from
        ``time.monotonic()``: that keeps a deadline reproducible in a replay instead of
        making it the ambient time this package bans everywhere else.

        ``residency_floor`` is the DEPLOYMENT's permitted regions, which a tenant
        binding may narrow and may not widen. Empty by default, which is the previous
        behaviour: residency came from the binding alone, and a binding that left it
        empty - the default - was unconstrained. An air-gapped deployment's whole
        control was therefore held by whoever assembled the binding, with nothing above
        them able to guarantee it.
        """
        if not providers:
            raise ConfigurationError("a ModelGateway needs at least one provider")
        self._providers = tuple(providers)
        self.pricing = pricing
        self._clock = clock
        self._retry = retry or RetryPolicy()
        self._breaker = breaker or CircuitBreaker()
        self._cache = ExactCache() if cache is None else cache
        self._semantic = semantic
        self._sleep = sleep if sleep is not None else time.sleep
        self._jitter = jitter if jitter is not None else self._default_jitter
        self._tier_order = tuple(tier_order)
        self._total_deadline = total_deadline
        self._residency_floor = residency_floor

    @staticmethod
    def _new_idempotency_key() -> str:
        """A fresh key per logical call. Random by construction - see `call`."""
        return uuid4().hex

    @staticmethod
    def _default_jitter() -> float:
        """Herd avoidance, not secrecy.

        S311 flags ``random`` for cryptographic use. This value only decides how long
        to wait, and a predictable retry delay costs an attacker nothing — while a
        *fixed* one costs the recovering provider everything, because every client
        that hit the outage comes back at the same instant.
        """
        value: float = random.random()  # noqa: S311 # nosec B311
        return value

    @staticmethod
    def _returned(provider: LLMProvider, stop: StopIteration) -> CompletionResponse:
        """The response a provider's stream returned, or a refusal to guess at one.

        A generator that yields text and returns nothing is a model call with no token
        counts, and a call with no token counts cannot be priced. The alternative is a
        zero in the cost record, which this package refuses for the same reason
        :meth:`PricingTable.price` refuses it: a zero meaning free and a zero meaning
        "we never found out" read identically once written.
        """
        response = stop.value
        if not isinstance(response, CompletionResponse):
            raise ConfigurationError(
                f"provider {provider.spec.name!r} streamed but its generator returned "
                f"{type(response).__name__} rather than a CompletionResponse. The return "
                f"value carries the token counts, and without them the call cannot be "
                f"priced."
            )
        return response

    def _deadline_from(self, started: datetime) -> datetime | None:
        """When this chain must give up, or ``None`` where the deployment set no budget."""
        return None if self._total_deadline is None else started + self._total_deadline

    def _expired(self, deadline: datetime | None) -> bool:
        return deadline is not None and self._clock.now() >= deadline

    def _chain_exhausted(
        self,
        context: ExecutionContext,
        failures: Sequence[str],
        *,
        out_of_time: bool,
    ) -> ResidencyRefused:
        """The refusal at the end of the chain, saying which way it ended.

        Two different remedies. "Every provider failed" sends an operator to look at
        routing; "the budget ran out" means the routing was fine and the budget was the
        constraint, and reporting the second as the first has somebody debugging a
        healthy provider list.
        """
        regions = sorted(context.binding.residency_regions) or "unconstrained"
        if out_of_time:
            return ResidencyRefused(
                Refusal(
                    reason=RefusalReason("deadline_exceeded"),
                    detail=(
                        f"the failover chain exceeded its {self._total_deadline} budget "
                        f"before any provider answered: {'; '.join(failures)}. Refusing "
                        f"rather than holding the caller for the sum of every timeout."
                    ),
                )
            )
        return ResidencyRefused(
            Refusal(
                reason=RefusalReason("evidence_source_unreachable"),
                detail=(
                    f"every provider permitted within residency {regions} failed: "
                    f"{'; '.join(failures)}. Refusing rather than failing over out of "
                    f"region."
                ),
            )
        )

    def session(self, context: ExecutionContext) -> ModelSession:
        """A gateway scoped to one run, accumulating what it spends."""
        return ModelSession(self, context)

    def router_for(self, context: ExecutionContext) -> ProviderRouter:
        """The router this run's binding implies. Regions are never a parameter.

        Zero retention comes from the binding too. It is a tenant's contractual
        position rather than a process-wide one, and `ProviderRouter` has honoured it
        since it was written - nothing passed it, so the one flag that keeps a tenant's
        text off a retaining provider could not be switched on through the only
        supported way to reach a provider.
        """
        return ProviderRouter(
            permitted_regions=self._regions_for(context),
            zero_retention_required=context.binding.zero_retention_required,
            tier_order=self._tier_order,
        )

    def _regions_for(self, context: ExecutionContext) -> frozenset[str]:
        """The binding's regions, narrowed by the deployment floor.

        A binding could previously widen residency to anywhere by leaving it empty, and
        empty is its default - so residency was set entirely by whoever assembled the
        binding, with nothing above them. For an air-gapped deployment that is the whole
        control, held by the layer least able to guarantee it.

        Note the asymmetry this closes. Everywhere else in this module absence is
        restrictive on purpose: an undeclared capability is absent, an undeclared tier
        ranks lowest. Residency alone read absence as permission.

        The intersection, not the union: a tenant may narrow the deployment's list and
        may not reach outside it.

        An empty intersection **refuses here** rather than being passed down. Empty means
        unconstrained to `select`, so returning it would turn "this tenant asked for a
        region the deployment forbids" into "this tenant asked for nothing in particular"
        and serve the call from anywhere - inverting the control at the exact moment it
        was doing its job.
        """
        binding = context.binding.residency_regions
        if not self._residency_floor:
            return binding
        if not binding:
            return self._residency_floor
        permitted = self._residency_floor & binding
        if not permitted:
            raise ResidencyRefused(
                Refusal(
                    reason=RefusalReason("residency_unavailable"),
                    detail=(
                        f"tenant {context.identity.tenant!r} is bound to "
                        f"{sorted(binding)}, and this deployment permits only "
                        f"{sorted(self._residency_floor)}. A binding may narrow the "
                        f"deployment's regions and may not reach outside them."
                    ),
                )
            )
        return permitted

    def call(
        self,
        request: CompletionRequest,
        *,
        context: ExecutionContext,
        on_circuit_open: Callable[[str], None] | None = None,
    ) -> tuple[CompletionResponse, ModelCall]:
        """Serve one request, or refuse. Never leaves the residency boundary."""
        eligible = self.router_for(context).select(
            [provider.spec for provider in self._providers],
            requires_tools=request.requires_tools,
            requires=request.requires,
            min_tier=request.min_tier,
        )
        permitted = {spec.name for spec in eligible}
        candidates = [p for p in self._providers if p.spec.name in permitted]

        cached = self._from_cache(request, candidates, context=context)
        if cached is not None:
            return cached

        # ONE key for this logical call, minted here and carried by every attempt below -
        # retries of one provider and failovers to the next.
        #
        # The failure it closes: a provider receives the request, completes it, bills it, and
        # the response is lost to a timeout. Without a key the retry is a SECOND completion the
        # customer pays for, and at failover it happens again. The cache cannot help - it is
        # written from a response, and the whole problem is the call that never returned one.
        #
        # RANDOM, not derived from the request, and that distinction is the easy thing to get
        # wrong. `ExactCache.key()` is content-derived and correct to be: a cache WANTS two
        # identical requests to collide. An idempotency key must not, or asking the same
        # question twice on purpose is served one answer twice and billed once.
        request = replace(request, idempotency_key=self._new_idempotency_key())

        now = self._clock.now()
        deadline = self._deadline_from(now)
        attempted: list[str] = []
        failures: list[str] = []
        for index, provider in enumerate(candidates):
            if self._expired(deadline):
                failures.append("deadline exceeded before the chain was exhausted")
                break
            if not self._breaker.allows(provider.spec.name, now=now):
                failures.append(f"{provider.spec.name}: circuit open")
                continue
            response = self._attempt(
                provider,
                request,
                failures,
                now=now,
                deadline=deadline,
                on_circuit_open=on_circuit_open,
            )
            if response is None:
                attempted.append(provider.spec.name)
                continue

            self._breaker.record_success(provider.spec.name)
            self._store(request, response, provider, context=context)
            call = self._price(
                response, provider, request, failover=index > 0, attempted=attempted, cached=False
            )
            return response, call

        raise self._chain_exhausted(context, failures, out_of_time=self._expired(deadline))

    def stream(
        self,
        request: CompletionRequest,
        *,
        context: ExecutionContext,
        on_circuit_open: Callable[[str], None] | None = None,
        on_abandoned: Callable[[str], None] | None = None,
    ) -> Generator[str, None, ModelCall]:
        """Serve one request as tokens, or refuse. Same rules as :meth:`call`.

        Residency, tier, features, the breaker, the retry policy, the deadline, the
        idempotency key and the cache all apply exactly as they do to a completion. That
        is the whole point of the method existing: a call site that could not stream
        through the gateway streamed around it, and every property above went back to
        being something that call site remembered on its own.

        **Failover happens only before the first chunk.** Once bytes have reached the
        reader, moving to another provider means re-emitting from the top, and a reader
        who watches the answer restart is worse served than one who sees it stop. After
        the first chunk a failure is a :class:`StreamInterrupted` carrying what was
        already shown.
        """
        eligible = self.router_for(context).select(
            [provider.spec for provider in self._providers],
            requires_tools=request.requires_tools,
            requires=request.requires | {Feature.STREAMING},
            min_tier=request.min_tier,
        )
        permitted = {spec.name for spec in eligible}
        candidates = [p for p in self._providers if p.spec.name in permitted]

        # A cached answer arrives whole. Served as one chunk rather than skipped, so a
        # streamed call cannot quietly bypass the tenant-partitioned cache that every
        # completed call goes through.
        cached = self._from_cache(request, candidates, context=context)
        if cached is not None:
            response, call = cached
            yield response.text
            return call

        request = replace(request, idempotency_key=self._new_idempotency_key())
        now = self._clock.now()
        deadline = self._deadline_from(now)
        attempted: list[str] = []
        failures: list[str] = []

        for index, provider in enumerate(candidates):
            if self._expired(deadline):
                failures.append("deadline exceeded before the chain was exhausted")
                break
            if not self._breaker.allows(provider.spec.name, now=now):
                failures.append(f"{provider.spec.name}: circuit open")
                continue
            if not isinstance(provider, StreamingProvider):
                # Unreachable while the STREAMING feature filter above holds, and checked
                # anyway: the filter reads a spec the provider supplied about itself.
                failures.append(f"{provider.spec.name}: declares streaming but has none")
                continue

            for attempt in range(1, self._retry.attempts + 1):
                seen: list[str] = []
                done: CompletionResponse | None = None
                source = provider.stream(request)
                try:
                    while done is None:
                        try:
                            chunk = next(source)
                        except StopIteration as stop:
                            done = self._returned(provider, stop)
                        else:
                            seen.append(chunk)
                            yield chunk
                except GeneratorExit:
                    # The reader walked away. The provider is still generating and still
                    # billing, and nobody in this process will learn how much - so it is
                    # recorded as an abandonment rather than as a zero-cost call.
                    source.close()
                    if on_abandoned is not None:
                        on_abandoned(provider.spec.name)
                    raise
                except ConfigurationError:
                    # A backend wired wrongly is not a backend having a bad minute.
                    # Failing over would try the next provider, and the next deployment
                    # that streams would meet the same wiring with the same silence.
                    source.close()
                    raise
                except Exception as exc:  # a provider failure is a failover, not a crash
                    source.close()
                    failures.append(f"{provider.spec.name}: {type(exc).__name__}")
                    if seen:
                        raise StreamInterrupted(
                            Refusal(
                                reason=RefusalReason("stream_interrupted"),
                                detail=(
                                    f"{provider.spec.name} failed with "
                                    f"{type(exc).__name__} after "
                                    f"{len(seen)} chunks had already been read. Not "
                                    f"failing over: the reader would see the answer "
                                    f"begin again."
                                ),
                            ),
                            partial="".join(seen),
                        ) from exc
                    if attempt < self._retry.attempts and not self._expired(deadline):
                        self._sleep(self._retry.delay(attempt, jitter=self._jitter()))
                        continue
                    if (
                        self._breaker.record_failure(provider.spec.name, now=now)
                        and on_circuit_open is not None
                    ):
                        on_circuit_open(provider.spec.name)
                    break

                self._breaker.record_success(provider.spec.name)
                self._store(request, done, provider, context=context)
                return self._price(
                    done,
                    provider,
                    request,
                    failover=index > 0,
                    attempted=attempted,
                    cached=False,
                )
            attempted.append(provider.spec.name)

        raise self._chain_exhausted(context, failures, out_of_time=self._expired(deadline))

    def _attempt(
        self,
        provider: LLMProvider,
        request: CompletionRequest,
        failures: list[str],
        *,
        now: datetime,
        deadline: datetime | None = None,
        on_circuit_open: Callable[[str], None] | None = None,
    ) -> CompletionResponse | None:
        """Try one provider, retrying it before giving up on it.

        Retrying the same provider is not the same as failing over to another, and
        conflating them is how a blip gets recorded as a fallback decision.
        """
        for attempt in range(1, self._retry.attempts + 1):
            try:
                return provider.complete(request)
            except Exception as exc:  # a provider failure is a failover, not a crash
                # The exception TYPE and the provider, never the message. Vendor SDK
                # exceptions routinely carry the request URL, echoed headers and
                # occasionally an Authorization prefix, and this string reaches the
                # ResidencyRefused detail, which becomes a Refusal on the sealed
                # attestation — where audit.md forbids credentials "in any form". The
                # body belongs in the host's logs, at a level that is not chained.
                failures.append(f"{provider.spec.name}: {type(exc).__name__}")
                # The deadline is checked HERE as well as in `call`, because the sleep is
                # where the time goes. Backing off past the budget and then discovering it
                # has passed spends the whole budget on waiting.
                if attempt < self._retry.attempts and not self._expired(deadline):
                    self._sleep(self._retry.delay(attempt, jitter=self._jitter()))
                    continue
                if (
                    self._breaker.record_failure(provider.spec.name, now=now)
                    and on_circuit_open is not None
                ):
                    on_circuit_open(provider.spec.name)
        return None

    def _from_cache(
        self,
        request: CompletionRequest,
        candidates: Sequence[LLMProvider],
        *,
        context: ExecutionContext,
    ) -> tuple[CompletionResponse, ModelCall] | None:
        """An exact hit, or a semantic one where a domain enabled it.

        A cache hit is priced at zero and **recorded as a hit**, not passed off as a
        fresh call: an attestation that showed a model call which never happened would
        misstate both the cost and where the answer came from.
        """
        if not request.cacheable or not candidates:
            return None
        provider = candidates[0]
        for response in (
            self._cache.get(request, model_id=provider.spec.model_id, context=context),
            None
            if self._semantic is None
            else self._semantic.lookup(request, model_id=provider.spec.model_id, context=context),
        ):
            if response is not None:
                return response, self._price(
                    response, provider, request, failover=False, attempted=(), cached=True
                )
        return None

    def _store(
        self,
        request: CompletionRequest,
        response: CompletionResponse,
        provider: LLMProvider,
        *,
        context: ExecutionContext,
    ) -> None:
        if not request.cacheable:
            return
        self._cache.put(
            request,
            response,
            model_id=provider.spec.model_id,
            region=provider.spec.region,
            context=context,
        )
        if self._semantic is not None:
            self._semantic.store(request, response, model_id=provider.spec.model_id)

    def _price(
        self,
        response: CompletionResponse,
        provider: LLMProvider,
        request: CompletionRequest,
        *,
        failover: bool,
        attempted: Sequence[str],
        cached: bool,
    ) -> ModelCall:
        cached_tokens = int(response.metadata.get("cached_input_tokens", "0") or 0)
        amount = (
            "0"
            if cached
            else self.pricing.price(
                response.model_id,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                cached=cached_tokens,
            )
        )
        return ModelCall(
            provider=response.provider,
            model_id=response.model_id,
            family=response.family,
            region=provider.spec.region,
            prompt_hash=request.prompt_hash,
            input_tokens=0 if cached else response.input_tokens,
            output_tokens=0 if cached else response.output_tokens,
            cached_tokens=cached_tokens,
            amount=amount,
            failover=failover,
            attempted=tuple(attempted),
            served_from_cache=cached,
        )
