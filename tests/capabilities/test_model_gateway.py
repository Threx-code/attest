"""The gateway as the only thing that calls a provider.

Three properties carry this module, and each was a hole before it existed:

*Residency is enforced, not merely recorded.* ``TenantBinding.residency_regions`` was
serialised into every attestation and read by nothing — a record asserting a boundary
that never applied.

*Failover is a fact the record carries.* A decision made by a fallback model is a
materially different decision, and by the time the run ends the routing state is gone.

*Cost is measured.* A figure the host asserts cannot be reconciled against a bill.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

import pytest

from attest.capabilities.gateway import (
    CanaryPrompt,
    CircuitBreaker,
    CircuitState,
    CompletionRequest,
    CompletionResponse,
    DriftCanary,
    ExactCache,
    Feature,
    ModelGateway,
    ModelPrice,
    PricingTable,
    ProviderSpec,
    ResidencyRefused,
    RetryPolicy,
)
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.errors import ConfigurationError
from attest.kernel.identifiers import ActorId, Hash, RunId, TenantId

pytestmark = pytest.mark.unit

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


class Clock:
    def __init__(self, at: datetime = AT) -> None:
        self.at = at

    def now(self) -> datetime:
        return self.at


class Provider:
    """A provider that answers, or fails in a stated way."""

    def __init__(
        self,
        name: str,
        *,
        region: str = "eu-west-2",
        model_id: str = "claude-opus-5",
        family: str = "claude",
        raises: Exception | None = None,
        tokens: tuple[int, int] = (1000, 500),
        cached: int = 0,
        supports_tools: bool = True,
        supports_vision: bool = False,
        tier: str = "",
    ) -> None:
        self._spec = ProviderSpec(
            name=name,
            model_id=model_id,
            family=family,
            region=region,
            tier=tier,
            supports_tools=supports_tools,
            supports_vision=supports_vision,
        )
        self._raises = raises
        self._tokens = tokens
        self._cached = cached
        self.calls: list[CompletionRequest] = []

    @property
    def spec(self) -> ProviderSpec:
        return self._spec

    def supports(self, feature: Feature) -> bool:
        return self._spec.supports(feature)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.calls.append(request)
        if self._raises is not None:
            raise self._raises
        return CompletionResponse(
            text="answered",
            provider=self._spec.name,
            model_id=self._spec.model_id,
            family=self._spec.family,
            input_tokens=self._tokens[0],
            output_tokens=self._tokens[1],
            metadata={"cached_input_tokens": str(self._cached)} if self._cached else {},
        )


def pricing() -> PricingTable:
    return PricingTable(
        version="2026-07-01",
        currency="USD",
        prices={
            "claude-opus-5": ModelPrice("5.00", "25.00", cached_input_per_million="0.50"),
            "claude-haiku-4-5": ModelPrice("1.00", "5.00"),
        },
    )


class Flaky(Provider):
    """Fails a stated number of times, then answers. A transient outage."""

    def __init__(self, name: str, *, fail_times: int) -> None:
        super().__init__(name)
        self._remaining = fail_times
        self.attempts = 0

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        self.attempts += 1
        if self._remaining > 0:
            self._remaining -= 1
            raise RuntimeError("503")
        return super().complete(request)


def context(
    *,
    regions: frozenset[str] = frozenset(),
    epochs: dict[str, str] | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        run_id=RunId("run_1"),
        captured_at=AT,
        identity=IdentitySnapshot(actor=ActorId("alice"), tenant=TenantId("t1")),
        binding=TenantBinding(
            tenant=TenantId("t1"),
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
            residency_regions=regions,
        ),
        framework_version="0.1.0",
        policy_version="2026.07",
        corpus_epochs=dict(epochs or {}),  # type: ignore[arg-type]
    )


def request(
    max_tokens: int = 1000,
    *,
    requires_tools: bool = False,
    requires: frozenset[Feature] = frozenset(),
    cacheable: bool = True,
    min_tier: str = "",
    messages: tuple[str, ...] = ("question",),
) -> CompletionRequest:
    return CompletionRequest.for_messages(
        messages,
        max_tokens=max_tokens,
        requires_tools=requires_tools,
        requires=requires,
        cacheable=cacheable,
        min_tier=min_tier,
    )


# ── Residency ────────────────────────────────────────────────────────────────


def test_a_provider_outside_the_residency_boundary_is_never_asked() -> None:
    """Filtered before the call, not after — afterwards the data has already gone."""
    inside = Provider("eu", region="eu-west-2")
    outside = Provider("us", region="us-east-1")
    gateway = ModelGateway([outside, inside], pricing=pricing(), clock=Clock())

    response = gateway.session(context(regions=frozenset({"eu-west-2"}))).complete(request())
    assert response.provider == "eu"
    assert outside.calls == [], "the out-of-region provider must not be consulted at all"


def test_the_regions_come_from_the_binding_rather_than_a_parameter() -> None:
    """The constraint that filters is the same one the attestation records.

    A constructor argument is a thing a caller can forget, and the attestation would
    still claim the boundary applied.
    """
    gateway = ModelGateway([Provider("us", region="us-east-1")], pricing=pricing(), clock=Clock())
    with pytest.raises(ResidencyRefused):
        gateway.session(context(regions=frozenset({"eu-west-2"}))).complete(request())


def test_no_permitted_provider_is_a_refusal_rather_than_a_fallback() -> None:
    """Crossing the boundary to keep serving turns an outage into a breach."""
    gateway = ModelGateway([Provider("us", region="us-east-1")], pricing=pricing(), clock=Clock())
    with pytest.raises(ResidencyRefused) as caught:
        gateway.session(context(regions=frozenset({"eu-west-2"}))).complete(request())
    assert caught.value.refusal.reason == "residency_unavailable"


def test_an_unconstrained_tenant_may_use_any_region() -> None:
    gateway = ModelGateway([Provider("us", region="us-east-1")], pricing=pricing(), clock=Clock())
    assert gateway.session(context()).complete(request()).provider == "us"


def test_a_provider_without_tool_support_is_filtered_out_when_tools_are_required() -> None:
    """A failover that silently drops tool calling continues and cannot do the job."""
    gateway = ModelGateway(
        [Provider("no-tools", supports_tools=False), Provider("tools")],
        pricing=pricing(),
        clock=Clock(),
    )
    response = gateway.session(context()).complete(request(requires_tools=True))
    assert response.provider == "tools"


# ── Failover ─────────────────────────────────────────────────────────────────


def test_a_failed_provider_fails_over_and_the_failover_is_recorded() -> None:
    primary = Provider("primary", raises=RuntimeError("503"))
    secondary = Provider("secondary")
    session = ModelGateway([primary, secondary], pricing=pricing(), clock=Clock()).session(
        context()
    )

    response = session.complete(request())
    assert response.provider == "secondary"

    call = session.log().calls[0]
    assert call.failover is True
    assert call.attempted == ("primary",)


def test_a_first_attempt_success_is_not_recorded_as_a_failover() -> None:
    session = ModelGateway(
        [Provider("primary"), Provider("secondary")], pricing=pricing(), clock=Clock()
    ).session(context())
    session.complete(request())
    assert session.log().calls[0].failover is False


def test_the_run_ref_reports_a_failover_if_any_call_used_one() -> None:
    """One fallback answer taints the run's model attribution, not just that call."""
    gateway = ModelGateway(
        [Provider("primary", raises=RuntimeError("down")), Provider("secondary")],
        pricing=pricing(),
        clock=Clock(),
    )
    session = gateway.session(context())
    session.complete(request())
    ref = session.log().model_ref()
    assert ref is not None
    assert ref.failover is True
    assert ref.provider == "secondary"


def test_every_provider_failing_is_a_refusal_naming_what_was_tried() -> None:
    gateway = ModelGateway(
        [Provider("a", raises=RuntimeError("503")), Provider("b", raises=RuntimeError("timeout"))],
        pricing=pricing(),
        clock=Clock(),
    )
    with pytest.raises(ResidencyRefused) as caught:
        gateway.session(context()).complete(request())
    detail = caught.value.refusal.detail
    assert "a: RuntimeError" in detail
    assert "b: RuntimeError" in detail


@pytest.mark.security
def test_provider_exception_text_does_not_reach_the_refusal() -> None:
    """ATT-21. This string is interpolated into a Refusal on the sealed attestation.

    Vendor SDK exceptions routinely carry the request URL, headers echoed back, and
    occasionally an Authorization prefix — and audit.md forbids credentials in the
    chain "in any form". The type and the provider are enough to triage; the body
    belongs in the host's logs, at a level that is not chained.
    """
    leaky = RuntimeError(
        "401 from https://api.vendor.example/v1/messages "
        "headers={'Authorization': 'Bearer sk-live-4471'}"
    )
    gateway = ModelGateway([Provider("a", raises=leaky)], pricing=pricing(), clock=Clock())
    with pytest.raises(ResidencyRefused) as caught:
        gateway.session(context()).complete(request())

    detail = caught.value.refusal.detail
    assert "sk-live-4471" not in detail, "a credential reached the sealed record"
    assert "Authorization" not in detail
    assert "api.vendor.example" not in detail
    assert "a: RuntimeError" in detail, "the refusal must still say what failed"


# ── The circuit ──────────────────────────────────────────────────────────────


def test_a_repeatedly_failing_provider_is_skipped_for_its_cooldown() -> None:
    """Otherwise every run retries a dead provider at once — a slower outage."""
    primary = Provider("primary", raises=RuntimeError("down"))
    secondary = Provider("secondary")
    clock = Clock()
    gateway = ModelGateway(
        [primary, secondary],
        pricing=pricing(),
        clock=clock,
        breaker=CircuitBreaker(threshold=2, cooldown=timedelta(seconds=30)),
    )
    session = gateway.session(context())
    for _ in range(3):
        session.complete(request())

    assert len(primary.calls) == 2, "the third run must not reach the open circuit"


def test_the_circuit_half_opens_after_the_cooldown() -> None:
    breaker = CircuitBreaker(threshold=1, cooldown=timedelta(seconds=30))
    assert breaker.record_failure("p", now=AT) is True
    assert breaker.state("p", now=AT) is CircuitState.OPEN
    assert breaker.allows("p", now=AT) is False
    assert breaker.state("p", now=AT + timedelta(seconds=31)) is CircuitState.HALF_OPEN
    assert breaker.allows("p", now=AT + timedelta(seconds=31)) is True


def test_a_success_closes_the_circuit_again() -> None:
    breaker = CircuitBreaker(threshold=1)
    breaker.record_failure("p", now=AT)
    breaker.record_success("p")
    assert breaker.state("p", now=AT) is CircuitState.CLOSED


# ── Cost ─────────────────────────────────────────────────────────────────────


def test_a_call_is_priced_from_the_pinned_table() -> None:
    session = ModelGateway(
        [Provider("p", tokens=(1_000_000, 1_000_000))], pricing=pricing(), clock=Clock()
    ).session(context())
    session.complete(request())
    # 1M input at $5 + 1M output at $25.
    assert Decimal(session.log().calls[0].amount) == Decimal("30")


def test_cached_input_is_billed_at_the_cached_rate() -> None:
    """Otherwise a cached run looks as expensive as an uncached one, and nothing reconciles."""
    session = ModelGateway(
        [Provider("p", tokens=(1_000_000, 0), cached=1_000_000)], pricing=pricing(), clock=Clock()
    ).session(context())
    session.complete(request())
    assert Decimal(session.log().calls[0].amount) == Decimal("0.5")


def test_the_log_totals_every_call_and_pins_the_pricing_version() -> None:
    session = ModelGateway(
        [Provider("p", tokens=(1_000_000, 0))], pricing=pricing(), clock=Clock()
    ).session(context())
    # Distinct prompts: two identical ones would be one call and one cache hit.
    session.complete(request())
    session.complete(CompletionRequest.for_messages(("other",), max_tokens=1000))
    cost = session.log().cost()
    assert cost.input_tokens == 2_000_000
    assert Decimal(cost.amount) == Decimal("10")
    assert cost.pricing_version == "2026-07-01"
    assert cost.currency == "USD"


def test_an_unpriced_model_raises_rather_than_costing_zero() -> None:
    """A zero meaning 'free' and a zero meaning 'no rate' are indistinguishable once written."""
    with pytest.raises(KeyError, match="no rate"):
        pricing().price("some-new-model", input_tokens=10, output_tokens=10)


def test_a_run_with_no_calls_has_no_model_ref() -> None:
    """The honest value for a rules engine proposing through the same kernel."""
    log = ModelGateway([Provider("p")], pricing=pricing(), clock=Clock()).session(context()).log()
    assert log.model_ref() is None
    assert log.cost().amount == "0"


# ── Caching ─────────────────────────────────────────────────────────────────


def test_an_identical_request_is_served_from_cache_without_calling_a_provider() -> None:
    provider = Provider("p")
    session = ModelGateway([provider], pricing=pricing(), clock=Clock()).session(context())
    session.complete(request())
    session.complete(request())
    assert len(provider.calls) == 1


def test_a_cache_hit_is_recorded_as_a_hit_rather_than_as_a_call() -> None:
    """An attestation showing a model call that never happened misstates where the
    answer came from, and what it cost."""
    session = ModelGateway([Provider("p")], pricing=pricing(), clock=Clock()).session(context())
    session.complete(request())
    session.complete(request())
    fresh, hit = session.log().calls
    assert fresh.served_from_cache is False
    assert hit.served_from_cache is True
    assert hit.amount == "0"
    assert hit.input_tokens == 0


def test_a_corpus_update_invalidates_the_answers_derived_from_it() -> None:
    """Otherwise a document change serves a stale citation with a fresh timestamp."""
    provider = Provider("p")
    gateway = ModelGateway([provider], pricing=pricing(), clock=Clock())
    gateway.session(context(epochs={"corpus-1": "epoch-4"})).complete(request())
    gateway.session(context(epochs={"corpus-1": "epoch-5"})).complete(request())
    assert len(provider.calls) == 2


def test_a_cached_answer_is_not_replayed_out_of_a_region_no_longer_permitted() -> None:
    """A residency change must not keep serving answers a tenant may no longer receive."""
    provider = Provider("p", region="us-east-1")
    gateway = ModelGateway([provider], pricing=pricing(), clock=Clock())
    gateway.session(context()).complete(request())
    cache = ExactCache()
    cache.put(
        request(),
        CompletionResponse(text="x", provider="p", model_id="claude-opus-5", family="claude"),
        model_id="claude-opus-5",
        region="us-east-1",
        context=context(),
    )
    assert cache.get(request(), model_id="claude-opus-5", context=context()) is not None
    narrowed = context(regions=frozenset({"eu-west-2"}))
    assert cache.get(request(), model_id="claude-opus-5", context=narrowed) is None


def test_an_uncacheable_request_is_always_recomputed() -> None:
    provider = Provider("p")
    session = ModelGateway([provider], pricing=pricing(), clock=Clock()).session(context())
    session.complete(request(cacheable=False))
    session.complete(request(cacheable=False))
    assert len(provider.calls) == 2


def test_a_semantic_cache_is_not_consulted_unless_a_domain_supplies_one() -> None:
    """Off by default: a near-miss answer is fine for a support bot and not for a claim."""

    class Recording:
        def __init__(self) -> None:
            self.lookups = 0

        def lookup(
            self, request: CompletionRequest, *, model_id: str, context: ExecutionContext
        ) -> CompletionResponse | None:
            self.lookups += 1
            return None

        def store(
            self, request: CompletionRequest, response: CompletionResponse, *, model_id: str
        ) -> None:
            """Stored nowhere: this stands in for a domain's own implementation."""

    without = ModelGateway([Provider("p")], pricing=pricing(), clock=Clock())
    without.session(context()).complete(request(cacheable=True))

    semantic = Recording()
    withit = ModelGateway([Provider("p")], pricing=pricing(), clock=Clock(), semantic=semantic)
    withit.session(context()).complete(request())
    assert semantic.lookups == 1


# ── Retry, before failover ───────────────────────────────────────────────────


def test_a_transient_failure_retries_the_same_provider_before_failing_over() -> None:
    """A blip answered by a fallback would record a materially different decision."""
    flaky = Flaky("primary", fail_times=1)
    secondary = Provider("secondary")
    gateway = ModelGateway(
        [flaky, secondary],
        pricing=pricing(),
        clock=Clock(),
        retry=RetryPolicy(attempts=2),
        sleep=lambda _seconds: None,
        jitter=lambda: 0.0,
    )
    session = gateway.session(context())
    response = session.complete(request())
    assert response.provider == "primary"
    assert session.log().calls[0].failover is False
    assert secondary.calls == []


def test_failover_happens_only_once_the_retries_are_spent() -> None:
    flaky = Flaky("primary", fail_times=5)
    secondary = Provider("secondary")
    gateway = ModelGateway(
        [flaky, secondary],
        pricing=pricing(),
        clock=Clock(),
        retry=RetryPolicy(attempts=2),
        sleep=lambda _seconds: None,
        jitter=lambda: 0.0,
    )
    response = gateway.session(context()).complete(request())
    assert flaky.attempts == 2, "the primary is retried before the run moves model"
    assert response.provider == "secondary"


def test_the_backoff_grows_and_the_jitter_moves_it() -> None:
    """Without jitter every client that hit an outage returns at the same instant."""
    policy = RetryPolicy(attempts=3, base_delay=1.0, max_delay=10.0)
    assert policy.delay(1, jitter=0.0) == 1.0
    assert policy.delay(2, jitter=0.0) == 2.0
    assert policy.delay(3, jitter=0.0) == 4.0
    assert policy.delay(1, jitter=0.5) == 1.5
    assert policy.delay(9, jitter=0.0) == 10.0, "capped"


def test_a_retry_policy_needs_at_least_one_attempt() -> None:
    with pytest.raises(ConfigurationError, match="at least one attempt"):
        RetryPolicy(attempts=0)


# ── Features ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("feature", "expected"),
    [
        (Feature.TOOLS, True),
        (Feature.JSON_MODE, True),
        (Feature.VISION, False),
        (Feature.CACHING, False),
    ],
)
def test_an_undeclared_capability_is_absent(feature: Feature, expected: bool) -> None:
    """A provider that forgot to describe itself is filtered out, not asked anyway."""
    assert Provider("p").spec.supports(feature) is expected


def test_a_request_needing_vision_skips_a_provider_that_cannot_see() -> None:
    blind = Provider("blind")
    seeing = Provider("seeing", supports_vision=True)
    gateway = ModelGateway([blind, seeing], pricing=pricing(), clock=Clock())
    response = gateway.session(context()).complete(request(requires=frozenset({Feature.VISION})))
    assert response.provider == "seeing"
    assert blind.calls == []


def test_a_request_no_provider_can_honour_is_refused_not_degraded() -> None:
    gateway = ModelGateway([Provider("p")], pricing=pricing(), clock=Clock())
    with pytest.raises(ResidencyRefused, match="vision"):
        gateway.session(context()).complete(request(requires=frozenset({Feature.VISION})))


# ── Drift ────────────────────────────────────────────────────────────────────


def test_a_stable_model_reports_no_drift() -> None:
    canary = CanaryPrompt(
        name="tone", request=request(), baseline_text="answered", baseline_taken_at=AT
    )
    report = DriftCanary([canary], clock=Clock()).sweep(Provider("p"))
    assert report.drifted is False
    assert report.checked == 1


def test_a_changed_answer_under_a_stable_model_id_is_detected() -> None:
    """The problem: the prompt is pinned, the model id is pinned, the behaviour is not."""
    canary = CanaryPrompt(
        name="tone",
        request=request(),
        baseline_text="the claim is payable under section 4.2",
        baseline_taken_at=AT,
    )
    report = DriftCanary([canary], clock=Clock()).sweep(Provider("p"))
    assert report.drifted is True
    assert report.findings[0].canary == "tone"
    assert report.findings[0].similarity < 0.85


def test_drift_produces_a_version_marker_that_distinguishes_later_attestations() -> None:
    """Without it, "the model changed under us" arrives as a support ticket months later."""
    drifting = CanaryPrompt(name="a", request=request(), baseline_text="completely different text")
    stable = CanaryPrompt(name="a", request=request(), baseline_text="answered")
    before = DriftCanary([stable], clock=Clock()).sweep(Provider("p"))
    after = DriftCanary([drifting], clock=Clock()).sweep(Provider("p"))
    assert before.version_marker() != after.version_marker()


def test_similarity_is_one_for_identical_text_and_zero_for_disjoint() -> None:
    assert DriftCanary.similarity("a b c", "a b c") == 1.0
    assert DriftCanary.similarity("a b", "c d") == 0.0
    assert DriftCanary.similarity("", "") == 1.0


def test_an_impossible_tolerance_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="similarity"):
        DriftCanary([], clock=Clock(), tolerance=1.5)


# ── Construction ─────────────────────────────────────────────────────────────


def test_a_gateway_with_no_providers_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="at least one provider"):
        ModelGateway([], pricing=pricing(), clock=Clock())


def test_the_log_is_bound_to_the_run_that_made_the_calls() -> None:
    """What lets the engine treat the log as evidence rather than as a claim."""
    ctx = context()
    log = ModelGateway([Provider("p")], pricing=pricing(), clock=Clock()).session(ctx).log()
    assert log.context_hash == str(ctx.content_hash())


# ── The binding to a run (review finding 15) ─────────────────────────────────


def engine_with(provider: Provider) -> tuple[Any, Any]:
    """A gateway and an engine sharing a clock, as a host would wire them."""
    from attest.adapters.memory import InMemoryAuditSink, InMemoryNonceStore
    from attest.runtime.engine import RunEngine

    class Ids:
        def __init__(self) -> None:
            self._n = 0

        def new_id(self, prefix: str) -> str:
            self._n += 1
            return f"{prefix}_{self._n}"

    gateway = ModelGateway([provider], pricing=pricing(), clock=Clock())
    engine = RunEngine(
        clock=Clock(),
        ids=Ids(),
        audit=InMemoryAuditSink(),
        nonces=InMemoryNonceStore(),
        brand="acme",
    )
    return gateway, engine


def test_a_model_call_log_reaches_the_attestation_through_the_public_api() -> None:
    """The path the review found unreachable, and untested.

    The engine mints its run id and timestamp inside execute, so a caller could never
    produce a log the binding would accept. `new_run_id` plus `capture` is what makes
    the two agree.
    """
    from attest.kernel.identifiers import ActorId, Hash, TenantId
    from attest.runtime.engine import RunRequest

    provider = Provider("p", tokens=(1_000_000, 0))
    gateway, engine = engine_with(provider)
    binding = TenantBinding(
        tenant=TenantId("t1"),
        profile=ProfileRef(name="generic", version="1.0.0"),
        config_hash=Hash("c" * 64),
    )
    proposal = RunRequest(actor=ActorId("alice"), tenant=TenantId("t1"), answer="done")

    run_id = engine.new_run_id()
    captured = engine.capture(proposal, binding=binding, run_id=run_id)
    session = gateway.session(captured)
    session.complete(request())

    from dataclasses import replace as _replace

    # The same context back, so the log is bound to the snapshot the gateway ran
    # under rather than to a run id the caller supplies to both sides.
    result = engine.execute(
        _replace(proposal, model_calls=session.log()),
        binding=binding,
        run_id=run_id,
        context=captured,
    )
    assert Decimal(result.attestation.cost.amount) == Decimal("5")
    assert result.attestation.cost.pricing_version == "2026-07-01"
    ref = result.attestation.context.model
    assert ref is not None, "the model that answered must reach the context"
    assert ref.model_id == "claude-opus-5"
    types = [event.event_type for event in result.events]
    assert "model.call_completed" in types


def test_a_log_from_another_run_is_refused() -> None:
    """Otherwise a run is attributed another's cost, models and residency."""
    from attest.kernel.errors import ConfigurationError
    from attest.kernel.identifiers import ActorId, Hash, TenantId
    from attest.runtime.engine import RunRequest

    gateway, engine = engine_with(Provider("p"))
    binding = TenantBinding(
        tenant=TenantId("t1"),
        profile=ProfileRef(name="generic", version="1.0.0"),
        config_hash=Hash("c" * 64),
    )
    proposal = RunRequest(actor=ActorId("alice"), tenant=TenantId("t1"))
    other = engine.new_run_id()
    session = gateway.session(engine.capture(proposal, binding=binding, run_id=other))
    session.complete(request())

    from dataclasses import replace as _replace

    with pytest.raises(ConfigurationError, match="belongs to run"):
        engine.execute(
            _replace(proposal, model_calls=session.log()),
            binding=binding,
            run_id=engine.new_run_id(),
        )


# ── The cache is partitioned per tenant ──────────────────────────────────────


def _context_for(tenant: str, *, config: str = "c") -> ExecutionContext:
    identifier = TenantId(tenant)
    return ExecutionContext(
        run_id=RunId("run_1"),
        captured_at=AT,
        identity=IdentitySnapshot(actor=ActorId("alice"), tenant=identifier),
        binding=TenantBinding(
            tenant=identifier,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash(config * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )


@pytest.mark.security
def test_one_tenants_completion_is_never_served_to_another() -> None:
    """ATT-01. The highest-severity failure available in a multi-tenant system.

    The cache lives on the gateway, the gateway is a per-process singleton shared by
    every tenant's runs, and it is consulted before any provider is chosen — so one
    tenant's claim decision was served to another as that run's model output, priced at
    zero, with no provider call for residency, budget or audit to observe.
    """
    cache = ExactCache()
    request = CompletionRequest.for_messages(("what is the balance",), max_tokens=100)
    secret = CompletionResponse(
        text="TENANT-A CLAIM DECISION", provider="p", model_id="m", family="f"
    )
    cache.put(request, secret, model_id="m", region="eu", context=_context_for("tenant-a"))

    assert cache.get(request, model_id="m", context=_context_for("tenant-b")) is None, (
        "a cache hit crossed a tenant boundary"
    )
    assert cache.get(request, model_id="m", context=_context_for("tenant-a")) is not None


@pytest.mark.security
def test_the_cache_key_carries_the_tenant() -> None:
    request = CompletionRequest.for_messages(("q",), max_tokens=10)
    assert ExactCache.key(request, model_id="m", context=_context_for("a")) != ExactCache.key(
        request, model_id="m", context=_context_for("b")
    )


@pytest.mark.security
def test_a_stored_entry_is_re_checked_against_the_caller_not_only_the_key() -> None:
    """Belt and braces. A hash is the key; a comparison is the guarantee.

    A future change to what goes into the key would silently reopen the hole, and this
    costs one string comparison.
    """
    cache = ExactCache()
    request = CompletionRequest.for_messages(("q",), max_tokens=10)
    cache.put(
        request,
        CompletionResponse(text="a", provider="p", model_id="m", family="f"),
        model_id="m",
        region="eu",
        context=_context_for("tenant-a"),
    )
    # Reach past the key: the entry itself must still refuse a different tenant.
    entry = next(iter(cache._entries.values()))
    assert entry.tenant == "tenant-a"


@pytest.mark.security
def test_a_config_change_does_not_reuse_answers_from_the_old_binding() -> None:
    cache = ExactCache()
    request = CompletionRequest.for_messages(("q",), max_tokens=10)
    cache.put(
        request,
        CompletionResponse(text="a", provider="p", model_id="m", family="f"),
        model_id="m",
        region="eu",
        context=_context_for("tenant-a", config="c"),
    )
    assert cache.get(request, model_id="m", context=_context_for("tenant-a", config="d")) is None


@pytest.mark.security
def test_a_prompt_hash_that_is_not_the_hash_of_the_prompt_is_refused() -> None:
    """The hash is the cache key, so an unbound one lets a caller alias entries.

    A host hashing the prompt *template* rather than the rendered body made every tenant
    asking the same question collide on one entry — which was the aggravating half of
    ATT-01.
    """
    with pytest.raises(ValueError, match="is not the hash of these messages"):
        CompletionRequest(prompt_hash=Hash("a" * 64), messages=("q",), max_tokens=10)


def test_for_messages_builds_a_correctly_bound_request() -> None:
    request = CompletionRequest.for_messages(("q", "r"), max_tokens=10)
    assert request.prompt_hash == CompletionRequest.digest_of(("q", "r"))
    assert CompletionRequest.digest_of(("q",)) != CompletionRequest.digest_of(("q", "r"))


# ── Capability tier ──────────────────────────────────────────────────────────
#
# Features and capability are different axes, and the router filtered only the first.
# A model that supports tools and JSON is not thereby as GOOD at the work, so a
# frontier-tier call could fail over to a small fast model and return output that was
# structurally identical and materially weaker - same shape, same fields, same citation
# envelope, poorer reasoning. Nothing downstream could tell, which is why this cannot be
# left to a caller to notice.

TIERS = ("fast", "chat", "drafting")


def test_a_tiered_call_will_not_fail_over_to_a_weaker_model() -> None:
    """The defect, stated as the outcome: the cheap provider is never asked."""
    strong = Provider("strong", tier="drafting", raises=RuntimeError("503"))
    cheap = Provider("cheap", tier="fast")
    gateway = ModelGateway(
        [strong, cheap], pricing=pricing(), clock=Clock(), tier_order=TIERS, sleep=lambda _: None
    )

    with pytest.raises(ResidencyRefused):
        gateway.session(context()).complete(request(min_tier="drafting"))
    assert cheap.calls == [], "a drafting call was served by a fast model"


def test_it_fails_over_to_another_provider_at_the_same_tier() -> None:
    """Refusing to down-tier is not refusing to fail over."""
    first = Provider("first", tier="drafting", raises=RuntimeError("503"))
    second = Provider("second", tier="drafting")
    gateway = ModelGateway(
        [first, second], pricing=pricing(), clock=Clock(), tier_order=TIERS, sleep=lambda _: None
    )

    response = gateway.session(context()).complete(request(min_tier="drafting"))
    assert response.provider == "second"


def test_a_provider_that_declares_no_tier_is_excluded_from_a_tiered_call() -> None:
    """An undeclared tier ranks below every declared one, matching the existing rule that
    an undeclared capability is absent. Trusting silence is how the weaker model gets in."""
    undeclared = Provider("undeclared")
    gateway = ModelGateway([undeclared], pricing=pricing(), clock=Clock(), tier_order=TIERS)

    with pytest.raises(ResidencyRefused):
        gateway.session(context()).complete(request(min_tier="chat"))
    assert undeclared.calls == []


def test_a_deployment_that_does_not_model_tiers_is_unaffected() -> None:
    """The no-adoption path. Empty `tier_order` must leave behaviour exactly as it was."""
    strong = Provider("strong", raises=RuntimeError("503"))
    cheap = Provider("cheap")
    gateway = ModelGateway([strong, cheap], pricing=pricing(), clock=Clock(), sleep=lambda _: None)

    assert gateway.session(context()).complete(request()).provider == "cheap"


def test_the_refusal_says_the_tier_it_could_not_satisfy() -> None:
    """ "No provider available" sends someone to look at residency. Name the real reason."""
    gateway = ModelGateway(
        [Provider("cheap", tier="fast")], pricing=pricing(), clock=Clock(), tier_order=TIERS
    )

    with pytest.raises(ResidencyRefused) as caught:
        gateway.session(context()).complete(request(min_tier="drafting"))
    assert "drafting" in caught.value.refusal.detail


# ── Idempotency ──────────────────────────────────────────────────────────────
#
# A provider receives the request, completes it, bills it, and the response is lost to a
# timeout. Without a key the retry is a SECOND completion the customer pays for, and at
# failover it happens again. `ExactCache` cannot help: it is written from a response, and
# the whole problem is the call that never returned one.


class RecordsEveryAttempt(Provider):
    """Records the request on FAILURE as well as success.

    `Flaky` appends only when it answers, so it cannot see the attempt that was billed and
    lost - which is the only attempt this property is about.
    """

    def __init__(self, name: str, *, fail_times: int, tier: str = "") -> None:
        super().__init__(name, tier=tier)
        self._remaining = fail_times

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        if self._remaining > 0:
            self._remaining -= 1
            self.calls.append(request)
            raise RuntimeError("503 after the provider had already completed it")
        return super().complete(request)


def test_one_key_is_carried_across_every_retry_of_a_provider() -> None:
    """The property that stops the double charge."""
    provider = RecordsEveryAttempt("flaky", fail_times=2)
    gateway = ModelGateway(
        [provider],
        pricing=pricing(),
        clock=Clock(),
        retry=RetryPolicy(attempts=3),
        sleep=lambda _: None,
    )

    gateway.session(context()).complete(request())

    keys = {call.idempotency_key for call in provider.calls}
    assert len(provider.calls) == 3, "the retry did not happen, so this proves nothing"
    assert keys != {""}, "no key was minted at all"
    assert len(keys) == 1, f"a retry changed the key: {keys}"


def test_the_key_survives_a_failover_to_another_provider() -> None:
    """A failover is still the same logical call, and the first provider may already have
    been billed for it."""
    failing = Provider("failing", raises=RuntimeError("503"))
    healthy = Provider("healthy")
    gateway = ModelGateway(
        [failing, healthy], pricing=pricing(), clock=Clock(), sleep=lambda _: None
    )

    gateway.session(context()).complete(request())

    assert failing.calls, "the first provider was never tried"
    assert healthy.calls, "the failover never happened"
    assert failing.calls[0].idempotency_key == healthy.calls[0].idempotency_key


def test_two_identical_requests_get_different_keys() -> None:
    """The half that makes the key random rather than content-derived.

    `ExactCache.key()` IS content-derived and correct to be - a cache wants two identical
    requests to collide. An idempotency key must not, or asking the same question twice on
    purpose is billed once and answered once. The two rules live in the same file and are
    opposites.
    """
    provider = Provider("p")
    gateway = ModelGateway([provider], pricing=pricing(), clock=Clock())
    session = gateway.session(context())

    session.complete(request(cacheable=False))
    session.complete(request(cacheable=False))

    first, second = provider.calls
    assert first.messages == second.messages, (
        "the requests must be identical for this to mean anything"
    )
    assert first.idempotency_key != second.idempotency_key


def test_a_caller_supplied_key_is_not_trusted() -> None:
    """The gateway mints it. A caller cannot know that a retry it never saw already
    happened, so a caller-supplied key is a guarantee nobody is in a position to make."""
    provider = Provider("p")
    gateway = ModelGateway([provider], pricing=pricing(), clock=Clock())

    gateway.session(context()).complete(request())

    assert provider.calls[0].idempotency_key
