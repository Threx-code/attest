"""Shared breaker and cache, against a Redis faithful enough to be worth testing against.

The fake below models the two things the design actually depends on: ``SET NX`` returns
falsey when the key exists, and the script body runs without interleaving. Everything
else about Redis is irrelevant here — what is under test is whether forty workers open
one circuit or forty.
"""

from __future__ import annotations

import threading
import warnings
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from attest.adapters.redis import RedisCircuitBreaker, RedisExactCache, SharedStateDegraded
from attest.capabilities.gateway import CircuitState, CompletionRequest, CompletionResponse
from attest.kernel.context import (
    ExecutionContext,
    IdentitySnapshot,
    ProfileRef,
    TenantBinding,
)
from attest.kernel.identifiers import ActorId, CorpusId, Hash, RunId, TenantId

pytestmark = pytest.mark.unit

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


class FakeRedis:
    """Enough Redis to be honest about atomicity, and nothing else.

    ``register_script`` returns a callable that runs the body under a lock, which is
    what a real Redis gives you by being single-threaded. Without that the test would
    pass for a broken implementation.
    """

    def __init__(self, *, broken: bool = False) -> None:
        self.data: dict[str, bytes] = {}
        self.broken = broken
        self._lock = threading.Lock()
        self.script_calls = 0

    def _check(self) -> None:
        if self.broken:
            raise ConnectionError("redis unreachable")

    def get(self, key: str) -> bytes | None:
        self._check()
        return self.data.get(key)

    def set(self, key: str, value: Any, ex: int | None = None, nx: bool = False) -> bool | None:
        self._check()
        if nx and key in self.data:
            return None
        self.data[key] = value if isinstance(value, bytes) else str(value).encode()
        return True

    def delete(self, *keys: str) -> int:
        self._check()
        return sum(1 for key in keys if self.data.pop(key, None) is not None)

    def register_script(self, body: str) -> Any:
        def run(keys: list[str], args: list[Any]) -> int:
            self._check()
            # One lock for the whole body: a real Redis is single-threaded, and the
            # entire design rests on INCR-then-SET-NX being indivisible.
            with self._lock:
                self.script_calls += 1
                counter = int(self.data.get(keys[0], b"0")) + 1
                self.data[keys[0]] = str(counter).encode()
                if counter >= int(args[0]) and keys[1] not in self.data:
                    self.data[keys[1]] = str(args[1]).encode()
                    return 1
                return 0

        return run


def context() -> ExecutionContext:
    tenant = TenantId("t1")
    return ExecutionContext(
        run_id=RunId("run_1"),
        captured_at=AT,
        identity=IdentitySnapshot(actor=ActorId("alice"), tenant=tenant),
        binding=TenantBinding(
            tenant=tenant,
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )


def request() -> CompletionRequest:
    return CompletionRequest.for_messages(("what is the balance",), max_tokens=100)


def response(text: str = "the balance is 500000") -> CompletionResponse:
    return CompletionResponse(
        text=text,
        provider="anthropic",
        model_id="claude-opus-5",
        family="claude",
        input_tokens=10,
        output_tokens=20,
    )


# ── The breaker shares its counter ───────────────────────────────────────────


@pytest.mark.security
def test_the_threshold_is_reached_across_processes_not_per_process() -> None:
    """The failure this exists for.

    Three separate breaker instances — three worker processes — must together open the
    circuit on the third failure, not on the ninth.
    """
    client = FakeRedis()
    workers = [RedisCircuitBreaker(client, threshold=3) for _ in range(3)]
    opened = [worker.record_failure("anthropic", now=AT) for worker in workers]

    assert opened.count(True) == 1, (
        f"{opened.count(True)} of three workers opened the circuit; the counter is not "
        f"shared, so a dead provider absorbs the threshold once per worker"
    )
    assert workers[0].state("anthropic", now=AT) is CircuitState.OPEN
    assert workers[2].allows("anthropic", now=AT) is False


@pytest.mark.concurrency
@pytest.mark.security
def test_simultaneous_failures_open_the_circuit_exactly_once() -> None:
    """One CIRCUIT_OPENED event, not one per worker that happened to be mid-flight."""
    client = FakeRedis()
    results: list[bool] = []
    lock = threading.Lock()
    barrier = threading.Barrier(12)

    def fail() -> None:
        breaker = RedisCircuitBreaker(client, threshold=3)
        barrier.wait()
        won = breaker.record_failure("anthropic", now=AT)
        with lock:
            results.append(won)

    threads = [threading.Thread(target=fail) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1, f"{results.count(True)} callers each opened the circuit"


def test_the_cooldown_moves_the_circuit_to_half_open() -> None:
    client = FakeRedis()
    breaker = RedisCircuitBreaker(client, threshold=1, cooldown=timedelta(seconds=30))
    breaker.record_failure("anthropic", now=AT)
    assert breaker.state("anthropic", now=AT) is CircuitState.OPEN
    assert breaker.state("anthropic", now=AT + timedelta(seconds=31)) is CircuitState.HALF_OPEN


@pytest.mark.security
def test_one_success_closes_the_circuit_for_everyone() -> None:
    """The point of sharing: one worker's probe is enough for the whole pool."""
    client = FakeRedis()
    first, second = (RedisCircuitBreaker(client, threshold=1) for _ in range(2))
    first.record_failure("anthropic", now=AT)
    assert second.allows("anthropic", now=AT) is False

    first.record_success("anthropic")
    assert second.state("anthropic", now=AT) is CircuitState.CLOSED


def test_an_unparseable_open_marker_does_not_block_every_provider() -> None:
    """A stray key must not become an outage caused by the safety mechanism."""
    client = FakeRedis()
    client.data["attest:breaker:anthropic:open"] = b"not-a-timestamp"
    breaker = RedisCircuitBreaker(client)
    assert breaker.state("anthropic", now=AT) is CircuitState.HALF_OPEN


# ── Degradation is reported, never silent ────────────────────────────────────


@pytest.mark.security
def test_an_unreachable_redis_keeps_the_protection_and_says_so() -> None:
    """Neither fail-open nor fail-closed. Local protection, loudly degraded."""
    breaker = RedisCircuitBreaker(FakeRedis(broken=True), threshold=2)
    with pytest.warns(SharedStateDegraded, match="fell back to per-process"):
        assert breaker.record_failure("anthropic", now=AT) is False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SharedStateDegraded)
        assert breaker.record_failure("anthropic", now=AT) is True
        assert breaker.allows("anthropic", now=AT) is False, (
            "the fallback did not protect anything; an unreachable Redis became "
            "an unlimited failure budget"
        )


def test_a_client_without_scripting_uses_the_local_breaker() -> None:
    class NoScripts:
        def get(self, key: str) -> None:
            return None

    breaker = RedisCircuitBreaker(NoScripts(), threshold=1)
    assert breaker.record_failure("anthropic", now=AT) is True


# ── The cache is shared, and still refuses on residency ──────────────────────


def test_a_response_cached_by_one_process_is_served_to_another() -> None:
    client = FakeRedis()
    writer, reader = (RedisExactCache(client) for _ in range(2))
    ctx = context()
    writer.put(request(), response(), model_id="claude-opus-5", region="eu", context=ctx)

    served = reader.get(request(), model_id="claude-opus-5", context=ctx)
    assert served is not None, "the cache is not shared; hit rate falls to 1/N"
    assert served.text == "the balance is 500000"
    assert served.input_tokens == 10
    assert served.family == "claude"


def test_a_miss_is_none_rather_than_an_error() -> None:
    assert (
        RedisExactCache(FakeRedis()).get(request(), model_id="claude-opus-5", context=context())
        is None
    )


@pytest.mark.security
def test_a_cached_answer_is_withheld_when_the_region_is_no_longer_permitted() -> None:
    """A residency change must not keep replaying answers a tenant may no longer receive."""
    client = FakeRedis()
    cache = RedisExactCache(client)
    ctx = context()
    cache.put(request(), response(), model_id="claude-opus-5", region="us", context=ctx)

    narrowed = ExecutionContext(
        run_id=ctx.run_id,
        captured_at=ctx.captured_at,
        identity=ctx.identity,
        binding=TenantBinding(
            tenant=TenantId("t1"),
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
            residency_regions=frozenset({"eu"}),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
    )
    assert cache.get(request(), model_id="claude-opus-5", context=narrowed) is None


@pytest.mark.security
def test_a_corrupt_entry_is_a_miss_rather_than_a_partial_answer() -> None:
    """Serving half a cached response is worse than calling the provider again."""
    client = FakeRedis()
    cache = RedisExactCache(client)
    key = f"attest:cache:{cache.key(request(), model_id='claude-opus-5', context=context())}"
    client.data[key] = b'{"response": {"text": "truncated"'
    assert cache.get(request(), model_id="claude-opus-5", context=context()) is None


@pytest.mark.security
def test_a_document_update_invalidates_the_answers_derived_from_it() -> None:
    """The key carries corpus epochs, so a stale citation is not served with a fresh date."""
    client = FakeRedis()
    cache = RedisExactCache(client)

    before = ExecutionContext(
        run_id=RunId("run_1"),
        captured_at=AT,
        identity=IdentitySnapshot(actor=ActorId("alice"), tenant=TenantId("t1")),
        binding=TenantBinding(
            tenant=TenantId("t1"),
            profile=ProfileRef(name="generic", version="1.0.0"),
            config_hash=Hash("c" * 64),
        ),
        framework_version="0.1.0",
        policy_version="1.0.0",
        corpus_epochs={CorpusId("policies"): "v1"},
    )
    after = ExecutionContext(
        run_id=before.run_id,
        captured_at=before.captured_at,
        identity=before.identity,
        binding=before.binding,
        framework_version="0.1.0",
        policy_version="1.0.0",
        corpus_epochs={CorpusId("policies"): "v2"},
    )
    cache.put(request(), response(), model_id="claude-opus-5", region="eu", context=before)
    assert cache.get(request(), model_id="claude-opus-5", context=before) is not None
    assert cache.get(request(), model_id="claude-opus-5", context=after) is None


def test_a_cache_outage_is_a_miss_not_a_failure() -> None:
    """A run must not fail because a cache was unavailable."""
    cache = RedisExactCache(FakeRedis(broken=True))
    cache.put(request(), response(), model_id="claude-opus-5", region="eu", context=context())
    assert cache.get(request(), model_id="claude-opus-5", context=context()) is not None, (
        "the local fallback did not take the write, so the run lost its cache entirely"
    )
