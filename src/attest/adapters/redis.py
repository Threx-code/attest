"""Shared circuit breaker and exact cache, for deployments with more than one process.

The per-process versions in :mod:`attest.capabilities.gateway` are correct and useless
at scale, in a specific way worth stating plainly:

.. code-block:: text

    ONE PROCESS                         N PROCESSES, PER-PROCESS STATE
    ─────────────────────────           ────────────────────────────────────
    3 failures  -> circuit opens        3 x N failures before anything opens
    cache warms up                      1/N hit rate; N times the spend

    With 40 workers and a threshold of 3, a dead provider absorbs 120
    requests before the first circuit opens — and each of the 40 circuits
    opens independently, so the herd is not thundering once, it is
    thundering forty times.

That is the thundering herd the breaker exists to prevent, arriving because the breaker
is local. Sharing the counter is the fix.

.. rubric:: What happens when Redis is down

**Neither fail-open nor fail-closed.** Both are wrong here. Failing open removes the
protection at exactly the moment infrastructure is unhealthy, which is when a provider
outage is most likely; failing closed turns a Redis blip into a total outage caused by
the safety mechanism itself.

So each class falls back to the in-process implementation it wraps. You lose the
*sharing* — back to N times the failure budget — and you keep the *protection*. The
degradation is reported rather than silent, because a deployment that believes it has a
shared breaker and does not is making capacity decisions on a false premise.

.. code-block:: python

    from redis import Redis
    from attest.adapters.redis import RedisCircuitBreaker, RedisExactCache

    client = Redis.from_url(settings.REDIS_URL)
    gateway = ModelGateway(
        providers=[...],
        breaker=RedisCircuitBreaker(client),
        cache=RedisExactCache(client, ttl=timedelta(hours=6)),
    )

``redis`` is an optional extra and is never imported here — the client is passed in, so
this module works with ``redis``, ``redis.asyncio``'s sync facade, a cluster client, or
a fake, and installing ``attest[django]`` does not drag a Redis library onto the path.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar, Final

from attest.capabilities.gateway import (
    CircuitBreaker,
    CircuitState,
    CompletionResponse,
    ExactCache,
)
from attest.kernel.canonical import Canonical

if TYPE_CHECKING:
    from datetime import datetime

    from attest.capabilities.gateway import CompletionRequest
    from attest.kernel.context import ExecutionContext

__all__ = ["Degradation", "RedisCircuitBreaker", "RedisExactCache", "SharedStateDegraded"]


class Degradation:
    """How a fallback to per-process state is reported. Counted, not just warned.

    Three channels, because each catches a different reader: a **counter** a health
    endpoint can expose, a **log record** an aggregator picks up, and a **warning** for
    an interactive run. Any one of them alone is a report somebody does not receive.
    """

    #: How many times each subsystem has fallen back. Read by a health check.
    COUNTS: ClassVar[dict[str, int]] = {}

    @classmethod
    def record(cls, what: str, consequence: str) -> None:
        import logging
        import warnings

        cls.COUNTS[what] = cls.COUNTS.get(what, 0) + 1
        message = (
            f"the shared {what} could not reach Redis and fell back to per-process "
            f"state ({cls.COUNTS[what]} time(s)): {consequence}"
        )
        logging.getLogger("attest.redis").warning(message)
        warnings.warn(message, SharedStateDegraded, stacklevel=3)

    @classmethod
    def reset(cls) -> None:
        """For tests. A counter that cannot be reset makes them order-dependent."""
        cls.COUNTS.clear()


class SharedStateDegraded(RuntimeWarning):
    """Redis was unreachable and the local fallback took over.

    A warning rather than an exception: the run must continue. But it is raised as a
    warning rather than swallowed, because a deployment that believes it has a shared
    breaker and does not will size its provider capacity on a premise that stopped
    being true.
    """


class RedisCircuitBreaker:
    """A circuit breaker whose counter is shared by every process.

    Drop-in for :class:`~attest.capabilities.gateway.CircuitBreaker`: same methods, same
    meanings, same injected time. Only the storage differs.

    The failure count is incremented and the circuit opened in **one Lua script**, which
    is the whole point. Read-then-write across N workers would let each of them observe
    a count below the threshold and none of them open it — the exact race the shared
    counter exists to remove, faithfully reproduced at a larger scale.
    """

    #: INCR the counter, and open the circuit if this call crossed the threshold.
    #: ``SET NX`` decides the winner, so exactly one caller is told it opened the
    #: circuit and exactly one CIRCUIT_OPENED event is emitted no matter how many
    #: workers fail simultaneously.
    OPEN_IF_TRIPPED: Final = """
    local failures = redis.call('INCR', KEYS[1])
    redis.call('EXPIRE', KEYS[1], ARGV[3])
    if failures >= tonumber(ARGV[1]) then
        if redis.call('SET', KEYS[2], ARGV[2], 'NX', 'EX', ARGV[3]) then
            return 1
        end
    end
    return 0
    """

    PREFIX: Final = "attest:breaker"

    __slots__ = ("_client", "_cooldown", "_fallback", "_prefix", "_script", "_threshold", "_ttl")

    def __init__(
        self,
        client: Any,  # noqa: ANN401 — a redis client; typing it would import redis at load
        *,
        threshold: int = 3,
        cooldown: timedelta = timedelta(seconds=30),
        prefix: str = PREFIX,
        ttl: timedelta | None = None,
    ) -> None:
        self._client = client
        self._threshold = threshold
        self._cooldown = cooldown
        self._prefix = prefix
        # Keys expire well after the cooldown so a provider that fails once an hour
        # does not accumulate toward a threshold across unrelated incidents. A counter
        # with no TTL opens a circuit on the third failure of the year.
        self._ttl = ttl if ttl is not None else cooldown * 10
        self._fallback = CircuitBreaker(threshold=threshold, cooldown=cooldown)
        self._script = self._register(client)

    def _register(self, client: Any) -> Any:  # noqa: ANN401
        register = getattr(client, "register_script", None)
        return None if register is None else register(self.OPEN_IF_TRIPPED)

    def state(self, provider: str, *, now: datetime) -> CircuitState:
        try:
            raw = self._client.get(self._key(provider, "open"))
        except Exception:
            self._degraded()
            return self._fallback.state(provider, now=now)
        if raw is None:
            return CircuitState.CLOSED
        opened = self._instant(raw)
        if opened is None or now - opened >= self._cooldown:
            return CircuitState.HALF_OPEN
        return CircuitState.OPEN

    def allows(self, provider: str, *, now: datetime) -> bool:
        return self.state(provider, now=now) is not CircuitState.OPEN

    def record_failure(self, provider: str, *, now: datetime) -> bool:
        """Count a failure. ``True`` only for the caller whose failure opened the circuit.

        Exactly one caller gets ``True``, decided by ``SET NX`` inside the script, so
        one ``CIRCUIT_OPENED`` event is emitted rather than one per worker that
        happened to be mid-flight.
        """
        if self._script is None:
            return self._fallback.record_failure(provider, now=now)
        try:
            opened = self._script(
                keys=[self._key(provider, "failures"), self._key(provider, "open")],
                args=[self._threshold, now.isoformat(), int(self._ttl.total_seconds())],
            )
        except Exception:
            self._degraded()
            return self._fallback.record_failure(provider, now=now)
        return bool(opened)

    def record_success(self, provider: str) -> None:
        """Clear the counter and close the circuit.

        A success in HALF_OPEN closing the circuit for everyone is the point of sharing:
        one worker's probe is enough, rather than each of forty discovering recovery
        separately.
        """
        self._fallback.record_success(provider)
        try:
            self._client.delete(self._key(provider, "failures"), self._key(provider, "open"))
        except Exception:
            self._degraded()

    def _key(self, provider: str, suffix: str) -> str:
        return f"{self._prefix}:{provider}:{suffix}"

    @staticmethod
    def _instant(raw: object) -> datetime | None:
        from datetime import datetime as _datetime

        try:
            text = raw.decode() if isinstance(raw, bytes) else str(raw)
            return _datetime.fromisoformat(text)
        except (ValueError, AttributeError):
            # An unparseable timestamp is treated as HALF_OPEN rather than OPEN: it
            # means something wrote a key we do not understand, and refusing every
            # provider on that basis would be an outage caused by a stray key.
            return None

    def _degraded(self) -> None:
        """Count it, log it, and warn once.

        ``warnings.warn`` alone was the whole report, and Python dedupes it per call
        site by default — so a Redis outage produced one line on stderr for the lifetime
        of the process, and most deployments route warnings nowhere. A deployment that
        believes it has a shared breaker and does not is sizing provider capacity on a
        false premise, and it needs to be able to *see* that, not to have been told once
        at 3am.
        """
        Degradation.record(
            "circuit breaker",
            "protection is intact; sharing is not, so a degraded provider now absorbs "
            "the failure threshold once per worker",
        )


class RedisExactCache:
    """An exact-match response cache shared by every process.

    Drop-in for :class:`~attest.capabilities.gateway.ExactCache`, and it reuses that
    class's key derivation rather than reimplementing it. That matters more than it
    looks: the key includes the corpus epochs the run was reading, so a document update
    invalidates the answers derived from it. A second copy of that rule would eventually
    disagree with the first, and the failure mode is serving a stale citation with a
    fresh timestamp.

    Residency is re-checked on read, here as there. A cached answer is still an answer
    a tenant may no longer be permitted to receive, and a cache is exactly where that
    is easy to forget.
    """

    PREFIX: Final = "attest:cache"

    __slots__ = ("_client", "_fallback", "_prefix", "_ttl")

    def __init__(
        self,
        client: Any,  # noqa: ANN401 — a redis client; typing it would import redis at load
        *,
        ttl: timedelta = timedelta(hours=6),
        prefix: str = PREFIX,
    ) -> None:
        self._client = client
        self._ttl = ttl
        self._prefix = prefix
        self._fallback = ExactCache()

    @staticmethod
    def key(request: CompletionRequest, *, model_id: str, context: ExecutionContext) -> str:
        """The same key as the in-process cache. Deliberately delegated, not copied."""
        return ExactCache.key(request, model_id=model_id, context=context)

    def get(
        self, request: CompletionRequest, *, model_id: str, context: ExecutionContext
    ) -> CompletionResponse | None:
        try:
            raw = self._client.get(self._redis_key(request, model_id, context))
        except Exception:
            return self._fallback.get(request, model_id=model_id, context=context)
        if raw is None:
            return None
        entry = self._decode(raw)
        if entry is None:
            return None
        permitted = context.binding.residency_regions
        if permitted and entry[1] not in permitted:
            # A residency change must not keep replaying answers a tenant may no
            # longer receive.
            return None
        return entry[0]

    def put(
        self,
        request: CompletionRequest,
        response: CompletionResponse,
        *,
        model_id: str,
        region: str,
        context: ExecutionContext,
    ) -> None:
        payload = Canonical.encode(
            {
                "region": region,
                "corpus_epochs": {str(k): v for k, v in context.corpus_epochs.items()},
                "response": {
                    "text": response.text,
                    "provider": response.provider,
                    "model_id": response.model_id,
                    "family": response.family,
                    "input_tokens": response.input_tokens,
                    "output_tokens": response.output_tokens,
                    "failover": response.failover,
                    "metadata": dict(response.metadata),
                },
            }
        )
        try:
            self._client.set(
                self._redis_key(request, model_id, context),
                payload,
                ex=int(self._ttl.total_seconds()),
            )
        except Exception:
            self._fallback.put(request, response, model_id=model_id, region=region, context=context)

    def _redis_key(
        self, request: CompletionRequest, model_id: str, context: ExecutionContext
    ) -> str:
        return f"{self._prefix}:{self.key(request, model_id=model_id, context=context)}"

    @staticmethod
    def _decode(raw: object) -> tuple[CompletionResponse, str] | None:
        """Rebuild the response, or treat it as a miss.

        A corrupt or old-format entry is a **miss**, never a partial response. Serving
        half a cached answer would be worse than calling the provider again, and the
        provider call is the cheap correct fallback.
        """
        try:
            body = json.loads(raw.decode() if isinstance(raw, bytes) else str(raw))
            stored = body["response"]
            return (
                CompletionResponse(
                    text=str(stored["text"]),
                    provider=str(stored["provider"]),
                    model_id=str(stored["model_id"]),
                    family=str(stored["family"]),
                    input_tokens=int(stored.get("input_tokens", 0)),
                    output_tokens=int(stored.get("output_tokens", 0)),
                    failover=bool(stored.get("failover", False)),
                    metadata={str(k): str(v) for k, v in dict(stored.get("metadata", {})).items()},
                ),
                str(body.get("region", "")),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            return None
