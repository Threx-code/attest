"""Anthropic backend — the Messages API, over an explicit model catalogue.

Deliberately absent: a ``system=`` constructor argument. A system prompt configured on
the provider would not appear in ``CompletionRequest.prompt_hash``, so two runs with
materially different instructions would hash identically and replay would reproduce
neither. Instructions belong in the transcript the gateway hashed.

.. rubric:: Why a catalogue rather than a substring rule

The models differ in ways that are hard 400s, not preferences: current models reject
``temperature`` outright, Haiku 4.5 caps output at 64K where the rest allow 128K, and
its context window is 200K rather than 1M. A substring rule expresses one of those and
silently omits every model it forgot — which is how ``claude-haiku-4-5`` ends up
receiving a 128K ``max_tokens`` and failing in production rather than at construction.

:class:`ClaudeModels` states the whole shipped line. It is a convenience, not a
gate — an id it does not know still works, and is treated conservatively:
sampling parameters are withheld (sending them to a model that refuses them is a hard
failure; withholding them from one that accepts them merely means default sampling),
and the response records ``sampling=model-controlled`` so nobody is left believing a
determinism knob was applied.

.. rubric:: Two further behaviours handled rather than hoped for

**A large ``max_tokens`` requires streaming.** The SDK refuses a non-streaming request
it estimates will outlive the HTTP timeout, so anything above the threshold is streamed
and reassembled. The caller sees no difference.

**A safety refusal is not an empty answer.** Claude can decline with HTTP 200,
``stop_reason="refusal"`` and no content. That is raised as
:class:`~attest.adapters.providers.base.ProviderRefused`, carrying the category, so the
gateway routes to a different family rather than retrying the same model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from attest.kernel.errors import ConfigurationError

from .base import BaseProvider, ProviderError, ProviderRefused

if TYPE_CHECKING:
    from collections.abc import Mapping

    from attest.capabilities.gateway import CompletionRequest, CompletionResponse

__all__ = ["AnthropicProvider", "ClaudeModel", "ClaudeModels", "VertexAnthropicProvider"]


@dataclass(frozen=True, slots=True)
class ClaudeModel:
    """What a backend must know about one Claude model before it calls it."""

    model_id: str
    context_window: int
    max_output_tokens: int
    accepts_sampling: bool
    """Whether ``temperature`` / ``top_p`` / ``top_k`` are accepted.

    ``False`` means the API returns HTTP 400 for them, not that they are discouraged.
    """

    thinking_by_default: bool = False
    """Whether omitting ``thinking`` still spends thinking tokens.

    Load-bearing for budgeting: ``max_tokens`` caps thinking *and* response text
    together, so a ceiling sized for the answer alone truncates the answer.
    """


class ClaudeModels:
    """The shipped Claude line.

    Retired ids are absent deliberately — listing a model that returns 404 would make
    a configuration error look like an outage. Deprecated-but-serving models are
    present, because a regulated deployment pinned to one needs it to keep working
    until it migrates.
    """

    FABLE_5 = "claude-fable-5"
    MYTHOS_5 = "claude-mythos-5"
    OPUS_5 = "claude-opus-5"
    OPUS_4_8 = "claude-opus-4-8"
    OPUS_4_7 = "claude-opus-4-7"
    OPUS_4_6 = "claude-opus-4-6"
    OPUS_4_5 = "claude-opus-4-5"
    SONNET_5 = "claude-sonnet-5"
    SONNET_4_6 = "claude-sonnet-4-6"
    SONNET_4_5 = "claude-sonnet-4-5"
    HAIKU_4_5 = "claude-haiku-4-5"

    #: Every model whose limits this release can state from published documentation.
    #: ``OPUS_4_5`` and ``SONNET_4_5`` are named above but absent here on purpose:
    #: their ceilings are not stated in the documentation this catalogue was built
    #: from, and a guessed ceiling would reject a legitimate request. They fall to the
    #: conservative unknown-model path, which is a smaller cost than a wrong number.
    CATALOGUE: ClassVar[Mapping[str, ClaudeModel]] = {
        model.model_id: model
        for model in (
            # Thinking always on and not disablable; sampling parameters removed.
            ClaudeModel(
                FABLE_5, 1_000_000, 128_000, accepts_sampling=False, thinking_by_default=True
            ),
            ClaudeModel(
                MYTHOS_5, 1_000_000, 128_000, accepts_sampling=False, thinking_by_default=True
            ),
            # Thinking on by default — unlike 4.8/4.7, where omitting it meant none.
            ClaudeModel(
                OPUS_5, 1_000_000, 128_000, accepts_sampling=False, thinking_by_default=True
            ),
            ClaudeModel(OPUS_4_8, 1_000_000, 128_000, accepts_sampling=False),
            ClaudeModel(OPUS_4_7, 1_000_000, 128_000, accepts_sampling=False),
            ClaudeModel(OPUS_4_6, 1_000_000, 128_000, accepts_sampling=True),
            ClaudeModel(SONNET_5, 1_000_000, 128_000, accepts_sampling=False),
            ClaudeModel(SONNET_4_6, 1_000_000, 128_000, accepts_sampling=True),
            # The one model in the line with a smaller window and a lower output cap.
            # Exactly the case a substring rule gets wrong.
            ClaudeModel(HAIKU_4_5, 200_000, 64_000, accepts_sampling=True),
        )
    }

    @classmethod
    def get(cls, model_id: str) -> ClaudeModel | None:
        """The catalogue entry for ``model_id``, or ``None`` if it is not shipped here.

        ``None`` is not an error. New models appear between releases of this package,
        and a framework that refused to call one until it had been added to a table
        would be a worse problem than the table being incomplete.
        """
        return cls.CATALOGUE.get(model_id)


class AnthropicProvider(BaseProvider):
    """Claude via Anthropic's first-party API."""

    SDK_MODULE = "anthropic"
    EXTRA = "anthropic"
    PROVIDER_NAME = "anthropic"
    DEFAULT_MODEL = ClaudeModels.OPUS_5

    #: Above this the SDK refuses a non-streaming request, so we stream and reassemble.
    STREAM_ABOVE_MAX_TOKENS: ClassVar[int] = 16_000

    #: Assumed output ceiling for a model the catalogue does not list. The smallest
    #: shipped ceiling, so an unknown model is under-requested rather than rejected.
    UNKNOWN_MODEL_OUTPUT_CEILING: ClassVar[int] = 64_000

    __slots__ = ()

    @property
    def model(self) -> ClaudeModel | None:
        """The catalogue entry for the configured model, if it is a shipped one."""
        return ClaudeModels.get(self._spec.model_id)

    def _model_controls_sampling(self) -> bool:
        """Withhold sampling parameters unless the catalogue says they are accepted.

        Unknown models are treated as controlling their own sampling. That is the
        cheap direction to be wrong in: withholding ``temperature`` from a model that
        would have accepted it costs default sampling, while sending it to one that
        refuses it fails the call outright.
        """
        entry = self.model
        return entry is None or not entry.accepts_sampling

    def _output_ceiling(self) -> int:
        entry = self.model
        return entry.max_output_tokens if entry else self.UNKNOWN_MODEL_OUTPUT_CEILING

    def _build_client(self) -> Any:
        return self._sdk().Anthropic()

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        ceiling = self._output_ceiling()
        if request.max_tokens > ceiling:
            raise ProviderError(
                f"model {self._spec.model_id!r} caps output at {ceiling:,} tokens; "
                f"{request.max_tokens:,} were requested. Refused before the call "
                f"rather than after the 400, so the budget is untouched."
            )

        payload: dict[str, Any] = {
            "model": self._spec.model_id,
            "max_tokens": request.max_tokens,
            "messages": self._turns(request),
        }
        if not self._model_controls_sampling():
            payload["temperature"] = request.temperature

        return self._read(self._send(payload))

    def _send(self, payload: dict[str, Any]) -> Any:
        """One call, streamed when the requested output is large enough to time out."""
        if payload["max_tokens"] > self.STREAM_ABOVE_MAX_TOKENS:
            with self.client.messages.stream(**payload) as stream:
                return stream.get_final_message()
        return self.client.messages.create(**payload)

    def _read(self, message: Any) -> CompletionResponse:
        """Turn a Messages response into a gateway response, or refuse honestly."""
        stop_reason = str(getattr(message, "stop_reason", "") or "")
        if stop_reason == "refusal":
            details = getattr(message, "stop_details", None)
            category = str(getattr(details, "category", "") or "")
            raise ProviderRefused(
                f"{self._spec.name} declined the request on model "
                f"{self._spec.model_id!r}"
                + (f" (category {category!r})" if category else "")
                + ". This is a policy decline, not a transient failure: the same "
                "request on the same model will decline again.",
                provider=self._spec.name,
                model_id=self._spec.model_id,
                category=category,
            )

        text = "".join(
            str(getattr(block, "text", ""))
            for block in getattr(message, "content", ())
            if getattr(block, "type", None) == "text"
        )
        usage = getattr(message, "usage", None)
        metadata = {"stop_reason": stop_reason}
        response_id = getattr(message, "id", None)
        if response_id:
            metadata["response_id"] = str(response_id)
        cached = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        if cached:
            metadata["cached_input_tokens"] = str(cached)
        served_by = str(getattr(message, "model", "") or "")
        if served_by and served_by != self._spec.model_id:
            # A server-side fallback answered. A decision made by a different model is
            # a materially different decision, and replay must be able to see that.
            metadata["served_by"] = served_by

        return self._respond(
            text=text,
            # Required, not defaulted: a renamed field would record this call at zero
            # tokens and zero cost rather than raising.
            input_tokens=int(self.require(usage, "input_tokens")),
            output_tokens=int(self.require(usage, "output_tokens")),
            metadata=metadata,
        )


class VertexAnthropicProvider(AnthropicProvider):
    """Claude served from Google Cloud Vertex AI.

    A separate backend rather than a flag, because residency is the whole reason it
    exists: the same weights in a different region are a different provider as far as
    :class:`~attest.capabilities.gateway.ProviderRouter` is concerned, and conflating
    them is how a failover leaves the permitted region.

    Only Claude on Vertex is implemented. Gemini on Vertex is not — see the package
    README rather than assuming this class covers it.
    """

    EXTRA = "vertex"
    PROVIDER_NAME = "vertex"

    __slots__ = ("_project_id",)

    def __init__(self, *, project_id: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if self._spec.region == "unspecified":
            raise ConfigurationError(
                "VertexAnthropicProvider requires an explicit region. It is not "
                "optional here: the router filters failover candidates on it before "
                "any data leaves, so an unlabelled region silently opts out of "
                "residency enforcement."
            )
        self._project_id = project_id

    def _build_client(self) -> Any:
        return self._sdk().AnthropicVertex(
            project_id=self._project_id,
            region=self._spec.region,
        )
