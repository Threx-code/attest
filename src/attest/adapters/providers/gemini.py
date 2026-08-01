"""Gemini — on Vertex AI, or on the Gemini Developer API.

One class, because they are the same SDK and the same wire shape reached through
different credentials. What genuinely differs is **residency**: a Vertex deployment
lives in a stated region and the Developer API does not, and residency is already a
first-class field on :class:`~attest.capabilities.gateway.ProviderSpec`. So passing
``project`` selects Vertex, requires a region, and renames the provider to
``vertex-gemini`` — the same decision taken for Azure on the OpenAI backend.

.. rubric:: Why the roles are not ``assistant``

Gemini names the model's turn ``model``, not ``assistant``. A backend that passed the
chat-completions role names through would have its history silently dropped or
rejected, and a dropped assistant turn changes the prompt that was hashed into the
attestation.

.. rubric:: Blocked responses are refusals, not empty answers

A prompt blocked by safety filters comes back with no candidate and a
``prompt_feedback.block_reason``; a candidate cut off by a filter comes back with a
``finish_reason`` of ``SAFETY``, ``PROHIBITED_CONTENT``, ``BLOCKLIST`` or
``RECITATION``. Both raise :class:`~attest.adapters.providers.base.ProviderRefused`
rather than returning the empty string the SDK would otherwise hand back.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from attest.kernel.errors import ConfigurationError

from .base import BaseProvider, ProviderRefused

if TYPE_CHECKING:
    from attest.capabilities.gateway import CompletionRequest, CompletionResponse

__all__ = ["GeminiProvider"]


class GeminiProvider(BaseProvider):
    """Gemini models through ``google-genai``."""

    SDK_MODULE = "google.genai"
    EXTRA = "gemini"
    PROVIDER_NAME = "gemini"
    DEFAULT_MODEL = "gemini-2.5-pro"

    #: ``finish_reason`` values that mean the model was stopped, not that it finished.
    #: Returning the partial text as an answer would present a filtered response as a
    #: considered one.
    BLOCKING_FINISH_REASONS: ClassVar[frozenset[str]] = frozenset(
        {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "RECITATION", "SPII", "IMAGE_SAFETY"}
    )

    __slots__ = ("_location", "_project")

    def __init__(
        self,
        *,
        project: str | None = None,
        location: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Construct the backend.

        Passing ``project`` selects Vertex AI. ``location`` defaults to the declared
        ``region`` so the two cannot drift — a provider whose residency label and
        whose actual endpoint disagree is worse than one with no label at all.
        """
        kwargs.setdefault("name", "vertex-gemini" if project else None)
        super().__init__(**kwargs)
        if project and self._spec.region == "unspecified":
            raise ConfigurationError(
                "Gemini on Vertex requires an explicit region. The router filters "
                "failover candidates on region before any data leaves, so an "
                "unlabelled deployment silently opts out of residency enforcement."
            )
        self._project = project
        self._location = location or (self._spec.region if project else None)

    def _build_client(self) -> Any:
        sdk = self._sdk()
        if self._project:
            return sdk.Client(vertexai=True, project=self._project, location=self._location)
        return sdk.Client()

    def _types(self) -> Any:
        """The SDK's ``types`` module, loaded on the same lazy path as the client."""
        import importlib

        return importlib.import_module(f"{self.SDK_MODULE}.types")

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        types = self._types()
        config: dict[str, Any] = {"max_output_tokens": request.max_tokens}
        if not self._model_controls_sampling():
            config["temperature"] = request.temperature
        if request.seed is not None:
            config["seed"] = request.seed

        response = self.client.models.generate_content(
            model=self._spec.model_id,
            contents=[
                types.Content(
                    # Gemini's name for the model's own turn is "model".
                    role="user" if turn["role"] == "user" else "model",
                    parts=[types.Part.from_text(text=turn["content"])],
                )
                for turn in self._turns(request)
            ],
            config=types.GenerateContentConfig(**config),
        )
        return self._read(response)

    def _read(self, response: Any) -> CompletionResponse:
        self._assert_not_blocked(response)

        candidates = getattr(response, "candidates", None) or []
        finish = str(getattr(candidates[0], "finish_reason", "") or "") if candidates else ""
        # The SDK exposes finish_reason as an enum; compare on the name either way.
        finish = finish.rsplit(".", 1)[-1]
        if finish in self.BLOCKING_FINISH_REASONS:
            raise ProviderRefused(
                f"{self._spec.name} stopped generating on model "
                f"{self._spec.model_id!r} with finish reason {finish!r}. Any partial "
                f"text is a filtered response, not a considered one, and is not "
                f"returned as an answer.",
                provider=self._spec.name,
                model_id=self._spec.model_id,
                category=finish.lower(),
            )

        usage = getattr(response, "usage_metadata", None)
        metadata = {"stop_reason": finish or "STOP"}
        cached = int(getattr(usage, "cached_content_token_count", 0) or 0)
        if cached:
            metadata["cached_input_tokens"] = str(cached)
        thoughts = int(getattr(usage, "thoughts_token_count", 0) or 0)
        if thoughts:
            # Billed as output, and invisible in candidates_token_count on some
            # models. Recorded so a cost figure can be reconciled against the bill.
            metadata["thinking_tokens"] = str(thoughts)

        return self._respond(
            text=str(getattr(response, "text", "") or ""),
            input_tokens=int(self.require(usage, "prompt_token_count")),
            output_tokens=int(self.require(usage, "candidates_token_count")),
            metadata=metadata,
        )

    def _assert_not_blocked(self, response: Any) -> None:
        """Refuse a prompt the safety filters rejected outright.

        This arrives with no candidate at all, so the SDK's ``.text`` is empty — the
        one case where an empty completion has a specific, reportable cause.
        """
        feedback = getattr(response, "prompt_feedback", None)
        reason = getattr(feedback, "block_reason", None) if feedback else None
        if not reason:
            return
        name = str(reason).rsplit(".", 1)[-1]
        raise ProviderRefused(
            f"{self._spec.name} blocked the prompt for model {self._spec.model_id!r} "
            f"({name}). This is a policy decision, not a transient failure: the same "
            f"prompt on the same model will block again.",
            provider=self._spec.name,
            model_id=self._spec.model_id,
            category=name.lower(),
        )
