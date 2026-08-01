"""Amazon Bedrock backend, over the Converse API.

Converse rather than ``InvokeModel``: Bedrock serves Claude, Llama, Mistral, Nova,
Titan, Command and Jamba, and ``InvokeModel`` takes a different request body for each.
One call site per family inside the one class that exists to be the single call site
would be self-defeating.

The trade is explicit. Converse is family-agnostic, so Claude-specific controls —
adaptive thinking, effort, task budgets — are not reachable through it. A deployment
that needs those wants the Anthropic SDK's Bedrock client instead of this backend, and
should say so rather than discovering the gap at review time.

``region`` is mandatory. On the first-party APIs an omitted region is merely unlabelled;
on Bedrock it is also the endpoint, so getting it wrong sends data somewhere the router
never approved.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from attest.kernel.errors import ConfigurationError

from .base import BaseProvider, ProviderRefused

if TYPE_CHECKING:
    from attest.capabilities.gateway import CompletionRequest, CompletionResponse

__all__ = ["BedrockProvider"]


class BedrockProvider(BaseProvider):
    """Any Bedrock-hosted family, through ``bedrock-runtime.converse``."""

    SDK_MODULE = "boto3"
    EXTRA = "bedrock"
    PROVIDER_NAME = "bedrock"

    __slots__ = ()

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if self._spec.region == "unspecified":
            raise ConfigurationError(
                "BedrockProvider requires an explicit region: on Bedrock the region is "
                "the endpoint, so an unlabelled one both opts out of residency "
                "filtering and picks a destination nobody chose."
            )

    def _build_client(self) -> Any:
        return self._sdk().client("bedrock-runtime", region_name=self._spec.region)

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        inference: dict[str, Any] = {"maxTokens": request.max_tokens}
        if not self._model_controls_sampling():
            inference["temperature"] = request.temperature

        response = self.client.converse(
            modelId=self._spec.model_id,
            messages=[
                {"role": turn["role"], "content": [{"text": turn["content"]}]}
                for turn in self._turns(request)
            ],
            inferenceConfig=inference,
        )

        stop_reason = str(response.get("stopReason", "") or "")
        if stop_reason == "guardrail_intervened":
            raise ProviderRefused(
                f"a Bedrock guardrail blocked the request on model "
                f"{self._spec.model_id!r}. This is a policy decision, not a transient "
                f"failure: retrying the same request on the same model will block "
                f"again.",
                provider=self._spec.name,
                model_id=self._spec.model_id,
                category="guardrail",
            )

        blocks = response.get("output", {}).get("message", {}).get("content", [])
        text = "".join(str(block.get("text", "")) for block in blocks if "text" in block)
        usage = response.get("usage", {})
        return self._respond(
            text=text,
            input_tokens=int(self.required_key(usage, "inputTokens")),
            output_tokens=int(self.required_key(usage, "outputTokens")),
            metadata={"stop_reason": stop_reason},
        )
