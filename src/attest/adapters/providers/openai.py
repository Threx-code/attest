"""OpenAI backend, and Azure OpenAI as a parameter rather than a second class.

Azure is the same SDK, the same wire shape and the same model families reached through
a different endpoint with a different credential. Shipping it as a separate class would
duplicate the request shaping and let the two drift — which is precisely the
per-call-site divergence the gateway exists to end. What genuinely differs is
*residency*, and residency is already a first-class field on
:class:`~attest.capabilities.gateway.ProviderSpec`.

Reasoning models reject a caller-supplied ``temperature``, so it is omitted for them
and the response records that sampling was model-controlled.
"""

from __future__ import annotations

from typing import Any, ClassVar

from attest.kernel.errors import ConfigurationError

from .base import ChatCompletionsProvider

__all__ = ["OpenAIProvider"]


class OpenAIProvider(ChatCompletionsProvider):
    """OpenAI models, first-party or through an Azure deployment."""

    SDK_MODULE = "openai"
    EXTRA = "openai"
    PROVIDER_NAME = "openai"
    DEFAULT_MODEL = "gpt-5"

    #: Reasoning models reject a non-default ``temperature``.
    MODEL_CONTROLLED_SAMPLING: ClassVar[tuple[str, ...]] = ("gpt-5", "o1", "o3", "o4")

    __slots__ = ("_azure_api_version", "_azure_endpoint")

    def __init__(
        self,
        *,
        azure_endpoint: str | None = None,
        azure_api_version: str = "2024-10-21",
        **kwargs: Any,
    ) -> None:
        """Construct the backend.

        Passing ``azure_endpoint`` selects the Azure client and renames the provider to
        ``azure-openai``, so cost attribution and failover records distinguish the two
        even though the SDK is shared. When it is set, ``region`` must be too: an Azure
        deployment exists in a stated region, and a provider that does not say which
        cannot be filtered by the residency rule.
        """
        kwargs.setdefault("name", "azure-openai" if azure_endpoint else None)
        super().__init__(**kwargs)
        if azure_endpoint and self._spec.region == "unspecified":
            raise ConfigurationError(
                "an Azure OpenAI deployment must declare its region. The router "
                "filters failover candidates on region before any data leaves, so an "
                "unlabelled deployment silently opts out of residency enforcement."
            )
        self._azure_endpoint = azure_endpoint
        self._azure_api_version = azure_api_version

    def _build_client(self) -> Any:
        sdk = self._sdk()
        if self._azure_endpoint:
            return sdk.AzureOpenAI(
                azure_endpoint=self._azure_endpoint,
                api_version=self._azure_api_version,
            )
        return sdk.OpenAI()
