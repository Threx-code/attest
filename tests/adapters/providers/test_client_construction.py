"""Client construction, without installing a single vendor SDK.

The lazy import is what keeps the base install dependency-free, so it has to be
exercised — but exercising it must not require the SDK, or the test only runs where the
extra happens to be installed. A stand-in module object is substituted for the import,
which checks the construction call we make rather than the library's behaviour.
"""

from __future__ import annotations

from typing import Any

import pytest

from attest.adapters.providers import (
    AnthropicProvider,
    BedrockProvider,
    DeterministicProvider,
    GeminiProvider,
    GroqProvider,
    OpenAIProvider,
    VertexAnthropicProvider,
)

pytestmark = pytest.mark.unit


class FakeSdk:
    """Records how a backend asked for its client."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def _record(self, name: str, *args: Any, **kwargs: Any) -> str:
        self.calls.append((name, args, kwargs))
        return f"{name}-client"

    def Anthropic(self, *args: Any, **kwargs: Any) -> str:  # SDK's own capitalisation
        return self._record("Anthropic", *args, **kwargs)

    def AnthropicVertex(self, *args: Any, **kwargs: Any) -> str:
        return self._record("AnthropicVertex", *args, **kwargs)

    def OpenAI(self, *args: Any, **kwargs: Any) -> str:
        return self._record("OpenAI", *args, **kwargs)

    def AzureOpenAI(self, *args: Any, **kwargs: Any) -> str:
        return self._record("AzureOpenAI", *args, **kwargs)

    def Groq(self, *args: Any, **kwargs: Any) -> str:
        return self._record("Groq", *args, **kwargs)

    def Client(self, *args: Any, **kwargs: Any) -> str:
        return self._record("Client", *args, **kwargs)

    def client(self, *args: Any, **kwargs: Any) -> str:
        return self._record("client", *args, **kwargs)


def with_fake_sdk(provider: object, monkeypatch: pytest.MonkeyPatch) -> FakeSdk:
    sdk = FakeSdk()
    monkeypatch.setattr(type(provider), "_sdk", lambda self: sdk)
    return sdk


def test_the_anthropic_client_is_built_lazily(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = AnthropicProvider()
    sdk = with_fake_sdk(provider, monkeypatch)
    assert sdk.calls == [], "nothing is dialled until a client is actually needed"
    assert provider.client == "Anthropic-client"
    assert provider.client == "Anthropic-client", "built once, then reused"
    assert len(sdk.calls) == 1


def test_vertex_passes_the_project_and_the_region(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = VertexAnthropicProvider(project_id="proj-1", region="europe-west1")
    sdk = with_fake_sdk(provider, monkeypatch)
    assert provider.client
    assert sdk.calls == [
        ("AnthropicVertex", (), {"project_id": "proj-1", "region": "europe-west1"})
    ]


def test_openai_builds_the_first_party_client_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAIProvider(model_id="gpt-4o")
    sdk = with_fake_sdk(provider, monkeypatch)
    assert provider.client
    assert sdk.calls[0][0] == "OpenAI"


def test_an_azure_endpoint_selects_the_azure_client(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = OpenAIProvider(
        model_id="gpt-4o",
        azure_endpoint="https://acme.openai.azure.com",
        azure_api_version="2024-10-21",
        region="uksouth",
    )
    sdk = with_fake_sdk(provider, monkeypatch)
    assert provider.client
    name, _, kwargs = sdk.calls[0]
    assert name == "AzureOpenAI"
    assert kwargs["azure_endpoint"] == "https://acme.openai.azure.com"
    assert kwargs["api_version"] == "2024-10-21"


def test_groq_builds_its_own_client(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = GroqProvider()
    sdk = with_fake_sdk(provider, monkeypatch)
    assert provider.client
    assert sdk.calls[0][0] == "Groq"


def test_bedrock_pins_the_runtime_to_the_declared_region(monkeypatch: pytest.MonkeyPatch) -> None:
    """The region is the endpoint here, so it must reach the client, not just the spec."""
    provider = BedrockProvider(model_id="anthropic.claude-opus-5", region="eu-west-2")
    sdk = with_fake_sdk(provider, monkeypatch)
    assert provider.client
    assert sdk.calls == [("client", ("bedrock-runtime",), {"region_name": "eu-west-2"})]


def test_gemini_builds_the_developer_api_client_when_no_project_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = GeminiProvider()
    sdk = with_fake_sdk(provider, monkeypatch)
    assert provider.client
    assert sdk.calls == [("Client", (), {})]


def test_gemini_on_vertex_pins_the_project_and_the_location(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The location defaults to the declared region, so the label and the endpoint agree."""
    provider = GeminiProvider(project="proj-1", region="europe-west1")
    sdk = with_fake_sdk(provider, monkeypatch)
    assert provider.client
    assert sdk.calls == [
        ("Client", (), {"vertexai": True, "project": "proj-1", "location": "europe-west1"})
    ]


def test_the_deterministic_backend_has_no_client_at_all() -> None:
    """Nothing is imported and nothing is dialled — the point of an air-gapped backend."""
    assert DeterministicProvider().client is None
