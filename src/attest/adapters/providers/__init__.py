"""Provider backends for the LLM gateway.

Every class here satisfies :class:`~attest.capabilities.gateway.LLMProvider` and is
reached only through :class:`~attest.capabilities.gateway.ProviderRouter`. Nothing else
in the package calls a provider SDK — that rule is what makes cost attribution,
redaction and drift detection possible at all, and it is checked by the ``import-linter``
contract that forbids ``anthropic`` and ``openai`` anywhere below L4.

.. code-block:: text

    BACKEND                       FAMILIES SERVED        EXTRA
    ─────────────────────────     ───────────────────    ──────────────────
    AnthropicProvider             claude                 [anthropic]
    VertexAnthropicProvider       claude                 [vertex]
    GeminiProvider                gemini (+ Vertex)      [gemini] / [vertex]
    OpenAIProvider                gpt   (+ Azure)        [openai] / [azure]
    BedrockProvider               any Bedrock family     [bedrock]
    GroqProvider                  llama qwen gemma …     [groq]
    DeterministicProvider         —                      none

**Importing this package pulls no SDK.** Each backend imports its vendor library inside
a method, so a deployment that installed only ``[anthropic]`` can still import the
module list above without a ``ModuleNotFoundError`` from a library it never asked for.
The CI clean-environment job asserts the base install stays dependency-free.

**The family is resolved from the model id, never from the vendor.** Groq, Bedrock and
Vertex all serve weights that other providers also serve, so "a different provider"
does not mean "an independent judge". See
:mod:`attest.adapters.providers.families` and ADR 0041.
"""

from __future__ import annotations

from attest.adapters.providers.anthropic import (
    AnthropicProvider,
    ClaudeModel,
    ClaudeModels,
    VertexAnthropicProvider,
)
from attest.adapters.providers.base import (
    BaseProvider,
    ChatCompletionsProvider,
    ProviderError,
    ProviderRefused,
    ProviderUnavailable,
)
from attest.adapters.providers.bedrock import BedrockProvider
from attest.adapters.providers.deterministic import DeterministicProvider
from attest.adapters.providers.families import ModelFamilies
from attest.adapters.providers.gemini import GeminiProvider
from attest.adapters.providers.groq import GroqProvider
from attest.adapters.providers.openai import OpenAIProvider

__all__ = [
    "AnthropicProvider",
    "BaseProvider",
    "BedrockProvider",
    "ChatCompletionsProvider",
    "ClaudeModel",
    "ClaudeModels",
    "DeterministicProvider",
    "GeminiProvider",
    "GroqProvider",
    "ModelFamilies",
    "OpenAIProvider",
    "ProviderError",
    "ProviderRefused",
    "ProviderUnavailable",
    "VertexAnthropicProvider",
]
