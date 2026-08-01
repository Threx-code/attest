"""Groq backend.

Groq matters to this framework for a reason that is not latency. It serves *open-weight
families* — Llama, Qwen, Gemma, GPT-OSS — which widens the pool of genuinely
independent judges (ADR 0041). A deployment whose primary and judge models are both
Claude has no cross-family check available; adding a Groq endpoint gives it one without
adding a second vendor relationship for the primary path.

That is also the trap. Groq is a *provider*, not a family: a Groq-served Llama judging
a Bedrock-served Llama is the same weights marking their own homework. The family is
resolved from the model id for exactly this reason — see
:mod:`attest.adapters.providers.families`.
"""

from __future__ import annotations

from typing import Any

from .base import ChatCompletionsProvider

__all__ = ["GroqProvider"]


class GroqProvider(ChatCompletionsProvider):
    """Open-weight models on Groq's inference API."""

    SDK_MODULE = "groq"
    EXTRA = "groq"
    PROVIDER_NAME = "groq"
    DEFAULT_MODEL = "llama-3.3-70b-versatile"

    __slots__ = ()

    def _build_client(self) -> Any:
        return self._sdk().Groq()
