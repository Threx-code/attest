"""Family resolution — the input to the independence guarantee.

These are not string-formatting tests. ``family`` is what the cross-family judging rule
compares to decide whether a judge is independent of what it is judging, so a wrong
answer here is an independence claim nobody made.
"""

from __future__ import annotations

import pytest

from attest.adapters.providers import ModelFamilies

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("model_id", "expected"),
    [
        ("claude-opus-5", "claude"),
        ("claude-haiku-4-5", "claude"),
        # Deployment prefixes must not change the answer: the weights are the same.
        ("anthropic.claude-opus-5", "claude"),
        ("us.anthropic.claude-sonnet-5", "claude"),
        ("publishers/anthropic/models/claude-opus-5", "claude"),
        ("meta.llama3-3-70b-instruct-v1:0", "llama"),
        ("meta-llama/Llama-3.3-70B-Instruct", "llama"),
        ("llama-3.3-70b-versatile", "llama"),
        ("mistral.mixtral-8x7b-instruct-v0:1", "mistral"),
        ("gemini-2.0-flash", "gemini"),
        ("gemma2-9b-it", "gemma"),
        ("qwen-2.5-32b", "qwen"),
        ("amazon.nova-pro-v1:0", "nova"),
        ("cohere.command-r-plus-v1:0", "command"),
        ("gpt-4o", "gpt"),
        ("o3-mini", "gpt"),
    ],
)
def test_the_family_is_resolved_from_the_weights_not_the_vendor(
    model_id: str, expected: str
) -> None:
    assert ModelFamilies.resolve(model_id) == expected


def test_gpt_oss_is_not_resolved_as_gpt() -> None:
    """The ordering bug this would otherwise be.

    ``gpt-oss`` contains ``gpt``. Resolving it to the proprietary family would let a
    GPT-OSS judge review GPT-4 output and be counted as independent, which is exactly
    the check ADR 0041 exists to make.
    """
    assert ModelFamilies.resolve("openai/gpt-oss-120b") == "gpt-oss"
    assert ModelFamilies.resolve("gpt-oss-20b") != ModelFamilies.resolve("gpt-4o")


def test_an_unrecognised_model_resolves_to_none_rather_than_a_guess() -> None:
    """No fallback label. A guess here is a silent independence claim."""
    assert ModelFamilies.resolve("acme-frontier-9") is None


def test_same_family_treats_identical_unknown_labels_as_identical() -> None:
    """The conservative direction: same label means no independence, so judging is refused."""
    assert ModelFamilies.same_family("acme-9", "ACME-9 ")
    assert not ModelFamilies.same_family("claude", "llama")
