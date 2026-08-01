"""Model family resolution — weights, not vendors.

The cross-family judging rule (ADR 0041) compares the *weights* a judge runs on
against the weights that produced the output under review. Comparing vendors instead
is the bug it exists to prevent: Groq, Bedrock and Vertex all serve Llama, so a
"different provider" judge can be the same model marking its own homework.

.. code-block:: text

    WRONG                              RIGHT
    ─────────────────────              ────────────────────────────────
    provider != provider               family != family
    groq vs bedrock  -> ok             llama vs llama  -> refused
    (both serving Llama 3.3)           (same weights, no independence)

**Resolution never guesses.** :meth:`ModelFamilies.resolve` returns ``None`` for a
model id it does not recognise, and the provider constructor then requires an explicit
``family=``. A guessed family silently weakens the independence guarantee — two
unrelated models mapped to the same fallback label would be *refused* judging, which
is safe, but two related models mapped to different labels would be *permitted* it,
which is not. Neither is worth guessing for.
"""

from __future__ import annotations

from typing import ClassVar

__all__ = ["ModelFamilies"]


class ModelFamilies:
    """The shipped model-family vocabulary, and substring resolution over it.

    Open by construction: a family is a plain string, so a deployment serving weights
    nobody here has heard of passes ``family="..."`` to the provider and everything
    downstream works. This class is a convenience for the families that ship, not a
    closed set the framework enforces.
    """

    CLAUDE = "claude"
    GPT = "gpt"
    GPT_OSS = "gpt-oss"
    LLAMA = "llama"
    MISTRAL = "mistral"
    GEMINI = "gemini"
    GEMMA = "gemma"
    QWEN = "qwen"
    DEEPSEEK = "deepseek"
    COMMAND = "command"
    NOVA = "nova"
    TITAN = "titan"
    JAMBA = "jamba"
    PHI = "phi"
    KIMI = "kimi"
    GROK = "grok"

    #: Ordered longest-first where one marker is a prefix of another. ``gpt-oss`` must
    #: be tested before ``gpt`` or every open-weight GPT-OSS deployment would be
    #: labelled as OpenAI's proprietary family — which would let GPT-OSS judge GPT-4
    #: output and call it independent.
    _MARKERS: ClassVar[tuple[tuple[str, str], ...]] = (
        ("gpt-oss", GPT_OSS),
        ("gpt_oss", GPT_OSS),
        ("claude", CLAUDE),
        ("llama", LLAMA),
        ("mixtral", MISTRAL),
        ("mistral", MISTRAL),
        ("ministral", MISTRAL),
        ("magistral", MISTRAL),
        ("gemini", GEMINI),
        ("gemma", GEMMA),
        ("qwen", QWEN),
        ("deepseek", DEEPSEEK),
        ("command", COMMAND),
        ("nova", NOVA),
        ("titan", TITAN),
        ("jamba", JAMBA),
        ("kimi", KIMI),
        ("grok", GROK),
        ("phi-", PHI),
        ("phi3", PHI),
        ("phi4", PHI),
        ("gpt", GPT),
        ("o1-", GPT),
        ("o3-", GPT),
        ("o4-", GPT),
    )

    @classmethod
    def resolve(cls, model_id: str) -> str | None:
        """The weights family ``model_id`` names, or ``None`` when unrecognised.

        Deployment prefixes are irrelevant to the answer and are simply searched
        through: ``us.anthropic.claude-opus-5``, ``publishers/anthropic/models/…``
        and ``meta-llama/Llama-3.3-70B`` all resolve on the same marker.
        """
        candidate = model_id.lower()
        for marker, family in cls._MARKERS:
            if marker in candidate:
                return family
        return None

    @classmethod
    def same_family(cls, left: str, right: str) -> bool:
        """Whether two family labels denote the same weights.

        Comparison is on the label, so an unrecognised pair a caller labelled
        identically is treated as identical — the conservative direction.
        """
        return left.strip().lower() == right.strip().lower()
