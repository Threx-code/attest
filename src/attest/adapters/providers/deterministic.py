"""A provider with no network and no SDK.

Two jobs, both real:

**Conformance.** A domain package inherits the conformance kit and must be able to run
it in CI without an API key, a network egress rule, or a bill. A suite that only passes
when someone has configured credentials is a suite that gets skipped.

**Air-gapped deployments.** Some of the environments this framework targets have no
outbound network at all. Being able to exercise the whole control path — grants,
warrants, sealing, export — with a model that returns a stated placeholder is the
difference between "we could adopt this" and "we cannot evaluate this".

It is **not** a model. It returns a deterministic function of the request, and says so
in the response text, so nobody can mistake its output for an answer or wire it into a
production route by accident.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any, ClassVar

from .base import BaseProvider

if TYPE_CHECKING:
    from attest.capabilities.gateway import CompletionRequest, CompletionResponse

__all__ = ["DeterministicProvider"]


class DeterministicProvider(BaseProvider):
    """Returns a stable, self-identifying placeholder derived from the request.

    Determinism is the point: replay of a run that used this provider reproduces
    byte-identical output, so the replay machinery can be tested for real rather than
    against a recorded fixture that hides drift.
    """

    PROVIDER_NAME = "deterministic"
    DEFAULT_MODEL = "deterministic-1"
    EXTRA = "none"

    #: Not weights. Named so the cross-family judging rule treats two deterministic
    #: providers as the same family and refuses to call them independent judges — they
    #: are the same function, and pretending otherwise would fake an independence check.
    FAMILY: ClassVar[str] = "deterministic"

    __slots__ = ("_prefix",)

    def __init__(self, *, prefix: str = "[deterministic]", **kwargs: Any) -> None:
        kwargs.setdefault("family", self.FAMILY)
        kwargs.setdefault("supports_tools", False)
        super().__init__(**kwargs)
        self._prefix = prefix

    def _build_client(self) -> Any:
        """No client. Nothing is imported and nothing is dialled."""
        return None

    def complete(self, request: CompletionRequest) -> CompletionResponse:
        digest = hashlib.sha256(
            "\x1f".join(request.messages).encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        # Rough but stable: the point is a number that moves with the input, not a
        # tokenizer this package has no business shipping.
        input_tokens = sum(len(message.split()) for message in request.messages)
        return self._respond(
            text=f"{self._prefix} {digest}",
            input_tokens=input_tokens,
            output_tokens=len(digest.split()),
            metadata={"stop_reason": "end_turn", "synthetic": "true"},
        )
