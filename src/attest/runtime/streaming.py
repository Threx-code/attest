"""Two-phase streaming — provisional frames, then a settled attestation.

"It is high-stakes, so it can be slow" is not an argument anyone downstream accepts.
The alternative they choose is not a slower UI; it is a different framework.

The consumer contract is explicit: **provisional frames are not an answer.** Frames
carry no attestation id, and the settled frame is the only one that does — so a client
that renders provisional content as final is misusing the API rather than reading an
ambiguous one.

The hazard, stated: a retracted statement was still read. Retraction is a UI event,
not an undo, which is why ``FORBIDDEN`` is the default.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from attest.kernel.errors import ConfigurationError
from attest.runtime.agents import StreamPolicy

if TYPE_CHECKING:
    from attest.kernel.identifiers import RunId
    from attest.kernel.verdicts import Refusal
    from attest.runtime.agents import AgentSpec

__all__ = ["Frame", "SettledOutcome", "StreamSession"]


class SettledOutcome(StrEnum):
    CONFIRMED = "confirmed"
    AMENDED = "amended"
    RETRACTED = "retracted"


@dataclass(frozen=True, slots=True)
class Frame:
    """One streamed chunk.

    ``attestation_id`` is ``None`` on every provisional frame, deliberately: it is the
    structural signal that this is not yet an answer, and the SDK cannot hand a client
    something that looks settled before it is.
    """

    text: str
    provisional: bool
    attestation_id: RunId | None = None

    def __post_init__(self) -> None:
        if self.provisional and self.attestation_id is not None:
            raise ConfigurationError(
                "a provisional frame must not carry an attestation id: that id is the "
                "signal that content has settled"
            )
        if not self.provisional and self.attestation_id is None:
            raise ConfigurationError("a settled frame must carry its attestation id")


class StreamSession:
    """Governs one streamed response.

    Per-chunk outbound guards run on the way out; evidence verification, entailment,
    completeness and warrant evaluation run only at settle, because they need the whole
    answer. A per-chunk guard failure **terminates the stream immediately** rather than
    waiting for generation to finish.
    """

    __slots__ = ("_frames", "_policy", "_refusal", "_terminated")

    def __init__(self, spec: AgentSpec) -> None:
        self._assert_safe(spec)
        self._policy = spec.stream
        self._frames: list[Frame] = []
        self._terminated = False
        self._refusal: Refusal | None = None

    @staticmethod
    def _assert_safe(spec: AgentSpec) -> None:
        """Refuse the combination that is obviously unsafe, at construction.

        An agent that can cause effects must not stream: effects never execute during
        phase one, but a provisional line about an irreversible action has already been
        read by the time it is retracted.

        **``delegates_to`` counts, and it did not.** ATT-62. The check was
        ``spec.stream is not FORBIDDEN and spec.tools``, so a supervisor holding no
        tools of its own — which is the ordinary shape of a supervisor — streamed
        freely while delegating to a child holding irreversible ones. The rule was
        evaded by one level of indirection, and the indirection is the design pattern
        the composition docs recommend.

        The reach an agent has is the reach of everything it can call. That is the same
        principle :meth:`~attest.runtime.agents.Scope.narrowed_to` enforces for every
        other boundary, applied here.
        """
        if spec.stream is StreamPolicy.FORBIDDEN:
            return
        reach = [
            ("tools", tuple(spec.tools)),
            ("delegates_to", tuple(spec.delegates_to)),
        ]
        held = [f"{name}={list(values)}" for name, values in reach if values]
        if held:
            raise ConfigurationError(
                f"agent {spec.name!r} declares {' and '.join(held)} with a stream policy "
                f"of {spec.stream.value}. Streaming an agent that can cause effects — "
                f"directly, or through anything it delegates to — is refused at "
                f"construction: a retracted statement was still read."
            )

    @property
    def provisional_frames(self) -> int:
        return sum(1 for f in self._frames if f.provisional)

    def emit(self, text: str) -> Frame:
        """Emit a provisional chunk."""
        if self._policy is StreamPolicy.FORBIDDEN:
            raise ConfigurationError("this agent's policy forbids streaming; verify, then release")
        if self._terminated:
            raise ConfigurationError("the stream was terminated by an outbound guard")
        frame = Frame(text=text, provisional=True)
        self._frames.append(frame)
        return frame

    def terminate(self, refusal: Refusal) -> SettledOutcome:
        """A per-chunk guard failed. Stop now rather than at end of generation.

        **The refusal is kept.** ATT-63. This argument used to be discarded — there was
        an ``ARG002`` suppression in ``pyproject.toml`` acknowledging it, with a comment
        saying a real implementation could log it. So a stream killed by an outbound
        guard left no record of *why*: no event, no finding, nothing. The guard fired,
        the reader saw text stop mid-sentence, and the audit trail said a stream ended.

        That is the worst shape for this particular failure. An outbound guard
        terminating a stream means something was about to leave the boundary that should
        not have, which is precisely the event an incident review needs and precisely
        the one that was unrecoverable.

        Retained on the session and surfaced by :attr:`refusal`, so the caller that owns
        the recorder can write it into the chain. Not written here: this class is
        constructed per response and holds no sink, and giving it one would make every
        streamed frame a write.
        """
        self._terminated = True
        self._refusal = refusal
        return SettledOutcome.RETRACTED

    @property
    def refusal(self) -> Refusal | None:
        """Why the stream was terminated, or ``None`` if it was not.

        A caller that ignores this loses the reason — but it can no longer be lost
        *silently*, which is the difference between an oversight and a design that
        discards evidence.
        """
        return self._refusal

    @property
    def terminated(self) -> bool:
        return self._terminated

    def settle(self, *, attestation_id: RunId, final_text: str) -> tuple[Frame, SettledOutcome]:
        """Close the stream with the verified answer."""
        if self._terminated:
            return (
                Frame(text="", provisional=False, attestation_id=attestation_id),
                SettledOutcome.RETRACTED,
            )
        streamed = "".join(f.text for f in self._frames if f.provisional)
        outcome = SettledOutcome.CONFIRMED if streamed == final_text else SettledOutcome.AMENDED
        return (
            Frame(text=final_text, provisional=False, attestation_id=attestation_id),
            outcome,
        )
