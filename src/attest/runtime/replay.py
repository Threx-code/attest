"""Replay — three modes, named for the question each answers.

Naming matters here more than usual. "We replayed the decision" is ambiguous in a way
that becomes dangerous in front of a regulator: it can mean "we reconstructed what
happened" or "we ran today's model against old inputs", and those are not equivalent
claims.

Never describe ``BEHAVIOURAL`` output as a replay of the original decision. It is a
counterfactual against a system that has changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from attest.kernel.effects import IdempotencyMode
from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from attest.kernel.actions import Action
    from attest.kernel.attestation import Attestation

__all__ = ["PolicyAt", "ReplayDiff", "ReplayMode", "ReplayPlan"]


class ReplayMode(StrEnum):
    """One vocabulary. ADR 0037 withdrew STRICT/PINNED/CURRENT."""

    HISTORICAL = "replay_historical"
    """What exactly happened? Recorded model outputs, recorded tool results, no live
    calls. Reconstructs the run as it ran."""

    VERIFY = "replay_verify"
    """Does the attestation still verify? No model calls at all — recomputes chain,
    seal, evidence and warrants against the captured context."""

    BEHAVIOURAL = "replay_behavioural"
    """What would the system do now? Live model calls. Answers a DIFFERENT question
    from the other two, and must never be reported as reproducing the original."""


class PolicyAt(StrEnum):
    """Which policy a behavioural replay runs under. A parameter, not a fourth mode."""

    AS_AT_RUN = "as_at_run"
    """Drift measurement: the model is the only variable."""

    CURRENT = "current"
    """Policy assessment: how many historical decisions would flip under today's rules?"""


@dataclass(frozen=True, slots=True)
class ReplayPlan:
    """A replay, and what it is permitted to do."""

    mode: ReplayMode
    policy: PolicyAt = PolicyAt.AS_AT_RUN

    def __post_init__(self) -> None:
        if self.mode is not ReplayMode.BEHAVIOURAL and self.policy is PolicyAt.CURRENT:
            raise ConfigurationError(
                f"{self.mode.value} reconstructs a historical run, so it cannot be run "
                f"under current policy. Use BEHAVIOURAL to ask what the system would "
                f"do now — and report it as that, not as a replay of the original."
            )

    @property
    def calls_the_model(self) -> bool:
        return self.mode is ReplayMode.BEHAVIOURAL

    def assert_permits(self, action: Action) -> None:
        """Refuse to re-execute a side effect during replay.

        Replay is read-only by construction. Tool results are replayed from the
        record; the effects themselves are not re-run, and a tool whose idempotency is
        anything but NATURAL cannot be safely repeated for a report.
        """
        if action.idempotency is not IdempotencyMode.NATURAL:
            raise ConfigurationError(
                f"replay refuses to execute {action.tool!r}: its idempotency is "
                f"{action.idempotency.value}, not natural. Replay is read-only — "
                f"reconstructing a report must not move money a second time."
            )

    def claim(self) -> str:
        """The only claim this replay supports. Copied verbatim into reports."""
        return {
            ReplayMode.HISTORICAL: "this is what happened",
            ReplayMode.VERIFY: "the record is sound",
            ReplayMode.BEHAVIOURAL: "this is what we would do now",
        }[self.mode]


@dataclass(frozen=True, slots=True)
class ReplayDiff:
    """What changed between an original run and its replay."""

    original: Attestation
    replayed: Attestation

    @property
    def verdict_changed(self) -> bool:
        return self.original.verdict is not self.replayed.verdict

    @property
    def evidence_changed(self) -> bool:
        return self.original.context.content_hash() != self.replayed.context.content_hash()

    @property
    def reproducible(self) -> bool:
        return not self.verdict_changed and not self.evidence_changed

    def summary(self) -> str:
        if self.reproducible:
            return "reproducible: same verdict, same evidence"
        if self.evidence_changed and not self.verdict_changed:
            return "evidence no longer verifies — tampering or data drift; investigate"
        return (
            f"verdict changed {self.original.verdict.value} -> "
            f"{self.replayed.verdict.value}; investigate"
        )
