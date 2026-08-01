"""Approvals at scale — and whether the review is real.

Human-in-the-loop is correct and creates a throughput ceiling unrelated to compute.
Worse, an approval obligation reliably discharged without genuine review
**manufactures evidence of oversight**, which is worse than having no obligation: in
an enforcement review the records show diligent oversight of decisions nobody read.

The framework cannot force attention. It can shape the queue so attention is possible,
and it can **measure** whether review is real.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime, timedelta

    from attest.kernel.authority import ApprovalRecord

__all__ = ["ApprovalQueue", "ControlItem", "ReviewDepth", "ReviewSignals"]


class ReviewDepth(StrEnum):
    """How much human attention an action gets. Not every action needs the same."""

    AUTO = "auto"
    SAMPLED = "sampled"
    """A proportion routed to review. Sampling must be UNPREDICTABLE to the proposing
    actor, or it becomes a gap to route around — so the decision is made by the
    framework, seeded per run, and recorded."""

    REVIEW = "review"
    DUAL = "dual"
    PANEL = "panel"


@dataclass(frozen=True, slots=True)
class ControlItem:
    """A synthetic action that SHOULD be rejected, injected into the queue.

    The sharpest instrument available: a reviewer who approves one is not reviewing.
    Standard practice in screening professions, and it transfers directly.

    Marked clearly synthetic in the record, and refused at the execution boundary
    regardless of approval, so it can never produce a real effect.
    """

    item_id: str
    expected_rejection: str

    @property
    def is_synthetic(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class ReviewSignals:
    """What is measured to tell whether oversight is real.

    Every one of these is a leading indicator: they move before the failure, which is
    what makes them worth collecting.
    """

    decisions: int = 0
    approvals: int = 0
    median_seconds_to_decision: float = 0.0
    evidence_expanded: int = 0
    control_items_approved: int = 0

    @property
    def approval_rate(self) -> float:
        return self.approvals / self.decisions if self.decisions else 0.0

    @property
    def evidence_expansion_rate(self) -> float:
        return self.evidence_expanded / self.decisions if self.decisions else 0.0

    def rubber_stamping_suspected(self, *, floor_seconds: float = 5.0) -> bool:
        """Whether the numbers say review has stopped happening.

        Any one of: approving a control item, a 100% approval rate over a meaningful
        sample, or a median decision time too short to have read anything.
        """
        if self.control_items_approved:
            return True
        if self.decisions >= 20 and self.approval_rate == 1.0:
            return True
        return bool(self.decisions and self.median_seconds_to_decision < floor_seconds)


class ApprovalQueue:
    """Shapes the queue so attention is possible, and measures whether it happened.

    The framework cannot force a reviewer to read. What it can do is refuse to make
    not-reading easy, and record the signals that say it is happening anyway.
    """

    __slots__ = ("_expiry_window",)

    def __init__(self, *, expiry_window: timedelta) -> None:
        if expiry_window.total_seconds() <= 0:
            raise ValueError(
                "an approval queue needs a positive expiry window: a queue without one "
                "becomes a backlog of half-executed decisions with no owner"
            )
        self._expiry_window = expiry_window

    def expires_at(self, opened: datetime) -> datetime:
        """Every pending action has a deadline. Expiry is a typed refusal, not a drop."""
        return opened + self._expiry_window

    @staticmethod
    def batch(
        items: Sequence[object], *, outliers: Sequence[object] = ()
    ) -> tuple[tuple[object, ...], tuple[object, ...]]:
        """Split a queue into a homogeneous group and items needing individual review.

        Batching is necessary at volume and dangerous done naively: an "approve all
        200" button makes the warrant meaningless. Batch approval is offered only for
        the homogeneous group, and the batch's composition is recorded in every
        member's attestation.
        """
        outlier_list = list(outliers)
        routine = [item for item in items if item not in outlier_list]
        return tuple(routine), tuple(outlier_list)

    @staticmethod
    def control_item_failures(
        items: Sequence[ControlItem], decisions: Sequence[ApprovalRecord]
    ) -> tuple[str, ...]:
        """Control items that were approved.

        The sharpest instrument available: a reviewer who approves a synthetic item
        that should have been rejected is not reviewing. A non-empty result is a
        finding about the reviewer, recorded rather than hidden.
        """
        approved = {d.approval_id for d in decisions if d.approved}
        return tuple(item.item_id for item in items if item.item_id in approved)
