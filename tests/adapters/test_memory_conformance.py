"""The in-memory adapters, run through the conformance kit.

These are the adapters every quickstart uses, every test fixture reaches for, and every
evaluation of the framework runs against first. They had no conformance coverage at all
— the kit was applied to the Django and SQLite adapters and not to the ones a new
adopter actually meets.

That matters more than it sounds. An in-memory store is where a team forms its
expectations of what the port guarantees, so an in-memory store that is subtly weaker
than the port teaches the wrong contract, and the lesson is only corrected in
production.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from attest.adapters.memory import (
    InMemoryApprovalStore,
    InMemoryAuditSink,
    InMemoryBudgetStore,
    InMemoryIdempotencyStore,
    InMemoryNonceStore,
    InMemoryRunStore,
)
from attest.assurance.conformance import (
    ApprovalStoreConformance,
    AuditSinkConformance,
    BudgetStoreConformance,
    IdempotencyStoreConformance,
    NonceStoreConformance,
    RunStoreConformance,
)

if TYPE_CHECKING:
    from attest.kernel.ports import (
        ApprovalStore,
        AuditSink,
        BudgetStore,
        IdempotencyStore,
        NonceStore,
        RunStore,
    )

pytestmark = pytest.mark.contract


class TestInMemoryRunStore(RunStoreConformance):
    def store(self) -> RunStore:
        return InMemoryRunStore()


class TestInMemoryAuditSink(AuditSinkConformance):
    def store(self) -> AuditSink:
        return InMemoryAuditSink()


class TestInMemoryNonceStore(NonceStoreConformance):
    def store(self) -> NonceStore:
        return InMemoryNonceStore()


class TestInMemoryApprovalStore(ApprovalStoreConformance):
    def store(self) -> ApprovalStore:
        return InMemoryApprovalStore()


class TestInMemoryIdempotencyStore(IdempotencyStoreConformance):
    def store(self) -> IdempotencyStore:
        return InMemoryIdempotencyStore()


class TestInMemoryBudgetStore(BudgetStoreConformance):
    def store(self) -> BudgetStore:
        # Both scopes. The concurrency test uses its own so a committed race cannot
        # perturb the sequential ceiling tests — see BudgetStoreConformance.CONCURRENT_SCOPE.
        return InMemoryBudgetStore(
            ceilings=dict.fromkeys(
                (BudgetStoreConformance.SCOPE, BudgetStoreConformance.CONCURRENT_SCOPE),
                BudgetStoreConformance.CEILING,
            )
        )
