"""The evidence tree's bounds, and whether they bound anything.

A node budget bounds the *count*. Only memoisation bounds the *cost*, and until it
existed the budget was a number that permitted a four-second request.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from attest.kernel.evidence import (
    AuthorityLevel,
    Evidence,
    EvidenceKinds,
    SourceRef,
    SourceType,
)
from attest.kernel.identifiers import EvidenceId, Hash

pytestmark = pytest.mark.security

AT = datetime(2026, 1, 1, tzinfo=UTC)
SOURCE = SourceRef(
    source_id="PW-2019",
    source_type=SourceType.POLICY_DOC,
    authority=AuthorityLevel.AUTHORITATIVE,
    version="7",
    retrieved_at=AT,
    integrity_hash=Hash("a" * 64),
)


def _item(eid: str, value: str = "covers escape of water") -> Evidence:
    return Evidence(
        evidence_id=EvidenceId(eid),
        kind=EvidenceKinds.QUOTED_SPAN,
        source=SOURCE,
        value=value,
    )


def _derivation(eid: str, children: tuple[Evidence, ...]) -> Evidence:
    return Evidence(
        evidence_id=EvidenceId(eid),
        kind=EvidenceKinds.DERIVATION,
        source=SOURCE,
        value="total",
        sub_evidence=children,
    )


def _spine(width: int, depth: int) -> Evidence:
    """A legal tree: deep, wide at every level, all nodes distinct."""
    made = 0

    def leaf() -> Evidence:
        nonlocal made
        made += 1
        return _item(f"e{made}", value=f"clause {made}")

    node = leaf()
    for _ in range(depth):
        made += 1
        node = _derivation(f"d{made}", (node, *(leaf() for _ in range(width))))
    return node


# ── The node budget is a budget, not a hope ──────────────────────────────────


def test_a_legal_deep_tree_costs_linear_time_not_superlinear() -> None:
    """ATT-10. Remote CPU exhaustion by any authenticated principal.

    ``__post_init__`` runs ``depth()`` and ``_reject_cycles()``, which calls
    ``content_hash()`` on every node, and ``content_hash`` recursively hashed the
    entire subtree beneath it. Nothing was memoised, so an *n*-node tree cost
    O(n·depth) full subtree hashes.

    Measured before the fix: a legal 2016-node tree burned 4.2 seconds of CPU before
    any guard, verifier or authority check ran — and 4096 nodes are permitted. The
    request is repeated concurrently, DispatchView is synchronous, and a handful
    exhausts the pool.
    """
    started = time.perf_counter()
    tree = _spine(64, 31)
    elapsed = time.perf_counter() - started

    assert tree.node_count() > 2000
    assert elapsed < 1.0, (
        f"{tree.node_count()} nodes took {elapsed:.2f}s to construct; the tree is legal "
        f"and a handful of concurrent requests would exhaust the worker pool"
    )


def test_a_node_is_hashed_once_however_often_it_is_asked() -> None:
    """The property, rather than a stopwatch.

    Timing two already-warm calls compares nanoseconds and fails on scheduler noise;
    what matters is that the digest is computed once per node, which is observable
    directly.
    """
    computed = 0
    original = Evidence._compute_hash

    def counted(self: Evidence) -> Hash:
        nonlocal computed
        computed += 1
        return original(self)

    tree = _spine(8, 4)
    nodes = tree.node_count()
    Evidence._compute_hash = counted  # type: ignore[method-assign]
    try:
        for _ in range(5):
            tree.content_hash()
    finally:
        Evidence._compute_hash = original  # type: ignore[method-assign]

    assert computed == 0, (
        f"{computed} nodes were re-hashed across five calls over a {nodes}-node tree; "
        f"construction already memoised them"
    )


def test_the_memo_does_not_change_the_hash() -> None:
    """A cache that altered the value it caches would be worse than no cache."""
    item = _item("e1")
    first = item.content_hash()
    assert item.content_hash() == first
    assert _item("e1").content_hash() == first


def test_two_identical_items_compare_equal_whether_or_not_either_was_hashed() -> None:
    """The memo is excluded from equality; it is not data."""
    left, right = _item("e1"), _item("e1")
    left.content_hash()
    assert left == right


def test_the_memo_does_not_appear_in_the_repr() -> None:
    """It is machinery, and a repr full of digests is a repr nobody reads."""
    item = _item("e1")
    item.content_hash()
    assert "_digest" not in repr(item)


def test_distinct_subtrees_still_hash_distinctly() -> None:
    """The memo is per-instance; it must not collapse two different trees."""
    left = _derivation("d", (_item("a", value="one"),))
    right = _derivation("d", (_item("a", value="two"),))
    assert left.content_hash() != right.content_hash()
