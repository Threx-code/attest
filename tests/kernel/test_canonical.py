"""Canonicalisation is the root of every integrity guarantee in the system.

If two distinct values can share a hash, then evidence can be forged, a grant can be
redeemed against an action it was not issued for, and an audit chain can be rewritten
without detection. These tests are correspondingly paranoid.
"""

from __future__ import annotations

import math
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from attest.kernel.canonical import NULL_HASH, Canonical, CanonicalisationError


class Colour(Enum):
    RED = "red"
    ONE = 1


# ── Stability ────────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_null_hash_is_a_64_char_zero_string() -> None:
    assert NULL_HASH == "0" * 64
    assert len(NULL_HASH) == len(Canonical.digest("anything"))


@pytest.mark.unit
def test_hash_is_stable_across_calls() -> None:
    value = {"tool": "transfer", "amount": Decimal("500000.00")}
    assert Canonical.digest(value) == Canonical.digest(value)


@pytest.mark.unit
def test_mapping_key_order_does_not_change_the_hash() -> None:
    assert Canonical.digest({"a": 1, "b": 2}) == Canonical.digest({"b": 2, "a": 1})


@pytest.mark.unit
def test_nested_mapping_order_does_not_change_the_hash() -> None:
    left = {"outer": {"z": [1, {"b": 2, "a": 1}], "y": 3}}
    right = {"outer": {"y": 3, "z": [1, {"a": 1, "b": 2}]}}
    assert Canonical.digest(left) == Canonical.digest(right)


@pytest.mark.unit
def test_set_iteration_order_does_not_change_the_hash() -> None:
    assert Canonical.digest(frozenset({3, 1, 2})) == Canonical.digest(frozenset({2, 3, 1}))


@pytest.mark.unit
def test_sets_of_mixed_types_canonicalise() -> None:
    # Sorting raw elements would raise on mixed types; we sort encoded elements.
    assert Canonical.digest(frozenset({1, "a", None})) == Canonical.digest(
        frozenset({None, "a", 1})
    )


@pytest.mark.unit
def test_sequence_order_does_change_the_hash() -> None:
    # Order is meaningful in a sequence, unlike a set. Losing this would let an
    # audit chain be reordered without detection.
    assert Canonical.digest([1, 2]) != Canonical.digest([2, 1])


# ── Equal values must agree ──────────────────────────────────────────────────────


@pytest.mark.unit
def test_equal_decimals_with_different_scale_agree() -> None:
    assert Decimal("1.10") == Decimal("1.1")
    assert Canonical.digest(Decimal("1.10")) == Canonical.digest(Decimal("1.1"))


@pytest.mark.unit
def test_decimals_encode_positionally_not_scientifically() -> None:
    # An auditor following VERIFY.md by hand should not have to parse exponents.
    assert b"12400" in Canonical.encode(Decimal("12400.00"))
    assert b"E+" not in Canonical.encode(Decimal("12400.00"))


@pytest.mark.unit
def test_same_instant_in_different_timezones_agrees() -> None:
    utc = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)
    lagos = datetime(2026, 7, 31, 13, 0, tzinfo=timezone(timedelta(hours=1)))
    assert utc == lagos
    assert Canonical.digest(utc) == Canonical.digest(lagos)


@pytest.mark.unit
def test_enum_hashes_as_its_value() -> None:
    assert Canonical.digest(Colour.RED) == Canonical.digest("red")


# ── Distinct values must NOT collide ─────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.security
def test_bool_does_not_collapse_into_int() -> None:
    # bool is a subclass of int. Encoding True as 1 would make an approved flag
    # indistinguishable from a count.
    assert Canonical.digest(True) != Canonical.digest(1)
    assert Canonical.digest(False) != Canonical.digest(0)


@pytest.mark.unit
@pytest.mark.security
@pytest.mark.parametrize(
    "value",
    [
        1.5,
        Decimal("1.5"),
        datetime(2026, 7, 31, 12, 0, tzinfo=UTC),
        date(2026, 7, 31),
        b"bytes",
        Colour.ONE,
    ],
    ids=["float", "decimal", "datetime", "date", "bytes", "enum-int"],
)
def test_value_does_not_collide_with_its_string_form(value: object) -> None:
    # The str() fallback that json.dumps(default=str) would apply is a forgery
    # primitive: any object whose repr matches a string would share its hash.
    assert Canonical.digest(value) != Canonical.digest(str(value))


@pytest.mark.unit
@pytest.mark.security
def test_typed_wrappers_do_not_collide_with_each_other() -> None:
    hashes = {
        Canonical.digest(1.0),
        Canonical.digest(Decimal("1.0")),
        Canonical.digest(1),
        Canonical.digest("1"),
    }
    assert len(hashes) == 4


@pytest.mark.unit
@pytest.mark.security
def test_distinct_actions_do_not_collide() -> None:
    # The threat-model case: a grant for one payment must not authorise another.
    authorised = {"tool": "pay", "to": "X", "amount": Decimal("12400.00")}
    attacker = {"tool": "pay", "to": "Y", "amount": Decimal("500000.00")}
    assert Canonical.digest(authorised) != Canonical.digest(attacker)


@pytest.mark.unit
@pytest.mark.security
def test_mapping_does_not_collide_with_sequence_of_pairs() -> None:
    assert Canonical.digest({"a": 1}) != Canonical.digest([["a", 1]])


# ── Ambiguous input is rejected, never coerced ───────────────────────────────────


@pytest.mark.unit
@pytest.mark.parametrize(
    "value",
    [float("nan"), float("inf"), float("-inf")],
    ids=["nan", "inf", "-inf"],
)
def test_non_finite_floats_are_rejected(value: float) -> None:
    with pytest.raises(CanonicalisationError):
        Canonical.digest(value)


@pytest.mark.unit
def test_non_finite_decimals_are_rejected() -> None:
    with pytest.raises(CanonicalisationError):
        Canonical.digest(Decimal("NaN"))


@pytest.mark.unit
def test_naive_datetimes_are_rejected() -> None:
    # A naive datetime is ambiguous by an unknown offset; accepting one would make
    # the hash depend on the server's timezone.
    with pytest.raises(CanonicalisationError, match="naive"):
        Canonical.digest(datetime(2026, 7, 31, 12, 0))


@pytest.mark.unit
def test_non_string_mapping_keys_are_rejected() -> None:
    with pytest.raises(CanonicalisationError, match="not str"):
        Canonical.digest({1: "a"})


@pytest.mark.unit
def test_unsupported_types_are_rejected_not_stringified() -> None:
    class Opaque:
        def __str__(self) -> str:
            return "harmless"

    with pytest.raises(CanonicalisationError, match="unsupported type"):
        Canonical.digest(Opaque())


@pytest.mark.unit
def test_error_message_says_what_to_do() -> None:
    with pytest.raises(CanonicalisationError) as exc:
        Canonical.digest(object())
    assert "never guesses" in str(exc.value)


# ── Property-based ───────────────────────────────────────────────────────────────

_json_like = st.recursive(
    st.none()
    | st.booleans()
    | st.integers()
    | st.text()
    | st.binary()
    | st.decimals(allow_nan=False, allow_infinity=False)
    | st.datetimes(timezones=st.just(UTC)),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=25,
)


@pytest.mark.property
@given(_json_like)
@settings(max_examples=300)
def test_hashing_is_deterministic(value: object) -> None:
    try:
        first = Canonical.digest(value)
    except CanonicalisationError:
        # A refusal must be just as deterministic as a digest: a value that is
        # ambiguous now must not become acceptable on a later call.
        with pytest.raises(CanonicalisationError):
            Canonical.digest(value)
        return
    assert first == Canonical.digest(value)


@pytest.mark.property
@given(_json_like)
@settings(max_examples=300)
def test_canonicalisation_either_digests_or_refuses(value: object) -> None:
    """The stronger property, and the one that matters.

    Not "everything hashes" — a mapping whose only key is a reserved tag is
    deliberately rejected, because it would otherwise share a hash with the scalar it
    imitates. What must hold is that there is no third outcome: never a short digest,
    never a non-hex one, never a plausible answer for an ambiguous input.
    """
    try:
        digest = Canonical.digest(value)
    except CanonicalisationError:
        return
    assert len(digest) == 64
    assert all(character in "0123456789abcdef" for character in digest)


@pytest.mark.property
@given(st.dictionaries(st.text(), st.integers(), min_size=2))
@settings(max_examples=200)
def test_hash_is_independent_of_insertion_order(mapping: dict[str, int]) -> None:
    reversed_insert = dict(reversed(list(mapping.items())))
    assert Canonical.digest(mapping) == Canonical.digest(reversed_insert)


@pytest.mark.property
@given(st.floats(allow_nan=False, allow_infinity=False))
@settings(max_examples=200)
def test_finite_floats_round_trip_through_repr(value: float) -> None:
    # The encoding relies on repr() being shortest-round-trip. If that ever stops
    # holding, distinct floats could share an encoding.
    assert float(repr(value)) == value or math.isclose(float(repr(value)), value)
    assert Canonical.digest(value) == Canonical.digest(value)


@pytest.mark.property
@given(st.binary())
@settings(max_examples=200)
def test_bytes_are_hashed_by_content(payload: bytes) -> None:
    assert Canonical.digest(payload) == Canonical.digest(bytes(payload))


@pytest.mark.unit
def test_hash_bytes_matches_known_sha256() -> None:
    # Pinned against a value anyone can reproduce with sha256sum, so a change to
    # the hash function cannot pass silently.
    assert Canonical.digest_bytes(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
