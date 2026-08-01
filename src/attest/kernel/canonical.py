"""Canonical serialisation and content addressing.

Every integrity guarantee in Attest reduces to this module. An ``action_hash`` binds
a grant to exact arguments; the audit chain links events; evidence is content-addressed;
a dataset is committed by Merkle root. All of them call :func:`content_hash`.

So the encoding has one job: **the same value must produce the same bytes, on every
machine, on every supported Python, forever.** A canonicaliser that is merely usually
stable produces attestations that are merely usually verifiable.

Two rules follow, and both are deliberate:

*Unknown types are rejected, never coerced.* The obvious implementation passes
``default=str`` to :func:`json.dumps`, which silently stringifies anything it does not
recognise. That makes two distinct objects hash identically whenever their ``str()``
happens to agree, which is a forged-evidence primitive rather than a serialisation
convenience.

*Ambiguity is rejected.* Non-finite floats, non-string mapping keys, and duplicate keys
after coercion all raise rather than resolve to something plausible.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from collections.abc import Mapping, Sequence, Set
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Final

__all__ = ["NULL_HASH", "Canonical", "CanonicalisationError"]

# The predecessor hash of the first event in any chain. A fixed, recognisable
# sentinel rather than an empty string, so a truncated chain cannot masquerade
# as a chain that simply started here.
NULL_HASH: Final = "0" * 64

_HASH = hashlib.sha256


class CanonicalisationError(TypeError):
    """A value cannot be canonicalised unambiguously.

    Raised rather than falling back to a string representation. See the module
    docstring: silent coercion here would let distinct values share a hash.
    """


class Canonical:
    """Canonical encoding and content addressing.

    A namespace rather than loose functions, so every call site reads the same way and
    the four operations that must agree stay visibly together: a change to `form`
    changes every hash in the system.
    """

    @staticmethod
    def _fail(value: object, reason: str) -> CanonicalisationError:
        """Build the rejection. A method rather than a module function so every
        refusal in this class is phrased identically."""
        return CanonicalisationError(
            f"cannot canonicalise {type(value).__name__}: {reason}. "
            f"Convert it to a supported type explicitly - canonicalisation never guesses."
        )

    @staticmethod
    def form(value: Any) -> Any:
        """Reduce ``value`` to a JSON-encodable form with a single representation.

        Supported: ``None``, ``bool``, ``int``, finite ``float``, ``str``, ``bytes``,
        ``Decimal``, ``datetime``, ``date``, ``Enum``, and any mapping, sequence or set
        thereof.

        Ordering is imposed where the source type has none: mapping keys sort
        lexicographically, and sets sort by their canonical encoding, so two equal sets
        always encode identically regardless of insertion or iteration order.
        """
        # bool before int: bool is a subclass of int and must stay true/false, not 1/0.
        if value is None or isinstance(value, bool):
            return value

        if isinstance(value, int):
            return value

        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                raise Canonical._fail(value, "non-finite floats have no canonical JSON form")
            # repr() is the shortest string that round-trips exactly (PEP 3141 / CPython
            # 3.1+), so it is stable across platforms for IEEE-754 doubles. Encoding as a
            # string rather than a JSON number also stops a reader's float parser from
            # becoming part of the trust chain.
            return {"__float__": repr(value)}

        if isinstance(value, str):
            return value

        if isinstance(value, bytes | bytearray):
            return {"__bytes__": base64.b64encode(bytes(value)).decode("ascii")}

        if isinstance(value, Decimal):
            if not value.is_finite():
                raise Canonical._fail(value, "non-finite Decimals have no canonical form")
            # Normalised so Decimal("1.10") and Decimal("1.1") - which compare equal -
            # cannot produce different hashes. Formatted with "f" rather than str() so
            # the result is positional ("12400") rather than scientific ("1.24E+4"):
            # an auditor verifying a bundle by hand should not have to parse exponents.
            return {"__decimal__": format(value.normalize(), "f")}

        if isinstance(value, datetime):
            if value.tzinfo is None:
                raise Canonical._fail(
                    value,
                    "naive datetimes are ambiguous; attach a timezone (the Clock port "
                    "supplies aware values)",
                )
            # Normalise to UTC with microsecond precision so the same instant expressed
            # in two timezones hashes identically.
            return {"__datetime__": value.astimezone(UTC).isoformat(timespec="microseconds")}

        if isinstance(value, date):
            return {"__date__": value.isoformat()}

        if isinstance(value, Enum):
            return Canonical.form(value.value)

        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            if len(value) == 1 and next(iter(value)) in Canonical.RESERVED_TAGS:
                # A mapping whose only key is a tag is byte-identical to the tagged
                # scalar. Refused here rather than in the codec, because
                # `Action.action_hash` calls `digest` directly: a check that lived only
                # at encode time would let a grant issued for one action authorise
                # another, which is the exact binding actions exist to make.
                raise Canonical._fail(
                    value,
                    f"its only key is {next(iter(value))!r}, which is reserved for a "
                    f"tagged scalar and would make the two indistinguishable. Nest it "
                    f"under another key, or add a sibling",
                )
            for key, item in value.items():
                if not isinstance(key, str):
                    raise Canonical._fail(
                        value, f"mapping key {key!r} is {type(key).__name__}, not str"
                    )
                if key in out:  # pragma: no cover - defensive; dict keys are unique
                    raise Canonical._fail(value, f"duplicate mapping key {key!r}")
                out[key] = Canonical.form(item)
            return {k: out[k] for k in sorted(out)}

        if isinstance(value, Set):
            # Sets have no inherent order, so impose one on the *encoded* elements —
            # sorting the raw elements would fail on mixed types. Tagged because an
            # untagged list of encoded strings is byte-identical to a plain list of
            # those strings, so {"a"} and ['"a"'] would share a hash.
            return {"__set__": sorted(Canonical.encode(item).decode("utf-8") for item in value)}

        if isinstance(value, Sequence):
            return [Canonical.form(item) for item in value]

        raise Canonical._fail(value, "unsupported type")

    @staticmethod
    def encode(value: Any) -> bytes:
        """Encode ``value`` to its canonical UTF-8 bytes."""
        return Canonical.encode_form(Canonical.form(value))

    @staticmethod
    def encode_form(form: Any) -> bytes:
        """Serialise an **already-canonical** form, without re-applying :meth:`form`.

        The distinction matters to anything that builds a canonical form itself, such
        as :class:`~attest.kernel.codec.AttestationCodec`. Passing such a form back
        through ``form`` would tag it a second time — a ``{"__decimal__": "1"}`` that
        the codec produced deliberately would become a *mapping containing* a decimal
        tag, and would no longer decode to a decimal. One pass, or none.
        """
        return json.dumps(
            form,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    #: The sentinel keys :meth:`form` uses to tag scalars that JSON cannot express.
    #: A mapping in user data whose *only* key is one of these is indistinguishable
    #: from a tagged scalar, so :class:`~attest.kernel.codec.AttestationCodec` refuses
    #: to encode one rather than let it come back as a different type.
    RESERVED_TAGS: Final = frozenset(
        {"__float__", "__bytes__", "__decimal__", "__datetime__", "__date__", "__set__"}
    )

    @staticmethod
    def revive(form: Any) -> Any:
        """Invert :meth:`form` for the tagged scalars.

        The inverse is partial by construction, and deliberately so: ``form`` erases
        the difference between a tuple and a list, between a set and a sorted list of
        encoded strings, and between an enum and its value. Those are restored by the
        *field* being decoded, which knows the type it wants —
        :class:`~attest.kernel.codec.AttestationCodec` does that. What cannot be
        recovered from the field alone is a scalar's type, and that is exactly what
        this restores.

        Building the codec on this rather than on a parallel decoder is what keeps the
        two from drifting: a change to ``form`` changes every hash in the system, and
        it would now also fail these round-trips loudly instead of silently producing
        records that no longer decode.
        """
        if isinstance(form, Mapping):
            if len(form) == 1:
                key, raw = next(iter(form.items()))
                if key == "__float__":
                    return float(raw)
                if key == "__bytes__":
                    return base64.b64decode(raw)
                if key == "__decimal__":
                    return Decimal(raw)
                if key == "__datetime__":
                    return datetime.fromisoformat(raw)
                if key == "__date__":
                    return date.fromisoformat(raw)
                if key == "__set__":
                    return {json.loads(item) for item in raw}
            return {key: Canonical.revive(item) for key, item in form.items()}
        if isinstance(form, list):
            return [Canonical.revive(item) for item in form]
        return form

    @staticmethod
    def digest_bytes(data: bytes) -> str:
        """SHA-256 of raw bytes, as lowercase hex."""
        return _HASH(data).hexdigest()

    @staticmethod
    def digest(value: Any) -> str:
        """The content address of ``value``: SHA-256 over its canonical encoding."""
        return Canonical.digest_bytes(Canonical.encode(value))
