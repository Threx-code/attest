"""Witness adapters — the three the design names, and nothing pretending to be a fourth.

.. code-block:: text

    InMemoryWitness         tests, air-gapped deployments.        NOT a witness.
    TransparencyLogWitness  a third-party append-only log.        LOGGED
    Rfc3161Witness          an RFC 3161 timestamping authority.   TIMESTAMPED

Anchoring is deliberately absent. The design takes no position on which public medium
a host anchors to, and a "generic anchoring adapter" would be a configuration file
pretending to be a mechanism.

**The in-memory witness is not a witness.** It lives in the same process as the thing it
is supposed to be independent of, so it defeats nothing — a host that can rewrite its
chain can rewrite this too. It says so when asked, because the failure mode here is a
deployment that believes it is witnessed.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, ClassVar, Final, cast
from urllib.parse import quote, urlsplit

from attest.capabilities.witness import (
    ConsistencyProof,
    InclusionProof,
    MerkleTree,
    WitnessLevel,
    WitnessReceipt,
)
from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import Hash, Hashes

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from attest.adapters.rfc3161 import Rfc3161Verifier
    from attest.capabilities.witness import Checkpoint

__all__ = ["InMemoryWitness", "Rfc3161Witness", "TransparencyLogWitness", "WitnessError"]


class Endpoint:
    """What an external witness endpoint must be, checked at construction.

    ``startswith("https://")`` was the only control, and it admits
    ``https://user@internal-host/``, ``https://169.254.169.254/…`` and every private
    address. These URLs are deployment configuration rather than user input, so the
    exposure is a misconfiguration or a compromised config store — real, and cheap to
    close.

    Literal private and link-local addresses are refused. Names are **not** resolved:
    resolution here would be a check the request does not repeat, and DNS can answer
    differently the second time. A deployment that needs certainty pins egress at the
    network, which is where that control belongs.
    """

    BLOCKED_LITERALS: ClassVar[tuple[str, ...]] = (
        "169.254.",  # link-local, including the cloud metadata services
        "127.",
        "10.",
        "192.168.",
        "0.0.0.0",  # noqa: S104 # nosec B104 - refused as a target, not bound to
        "[::1]",
        "localhost",
        "metadata.google.internal",
    )

    @classmethod
    def assert_reachable_target(cls, url: str, *, what: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            raise ContractViolation(
                f"{what} {url!r} is not https. The whole value of an external witness "
                f"is that its answers did not come from the host; over plain http they "
                f"may as well have."
            )
        if parsed.username or parsed.password:
            raise ContractViolation(
                f"{what} {url!r} carries userinfo. `https://user@internal-host/` reads "
                f"as one host and connects to another, which is the oldest way to make "
                f"a URL check pass while reaching somewhere else."
            )
        host = (parsed.hostname or "").lower()
        if not host:
            raise ContractViolation(f"{what} {url!r} names no host")
        if any(host.startswith(blocked) for blocked in cls.BLOCKED_LITERALS):
            raise ContractViolation(
                f"{what} {url!r} points at {host!r}, which is loopback, link-local or "
                f"private. A witness inside the trust boundary witnesses nothing, and "
                f"169.254.169.254 is a cloud credential endpoint."
            )

    @classmethod
    def assert_ok(cls, url: str, *, what: str) -> None:
        cls.assert_reachable_target(url, what=what)


class WitnessError(ContractViolation):
    """The external witness could not be reached, or answered something unusable.

    Raised rather than swallowed. A witnessing step that fails quietly leaves a
    deployment believing it has external evidence it does not have, which is worse
    than not witnessing at all — it is the same exposure plus false confidence.
    """


class InMemoryWitness:
    """A witness that witnesses nothing. For tests and air-gapped builds.

    It keeps its own copy of the tree so inclusion proofs are real and the plumbing can
    be exercised end to end. What it cannot provide is the only property that matters:
    independence. It runs in the process it is meant to hold to account.
    """

    LEVEL: Final = WitnessLevel.NONE

    __slots__ = ("_by_root", "_leaves", "_submissions")

    def __init__(self, leaves: tuple[Hash, ...] = ()) -> None:
        self._leaves = MerkleTree(leaves)
        self._submissions: list[Checkpoint] = []
        self._by_root: dict[Hash, Checkpoint] = {}

    @property
    def independent(self) -> bool:
        """Always False, and asked by the export path before it claims a bundle is witnessed."""
        return False

    @property
    def submissions(self) -> tuple[Checkpoint, ...]:
        return tuple(self._submissions)

    def observe(self, leaf: Hash) -> None:
        """Mirror a leaf, so inclusion proofs can be served."""
        self._leaves.append(leaf)

    def submit(self, checkpoint: Checkpoint) -> WitnessReceipt:
        self._submissions.append(checkpoint)
        self._by_root[checkpoint.root] = checkpoint
        return WitnessReceipt(
            checkpoint=checkpoint,
            reference=f"memory:{len(self._submissions)}",
            witnessed_at=checkpoint.created_at,
            detail={"independent": "false", "warning": "in-process; defeats nothing"},
        )

    def inclusion_proof(self, leaf: Hash) -> InclusionProof | None:
        try:
            index = self._leaves.leaves.index(leaf)
        except ValueError:
            return None
        return self._leaves.inclusion_proof(index)

    def consistency_proof(self, old: Checkpoint, new: Checkpoint) -> ConsistencyProof | None:
        if old.tree_size > len(self._leaves) or new.tree_size > len(self._leaves):
            return None
        return MerkleTree(self._leaves.leaves[: new.tree_size]).consistency_proof(old.tree_size)


class TransparencyLogWitness:
    """A client for a third-party append-only log that speaks JSON over HTTPS.

    The wire format is deliberately minimal — ``POST {base}/checkpoints``, ``GET
    {base}/proofs/{leaf}``, ``GET {base}/consistency?old=&new=`` — because there is no
    single standard here and inventing an elaborate one would fit fewer logs, not more.
    A host whose log speaks something else subclasses and overrides three methods.

    ``verify_root`` is the setting that matters. A log that returns a root differing
    from the one submitted has either lost the submission or is answering about a
    different tree, and accepting it would record external evidence for a commitment
    nobody made.
    """

    LEVEL: Final = WitnessLevel.LOGGED

    __slots__ = ("_base", "_headers", "_timeout", "_verify_root")

    def __init__(
        self,
        base_url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = 10.0,
        verify_root: bool = True,
    ) -> None:
        Endpoint.assert_reachable_target(base_url, what="witness base URL")
        self._base = base_url.rstrip("/")
        self._headers = dict(headers or {})
        self._timeout = timeout
        self._verify_root = verify_root

    @property
    def independent(self) -> bool:
        return True

    def submit(self, checkpoint: Checkpoint) -> WitnessReceipt:
        answer = self._post(
            "/checkpoints",
            {
                "root": str(checkpoint.root),
                "tree_size": checkpoint.tree_size,
                "created_at": checkpoint.created_at.isoformat(),
                "signature": checkpoint.signature,
            },
        )
        reference = str(answer.get("reference") or answer.get("index") or "")
        if not reference:
            raise WitnessError(
                f"{self._base} accepted the checkpoint but returned no reference. "
                f"Without one there is nothing to ask it for later, so the submission "
                f"is unverifiable and must not be recorded as witnessed."
            )
        returned = answer.get("root")
        if self._verify_root and returned is not None and str(returned) != str(checkpoint.root):
            raise WitnessError(
                f"{self._base} acknowledged root {returned!r} for a submission of "
                f"{checkpoint.root!r}. The log is answering about a different tree."
            )
        return WitnessReceipt(
            checkpoint=checkpoint,
            reference=reference,
            witnessed_at=checkpoint.created_at,
            detail={"log": self._base},
        )

    def inclusion_proof(self, leaf: Hash) -> InclusionProof | None:
        # Validated and escaped. `Hash` is a NewType with no runtime check, so a value
        # containing "?", "#" or "../" used to alter the request path against the log's
        # API rather than being rejected.
        answer = self._get(f"/proofs/{quote(Hashes.parse(leaf, where='leaf'), safe='')}")
        if answer is None:
            return None
        return InclusionProof(
            leaf=leaf,
            index=int(cast("int", answer["index"])),
            tree_size=int(cast("int", answer["tree_size"])),
            path=tuple(
                (str(side), Hash(str(node)))
                for side, node in cast("Sequence[tuple[str, str]]", answer["path"])
            ),
        )

    def consistency_proof(self, old: Checkpoint, new: Checkpoint) -> ConsistencyProof | None:
        answer = self._get(f"/consistency?old={old.tree_size}&new={new.tree_size}")
        if answer is None:
            return None
        return ConsistencyProof(
            old_size=old.tree_size,
            new_size=new.tree_size,
            path=tuple(Hash(str(node)) for node in cast("Sequence[str]", answer["path"])),
        )

    def _post(self, path: str, body: Mapping[str, object]) -> Mapping[str, object]:
        request = urllib.request.Request(  # noqa: S310 — the scheme is checked in __init__
            f"{self._base}{path}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **self._headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310 - the https scheme is enforced in __init__
                request, timeout=self._timeout
            ) as response:
                decoded = json.loads(response.read())
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise WitnessError(f"could not submit a checkpoint to {self._base}: {exc}") from exc
        if not isinstance(decoded, dict):
            raise WitnessError(f"{self._base} returned {type(decoded).__name__}, not an object")
        return decoded

    def _get(self, path: str) -> Mapping[str, object] | None:
        request = urllib.request.Request(  # noqa: S310 — the scheme is checked in __init__
            f"{self._base}{path}", headers=self._headers, method="GET"
        )
        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310 - the https scheme is enforced in __init__
                request, timeout=self._timeout
            ) as response:
                decoded = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise WitnessError(f"{self._base} answered {exc.code} for {path}") from exc
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            raise WitnessError(f"could not read {path} from {self._base}: {exc}") from exc
        return decoded if isinstance(decoded, dict) else None


class Rfc3161Witness:
    """An RFC 3161 timestamping authority. Defeats backdating a whole window.

    A TSA signs *that a hash existed at a time*. It has no view of the tree, so it
    cannot answer inclusion or consistency — both return ``None`` rather than something
    that would read as a proof. Pairing this with receipts is what the design intends:
    the TSA stops the clock being moved, the receipts stop a run being left out.

    The response token is stored **verbatim**, base64-encoded. Verifying it needs the
    TSA's certificate chain and is done outside this process::

        openssl ts -verify -in token.tsr -queryfile request.tsq -CAfile tsa-chain.pem

    Parsing it here would mean shipping an ASN.1 stack and a certificate validator, and
    a half-implemented verifier that returns True is worse than one that does not exist.
    """

    LEVEL: Final = WitnessLevel.NONE
    """The level with **no verifier configured**. See :attr:`level`.

    NONE, not TIMESTAMPED.

    ``submit`` posts a TimeStampReq and accepts whatever comes back with one check:
    that it is non-empty. It does not parse ``PKIStatusInfo`` — a *rejection* is a
    non-empty token and passed — does not check that the token's ``messageImprint``
    matches the root submitted, does not verify the TSA's signature or certificate
    chain, and sent no nonce, which is the RFC's own replay defence.

    So one previously-obtained token satisfied every root forever, and an operator
    pointing this at an endpoint they control earned the level that exists specifically
    to defeat operator backdating. This module's own docstring names "a deployment that
    believes it is witnessed" as the thing it must avoid.

    Claiming NONE is the honest level for what is implemented: the token is obtained and
    stored verbatim, which is useful, and nothing here has checked it.
    """

    CHECKED_LEVEL: Final = WitnessLevel.TIMESTAMPED
    """The level once a :class:`~attest.adapters.rfc3161.Rfc3161Verifier` is wired.

    Earned rather than declared: the verifier compares the token's imprint to the root
    submitted, matches the nonce, verifies the signature over the signed attributes,
    requires a critical timeStamping EKU, and walks the chain to an anchor this
    deployment chose. Only then is the level the one the docs describe.
    """

    SHA256_OID: Final = bytes.fromhex("608648016503040201")
    CONTENT_TYPE: Final = "application/timestamp-query"

    __slots__ = ("_headers", "_timeout", "_url", "_verifier")

    def __init__(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = 10.0,
        verifier: Rfc3161Verifier | None = None,
    ) -> None:
        Endpoint.assert_reachable_target(url, what="TSA URL")
        self._url = url
        self._headers = dict(headers or {})
        self._timeout = timeout
        self._verifier = verifier
        """Supplied, never constructed here. It needs trust anchors, and a default set
        would be this package deciding whose timestamps a regulated deployment trusts."""

    @property
    def level(self) -> WitnessLevel:
        """TIMESTAMPED only when a verifier is wired. Otherwise NONE.

        The level follows what has actually been checked rather than what the class is
        called. Without a verifier the token is obtained, stored verbatim and not
        examined — useful, and not a defence against backdating.
        """
        return self.CHECKED_LEVEL if self._verifier is not None else self.LEVEL

    @property
    def independent(self) -> bool:
        """True only once the response is verified.

        The authority is genuinely a third party either way. What was missing was any
        check that the bytes it returned are about *this* root and were signed by *that*
        authority — and a deployment cannot rely on an unexamined token however
        independent its source.
        """
        return self._verifier is not None

    def submit(self, checkpoint: Checkpoint) -> WitnessReceipt:
        import base64
        import secrets

        # The RFC's own replay defence, and it was omitted. Without it the TSA's
        # response cannot be tied to this request at all.
        nonce = secrets.randbits(64)
        query = self.time_stamp_request(checkpoint.root, nonce=nonce)
        request = urllib.request.Request(  # noqa: S310 — the scheme is checked in __init__
            self._url,
            data=query,
            headers={"Content-Type": self.CONTENT_TYPE, **self._headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310  # nosec B310 - the https scheme is enforced in __init__
                request, timeout=self._timeout
            ) as response:
                token = response.read()
        except (urllib.error.URLError, TimeoutError) as exc:
            raise WitnessError(f"could not obtain a timestamp from {self._url}: {exc}") from exc
        if not token:
            raise WitnessError(f"{self._url} returned an empty timestamp token")
        detail = self._examine(token, checkpoint, nonce=nonce)
        return WitnessReceipt(
            checkpoint=checkpoint,
            reference=base64.b64encode(token).decode(),
            witnessed_at=checkpoint.created_at,
            detail=detail,
        )

    def _examine(self, token: bytes, checkpoint: Checkpoint, *, nonce: int) -> dict[str, str]:
        """Verify the response where a verifier exists, and say so either way.

        With one, a token that fails raises: a timestamp that does not verify is not
        weak evidence, it is absent evidence, and recording it would report a level the
        deployment does not have.

        Without one, the status is still checked — a rejection is a well-formed,
        non-empty response — and the receipt says ``verified: no`` in as many words. The
        failure this module exists to avoid is a deployment that believes it is
        witnessed, and silence about what was skipped is how that happens.
        """
        import json

        if self._verifier is None:
            self.assert_granted(token)
            return {
                "tsa": self._url,
                "format": "rfc3161-der-base64",
                "nonce": str(nonce),
                "verified": "no",
                "level": str(self.LEVEL),
                "why": (
                    "no Rfc3161Verifier is wired, so the signature, the message imprint "
                    "and the certificate chain are unchecked. Pass one, with the trust "
                    "anchors this deployment has chosen."
                ),
                "verify_with": (
                    "openssl ts -verify -in token.tsr -queryfile request.tsq "
                    "-CAfile <your TSA chain>"
                ),
            }

        assertion = self._verifier.verify(
            token, root=checkpoint.root, nonce=nonce, requested_at=checkpoint.created_at
        )
        return {
            "tsa": self._url,
            "format": "rfc3161-der-base64",
            "nonce": str(nonce),
            "verified": "yes",
            "level": str(self.CHECKED_LEVEL),
            # The assertion travels with the token, so a bundle carries what the check
            # covered and what it did not — a result read without its limits gets read
            # as a stronger claim than it is.
            "assertion": json.dumps(assertion.as_dict(), sort_keys=True),
        }

    @classmethod
    def assert_granted(cls, token: bytes) -> None:
        """Refuse a response whose ``PKIStatus`` is not granted.

        A rejection is a well-formed, non-empty TimeStampResp. The only check used to be
        ``if not token``, so a TSA saying "no" earned the same receipt as one saying
        "yes" — and the deployment reported a witness level it did not have.

        This reads the status integer and nothing else. It is not a verification: the
        signature, the certificate chain and the message imprint still need the TSA's
        trust anchor, which is why :attr:`LEVEL` is NONE. Refusing an outright rejection
        is the part that can be done without one.
        """
        status = cls._status(token)
        if status is None:
            raise WitnessError(
                "the timestamp response could not be parsed far enough to read its "
                "PKIStatus. Refusing rather than storing bytes of unknown meaning: a "
                "rejection is a non-empty token too."
            )
        if status not in (0, 1):  # granted, grantedWithMods
            raise WitnessError(
                f"the timestamping authority refused the request (PKIStatus {status}). "
                f"Storing the response would record a witness that declined to witness."
            )

    @staticmethod
    def _status(token: bytes) -> int | None:
        """The ``PKIStatus`` integer from the front of a ``TimeStampResp``.

        ``TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }``
        and ``PKIStatusInfo ::= SEQUENCE { status INTEGER, ... }`` — so the value is the
        first INTEGER inside the second SEQUENCE, at a fixed shallow offset. Walked by
        hand for the same reason the request is built by hand: one small structure does
        not justify an ASN.1 stack in a package whose core has no dependencies.
        """
        cursor = 0
        for _ in range(2):  # outer TimeStampResp, then PKIStatusInfo
            if cursor >= len(token) or token[cursor] != 0x30:
                return None
            cursor += 1
            cursor = Rfc3161Witness._skip_length(token, cursor)
            if cursor < 0:
                return None
        if cursor >= len(token) or token[cursor] != 0x02:  # INTEGER
            return None
        cursor += 1
        if cursor >= len(token):
            return None
        width = token[cursor]
        cursor += 1
        if width == 0 or cursor + width > len(token):
            return None
        return int.from_bytes(token[cursor : cursor + width], "big")

    @staticmethod
    def _skip_length(token: bytes, cursor: int) -> int:
        """Step past a DER length field, returning the offset of the content."""
        if cursor >= len(token):
            return -1
        first = token[cursor]
        if first < 0x80:
            return cursor + 1
        return cursor + 1 + (first & 0x7F)

    def inclusion_proof(self, leaf: Hash) -> InclusionProof | None:  # noqa: ARG002
        """Always ``None``. A TSA does not hold a tree.

        Returning something here would be inventing a proof, which is the one thing
        this module must never do.
        """
        return None

    def consistency_proof(
        self,
        old: Checkpoint,  # noqa: ARG002 — a TSA holds no tree; the parameters exist for the port
        new: Checkpoint,  # noqa: ARG002
    ) -> ConsistencyProof | None:
        """Always ``None``. Timestamps stop backdating, not rewriting."""
        return None

    @classmethod
    def time_stamp_request(cls, root: Hash, *, nonce: int | None = None) -> bytes:
        """A DER-encoded RFC 3161 ``TimeStampReq`` over ``root``.

        Built by hand rather than by pulling in an ASN.1 library: this is one fixed
        structure of four fields, and the dependency would travel into every install of
        a package whose core has none.

        ``certReq`` is TRUE so the TSA returns its certificate — a token whose signer
        cannot be identified cannot be verified by the third party it exists to
        convince.
        """
        digest = bytes.fromhex(root)
        algorithm = cls._sequence(cls._oid(cls.SHA256_OID) + cls._null())
        imprint = cls._sequence(algorithm + cls._octet_string(digest))
        body = cls._integer(1) + imprint
        if nonce is not None:
            body += cls._integer(nonce)
        return cls._sequence(body + cls._boolean(value=True))

    # ── A DER writer, small enough to read in one sitting ────────────────────

    @staticmethod
    def _length(payload: bytes) -> bytes:
        size = len(payload)
        if size < 0x80:
            return bytes([size])
        encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(encoded)]) + encoded

    @classmethod
    def _tagged(cls, tag: int, payload: bytes) -> bytes:
        return bytes([tag]) + cls._length(payload) + payload

    @classmethod
    def _sequence(cls, payload: bytes) -> bytes:
        return cls._tagged(0x30, payload)

    @classmethod
    def _octet_string(cls, payload: bytes) -> bytes:
        return cls._tagged(0x04, payload)

    @classmethod
    def _oid(cls, payload: bytes) -> bytes:
        return cls._tagged(0x06, payload)

    @classmethod
    def _null(cls) -> bytes:
        return b"\x05\x00"

    @classmethod
    def _boolean(cls, *, value: bool) -> bytes:
        return cls._tagged(0x01, b"\xff" if value else b"\x00")

    @classmethod
    def _integer(cls, value: int) -> bytes:
        if value == 0:
            return cls._tagged(0x02, b"\x00")
        width = (value.bit_length() + 8) // 8  # a leading zero when the top bit is set
        return cls._tagged(0x02, value.to_bytes(width, "big"))
