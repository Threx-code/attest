"""RFC 3161 timestamp verification. The thing that turns a stored token into evidence.

Obtaining a token is easy and proves nothing. Everything that makes a timestamp worth
having is in the checking, and until this module existed none of it happened: a
rejection is a non-empty response and passed, one token satisfied every root forever
because nothing compared the imprint, and no signature was ever verified — so an
operator who pointed the client at an endpoint they controlled earned the witness level
that exists specifically to defeat operator backdating.

.. code-block:: text

    WHAT IS CHECKED                          WHY IT MATTERS
    ─────────────────────────────────        ────────────────────────────────────
    PKIStatus is granted                     a rejection is a well-formed response
    messageImprint == the root submitted     else one token witnesses everything
    nonce == the nonce sent                  else a replayed token passes
    eContent digest == message-digest attr   the signature covers the attributes,
                                             not the content, so this is the link
    signature over signedAttrs               the only thing binding it to the TSA
    EKU contains id-kp-timeStamping          RFC 3161 §2.3: a general-purpose
      and is critical                        certificate must not sign timestamps
    validity window covers genTime           an expired TSA key is not authority
    chains to a configured trust anchor      "signed by somebody" is not a witness

.. rubric:: What is deliberately NOT checked

**Revocation.** No CRL, no OCSP. Both need network access at verification time, which
turns an offline evidence check into an online one — and an evidence bundle that cannot
be verified offline is the failure ``docs/assurance/export.md`` is built to avoid. A
deployment that needs revocation checks the chain out of band, on its own schedule.

**Name constraints and policy constraints.** Rarely present on TSA chains, and a
half-implementation of RFC 5280 path validation is worse than an absent one because it
reads as complete.

Both omissions are stated in :class:`TimestampAssertion`, which travels with the result,
so nobody has to read this docstring to know what the green tick means.

.. rubric:: Availability

``asn1crypto`` and ``cryptography`` are **required** dependencies, not an extra.
Verification a deployment has to opt into is a control that is off by default, which is
exactly the defect class this package was audited for fifteen times over. The imports
are still deferred so a deployment that never timestamps never loads them, and the guard
below stays because a vendored or trimmed install can still arrive without them — it
just fails at construction rather than at the first checkpoint.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Final

from attest.kernel.errors import ContractViolation

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from attest.kernel.identifiers import Hash

__all__ = ["Rfc3161Unavailable", "Rfc3161Verifier", "TimestampAssertion", "TimestampInvalid"]


class Rfc3161Unavailable(ContractViolation):
    """The verifier cannot be built.

    Either the parsing libraries are absent — which should not happen, since they are
    required dependencies, and does happen when an install is vendored or trimmed — or
    no trust anchor was supplied.

    Raised at construction either way. A verifier that fails only when the first token
    arrives fails during the first checkpoint of a real deployment, which is the moment
    it was added to protect.
    """


class TimestampInvalid(ContractViolation):
    """A token did not verify. **Never downgraded to a warning.**

    A timestamp that does not verify is not weak evidence, it is absent evidence — and
    a deployment that recorded it anyway would report a witness level it does not have,
    which is the specific failure the witness adapters exist to avoid.
    """


@dataclass(frozen=True, slots=True)
class TimestampAssertion:
    """What a verified token actually establishes, and what it does not.

    Carries its own limits because a result that travels without them gets read as a
    stronger claim than it is — the same reason ``ConformanceReport`` emits its
    ``NOT ESTABLISHED`` block on every run including passes.
    """

    root: str
    """The checkpoint root the authority attested to, as hex."""

    signed_at: datetime
    """``genTime``: when the authority says it saw this root. The whole point."""

    accuracy: str
    """The authority's own stated bound on ``signed_at``, e.g. ``±1s``. Empty when the
    token does not state one, which is common and means the bound is the policy's."""

    authority: str
    """The signing certificate's subject."""

    serial: str
    """The token's serial number, for correlating with the authority's own log."""

    policy: str = ""
    checked: tuple[str, ...] = ()
    """Every check that passed, named. An auditor reading a bundle should not have to
    read this module to learn what the verification covered."""

    not_checked: ClassVar[tuple[str, ...]] = (
        "revocation (CRL/OCSP) — deliberate: it needs the network at verification "
        "time, and a bundle that cannot be verified offline is not a bundle",
        "name constraints, policy constraints and path-length — a partial RFC 5280 "
        "reads as complete, so the omission is named rather than half-implemented",
        "the TSA's own accuracy claim is recorded, not independently corroborated",
    )
    """What a green result does **not** cover.

    Kept complete on purpose. The list was short by an item — CA checking, which is now
    performed rather than omitted — and a stated-omissions list that is itself
    incomplete is worse than none, because it reads as exhaustive.
    """

    def as_dict(self) -> dict[str, Any]:
        """The form that goes into a receipt and an evidence bundle."""
        return {
            "root": self.root,
            "signed_at": self.signed_at.isoformat(),
            "accuracy": self.accuracy,
            "authority": self.authority,
            "serial": self.serial,
            "policy": self.policy,
            "checked": list(self.checked),
            "not_checked": list(self.not_checked),
        }


class Rfc3161Verifier:
    """Verifies a ``TimeStampResp`` against a configured trust anchor.

    ``anchors`` is not optional and has no default. A verifier with no anchor can check
    that a token is internally consistent and self-signed by *somebody*, which is not a
    witness — and a default anchor set would be this package deciding whose timestamps
    a regulated deployment trusts.
    """

    #: RFC 3161 §2.3 requires this EKU, and requires it be the only one.
    TIMESTAMPING_EKU: Final = "1.3.6.1.5.5.7.3.8"

    #: id-ct-TSTInfo. The content type the signed attributes must name.
    TST_INFO: Final = "tst_info"

    __slots__ = ("_anchors", "_max_skew")

    def __init__(self, *, anchors: Sequence[bytes], max_skew_seconds: int = 0) -> None:
        """``anchors`` are DER-encoded certificates the deployment has chosen to trust.

        ``max_skew_seconds`` widens the window in which ``genTime`` is accepted relative
        to when the request was made. Zero by default: a timestamp that claims a moment
        the requester never asked at is the thing being detected, and a generous default
        would hide it.
        """
        self._require_extra()
        if not anchors:
            raise Rfc3161Unavailable(
                "Rfc3161Verifier needs at least one trust anchor. Without one it can "
                "confirm a token is signed by somebody and nothing more, which is not "
                "a witness — and a shipped default would be this package choosing whose "
                "timestamps your regulator sees."
            )
        self._anchors = tuple(anchors)
        self._max_skew = max_skew_seconds

    @staticmethod
    def _require_extra() -> None:
        try:
            import asn1crypto.tsp  # noqa: F401
            import cryptography.x509  # noqa: F401
        except ImportError as exc:
            raise Rfc3161Unavailable(
                "asn1crypto and cryptography are required dependencies of this package "
                "and are not importable, so this install has been vendored or trimmed. "
                "Refusing at construction rather than at the first checkpoint, which is "
                "when a deployment would otherwise discover it."
            ) from exc

    def verify(
        self,
        token: bytes,
        *,
        root: Hash,
        nonce: int | None = None,
        requested_at: datetime | None = None,
    ) -> TimestampAssertion:
        """Check a response end to end, or raise. **There is no partial success.**

        ``root`` is the checkpoint root that was submitted, and ``nonce`` the nonce that
        was sent. Both are compared against the token's own claims, which is what stops
        one token from witnessing every root forever.
        """
        from asn1crypto import tsp

        checked: list[str] = []
        outer, status = self._parse(token, tsp)
        checked.append("response parses as a TimeStampResp")

        self._assert_granted(status, outer)
        checked.append("PKIStatus is granted")

        signed_data = self._token_of(outer)
        info = signed_data["encap_content_info"]["content"].parsed

        self._assert_imprint(info, root)
        checked.append("messageImprint equals the root submitted")

        self._assert_nonce(info, nonce)
        checked.append("nonce equals the nonce sent" if nonce is not None else "no nonce sent")

        signer, certificate = self._signer(signed_data)
        self._assert_content_binding(signer, signed_data)
        checked.append("signed message-digest equals the digest of the TSTInfo")

        self._assert_signature(signer, certificate)
        checked.append("signature verifies against the signing certificate")

        gen_time = info["gen_time"].native
        self._assert_timestamping_certificate(certificate, at=gen_time)
        checked.append("certificate carries a critical timeStamping EKU and is in date")

        self._assert_chains_to_anchor(certificate, signed_data)
        checked.append("certificate chains to a configured trust anchor")

        self._assert_plausible(gen_time, requested_at)
        if requested_at is not None:
            checked.append("genTime is not before the request was made")

        return TimestampAssertion(
            root=str(root),
            signed_at=gen_time,
            accuracy=self._accuracy(info),
            authority=certificate.subject.rfc4514_string(),
            serial=str(info["serial_number"].native),
            policy=str(info["policy"].native or ""),
            checked=tuple(checked),
        )

    # ── The individual checks ────────────────────────────────────────────────

    @staticmethod
    def _parse(token: bytes, tsp: Any) -> Any:
        """Load the response, and reach the status **without** forcing a full parse.

        A rejection legitimately carries no ``timeStampToken`` (RFC 3161 §2.4.2), and
        asn1crypto declares that field required — so forcing the whole structure would
        report a genuine refusal as "malformed" and hide the reason the authority gave.
        The status is read first; whether a token is present is the *next* check's
        business.
        """
        from asn1crypto import core

        try:
            outer = core.Sequence.load(token)
            status = tsp.PKIStatusInfo.load(outer[0].dump())
        except Exception as exc:
            raise TimestampInvalid(
                f"the response is not a well-formed TimeStampResp ({type(exc).__name__}). "
                f"Refusing rather than storing bytes of unknown meaning."
            ) from exc
        return outer, status

    @staticmethod
    def _assert_granted(status: Any, outer: Any) -> None:
        """The status, and then whether a token came with it.

        A rejection carries a reason and no token. Reporting it as "malformed" would
        hide what the authority actually said, which is usually what an operator needs —
        "policy does not permit this request" reads very differently from a fault.
        """
        name = str(status["status"].native)
        if name not in ("granted", "granted_with_mods"):
            reason = status["status_string"].native if status["status_string"] else None
            said = f": {'; '.join(reason)}" if reason else ""
            raise TimestampInvalid(
                f"the authority refused the request (PKIStatus {name!r}){said}. A "
                f"rejection is a well-formed, non-empty response — storing it would "
                f"record a witness that declined to witness."
            )
        if len(outer) < 2:
            raise TimestampInvalid("the response is granted but carries no token")

    @staticmethod
    def _token_of(outer: Any) -> Any:
        """The SignedData inside the timeStampToken."""
        from asn1crypto import cms

        try:
            content = cms.ContentInfo.load(outer[1].dump())
            if str(content["content_type"].native) != "signed_data":
                raise TimestampInvalid(
                    f"the token is {content['content_type'].native!r}, not signed_data; "
                    f"an unsigned timestamp is not a timestamp."
                )
        except TimestampInvalid:
            raise
        except Exception as exc:
            raise TimestampInvalid(
                f"the response is granted and its token does not parse "
                f"({type(exc).__name__}), so there is nothing to verify."
            ) from exc
        return content["content"]

    @staticmethod
    def _assert_imprint(info: Any, root: Hash) -> None:
        """The check that stops one token witnessing everything."""
        algorithm = str(info["message_imprint"]["hash_algorithm"]["algorithm"].native)
        if algorithm != "sha256":
            raise TimestampInvalid(
                f"the token attests to a {algorithm} imprint; this package submits "
                f"sha256 roots, so the token is about a different message."
            )
        imprint = bytes(info["message_imprint"]["hashed_message"].native)
        expected = bytes.fromhex(str(root))
        if imprint != expected:
            raise TimestampInvalid(
                f"the token attests to {imprint.hex()[:16]}… and the root submitted was "
                f"{expected.hex()[:16]}…. This token is about a different message — "
                f"which is how one previously-obtained token satisfies every checkpoint."
            )

    @staticmethod
    def _assert_nonce(info: Any, nonce: int | None) -> None:
        if nonce is None:
            return
        found = info["nonce"].native
        if found is None:
            raise TimestampInvalid(
                "a nonce was sent and the token carries none, so nothing ties this "
                "response to this request. That is the RFC's own replay defence."
            )
        if int(found) != nonce:
            raise TimestampInvalid(
                f"the token answers nonce {found}, and {nonce} was sent. This is a "
                f"replayed response."
            )

    def _signer(self, signed_data: Any) -> tuple[Any, Any]:
        """The SignerInfo and the certificate it names, or a refusal."""
        from cryptography.x509 import load_der_x509_certificate

        infos = signed_data["signer_infos"]
        if len(infos) != 1:
            raise TimestampInvalid(
                f"the token carries {len(infos)} signers; a timestamp with none has no "
                f"authority behind it and one with several has no single one."
            )
        signer = infos[0]
        certificates = signed_data["certificates"]
        if certificates is None or len(certificates) == 0:
            raise TimestampInvalid(
                "the token carries no certificates, so the signature cannot be attributed. "
                "Request certReq=TRUE, which this package's client does."
            )
        wanted = signer["sid"]
        for candidate in certificates:
            parsed = candidate.chosen if hasattr(candidate, "chosen") else candidate
            if self._identifies(wanted, parsed):
                return signer, load_der_x509_certificate(parsed.dump())
        raise TimestampInvalid(
            "the signer identified in the token is not among the certificates it "
            "carries, so the signature is attributed to a certificate nobody supplied."
        )

    @staticmethod
    def _identifies(sid: Any, certificate: Any) -> bool:
        """Match a SignerIdentifier against a certificate, by issuer+serial or key id."""
        name = sid.name
        if name == "issuer_and_serial_number":
            chosen = sid.chosen
            return bool(
                chosen["issuer"] == certificate["tbs_certificate"]["issuer"]
                and chosen["serial_number"].native
                == certificate["tbs_certificate"]["serial_number"].native
            )
        return bytes(sid.chosen.native) == bytes(certificate.key_identifier or b"")

    def _assert_content_binding(self, signer: Any, signed_data: Any) -> None:
        """The signature covers the attributes, so this is what ties it to the content.

        Without it a valid signature over a valid attribute set says nothing about the
        TSTInfo beside it, and the imprint check above would be verifying an unsigned
        payload.
        """
        attributes = signer["signed_attrs"]
        if attributes is None or len(attributes) == 0:
            raise TimestampInvalid(
                "the token has no signed attributes, so its signature covers nothing "
                "that identifies the content it travels with."
            )
        # `.contents` is the raw octet-string bytes; `.native` would hand back the
        # *parsed* TSTInfo, and the digest is over the encoding rather than the object.
        content = bytes(signed_data["encap_content_info"]["content"].contents)
        found: bytes | None = None
        content_type: str | None = None
        for attribute in attributes:
            kind = str(attribute["type"].native)
            if kind == "message_digest":
                found = bytes(attribute["values"][0].native)
            elif kind == "content_type":
                content_type = str(attribute["values"][0].native)
        if content_type != self.TST_INFO:
            raise TimestampInvalid(
                f"the signed content-type is {content_type!r}, not {self.TST_INFO!r}. "
                f"The signature is over something that is not a timestamp."
            )
        if found is None:
            raise TimestampInvalid("the token signs no message-digest attribute")
        algorithm = str(signer["digest_algorithm"]["algorithm"].native)
        hasher = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}.get(
            algorithm
        )
        if hasher is None:
            raise TimestampInvalid(
                f"the token digests its attributes with {algorithm!r}, which this "
                f"verifier does not implement. Refusing beats assuming SHA-256 — a "
                f"legitimate SHA-384 token would otherwise be rejected as tampered."
            )
        if found != hasher(content).digest():
            raise TimestampInvalid(
                "the signed message-digest does not match the TSTInfo in the token. "
                "The signature is genuine and it is not about this content."
            )

    @staticmethod
    def _assert_signature(signer: Any, certificate: Any) -> None:
        """Verify over the DER re-encoding of signedAttrs, as CMS requires.

        On the wire the attributes carry an implicit ``[0]`` tag; the signature is over
        the same bytes re-tagged as ``SET OF``. Verifying the wire form fails on every
        genuine token, which is the kind of mistake that gets a verifier disabled.
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

        payload = signer["signed_attrs"].untag().dump()
        signature = bytes(signer["signature"].native)
        digest = {
            "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512(),
        }.get(str(signer["digest_algorithm"]["algorithm"].native))
        if digest is None:
            raise TimestampInvalid(
                f"unsupported digest {signer['digest_algorithm']['algorithm'].native!r}; "
                f"refusing rather than assuming one."
            )

        key = certificate.public_key()
        try:
            if isinstance(key, rsa.RSAPublicKey):
                # PSS where the token says PSS. Assuming PKCS#1 v1.5 unconditionally
                # rejected every PSS-signing authority as tampered, which is the shape
                # of false negative that gets a verifier switched off.
                scheme = str(signer["signature_algorithm"]["algorithm"].native)
                if "pss" in scheme:
                    key.verify(
                        signature,
                        payload,
                        padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                        digest,
                    )
                else:
                    key.verify(signature, payload, padding.PKCS1v15(), digest)
            elif isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(signature, payload, ec.ECDSA(digest))
            else:
                raise TimestampInvalid(
                    f"unsupported signing key {type(key).__name__}; refusing rather "
                    f"than treating an unverifiable signature as verified."
                )
        except InvalidSignature as exc:
            raise TimestampInvalid(
                "the token's signature does not verify against the certificate it "
                "names. The bytes have been altered, or they never came from that "
                "authority."
            ) from exc

    def _assert_timestamping_certificate(self, certificate: Any, *, at: datetime) -> None:
        """RFC 3161 §2.3: the EKU must be present, must be timeStamping, and critical.

        A general-purpose TLS certificate must not be able to sign timestamps — otherwise
        anyone who can obtain a web certificate for any name can backdate.
        """
        from cryptography import x509

        try:
            extension = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        except x509.ExtensionNotFound as exc:
            raise TimestampInvalid(
                "the signing certificate has no extended key usage, so it is not a "
                "timestamping certificate. RFC 3161 requires one."
            ) from exc
        usages = [usage.dotted_string for usage in extension.value]
        if usages != [self.TIMESTAMPING_EKU]:
            raise TimestampInvalid(
                f"the signing certificate's EKU is {usages}, not exactly "
                f"[{self.TIMESTAMPING_EKU}]. RFC 3161 requires timeStamping and only "
                f"that: a general-purpose certificate must not be able to backdate."
            )
        if not extension.critical:
            raise TimestampInvalid(
                "the timeStamping EKU is not marked critical, so a verifier that does "
                "not understand it would ignore the restriction entirely."
            )
        if not certificate.not_valid_before_utc <= at <= certificate.not_valid_after_utc:
            raise TimestampInvalid(
                f"the token claims {at.isoformat()}, outside the signing certificate's "
                f"validity ({certificate.not_valid_before_utc.isoformat()} to "
                f"{certificate.not_valid_after_utc.isoformat()}). An expired key is not "
                f"an authority, and a timestamp outside it is the backdating being "
                f"looked for."
            )

    def _assert_chains_to_anchor(self, certificate: Any, signed_data: Any) -> None:
        """Walk from the signer to a configured anchor, verifying each link.

        Deliberately not full RFC 5280 path validation — see the module docstring for
        exactly which parts are missing and why. What is here is the part that decides
        whether these timestamps are *yours*: signed by somebody is not a witness.
        """
        from cryptography.x509 import load_der_x509_certificate

        anchors = [load_der_x509_certificate(der) for der in self._anchors]
        if any(self._same(certificate, anchor) for anchor in anchors):
            return

        pool = [load_der_x509_certificate(c.dump()) for c in (signed_data["certificates"] or [])]
        if self._reaches_anchor(certificate, anchors=anchors, pool=pool, depth=len(pool) + 1):
            return
        raise TimestampInvalid(
            f"the signing certificate ({certificate.subject.rfc4514_string()}) does not "
            f"chain to any configured trust anchor. A token signed by an authority this "
            f"deployment has not chosen is not a witness."
        )

    def _reaches_anchor(
        self,
        certificate: Any,
        *,
        anchors: Sequence[Any],
        pool: Sequence[Any],
        depth: int,
    ) -> bool:
        """Try **every** candidate issuer, not the first name match.

        Certificates in ``SignedData`` are not covered by the CMS signature, so anyone
        who can alter a stored token — an operator, or anything with write access to a
        bundle — could append a decoy whose subject collides with the real issuer's.
        Taking the first match and failing on it turned a genuine timestamp into a
        verification failure: a way to silently invalidate real evidence, closed in the
        safe direction and still a way.
        """
        if depth < 0:
            return False
        if any(self._same(certificate, anchor) for anchor in anchors):
            return True
        for candidate in [*anchors, *pool]:
            if candidate.subject != certificate.issuer or self._same(candidate, certificate):
                continue
            if not self._issued(certificate, candidate):
                continue  # a decoy, or an unrelated certificate sharing a subject
            if self._reaches_anchor(candidate, anchors=anchors, pool=pool, depth=depth - 1):
                return True
        return False

    @staticmethod
    def _same(left: Any, right: Any) -> bool:
        """Identity by fingerprint, not by subject. Two certificates can share a name."""
        from cryptography.hazmat.primitives import hashes

        return bool(left.fingerprint(hashes.SHA256()) == right.fingerprint(hashes.SHA256()))

    @staticmethod
    def _issued(child: Any, issuer: Any) -> bool:
        """Whether the issuer's key really signed this certificate, **and may have**.

        The signature is the link. ``basicConstraints`` is the authority to make one:
        without it an end-entity certificate can act as an intermediate, so anyone
        holding a leaf from the same CA could mint an issuer for their own key.
        """
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature

        try:
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints)
            if not constraints.value.ca:
                return False
        except x509.ExtensionNotFound:
            return False
        try:
            child.verify_directly_issued_by(issuer)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True

    #: How far ahead of the request a genTime may sit before it is refused, on top of
    #: ``max_skew_seconds``. Generous — a TSA is entitled to queue — and finite.
    MAX_FORWARD: Final = 300

    def _assert_plausible(self, gen_time: datetime, requested_at: datetime | None) -> None:
        """Bounded **both ways**.

        Backdating is the attack this exists to catch, and the bound was only from
        below — so a token dated next year passed. Forward-dating is weaker and it is
        not nothing: a timestamp claiming a moment that has not happened yet is either a
        broken clock or a claim that a record existed before it did.
        """
        if requested_at is None:
            return
        from datetime import timedelta

        skew = timedelta(seconds=self._max_skew)
        if gen_time + skew < requested_at:
            raise TimestampInvalid(
                f"the token claims {gen_time.isoformat()}, before the request was made "
                f"at {requested_at.isoformat()}. Either a clock is wrong or this is a "
                f"token from earlier being replayed."
            )
        if gen_time - skew > requested_at + timedelta(seconds=self.MAX_FORWARD):
            raise TimestampInvalid(
                f"the token claims {gen_time.isoformat()}, more than "
                f"{self.MAX_FORWARD}s after the request at {requested_at.isoformat()}. "
                f"A timestamp for a moment that has not happened is a broken clock or a "
                f"claim that this record existed before it did."
            )

    @staticmethod
    def _accuracy(info: Any) -> str:
        """The authority's own stated bound, rendered for a human."""
        accuracy = info["accuracy"].native
        if not accuracy:
            return ""
        parts = [
            f"{accuracy.get('seconds', 0)}s" if accuracy.get("seconds") else "",
            f"{accuracy.get('millis', 0)}ms" if accuracy.get("millis") else "",
            f"{accuracy.get('micros', 0)}us" if accuracy.get("micros") else "",
        ]
        joined = " ".join(part for part in parts if part)
        return f"±{joined}" if joined else ""


@dataclass(frozen=True, slots=True)
class VerifiedTimestamp:
    """A token and what checking it established. Stored together, deliberately.

    A token filed without its assertion is a token somebody will later assume was
    checked.
    """

    token: bytes
    assertion: TimestampAssertion
    detail: dict[str, str] = field(default_factory=dict)
