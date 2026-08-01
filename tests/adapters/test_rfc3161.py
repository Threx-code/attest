"""RFC 3161 verification, against real tokens built by a miniature authority.

A mock cannot test this. Every check that matters is about the *bytes* — an imprint
that does not match, a signature over different attributes, a certificate without the
timeStamping EKU — so the fixture below is a working TSA: it builds a certificate,
signs a real ``TimeStampResp``, and can be told to build a bad one in each specific way
the verifier is supposed to catch.

Where the token is malformed on purpose, that is stated in the test's own words rather
than left as an opaque byte string.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from dataclasses import dataclass
from typing import Any

import pytest
from asn1crypto import cms, core, tsp
from asn1crypto import x509 as a_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from attest.adapters.rfc3161 import (
    Rfc3161Unavailable,
    Rfc3161Verifier,
    TimestampInvalid,
)
from attest.kernel.identifiers import Hash

pytestmark = [pytest.mark.unit, pytest.mark.security]

AT = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC)
ROOT = Hash(hashlib.sha256(b"a checkpoint root").hexdigest())
NONCE = 987654321


@dataclass(frozen=True, slots=True)
class Authority:
    """A working timestamping authority, and every way of building a bad one."""

    key: Any
    certificate: Any
    der: bytes

    @classmethod
    def build(
        cls,
        *,
        eku: list[Any] | None = None,
        eku_critical: bool = True,
        not_before: dt.datetime = AT - dt.timedelta(days=1),
        not_after: dt.datetime = AT + dt.timedelta(days=365),
        common_name: str = "Test TSA",
        issuer: Authority | None = None,
        ca: bool = False,
    ) -> Authority:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer.certificate.subject if issuer else subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        )
        usages = eku if eku is not None else [ExtendedKeyUsageOID.TIME_STAMPING]
        if usages:
            builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=eku_critical)
        certificate = builder.sign(issuer.key if issuer else key, hashes.SHA256())
        return cls(
            key=key,
            certificate=certificate,
            der=certificate.public_bytes(serialization.Encoding.DER),
        )

    def token(
        self,
        *,
        root: Hash = ROOT,
        nonce: int | None = NONCE,
        gen_time: dt.datetime = AT,
        status: str = "granted",
        digest_algorithm: str = "sha256",
        sign_a_different_digest: bool = False,
        content_type: str = "tst_info",
        extra_certificates: tuple[bytes, ...] = (),
    ) -> bytes:
        info = tsp.TSTInfo(
            {
                "version": "v1",
                "policy": "1.2.3.4.5",
                "message_imprint": {
                    "hash_algorithm": {"algorithm": digest_algorithm},
                    "hashed_message": bytes.fromhex(str(root)),
                },
                "serial_number": 42,
                "gen_time": gen_time,
                **({"nonce": nonce} if nonce is not None else {}),
            }
        )
        econtent = info.dump()
        digest = hashlib.sha256(b"something else" if sign_a_different_digest else econtent).digest()
        attributes = cms.CMSAttributes(
            [
                cms.CMSAttribute({"type": "content_type", "values": [content_type]}),
                cms.CMSAttribute({"type": "message_digest", "values": [digest]}),
            ]
        )
        signature = self.key.sign(attributes.dump(), padding.PKCS1v15(), hashes.SHA256())
        mine = a_x509.Certificate.load(self.der)
        certificates = [mine, *[a_x509.Certificate.load(der) for der in extra_certificates]]
        signed = cms.SignedData(
            {
                "version": "v3",
                "digest_algorithms": [{"algorithm": "sha256"}],
                "encap_content_info": {
                    "content_type": "tst_info",
                    "content": core.ParsableOctetString(econtent),
                },
                "certificates": certificates,
                "signer_infos": [
                    {
                        "version": "v1",
                        "sid": {
                            "issuer_and_serial_number": {
                                "issuer": mine["tbs_certificate"]["issuer"],
                                "serial_number": mine["tbs_certificate"]["serial_number"].native,
                            }
                        },
                        "digest_algorithm": {"algorithm": "sha256"},
                        "signed_attrs": attributes,
                        "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                        "signature": signature,
                    }
                ],
            }
        )
        if status not in ("granted", "granted_with_mods"):
            return _rejection(status)
        return bytes(
            tsp.TimeStampResp(
                {
                    "status": {"status": status},
                    "time_stamp_token": cms.ContentInfo(
                        {"content_type": "signed_data", "content": signed}
                    ),
                }
            ).dump()
        )


def _rejection(status: str) -> bytes:
    """A real rejection: a status, a reason, and **no token at all**.

    Built at the DER level because asn1crypto declares ``time_stamp_token`` required
    while RFC 3161 §2.4.2 marks it OPTIONAL — a rejection legitimately omits it. This is
    exactly the shape the old ``if not token`` check let through: well-formed, non-empty,
    and a refusal.
    """
    info = tsp.PKIStatusInfo(
        {"status": status, "status_string": ["policy does not permit this request"]}
    ).dump()
    length = len(info)
    if length < 0x80:
        header = bytes([0x30, length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x30, 0x80 | len(encoded), *encoded])
    return bytes(header + info)


@pytest.fixture(scope="module")
def tsa() -> Authority:
    return Authority.build()


def verifier(*anchors: bytes, skew: int = 0) -> Rfc3161Verifier:
    return Rfc3161Verifier(anchors=list(anchors), max_skew_seconds=skew)


# ── The honest path ──────────────────────────────────────────────────────────


def test_a_genuine_token_verifies_and_says_what_it_established(tsa: Authority) -> None:
    assertion = verifier(tsa.der).verify(tsa.token(), root=ROOT, nonce=NONCE)
    assert assertion.signed_at == AT
    assert assertion.root == str(ROOT)
    assert "Test TSA" in assertion.authority

    checked = " ".join(assertion.checked)
    for expected in ("PKIStatus", "messageImprint", "nonce", "signature", "EKU", "anchor"):
        assert expected in checked, f"the assertion does not mention {expected}"


def test_the_assertion_carries_what_it_did_not_check(tsa: Authority) -> None:
    """A result that travels without its limits gets read as a stronger claim."""
    assertion = verifier(tsa.der).verify(tsa.token(), root=ROOT, nonce=NONCE)
    joined = " ".join(assertion.not_checked)
    assert "revocation" in joined
    assert "constraints" in joined
    assert "not_checked" in assertion.as_dict()


# ── What it refuses ──────────────────────────────────────────────────────────


def test_a_rejection_is_refused(tsa: Authority) -> None:
    """A rejection is a well-formed, non-empty response. The old check was `if token`."""
    with pytest.raises(TimestampInvalid, match="refused the request"):
        verifier(tsa.der).verify(tsa.token(status="rejection"), root=ROOT, nonce=NONCE)


def test_a_token_about_a_different_root_is_refused(tsa: Authority) -> None:
    """The check that stops one previously-obtained token witnessing everything."""
    other = Hash(hashlib.sha256(b"a different root").hexdigest())
    with pytest.raises(TimestampInvalid, match="different message"):
        verifier(tsa.der).verify(tsa.token(root=other), root=ROOT, nonce=NONCE)


def test_a_replayed_token_with_the_wrong_nonce_is_refused(tsa: Authority) -> None:
    """The RFC's own replay defence, which the client was not sending at all."""
    with pytest.raises(TimestampInvalid, match="replayed response"):
        verifier(tsa.der).verify(tsa.token(nonce=111), root=ROOT, nonce=NONCE)


def test_a_token_with_no_nonce_is_refused_when_one_was_sent(tsa: Authority) -> None:
    with pytest.raises(TimestampInvalid, match="carries none"):
        verifier(tsa.der).verify(tsa.token(nonce=None), root=ROOT, nonce=NONCE)


def test_a_signature_over_a_different_digest_is_refused(tsa: Authority) -> None:
    """The signature covers the attributes, so this is what ties it to the content.

    Without it a genuine signature over a genuine attribute set says nothing about the
    TSTInfo beside it, and the imprint check would be reading an unsigned payload.
    """
    with pytest.raises(TimestampInvalid, match="does not match the TSTInfo"):
        verifier(tsa.der).verify(tsa.token(sign_a_different_digest=True), root=ROOT, nonce=NONCE)


def test_a_signature_for_a_different_content_type_is_refused(tsa: Authority) -> None:
    with pytest.raises(TimestampInvalid, match="not a timestamp"):
        verifier(tsa.der).verify(tsa.token(content_type="data"), root=ROOT, nonce=NONCE)


def test_a_tampered_token_fails_the_signature(tsa: Authority) -> None:
    """The only thing binding the response to the authority."""
    token = bytearray(tsa.token())
    token[-1] ^= 0xFF  # flip a bit in the signature
    with pytest.raises(TimestampInvalid):
        verifier(tsa.der).verify(bytes(token), root=ROOT, nonce=NONCE)


def test_a_truncated_response_is_refused_rather_than_partially_read(tsa: Authority) -> None:
    with pytest.raises(TimestampInvalid, match="not a well-formed"):
        verifier(tsa.der).verify(tsa.token()[:40], root=ROOT, nonce=NONCE)


# ── The certificate, which is where backdating actually gets in ─────────────


def test_a_certificate_without_the_timestamping_eku_is_refused() -> None:
    """RFC 3161 §2.3. Otherwise anyone who can get a web certificate can backdate."""
    web = Authority.build(eku=[ExtendedKeyUsageOID.SERVER_AUTH])
    with pytest.raises(TimestampInvalid, match="not exactly"):
        verifier(web.der).verify(web.token(), root=ROOT, nonce=NONCE)


def test_a_certificate_with_no_eku_at_all_is_refused() -> None:
    bare = Authority.build(eku=[])
    with pytest.raises(TimestampInvalid, match="no extended key usage"):
        verifier(bare.der).verify(bare.token(), root=ROOT, nonce=NONCE)


def test_a_non_critical_timestamping_eku_is_refused() -> None:
    """A verifier that does not understand the extension would ignore the restriction."""
    lax = Authority.build(eku_critical=False)
    with pytest.raises(TimestampInvalid, match="not marked critical"):
        verifier(lax.der).verify(lax.token(), root=ROOT, nonce=NONCE)


def test_a_timestamp_outside_the_certificates_validity_is_refused() -> None:
    """An expired key is not an authority, and this is the backdating being looked for."""
    expired = Authority.build(
        not_before=AT - dt.timedelta(days=800), not_after=AT - dt.timedelta(days=400)
    )
    with pytest.raises(TimestampInvalid, match="outside the signing certificate"):
        verifier(expired.der).verify(expired.token(), root=ROOT, nonce=NONCE)


# ── The anchor, which is what makes it *your* witness ───────────────────────


def test_a_token_from_an_authority_you_did_not_choose_is_refused(tsa: Authority) -> None:
    """ "Signed by somebody" is not a witness."""
    stranger = Authority.build(common_name="Someone Else's TSA")
    with pytest.raises(TimestampInvalid, match="does not chain"):
        verifier(tsa.der).verify(stranger.token(), root=ROOT, nonce=NONCE)


def test_a_token_chaining_through_an_intermediate_verifies() -> None:
    """The realistic shape: a root anchor, an issuing CA, a leaf that signs tokens."""
    root_ca = Authority.build(common_name="Root CA", ca=True, eku=[])
    intermediate = Authority.build(common_name="Issuing CA", ca=True, eku=[], issuer=root_ca)
    leaf = Authority.build(common_name="Leaf TSA", issuer=intermediate)

    assertion = verifier(root_ca.der).verify(
        leaf.token(extra_certificates=(intermediate.der,)), root=ROOT, nonce=NONCE
    )
    assert "Leaf TSA" in assertion.authority


def test_a_chain_missing_its_intermediate_is_refused() -> None:
    """A chain that is asserted rather than verified is a chain anyone can assert."""
    root_ca = Authority.build(common_name="Root CA", ca=True, eku=[])
    intermediate = Authority.build(common_name="Issuing CA", ca=True, eku=[], issuer=root_ca)
    leaf = Authority.build(common_name="Leaf TSA", issuer=intermediate)

    with pytest.raises(TimestampInvalid, match="does not chain"):
        verifier(root_ca.der).verify(leaf.token(), root=ROOT, nonce=NONCE)


# ── Construction refuses early ───────────────────────────────────────────────


def test_a_verifier_without_anchors_is_refused() -> None:
    """It could confirm a token is signed by somebody, which is not a witness."""
    with pytest.raises(Rfc3161Unavailable, match="at least one trust anchor"):
        Rfc3161Verifier(anchors=[])


def test_a_timestamp_from_before_the_request_is_refused(tsa: Authority) -> None:
    """Either a clock is wrong or an earlier token is being replayed."""
    with pytest.raises(TimestampInvalid, match="before the request"):
        verifier(tsa.der).verify(
            tsa.token(gen_time=AT - dt.timedelta(hours=2)),
            root=ROOT,
            nonce=NONCE,
            requested_at=AT,
        )


def test_a_small_clock_skew_can_be_permitted_deliberately(tsa: Authority) -> None:
    """Zero by default, because a generous default hides the thing being detected."""
    assertion = verifier(tsa.der, skew=120).verify(
        tsa.token(gen_time=AT - dt.timedelta(seconds=30)),
        root=ROOT,
        nonce=NONCE,
        requested_at=AT,
    )
    assert assertion.signed_at < AT
