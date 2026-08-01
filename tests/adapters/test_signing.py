"""The signer, and the property that makes a bundle evidence rather than a claim.

Chain integrity proves a record is self-consistent. A signature proves it came from this
system rather than from someone who reconstructed a plausible chain — and until a signer
shipped, no deployment had the second one without writing it first.

The test that matters most is the last one in each section: a signature checked with
``openssl`` and nothing of ours. If that fails, the bundle is only verifiable by people
who trust us, which defeats the point of a bundle.
"""

from __future__ import annotations

import base64
import subprocess
from pathlib import Path

import pytest

from attest.adapters.signing import Ed25519Signer, Ed25519Verifier, SigningKeyError

pytestmark = [pytest.mark.unit, pytest.mark.security]

PAYLOAD = b'{"attestation.json": "a1b2", "chain.jsonl": "c3d4"}'


@pytest.fixture(scope="module")
def signer() -> Ed25519Signer:
    return Ed25519Signer.generate()


# ── The round trip ───────────────────────────────────────────────────────────


def test_a_signature_verifies_from_the_public_key_alone(signer: Ed25519Signer) -> None:
    """ "verify must work from the public key alone" — the port says so, and this is it."""
    signature = signer.sign(PAYLOAD)
    assert Ed25519Verifier(signer.public_key_pem()).verify(PAYLOAD, signature)


def test_altered_bytes_do_not_verify(signer: Ed25519Signer) -> None:
    signature = signer.sign(PAYLOAD)
    assert not Ed25519Verifier(signer.public_key_pem()).verify(PAYLOAD + b" ", signature)


def test_another_key_does_not_verify(signer: Ed25519Signer) -> None:
    """The whole claim: this came from *this* system, not merely from something."""
    signature = signer.sign(PAYLOAD)
    stranger = Ed25519Signer.generate()
    assert not Ed25519Verifier(stranger.public_key_pem()).verify(PAYLOAD, signature)


@pytest.mark.parametrize(
    "signature",
    ["", "not base64 at all!", base64.b64encode(b"too short").decode()],
    ids=["empty", "malformed", "wrong-length"],
)
def test_a_malformed_signature_is_false_rather_than_an_exception(
    signer: Ed25519Signer, signature: str
) -> None:
    """All of these are "this does not verify".

    A caller forced to distinguish them would end up treating one of them as success.
    """
    assert not Ed25519Verifier(signer.public_key_pem()).verify(PAYLOAD, signature)


# ── Key identity ─────────────────────────────────────────────────────────────


def test_the_key_id_identifies_the_key_not_a_slot(signer: Ed25519Signer) -> None:
    """A rotated key is visibly a different key in every record it signed.

    Which is what makes a key-compromise timeline reconstructable rather than guessed.
    """
    assert signer.key_id.startswith("ed25519:")
    assert Ed25519Signer.generate().key_id != signer.key_id


def test_the_verifier_reports_the_same_id_as_the_signer(signer: Ed25519Signer) -> None:
    """Otherwise a record naming a key and a verifier holding it cannot be matched."""
    assert Ed25519Verifier(signer.public_key_pem()).key_id == signer.key_id


# ── Loading ──────────────────────────────────────────────────────────────────


def test_a_key_round_trips_through_pem(signer: Ed25519Signer) -> None:
    """A key generated in-process dies with it; production keys come from a file."""
    reloaded = Ed25519Signer.from_pem(signer.private_key_pem())
    assert reloaded.key_id == signer.key_id
    assert Ed25519Verifier(signer.public_key_pem()).verify(PAYLOAD, reloaded.sign(PAYLOAD))


def test_an_encrypted_key_round_trips(signer: Ed25519Signer) -> None:
    encrypted = signer.private_key_pem(password=b"correct horse battery staple")
    assert b"ENCRYPTED" in encrypted
    reloaded = Ed25519Signer.from_pem(encrypted, password=b"correct horse battery staple")
    assert reloaded.key_id == signer.key_id


def test_a_key_is_loaded_from_a_file(signer: Ed25519Signer, tmp_path: Path) -> None:
    path = tmp_path / "signing.pem"
    path.write_bytes(signer.private_key_pem())
    assert Ed25519Signer.from_file(path).key_id == signer.key_id


def test_a_wrong_password_is_a_configuration_error(signer: Ed25519Signer) -> None:
    """A deployment with an unusable key must not start and find out at the first seal."""
    encrypted = signer.private_key_pem(password=b"the right one")
    with pytest.raises(SigningKeyError, match="could not load"):
        Ed25519Signer.from_pem(encrypted, password=b"the wrong one")


def test_a_public_key_is_not_a_signing_key(signer: Ed25519Signer) -> None:
    with pytest.raises(SigningKeyError):
        Ed25519Signer.from_pem(signer.public_key_pem())


def test_an_rsa_key_is_refused() -> None:
    """Refusing beats signing with an algorithm the record does not name."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    rsa_pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    with pytest.raises(SigningKeyError, match="not an Ed25519 key"):
        Ed25519Signer.from_pem(rsa_pem)


def test_a_non_ed25519_public_key_is_refused_by_the_verifier() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    rsa_public = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    )
    with pytest.raises(SigningKeyError, match="expected an Ed25519"):
        Ed25519Verifier(rsa_public)


def test_the_private_key_is_not_exported_by_default(signer: Ed25519Signer) -> None:
    """public_key_pem is the only thing that leaves the object without being asked."""
    assert b"PRIVATE" not in signer.public_key_pem()
    assert b"PUBLIC KEY" in signer.public_key_pem()


# ── The claim that matters: verifiable without our code ─────────────────────


def test_a_signature_verifies_with_openssl_and_nothing_of_ours(
    signer: Ed25519Signer, tmp_path: Path
) -> None:
    """The step VERIFY.md tells an auditor to perform, performed.

    If this fails, the bundle is verifiable only by people who already trust us, which
    is what an evidence bundle exists to avoid.
    """
    openssl = shutil_which("openssl")
    if openssl is None:
        pytest.skip("openssl is not on PATH")

    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(PAYLOAD)
    (tmp_path / "pubkey.pem").write_bytes(signer.public_key_pem())
    (tmp_path / "signature.raw").write_bytes(base64.b64decode(signer.sign(PAYLOAD)))

    result = subprocess.run(  # noqa: S603 — absolute path, fixed argv, no shell
        [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(tmp_path / "pubkey.pem"),
            "-rawin",
            "-in",
            str(manifest),
            "-sigfile",
            str(tmp_path / "signature.raw"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{result.stdout}{result.stderr}"


def test_openssl_rejects_an_altered_manifest(signer: Ed25519Signer, tmp_path: Path) -> None:
    """A verification that passes on tampered bytes proves nothing about untampered ones."""
    openssl = shutil_which("openssl")
    if openssl is None:
        pytest.skip("openssl is not on PATH")

    (tmp_path / "pubkey.pem").write_bytes(signer.public_key_pem())
    (tmp_path / "signature.raw").write_bytes(base64.b64decode(signer.sign(PAYLOAD)))
    altered = tmp_path / "manifest.json"
    altered.write_bytes(PAYLOAD.replace(b"a1b2", b"0000"))

    result = subprocess.run(  # noqa: S603 — absolute path, fixed argv, no shell
        [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(tmp_path / "pubkey.pem"),
            "-rawin",
            "-in",
            str(altered),
            "-sigfile",
            str(tmp_path / "signature.raw"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0


def shutil_which(name: str) -> str | None:
    """The absolute path to a tool, or None. Absolute so the argv is unambiguous."""
    import shutil

    return shutil.which(name)
