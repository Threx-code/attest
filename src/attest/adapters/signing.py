"""A signer that ships, so seals and bundles are not unsigned by default.

There was no implementation of :class:`~attest.kernel.ports.Signer` anywhere in the
package. Every host had to write one before a seal carried a signature or a bundle
carried anything binding it to its issuer — and until they did, ``VERIFY.md`` told a
verifier to check files against a manifest that travelled in the same archive, which
establishes internal consistency and nothing about where the archive came from.

Chain integrity proves the record is *self-consistent*. A signature proves it came from
this system rather than from someone who reconstructed a plausible chain. They are
different claims and the second one needs a key.

.. rubric:: Why Ed25519

.. code-block:: text

    no parameters to choose        no curve, no padding, no hash to get wrong
    no RNG at signing time         deterministic; a bad RNG cannot leak the key
    32-byte public key             fits in the bundle, so an offline verifier
                                   has the key rather than a fingerprint of one
    small signatures               64 bytes, in every seal and every bundle

The alternative is RSA with a padding mode and a digest, both of which have wrong
answers that still produce a signature.

.. rubric:: The private key never leaves the signer

:meth:`Ed25519Signer.public_key_pem` is the only export. Verification runs from that
alone — see :class:`Ed25519Verifier`, which imports nothing from this package and is
what an auditor uses to check a bundle without running our code.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from attest.kernel.errors import ConfigurationError

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["Ed25519Signer", "Ed25519Verifier", "SigningKeyError"]


class SigningKeyError(ConfigurationError):
    """A key could not be loaded, or is not the kind this signer uses.

    A :class:`~attest.kernel.errors.ConfigurationError` rather than a runtime failure:
    a deployment with an unusable signing key must not start and discover it at the
    first seal.
    """


class Ed25519Signer:
    """Signs with Ed25519. Satisfies :class:`~attest.kernel.ports.Signer`.

    ``key_id`` is the SHA-256 of the public key, truncated to 32 hex characters and
    prefixed. It identifies *the key* rather than naming a file or a slot, so a rotated
    key is visibly a different key in every record it signed — which is what makes a
    key-compromise timeline reconstructable rather than guessable.
    """

    #: Prefix on every key id, so a bare hash in a log is recognisable as one of ours.
    PREFIX: Final = "ed25519"

    #: How much of the public key digest the id carries. 128 bits of a public value —
    #: enough that two live keys will not collide, short enough to read in a log line.
    ID_LENGTH: Final = 32

    __slots__ = ("_key", "_key_id")

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        """``private_key`` is a ``cryptography`` Ed25519 private key object.

        Constructed from :meth:`generate`, :meth:`from_pem` or :meth:`from_file` rather
        than assembled here, so the loading errors are typed and happen once.
        """
        if not isinstance(private_key, Ed25519PrivateKey):
            raise SigningKeyError(
                f"Ed25519Signer needs an Ed25519 private key, got "
                f"{type(private_key).__name__}. Use from_pem() or generate()."
            )
        self._key = private_key
        self._key_id = self._identify(self.public_key_pem())

    # ── Construction ─────────────────────────────────────────────────────────

    @classmethod
    def generate(cls) -> Ed25519Signer:
        """A fresh key. **For tests and first-run bootstrap, not for production.**

        A key generated in-process lives and dies with it, so anything it signed becomes
        unverifiable at the next restart. Production keys come from a KMS, an HSM, or a
        file a deployment can back up — and whichever it is, that decision belongs to
        the deployment rather than to a default here.
        """
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes, *, password: bytes | None = None) -> Ed25519Signer:
        """Load a PKCS#8 PEM private key."""
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        try:
            key = load_pem_private_key(pem, password=password)
        except Exception as exc:
            raise SigningKeyError(
                f"could not load the signing key ({type(exc).__name__}). An encrypted "
                f"key needs its password; a public key is not a signing key."
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningKeyError(
                f"the file holds a {type(key).__name__}, not an Ed25519 key. Refusing "
                f"rather than signing with an algorithm the record does not name."
            )
        return cls(key)

    @classmethod
    def from_file(cls, path: Path, *, password: bytes | None = None) -> Ed25519Signer:
        """Load from disk. The bytes are read once and not retained."""
        return cls.from_pem(path.read_bytes(), password=password)

    # ── The port ─────────────────────────────────────────────────────────────

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: bytes) -> str:
        """Sign, and return base64 — the form that survives JSON and a text file."""
        return base64.b64encode(self._key.sign(payload)).decode("ascii")

    def verify(self, payload: bytes, signature: str) -> bool:
        """Check a signature this signer produced.

        Present because the port declares it, and it verifies from the *public* half —
        the same code path :class:`Ed25519Verifier` uses, so a passing check here means
        an external verifier will pass too rather than meaning something weaker.
        """
        return Ed25519Verifier(self.public_key_pem()).verify(payload, signature)

    # ── Export ───────────────────────────────────────────────────────────────

    def public_key_pem(self) -> bytes:
        """The public half, in PEM. **The only thing that leaves this object.**

        Written into the bundle so an offline verifier has the key rather than a
        fingerprint of one — ``pubkey.id`` alone tells a verifier which key they would
        need and gives them no way to use it.
        """
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        return bytes(
            self._key.public_key().public_bytes(
                encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
            )
        )

    def private_key_pem(self, *, password: bytes | None = None) -> bytes:
        """Export the private key, for a deployment writing one out at bootstrap.

        Encrypted when a password is given, and deliberately not by default — a silent
        default password is worse than none, because it reads as protection.
        """
        from cryptography.hazmat.primitives.serialization import (
            BestAvailableEncryption,
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        return bytes(
            self._key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=(
                    NoEncryption() if password is None else BestAvailableEncryption(password)
                ),
            )
        )

    @classmethod
    def _identify(cls, public_pem: bytes) -> str:
        import hashlib

        digest = hashlib.sha256(public_pem).hexdigest()[: cls.ID_LENGTH]
        return f"{cls.PREFIX}:{digest}"


class Ed25519Verifier:
    """Checks signatures from the public key alone.

    Deliberately usable on its own: an auditor holding a bundle needs the public key and
    this class, and nothing else from this package. That is what "verify must work from
    the public key alone" means in :class:`~attest.kernel.ports.Signer`, and it is the
    difference between an evidence bundle and a bundle you have to trust us about.
    """

    __slots__ = ("_key", "_key_id")

    def __init__(self, public_pem: bytes) -> None:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        try:
            key = load_pem_public_key(public_pem)
        except Exception as exc:
            raise SigningKeyError(f"could not load the public key ({type(exc).__name__})") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise SigningKeyError(
                f"expected an Ed25519 public key, got {type(key).__name__}. Refusing "
                f"rather than verifying with an algorithm the record does not name."
            )
        self._key = key
        self._key_id = Ed25519Signer._identify(public_pem)  # noqa: SLF001 — one definition

    @property
    def key_id(self) -> str:
        """Which key this is, in the same form the record carries."""
        return self._key_id

    def verify(self, payload: bytes, signature: str) -> bool:
        """``True`` only for a signature this key really produced.

        Every failure is ``False`` rather than an exception: a malformed signature, a
        signature from another key, and altered bytes are all "this does not verify",
        and a caller that had to distinguish them would end up treating some of them as
        success.
        """
        from cryptography.exceptions import InvalidSignature

        try:
            self._key.verify(base64.b64decode(signature, validate=True), payload)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True
