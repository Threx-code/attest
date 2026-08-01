"""Evidence bundles — verifiable without our code.

.. code-block:: text

    If checking the bundle requires the framework, it is not evidence.
    It is a claim about evidence.

So ``VERIFY.md`` contains the actual commands rather than a description of them, and
every step uses standard tools. The step that matters most is the last: compare the
witness root against a value obtained from the **third party**, not from the bundle.
Comparing against a root the bundle supplied proves only that the bundle is
self-consistent.

Sources are **embedded**, not linked. A bundle that links to a document is worthless
the day that document is edited or the URL rots.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from attest.kernel.attestation import AttestationError
from attest.kernel.canonical import NULL_HASH, Canonical
from attest.kernel.codec import AttestationCodec, AuditEventCodec
from attest.kernel.identifiers import Hash

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from attest.capabilities.witness import Checkpoint, InclusionProof, Receipt
    from attest.kernel.attestation import Attestation
    from attest.kernel.audit import AuditEvent
    from attest.kernel.ports import Signer
    from attest.kernel.warrants import WarrantReport

__all__ = ["BundleBuilder", "DisclosureProfile", "EvidenceBundle"]


class DisclosureProfile(StrEnum):
    """The same run needs different bundles for different audiences."""

    INTERNAL = "internal"
    REGULATOR = "regulator"
    SUBJECT = "subject"
    """Their own data; other subjects redacted."""

    LITIGATION = "litigation"


@dataclass(frozen=True, slots=True)
class EvidenceBundle:
    """A self-contained, offline-verifiable archive."""

    run_id: str
    files: Mapping[str, bytes]
    manifest: Mapping[str, Hash]
    redacted: frozenset[str] = frozenset()
    """Files withheld for this disclosure profile.

    The manifest still carries their ORIGINAL hashes, so a verifier can confirm
    nothing else was altered while accepting that redacted content will not match.
    Dropping them from the manifest instead would make redaction indistinguishable
    from tampering.
    """

    signature: str | None = None

    def verify_manifest(self) -> tuple[str, ...]:
        """Files whose bytes disagree with the manifest. Redacted ones are skipped."""
        return tuple(
            name
            for name, digest in self.manifest.items()
            if name not in self.redacted
            and name in self.files
            and Canonical.digest_bytes(self.files[name]) != digest
        )


class BundleBuilder:
    """Assembles a bundle, refusing to build one that would overclaim.

    Every file the instructions name is a file the bundle contains, and every file the
    bundle contains is hashed in a manifest the bundle also contains. That sounds like
    a restatement of the obvious; it is here because the previous implementation named
    ``manifest.json``, ``pubkey.pem``, ``signature.sig`` and
    ``witness/inclusion_proof.json`` in its instructions and wrote none of them, told
    the verifier to walk a ``prev`` field that did not exist, and shipped a file called
    ``attestation.json`` that contained the attestation's *hash* rather than the
    attestation. A bundle that cannot be checked is worse than no bundle: it looks like
    evidence.
    """

    __slots__ = ("_disclosure", "_signer")

    def __init__(
        self,
        *,
        disclosure: DisclosureProfile = DisclosureProfile.INTERNAL,
        signer: Signer | None = None,
    ) -> None:
        self._disclosure = disclosure
        self._signer = signer

    def build(
        self,
        attestation: Attestation,
        *,
        chain: Sequence[AuditEvent],
        sources: Mapping[str, bytes] | None = None,
        inclusion_proof: InclusionProof | None = None,
        checkpoint: Checkpoint | None = None,
        receipt: Receipt | None = None,
    ) -> EvidenceBundle:
        """Build the bundle, or refuse.

        ``assert_exportable`` runs first: an unsealed record has no verifiable chain,
        and a non-final one has warrants nobody evaluated. Either would put something
        in front of a regulator that claims more than it establishes.

        ``inclusion_proof`` is the proof from an external witness. It is the proof
        rather than a flag because the previous version took a witness root and used it
        only to *toggle the instructions* — telling the verifier to walk a proof the
        bundle did not contain.

        ``checkpoint`` is written for reference only, and the instructions say so: a
        verifier who compares the folded root against the checkpoint in this bundle has
        established that the bundle agrees with itself. The comparison that means
        anything is against the copy the third party publishes.

        ``receipt`` is the promise issued at decision time. It is what a holder later
        presents to demand an inclusion proof, so a bundle that omits it has dropped
        the one artefact that survives the host deciding not to cooperate.
        """
        attestation.assert_exportable()
        if not chain:
            raise AttestationError(
                f"run {attestation.run_id!r} has no chain to export; there would be "
                f"nothing for a verifier to walk"
            )
        seal = attestation.seal
        if seal is None:  # pragma: no cover - assert_exportable already refused
            raise AttestationError("an unsealed record is not evidence")

        disclosed, withheld = self._for_audience(attestation)
        files: dict[str, bytes] = {
            # The record itself, in the wire format that decodes back to it and
            # verifies its own content hash on the way.
            "attestation.json": AttestationCodec.encode(disclosed),
            "chain.jsonl": self._chain(chain),
            "seal.json": Canonical.encode(AuditEventCodec.dump_seal(seal)),
        }
        for name, payload in (sources or {}).items():
            if self._disclosure is DisclosureProfile.INTERNAL:
                files[f"evidence/{name}"] = payload
            else:
                # Named in the manifest with its original hash, and its bytes withheld.
                # Dropping it entirely would make redaction indistinguishable from
                # tampering; including it hands one subject another's evidence.
                withheld.add(f"evidence/{name}")
                files[f"evidence/{name}"] = payload
        if inclusion_proof is not None:
            files["witness/inclusion_proof.json"] = Canonical.encode(
                {
                    "leaf": inclusion_proof.leaf,
                    "index": inclusion_proof.index,
                    "tree_size": inclusion_proof.tree_size,
                    "path": [[side, node] for side, node in inclusion_proof.path],
                }
            )
        if checkpoint is not None:
            files["witness/checkpoint.json"] = Canonical.encode(
                {
                    "root": checkpoint.root,
                    "tree_size": checkpoint.tree_size,
                    "created_at": checkpoint.created_at,
                    "signature": checkpoint.signature,
                }
            )
        if receipt is not None:
            files["witness/receipt.json"] = Canonical.encode(
                {
                    "run_id": receipt.run_id,
                    "leaf": receipt.leaf,
                    "promised_by": receipt.promised_by,
                    "issued_at": receipt.issued_at,
                    "signature": receipt.signature,
                }
            )

        files["VERIFY.md"] = self._verify_instructions(
            witnessed=inclusion_proof is not None,
            receipted=receipt is not None,
            signed=self._signer is not None,
            sources=sorted(sources or {}),
            redacted=sorted(withheld),
        )

        manifest = {name: Hash(Canonical.digest_bytes(body)) for name, body in files.items()}
        # The manifest is a file too, and it deliberately does **not** list itself —
        # it cannot, since adding the entry changes the bytes the entry describes. It
        # used to be written without the entry and then gain one in memory when signing,
        # so a verifier following VERIFY.md and a caller using verify_manifest() were
        # checking two different sets. The instructions say so explicitly now.
        files["manifest.json"] = Canonical.encode(dict(sorted(manifest.items())))

        signature = None
        if self._signer is not None:
            signature = self._signer.sign(files["manifest.json"])
            files["signature.sig"] = signature.encode("utf-8")
            files["pubkey.id"] = self._signer.key_id.encode("utf-8")
            # The key itself, where the signer can export one. `pubkey.id` alone tells a
            # verifier which key they would need and gives them no way to use it — so
            # step 2 asked them to check a signature against a fingerprint.
            public_key = getattr(self._signer, "public_key_pem", None)
            if public_key is not None:
                files["pubkey.pem"] = public_key()

        for name in withheld:
            files.pop(name, None)

        return EvidenceBundle(
            run_id=str(attestation.run_id),
            files=files,
            manifest=manifest,
            redacted=frozenset(withheld),
            signature=signature,
        )

    def _for_audience(self, attestation: Attestation) -> tuple[Attestation, set[str]]:
        """The record this audience may see, and the file names withheld from them.

        The profile was accepted, stored, and **never read** — every bundle was the
        INTERNAL bundle whatever was requested. A subject exercising a data-access
        right received other subjects' evidence values, the operator-facing refusal
        detail, and internal actor identifiers, while the operator who passed
        ``SUBJECT`` believed redaction had happened. Worse than an absent feature: the
        presence of the parameter suppressed the manual review that would otherwise
        have caught it.

        Redaction is by *replacement*, not deletion, and the manifest keeps the
        original hashes — so a verifier can still check every file that is present and
        can tell a withheld file from an altered one.
        """
        if self._disclosure is DisclosureProfile.INTERNAL:
            return attestation, set()

        narrowed = replace(
            attestation,
            # The operator-facing detail names the actor and the capability. A subject
            # is owed the fact of a refusal and its reason code, not the system's
            # reasoning about them.
            refusal=None
            if attestation.refusal is None
            else replace(
                attestation.refusal,
                detail=attestation.refusal.subject_message or "",
                metadata={},
            ),
            warrants={
                kind: self._narrow_report(report) for kind, report in attestation.warrants.items()
            },
        )
        return narrowed, set()

    @staticmethod
    def _narrow_report(report: WarrantReport) -> WarrantReport:
        """Finding codes survive; finding messages do not.

        A code is enough to count, categorise, alert on and contest. The message is
        built from ``CapabilityCheck.detail``, which names the actor and the capability
        — internal authorisation topology, disclosed to whoever the bundle reaches.
        """
        return replace(
            report,
            findings=tuple(
                replace(finding, message=finding.code, data={}) for finding in report.findings
            ),
        )

    @staticmethod
    def _chain(chain: Sequence[AuditEvent]) -> bytes:
        """One canonical event per line, with the linkage a verifier is told to walk.

        Each line carries the event, its recomputed ``hash`` and the ``prev`` it links
        to — so step 3 can be performed with a hash utility and nothing else. The
        previous format carried only a sequence and a hash, which is not enough to
        recompute anything.
        """
        lines = []
        for event in chain:
            body = AuditEventCodec.to_form(event)
            body["hash"] = str(event.event_hash())
            body["prev"] = str(event.previous_hash) if event.previous_hash else NULL_HASH
            lines.append(Canonical.encode_form(body))
        return b"\n".join(lines) + b"\n"

    @staticmethod
    def _verify_instructions(
        *,
        witnessed: bool,
        signed: bool,
        receipted: bool = False,
        sources: Sequence[str] = (),
        redacted: Sequence[str] = (),
    ) -> bytes:
        """Generated to match the bundle it ships with.

        Steps never reference a file that is not there, because an instruction a
        verifier cannot follow reads as a failed verification — and a reader who cannot
        tell the difference will assume the bundle is at fault when the instructions
        were.
        """
        steps = [
            "# VERIFY",
            "",
            "Check this bundle by hand. No framework code is required.",
            "",
            "1. Recompute file hashes",
            "     every entry in manifest.json is sha256 of that file's bytes.",
        ]
        if signed:
            steps += [
                "",
                "2. Verify the signature",
                "     signature.sig is base64, over the bytes of manifest.json, from",
                "     the key named in pubkey.id.",
                "",
                "     pubkey.pem is that key, included so this step is followable at",
                "     all. It is NOT a trust anchor: a key the bundle supplied proves",
                "     only that the bundle agrees with itself. Compare its fingerprint",
                "     against the key id the issuer published, out of band. If they",
                "     differ, stop.",
                "",
                "     Ed25519. With openssl:",
                "       base64 -d signature.sig > signature.raw",
                "       openssl pkeyutl -verify -pubin -inkey pubkey.pem \\",
                "         -rawin -in manifest.json -sigfile signature.raw",
            ]
        steps += [
            "",
            f"{3 if signed else 2}. Walk the provenance chain",
            "     in chain.jsonl each line's `prev` must equal the previous line's",
            "     `hash`; line 1 has prev = 000...0.",
            "",
            f"{4 if signed else 3}. Check the seal covers the whole chain",
            "     seal.json `event_count` must equal the line count of chain.jsonl,",
            "     and `head_hash` must equal the last line's `hash`.",
            "     This is the step that detects an OMITTED event: a chain can be",
            "     internally valid and still be missing one, so linkage alone is",
            "     not enough.",
            "",
            f"{5 if signed else 4}. Check the record against its own hash",
            "     attestation.json carries `content_hash`. Recompute the canonical",
            "     digest over the record and compare.",
        ]
        if sources:
            steps += [
                "",
                f"{6 if signed else 5}. Spot-check a citation",
                "     the evidence/ directory contains the cited sources:",
                *[f"       evidence/{name}" for name in sources],
                "     attestation.json gives each source id, version and integrity",
                "     hash; the file's sha256 must match the integrity hash.",
            ]
        if witnessed:
            base = (7 if signed else 6) if sources else (6 if signed else 5)
            steps += [
                "",
                f"{base}. Walk the inclusion proof",
                "     fold witness/inclusion_proof.json up to a root.",
                "",
                f"{base + 1}. Compare that root to the INDEPENDENTLY published checkpoint",
                "     Obtain it from the third-party log, NOT from this bundle.",
                "     witness/checkpoint.json is included for reference only;",
                "     comparing against it proves only that the bundle agrees with",
                "     itself, which is what witnessing exists to get past.",
            ]
            if receipted:
                steps += [
                    "",
                    f"{base + 2}. Check the receipt names the same leaf",
                    "     witness/receipt.json was issued at decision time, before or",
                    "     with the effect. If the leaf it names is absent from the log,",
                    "     the host signed a promise it did not keep — which is",
                    "     evidence of omission that does not depend on our cooperation.",
                ]
        if not signed:
            steps += [
                "",
                "## UNSIGNED — read step 1 again before relying on anything here",
                "",
                "Nothing binds this bundle to its issuer. manifest.json travelled in",
                "the same archive as the files it describes, so anyone who edited a",
                "file could edit its manifest entry too and every check above would",
                "still pass. What step 1 establishes is that this archive is",
                "INTERNALLY CONSISTENT — not that it came from anywhere in",
                "particular, and not that it has not been rebuilt wholesale.",
                "",
                "For that you need a signature over manifest.json from a key you",
                "already trust, or an independently published checkpoint.",
            ]
        if redacted:
            steps += [
                "",
                "## Redacted for this audience",
                "",
                "The files below were withheld. Their ORIGINAL hashes remain in",
                "manifest.json, so a withheld file is distinguishable from an altered",
                "one — verify_manifest() skips them rather than reporting a mismatch.",
                *[f"     {name}" for name in redacted],
            ]
        steps += [
            "",
            "## What this bundle does not establish",
            "",
            "That the decision was *correct*. It establishes what was decided, from",
            "which sources, under which policy version, and authorised by whom. A",
            "beautifully verifiable attestation of a wrong decision is entirely",
            "possible.",
        ]
        return ("\n".join(steps) + "\n").encode("utf-8")
