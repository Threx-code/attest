"""``manage.py export_bundle`` — write a run's record out for offline verification.

**It refuses to export an unsealed or non-final run**, mirroring
:meth:`Attestation.assert_exportable`. A bundle is what goes to a regulator: one whose
chain cannot be verified, or whose warrants nobody evaluated, would present an
unverified result as a settled record. That refusal is the point of the command, not an
inconvenience in it.

The bundle is plain files plus a manifest, so verification needs a hash utility rather
than this package.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from django.core.management.base import BaseCommand, CommandError

from attest.adapters.django.chain import StoredChainCheck
from attest.adapters.django.models import AttestationRecord
from attest.adapters.django.stores import DjangoAuditSink, DjangoRunStore
from attest.capabilities.audit import ChainSealer
from attest.kernel.codec import AttestationCodec, AuditEventCodec
from attest.kernel.identifiers import RunId

if TYPE_CHECKING:
    from argparse import ArgumentParser
    from collections.abc import Sequence

    from attest.kernel.audit import AuditEvent

__all__ = ["Command"]


class Command(BaseCommand):
    help = "Export a sealed, final attestation and its chain as an evidence bundle."

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("run_id")
        parser.add_argument("--out", required=True, help="Directory to write the bundle into.")

    def handle(self, *args: Any, **options: Any) -> None:
        run_id = str(options["run_id"])
        record = AttestationRecord.objects.filter(pk=run_id).first()
        if record is None:
            raise CommandError(f"no attestation for run {run_id!r}")
        if not record.sealed:
            raise CommandError(
                f"run {run_id!r} is not sealed, so its chain cannot be verified "
                f"offline. An unsealed record is not evidence."
            )
        if not record.is_final:
            raise CommandError(
                f"run {run_id!r} has warrants still pending. Exporting it would present "
                f"an unverified result as a settled record; let deferred assurance "
                f"settle first."
            )

        check = StoredChainCheck().run(RunId(run_id))
        if not check.verified:
            reasons = ", ".join(failure.value for failure in check.failures)
            raise CommandError(
                f"chain for run {run_id!r} does not verify ({reasons}): {check.detail}"
            )

        # Decoded, not copied: this both verifies the stored payload against its own
        # content hash and produces something a verifier can read without our code.
        attestation = DjangoRunStore().get(RunId(run_id))
        if attestation is None:  # pragma: no cover - the row was fetched above
            raise CommandError(f"no attestation for run {run_id!r}")
        # Sealed for export: stored events carry no positions, and a bundle whose
        # chain lines had no sequence would be unverifiable by the very steps
        # VERIFY.md sets out.
        events, _ = ChainSealer().seal(
            DjangoAuditSink().read_chain(RunId(run_id)),
            run_id=RunId(run_id),
            attestation_hash=attestation.content_hash(),
            sealed_at=attestation.seal.sealed_at if attestation.seal else record.created_at,
        )

        directory = Path(options["out"]) / run_id
        directory.mkdir(parents=True, exist_ok=True)
        files = {
            "attestation.json": AttestationCodec.encode(attestation),
            "chain.jsonl": self._chain_bytes(events),
            "VERIFY.md": self._instructions(run_id).encode("utf-8"),
        }
        for name, blob in files.items():
            (directory / name).write_bytes(blob)

        manifest = {
            "run_id": run_id,
            "verdict": record.verdict,
            "warnings": record.warnings,
            "content_hash": record.content_hash,
            "seal_signature": record.seal_signature,
            "events": len(events),
            "event_hashes_recomputed": StoredChainCheck.RECOMPUTED,
            "chain_sealed": check.sealed,
            "files": {
                name: hashlib.sha256(blob).hexdigest() for name, blob in sorted(files.items())
            },
        }
        (directory / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        self.stdout.write(f"Wrote bundle for {run_id} to {directory}")

    def _chain_bytes(self, events: Sequence[AuditEvent]) -> bytes:
        """One canonical event per line, plus its recomputed hash.

        The hash is recomputed from the event's content rather than copied from the
        row, so a verifier can redo the same computation and get the same answer
        without trusting either the exporter or the database.
        """
        lines = [
            AuditEventCodec.encode(event).decode("utf-8")
            + "\n"
            + json.dumps({"event_hash": str(event.event_hash())}, sort_keys=True)
            for event in events
        ]
        return ("\n".join(lines) + "\n").encode("utf-8")

    def _instructions(self, run_id: str) -> str:
        """What a verifier can check without this package — and what it cannot."""
        return (
            f"# Verifying run {run_id}\n\n"
            "1. Recompute `sha256` of each file and compare with `manifest.json`.\n"
            "2. Check `chain.jsonl` sequences are dense from 1 with no gaps. A gap is\n"
            "   how an omitted event looks from the inside; linkage alone cannot show\n"
            "   it, because removing an event and re-pointing its successor leaves\n"
            "   every stored hash consistent.\n"
            "3. Check each line's `previous_hash` against the preceding line.\n\n"
            "4. `attestation.json` carries its own `content_hash`. Recompute the\n"
            "   canonical digest over the record and compare — the exporter did this\n"
            "   too, and a mismatch means the payload and the record have come apart.\n\n"
            "## What this bundle does not establish\n\n"
            "It does not establish that the decision was *correct*. It establishes\n"
            "what was decided, from which sources, under which policy version, and\n"
            "authorised by whom. A beautifully verifiable attestation of a wrong\n"
            "decision is entirely possible.\n"
        )
