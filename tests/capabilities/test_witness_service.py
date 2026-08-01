"""The submission path — the half of witnessing that was types only.

`Witness`, `Checkpoint`, `Receipt` and `MerkleTree` were well built and called by
nothing, which made external witnessing a design note rather than a mitigation. These
tests exercise the path end to end: leaf queued, window closed, checkpoint published,
proof retrievable per run, receipt issued before the effect.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attest.adapters.witness import (
    InMemoryWitness,
    Rfc3161Witness,
    TransparencyLogWitness,
    WitnessError,
)
from attest.capabilities.witness import (
    Checkpoint,
    ConsistencyProof,
    MerkleTree,
    WitnessLevel,
    WitnessService,
)
from attest.kernel.errors import ContractViolation
from attest.kernel.identifiers import Hash, RunId

pytestmark = pytest.mark.unit

AT = datetime(2026, 7, 31, 12, 0, tzinfo=UTC)


class RecordingSigner:
    """A signer that is deterministic, so a signature can be asserted on."""

    key_id = "test-key"

    def sign(self, payload: bytes) -> str:
        # Over the content, not its length: a length-based fake cannot tell two
        # payloads apart and would pass a test about what the signature covers.
        import hashlib

        return f"sig:{hashlib.sha256(payload).hexdigest()[:16]}"

    def verify(self, payload: bytes, signature: str) -> bool:
        return signature == self.sign(payload)


def service(*, signer: RecordingSigner | None = None) -> tuple[WitnessService, InMemoryWitness]:
    """The in-process witness, used deliberately.

    ``allow_non_independent`` is the explicit opt-in the service now requires: an
    in-process witness IS the host, so a receipt issued against one survives nothing.
    These tests exercise the plumbing, which is exactly what the flag is for.
    """
    witness = InMemoryWitness()
    return (
        WitnessService(witness, signer=signer, allow_non_independent=True),
        witness,
    )


# ── The submission path ──────────────────────────────────────────────────────


def test_a_queued_run_is_provable_after_the_window_closes() -> None:
    made, witness = service()
    leaf = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    witness.observe(leaf)
    receipt = made.checkpoint(at=AT)
    assert receipt is not None

    proof = made.proof_for(RunId("run_1"))
    assert proof is not None
    assert proof.verifies_against(receipt.checkpoint.root)


def test_a_run_that_was_never_queued_has_no_proof() -> None:
    """``None`` is the honest answer, and the alarming one.

    A run with no leaf is a run the log does not know about — exactly what a receipt
    holder is checking when they demand a proof.
    """
    made, _ = service()
    made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    assert made.proof_for(RunId("run_absent")) is None


@pytest.mark.security
def test_enqueueing_the_same_run_twice_does_not_add_a_second_leaf() -> None:
    """Two leaves for one decision make the tree size disagree with the decision count."""
    made, _ = service()
    first = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    second = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    assert first == second
    assert made.tree_size == 1


def test_an_empty_window_does_not_close() -> None:
    """An empty checkpoint commits to nothing and would still consume a submission."""
    made, witness = service()
    assert made.checkpoint(at=AT) is None
    assert witness.submissions == ()


def test_the_checkpoint_is_signed_when_a_signer_is_supplied() -> None:
    made, _ = service(signer=RecordingSigner())
    made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    receipt = made.checkpoint(at=AT)
    assert receipt is not None
    assert receipt.checkpoint.signature is not None


# ── Receipts: the synchronous half ───────────────────────────────────────────


@pytest.mark.security
def test_a_receipt_is_issued_before_the_window_closes() -> None:
    """The receipt costs a hash, not a round trip, which is why it can precede the effect.

    A receipt handed over afterwards is a receipt the host could have chosen not to
    hand over.
    """
    made, _ = service(signer=RecordingSigner())
    leaf = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    receipt = made.issue_receipt(RunId("run_1"), leaf, at=AT, window="w-1")
    assert receipt.leaf == leaf
    assert receipt.signature is not None
    assert made.checkpoints == ()  # nothing has been published yet


@pytest.mark.security
def test_a_receipt_names_a_leaf_that_a_later_proof_must_match() -> None:
    """The inversion of burden: the affected party holds the evidence of omission."""
    made, witness = service(signer=RecordingSigner())
    leaf = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    held = made.issue_receipt(RunId("run_1"), leaf, at=AT, window="w-1")
    witness.observe(leaf)
    published = made.checkpoint(at=AT)
    assert published is not None

    served = witness.inclusion_proof(held.leaf)
    assert served is not None, (
        "the host promised this leaf and the log cannot produce it; a signed promise "
        "it did not keep"
    )
    assert served.verifies_against(published.checkpoint.root)


# ── Consistency: the proof that defeats rewriting ────────────────────────────


@pytest.mark.security
def test_a_later_checkpoint_provably_extends_an_earlier_one() -> None:
    made, _ = service()
    made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("1" * 64))
    first = made.checkpoint(at=AT)
    assert first is not None

    for index in range(2, 6):
        made.enqueue(RunId(f"run_{index}"), Hash(f"{index}" * 64), Hash("1" * 64))
    second = made.checkpoint(at=AT)
    assert second is not None

    proof = made.extends(first.checkpoint)
    assert proof.verifies(first.checkpoint.root, second.checkpoint.root)


@pytest.mark.security
def test_a_rewritten_history_fails_the_consistency_check() -> None:
    """The attack this exists for: an internally perfect chain that is completely false.

    The host recomputes every hash and re-seals. Nothing inside detects it. A third
    party holding the earlier root does.
    """
    honest = MerkleTree([MerkleTree.leaf_hash(bytes([index])) for index in range(5)])
    published_root = MerkleTree(honest.leaves[:3]).root()

    rewritten = MerkleTree(
        [MerkleTree.leaf_hash(b"forged"), *[MerkleTree.leaf_hash(bytes([i])) for i in range(1, 5)]]
    )
    proof = rewritten.consistency_proof(3)
    assert not proof.verifies(published_root, rewritten.root()), (
        "a rewritten log verified against a root a third party already held"
    )


def test_a_proof_with_a_truncated_path_does_not_verify() -> None:
    tree = MerkleTree([MerkleTree.leaf_hash(bytes([index])) for index in range(7)])
    honest = tree.consistency_proof(3)
    truncated = ConsistencyProof(
        old_size=honest.old_size, new_size=honest.new_size, path=honest.path[:-1]
    )
    assert not truncated.verifies(MerkleTree(tree.leaves[:3]).root(), tree.root())


def test_consistency_with_a_tree_larger_than_this_one_is_refused() -> None:
    tree = MerkleTree([MerkleTree.leaf_hash(b"a")])
    with pytest.raises(ValueError, match="cannot prove consistency"):
        tree.consistency_proof(9)


# ── The adapters say what they are ───────────────────────────────────────────


@pytest.mark.security
def test_the_in_memory_witness_reports_that_it_is_not_independent() -> None:
    """The failure mode here is a deployment that believes it is witnessed."""
    assert InMemoryWitness().independent is False


@pytest.mark.security
def test_a_plaintext_witness_endpoint_is_refused() -> None:
    """Answers obtained over a channel the host controls did not come from outside it."""
    with pytest.raises(ContractViolation, match="not https"):
        TransparencyLogWitness("http://log.example")
    with pytest.raises(ContractViolation, match="not https"):
        Rfc3161Witness("http://tsa.example")


@pytest.mark.security
def test_a_log_that_returns_no_reference_is_a_failed_submission() -> None:
    """Recording it as witnessed would be false confidence, which is worse than none."""

    class Silent(TransparencyLogWitness):
        def _post(self, path: str, body: object) -> dict[str, object]:
            return {"ok": True}

    with pytest.raises(WitnessError, match="no reference"):
        Silent("https://log.example").submit(
            Checkpoint(root=Hash("a" * 64), tree_size=1, created_at=AT)
        )


@pytest.mark.security
def test_a_log_acknowledging_a_different_root_is_refused() -> None:
    class Confused(TransparencyLogWitness):
        def _post(self, path: str, body: object) -> dict[str, object]:
            return {"reference": "7", "root": "b" * 64}

    with pytest.raises(WitnessError, match="different tree"):
        Confused("https://log.example").submit(
            Checkpoint(root=Hash("a" * 64), tree_size=1, created_at=AT)
        )


def test_a_timestamping_authority_does_not_invent_proofs_it_cannot_hold() -> None:
    """A TSA has no view of the tree. Returning anything here would be a fabrication."""
    tsa = Rfc3161Witness("https://tsa.example")
    checkpoint = Checkpoint(root=Hash("a" * 64), tree_size=1, created_at=AT)
    assert tsa.inclusion_proof(Hash("a" * 64)) is None
    assert tsa.consistency_proof(checkpoint, checkpoint) is None


def test_the_timestamp_request_is_a_well_formed_der_structure() -> None:
    """Checked against the DER on the wire, because a malformed query gets rejected.

    A TimeStampReq is SEQUENCE { version 1, messageImprint SEQUENCE { AlgorithmIdentifier,
    OCTET STRING }, certReq TRUE }.
    """
    request = Rfc3161Witness.time_stamp_request(Hash("ab" * 32))
    assert request[0] == 0x30  # SEQUENCE
    assert request[1] == len(request) - 2  # short-form length covers the rest
    assert request[2:5] == b"\x02\x01\x01"  # version 1
    assert Rfc3161Witness.SHA256_OID in request
    assert bytes.fromhex("ab" * 32) in request  # the imprint is the checkpoint root
    assert request.endswith(b"\x01\x01\xff")  # certReq TRUE


def test_a_witness_receipt_without_a_reference_is_refused() -> None:
    """There would be nothing to ask the third party for later."""
    from attest.capabilities.witness import WitnessReceipt

    with pytest.raises(ValueError, match="witnesses nothing"):
        WitnessReceipt(
            checkpoint=Checkpoint(root=Hash("a" * 64), tree_size=1, created_at=AT),
            reference="",
            witnessed_at=AT,
        )


# ── A witness that defeats nothing must not produce witnessed artefacts ──────


@pytest.mark.security
def test_a_receipt_is_refused_against_a_non_independent_witness() -> None:
    """ATT-29. InMemoryWitness is honest and nothing consumed its honesty.

    It reports independent=False and its receipt carries "in-process; defeats nothing",
    but WitnessService accepted any witness and BundleBuilder wrote witness/ from
    whatever it was handed — so a deployment could ship with the test witness and
    produce bundles that read as witnessed.
    """
    made = WitnessService(InMemoryWitness())
    leaf = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    with pytest.raises(ContractViolation, match="not independent"):
        made.issue_receipt(RunId("run_1"), leaf, at=AT, window="w-1")


def test_the_opt_in_is_explicit_and_named() -> None:
    """Exercising the plumbing must be possible; it must not be the default."""
    made = WitnessService(InMemoryWitness(), allow_non_independent=True)
    leaf = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    assert made.issue_receipt(RunId("run_1"), leaf, at=AT, window="w-1").leaf == leaf


@pytest.mark.security
def test_the_receipt_signature_covers_when_it_was_issued() -> None:
    """ATT-12. issued_at was excluded, and it is the whole evidentiary claim.

    A receipt's value rests on it having been issued before or with the effect. That
    timing claim was unsigned, so the party the receipt exists to hold to account could
    restate it at will.
    """
    signer = RecordingSigner()
    made, _ = service(signer=signer)
    leaf = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))

    early = made.issue_receipt(RunId("run_1"), leaf, at=AT, window="w-1")
    later = made.issue_receipt(RunId("run_1"), leaf, at=AT.replace(hour=23), window="w-1")
    assert early.signature != later.signature, (
        "the same signature covers two different issue times, so the time is restatable"
    )


def test_an_external_verifier_can_rebuild_the_signed_bytes() -> None:
    """A signature nobody outside this package can check is not evidence."""
    signer = RecordingSigner()
    made, _ = service(signer=signer)
    leaf = made.enqueue(RunId("run_1"), Hash("a" * 64), Hash("b" * 64))
    receipt = made.issue_receipt(RunId("run_1"), leaf, at=AT, window="w-1")

    rebuilt = WitnessService.receipt_payload(
        run_id=receipt.run_id,
        leaf=receipt.leaf,
        promised_by=receipt.promised_by,
        issued_at=receipt.issued_at,
    )
    assert signer.verify(rebuilt, receipt.signature or "")


# ── The timestamping authority claims only what it has checked ──────────────


@pytest.mark.security
def test_a_timestamping_authority_does_not_claim_a_level_it_has_not_earned() -> None:
    """ATT-07. Any bytes earned TIMESTAMPED.

    submit() accepted the response with one check — that it was non-empty. A rejection
    is a non-empty token. Nothing compared the token's imprint to the root, nothing
    verified the signature, and no nonce was sent, so one previously-obtained token
    satisfied every root forever while the deployment reported the level that exists
    specifically to defeat operator backdating.
    """
    tsa = Rfc3161Witness("https://tsa.example")
    assert tsa.LEVEL is WitnessLevel.NONE
    assert tsa.independent is False


@pytest.mark.security
def test_a_rejected_timestamp_response_is_refused() -> None:
    """PKIStatus 2 is "rejection", and it arrives as a well-formed non-empty token."""
    rejection = bytes.fromhex("30073005020102300 0".replace(" ", ""))
    with pytest.raises(WitnessError, match="refused the request"):
        Rfc3161Witness.assert_granted(rejection)


def test_a_granted_timestamp_response_is_accepted() -> None:
    granted = bytes.fromhex("300730050201003000")
    Rfc3161Witness.assert_granted(granted)


@pytest.mark.security
def test_an_unparseable_response_is_refused_rather_than_stored() -> None:
    """Storing bytes of unknown meaning is how a rejection becomes a receipt."""
    with pytest.raises(WitnessError, match="could not be parsed"):
        Rfc3161Witness.assert_granted(b"not asn.1 at all")


def test_the_request_carries_a_nonce() -> None:
    """The RFC's own replay defence, and it was omitted."""
    with_nonce = Rfc3161Witness.time_stamp_request(Hash("ab" * 32), nonce=12345)
    without = Rfc3161Witness.time_stamp_request(Hash("ab" * 32))
    assert len(with_nonce) > len(without)


# ── The endpoint check is more than a prefix ─────────────────────────────────


@pytest.mark.security
@pytest.mark.parametrize(
    "url",
    [
        "https://user@internal-host/log",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/log",
        "https://localhost/log",
        "https://10.0.0.5/log",
        "https://metadata.google.internal/computeMetadata/v1/",
    ],
)
def test_an_internal_or_userinfo_endpoint_is_refused(url: str) -> None:
    """ATT-27. startswith("https://") was the only control.

    It admits userinfo — which reads as one host and connects to another — and every
    private and link-local address, including the cloud credential endpoint.
    """
    with pytest.raises(ContractViolation):
        TransparencyLogWitness(url)


def test_an_ordinary_https_endpoint_is_accepted() -> None:
    assert TransparencyLogWitness("https://log.example/ct").independent is True


@pytest.mark.security
def test_a_leaf_that_is_not_a_hash_cannot_alter_the_request_path() -> None:
    """ATT-26. Hash is a NewType with no runtime check, interpolated into a URL.

    A value containing "?", "#" or "../" changed which endpoint of the log's API was
    called.
    """
    from attest.kernel.identifiers import Hash as _Hash

    log = TransparencyLogWitness("https://log.example")
    with pytest.raises(ValueError, match="is not a hash"):
        log.inclusion_proof(_Hash("../checkpoints/latest?x="))


def test_a_valid_hash_parses() -> None:
    from attest.kernel.identifiers import Hashes

    assert Hashes.parse("a" * 64) == "a" * 64
    with pytest.raises(ValueError, match="is not a hash"):
        Hashes.parse("A" * 64)  # uppercase: two spellings of one digest


@pytest.mark.security
def test_grant_checks_compare_in_constant_time() -> None:
    """ATT-30. The convention is set once rather than re-decided at each site."""
    from attest.kernel.identifiers import Secrets

    assert Secrets.equal("a" * 64, "a" * 64)
    assert not Secrets.equal("a" * 64, "b" * 64)
